package emulator

import (
	"debug/elf"
	"fmt"

	"github.com/sisi0318/gonidbg/dvm"
	"github.com/sisi0318/gonidbg/internal/emu"
	"github.com/sisi0318/gonidbg/internal/kernel"
	"github.com/sisi0318/gonidbg/internal/memory"
)

// Snapshot is a full, restorable image of one emulator's mutable guest+host
// state, captured after boot/init. Restoring it rewinds the instance to that
// exact point, so a pooled emulator can serve many calls while each call starts
// from the same pristine state a freshly-booted process would have.
//
// This is the cure for signature/output drift when reusing an emulator: an
// obfuscated .so accumulates state across calls — globals in .data/.bss, heap
// contents and allocation addresses (which shift as the monotonic arena grows),
// leftover stack bytes, the exit latch, JNI handles — so call N diverges from a
// clean call 1. It is unidbg's classic "save/restore context" pattern.
//
// Not safe for concurrent use: hold the emulator exclusively (as a worker pool
// does — one request per instance at a time) around Snapshot and Restore.
type Snapshot struct {
	cpu      emu.CPUContext  // full register file (GP + SIMD + SP/PC/PSTATE/TPIDR)
	writable []memWrite      // bytes of every writable guest region at snapshot time
	regions  []memRange      // every known region + its protection at snapshot time
	layout   []memory.Region // mmap-arena allocator table
	mmapTop  uint64          // mmap-arena cursor
	kstate   kernel.State    // brk / exit latch / fds / FS overlay
	vmstate  dvm.VMState     // JNI object-handle table
	// classRefs is the host-side FindClass cache. It hands out dvm.Ref values
	// drawn from the same counter vmstate rewinds, so leaving it alone across a
	// Restore leaves cached jclass handles pointing at dropped — and then at
	// freshly reissued, unrelated — objects.
	classRefs map[string]dvm.Ref
	// staticFields is guest-written static field state; same rewind requirement
	// as the object handle table.
	staticFields map[string]uint64
	nextFiberID  int
}

type memWrite struct {
	addr uint64
	prot int
	data []byte
}

type memRange struct {
	addr uint64
	size uint64
	prot int
}

func pageDown(x uint64) uint64 { return x &^ 0xfff }
func pageUp(x uint64) uint64   { return (x + 0xfff) &^ 0xfff }

// writableGuestRanges lists every writable guest region whose bytes can change
// during a call and therefore must be captured and restored. These live in
// different maps — most are backed on the CPU engine directly and are NOT in the
// mmap-arena allocator (Space) — so they're assembled explicitly:
//
//   - stack, TLS, import-stub trampolines (fixed regions mapped at boot),
//   - each module's writable (.data/.bss) segments — the accumulating globals,
//   - the brk heap [BrkBase, BrkTop),
//   - the mmap arena (host scratch + guest mmap, the only Space-tracked set).
func (e *Emulator) writableGuestRanges() []memRange {
	var rs []memRange
	for _, r := range e.guestRanges() {
		if r.prot&emu.ProtWrite != 0 {
			rs = append(rs, r)
		}
	}
	return rs
}

// guestRanges lists every region the emulator knows it mapped, with the
// protection it currently has. writableGuestRanges is the subset whose bytes
// can change and therefore need their contents captured too.
//
// The protections matter on their own: a guest that mprotects a region during a
// call (an unpacker flipping its scratch buffer from RW to R-X, say) leaves the
// engine's page protection changed. Restoring only the allocator table would
// put the table and the engine permanently out of sync, and because unicorn's
// mem_write ignores protection the rewind would still look like it worked.
func (e *Emulator) guestRanges() []memRange {
	rs := []memRange{
		{stackBase, stackSize, emu.ProtRead | emu.ProtWrite},
		{tlsBase, tlsSize, emu.ProtRead | emu.ProtWrite},
		{stubBase, stubSize, emu.ProtAll},
	}
	for _, m := range e.modules {
		for _, s := range m.Img.Segments {
			va := m.Base + pageDown(s.Vaddr)
			rs = append(rs, memRange{va, pageUp(s.Vaddr+s.MemSz) - pageDown(s.Vaddr), segProt(s.Flags)})
		}
	}
	if top := e.kctx.BrkTop(); top > kernel.BrkBase {
		rs = append(rs, memRange{kernel.BrkBase, top - kernel.BrkBase, emu.ProtRead | emu.ProtWrite})
	}
	for _, r := range e.mem.Regions() {
		rs = append(rs, memRange{r.Addr, r.Size, r.Prot})
	}
	return rs
}

// segProt maps PT_LOAD flags to backend protection bits.
func segProt(f elf.ProgFlag) int {
	p := 0
	if f&elf.PF_R != 0 {
		p |= emu.ProtRead
	}
	if f&elf.PF_W != 0 {
		p |= emu.ProtWrite
	}
	if f&elf.PF_X != 0 {
		p |= emu.ProtExec
	}
	return p
}

// Snapshot captures the current guest state. Take it once, right after New()
// (which has already run init_array + JNI_OnLoad) and after any Replace/patch
// setup, then Restore before each reused call. The returned Snapshot owns a
// backend CPU context; release it with Free when the emulator is discarded.
func (e *Emulator) Snapshot() (*Snapshot, error) {
	if e.closed() {
		return nil, errClosed
	}
	// Build the JNI tables now if nothing has needed them yet. They are Alloc'd
	// from the mmap arena, so if they were created *after* the snapshot, Restore
	// would unmap them (absent from the snapshot layout) and rewind mmapTop below
	// them while e.jniEnv/e.javaVM still pointed there — and the next scratch
	// allocation would then be handed that exact address, leaving the guest to
	// call through a function table that now holds string bytes.
	e.JavaVM()
	e.JNIEnv()

	cpu, err := e.be.SaveContext()
	if err != nil {
		return nil, fmt.Errorf("snapshot: save cpu: %w", err)
	}
	regions := e.guestRanges()
	var writable []memWrite
	for _, r := range regions {
		if r.prot&emu.ProtWrite == 0 {
			continue
		}
		data, err := e.be.MemRead(r.addr, r.size)
		if err != nil {
			continue // unmapped hole (e.g. a gap between segments) — nothing to restore
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		writable = append(writable, memWrite{addr: r.addr, prot: r.prot, data: buf})
	}
	regs := e.mem.Regions()
	layout := make([]memory.Region, len(regs))
	copy(layout, regs)

	classRefs := make(map[string]dvm.Ref, len(e.classRefs))
	for k, v := range e.classRefs {
		classRefs[k] = v
	}
	staticFields := make(map[string]uint64, len(e.staticFields))
	for k, v := range e.staticFields {
		staticFields[k] = v
	}

	return &Snapshot{
		cpu:          cpu,
		writable:     writable,
		regions:      regions,
		layout:       layout,
		mmapTop:      e.mem.MmapTop(),
		kstate:       e.kctx.Snapshot(),
		vmstate:      e.vm.Snapshot(),
		classRefs:    classRefs,
		staticFields: staticFields,
		nextFiberID:  e.nextFiberID,
	}, nil
}

// Restore rewinds the emulator to snap. Call it before each reused invocation
// (before writing this call's arguments) so the call runs against pristine
// state. Cost is a memcpy of the writable footprint through the backend — a few
// milliseconds, negligible against a real sign.
func (e *Emulator) Restore(snap *Snapshot) error {
	if snap == nil {
		return fmt.Errorf("restore: nil snapshot")
	}
	if e.closed() {
		return errClosed
	}
	// 1) Unmap arena regions the guest mapped after the snapshot (scratch allocs,
	//    guest mmaps) so the address space matches the snapshot again.
	snapSet := make(map[uint64]uint64, len(snap.layout))
	for _, r := range snap.layout {
		snapSet[r.Addr] = r.Size
	}
	for _, r := range e.mem.Regions() {
		if sz, ok := snapSet[r.Addr]; !ok || sz != r.Size {
			_ = e.be.MemUnmap(r.Addr, r.Size)
		}
	}
	// 2) Restore the arena allocator table + cursor.
	e.mem.SetLayout(snap.layout, snap.mmapTop)
	// 3) Restore kernel state — this also unmaps brk pages grown during the call,
	//    freeing those addresses before we write the snapshot brk bytes back.
	e.kctx.Restore(snap.kstate)
	// 4) Re-map any snapshot region the guest unmapped during the call. A
	//    read-only region isn't in snap.writable, so without this it would stay
	//    gone and the next call would fault on its first read. (Its bytes are not
	//    recoverable here — only the mapping is — but a zeroed page beats an
	//    unmapped one, and writable regions get their contents back below.)
	//    MemMap on an already-mapped range just errors; that's the common case.
	for _, r := range snap.regions {
		_ = e.be.MemMap(r.addr, r.size, r.prot)
	}
	// 5) Restore writable memory bytes: stack, TLS, stubs, .data/.bss, brk, arena.
	for _, w := range snap.writable {
		if err := e.be.MemWrite(w.addr, w.data); err != nil {
			_ = e.be.MemMap(w.addr, uint64(len(w.data)), w.prot)
			if err := e.be.MemWrite(w.addr, w.data); err != nil {
				return fmt.Errorf("restore: write 0x%x: %w", w.addr, err)
			}
		}
	}
	// 6) Re-apply protections. Writes above go through unicorn's mem_write, which
	//    ignores protection, so this has to come after them — and it has to happen
	//    at all, or a guest mprotect during the call outlives the rewind.
	for _, r := range snap.regions {
		_ = e.be.MemProtect(r.addr, r.size, r.prot)
	}
	// 7) Restore the CPU register file (incl. SP → a fresh, dirty-free stack top,
	//    TPIDR, PSTATE). CallFunc overwrites X0..X7/LR/PC for the next call.
	if err := e.be.RestoreContext(snap.cpu); err != nil {
		return fmt.Errorf("restore: cpu: %w", err)
	}
	// 8) Restore JNI object handles and reset per-run scheduler / JNI scratch.
	e.vm.Restore(snap.vmstate)
	e.classRefs = make(map[string]dvm.Ref, len(snap.classRefs))
	for k, v := range snap.classRefs {
		e.classRefs[k] = v
	}
	e.staticFields = make(map[string]uint64, len(snap.staticFields))
	for k, v := range snap.staticFields {
		e.staticFields[k] = v
	}
	e.fibers = nil
	e.curFiber = nil
	e.nextFiberID = snap.nextFiberID
	e.threadCap, e.threadOps, e.yieldReason, e.yieldAddr = 0, 0, 0, 0
	e.scCount = 0
	e.pendingExc = false
	e.arrayPins = map[uint64]dvm.Ref{}
	return nil
}

// Free releases the snapshot's backend CPU context. Call it when the emulator
// (and thus this snapshot) is being discarded, e.g. on pool renewal or Close.
func (s *Snapshot) Free() {
	if s != nil && s.cpu != nil {
		_ = s.cpu.Free()
		s.cpu = nil
	}
}
