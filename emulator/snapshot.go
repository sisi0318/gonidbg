package emulator

import (
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
	cpu         emu.CPUContext   // full register file (GP + SIMD + SP/PC/PSTATE/TPIDR)
	writable    []memWrite       // bytes of every writable region at snapshot time
	layout      []memory.Region  // allocator region table
	mmapTop     uint64           // allocator cursor
	kstate      kernel.State     // brk / exit latch / fds / FS overlay
	vmstate     dvm.VMState      // JNI object-handle table
	nextFiberID int
}

type memWrite struct {
	addr uint64
	prot int
	data []byte
}

// Snapshot captures the current guest state. Take it once, right after New()
// (which has already run init_array + JNI_OnLoad), then Restore before each
// reused call. The returned Snapshot owns a backend CPU context; release it with
// Free when the emulator is discarded.
func (e *Emulator) Snapshot() (*Snapshot, error) {
	cpu, err := e.be.SaveContext()
	if err != nil {
		return nil, fmt.Errorf("snapshot: save cpu: %w", err)
	}
	regs := e.mem.Regions()
	layout := make([]memory.Region, len(regs))
	copy(layout, regs)

	var writable []memWrite
	for _, r := range regs {
		if r.Prot&emu.ProtWrite == 0 {
			continue // code / rodata never changes across calls — no need to save
		}
		data, err := e.be.MemRead(r.Addr, r.Size)
		if err != nil {
			continue // unreadable (guard page etc.) — skip; nothing to restore
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		writable = append(writable, memWrite{addr: r.Addr, prot: r.Prot, data: buf})
	}

	return &Snapshot{
		cpu:         cpu,
		writable:    writable,
		layout:      layout,
		mmapTop:     e.mem.MmapTop(),
		kstate:      e.kctx.Snapshot(),
		vmstate:     e.vm.Snapshot(),
		nextFiberID: e.nextFiberID,
	}, nil
}

// Restore rewinds the emulator to snap. Call it before each reused invocation
// (before writing this call's arguments) so the call runs against pristine
// state. Cheap relative to a real sign: a few MiB of memcpy through the backend.
func (e *Emulator) Restore(snap *Snapshot) error {
	if snap == nil {
		return fmt.Errorf("restore: nil snapshot")
	}
	// 1) Unmap everything the guest mapped after the snapshot (arena growth, brk
	//    extension, guest mmaps) so the address space matches the snapshot again.
	snapSet := make(map[uint64]uint64, len(snap.layout))
	for _, r := range snap.layout {
		snapSet[r.Addr] = r.Size
	}
	for _, r := range e.mem.Regions() {
		if sz, ok := snapSet[r.Addr]; !ok || sz != r.Size {
			_ = e.be.MemUnmap(r.Addr, r.Size)
		}
	}
	// 2) Restore the allocator's region table + cursor.
	e.mem.SetLayout(snap.layout, snap.mmapTop)
	// 3) Restore writable memory bytes (re-map defensively if a region was split
	//    or unmapped mid-call, e.g. by a guest MAP_FIXED over its own data).
	for _, w := range snap.writable {
		if err := e.be.MemWrite(w.addr, w.data); err != nil {
			_ = e.be.MemMap(w.addr, uint64(len(w.data)), w.prot)
			if err := e.be.MemWrite(w.addr, w.data); err != nil {
				return fmt.Errorf("restore: write 0x%x: %w", w.addr, err)
			}
		}
	}
	// 4) Restore the CPU register file (incl. SP → a fresh dirty-free stack top,
	//    TPIDR, PSTATE). CallFunc overwrites X0..X7/LR/PC for the next call.
	if err := e.be.RestoreContext(snap.cpu); err != nil {
		return fmt.Errorf("restore: cpu: %w", err)
	}
	// 5) Restore kernel + JNI bookkeeping.
	e.kctx.Restore(snap.kstate)
	e.vm.Restore(snap.vmstate)
	// 6) Reset per-run scheduler / JNI scratch that accumulates across calls.
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
