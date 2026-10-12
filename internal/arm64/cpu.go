// Package arm64 is a pure-Go AArch64 user-mode CPU: an interpreter over a
// paged guest address space, with no cgo and no external dependencies. It
// backs gonidbg's "interp" engine (see internal/emu/interp.go).
//
// Each executable page gets an array of decoded instructions, filled lazily
// the first time an instruction runs. A decoded instruction is a handler plus
// pre-extracted operands, so the hot loop is fetch-from-cache, indirect call.
//
// Behavior follows Unicorn (QEMU) wherever the architecture leaves a choice,
// because Unicorn is the reference the differential tests compare against.
package arm64

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"sync/atomic"
)

// Register file slots. X0..X30 are 0..30; reads of register 31 in "zero
// register" position resolve to rZR (always 0), SP-position accesses to rSP,
// and writes to the zero register to rSink. Doing that remapping at decode
// time keeps every handler branch-free. R has 256 slots so a uint8 index
// never needs a bounds check.
const (
	rZR   = 31
	rSP   = 32
	rSink = 33
	rLR   = 30
)

// Vec is a 128-bit SIMD&FP register, little-endian lanes: [0] holds bits 63:0.
type Vec [2]uint64

// CPU is one AArch64 hardware thread plus its address space.
type CPU struct {
	R    [256]uint64
	PC   uint64
	NZCV uint32 // flags in bits 31..28, as MRS NZCV reads them
	V    [32]Vec
	FPCR uint32
	FPSR uint32

	TPIDR   uint64 // TPIDR_EL0
	TPIDRRO uint64 // TPIDRRO_EL0

	// exclusive monitor, QEMU-style: a store-exclusive succeeds when the
	// address matches and memory still holds the value the load-exclusive saw.
	exclAddr  uint64
	exclVal   uint64
	exclVal2  uint64
	exclSize  int
	exclValid bool

	Mem Memory

	// Instructions retired since the CPU was created; also CNTVCT_EL0, which
	// keeps guest time deterministic.
	icount uint64

	stopReq   atomic.Bool
	codeHooks []*codeHook
	intrHooks []*intrHook
}

// Context is a snapshot of the architectural register state.
type Context struct {
	R          [33]uint64 // X0..X30, (unused), SP
	PC         uint64
	NZCV       uint32
	V          [32]Vec
	FPCR, FPSR uint32
	TPIDR      uint64
	TPIDRRO    uint64
	exclAddr   uint64
	exclVal    uint64
	exclVal2   uint64
	exclSize   int
	exclValid  bool
	// icount is included because it backs CNTVCT_EL0: without it a restored
	// snapshot would read a different guest time than the run it was taken
	// from, and a library that mixes the counter into its output would drift
	// from call to call — the opposite of what Snapshot/Restore is for.
	icount uint64
}

type codeHook struct {
	begin, end uint64
	fn         func(addr uint64, size uint32)
}

type intrHook struct{ fn func(intno uint32) }

// Exception numbers passed to interrupt hooks, matching QEMU's EXCP_* so a
// hook sees the same intno as on Unicorn.
// (QEMU's EXCP_UDEF has no entry here: an undefined instruction is reported as
// an error from Run, which carries the encoding and the PC, rather than being
// delivered to a hook that could only abort the call anyway.)
const (
	ExcpSWI  = 2
	ExcpBKPT = 7
	ExcpHLT  = 8
)

// New returns a CPU with an empty address space.
func New() *CPU {
	c := &CPU{}
	c.Mem.init(&c.PC)
	return c
}

// SaveContext / RestoreContext snapshot the register state (not memory).
func (c *CPU) SaveContext() *Context {
	x := &Context{PC: c.PC, NZCV: c.NZCV, V: c.V, FPCR: c.FPCR, FPSR: c.FPSR,
		TPIDR: c.TPIDR, TPIDRRO: c.TPIDRRO, exclAddr: c.exclAddr, exclVal: c.exclVal,
		exclVal2: c.exclVal2, exclSize: c.exclSize, exclValid: c.exclValid, icount: c.icount}
	copy(x.R[:], c.R[:33])
	return x
}

func (c *CPU) RestoreContext(x *Context) {
	copy(c.R[:31], x.R[:31])
	c.R[rSP] = x.R[rSP]
	c.PC, c.NZCV, c.V, c.FPCR, c.FPSR = x.PC, x.NZCV, x.V, x.FPCR, x.FPSR
	c.TPIDR, c.TPIDRRO = x.TPIDR, x.TPIDRRO
	c.exclAddr, c.exclVal, c.exclVal2, c.exclSize, c.exclValid = x.exclAddr, x.exclVal, x.exclVal2, x.exclSize, x.exclValid
	c.icount = x.icount
}

// X / SetX access X0..X30 (31 = SP).
func (c *CPU) X(n int) uint64 {
	if n == 31 {
		return c.R[rSP]
	}
	return c.R[n&31]
}

func (c *CPU) SetX(n int, v uint64) {
	if n == 31 {
		c.R[rSP] = v
		return
	}
	c.R[n&31] = v
}

func (c *CPU) SP() uint64        { return c.R[rSP] }
func (c *CPU) SetSP(v uint64)    { c.R[rSP] = v }
func (c *CPU) InsnCount() uint64 { return c.icount }

// Stop asks a running Run to return before the next instruction. Safe to call
// from hooks and from other goroutines.
func (c *CPU) Stop() { c.stopReq.Store(true) }

// Release drops the guest address space, the decoded instructions and every
// hook. The CPU stays usable but has nothing mapped, so a stray use after the
// owning backend was closed reports unmapped memory instead of handing back
// freed state — and a closed emulator stops pinning its guest pages.
func (c *CPU) Release() {
	c.Mem = Memory{}
	c.Mem.init(&c.PC)
	c.codeHooks = nil
	c.intrHooks = nil
}

// AddCodeHook calls fn before each instruction in [begin, end] (begin > end:
// every instruction). If fn changes PC or calls Stop, the instruction it was
// called for is not executed.
func (c *CPU) AddCodeHook(begin, end uint64, fn func(addr uint64, size uint32)) func() {
	h := &codeHook{begin, end, fn}
	c.codeHooks = append(c.codeHooks, h)
	return func() {
		out := make([]*codeHook, 0, len(c.codeHooks))
		for _, x := range c.codeHooks {
			if x != h {
				out = append(out, x)
			}
		}
		c.codeHooks = out
	}
}

// AddInterruptHook calls fn for every exception: SVC (ExcpSWI, PC already
// past the SVC), BRK (ExcpBKPT) and HLT (ExcpHLT, PC on the instruction).
func (c *CPU) AddInterruptHook(fn func(intno uint32)) func() {
	h := &intrHook{fn}
	c.intrHooks = append(c.intrHooks, h)
	return func() {
		out := make([]*intrHook, 0, len(c.intrHooks))
		for _, x := range c.intrHooks {
			if x != h {
				out = append(out, x)
			}
		}
		c.intrHooks = out
	}
}

// UndefinedError reports an instruction this CPU does not implement (or that
// is architecturally undefined).
type UndefinedError struct {
	PC   uint64
	Insn uint32
}

func (e *UndefinedError) Error() string {
	return fmt.Sprintf("undefined or unimplemented instruction %#08x at pc=0x%x", e.Insn, e.PC)
}

// cpuError is a non-memory execution error (bad branch target, unhandled
// exception).
type cpuError struct{ msg string }

func (e *cpuError) Error() string { return e.msg }

// stopSignal unwinds a Stop that was requested from inside an exception hook.
// Raising it there, rather than having the run loop test the flag on every
// instruction, keeps the hot path free of the check: the hooks that stop
// execution — a guest exit_group, the scheduler preempting a fiber, a
// breakpoint — are rare, and a panic costs nothing until one fires.
type stopSignal struct{}

// Run executes from PC until PC == until (checked before each instruction),
// count instructions have retired (count > 0), Stop is called, or an error
// (memory fault, undefined instruction) occurs.
func (c *CPU) Run(until, count uint64) (err error) {
	c.stopReq.Store(false)
	defer func() {
		if r := recover(); r != nil {
			switch e := r.(type) {
			case *Fault:
				err = e
			case *UndefinedError:
				err = e
			case *cpuError:
				err = e
			case stopSignal:
				err = nil
			default:
				panic(r)
			}
		}
	}()
	limit := ^uint64(0)
	if count != 0 {
		limit = c.icount + count
	}
	m := &c.Mem
	for {
		// Reading the stop flag is an atomic load, which measured at ~7% of
		// total run time when paid per instruction, so it is amortised over a
		// batch instead. Stops that have to be prompt still are: an exception
		// hook unwinds through stopSignal and a code hook is checked below. A
		// Stop from a memory hook or from another goroutine takes effect
		// within one batch.
		if c.stopReq.Load() {
			return nil
		}
		batch := c.icount + stopCheckBatch
		if batch > limit {
			batch = limit
		}
		for c.icount < batch {
			pc := c.PC
			if pc == until {
				return nil
			}
			// One test covers both the alignment check and the fetch-cache
			// check. Alignment has to be checked per instruction because PC can
			// be set from outside (CallOffset, Hook.SetPC, RestoreContext) as
			// well as by a branch: the decoded-instruction array is indexed by
			// pc>>2 while the encoding is read from byte offset pc&0xfff, so a
			// misaligned PC would cache a garbage decode in the slot belonging
			// to the aligned address and, near a page end, index past the page.
			if (pc&3)|((pc>>PageBits)^m.fetchVPN) != 0 {
				if pc&3 != 0 {
					return &cpuError{fmt.Sprintf("misaligned instruction address 0x%x", pc)}
				}
				c.fetch(pc)
			}
			if len(c.codeHooks) != 0 {
				c.callCodeHooks(pc)
				if c.stopReq.Load() {
					return nil
				}
				if c.PC != pc {
					continue
				}
				// the hook may have invalidated the fetch cache
				if pc>>PageBits != m.fetchVPN {
					c.fetch(pc)
				}
			}
			in := &m.fetchCode.insts[(pc>>2)&(PageSize/4-1)]
			if in.fn == nil {
				decodeAt(in, m.fetchCode, pc)
			}
			in.fn(c, in)
			c.icount++
		}
		if c.icount >= limit {
			return nil
		}
	}
}

// stopCheckBatch is how many instructions run between reads of the stop flag.
const stopCheckBatch = 512

func (c *CPU) callCodeHooks(pc uint64) {
	for _, h := range c.codeHooks {
		if h.begin > h.end || (pc >= h.begin && pc <= h.end) {
			h.fn(pc, 4)
		}
	}
	// the hook may have remapped, reprotected or rewritten code
	c.Mem.fetchVPN = noVPN
}

func (c *CPU) fetch(pc uint64) {
	m := &c.Mem
	vpn := pc >> PageBits
	if e := &m.ctlb[vpn&ctlbMask]; e.vpn == vpn {
		m.fetchVPN, m.fetchCode = vpn, e.code
		return
	}
	p := m.guestPage(MemFetch, pc, 4, 0)
	if p.code == nil {
		p.code = &codePage{pg: p}
		if e := &m.wtlb[vpn&tlbMask]; e.vpn == vpn {
			e.vpn = noVPN // stores to this page must now drop the decoded code
		}
	}
	m.ctlb[vpn&ctlbMask] = codeEntry{vpn, p.code}
	m.fetchVPN, m.fetchCode = vpn, p.code
}

// raise delivers an exception to the interrupt hooks.
func (c *CPU) raise(intno uint32) {
	if len(c.intrHooks) == 0 {
		panic(&cpuError{fmt.Sprintf("unhandled exception %d at pc=0x%x", intno, c.PC)})
	}
	for _, h := range c.intrHooks {
		h.fn(intno)
	}
	c.Mem.fetchVPN = noVPN // the hook may have remapped or rewritten code
	if c.stopReq.Load() {
		// The hook asked to stop. Unwind now so it takes effect before the
		// next instruction: a BRK leaves PC on itself, so merely returning
		// would re-execute it until the batch ran out.
		panic(stopSignal{})
	}
}

// codePage holds the decoded instructions of one executable page.
type codePage struct {
	pg    *page
	insts [PageSize / 4]inst
}

func (cp *codePage) raw(pc uint64) uint32 {
	if cp.pg.data == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(cp.pg.data[pc&pageMask:])
}

// inst is one decoded instruction. The meaning of the operand fields is up to
// the handler; register fields hold R indices already remapped for SP/XZR.
// Kept at 32 bytes so two decoded instructions share a cache line: the
// instruction array is the interpreter's hottest memory, 8x the size of the
// guest code it mirrors. That is why the original encoding is not stored here
// — opUndef re-reads it from the code page, which costs nothing on a path that
// is about to raise an error anyway.
type inst struct {
	fn   func(*CPU, *inst)
	imm  uint64
	imm2 uint64
	rd   uint8
	rn   uint8
	rm   uint8
	ra   uint8
	cond uint8
	sh   uint8
	amt  uint8
	sz   uint8
}

func decodeAt(in *inst, cp *codePage, pc uint64) {
	*in = inst{}
	decode(in, cp.raw(pc), pc)
	if in.fn == nil {
		in.fn = opUndef
	}
}

func opUndef(c *CPU, i *inst) {
	raw := uint32(0)
	if cp := c.Mem.fetchCode; cp != nil {
		raw = cp.raw(c.PC)
	}
	panic(&UndefinedError{PC: c.PC, Insn: raw})
}

// ---- condition codes and flags ---------------------------------------------

// condTab[cond] has bit f set when cond holds for NZCV value f (N=8 Z=4 C=2 V=1).
var condTab [16]uint16

func init() {
	for f := 0; f < 16; f++ {
		n, z, cf, v := f&8 != 0, f&4 != 0, f&2 != 0, f&1 != 0
		base := [8]bool{z, cf, n, v, cf && !z, n == v, !z && n == v, true}
		for cc := 0; cc < 16; cc++ {
			r := base[cc>>1]
			if cc&1 == 1 && cc != 15 {
				r = !r
			}
			if r {
				condTab[cc] |= 1 << f
			}
		}
	}
}

func (c *CPU) cond(cc uint8) bool { return condTab[cc&15]>>(c.NZCV>>28)&1 != 0 }

func (c *CPU) carry() uint64 { return uint64(c.NZCV>>29) & 1 }

const (
	flagN = 1 << 31
	flagZ = 1 << 30
	flagC = 1 << 29
	flagV = 1 << 28
)

func addFlags64(a, b, cin uint64) (uint64, uint32) {
	r, co := bits.Add64(a, b, cin)
	f := uint32(r>>63)<<31 | uint32(co)<<29 | uint32(((a^r)&(b^r))>>63)<<28
	if r == 0 {
		f |= flagZ
	}
	return r, f
}

func addFlags32(a, b, cin uint32) (uint32, uint32) {
	r, co := bits.Add32(a, b, cin)
	f := (r>>31)<<31 | co<<29 | (((a^r)&(b^r))>>31)<<28
	if r == 0 {
		f |= flagZ
	}
	return r, f
}

func logicFlags64(r uint64) uint32 {
	f := uint32(r>>63) << 31
	if r == 0 {
		f |= flagZ
	}
	return f
}

func logicFlags32(r uint32) uint32 {
	f := (r >> 31) << 31
	if r == 0 {
		f |= flagZ
	}
	return f
}

// decode-time register index helpers
func xr(n uint32) uint8 { return uint8(n & 31) } // read, 31 = XZR
func xsp(n uint32) uint8 { // read or write, 31 = SP
	if n&31 == 31 {
		return rSP
	}
	return uint8(n & 31)
}
func xw(n uint32) uint8 { // write, 31 = XZR (discarded)
	if n&31 == 31 {
		return rSink
	}
	return uint8(n & 31)
}

func sext(v uint64, bitsN uint) uint64 { return uint64(int64(v<<(64-bitsN)) >> (64 - bitsN)) }
