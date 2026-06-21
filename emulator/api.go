package emulator

import (
	"encoding/binary"
	"fmt"

	"github.com/sisi0318/gonidbg/internal/emu"
)

// Guest memory protection bits (mirror the CPU backend's UC_PROT_*).
const (
	ProtNone  = emu.ProtNone
	ProtRead  = emu.ProtRead
	ProtWrite = emu.ProtWrite
	ProtExec  = emu.ProtExec
	ProtAll   = emu.ProtAll
)

// Alloc maps a fresh guest region with the given protection and returns its base.
func (e *Emulator) Alloc(size uint64, prot int) uint64 {
	a := e.mem.Mmap(size, prot, "alloc")
	_ = e.be.MemMap(a, (size+0xfff)&^0xfff, prot)
	return a
}

// Malloc maps a fresh read/write guest region and returns its base.
func (e *Emulator) Malloc(size uint64) uint64 { return e.Alloc(size, ProtRead|ProtWrite) }

// WriteScratch copies bytes into a fresh RW region and returns the address.
func (e *Emulator) WriteScratch(data []byte) uint64 {
	a := e.Alloc(uint64(len(data))+16, ProtRead|ProtWrite)
	_ = e.be.MemWrite(a, data)
	return a
}

// WriteBytes writes raw bytes to guest memory at addr.
func (e *Emulator) WriteBytes(addr uint64, data []byte) error { return e.be.MemWrite(addr, data) }

// ReadBytes reads n bytes from guest memory at addr.
func (e *Emulator) ReadBytes(addr, n uint64) ([]byte, error) { return e.be.MemRead(addr, n) }

// WriteCString writes s followed by a NUL terminator at addr.
func (e *Emulator) WriteCString(addr uint64, s string) error {
	return e.be.MemWrite(addr, append([]byte(s), 0))
}

// WriteCStringAlloc allocates a region, writes s+NUL, and returns its address.
func (e *Emulator) WriteCStringAlloc(s string) uint64 { return e.WriteScratch(append([]byte(s), 0)) }

// ReadU32 / ReadU64 read a little-endian integer from guest memory.
func (e *Emulator) ReadU32(addr uint64) (uint32, error) {
	b, err := e.be.MemRead(addr, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
func (e *Emulator) ReadU64(addr uint64) (uint64, error) {
	b, err := e.be.MemRead(addr, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// WriteU32 / WriteU64 write a little-endian integer to guest memory.
func (e *Emulator) WriteU32(addr uint64, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return e.be.MemWrite(addr, b[:])
}
func (e *Emulator) WriteU64(addr uint64, v uint64) error { return putU64(e.be, addr, v) }

// ReadCStr reads a NUL-terminated string from guest memory.
func (e *Emulator) ReadCStr(addr uint64) (string, error) {
	var out []byte
	for {
		b, err := e.be.MemRead(addr+uint64(len(out)), 64)
		if err != nil {
			return "", err
		}
		for _, c := range b {
			if c == 0 {
				return string(out), nil
			}
			out = append(out, c)
		}
		if len(out) > 1<<20 {
			return string(out), nil
		}
	}
}

// ReadCString is an alias for ReadCStr (unidbg-style naming).
func (e *Emulator) ReadCString(addr uint64) (string, error) { return e.ReadCStr(addr) }

// ---- function replacement (native hook) -----------------------------------

// Hook is the context passed to a Replace callback: read the incoming args and
// reach the emulator for memory access; the callback's return value becomes X0.
type Hook struct{ e *Emulator }

// Emu returns the emulator, for memory access inside a Replace callback.
func (h *Hook) Emu() *Emulator { return h.e }

// Arg returns integer argument / register Xi (0-based, X0..X7).
func (h *Hook) Arg(i int) uint64 {
	if i < 0 || i > 7 {
		return 0
	}
	v, _ := h.e.be.RegRead(emu.RegX0 + emu.Reg(i))
	return v
}

// Reg returns register Xi for any i in 0..30 (also 31=SP, 32=PC, 33=NZCV) via the
// full GP register file. Use this instead of Arg for X8..X30 (Arg only covers X0..X7).
func (h *Hook) Reg(i int) uint64 {
	if i < 0 || i > 33 {
		return 0
	}
	regs, err := h.e.be.ReadGPRegs()
	if err != nil {
		return 0
	}
	return regs[i]
}

// SetArg sets register Xi (0..7) — e.g. to rewrite an argument from an inline hook.
func (h *Hook) SetArg(i int, v uint64) {
	if i >= 0 && i <= 7 {
		_ = h.e.be.RegWrite(emu.RegX0+emu.Reg(i), v)
	}
}

// PC / SP / LR read those registers (handy inside an inline hook).
func (h *Hook) PC() uint64 { v, _ := h.e.be.RegRead(emu.RegPC); return v }
func (h *Hook) SP() uint64 { v, _ := h.e.be.RegRead(emu.RegSP); return v }
func (h *Hook) LR() uint64 { v, _ := h.e.be.RegRead(emu.RegLR); return v }

// SetPC redirects execution (e.g. skip an instruction, jump elsewhere).
func (h *Hook) SetPC(v uint64) { _ = h.e.be.RegWrite(emu.RegPC, v) }

// ReplaceFunc is a Go stand-in for a native function; its return value is the
// function's return (X0).
type ReplaceFunc func(h *Hook) uint64

// Replace makes calls to the function at addr run fn instead (the entry is
// overwritten with an `svc; ret` trampoline). This is gonidbg's analogue of
// unidbg's hook/replace: model or stub a native function in Go. Works on both
// engines (it's a trap, not an inline patch).
func (e *Emulator) Replace(addr uint64, fn ReplaceFunc) {
	e.replaced[addr] = func(em *Emulator, b emu.Backend) {
		ret := fn(&Hook{em})
		_ = b.RegWrite(emu.RegX0, ret)
	}
	// svc #0 ; ret  — trap to onInterrupt, which dispatches to e.replaced[addr].
	_ = e.be.MemWrite(addr, []byte{0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6})
	_ = e.be.FlushCache() // drop any stale translation of the old code
}

// ReplaceSymbol is Replace by exported symbol name.
func (e *Emulator) ReplaceSymbol(name string, fn ReplaceFunc) error {
	addr, ok := e.Sym(name)
	if !ok {
		return fmt.Errorf("symbol %q not found", name)
	}
	e.Replace(addr, fn)
	return nil
}

// ---- inline hooks ----------------------------------------------------------

// HookAddr installs an inline hook that fires every time guest PC reaches addr
// (mid-function, not just at the entry like Replace). The callback reads/edits
// registers via *Hook — rewrite an argument, capture a value, or SetPC to skip
// or redirect. Returns a remover.
//
// Requires the Unicorn engine: dynarmic is a block JIT with no per-instruction
// hook, so HookAddr errors there (use Replace for function-entry interception).
func (e *Emulator) HookAddr(addr uint64, fn func(h *Hook)) (func(), error) {
	if e.engine != "unicorn" {
		return nil, fmt.Errorf("HookAddr: inline hooks require the unicorn engine (current %q); use Replace for entry hooks", e.engine)
	}
	h, err := e.be.HookCode(addr, addr, func(b emu.Backend, a uint64, size uint32) {
		fn(&Hook{e})
	})
	if err != nil {
		return nil, err
	}
	return func() { _ = h.Remove() }, nil
}

// HookSymbol is HookAddr by exported symbol name.
func (e *Emulator) HookSymbol(name string, fn func(h *Hook)) (func(), error) {
	addr, ok := e.Sym(name)
	if !ok {
		return nil, fmt.Errorf("symbol %q not found", name)
	}
	return e.HookAddr(addr, fn)
}

// HookRange installs a per-instruction hook over [start,end); fn gets the Hook
// and the current PC. Like HookAddr but for a whole region (Unicorn only).
func (e *Emulator) HookRange(start, end uint64, fn func(h *Hook, addr uint64)) (func(), error) {
	if e.engine != "unicorn" {
		return nil, fmt.Errorf("HookRange requires the unicorn engine (current %q)", e.engine)
	}
	h, err := e.be.HookCode(start, end, func(b emu.Backend, a uint64, size uint32) {
		fn(&Hook{e}, a)
	})
	if err != nil {
		return nil, err
	}
	return func() { _ = h.Remove() }, nil
}

// ---- tracing ---------------------------------------------------------------

// Trace prints every executed instruction's PC (with nearest symbol) in
// [start,end). Returns a remover. Requires a backend with per-instruction
// hooks (Unicorn); on dynarmic this is a no-op (block JIT, no instr hook).
func (e *Emulator) Trace(start, end uint64) (func(), error) {
	h, err := e.be.HookCode(start, end, func(b emu.Backend, addr uint64, size uint32) {
		fmt.Printf("[trace] 0x%x  %s\n", addr, e.NearestSym(addr))
	})
	if err != nil {
		return nil, err
	}
	return func() { _ = h.Remove() }, nil
}
