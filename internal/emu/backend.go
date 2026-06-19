// Package emu defines the CPU backend abstraction — the single component that
// cannot be written in pure Go. It mirrors the surface unidbg's
// com.github.unidbg.arm.backend.Backend exposes and that unidbg uses:
// register access, guest memory map/read/write/protect, code hooks, and
// run/stop.
//
// Like unidbg, the engine is selectable. Concrete backends are compiled in via
// build tags and register themselves (see registry.go):
//
//	-tags unicorn   -> Unicorn2 via cgo, runtime-loaded libunicorn (unicorn_cgo.go)
//	-tags dynarmic  -> dynarmic JIT, statically linked C++ (dynarmic_cgo.go)
//
// Build with both to choose at run time (arg / $GONIDBG_ENGINE). Everything else
// in this module is written against this interface so it compiles and is
// testable without a C toolchain (a pure-Go build registers no backend).
package emu

import "errors"

// ErrNoBackend is returned when no CPU backend is compiled in (a pure-Go build
// with neither the `unicorn` nor the `dynarmic` build tag).
var ErrNoBackend = errors.New("emu: no CPU backend compiled in (build with -tags unicorn and/or -tags dynarmic)")

// Prot bits for mem_map / mem_protect (match Unicorn UC_PROT_*).
const (
	ProtNone  = 0
	ProtRead  = 1
	ProtWrite = 2
	ProtExec  = 4
	ProtAll   = ProtRead | ProtWrite | ProtExec
)

// Reg is an abstract ARM64 register id. Each backend translates it to its own
// numbering (e.g. unicorn.ARM64_REG_*). Keeping it abstract avoids baking
// engine-specific enum values into the rest of the code.
type Reg int

const (
	RegX0 Reg = iota
	RegX1
	RegX2
	RegX3
	RegX4
	RegX5
	RegX6
	RegX7
	RegX8
	RegX9
	RegX10
	RegX23 // used by the crypto register-dump hook in the host app
	RegSP
	RegPC
	RegLR  // X30
	RegNZCV
	RegTPIDR_EL0
)

// CodeHookFunc fires for each hooked instruction/range. addr is the guest PC,
// size the instruction size. Mirrors the host app's CodeHook.hook(...).
type CodeHookFunc func(b Backend, addr uint64, size uint32)

// InterruptHookFunc fires on SVC/exception. swi is the syscall/exception id.
// The syscall handler registers one of these to service guest syscalls.
type InterruptHookFunc func(b Backend, intno uint32)

// Backend is the CPU + memory engine. A Unicorn2 cgo wrapper implements it.
type Backend interface {
	// Registers
	RegRead(reg Reg) (uint64, error)
	RegWrite(reg Reg, val uint64) error

	// Memory
	MemMap(addr, size uint64, prot int) error
	MemUnmap(addr, size uint64) error
	MemProtect(addr, size uint64, prot int) error
	MemWrite(addr uint64, data []byte) error
	MemRead(addr uint64, size uint64) ([]byte, error)

	// Hooks
	HookCode(start, end uint64, fn CodeHookFunc) (HookHandle, error)
	HookInterrupt(fn InterruptHookFunc) (HookHandle, error)
	HookMemInvalid(fn func(b Backend, typ int, addr uint64, size int, value int64) bool) (HookHandle, error)

	// Execution
	Start(begin, until uint64) error
	Stop() error

	// FlushCache invalidates the engine's translated/JIT'd code cache. Call after
	// writing new code into an executable region (self-modifying code / Replace),
	// otherwise a previously executed block keeps running its stale translation.
	FlushCache() error

	Close() error
}

// HookHandle lets a hook be removed.
type HookHandle interface{ Remove() error }
