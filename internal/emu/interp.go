// Pure-Go CPU backend: emu.Backend over the internal/arm64 interpreter.
//
// Unlike the unicorn and dynarmic backends this file carries no build tag and
// no cgo, so it is compiled into every build and a plain
//
//	CGO_ENABLED=0 go build ./...
//
// produces a binary that can actually run guest code. It registers as engine
// "interp"; the other two are preferred when compiled in (see registry.go).
package emu

import (
	"fmt"

	"github.com/sisi0318/gonidbg/internal/arm64"
)

func init() { Register("interp", newInterpBackend) }

type interpBackend struct {
	c *arm64.CPU
}

func newInterpBackend() (Backend, error) { return &interpBackend{c: arm64.New()}, nil }

// CodeHooksSupported: the interpreter calls code hooks per instruction.
func (b *interpBackend) CodeHooksSupported() bool { return true }

func (b *interpBackend) RegRead(r Reg) (uint64, error) {
	c := b.c
	switch r {
	case RegSP:
		return c.SP(), nil
	case RegPC:
		return c.PC, nil
	case RegLR:
		return c.X(30), nil
	case RegNZCV:
		return uint64(c.NZCV), nil
	case RegTPIDR_EL0:
		return c.TPIDR, nil
	case RegX23:
		return c.X(23), nil
	default:
		if r >= RegX0 && r <= RegX10 {
			return c.X(int(r - RegX0)), nil
		}
	}
	return 0, fmt.Errorf("emu(interp): reg_read: bad register id %d", int(r))
}

func (b *interpBackend) RegWrite(r Reg, val uint64) error {
	c := b.c
	switch r {
	case RegSP:
		c.SetSP(val)
	case RegPC:
		c.PC = val
	case RegLR:
		c.SetX(30, val)
	case RegNZCV:
		c.NZCV = uint32(val) & 0xf0000000
	case RegTPIDR_EL0:
		c.TPIDR = val
	case RegX23:
		c.SetX(23, val)
	default:
		if r >= RegX0 && r <= RegX10 {
			c.SetX(int(r-RegX0), val)
			return nil
		}
		return fmt.Errorf("emu(interp): reg_write: bad register id %d", int(r))
	}
	return nil
}

func (b *interpBackend) ReadGPRegs() ([34]uint64, error) {
	var out [34]uint64
	for i := 0; i < 31; i++ {
		out[i] = b.c.X(i)
	}
	out[31] = b.c.SP()
	out[32] = b.c.PC
	out[33] = uint64(b.c.NZCV)
	return out, nil
}

func (b *interpBackend) MemMap(addr, size uint64, prot int) error {
	return b.c.Mem.Map(addr, size, prot)
}

func (b *interpBackend) MemUnmap(addr, size uint64) error { return b.c.Mem.Unmap(addr, size) }

func (b *interpBackend) MemProtect(addr, size uint64, prot int) error {
	return b.c.Mem.Protect(addr, size, prot)
}

func (b *interpBackend) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return b.c.Mem.HostWrite(addr, data)
}

func (b *interpBackend) MemRead(addr uint64, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if size > MaxMemReadLen {
		return nil, fmt.Errorf("mem_read @0x%x: size %d exceeds MaxMemReadLen (%d)", addr, size, uint64(MaxMemReadLen))
	}
	buf := make([]byte, size)
	if err := b.c.Mem.HostRead(addr, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Hook callbacks are wrapped in guardHook so a panic in a syscall or JNI
// handler stops emulation and surfaces as a failed call, exactly as it does on
// the cgo backends (where an unguarded panic would abort the process).
func (b *interpBackend) HookCode(start, end uint64, fn CodeHookFunc) (HookHandle, error) {
	rm := b.c.AddCodeHook(start, end, func(addr uint64, size uint32) {
		defer guardHook(b, "code")
		fn(b, addr, size)
	})
	return funcHook(rm), nil
}

func (b *interpBackend) HookInterrupt(fn InterruptHookFunc) (HookHandle, error) {
	rm := b.c.AddInterruptHook(func(intno uint32) {
		defer guardHook(b, "interrupt")
		fn(b, intno)
	})
	return funcHook(rm), nil
}

func (b *interpBackend) HookMemInvalid(fn func(Backend, int, uint64, int, int64) bool) (HookHandle, error) {
	rm := b.c.Mem.AddInvalidHook(func(kind int, addr uint64, size int, value int64) (handled bool) {
		defer guardHook(b, "memory")
		return fn(b, kind, addr, size, value)
	})
	return funcHook(rm), nil
}

func (b *interpBackend) HookMemRead(start, end uint64, fn func(Backend, uint64, int)) (HookHandle, error) {
	rm := b.c.Mem.AddReadHook(start, end, func(addr uint64, size int, _ int64) {
		defer guardHook(b, "memory")
		fn(b, addr, size)
	})
	return funcHook(rm), nil
}

func (b *interpBackend) HookMemWrite(start, end uint64, fn func(Backend, uint64, int, int64)) (HookHandle, error) {
	rm := b.c.Mem.AddWriteHook(start, end, func(addr uint64, size int, value int64) {
		defer guardHook(b, "memory")
		fn(b, addr, size, value)
	})
	return funcHook(rm), nil
}

func (b *interpBackend) Start(begin, until uint64) error { return b.StartCount(begin, until, 0) }

func (b *interpBackend) StartCount(begin, until, count uint64) error {
	b.c.PC = begin
	if err := b.c.Run(until, count); err != nil {
		return fmt.Errorf("emu(interp): %w", err)
	}
	return nil
}

func (b *interpBackend) Stop() error { b.c.Stop(); return nil }

type interpContext struct{ x *arm64.Context }

func (c *interpContext) Free() error { c.x = nil; return nil }

func (b *interpBackend) SaveContext() (CPUContext, error) {
	return &interpContext{x: b.c.SaveContext()}, nil
}

func (b *interpBackend) RestoreContext(ctx CPUContext) error {
	c, ok := ctx.(*interpContext)
	if !ok || c.x == nil {
		return fmt.Errorf("emu(interp): invalid CPU context")
	}
	b.c.RestoreContext(c.x)
	return nil
}

// FlushCache drops every decoded instruction. The interpreter also drops them
// automatically on any write to the page they came from, so this is only
// needed to match the other backends' contract.
func (b *interpBackend) FlushCache() error { b.c.Mem.DropCode(); return nil }

func (b *interpBackend) Close() error { return nil }

// funcHook adapts a remover closure to HookHandle.
type funcHook func()

func (h funcHook) Remove() error {
	h()
	return nil
}
