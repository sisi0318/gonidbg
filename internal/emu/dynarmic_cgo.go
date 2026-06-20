//go:build dynarmic

// Real CPU backend #2: emu.Backend over dynarmic's A64 JIT, statically linked
// through the C++ shim (dyn_shim.*). Registered as engine "dynarmic"; pick it
// with -engine dynarmic / $GONIDBG_ENGINE=dynarmic when the binary is built with
// -tags dynarmic. Build (paths come from the dynarmic build, see build scripts):
//
//	CGO_ENABLED=1 CXX="zig c++" \
//	CGO_CXXFLAGS="-IC:/dynvendor/include -std=c++20" \
//	CGO_LDFLAGS="-LC:/dynvendor/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++" \
//	go build -tags dynarmic ./...
//
// Unlike the unicorn backend, dynarmic serves guest memory through callbacks
// (no fastmem page faults), so it needs no dedicated engine thread on Windows.
package emu

/*
#cgo CXXFLAGS: -std=c++20
#include "dyn_shim.h"
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

func init() { Register("dynarmic", newDynarmicBackend) }

// callback registry, independent of the unicorn backend's (which is gated behind
// a different build tag) so either engine can be built alone or together.
var (
	dynMu  sync.Mutex
	dynSeq uint64
	dynReg = map[uint64]*dynHookReg{}
)

type dynHookReg struct {
	be   *dynarmicBackend
	intr InterruptHookFunc
	mem  func(Backend, int, uint64, int, int64) bool
}

func dynRegister(h *dynHookReg) uint64 {
	dynMu.Lock()
	defer dynMu.Unlock()
	dynSeq++
	dynReg[dynSeq] = h
	return dynSeq
}
func dynUnregister(id uint64) { dynMu.Lock(); delete(dynReg, id); dynMu.Unlock() }
func dynLookup(id uint64) *dynHookReg {
	dynMu.Lock()
	defer dynMu.Unlock()
	return dynReg[id]
}

//export goDynIntrHook
func goDynIntrHook(cbid C.uint64_t, swi C.uint32_t) {
	if e := dynLookup(uint64(cbid)); e != nil && e.intr != nil {
		e.intr(e.be, uint32(swi))
	}
}

//export goDynMemHook
func goDynMemHook(cbid C.uint64_t, typ C.int, addr C.uint64_t, size C.int, value C.int64_t) C.int {
	e := dynLookup(uint64(cbid))
	if e == nil || e.mem == nil {
		return 0
	}
	if e.mem(e.be, int(typ), uint64(addr), int(size), int64(value)) {
		return 1
	}
	return 0
}

type dynarmicBackend struct {
	e   *C.dyn_engine
	cbs []uint64
}

func newDynarmicBackend() (Backend, error) {
	e := C.dyn_new()
	if e == nil {
		return nil, fmt.Errorf("emu: dyn_new failed (dynarmic engine init)")
	}
	return &dynarmicBackend{e: e}, nil
}

func dynErr(op string, code C.int) error {
	if code == C.DYN_OK {
		return nil
	}
	return fmt.Errorf("emu(dynarmic): %s: %s", op, C.GoString(C.dyn_strerror(code)))
}

func dynRegMap(r Reg) C.int {
	switch r {
	case RegX0, RegX1, RegX2, RegX3, RegX4, RegX5, RegX6, RegX7, RegX8, RegX9, RegX10:
		return C.int(r - RegX0) // emu.RegX0..RegX10 are contiguous -> 0..10
	case RegX23:
		return 23
	case RegSP:
		return C.DYN_REG_SP
	case RegPC:
		return C.DYN_REG_PC
	case RegLR:
		return 30 // X30
	case RegNZCV:
		return C.DYN_REG_NZCV
	case RegTPIDR_EL0:
		return C.DYN_REG_TPIDR_EL0
	default:
		return -1
	}
}

func (b *dynarmicBackend) RegRead(r Reg) (uint64, error) {
	var v C.uint64_t
	if e := C.dyn_reg_read(b.e, dynRegMap(r), &v); e != C.DYN_OK {
		return 0, dynErr("reg_read", e)
	}
	return uint64(v), nil
}

func (b *dynarmicBackend) RegWrite(r Reg, val uint64) error {
	return dynErr("reg_write", C.dyn_reg_write(b.e, dynRegMap(r), C.uint64_t(val)))
}

func (b *dynarmicBackend) ReadGPRegs() ([34]uint64, error) {
	var out [34]uint64
	if e := C.dyn_read_gpregs(b.e, (*C.uint64_t)(unsafe.Pointer(&out[0]))); e != C.DYN_OK {
		return out, dynErr("read_gpregs", e)
	}
	return out, nil
}

func (b *dynarmicBackend) MemMap(addr, size uint64, prot int) error {
	return dynErr("mem_map", C.dyn_mem_map(b.e, C.uint64_t(addr), C.uint64_t(size), C.uint32_t(prot)))
}

func (b *dynarmicBackend) MemUnmap(addr, size uint64) error {
	return dynErr("mem_unmap", C.dyn_mem_unmap(b.e, C.uint64_t(addr), C.uint64_t(size)))
}

func (b *dynarmicBackend) MemProtect(addr, size uint64, prot int) error {
	return dynErr("mem_protect", C.dyn_mem_protect(b.e, C.uint64_t(addr), C.uint64_t(size), C.uint32_t(prot)))
}

func (b *dynarmicBackend) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return dynErr("mem_write", C.dyn_mem_write(b.e, C.uint64_t(addr), unsafe.Pointer(&data[0]), C.uint64_t(len(data))))
}

func (b *dynarmicBackend) MemRead(addr uint64, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if e := C.dyn_mem_read(b.e, C.uint64_t(addr), unsafe.Pointer(&buf[0]), C.uint64_t(size)); e != C.DYN_OK {
		return nil, dynErr("mem_read", e)
	}
	return buf, nil
}

// HookCode: dynarmic has no generic per-instruction hook (it's a block JIT).
// The call path doesn't use code hooks (only the optional crypto register dump
// does), so this returns a no-op handle rather than failing.
func (b *dynarmicBackend) HookCode(start, end uint64, fn CodeHookFunc) (HookHandle, error) {
	return noopHook{}, nil
}

func (b *dynarmicBackend) HookInterrupt(fn InterruptHookFunc) (HookHandle, error) {
	id := dynRegister(&dynHookReg{be: b, intr: fn})
	C.dyn_set_intr_cb(b.e, C.uint64_t(id))
	b.cbs = append(b.cbs, id)
	return &dynHook{b, id}, nil
}

func (b *dynarmicBackend) HookMemInvalid(fn func(Backend, int, uint64, int, int64) bool) (HookHandle, error) {
	id := dynRegister(&dynHookReg{be: b, mem: fn})
	C.dyn_set_mem_cb(b.e, C.uint64_t(id))
	b.cbs = append(b.cbs, id)
	return &dynHook{b, id}, nil
}

func (b *dynarmicBackend) Start(begin, until uint64) error {
	return dynErr("emu_start", C.dyn_emu_start(b.e, C.uint64_t(begin), C.uint64_t(until)))
}

// StartCount: dynarmic's run has its own tick budget and no public instruction
// limit, so the count is advisory — run normally (the scheduler also preempts
// via the interrupt budget, which works on both engines).
func (b *dynarmicBackend) StartCount(begin, until, count uint64) error {
	return b.Start(begin, until)
}

func (b *dynarmicBackend) Stop() error {
	return dynErr("emu_stop", C.dyn_emu_stop(b.e))
}

// SaveContext/RestoreContext: full register snapshot (incl. vectors) is wired
// through the C++ shim (dyn_context_*). See dyn_shim.cpp.
func (b *dynarmicBackend) SaveContext() (CPUContext, error) {
	p := C.dyn_context_alloc()
	if p == nil {
		return nil, dynErr("context_alloc", C.DYN_ERR_NOMEM)
	}
	if e := C.dyn_context_save(b.e, p); e != C.DYN_OK {
		C.dyn_context_free(p)
		return nil, dynErr("context_save", e)
	}
	return &dynContext{p: p}, nil
}

func (b *dynarmicBackend) RestoreContext(ctx CPUContext) error {
	c, ok := ctx.(*dynContext)
	if !ok || c.p == nil {
		return dynErr("context_restore", C.DYN_ERR)
	}
	return dynErr("context_restore", C.dyn_context_restore(b.e, c.p))
}

type dynContext struct{ p unsafe.Pointer }

func (c *dynContext) Free() error {
	if c.p != nil {
		C.dyn_context_free(c.p)
		c.p = nil
	}
	return nil
}

func (b *dynarmicBackend) FlushCache() error {
	C.dyn_flush_cache(b.e)
	return nil
}

func (b *dynarmicBackend) Close() error {
	for _, id := range b.cbs {
		dynUnregister(id)
	}
	if b.e != nil {
		C.dyn_free(b.e)
		b.e = nil
	}
	return nil
}

type dynHook struct {
	b  *dynarmicBackend
	id uint64
}

func (h *dynHook) Remove() error { dynUnregister(h.id); return nil }

type noopHook struct{}

func (noopHook) Remove() error { return nil }
