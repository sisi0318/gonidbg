//go:build unicorn

// Real CPU backend: emu.Backend over libunicorn via the runtime-load command-
// pump shim (uc_shim.*). On Windows the engine lives on a dedicated C thread
// (the shim marshals every call to it) so unicorn's on-fault page commits are
// serviced by unicorn's VEH rather than crashed by Go's exception handler. On
// Linux the shim calls unicorn directly. Build:
//
//	CGO_ENABLED=1 CC="zig cc" \
//	CGO_CFLAGS="-IC:/ucvendor/include -fno-sanitize=undefined -fno-stack-protector" \
//	CGO_CFLAGS_ALLOW='.*' go build -tags unicorn ./...
package emu

/*
#include "uc_shim.h"
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

var loadOnce struct {
	sync.Once
	err error
}

func ensureLoaded() error {
	loadOnce.Do(func() {
		if rc := C.ucs_load(nil); rc != 0 {
			loadOnce.err = fmt.Errorf("emu: ucs_load failed rc=%d (set GONIDBG_UNICORN to the lib path)", int(rc))
		}
	})
	return loadOnce.err
}

// callback registry: cbid -> registration; C trampolines echo cbid back.
var (
	cbMu  sync.Mutex
	cbSeq uint64
	cbReg = map[uint64]*hookReg{}
)

type hookReg struct {
	be   *unicornBackend
	code CodeHookFunc
	intr InterruptHookFunc
	mem  func(Backend, int, uint64, int, int64) bool
}

func registerCB(h *hookReg) uint64 {
	cbMu.Lock()
	defer cbMu.Unlock()
	cbSeq++
	cbReg[cbSeq] = h
	return cbSeq
}
func unregisterCB(id uint64) { cbMu.Lock(); delete(cbReg, id); cbMu.Unlock() }
func lookupCB(id uint64) *hookReg {
	cbMu.Lock()
	defer cbMu.Unlock()
	return cbReg[id]
}

//export goCodeHook
func goCodeHook(cbid C.uint64_t, addr C.uint64_t, size C.uint32_t) {
	if e := lookupCB(uint64(cbid)); e != nil && e.code != nil {
		e.code(e.be, uint64(addr), uint32(size))
	}
}

//export goIntrHook
func goIntrHook(cbid C.uint64_t, intno C.uint32_t) {
	if e := lookupCB(uint64(cbid)); e != nil && e.intr != nil {
		e.intr(e.be, uint32(intno))
	}
}

//export goMemHook
func goMemHook(cbid C.uint64_t, typ C.int, addr C.uint64_t, size C.int, value C.int64_t) C.int {
	e := lookupCB(uint64(cbid))
	if e == nil || e.mem == nil {
		return 0
	}
	if e.mem(e.be, int(typ), uint64(addr), int(size), int64(value)) {
		return 1
	}
	return 0
}

func init() { Register("unicorn", newUnicornBackend) }

type unicornBackend struct {
	e   *C.ucs_engine
	cbs []uint64
}

func newUnicornBackend() (Backend, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	var cerr C.uc_err
	e := C.ucs_new(&cerr)
	if e == nil {
		return nil, ucErr("ucs_new", cerr)
	}
	return &unicornBackend{e: e}, nil
}

func ucErr(op string, e C.uc_err) error {
	return fmt.Errorf("emu: %s: %s", op, C.GoString(C.ucs_strerror(e)))
}

func regMap(r Reg) C.int {
	switch r {
	case RegX0:
		return C.UC_ARM64_REG_X0
	case RegX1:
		return C.UC_ARM64_REG_X1
	case RegX2:
		return C.UC_ARM64_REG_X2
	case RegX3:
		return C.UC_ARM64_REG_X3
	case RegX4:
		return C.UC_ARM64_REG_X4
	case RegX5:
		return C.UC_ARM64_REG_X5
	case RegX6:
		return C.UC_ARM64_REG_X6
	case RegX7:
		return C.UC_ARM64_REG_X7
	case RegX8:
		return C.UC_ARM64_REG_X8
	case RegX9:
		return C.UC_ARM64_REG_X9
	case RegX10:
		return C.UC_ARM64_REG_X10
	case RegX23:
		return C.UC_ARM64_REG_X23
	case RegSP:
		return C.UC_ARM64_REG_SP
	case RegPC:
		return C.UC_ARM64_REG_PC
	case RegLR:
		return C.UC_ARM64_REG_X30
	case RegNZCV:
		return C.UC_ARM64_REG_NZCV
	case RegTPIDR_EL0:
		return C.UC_ARM64_REG_TPIDR_EL0
	default:
		return C.UC_ARM64_REG_INVALID
	}
}

func (b *unicornBackend) RegRead(r Reg) (uint64, error) {
	var v C.uint64_t
	if e := C.ucs_reg_read(b.e, regMap(r), &v); e != C.UC_ERR_OK {
		return 0, ucErr("reg_read", e)
	}
	return uint64(v), nil
}

func (b *unicornBackend) RegWrite(r Reg, val uint64) error {
	if e := C.ucs_reg_write(b.e, regMap(r), C.uint64_t(val)); e != C.UC_ERR_OK {
		return ucErr("reg_write", e)
	}
	return nil
}

func (b *unicornBackend) ReadGPRegs() ([34]uint64, error) {
	var out [34]uint64
	if e := C.ucs_read_gpregs(b.e, (*C.uint64_t)(unsafe.Pointer(&out[0]))); e != C.UC_ERR_OK {
		return out, ucErr("read_gpregs", e)
	}
	return out, nil
}

func (b *unicornBackend) MemMap(addr, size uint64, prot int) error {
	if e := C.ucs_mem_map(b.e, C.uint64_t(addr), C.size_t(size), C.uint32_t(prot)); e != C.UC_ERR_OK {
		return ucErr("mem_map", e)
	}
	return nil
}

func (b *unicornBackend) MemUnmap(addr, size uint64) error {
	if e := C.ucs_mem_unmap(b.e, C.uint64_t(addr), C.size_t(size)); e != C.UC_ERR_OK {
		return ucErr("mem_unmap", e)
	}
	return nil
}

func (b *unicornBackend) MemProtect(addr, size uint64, prot int) error {
	if e := C.ucs_mem_protect(b.e, C.uint64_t(addr), C.size_t(size), C.uint32_t(prot)); e != C.UC_ERR_OK {
		return ucErr("mem_protect", e)
	}
	return nil
}

func (b *unicornBackend) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if e := C.ucs_mem_write(b.e, C.uint64_t(addr), unsafe.Pointer(&data[0]), C.size_t(len(data))); e != C.UC_ERR_OK {
		return ucErr("mem_write", e)
	}
	return nil
}

func (b *unicornBackend) MemRead(addr uint64, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if e := C.ucs_mem_read(b.e, C.uint64_t(addr), unsafe.Pointer(&buf[0]), C.size_t(size)); e != C.UC_ERR_OK {
		return nil, ucErr("mem_read", e)
	}
	return buf, nil
}

func (b *unicornBackend) HookCode(start, end uint64, fn CodeHookFunc) (HookHandle, error) {
	id := registerCB(&hookReg{be: b, code: fn})
	var hh C.uint64_t
	if e := C.ucs_hook_code(b.e, &hh, C.uint64_t(start), C.uint64_t(end), C.uint64_t(id)); e != C.UC_ERR_OK {
		unregisterCB(id)
		return nil, ucErr("hook_code", e)
	}
	b.cbs = append(b.cbs, id)
	return &ucHook{b, uint64(hh), id}, nil
}

func (b *unicornBackend) HookInterrupt(fn InterruptHookFunc) (HookHandle, error) {
	id := registerCB(&hookReg{be: b, intr: fn})
	var hh C.uint64_t
	if e := C.ucs_hook_intr(b.e, &hh, C.uint64_t(id)); e != C.UC_ERR_OK {
		unregisterCB(id)
		return nil, ucErr("hook_intr", e)
	}
	b.cbs = append(b.cbs, id)
	return &ucHook{b, uint64(hh), id}, nil
}

func (b *unicornBackend) HookMemInvalid(fn func(Backend, int, uint64, int, int64) bool) (HookHandle, error) {
	id := registerCB(&hookReg{be: b, mem: fn})
	var hh C.uint64_t
	if e := C.ucs_hook_mem_invalid(b.e, &hh, C.uint64_t(id)); e != C.UC_ERR_OK {
		unregisterCB(id)
		return nil, ucErr("hook_mem", e)
	}
	b.cbs = append(b.cbs, id)
	return &ucHook{b, uint64(hh), id}, nil
}

func (b *unicornBackend) Start(begin, until uint64) error {
	if e := C.ucs_emu_start(b.e, C.uint64_t(begin), C.uint64_t(until), 0, 0); e != C.UC_ERR_OK {
		return ucErr("emu_start", e)
	}
	return nil
}

func (b *unicornBackend) StartCount(begin, until, count uint64) error {
	if e := C.ucs_emu_start(b.e, C.uint64_t(begin), C.uint64_t(until), 0, C.size_t(count)); e != C.UC_ERR_OK {
		return ucErr("emu_start", e)
	}
	return nil
}

func (b *unicornBackend) Stop() error {
	if e := C.ucs_emu_stop(b.e); e != C.UC_ERR_OK {
		return ucErr("emu_stop", e)
	}
	return nil
}

// ucContext wraps a uc_context* (engine-allocated full CPU snapshot).
type ucContext struct {
	b   *unicornBackend
	ptr unsafe.Pointer
}

func (c *ucContext) Free() error {
	if c.ptr != nil {
		C.ucs_context_free(c.b.e, c.ptr)
		c.ptr = nil
	}
	return nil
}

func (b *unicornBackend) SaveContext() (CPUContext, error) {
	var cerr C.uc_err
	p := C.ucs_context_alloc(b.e, &cerr)
	if p == nil || cerr != C.UC_ERR_OK {
		return nil, ucErr("context_alloc", cerr)
	}
	if e := C.ucs_context_save(b.e, p); e != C.UC_ERR_OK {
		C.ucs_context_free(b.e, p)
		return nil, ucErr("context_save", e)
	}
	return &ucContext{b: b, ptr: p}, nil
}

func (b *unicornBackend) RestoreContext(ctx CPUContext) error {
	c, ok := ctx.(*ucContext)
	if !ok || c.ptr == nil {
		return fmt.Errorf("emu: invalid CPU context")
	}
	if e := C.ucs_context_restore(b.e, c.ptr); e != C.UC_ERR_OK {
		return ucErr("context_restore", e)
	}
	return nil
}

func (b *unicornBackend) FlushCache() error {
	if e := C.ucs_flush_tb(b.e); e != C.UC_ERR_OK {
		return ucErr("flush_tb", e)
	}
	return nil
}

func (b *unicornBackend) Close() error {
	for _, id := range b.cbs {
		unregisterCB(id)
	}
	if b.e != nil {
		C.ucs_free(b.e)
		b.e = nil
	}
	return nil
}

type ucHook struct {
	b  *unicornBackend
	hh uint64
	id uint64
}

func (h *ucHook) Remove() error {
	unregisterCB(h.id)
	if e := C.ucs_hook_del(h.b.e, C.uint64_t(h.hh)); e != C.UC_ERR_OK {
		return ucErr("hook_del", e)
	}
	return nil
}
