// dyn_shim: a C ABI over dynarmic's C++-only A64 JIT, so cgo can drive it.
// dynarmic has no C API (only Dynarmic::A64::Jit + a UserCallbacks interface),
// so this shim wraps a Jit + an owned guest-memory page map and exposes the
// same surface emu.Backend needs (registers / map / read / write / run / stop).
//
// Guest memory lives here (a page map), and dynarmic reaches it through the
// MemoryRead*/MemoryWrite* callbacks — all C++->C++, no cgo crossing. Only SVC
// (CallSVC) and unmapped accesses trap back into Go. Because memory is callback-
// served (no fastmem/page-fault), there is no VEH/SIGSEGV interplay, so unlike
// the unicorn backend this needs no dedicated engine thread on Windows.
#ifndef DYSIGN_DYN_SHIM_H
#define DYSIGN_DYN_SHIM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dyn_engine dyn_engine;

// Abstract register ids (the Go side maps emu.Reg onto these). X0..X30 == 0..30.
enum {
	DYN_REG_SP        = 100,
	DYN_REG_PC        = 101,
	DYN_REG_NZCV      = 102,
	DYN_REG_TPIDR_EL0 = 103,
};

// Return codes.
enum {
	DYN_OK        = 0,
	DYN_ERR       = 1,
	DYN_ERR_REG   = 2,
	DYN_ERR_NOMEM = 3,
	DYN_ERR_RUN   = 4, // ran out of tick budget without reaching `until`
};

dyn_engine *dyn_new(void);
void        dyn_free(dyn_engine *e);
const char *dyn_strerror(int code);

int dyn_reg_read(dyn_engine *e, int regid, uint64_t *val);
int dyn_reg_write(dyn_engine *e, int regid, uint64_t val);
// dyn_read_gpregs fills out[0..30]=x0..x30, out[31]=sp, out[32]=pc, out[33]=nzcv.
int dyn_read_gpregs(dyn_engine *e, uint64_t *out);

int dyn_mem_map(dyn_engine *e, uint64_t addr, uint64_t size, uint32_t prot);
int dyn_mem_unmap(dyn_engine *e, uint64_t addr, uint64_t size);
int dyn_mem_protect(dyn_engine *e, uint64_t addr, uint64_t size, uint32_t prot);
int dyn_mem_write(dyn_engine *e, uint64_t addr, const void *p, uint64_t n);
int dyn_mem_read(dyn_engine *e, uint64_t addr, void *p, uint64_t n);

// Run from begin; stops cleanly when guest PC reaches `until` (executed via a
// deliberate no-execute fault), when dyn_emu_stop is called from a callback, or
// returns DYN_ERR_RUN if the instruction budget is exhausted.
int dyn_emu_start(dyn_engine *e, uint64_t begin, uint64_t until);
int dyn_emu_stop(dyn_engine *e);

// dyn_flush_cache drops all compiled blocks (call after patching guest code).
void dyn_flush_cache(dyn_engine *e);

// CPU context save/restore for cooperative thread switching: snapshots the full
// register file (X0..X30, SP, PC, PSTATE, TPIDR, V0..V31, FPCR, FPSR) into an
// opaque blob and reloads it. alloc returns NULL on OOM.
void *dyn_context_alloc(void);
void  dyn_context_free(void *ctx);
int   dyn_context_save(dyn_engine *e, void *ctx);
int   dyn_context_restore(dyn_engine *e, void *ctx);

// Hook wiring: cbid is echoed back to the Go trampolines (goDyn* in
// dynarmic_cgo.go). intr fires on SVC; mem fires on access to an unmapped page.
void dyn_set_intr_cb(dyn_engine *e, uint64_t cbid);
void dyn_set_mem_cb(dyn_engine *e, uint64_t cbid);

#ifdef __cplusplus
}
#endif

#endif
