// uc_shim: thin cross-platform C wrapper over libunicorn (loaded at RUNTIME via
// LoadLibrary/dlopen, so the Go link step never needs an import lib — only the
// headers at compile time).
//
// On Windows the engine is confined to a dedicated C thread and all uc_* calls
// are marshalled to it via a command pump. This is required because unicorn
// commits guest RAM on-fault through its own VEH, and Go's runtime exception
// handler would crash that fault on a Go-owned thread — but NOT on a thread Go
// doesn't manage. On Linux there is no such conflict (Go forwards SIGSEGV to
// cgo handlers) so calls run directly.
#ifndef DYSIGN_UC_SHIM_H
#define DYSIGN_UC_SHIM_H

#include <unicorn/unicorn.h>
#include <stdint.h>
#include <stddef.h>

typedef struct ucs_engine ucs_engine;

int          ucs_load(const char *path);              // 0 ok
unsigned int ucs_version(unsigned int *maj, unsigned int *min);
const char  *ucs_strerror(uc_err e);

ucs_engine *ucs_new(uc_err *err);                     // create engine (+thread on Win)
void        ucs_free(ucs_engine *e);

uc_err ucs_reg_read(ucs_engine *e, int regid, uint64_t *val);
uc_err ucs_reg_write(ucs_engine *e, int regid, uint64_t val);
// ucs_read_gpregs reads the GP register file in one engine-thread round-trip:
// out[0..30]=x0..x30, out[31]=sp, out[32]=pc, out[33]=nzcv. (For the tracer.)
uc_err ucs_read_gpregs(ucs_engine *e, uint64_t *out);
uc_err ucs_mem_map(ucs_engine *e, uint64_t addr, size_t size, uint32_t prot);
uc_err ucs_mem_unmap(ucs_engine *e, uint64_t addr, size_t size);
uc_err ucs_mem_protect(ucs_engine *e, uint64_t addr, size_t size, uint32_t prot);
uc_err ucs_mem_write(ucs_engine *e, uint64_t addr, const void *p, size_t n);
uc_err ucs_mem_read(ucs_engine *e, uint64_t addr, void *p, size_t n);
uc_err ucs_emu_start(ucs_engine *e, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);
uc_err ucs_emu_stop(ucs_engine *e);
uc_err ucs_flush_tb(ucs_engine *e); // invalidate translation cache (uc_ctl TB flush)

// CPU context save/restore for cooperative thread switching. The context is an
// opaque uc_context* (returned as void*); alloc/save/restore/free all run on the
// engine thread. ucs_context_alloc returns NULL (and *err != UC_ERR_OK) if the
// loaded libunicorn lacks the uc_context_* API.
void  *ucs_context_alloc(ucs_engine *e, uc_err *err);
uc_err ucs_context_save(ucs_engine *e, void *ctx);
uc_err ucs_context_restore(ucs_engine *e, void *ctx);
void   ucs_context_free(ucs_engine *e, void *ctx);

// Hooks. cbid is echoed back to the Go trampoline. The unicorn hook handle is
// returned in *hookOut for later removal.
uc_err ucs_hook_code(ucs_engine *e, uint64_t *hookOut, uint64_t begin, uint64_t end, uint64_t cbid);
uc_err ucs_hook_intr(ucs_engine *e, uint64_t *hookOut, uint64_t cbid);
uc_err ucs_hook_mem_invalid(ucs_engine *e, uint64_t *hookOut, uint64_t cbid);
uc_err ucs_hook_del(ucs_engine *e, uint64_t hook);

#endif
