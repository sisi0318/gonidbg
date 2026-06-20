//go:build unicorn

#include "uc_shim.h"
#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
static void *dlload(const char *p) { return (void *)LoadLibraryA(p); }
static void *dlfn(void *h, const char *n) { return (void *)GetProcAddress((HMODULE)h, n); }
#else
#include <dlfcn.h>
#include <pthread.h>
static void *dlload(const char *p) { return dlopen(p, RTLD_NOW | RTLD_GLOBAL); }
static void *dlfn(void *h, const char *n) { return dlsym(h, n); }
#endif

// ---- libunicorn entry points, resolved at runtime --------------------------
typedef uc_err (*pf_open)(uc_arch, uc_mode, uc_engine **);
typedef uc_err (*pf_close)(uc_engine *);
typedef uc_err (*pf_reg_read)(uc_engine *, int, void *);
typedef uc_err (*pf_reg_write)(uc_engine *, int, const void *);
typedef uc_err (*pf_mem_map)(uc_engine *, uint64_t, size_t, uint32_t);
typedef uc_err (*pf_mem_unmap)(uc_engine *, uint64_t, size_t);
typedef uc_err (*pf_mem_protect)(uc_engine *, uint64_t, size_t, uint32_t);
typedef uc_err (*pf_mem_write)(uc_engine *, uint64_t, const void *, size_t);
typedef uc_err (*pf_mem_read)(uc_engine *, uint64_t, void *, size_t);
typedef uc_err (*pf_emu_start)(uc_engine *, uint64_t, uint64_t, uint64_t, size_t);
typedef uc_err (*pf_emu_stop)(uc_engine *);
typedef uc_err (*pf_hook_add)(uc_engine *, uc_hook *, int, void *, void *, uint64_t, uint64_t, ...);
typedef uc_err (*pf_hook_del)(uc_engine *, uc_hook);
typedef unsigned int (*pf_version)(unsigned int *, unsigned int *);
typedef const char *(*pf_strerror)(uc_err);
typedef uc_err (*pf_ctl)(uc_engine *, int, ...);
typedef uc_err (*pf_ctx_alloc)(uc_engine *, uc_context **);
typedef uc_err (*pf_ctx_save)(uc_engine *, uc_context *);
typedef uc_err (*pf_ctx_restore)(uc_engine *, uc_context *);
typedef uc_err (*pf_ctx_free)(uc_context *);

static pf_open P_open; static pf_close P_close;
static pf_reg_read P_rr; static pf_reg_write P_rw;
static pf_mem_map P_map; static pf_mem_unmap P_unmap; static pf_mem_protect P_prot;
static pf_mem_write P_mw; static pf_mem_read P_mr;
static pf_emu_start P_start; static pf_emu_stop P_stop;
static pf_hook_add P_hadd; static pf_hook_del P_hdel;
static pf_version P_ver; static pf_strerror P_serr;
static pf_ctl P_ctl;
static pf_ctx_alloc P_ctxalloc; static pf_ctx_save P_ctxsave;
static pf_ctx_restore P_ctxrestore; static pf_ctx_free P_ctxfree;

int ucs_load(const char *path) {
	const char *env = getenv("GONIDBG_UNICORN");
	void *h = NULL;
	if (path && path[0]) h = dlload(path);
	if (!h && env && env[0]) h = dlload(env);
#if defined(_WIN32)
	if (!h) h = dlload("unicorn.dll");
	if (!h) h = dlload("C:/ucvendor/unicorn.dll");
#else
	if (!h) h = dlload("libunicorn.so.2");
	if (!h) h = dlload("libunicorn.so");
#endif
	if (!h) return 1;
	P_open=(pf_open)dlfn(h,"uc_open");        P_close=(pf_close)dlfn(h,"uc_close");
	P_rr=(pf_reg_read)dlfn(h,"uc_reg_read");  P_rw=(pf_reg_write)dlfn(h,"uc_reg_write");
	P_map=(pf_mem_map)dlfn(h,"uc_mem_map");   P_unmap=(pf_mem_unmap)dlfn(h,"uc_mem_unmap");
	P_prot=(pf_mem_protect)dlfn(h,"uc_mem_protect");
	P_mw=(pf_mem_write)dlfn(h,"uc_mem_write"); P_mr=(pf_mem_read)dlfn(h,"uc_mem_read");
	P_start=(pf_emu_start)dlfn(h,"uc_emu_start"); P_stop=(pf_emu_stop)dlfn(h,"uc_emu_stop");
	P_hadd=(pf_hook_add)dlfn(h,"uc_hook_add"); P_hdel=(pf_hook_del)dlfn(h,"uc_hook_del");
	P_ver=(pf_version)dlfn(h,"uc_version");    P_serr=(pf_strerror)dlfn(h,"uc_strerror");
	P_ctl=(pf_ctl)dlfn(h,"uc_ctl"); // optional (FlushCache); absent only on very old builds
	// optional (cooperative scheduler context save/restore); absent only on very old builds
	P_ctxalloc=(pf_ctx_alloc)dlfn(h,"uc_context_alloc");
	P_ctxsave=(pf_ctx_save)dlfn(h,"uc_context_save");
	P_ctxrestore=(pf_ctx_restore)dlfn(h,"uc_context_restore");
	P_ctxfree=(pf_ctx_free)dlfn(h,"uc_context_free");
	if (!P_open||!P_close||!P_rr||!P_rw||!P_map||!P_unmap||!P_prot||
	    !P_mw||!P_mr||!P_start||!P_stop||!P_hadd||!P_hdel) return 2;
	return 0;
}

unsigned int ucs_version(unsigned int *M, unsigned int *m){ return P_ver?P_ver(M,m):0; }
const char  *ucs_strerror(uc_err e){ return P_serr?P_serr(e):"?"; }

// ---- hook trampolines: unicorn -> Go ---------------------------------------
extern void goCodeHook(uint64_t cbid, uint64_t addr, uint32_t size);
extern void goIntrHook(uint64_t cbid, uint32_t intno);
extern int  goMemHook(uint64_t cbid, int type, uint64_t addr, int size, int64_t value);

static void code_tramp(uc_engine *uc, uint64_t addr, uint32_t size, void *user){
	(void)uc; goCodeHook((uint64_t)(uintptr_t)user, addr, size);
}
static void intr_tramp(uc_engine *uc, uint32_t intno, void *user){
	(void)uc; goIntrHook((uint64_t)(uintptr_t)user, intno);
}
static bool mem_tramp(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user){
	(void)uc; return goMemHook((uint64_t)(uintptr_t)user, (int)type, addr, size, value) != 0;
}

// ---- command model ---------------------------------------------------------
enum {
	OP_REGREAD=1, OP_REGWRITE, OP_MAP, OP_UNMAP, OP_PROTECT, OP_WRITE, OP_READ,
	OP_START, OP_STOP, OP_HOOKCODE, OP_HOOKINTR, OP_HOOKMEM, OP_HOOKDEL, OP_FLUSH,
	OP_CTXALLOC, OP_CTXSAVE, OP_CTXRESTORE, OP_CTXFREE, OP_QUIT
};

typedef struct {
	int op;
	uint64_t a0, a1, a2, a3;
	const void *cptr;
	void *ptr;
	uint64_t cbid;
	uc_err ret;
	uint64_t rval; // reg value / hook handle
} ucs_cmd;

struct ucs_engine {
	uc_engine *uc;
	uc_err open_err;
#if defined(_WIN32)
	HANDLE thread; DWORD tid;
	HANDLE ready, done, inited;
	CRITICAL_SECTION lock;
	ucs_cmd *cur;
#endif
};

// Execute one command on the engine (runs on the engine thread, or directly on
// Linux / when already on the engine thread).
static void ucs_dispatch(ucs_engine *e, ucs_cmd *c){
	uc_engine *uc = e->uc;
	uc_hook hh;
	switch (c->op) {
	case OP_REGREAD:  c->ret = P_rr(uc, (int)c->a0, &c->rval); break;
	case OP_REGWRITE: { uint64_t v=c->a1; c->ret = P_rw(uc, (int)c->a0, &v); break; }
	case OP_MAP:      c->ret = P_map(uc, c->a0, (size_t)c->a1, (uint32_t)c->a2); break;
	case OP_UNMAP:    c->ret = P_unmap(uc, c->a0, (size_t)c->a1); break;
	case OP_PROTECT:  c->ret = P_prot(uc, c->a0, (size_t)c->a1, (uint32_t)c->a2); break;
	case OP_WRITE:    c->ret = P_mw(uc, c->a0, c->cptr, (size_t)c->a1); break;
	case OP_READ:     c->ret = P_mr(uc, c->a0, c->ptr, (size_t)c->a1); break;
	case OP_START:    c->ret = P_start(uc, c->a0, c->a1, c->a2, (size_t)c->a3); break;
	case OP_STOP:     c->ret = P_stop(uc); break;
	case OP_HOOKCODE: c->ret = P_hadd(uc,&hh,UC_HOOK_CODE,(void*)code_tramp,(void*)(uintptr_t)c->cbid,c->a0,c->a1); c->rval=(uint64_t)hh; break;
	case OP_HOOKINTR: c->ret = P_hadd(uc,&hh,UC_HOOK_INTR,(void*)intr_tramp,(void*)(uintptr_t)c->cbid,(uint64_t)1,(uint64_t)0); c->rval=(uint64_t)hh; break;
	case OP_HOOKMEM:  c->ret = P_hadd(uc,&hh,UC_HOOK_MEM_UNMAPPED|UC_HOOK_MEM_PROT,(void*)mem_tramp,(void*)(uintptr_t)c->cbid,(uint64_t)1,(uint64_t)0); c->rval=(uint64_t)hh; break;
	case OP_HOOKDEL:  c->ret = P_hdel(uc, (uc_hook)c->a0); break;
	case OP_FLUSH:    c->ret = P_ctl ? P_ctl(uc, UC_CTL_WRITE(UC_CTL_TB_FLUSH, 0)) : UC_ERR_OK; break;
	case OP_CTXALLOC: {
		uc_context *ctx = NULL;
		c->ret = P_ctxalloc ? P_ctxalloc(uc, &ctx) : UC_ERR_HANDLE;
		c->rval = (uint64_t)(uintptr_t)ctx;
		break;
	}
	case OP_CTXSAVE:    c->ret = P_ctxsave ? P_ctxsave(uc, (uc_context*)(uintptr_t)c->a0) : UC_ERR_HANDLE; break;
	case OP_CTXRESTORE: c->ret = P_ctxrestore ? P_ctxrestore(uc, (uc_context*)(uintptr_t)c->a0) : UC_ERR_HANDLE; break;
	case OP_CTXFREE:    c->ret = P_ctxfree ? P_ctxfree((uc_context*)(uintptr_t)c->a0) : UC_ERR_OK; break;
	default:          c->ret = UC_ERR_ARG; break;
	}
}

#if defined(_WIN32)
static DWORD WINAPI engine_loop(LPVOID arg){
	ucs_engine *e = (ucs_engine*)arg;
	e->open_err = P_open(UC_ARCH_ARM64, UC_MODE_ARM, &e->uc);
	SetEvent(e->inited);
	if (e->open_err != UC_ERR_OK) return 0;
	for (;;) {
		WaitForSingleObject(e->ready, INFINITE);
		ucs_cmd *c = e->cur;
		if (c->op == OP_QUIT) { SetEvent(e->done); break; }
		ucs_dispatch(e, c);
		SetEvent(e->done);
	}
	if (e->uc) P_close(e->uc);
	return 0;
}

// Marshal a command to the engine thread (or run it inline if we're already on
// it — e.g. inside a hook callback during uc_emu_start, which must not re-enter
// the queue or it would deadlock).
static void ucs_run(ucs_engine *e, ucs_cmd *c){
	if (GetCurrentThreadId() == e->tid) { ucs_dispatch(e, c); return; }
	EnterCriticalSection(&e->lock);
	e->cur = c;
	SetEvent(e->ready);
	WaitForSingleObject(e->done, INFINITE);
	LeaveCriticalSection(&e->lock);
}

ucs_engine *ucs_new(uc_err *err){
	ucs_engine *e = (ucs_engine*)calloc(1, sizeof(*e));
	if (!e) { if (err) *err = UC_ERR_NOMEM; return NULL; }
	InitializeCriticalSection(&e->lock);
	e->ready  = CreateEvent(NULL, FALSE, FALSE, NULL);
	e->done   = CreateEvent(NULL, FALSE, FALSE, NULL);
	e->inited = CreateEvent(NULL, FALSE, FALSE, NULL);
	e->thread = CreateThread(NULL, 0, engine_loop, e, 0, &e->tid);
	WaitForSingleObject(e->inited, INFINITE);
	if (err) *err = e->open_err;
	if (e->open_err != UC_ERR_OK) { ucs_free(e); return NULL; }
	return e;
}

void ucs_free(ucs_engine *e){
	if (!e) return;
	if (e->thread) {
		ucs_cmd q; memset(&q,0,sizeof(q)); q.op = OP_QUIT;
		ucs_run(e, &q);
		WaitForSingleObject(e->thread, INFINITE);
		CloseHandle(e->thread);
	}
	if (e->ready) CloseHandle(e->ready);
	if (e->done) CloseHandle(e->done);
	if (e->inited) CloseHandle(e->inited);
	DeleteCriticalSection(&e->lock);
	free(e);
}

#else // ---- Linux/POSIX: no pump; Go forwards SIGSEGV to unicorn ------------

static void ucs_run(ucs_engine *e, ucs_cmd *c){ ucs_dispatch(e, c); }

ucs_engine *ucs_new(uc_err *err){
	ucs_engine *e = (ucs_engine*)calloc(1, sizeof(*e));
	if (!e) { if (err) *err = UC_ERR_NOMEM; return NULL; }
	e->open_err = P_open(UC_ARCH_ARM64, UC_MODE_ARM, &e->uc);
	if (err) *err = e->open_err;
	if (e->open_err != UC_ERR_OK) { free(e); return NULL; }
	return e;
}

void ucs_free(ucs_engine *e){
	if (!e) return;
	if (e->uc) P_close(e->uc);
	free(e);
}
#endif

// ---- public per-op API (builds a command + runs it) ------------------------
uc_err ucs_reg_read(ucs_engine *e, int reg, uint64_t *val){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_REGREAD; c.a0=(uint64_t)reg;
	ucs_run(e,&c); if (val) *val = c.rval; return c.ret;
}
uc_err ucs_reg_write(ucs_engine *e, int reg, uint64_t val){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_REGWRITE; c.a0=(uint64_t)reg; c.a1=val;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_mem_map(ucs_engine *e, uint64_t a, size_t n, uint32_t p){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_MAP; c.a0=a; c.a1=n; c.a2=p;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_mem_unmap(ucs_engine *e, uint64_t a, size_t n){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_UNMAP; c.a0=a; c.a1=n;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_mem_protect(ucs_engine *e, uint64_t a, size_t n, uint32_t p){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_PROTECT; c.a0=a; c.a1=n; c.a2=p;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_mem_write(ucs_engine *e, uint64_t a, const void *p, size_t n){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_WRITE; c.a0=a; c.cptr=p; c.a1=n;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_mem_read(ucs_engine *e, uint64_t a, void *p, size_t n){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_READ; c.a0=a; c.ptr=p; c.a1=n;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_emu_start(ucs_engine *e, uint64_t b, uint64_t u, uint64_t t, size_t cnt){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_START; c.a0=b; c.a1=u; c.a2=t; c.a3=cnt;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_emu_stop(ucs_engine *e){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_STOP;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_flush_tb(ucs_engine *e){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_FLUSH;
	ucs_run(e,&c); return c.ret;
}
void *ucs_context_alloc(ucs_engine *e, uc_err *err){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_CTXALLOC;
	ucs_run(e,&c); if (err) *err = c.ret; return (void*)(uintptr_t)c.rval;
}
uc_err ucs_context_save(ucs_engine *e, void *ctx){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_CTXSAVE; c.a0=(uint64_t)(uintptr_t)ctx;
	ucs_run(e,&c); return c.ret;
}
uc_err ucs_context_restore(ucs_engine *e, void *ctx){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_CTXRESTORE; c.a0=(uint64_t)(uintptr_t)ctx;
	ucs_run(e,&c); return c.ret;
}
void ucs_context_free(ucs_engine *e, void *ctx){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_CTXFREE; c.a0=(uint64_t)(uintptr_t)ctx;
	ucs_run(e,&c);
}
uc_err ucs_hook_code(ucs_engine *e, uint64_t *out, uint64_t b, uint64_t en, uint64_t cbid){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_HOOKCODE; c.a0=b; c.a1=en; c.cbid=cbid;
	ucs_run(e,&c); if (out) *out=c.rval; return c.ret;
}
uc_err ucs_hook_intr(ucs_engine *e, uint64_t *out, uint64_t cbid){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_HOOKINTR; c.cbid=cbid;
	ucs_run(e,&c); if (out) *out=c.rval; return c.ret;
}
uc_err ucs_hook_mem_invalid(ucs_engine *e, uint64_t *out, uint64_t cbid){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_HOOKMEM; c.cbid=cbid;
	ucs_run(e,&c); if (out) *out=c.rval; return c.ret;
}
uc_err ucs_hook_del(ucs_engine *e, uint64_t hook){
	ucs_cmd c; memset(&c,0,sizeof(c)); c.op=OP_HOOKDEL; c.a0=hook;
	ucs_run(e,&c); return c.ret;
}
