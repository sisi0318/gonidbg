//go:build unicorn && windows

// ucthread: test whether running unicorn on a dedicated C thread (created with
// CreateThread, unknown to the Go runtime) lets unicorn's own VEH service its
// lazy page-commit faults — i.e. Go's exception handler should CONTINUE_SEARCH
// for faults on non-Go threads. If this prints X0=11, Windows execution is
// viable by confining the engine to a C-owned thread.
package main

/*
#include <unicorn/unicorn.h>
#include <windows.h>

typedef uc_err (*pf_open)(uc_arch, uc_mode, uc_engine**);
typedef uc_err (*pf_map)(uc_engine*, uint64_t, size_t, uint32_t);
typedef uc_err (*pf_write)(uc_engine*, uint64_t, const void*, size_t);
typedef uc_err (*pf_rw)(uc_engine*, int, const void*);
typedef uc_err (*pf_rr)(uc_engine*, int, void*);
typedef uc_err (*pf_start)(uc_engine*, uint64_t, uint64_t, uint64_t, size_t);
static pf_open o; static pf_map mm; static pf_write mw; static pf_rw rw; static pf_rr rr; static pf_start es;

static int loaded;
static int uload(const char* p){
  HMODULE h=LoadLibraryA(p); if(!h) return 1;
  o=(pf_open)GetProcAddress(h,"uc_open"); mm=(pf_map)GetProcAddress(h,"uc_mem_map");
  mw=(pf_write)GetProcAddress(h,"uc_mem_write"); rw=(pf_rw)GetProcAddress(h,"uc_reg_write");
  rr=(pf_rr)GetProcAddress(h,"uc_reg_read"); es=(pf_start)GetProcAddress(h,"uc_emu_start");
  if(!o||!mm||!mw||!rw||!rr||!es) return 2; loaded=1; return 0;
}

typedef struct { int done; uc_err err; unsigned long long x0; } result_t;

static DWORD WINAPI worker(LPVOID arg){
  result_t* res=(result_t*)arg;
  uc_engine* uc=0;
  res->err = o(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
  if(res->err){ res->done=1; return 0; }
  res->err = mm(uc, 0x1000, 0x1000, UC_PROT_ALL);     // <-- this faulted under Go before
  if(res->err){ res->done=1; return 0; }
  unsigned char code[4]={0x00,0x04,0x00,0x91};         // add x0,x0,#1
  mw(uc, 0x1000, code, 4);
  unsigned long long x0=10; rw(uc, UC_ARM64_REG_X0, &x0);
  res->err = es(uc, 0x1000, 0x1004, 0, 1);
  rr(uc, UC_ARM64_REG_X0, &x0);
  res->x0 = x0; res->done=1; return 0;
}

// Run the whole unicorn sequence on a C-owned thread; block until it finishes.
static result_t run_on_c_thread(){
  result_t res; res.done=0; res.err=0; res.x0=0;
  HANDLE h=CreateThread(NULL,0,worker,&res,0,NULL);
  if(!h){ res.err=999; return res; }
  WaitForSingleObject(h, INFINITE);
  CloseHandle(h);
  return res;
}
*/
import "C"

import (
	"fmt"
	"os"
)

func main() {
	dll := C.CString("C:/ucvendor/unicorn.dll")
	if rc := C.uload(dll); rc != 0 {
		fmt.Println("load failed rc=", rc)
		os.Exit(1)
	}
	res := C.run_on_c_thread()
	fmt.Printf("done=%d err=%d X0=%d (expect 11)\n", int(res.done), int(res.err), uint64(res.x0))
	if uint64(res.x0) == 11 {
		fmt.Println("WINDOWS EXECUTION VIABLE: unicorn runs on a C-owned thread under Go")
	} else {
		fmt.Println("still blocked")
		os.Exit(2)
	}
}
