//go:build unicorn || dynarmic

package emulator

import (
	"bytes"
	"strings"
	"testing"
)

// TestNativeSo loads the bundled example native.so on whichever CPU engine is
// compiled in (-tags unicorn / -tags dynarmic) and exercises calling exported
// functions, an imported bionic call, guest memory writes, and Replace().
//
//	go test -tags unicorn  ./emulator
//	go test -tags dynarmic ./emulator
func TestNativeSo(t *testing.T) {
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
	})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 5 {
		t.Fatalf("add(2,3) = %d, want 5", int32(r))
	}
	if r, _ := e.CallSymbol("fib", 20); r != 6765 {
		t.Fatalf("fib(20) = %d, want 6765", r)
	}
	// slen imports bionic strlen and runs it from guest code.
	p := e.WriteCStringAlloc("hello")
	if r, _ := e.CallSymbol("slen", p); int32(r) != 5 {
		t.Fatalf("slen(\"hello\") = %d, want 5", int32(r))
	}
	// sum_into writes a+b through a guest pointer; read it back.
	out := e.Malloc(4)
	if _, err := e.CallSymbol("sum_into", out, 20, 22); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.ReadU32(out); v != 42 {
		t.Fatalf("sum_into -> *out = %d, want 42", v)
	}
	// Replace swaps the native add for a Go implementation.
	if err := e.ReplaceSymbol("add", func(h *Hook) uint64 { return h.Arg(0)*10 + h.Arg(1) }); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 23 {
		t.Fatalf("replaced add(2,3) = %d, want 23", int32(r))
	}
	t.Logf("engine %s: add / fib / slen / sum_into / Replace all OK", e.Engine())
}

// TestSyscalls exercises the expanded syscall table end-to-end: native.so calls
// bionic uname() and readlink(), which issue SYS_uname / SYS_readlinkat that the
// kernel layer now services.
func TestSyscalls(t *testing.T) {
	e, err := New(Config{SOPath: "../examples/native/native.so", AssetRoot: "../assets"})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	if r, _ := e.CallSymbol("uname_machine_len"); int32(r) != 7 { // len("aarch64")
		t.Fatalf("uname_machine_len = %d, want 7", int32(r))
	}
	if r, _ := e.CallSymbol("readlink_exe_len"); int32(r) != 25 { // len("/system/bin/app_process64")
		t.Fatalf("readlink_exe_len = %d, want 25", int32(r))
	}
	t.Logf("engine %s: uname + readlink syscalls OK", e.Engine())
}

// TestJNI drives native.so's jni_probe, which calls the JNIEnv table by slot to
// exercise the expanded JNI surface (strings, object arrays, exceptions).
func TestJNI(t *testing.T) {
	e, err := New(Config{SOPath: "../examples/native/native.so", AssetRoot: "../assets"})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	env := e.JNIEnv()
	r, err := e.CallSymbol("jni_probe", env)
	if err != nil {
		t.Fatal(err)
	}
	if int32(r) != 12 { // GetVersion + GetStringUTFLength(5) + GetArrayLength(3) + same + pending + cleared
		t.Fatalf("jni_probe = %d, want 12", int32(r))
	}
	t.Logf("engine %s: JNI strings/object-arrays/exceptions OK", e.Engine())
}

// TestInlineHook installs an inline hook at add's entry that rewrites the second
// argument, so add(2,3) returns 2 + (3+100) = 105. Unicorn only; on dynarmic
// HookAddr returns an error (no per-instruction hook).
func TestInlineHook(t *testing.T) {
	e, err := New(Config{SOPath: "../examples/native/native.so", AssetRoot: "../assets"})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	rm, err := e.HookSymbol("add", func(h *Hook) { h.SetArg(1, h.Arg(1)+100) })
	if e.Engine() != "unicorn" {
		if err == nil {
			t.Fatalf("expected HookAddr to error on %s engine", e.Engine())
		}
		t.Logf("engine %s: inline hooks correctly unsupported (%v)", e.Engine(), err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer rm()
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 105 {
		t.Fatalf("add(2,3) with inline hook = %d, want 105", int32(r))
	}
	t.Logf("engine %s: inline hook rewrote arg OK", e.Engine())
}

// TestDebugger sets a breakpoint at add, scripts the console ("r" then "c"),
// and checks the prompt printed registers and the call still returned. Unicorn
// only; on dynarmic NewDebugger errors.
func TestDebugger(t *testing.T) {
	e, err := New(Config{SOPath: "../examples/native/native.so", AssetRoot: "../assets"})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	d, err := e.NewDebugger()
	if e.Engine() != "unicorn" {
		if err == nil {
			t.Fatalf("expected NewDebugger to error on %s engine", e.Engine())
		}
		t.Logf("engine %s: debugger correctly unsupported (%v)", e.Engine(), err)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer d.Detach()

	var out bytes.Buffer
	d.Out = &out
	d.In = strings.NewReader("r\nc\n") // dump regs, then continue
	if err := d.BreakSymbol("add"); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 5 {
		t.Fatalf("add(2,3) = %d, want 5", int32(r))
	}
	s := out.String()
	if !strings.Contains(s, "break @") || !strings.Contains(s, "X0 =0x") {
		t.Fatalf("debugger output missing breakpoint/regs:\n%s", s)
	}
	t.Logf("engine %s: debugger breakpoint + register dump OK", e.Engine())
}
