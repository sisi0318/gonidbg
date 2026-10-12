// Engine tests for the pure-Go interpreter. This file carries no build tag:
// the "interp" backend is always compiled in, so these run under a plain
//
//	CGO_ENABLED=0 go test ./...
//
// which is the point of having it — the framework is exercised end to end with
// no C toolchain and no engine library present.
package emulator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sisi0318/gonidbg/dvm"
)

func newInterp(t *testing.T) *Emulator {
	t.Helper()
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
		Engine:    "interp",
	})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if e.Engine() != "interp" {
		t.Fatalf("engine = %q, want interp", e.Engine())
	}
	return e
}

// TestInterpNativeSo is the engine_test.go TestNativeSo coverage on the
// interpreter: exported calls, an imported bionic call, guest memory, Replace.
func TestInterpNativeSo(t *testing.T) {
	e := newInterp(t)
	defer e.Close()

	if r, err := e.CallSymbol("add", 2, 3); err != nil || int32(r) != 5 {
		t.Fatalf("add(2,3) = %d, %v; want 5", int32(r), err)
	}
	if r, err := e.CallSymbol("fib", 20); err != nil || r != 6765 {
		t.Fatalf("fib(20) = %d, %v; want 6765", r, err)
	}
	p := e.WriteCStringAlloc("hello")
	if r, err := e.CallSymbol("slen", p); err != nil || int32(r) != 5 {
		t.Fatalf("slen(\"hello\") = %d, %v; want 5", int32(r), err)
	}
	out := e.Malloc(4)
	if _, err := e.CallSymbol("sum_into", out, 20, 22); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.ReadU32(out); v != 42 {
		t.Fatalf("sum_into -> *out = %d, want 42", v)
	}
	if err := e.ReplaceSymbol("add", func(h *Hook) uint64 { return h.Arg(0)*10 + h.Arg(1) }); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 23 {
		t.Fatalf("replaced add(2,3) = %d, want 23", int32(r))
	}
}

// TestInterpSyscalls drives bionic uname()/readlink() through the syscall layer.
func TestInterpSyscalls(t *testing.T) {
	e := newInterp(t)
	defer e.Close()

	if r, err := e.CallSymbol("uname_machine_len"); err != nil || int32(r) != 7 {
		t.Fatalf("uname_machine_len = %d, %v; want 7", int32(r), err)
	}
	if r, err := e.CallSymbol("readlink_exe_len"); err != nil || int32(r) != 25 {
		t.Fatalf("readlink_exe_len = %d, %v; want 25", int32(r), err)
	}
}

// TestInterpJNI drives native.so's jni_probe through the JNI dispatcher.
func TestInterpJNI(t *testing.T) {
	e, err := New(Config{
		SOPath: "../examples/native/native.so", AssetRoot: "../assets",
		Engine: "interp", JNI: dvm.AbstractJni{},
	})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()
	if _, err := e.CallSymbol("jni_probe", e.JNIEnv()); err != nil {
		t.Fatalf("jni_probe: %v", err)
	}
}

// TestInterpInlineHook checks that an inline hook installed on already-executed
// code still fires: the interpreter drops its decoded instructions when a hook
// appears, the same invariant the unicorn backend needs a cache flush for.
func TestInterpInlineHook(t *testing.T) {
	e := newInterp(t)
	defer e.Close()

	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 5 {
		t.Fatalf("add(2,3) = %d, want 5", int32(r))
	}
	rm, err := e.HookSymbol("add", func(h *Hook) { h.SetArg(1, h.Arg(1)+100) })
	if err != nil {
		t.Fatal(err)
	}
	defer rm()
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 105 {
		t.Fatalf("add(2,3) with inline hook = %d, want 105", int32(r))
	}
}

// TestInterpSelfModifyingCode writes new code over a function between calls.
// The interpreter invalidates the decoded instructions of any page written to,
// so this works without an explicit cache flush.
func TestInterpSelfModifyingCode(t *testing.T) {
	e := newInterp(t)
	defer e.Close()

	addr, ok := e.Sym("add")
	if !ok {
		t.Fatal("symbol add not found")
	}
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 5 {
		t.Fatalf("add(2,3) = %d, want 5", int32(r))
	}
	// mov w0, #77 ; ret
	if err := e.WriteBytes(addr, []byte{0xa0, 0x09, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6}); err != nil {
		t.Fatal(err)
	}
	if r, err := e.CallSymbol("add", 2, 3); err != nil || int32(r) != 77 {
		t.Fatalf("patched add(2,3) = %d, %v; want 77", int32(r), err)
	}
}

// TestInterpTrace captures a full instruction trace, which needs an engine with
// per-instruction code hooks.
func TestInterpTrace(t *testing.T) {
	e := newInterp(t)
	defer e.Close()

	m := e.MainModule()
	var buf bytes.Buffer
	TraceGate, TraceMax = true, 100000
	defer func() { TraceGate, TraceMax = false, 0 }()
	stop, err := e.TraceInsns(&buf, m.Base, m.Base+m.Img.LoadSpan, m.Base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.CallSymbol("fib", 10); err != nil {
		t.Fatal(err)
	}
	stop()
	if n := strings.Count(buf.String(), "\n"); n < 10 {
		t.Fatalf("trace has %d lines, want a real instruction stream", n)
	}
}

// TestInterpDebugger breaks at a symbol, scripts the console, and checks the
// call still returns. Like the tracer this needs per-instruction hooks.
func TestInterpDebugger(t *testing.T) {
	e := newInterp(t)
	defer e.Close()

	d, err := e.NewDebugger()
	if err != nil {
		t.Fatal(err)
	}
	defer d.Detach()

	var out bytes.Buffer
	d.Out = &out
	d.In = strings.NewReader("r\nc\n") // dump registers, then continue
	if err := d.BreakSymbol("add"); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 5 {
		t.Fatalf("add(2,3) = %d, want 5", int32(r))
	}
	if s := out.String(); !strings.Contains(s, "x0") {
		t.Errorf("debugger output has no register dump:\n%s", s)
	}
}

// TestInterpSnapshot checks that Restore rewinds guest state: the second call
// must see the pristine heap and registers the first one started from.
func TestInterpSnapshot(t *testing.T) {
	e := newInterp(t)
	defer e.Close()

	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Free()

	first, err := e.CallSymbol("fib", 20)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Restore(snap); err != nil {
		t.Fatal(err)
	}
	second, err := e.CallSymbol("fib", 20)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("fib(20) after Restore = %d, want %d", second, first)
	}
}
