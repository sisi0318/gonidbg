//go:build unicorn || dynarmic

package emulator

import "testing"

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
