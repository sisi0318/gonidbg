//go:build unicorn

// Executes the bundled bionic libm on both engines and compares every result
// bit for bit. This covers the gap the project's other two correctness checks
// cannot:
//
//   - the differential test (internal/emu/diff_test.go) only offers encodings
//     the interpreter accepts, so it is blind to a missing instruction;
//   - a census of one real workload only covers the instructions that workload
//     executes, and the library used there never calls libm's transcendental
//     functions — which turned out to use an instruction the interpreter was
//     rejecting (FMOV to and from the high half of a vector register).
//
// libm is the right target: it ships with the project, every run loads it, it
// is dense in floating point and SIMD, and any workload can reach it.
package emulator

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/sisi0318/gonidbg/internal/emu"
)

// A guest trampoline, so double arguments can be passed without the backend
// needing to expose the vector registers:
//
//	ldr d0,[x0] ; ldr d1,[x0,#8] ; stp x0,x30,[sp,#-16]!
//	blr x1 ; ldp x0,x30,[sp],#16 ; str d0,[x0,#16] ; ret
//
// x0 points at {arg0, arg1, result} and x1 holds the function to call.
var libmTrampoline = [7]uint32{
	0xfd400000, 0xfd400401, 0xa9bf7be0, 0xd63f0020, 0xa8c17be0, 0xfd000800, 0xd65f03c0,
}

type libmRunner struct {
	e     *Emulator
	code  uint64
	buf   uint64
	calls int
}

func newLibmRunner(t *testing.T, engine string) *libmRunner {
	t.Helper()
	e, err := New(Config{AssetRoot: "../assets", Engine: engine})
	if err != nil {
		t.Fatalf("boot %s: %v", engine, err)
	}
	if e.Engine() != engine {
		t.Fatalf("engine = %q, want %q", e.Engine(), engine)
	}
	code := e.Alloc(0x1000, emu.ProtAll)
	var raw [len(libmTrampoline) * 4]byte
	for i, w := range libmTrampoline {
		binary.LittleEndian.PutUint32(raw[4*i:], w)
	}
	if err := e.WriteBytes(code, raw[:]); err != nil {
		t.Fatal(err)
	}
	return &libmRunner{e: e, code: code, buf: e.Malloc(32)}
}

// call runs fn(a, b) and returns the result's raw bits.
func (r *libmRunner) call(fn string, a, b float64) (uint64, bool) {
	addr, ok := r.e.Sym(fn)
	if !ok {
		return 0, false
	}
	if err := r.e.WriteU64(r.buf, math.Float64bits(a)); err != nil {
		return 0, false
	}
	if err := r.e.WriteU64(r.buf+8, math.Float64bits(b)); err != nil {
		return 0, false
	}
	if _, err := r.e.CallFunc(r.code, r.buf, addr); err != nil {
		return 0, false
	}
	v, err := r.e.ReadU64(r.buf + 16)
	if err != nil {
		return 0, false
	}
	r.calls++
	return v, true
}

func TestLibmAgainstUnicorn(t *testing.T) {
	one := []string{
		"sqrt", "exp", "exp2", "expm1", "log", "log2", "log10", "log1p",
		"sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh", "tanh",
		"cbrt", "ceil", "floor", "round", "trunc", "rint", "fabs", "erf", "erfc",
		"lgamma", "tgamma", "asinh", "acosh", "atanh", "exp10", "significand",
	}
	two := []string{"pow", "atan2", "fmod", "hypot", "fdim", "fmax", "fmin",
		"copysign", "remainder", "nextafter", "ldexp", "scalb"}

	args := []float64{
		0.5, 1.0, 1.5, 2.0, 3.0, 10.0, 0.1, 0.9, 1e-8, 1e8,
		-0.5, -1.0, -2.5, 0.0, math.Pi, math.E, 123.456, 1e-300, 1e300, 7.25,
		math.Inf(1), math.Inf(-1), math.NaN(),
	}

	ref := newLibmRunner(t, "unicorn")
	defer ref.e.Close()
	got := newLibmRunner(t, "interp")
	defer got.e.Close()

	checked, diffs, missing := 0, 0, 0
	check := func(fn string, a, b float64) {
		w, okW := ref.call(fn, a, b)
		g, okG := got.call(fn, a, b)
		if !okW {
			return // not exported, or unicorn could not run it either
		}
		if !okG {
			missing++
			if missing <= 8 {
				t.Errorf("%s(%g, %g): unicorn ran it, interp could not", fn, a, b)
			}
			return
		}
		checked++
		if w != g {
			diffs++
			if diffs <= 8 {
				t.Errorf("%s(%g, %g): unicorn %#016x (%g), interp %#016x (%g)",
					fn, a, b, w, math.Float64frombits(w), g, math.Float64frombits(g))
			}
		}
	}

	for _, fn := range one {
		for _, a := range args {
			check(fn, a, 0)
		}
	}
	for _, fn := range two {
		for _, a := range args {
			for _, b := range []float64{0.5, 2.0, -1.5, 3.0, 0.0} {
				check(fn, a, b)
			}
		}
	}
	t.Logf("compared %d libm results bit for bit: %d differed, %d unimplemented on interp",
		checked, diffs, missing)
	if checked < 300 {
		t.Fatalf("only %d comparisons ran; expected the bundled libm to export far more", checked)
	}
}
