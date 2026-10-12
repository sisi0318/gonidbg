package arm64

import (
	"encoding/binary"
	"math"
	"testing"
)

// These run anywhere with no engine and no cgo. The exhaustive correctness
// check lives in internal/emu/diff_test.go, which compares this interpreter
// against Unicorn instruction by instruction; what is here covers the pieces
// that test cannot reach — the memory model, the hook and exception plumbing,
// and a few encodings whose expected result is worth stating outright.

const (
	tCode = 0x10000
	tData = 0x20000
)

// newTest returns a CPU with a code page and a data page mapped, loaded with
// prog at tCode and with PC set there.
func newTest(t *testing.T, prog ...uint32) *CPU {
	t.Helper()
	c := New()
	if err := c.Mem.Map(tCode, PageSize, ProtRead|ProtExec); err != nil {
		t.Fatal(err)
	}
	if err := c.Mem.Map(tData, 4*PageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4*len(prog))
	for i, w := range prog {
		binary.LittleEndian.PutUint32(buf[4*i:], w)
	}
	if err := c.Mem.HostWrite(tCode, buf); err != nil {
		t.Fatal(err)
	}
	c.PC = tCode
	return c
}

// run executes exactly len(prog) instructions.
func run(t *testing.T, c *CPU, n uint64) {
	t.Helper()
	if err := c.Run(0, n); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestIntegerArithmetic(t *testing.T) {
	// movz x0,#0x1234 ; movk x0,#0xabcd,lsl#16 ; add x1,x0,#1 ; sub x2,x1,x0
	c := newTest(t, 0xd2824680, 0xf2b579a0, 0x91000401, 0xcb000022)
	run(t, c, 4)
	if c.X(0) != 0xabcd1234 {
		t.Errorf("x0 = %#x, want 0xabcd1234", c.X(0))
	}
	if c.X(1) != 0xabcd1235 {
		t.Errorf("x1 = %#x, want 0xabcd1235", c.X(1))
	}
	if c.X(2) != 1 {
		t.Errorf("x2 = %#x, want 1", c.X(2))
	}
}

func TestFlagsAndConditionalSelect(t *testing.T) {
	// subs xzr,x0,x1 (cmp) ; csel x2,x3,x4,eq ; cset x5,hi
	c := newTest(t, 0xeb01001f, 0x9a840062, 0x9a9f97e5)
	c.SetX(0, 5)
	c.SetX(1, 5)
	c.SetX(3, 0xaa)
	c.SetX(4, 0xbb)
	run(t, c, 3)
	if c.NZCV&flagZ == 0 {
		t.Errorf("Z not set after cmp of equal values (nzcv=%#x)", c.NZCV)
	}
	if c.X(2) != 0xaa {
		t.Errorf("csel eq picked %#x, want 0xaa", c.X(2))
	}
	if c.X(5) != 0 {
		t.Errorf("cset hi = %#x, want 0 (equal is not unsigned-greater)", c.X(5))
	}
}

func TestLoadStoreRoundTrip(t *testing.T) {
	// str x1,[x0] ; ldrb w2,[x0] ; ldrsb x3,[x0,#1] ; ldr x4,[x0],#8 (post-index)
	c := newTest(t, 0xf9000001, 0x39400002, 0x39800403, 0xf8408404)
	c.SetX(0, tData)
	c.SetX(1, 0xfedcba9876543280)
	run(t, c, 4)
	if c.X(2) != 0x80 {
		t.Errorf("ldrb = %#x, want 0x80", c.X(2))
	}
	if c.X(3) != 0x32 {
		t.Errorf("ldrsb of 0x32 = %#x, want 0x32", c.X(3))
	}
	if c.X(0) != tData+8 {
		t.Errorf("post-index base = %#x, want %#x", c.X(0), tData+8)
	}
	if v := c.Mem.Read64(tData); v != 0xfedcba9876543280 {
		t.Errorf("memory = %#x, want 0xfedcba9876543280", v)
	}
}

func TestUnalignedAndPageCrossingAccess(t *testing.T) {
	c := newTest(t)
	// a 64-bit store spanning the boundary between two pages
	addr := uint64(tData + PageSize - 3)
	c.Mem.Write64(addr, 0x1122334455667788)
	if got := c.Mem.Read64(addr); got != 0x1122334455667788 {
		t.Errorf("page-crossing read = %#x, want 0x1122334455667788", got)
	}
	// the halves landed in the right pages
	if lo := c.Mem.Read8(addr); lo != 0x88 {
		t.Errorf("low byte = %#x, want 0x88", lo)
	}
	if hi := c.Mem.Read8(tData + PageSize + 4); hi != 0x11 {
		t.Errorf("high byte = %#x, want 0x11", hi)
	}
}

func TestMemoryFaults(t *testing.T) {
	// ldr x0,[x1]
	c := newTest(t, 0xf9400020)
	c.SetX(1, 0x90000000) // unmapped
	err := c.Run(0, 1)
	var f *Fault
	if err == nil {
		t.Fatal("expected a fault reading unmapped memory")
	}
	if f, _ = err.(*Fault); f == nil || f.Kind != MemReadUnmapped {
		t.Fatalf("err = %v, want a read-unmapped Fault", err)
	}

	// a store to a read-only page faults as a protection violation
	c2 := newTest(t, 0xf9000020) // str x0,[x1]
	c2.SetX(1, tCode)
	err = c2.Run(0, 1)
	if f, _ = err.(*Fault); f == nil || f.Kind != MemWriteProt {
		t.Fatalf("err = %v, want a write-protection Fault", err)
	}
}

func TestInvalidHookCanMapAndRetry(t *testing.T) {
	// str x0,[x1] to an unmapped page; the hook maps it and lets the access retry
	c := newTest(t, 0xf9000020)
	c.SetX(0, 0x42)
	c.SetX(1, 0x90000000)
	var kinds []int
	c.Mem.AddInvalidHook(func(kind int, addr uint64, size int, value int64) bool {
		kinds = append(kinds, kind)
		_ = c.Mem.Map(addr&^uint64(pageMask), PageSize, ProtRead|ProtWrite)
		return true
	})
	run(t, c, 1)
	if len(kinds) != 1 || kinds[0] != MemWriteUnmapped {
		t.Fatalf("hook saw %v, want one write-unmapped", kinds)
	}
	if v := c.Mem.Read64(0x90000000); v != 0x42 {
		t.Errorf("value after retry = %#x, want 0x42", v)
	}
}

func TestSelfModifyingCodeIsNotCached(t *testing.T) {
	// A guest store over an instruction already executed must take effect: the
	// decoded-instruction array for a written page is dropped.
	//   loop: add x0,x0,#1 ; (patched later) ; b loop
	c := newTest(t, 0x91000400, 0x14000000)
	if err := c.Mem.Protect(tCode, PageSize, ProtAll); err != nil {
		t.Fatal(err)
	}
	c.PC = tCode
	run(t, c, 1)
	if c.X(0) != 1 {
		t.Fatalf("x0 = %d, want 1", c.X(0))
	}
	// overwrite with: add x0,x0,#16
	c.Mem.Write32(tCode, 0x91004000)
	c.PC = tCode
	run(t, c, 1)
	if c.X(0) != 17 {
		t.Errorf("x0 = %d, want 17 (patched instruction did not take effect)", c.X(0))
	}
}

func TestCodeHookAndRedirect(t *testing.T) {
	c := newTest(t, 0x91000400, 0x91000400) // add x0,x0,#1 twice
	var seen []uint64
	c.AddCodeHook(1, 0, func(addr uint64, size uint32) { // begin > end: everywhere
		seen = append(seen, addr)
		if addr == tCode+4 {
			c.PC = tCode + 8 // skip the second add
		}
	})
	if err := c.Run(tCode+8, 0); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != tCode || seen[1] != tCode+4 {
		t.Errorf("hook saw %v, want both instruction addresses", seen)
	}
	if c.X(0) != 1 {
		t.Errorf("x0 = %d, want 1 (the hook redirected past the second add)", c.X(0))
	}
}

func TestSVCAndBRKReachHooks(t *testing.T) {
	// svc #0 ; brk #0
	c := newTest(t, 0xd4000001, 0xd4200000)
	var got []uint32
	var pcs []uint64
	c.AddInterruptHook(func(intno uint32) {
		got = append(got, intno)
		pcs = append(pcs, c.PC)
		if intno == ExcpBKPT {
			c.Stop()
		}
	})
	if err := c.Run(0, 0); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != ExcpSWI || got[1] != ExcpBKPT {
		t.Fatalf("exceptions = %v, want [SWI BKPT]", got)
	}
	// SVC advances PC past itself; BRK does not, which is how the syscall layer
	// tells a real syscall from a debug trap.
	if pcs[0] != tCode+4 {
		t.Errorf("pc at SVC hook = %#x, want %#x", pcs[0], tCode+4)
	}
	if pcs[1] != tCode+4 {
		t.Errorf("pc at BRK hook = %#x, want %#x (BRK must not advance PC)", pcs[1], tCode+4)
	}
}

func TestUndefinedInstruction(t *testing.T) {
	c := newTest(t, 0x00000000)
	err := c.Run(0, 1)
	if u, _ := err.(*UndefinedError); u == nil {
		t.Fatalf("err = %v, want an UndefinedError", err)
	}
}

func TestExclusiveMonitor(t *testing.T) {
	// ldxr x1,[x0] ; stxr w2,x3,[x0] ; stxr w4,x5,[x0]
	c := newTest(t, 0xc85f7c01, 0xc8027c03, 0xc8047c05)
	c.SetX(0, tData)
	c.SetX(3, 0xaaaa)
	c.SetX(5, 0xbbbb)
	run(t, c, 3)
	if c.X(2) != 0 {
		t.Errorf("first stxr status = %d, want 0 (success)", c.X(2))
	}
	if c.X(4) != 1 {
		t.Errorf("second stxr status = %d, want 1 (monitor already consumed)", c.X(4))
	}
	if v := c.Mem.Read64(tData); v != 0xaaaa {
		t.Errorf("memory = %#x, want 0xaaaa (only the first store may land)", v)
	}
}

func TestVectorAndFloatingPoint(t *testing.T) {
	// ldr q0,[x0] ; add v1.4s,v0.4s,v0.4s ; str q1,[x0,#16]
	c := newTest(t, 0x3dc00000, 0x4ea08401, 0x3d800401)
	c.SetX(0, tData)
	for i := 0; i < 4; i++ {
		c.Mem.Write32(tData+uint64(4*i), uint32(i+1))
	}
	run(t, c, 3)
	for i := 0; i < 4; i++ {
		want := uint32(2 * (i + 1))
		if got := c.Mem.Read32(tData + 16 + uint64(4*i)); got != want {
			t.Errorf("lane %d = %d, want %d", i, got, want)
		}
	}
}

func TestFloatingPointNaNIsArchitectural(t *testing.T) {
	// fsqrt d0,d0 of a negative number must give the positive default NaN; the
	// host FPU returns a sign-flipped one on x86.
	c := newTest(t, 0x1e61c000)
	c.V[0] = Vec{math.Float64bits(-4.0), 0}
	run(t, c, 1)
	if c.V[0][0] != 0x7ff8000000000000 {
		t.Errorf("sqrt(-4) = %#x, want the default NaN 0x7ff8000000000000", c.V[0][0])
	}
}

func TestSystemRegisters(t *testing.T) {
	// mrs x0,tpidr_el0 ; msr tpidr_el0,x1 ; mrs x2,tpidr_el0
	c := newTest(t, 0xd53bd040, 0xd51bd041, 0xd53bd042)
	c.TPIDR = 0xd0000000
	c.SetX(1, 0xd0001000)
	run(t, c, 3)
	if c.X(0) != 0xd0000000 {
		t.Errorf("mrs tpidr_el0 = %#x, want 0xd0000000", c.X(0))
	}
	if c.X(2) != 0xd0001000 {
		t.Errorf("tpidr_el0 after msr = %#x, want 0xd0001000", c.X(2))
	}
}

func TestContextSaveRestore(t *testing.T) {
	c := newTest(t, 0x91000400) // add x0,x0,#1
	c.SetX(0, 7)
	c.V[3] = Vec{0x1111, 0x2222}
	c.NZCV = flagC
	ctx := c.SaveContext()

	run(t, c, 1)
	c.V[3] = Vec{}
	c.NZCV = flagZ
	c.RestoreContext(ctx)

	if c.X(0) != 7 || c.PC != tCode || c.NZCV != flagC || c.V[3] != (Vec{0x1111, 0x2222}) {
		t.Errorf("restore gave x0=%d pc=%#x nzcv=%#x v3=%v; want 7, %#x, %#x, {0x1111 0x2222}",
			c.X(0), c.PC, c.NZCV, c.V[3], uint64(tCode), uint32(flagC))
	}
}

func TestMemoryMappingRules(t *testing.T) {
	c := New()
	if err := c.Mem.Map(tData, PageSize, ProtRead); err != nil {
		t.Fatal(err)
	}
	if err := c.Mem.Map(tData, PageSize, ProtRead); err == nil {
		t.Error("mapping over an existing mapping should fail")
	}
	if err := c.Mem.Map(tData+1, PageSize, ProtRead); err == nil {
		t.Error("an unaligned map should fail")
	}
	if err := c.Mem.Unmap(tData+PageSize, PageSize); err == nil {
		t.Error("unmapping an unmapped range should fail")
	}
	if err := c.Mem.HostRead(tData+PageSize, make([]byte, 8)); err == nil {
		t.Error("a host read of unmapped memory should fail")
	}
	// host access ignores protection, guest access does not
	if err := c.Mem.HostWrite(tData, []byte{1, 2, 3, 4}); err != nil {
		t.Errorf("host write to a read-only page: %v", err)
	}
}

func TestDecodableRejectsUnallocated(t *testing.T) {
	for _, tc := range []struct {
		raw  uint32
		want bool
		what string
	}{
		{0x91000400, true, "add x0,x0,#1"},
		{0x00000000, false, "the zero word"},
		{0xd4000001, true, "svc #0"},
		{0x1e604000, true, "fmov d0,d0"},
		{0x1ff1a943, false, "fnmsub h3,... (needs FEAT_FP16)"},
		{0x38e7409f, false, "ldsmaxalb (needs FEAT_LSE)"},
		{0x9e670000, true, "fmov d0,x0 (bit 31 is sf here, not M)"},
		{0x4cdfa061, true, "ld1 {v1.16b,v2.16b},[x3],#32"},
	} {
		if got := Decodable(tc.raw); got != tc.want {
			t.Errorf("Decodable(%#08x) = %v, want %v (%s)", tc.raw, got, tc.want, tc.what)
		}
	}
}

// --- regressions -----------------------------------------------------------

// A misaligned PC must be rejected rather than indexing the decoded-instruction
// array with pc>>2 while reading the encoding from byte offset pc&0xfff: that
// combination cached a garbage decode in the slot belonging to the *aligned*
// address, so a later legitimate execution of that address ran the wrong
// instruction.
func TestMisalignedPCRejected(t *testing.T) {
	c := newTest(t, 0x91000400) // add x0,x0,#1
	c.PC = tCode + 2
	if err := c.Run(0, 1); err == nil {
		t.Fatal("a misaligned PC should be an error")
	}
	// the aligned address must still decode correctly
	c.PC = tCode
	c.SetX(0, 0)
	if err := c.Run(0, 1); err != nil {
		t.Fatalf("aligned run after a misaligned one: %v", err)
	}
	if c.X(0) != 1 {
		t.Errorf("x0 = %d, want 1 (the decode cache was poisoned)", c.X(0))
	}
}

// The same check also guards the end of a page, where a misaligned fetch would
// read past the page and panic with a bounds error — escaping Run's recover,
// which only converts the CPU's own error types.
func TestMisalignedPCAtPageEnd(t *testing.T) {
	c := newTest(t, 0x91000400)
	c.PC = tCode + PageSize - 2
	if err := c.Run(0, 1); err == nil {
		t.Fatal("a misaligned PC at a page end should be an error")
	}
}

// A branch to a misaligned target is rejected too, via the same check.
func TestMisalignedBranchTarget(t *testing.T) {
	c := newTest(t, 0xd61f0020) // br x1
	c.SetX(1, tCode+1)
	if err := c.Run(0, 2); err == nil {
		t.Fatal("a branch to a misaligned target should be an error")
	}
}

// A read hook may write the page it is reporting on. The backing array has to
// be resolved after the hook runs, or a first write inside the hook leaves the
// read looking at the shared zero page and returning a stale zero.
func TestReadHookWritingItsOwnPage(t *testing.T) {
	c := newTest(t, 0xf9400020) // ldr x0,[x1]
	target := uint64(tData + 2*PageSize)
	c.SetX(1, target)
	c.Mem.AddReadHook(0, ^uint64(0), func(addr uint64, size int, _ int64) {
		if addr == target {
			c.Mem.Write64(addr, 0x1234) // first write to this page
		}
	})
	run(t, c, 1)
	if c.X(0) != 0x1234 {
		t.Errorf("x0 = %#x, want 0x1234 (the read used a stale page pointer)", c.X(0))
	}
}

// A hook that unmaps the page mid-access must not crash the interpreter: the
// access is already in flight, so the bytes read as zero.
func TestHookUnmappingDuringAccess(t *testing.T) {
	c := newTest(t, 0xf9400020) // ldr x0,[x1]
	target := uint64(tData + PageSize)
	c.SetX(1, target-3) // crosses into the next page
	c.SetX(0, 0xffff)
	c.Mem.AddReadHook(0, ^uint64(0), func(addr uint64, size int, _ int64) {
		_ = c.Mem.Unmap(target, PageSize)
	})
	if err := c.Run(0, 1); err != nil {
		t.Fatalf("run: %v", err)
	}
}

// Removing an invalid-access hook really removes it.
func TestInvalidHookRemoval(t *testing.T) {
	c := newTest(t, 0xf9400020) // ldr x0,[x1]
	c.SetX(1, 0x90000000)
	calls := 0
	rm := c.Mem.AddInvalidHook(func(int, uint64, int, int64) bool { calls++; return false })
	c.PC = tCode
	_ = c.Run(0, 1)
	rm()
	c.PC = tCode
	_ = c.Run(0, 1)
	if calls != 1 {
		t.Errorf("invalid hook called %d times, want 1 (it was not removed)", calls)
	}
}

// CNTVCT_EL0 reads the instruction count, so a restored context has to restore
// it as well: otherwise a guest that mixes in the counter drifts between a run
// and a run resumed from a snapshot, which is what Snapshot/Restore exists to
// prevent.
func TestContextRestoresGuestCounter(t *testing.T) {
	// mrs x0,cntvct_el0
	c := newTest(t, 0xd53be040)
	ctx := c.SaveContext()
	run(t, c, 1)
	first := c.X(0)

	c.RestoreContext(ctx)
	c.SetX(0, 0)
	run(t, c, 1)
	if c.X(0) != first {
		t.Errorf("cntvct after restore = %d, want %d", c.X(0), first)
	}
}

// Release drops the address space, so a backend that has been closed cannot
// hand back freed guest state and does not pin it either.
func TestRelease(t *testing.T) {
	c := newTest(t, 0x91000400)
	c.Mem.Write64(tData, 1)
	c.Release()
	if c.Mem.Mapped(tData) {
		t.Error("memory still mapped after Release")
	}
	if err := c.Mem.HostRead(tData, make([]byte, 8)); err == nil {
		t.Error("a host read after Release should report unmapped memory")
	}
}

// A page no hook watches is cached in the TLB even while hooks exist
// elsewhere. The risk in that optimisation is caching a page a hook *does*
// watch and then silently skipping the callback, so check both directions,
// interleaved, and across a hook added after the page was already cached.
func TestRangedMemoryHookFiresExactly(t *testing.T) {
	// ldr x2,[x0] ; ldr x3,[x1]
	c := newTest(t, 0xf9400002, 0xf9400023)
	watched := uint64(tData + PageSize) // page the hook covers
	plain := uint64(tData + 2*PageSize) // page it does not
	c.SetX(0, watched)
	c.SetX(1, plain)

	// warm the TLB for both pages before any hook exists
	c.Mem.Read64(watched)
	c.Mem.Read64(plain)

	var hits []uint64
	rm := c.Mem.AddReadHook(watched, watched+0xff, func(addr uint64, size int, _ int64) {
		hits = append(hits, addr)
	})
	for i := 0; i < 3; i++ {
		c.PC = tCode
		run(t, c, 2)
	}
	if len(hits) != 3 {
		t.Fatalf("hook fired %d times, want 3 (one per load of the watched page)", len(hits))
	}
	for _, h := range hits {
		if h != watched {
			t.Errorf("hook saw %#x, want only %#x", h, watched)
		}
	}
	rm()
	c.PC = tCode
	run(t, c, 2)
	if len(hits) != 3 {
		t.Errorf("hook fired %d times after removal, want 3", len(hits))
	}
}
