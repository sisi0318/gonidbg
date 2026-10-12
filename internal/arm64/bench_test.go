package arm64

import (
	"encoding/binary"
	"testing"
)

// Interpreter throughput benchmarks. They report ns/insn, so the figure to
// watch is "ns/op" with b.N counted in instructions.
//
//	go test -run X -bench . ./internal/arm64
//
// The kernels are weighted the way a real workload is: a census of one
// production library's 51M executed instructions came out 41% load/store, 41%
// integer ALU, 16% branch, 1.3% SIMD/FP, so BenchmarkMixed is the number that
// matters most and the others exist to localise a regression.

const benchLoops = 1 << 12

// benchRun builds a CPU whose code page holds body repeated until it fills a
// page, then executes exactly b.N instructions. body must not branch.
func benchRun(b *testing.B, setup func(*CPU), body ...uint32) {
	b.Helper()
	c := New()
	if err := c.Mem.Map(tCode, 16*PageSize, ProtRead|ProtExec); err != nil {
		b.Fatal(err)
	}
	if err := c.Mem.Map(tData, 16*PageSize, ProtRead|ProtWrite); err != nil {
		b.Fatal(err)
	}
	// Fill the code region with the body, then branch back to the start so a
	// long run stays inside already-decoded pages — the steady state a real
	// workload spends its time in.
	n := (16*PageSize/4 - 1) / len(body) * len(body)
	buf := make([]byte, 4*n+4)
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint32(buf[4*i:], body[i%len(body)])
	}
	// b to the first instruction: imm26 = -(n)
	binary.LittleEndian.PutUint32(buf[4*n:], 0x14000000|uint32(-int32(n))&0x03ffffff)
	if err := c.Mem.HostWrite(tCode, buf); err != nil {
		b.Fatal(err)
	}
	if setup != nil {
		setup(c)
	}
	c.PC = tCode

	b.ResetTimer()
	if err := c.Run(0, uint64(b.N)); err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
	if got := c.InsnCount(); got != uint64(b.N) {
		b.Fatalf("executed %d instructions, wanted %d", got, b.N)
	}
}

// add x1,x1,#1 ; sub x2,x2,#1 ; orr x3,x1,x2 ; eor x4,x3,x1
func BenchmarkIntALU(b *testing.B) {
	benchRun(b, nil, 0x91000421, 0xd1000442, 0xaa020023, 0xca010064)
}

// cmp x1,x2 ; csel x3,x1,x2,eq ; cset x4,hi ; add x1,x1,#1
func BenchmarkIntFlags(b *testing.B) {
	benchRun(b, nil, 0xeb02003f, 0x9a820023, 0x9a9f97e4, 0x91000421)
}

// ldr x2,[x0] ; str x2,[x0,#8] ; ldrb w3,[x0,#16] ; ldp x4,x5,[x0,#32]
func BenchmarkLoadStore(b *testing.B) {
	benchRun(b, func(c *CPU) { c.SetX(0, tData+0x800) },
		0xf9400002, 0xf9000402, 0x39404003, 0xa9421404)
}

// Loads that hit the same page repeatedly: the TLB fast path.
func BenchmarkLoadSamePage(b *testing.B) {
	benchRun(b, func(c *CPU) { c.SetX(0, tData+0x800) },
		0xf9400002, 0xf9400403, 0xf9400804, 0xf9400c05)
}

// Loads that stride across pages: the TLB miss path.
func BenchmarkLoadCrossPage(b *testing.B) {
	benchRun(b, func(c *CPU) { c.SetX(0, tData) },
		0xf9400002, 0xf9480003, 0xf9500004, 0xf9580005)
}

// cbz x1,+8 (not taken) ; add x1,x1,#1 ; tbz x1,#0,+8 ; sub x1,x1,#1
func BenchmarkBranch(b *testing.B) {
	benchRun(b, func(c *CPU) { c.SetX(1, 1) },
		0xb4000041, 0x91000421, 0x36000041, 0xd1000421)
}

// add v1.4s,v1.4s,v2.4s ; eor v3.16b,v1.16b,v2.16b ; ushl v4.4s,v1.4s,v2.4s ; xtn v5.4h,v1.4s
func BenchmarkSIMD(b *testing.B) {
	benchRun(b, nil, 0x4ea28421, 0x6e221c23, 0x6ea24424, 0x0e612825)
}

// fadd d1,d1,d2 ; fmul d3,d1,d2 ; fmadd d4,d1,d2,d3 ; fcvtzs x5,d1
func BenchmarkFloat(b *testing.B) {
	benchRun(b, nil, 0x1e622821, 0x1e620823, 0x1f420c24, 0x9e780025)
}

// A mix in roughly the proportions a real workload executes: loads and stores,
// integer ALU, a compare and a branch.
func BenchmarkMixed(b *testing.B) {
	// x1 must be non-zero: the trailing cbz has to fall through to the
	// loop-back branch rather than jumping over it.
	benchRun(b, func(c *CPU) { c.SetX(0, tData+0x800); c.SetX(1, 1) },
		0xf9400002, // ldr x2,[x0]
		0x91000442, // add x2,x2,#1
		0xf9000402, // str x2,[x0,#8]
		0xaa0203e3, // mov x3,x2
		0xf9400c04, // ldr x4,[x0,#24]
		0xeb04005f, // cmp x2,x4
		0x9a841043, // csel x3,x2,x4,ne
		0xf9401005, // ldr x5,[x0,#32]
		0x8b050042, // add x2,x2,x5
		0xb4000041, // cbz x1,+8 (not taken)
	)
}

// Loads on a page no hook watches must stay on the fast path even while hooks
// exist elsewhere: one narrow hook used to push every load in the address
// space onto the slow path.
func BenchmarkLoadWithDistantHook(b *testing.B) {
	benchRun(b, func(c *CPU) {
		c.SetX(0, tData+0x800)
		far := uint64(tData + 8*PageSize)
		c.Mem.AddReadHook(far, far+0xff, func(uint64, int, int64) {})
	}, 0xf9400002, 0xf9400403, 0xf9400804, 0xf9400c05)
}

// The same loads with a hook that does watch them, for comparison.
func BenchmarkLoadWithCoveringHook(b *testing.B) {
	benchRun(b, func(c *CPU) {
		c.SetX(0, tData+0x800)
		c.Mem.AddReadHook(0, ^uint64(0), func(uint64, int, int64) {})
	}, 0xf9400002, 0xf9400403, 0xf9400804, 0xf9400c05)
}

// BenchmarkDispatchFloor is the cost of the run loop itself: NOP decodes to a
// handler that only advances PC, so this is the PC and alignment test, the
// fetch-cache test, the hook test, the array index, the nil test, the indirect
// call and the retire counter — everything a faster execution strategy would
// have to remove. The difference between this and a real kernel is the part
// that is actual work.
func BenchmarkDispatchFloor(b *testing.B) {
	benchRun(b, nil, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f) // nop x4
}

// A single register-to-register move: the cheapest instruction that does
// something, for comparison against the floor.
func BenchmarkMovReg(b *testing.B) {
	benchRun(b, nil, 0xaa0003e1, 0xaa0103e2, 0xaa0203e3, 0xaa0303e4)
}
