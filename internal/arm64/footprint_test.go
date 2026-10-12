package arm64

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// BenchmarkFootprint measures how the interpreter slows down as the amount of
// distinct guest code grows. Each decoded instruction occupies 32 bytes, so a
// workload touching N instructions needs 32N bytes of decode cache: the real
// library this engine was tuned against executes 122k distinct addresses, i.e.
// ~3.9 MB, which does not fit in L2. The instructions here are pure ALU ops so
// the only thing varying is that footprint.
//
//	go test -run X -bench Footprint ./internal/arm64
func BenchmarkFootprint(b *testing.B) {
	for _, pages := range []int{1, 4, 16, 64, 256, 1024} {
		insns := pages * PageSize / 4
		b.Run(fmt.Sprintf("%dKiB_code/%dKiB_decoded", pages*4, insns*32/1024), func(b *testing.B) {
			c := New()
			if err := c.Mem.Map(tCode, uint64(pages)*PageSize, ProtRead|ProtExec); err != nil {
				b.Fatal(err)
			}
			body := []uint32{0x91000421, 0xd1000442, 0xaa020023, 0xca010064}
			n := insns - 1
			buf := make([]byte, 4*insns)
			for i := 0; i < n; i++ {
				binary.LittleEndian.PutUint32(buf[4*i:], body[i%len(body)])
			}
			binary.LittleEndian.PutUint32(buf[4*n:], 0x14000000|uint32(-int32(n))&0x03ffffff)
			if err := c.Mem.HostWrite(tCode, buf); err != nil {
				b.Fatal(err)
			}
			c.PC = tCode
			// decode everything once so the measurement is steady state
			if err := c.Run(0, uint64(insns)); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			if err := c.Run(0, uint64(b.N)); err != nil {
				b.Fatal(err)
			}
		})
	}
}

// BenchmarkPredictability isolates the cost of indirect-branch mispredictions
// in the dispatch loop. Both cases execute the same number of instructions
// over the same code footprint; only the *order* differs. A short repeating
// cycle is perfectly predictable, so the CPU's indirect-branch predictor learns
// every handler target; a long varied sequence is the shape real code has.
//
// This is the number that decides whether a faster dispatch strategy is worth
// building: whatever the gap is here is what fusing instructions (fewer
// indirect branches) or emitting native code (none at all) could recover.
func BenchmarkPredictability(b *testing.B) {
	// 16 distinct, cheap, register-only instructions
	pool := []uint32{
		0x91000421, // add x1,x1,#1
		0xd1000442, // sub x2,x2,#1
		0xaa020023, // orr x3,x1,x2
		0xca010064, // eor x4,x3,x1
		0x8a0200a5, // and x5,x5,x2
		0xab0300c6, // adds x6,x6,x3
		0xcb0400e7, // subs x7,x7,x4
		0x9a8500a8, // csel x8,x5,x5,eq
		0xd3407c09, // ubfx x9,x0,#0,#32
		0x9b027c2a, // mul x10,x1,x2
		0xdac0100b, // clz x11,x0
		0xdac0000c, // rbit x12,x0
		0x9ac2202d, // lsl x13,x1,x2
		0x9ac2242e, // lsr x14,x1,x2
		0xd37ff82f, // lsl x15,x1,#1
		0xaa0103f0, // mov x16,x1
	}
	const pages = 64
	insns := pages * PageSize / 4

	run := func(b *testing.B, pick func(i int) uint32) {
		c := New()
		if err := c.Mem.Map(tCode, pages*PageSize, ProtRead|ProtExec); err != nil {
			b.Fatal(err)
		}
		n := insns - 1
		buf := make([]byte, 4*insns)
		for i := 0; i < n; i++ {
			binary.LittleEndian.PutUint32(buf[4*i:], pick(i))
		}
		binary.LittleEndian.PutUint32(buf[4*n:], 0x14000000|uint32(-int32(n))&0x03ffffff)
		if err := c.Mem.HostWrite(tCode, buf); err != nil {
			b.Fatal(err)
		}
		c.PC = tCode
		if err := c.Run(0, uint64(insns)); err != nil {
			b.Fatal(err)
		}
		b.ResetTimer()
		if err := c.Run(0, uint64(b.N)); err != nil {
			b.Fatal(err)
		}
	}

	b.Run("repeating_cycle_of_4", func(b *testing.B) {
		run(b, func(i int) uint32 { return pool[i%4] })
	})
	b.Run("varied_sequence", func(b *testing.B) {
		// a cheap LCG, so the handler order is unpredictable but the footprint
		// and instruction mix are the same
		s := uint32(12345)
		return_ := func(i int) uint32 {
			s = s*1664525 + 1013904223
			return pool[(s>>16)%uint32(len(pool))]
		}
		run(b, return_)
	})
}
