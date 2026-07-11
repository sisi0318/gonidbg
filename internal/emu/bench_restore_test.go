//go:build unicorn || dynarmic

package emu

import (
	"testing"
)

// Measures the per-call cost of the emulator's snapshot Restore primitives, so
// we can quantify the reuse overhead against a real sign (~360 ms).
func openBE(tb testing.TB) Backend {
	b, err := New()
	if err != nil {
		tb.Skipf("no backend: %v", err)
	}
	return b
}

func BenchmarkMemWrite8MiB(b *testing.B) {
	be := openBE(b)
	defer be.Close()
	const base, size = 0xC0000000, 8 << 20
	if err := be.MemMap(base, size, ProtRead|ProtWrite); err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, size)
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := be.MemWrite(base, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMemRead8MiB(b *testing.B) {
	be := openBE(b)
	defer be.Close()
	const base, size = 0xC0000000, 8 << 20
	if err := be.MemMap(base, size, ProtRead|ProtWrite); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := be.MemRead(base, size); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSaveRestoreContext(b *testing.B) {
	be := openBE(b)
	defer be.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, err := be.SaveContext()
		if err != nil {
			b.Fatal(err)
		}
		if err := be.RestoreContext(ctx); err != nil {
			b.Fatal(err)
		}
		_ = ctx.Free()
	}
}

// A realistic per-call restore footprint: 8 MiB stack + ~4 MiB .data/.bss +
// 1 MiB stubs + 64 KiB TLS + 2 MiB heap, plus one context restore.
func BenchmarkRestoreFootprint(b *testing.B) {
	be := openBE(b)
	defer be.Close()
	regions := []struct {
		base, size uint64
	}{
		{0xC0000000, 8 << 20}, // stack
		{0x12800000, 4 << 20}, // .data/.bss
		{0x60000000, 1 << 20}, // stubs
		{0xD0000000, 64 << 10}, // tls
		{0x30000000, 2 << 20}, // brk
	}
	var total uint64
	for _, r := range regions {
		if err := be.MemMap(r.base, r.size, ProtRead|ProtWrite); err != nil {
			b.Fatal(err)
		}
		total += r.size
	}
	bufs := make([][]byte, len(regions))
	for i, r := range regions {
		bufs[i] = make([]byte, r.size)
	}
	b.SetBytes(int64(total))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j, r := range regions {
			if err := be.MemWrite(r.base, bufs[j]); err != nil {
				b.Fatal(err)
			}
		}
		ctx, err := be.SaveContext()
		if err != nil {
			b.Fatal(err)
		}
		_ = be.RestoreContext(ctx)
		_ = ctx.Free()
	}
}
