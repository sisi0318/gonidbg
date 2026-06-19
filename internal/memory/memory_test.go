package memory

import "testing"

func TestMmapMonotonicAndFind(t *testing.T) {
	s := NewSpace()
	a := s.Mmap(0x100, ProtRW, "a")
	b := s.Mmap(0x1, ProtRW, "b") // rounds up to one page
	if a != MmapBase {
		t.Fatalf("first mmap = 0x%x, want 0x%x", a, MmapBase)
	}
	if b != MmapBase+0x1000 {
		t.Fatalf("second mmap = 0x%x, want 0x%x", b, MmapBase+0x1000)
	}
	if r, ok := s.Find(a + 0x10); !ok || r.Desc != "a" {
		t.Fatalf("Find(a+0x10) = %+v ok=%v", r, ok)
	}
}

func TestMunmapSplit(t *testing.T) {
	s := NewSpace()
	base := s.Mmap(0x4000, ProtRW, "big") // 4 pages
	s.Munmap(base+0x1000, 0x1000)         // punch a hole in page 2
	if _, ok := s.Find(base + 0x1000); ok {
		t.Fatal("hole should be unmapped")
	}
	if _, ok := s.Find(base); !ok {
		t.Fatal("head should remain")
	}
	if _, ok := s.Find(base + 0x3000); !ok {
		t.Fatal("tail should remain")
	}
}

func TestMapOverlapRejected(t *testing.T) {
	s := NewSpace()
	if err := s.Map(0x100000, 0x2000, ProtRX, "lib"); err != nil {
		t.Fatal(err)
	}
	if err := s.Map(0x101000, 0x1000, ProtRX, "dup"); err == nil {
		t.Fatal("expected overlap error")
	}
}

const (
	ProtRW = 1 | 2
	ProtRX = 1 | 4
)
