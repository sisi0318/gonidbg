package loader

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"
)

// sleb128 encodes signed LEB128, the encoding an APS2 stream is built from.
// Used to hand-build streams so the decoder is checked against the spec rather
// than against itself.
func sleb128(vals ...int64) []byte {
	var out []byte
	for _, v := range vals {
		for {
			c := byte(v & 0x7f)
			v >>= 7
			done := (v == 0 && c&0x40 == 0) || (v == -1 && c&0x40 != 0)
			if !done {
				c |= 0x80
			}
			out = append(out, c)
			if done {
				break
			}
		}
	}
	return out
}

func TestSLEB128RoundTrip(t *testing.T) {
	vals := []int64{0, 1, -1, 63, 64, -64, -65, 127, -127, 8192, -8192, 1 << 40, -(1 << 40)}
	s := &sleb{b: sleb128(vals...)}
	for _, want := range vals {
		got, err := s.next()
		if err != nil {
			t.Fatalf("decoding %d: %v", want, err)
		}
		if got != want {
			t.Errorf("got %d, want %d", got, want)
		}
	}
	if s.pos != len(s.b) {
		t.Errorf("consumed %d of %d bytes", s.pos, len(s.b))
	}
}

// TestDecodeAPS2Groups checks both group shapes: one fully grouped (shared
// stride, shared r_info, shared addend) and one fully explicit.
func TestDecodeAPS2Groups(t *testing.T) {
	stream := []byte("APS2")
	stream = append(stream, sleb128(3, 0x1000)...) // total, initial offset
	// group 1: 2 relocs sharing stride 8, info RELATIVE, addend 0x2000
	stream = append(stream, sleb128(2,
		apsGroupedByOffsetDelta|apsGroupedByInfo|apsGroupHasAddend|apsGroupedByAddend,
		8, int64(elf.R_AARCH64_RELATIVE), 0x2000)...)
	// group 2: 1 reloc, nothing grouped, no addend
	stream = append(stream, sleb128(1, 0)...)
	stream = append(stream, sleb128(0x10, int64(5)<<32|int64(elf.R_AARCH64_GLOB_DAT))...)

	got, err := decodeAPS2(stream, nil)
	if err != nil {
		t.Fatalf("decodeAPS2: %v", err)
	}
	want := []Reloc{
		{Offset: 0x1008, Type: elf.R_AARCH64_RELATIVE, Addend: 0x2000},
		{Offset: 0x1010, Type: elf.R_AARCH64_RELATIVE, Addend: 0x2000},
		{Offset: 0x1020, Type: elf.R_AARCH64_GLOB_DAT, Sym: 5},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d relocs, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reloc %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDecodeAPS2Rejects(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":      {},
		"bad magic":  []byte("APS1\x00\x00"),
		"truncated":  append([]byte("APS2"), sleb128(4, 0x1000)...),
		"huge count": append([]byte("APS2"), sleb128(maxPackedRelocs+1, 0)...),
	} {
		if _, err := decodeAPS2(in, nil); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// TestDecodeRELR checks the address-entry / bitmap-entry alternation.
func TestDecodeRELR(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint64(data[0:], 0x1000)      // address entry
	binary.LittleEndian.PutUint64(data[8:], 0b1011<<1|1) // bitmap: slots 0,1,3 after 0x1008

	got := decodeRELR(data, nil)
	want := []uint64{0x1000, 0x1008, 0x1010, 0x1020}
	if len(got) != len(want) {
		t.Fatalf("got %d relocs, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].Offset != w {
			t.Errorf("reloc %d: offset %#x, want %#x", i, got[i].Offset, w)
		}
		if got[i].Type != elf.R_AARCH64_RELATIVE {
			t.Errorf("reloc %d: type %v, want RELATIVE", i, got[i].Type)
		}
	}
}

// TestPackedRelocsRealLibrary guards the regression this decoder exists for:
// libcpp.so's .rela.dyn is SHT_ANDROID_RELA (0x60000002), and a loader that
// only matches SHT_RELA silently drops every relocation in it — the library
// still "parses", so nothing downstream notices until a vtable is dereferenced.
func TestPackedRelocsRealLibrary(t *testing.T) {
	const so = "../../assets/android/sdk23/lib64/libcpp.so"
	if _, err := os.Stat(so); err != nil {
		t.Skipf("bundled .so not present: %v", err)
	}

	f, err := elf.Open(so)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var packed *elf.Section
	for _, s := range f.Sections {
		if s.Type == shtAndroidRela {
			packed = s
		}
	}
	if packed == nil {
		t.Skip("libcpp.so is no longer APS2-packed; regression no longer reproducible here")
	}

	img, err := Parse(so)
	if err != nil {
		t.Fatal(err)
	}

	// The packed section must contribute; .rela.plt alone is 449 entries.
	hist := img.RelocHistogram()
	if n := hist[elf.R_AARCH64_RELATIVE]; n == 0 {
		t.Errorf("no RELATIVE relocations decoded — the packed section was dropped")
	}
	if len(img.Relocs) <= 449 {
		t.Errorf("got %d relocations; expected the packed section on top of .rela.plt's 449", len(img.Relocs))
	}

	// Every decoded relocation must be structurally sound, which a mis-parsed
	// SLEB128 stream would not be: offsets land in a PT_LOAD, symbol indices
	// are in range, and the type is one the AArch64 ABI defines.
	inLoad := func(v uint64) bool {
		for _, s := range img.Segments {
			if v >= s.Vaddr && v+8 <= s.Vaddr+s.MemSz {
				return true
			}
		}
		return false
	}
	for i, r := range img.Relocs {
		if !inLoad(r.Offset) {
			t.Fatalf("reloc %d: offset %#x outside every PT_LOAD", i, r.Offset)
		}
		if int(r.Sym) >= len(img.Syms) {
			t.Fatalf("reloc %d: symbol index %d >= dynsym length %d", i, r.Sym, len(img.Syms))
		}
		switch r.Type {
		case elf.R_AARCH64_RELATIVE, elf.R_AARCH64_GLOB_DAT,
			elf.R_AARCH64_JUMP_SLOT, elf.R_AARCH64_ABS64:
		default:
			t.Fatalf("reloc %d: implausible type %v at %#x", i, r.Type, r.Offset)
		}
		// A symbol-bearing reloc must name a symbol; a RELATIVE must not.
		if r.Type == elf.R_AARCH64_RELATIVE && r.Sym != 0 {
			t.Fatalf("reloc %d: RELATIVE with symbol index %d", i, r.Sym)
		}
	}
}
