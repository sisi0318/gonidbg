package loader

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"

	"github.com/sisi0318/gonidbg/internal/emu"
)

// memBE is an in-memory emu.Backend (sparse pages) for testing the linker
// without a CPU engine. It exercises MemMap/MemWrite/MemRead/MemProtect.
type memBE struct{ pages map[uint64][]byte }

func newMemBE() *memBE { return &memBE{pages: map[uint64][]byte{}} }

func (m *memBE) page(a uint64) []byte {
	p := a &^ 0xfff
	pg := m.pages[p]
	if pg == nil {
		pg = make([]byte, 0x1000)
		m.pages[p] = pg
	}
	return pg
}
func (m *memBE) MemMap(addr, size uint64, _ int) error {
	for a := addr &^ 0xfff; a < addr+size; a += 0x1000 {
		m.page(a)
	}
	return nil
}
func (m *memBE) MemWrite(addr uint64, data []byte) error {
	for i, b := range data {
		a := addr + uint64(i)
		m.page(a)[a&0xfff] = b
	}
	return nil
}
func (m *memBE) MemRead(addr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range out {
		a := addr + uint64(i)
		out[i] = m.page(a)[a&0xfff]
	}
	return out, nil
}
func (m *memBE) MemUnmap(uint64, uint64) error          { return nil }
func (m *memBE) MemProtect(uint64, uint64, int) error   { return nil }
func (m *memBE) RegRead(emu.Reg) (uint64, error)        { return 0, nil }
func (m *memBE) RegWrite(emu.Reg, uint64) error         { return nil }
func (m *memBE) Start(uint64, uint64) error             { return nil }
func (m *memBE) Stop() error                            { return nil }
func (m *memBE) FlushCache() error                      { return nil }
func (m *memBE) Close() error                           { return nil }
func (m *memBE) HookCode(uint64, uint64, emu.CodeHookFunc) (emu.HookHandle, error) {
	return nil, nil
}
func (m *memBE) HookInterrupt(emu.InterruptHookFunc) (emu.HookHandle, error) { return nil, nil }
func (m *memBE) HookMemInvalid(func(emu.Backend, int, uint64, int, int64) bool) (emu.HookHandle, error) {
	return nil, nil
}

// A real AArch64 shared object bundled with the repo (AOSP bionic), so the
// linker is exercised against genuine RELATIVE/JUMP_SLOT/GLOB_DAT relocations
// and libc imports — no proprietary target needed.
const targetSO = "../../assets/android/sdk23/lib64/libz.so"

func TestLinkerAppliesRealSo(t *testing.T) {
	if _, err := os.Stat(targetSO); err != nil {
		t.Skipf("bundled .so not present: %v", err)
	}
	img, err := Parse(targetSO)
	if err != nil {
		t.Fatal(err)
	}
	be := newMemBE()
	const base = uint64(0x12340000)
	stub := uint64(0xee0000)
	resolve := func(name string) (uint64, bool) { stub += 0x10; return stub, true }
	if err := img.Apply(be, base, resolve); err != nil {
		t.Fatal(err)
	}

	// (a) segment content landed: ELF magic at base+0.
	hdr, _ := be.MemRead(base, 4)
	if hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F' {
		t.Fatalf("ELF magic not mapped at base: %x", hdr)
	}

	// (b) a RELATIVE reloc resolved to base+addend.
	checked := 0
	for _, r := range img.Relocs {
		if r.Type == elf.R_AARCH64_RELATIVE {
			got, _ := be.MemRead(base+r.Offset, 8)
			want := base + uint64(r.Addend)
			if binary.LittleEndian.Uint64(got) != want {
				t.Fatalf("RELATIVE @0x%x = 0x%x, want 0x%x",
					r.Offset, binary.LittleEndian.Uint64(got), want)
			}
			checked++
			if checked >= 100 {
				break
			}
		}
	}
	if checked == 0 {
		t.Fatal("no RELATIVE relocs checked")
	}
	t.Logf("verified ELF magic + %d RELATIVE relocs applied into backend", checked)

	// (c) a JUMP_SLOT import points at a resolver-provided stub (non-zero).
	for _, r := range img.Relocs {
		if r.Type == elf.R_AARCH64_JUMP_SLOT {
			got, _ := be.MemRead(base+r.Offset, 8)
			if binary.LittleEndian.Uint64(got) == 0 {
				t.Fatalf("JUMP_SLOT @0x%x not resolved", r.Offset)
			}
			t.Logf("JUMP_SLOT @0x%x -> 0x%x (%s)",
				r.Offset, binary.LittleEndian.Uint64(got), img.Syms[r.Sym].Name)
			break
		}
	}
}
