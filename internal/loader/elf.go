// Package loader parses an Android ARM64 ELF shared object into a backend-
// agnostic load plan: segments to map, relocations to apply, symbols to
// export/import, and init functions to run. It is the data layer of the
// dynamic linker — applying the plan against guest memory lives in the linker
// once a CPU backend is wired up. Pure stdlib (debug/elf), no cgo.
package loader

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// Segment is one PT_LOAD region copied into guest memory at Vaddr+base.
type Segment struct {
	Vaddr   uint64
	FileSz  uint64
	MemSz   uint64 // MemSz>FileSz => zero-fill (.bss)
	Off     uint64
	Flags   elf.ProgFlag // R/W/X
	Aligned uint64       // page-aligned size
}

// Reloc is one dynamic relocation entry (RELA form).
type Reloc struct {
	Offset uint64 // where to patch (image-relative)
	Type   elf.R_AARCH64
	Sym    uint32 // index into dynamic symbol table (0 = none)
	Addend int64
}

// Sym is a dynamic symbol (imported when Undef, else exported).
type Sym struct {
	Name  string
	Value uint64
	Size  uint64
	Undef bool
	Bind  elf.SymBind
	Type  elf.SymType
}

// Image is the parsed, ready-to-map representation of one .so.
type Image struct {
	Path          string
	Machine       elf.Machine
	Segments      []Segment
	Relocs        []Reloc
	Syms          []Sym // indexed identically to ELF .dynsym
	Imports       []string
	Exports       map[string]uint64 // name -> image-relative addr
	InitArray     []uint64          // RAW .init_array contents (often all 0 on AArch64 — RELA addends hold the real pointers; read post-relocation from memory instead)
	InitArrayAddr uint64            // image-relative vaddr of .init_array
	InitArrayLen  int               // number of entries
	Init          uint64            // DT_INIT (0 if none)
	Needed        []string
	LoadSpan      uint64 // total virtual span to reserve
}

// Parse reads the ELF and builds the Image. base is not applied here; all
// addresses are image-relative (load bias added at map time).
func Parse(path string) (*Image, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	img := &Image{
		Path:    path,
		Machine: f.Machine,
		Exports: map[string]uint64{},
	}
	img.Needed, _ = f.DynString(elf.DT_NEEDED)

	var maxEnd uint64
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		seg := Segment{
			Vaddr: p.Vaddr, FileSz: p.Filesz, MemSz: p.Memsz,
			Off: p.Off, Flags: p.Flags, Aligned: pageUp(p.Vaddr+p.Memsz) - pageDown(p.Vaddr),
		}
		img.Segments = append(img.Segments, seg)
		if end := p.Vaddr + p.Memsz; end > maxEnd {
			maxEnd = end
		}
	}
	img.LoadSpan = pageUp(maxEnd)

	// Dynamic symbols (index-aligned with relocation r_sym).
	dyn, err := f.DynamicSymbols()
	if err == nil {
		// debug/elf drops the null symbol at index 0; r_sym indexes the real
		// table, so prepend a placeholder to realign.
		img.Syms = append(img.Syms, Sym{Name: ""})
		for _, s := range dyn {
			undef := s.Section == elf.SHN_UNDEF
			img.Syms = append(img.Syms, Sym{
				Name: s.Name, Value: s.Value, Size: s.Size, Undef: undef,
				Bind: elf.ST_BIND(s.Info), Type: elf.ST_TYPE(s.Info),
			})
			if undef {
				if s.Name != "" {
					img.Imports = append(img.Imports, s.Name)
				}
			} else if s.Name != "" {
				img.Exports[s.Name] = s.Value
			}
		}
	}

	// Relocations: parse SHT_RELA sections manually (we need r_sym + type).
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_RELA {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", sec.Name, err)
		}
		for off := 0; off+24 <= len(data); off += 24 {
			rOff := binary.LittleEndian.Uint64(data[off:])
			rInfo := binary.LittleEndian.Uint64(data[off+8:])
			rAdd := int64(binary.LittleEndian.Uint64(data[off+16:]))
			img.Relocs = append(img.Relocs, Reloc{
				Offset: rOff,
				Type:   elf.R_AARCH64(rInfo & 0xffffffff),
				Sym:    uint32(rInfo >> 32),
				Addend: rAdd,
			})
		}
	}

	// init_array
	if v, err := f.DynValue(elf.DT_INIT); err == nil && len(v) > 0 {
		img.Init = v[0]
	}
	for _, sec := range f.Sections {
		if sec.Type == elf.SHT_INIT_ARRAY {
			img.InitArrayAddr = sec.Addr
			img.InitArrayLen = int(sec.Size / 8)
			data, err := sec.Data()
			if err != nil {
				return nil, err
			}
			for off := 0; off+8 <= len(data); off += 8 {
				img.InitArray = append(img.InitArray, binary.LittleEndian.Uint64(data[off:]))
			}
		}
	}
	return img, nil
}

// RelocHistogram counts relocations by type — the linker only needs to
// implement the types that actually appear.
func (img *Image) RelocHistogram() map[elf.R_AARCH64]int {
	h := map[elf.R_AARCH64]int{}
	for _, r := range img.Relocs {
		h[r.Type]++
	}
	return h
}

// SymbolReloc reports relocations that require resolving an imported symbol
// (GLOB_DAT/JUMP_SLOT/ABS64 with a named undef symbol). These are the only
// ones whose count is bounded by the import surface.
func (img *Image) SymbolRelocCount() int {
	n := 0
	for _, r := range img.Relocs {
		if r.Sym != 0 && int(r.Sym) < len(img.Syms) && img.Syms[r.Sym].Undef {
			n++
		}
	}
	return n
}

func pageUp(x uint64) uint64   { return (x + 0xfff) &^ 0xfff }
func pageDown(x uint64) uint64 { return x &^ 0xfff }
