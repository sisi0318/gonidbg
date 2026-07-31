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
	// Absolute marks SHN_ABS symbols, whose Value is a literal constant rather
	// than an image-relative address — adding the load bias to one is wrong.
	// Version pseudo-symbols ("LIBC", "LIBC_PRIVATE") are the common case.
	Absolute bool
	Bind     elf.SymBind
	Type     elf.SymType
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

// exportable reports whether a defined dynamic symbol belongs in Exports, i.e.
// whether its Value is an image-relative address another module may bind to.
//
// Three kinds get filtered out, all of which used to be exported and then had
// the load bias added to them:
//
//   - SHN_ABS: version pseudo-symbols like "LIBC"/"LIBC_PRIVATE", whose value is
//     a constant (usually 0, so they registered as base+0);
//   - STB_LOCAL: not externally visible by definition;
//   - STT_TLS: the value is an offset into the TLS block, not the image.
func exportable(bind elf.SymBind, typ elf.SymType, absolute bool) bool {
	if absolute || typ == elf.STT_TLS {
		return false
	}
	return bind == elf.STB_GLOBAL || bind == elf.STB_WEAK
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
			bind, typ := elf.ST_BIND(s.Info), elf.ST_TYPE(s.Info)
			abs := s.Section == elf.SHN_ABS
			img.Syms = append(img.Syms, Sym{
				Name: s.Name, Value: s.Value, Size: s.Size, Undef: undef,
				Absolute: abs, Bind: bind, Type: typ,
			})
			switch {
			case s.Name == "":
			case undef:
				img.Imports = append(img.Imports, s.Name)
			case exportable(bind, typ, abs):
				img.Exports[s.Name] = s.Value
			}
		}
	}

	// Relocations: parse each section manually (we need r_sym + type). Beyond
	// plain SHT_RELA this must cover the compressed encodings the NDK emits by
	// default — see packed.go. Skipping them is silent: the library loads with
	// its relative relocations unapplied.
	implicit := implicitAddendFunc(f)
	for _, sec := range f.Sections {
		switch sec.Type {
		case elf.SHT_RELA, elf.SHT_REL, shtAndroidRela, shtAndroidRel, shtRelr, shtAndroidRelr:
		default:
			continue // don't pay sec.Data() on .text and friends
		}
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", sec.Name, err)
		}
		switch sec.Type {
		case elf.SHT_RELA:
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
		case shtAndroidRela, shtAndroidRel:
			var impl func(uint64) int64
			if sec.Type == shtAndroidRel {
				impl = implicit
			}
			rs, err := decodeAPS2(data, impl)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", sec.Name, err)
			}
			img.Relocs = append(img.Relocs, rs...)
		case shtRelr, shtAndroidRelr:
			img.Relocs = append(img.Relocs, decodeRELR(data, implicit)...)
		case elf.SHT_REL:
			img.Relocs = append(img.Relocs, decodeREL(data, implicit)...)
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
