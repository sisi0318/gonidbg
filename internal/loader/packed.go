package loader

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// Android and modern-generic ELF compress the relative relocations that dominate
// a PIC library's .rela.dyn. A loader that only understands SHT_RELA silently
// applies none of them: the library still "loads", but every GOT slot, vtable
// pointer and .data.rel.ro entry stays at its unrelocated value.
//
//	SHT_ANDROID_REL/RELA  APS2 group-encoded stream; the NDK default for minSdk<30
//	SHT_RELR              RELR bitmap of relative-only relocs; the default for minSdk>=30
//
// assets/android/sdk23/lib64/libcpp.so in this repo is APS2: its .rela.dyn is
// type 0x60000002, and skipping it drops every RELATIVE/GLOB_DAT it contains.
const (
	shtAndroidRel  elf.SectionType = 0x60000001
	shtAndroidRela elf.SectionType = 0x60000002
	shtAndroidRelr elf.SectionType = 0x6fffff00 // pre-standard spelling of SHT_RELR
	shtRelr        elf.SectionType = 19         // SHT_RELR, generic ABI
)

// APS2 group flags (bionic: RELOCATION_GROUPED_BY_*).
const (
	apsGroupedByInfo        = 1
	apsGroupedByOffsetDelta = 2
	apsGroupedByAddend      = 4
	apsGroupHasAddend       = 8
)

// maxPackedRelocs bounds what a declared relocation count may claim, so a
// corrupt or hostile stream can't drive a huge allocation. Real libraries are
// four to five orders of magnitude below this.
const maxPackedRelocs = 1 << 24

// sleb decodes the signed-LEB128 stream an APS2 section is built from.
type sleb struct {
	b   []byte
	pos int
}

func (s *sleb) next() (int64, error) {
	var v int64
	var shift uint
	for {
		if s.pos >= len(s.b) {
			return 0, fmt.Errorf("sleb128: truncated at %d", s.pos)
		}
		c := s.b[s.pos]
		s.pos++
		if shift < 64 {
			v |= int64(c&0x7f) << shift
		}
		shift += 7
		if c&0x80 == 0 {
			if shift < 64 && c&0x40 != 0 { // sign-extend
				v |= int64(-1) << shift
			}
			return v, nil
		}
		if shift > 70 {
			return 0, fmt.Errorf("sleb128: overlong at %d", s.pos)
		}
	}
}

// decodeAPS2 expands an SHT_ANDROID_REL/RELA section into plain relocations.
//
// The stream is a run-length encoding: relocations are emitted in groups that
// may share an offset stride, an r_info, and/or an addend, so the common case
// (a long run of consecutive RELATIVE entries 8 bytes apart) costs a few bytes
// total. implicit supplies the addend for entries whose group carries none.
func decodeAPS2(data []byte, implicit func(vaddr uint64) int64) ([]Reloc, error) {
	if len(data) < 4 || string(data[:4]) != "APS2" {
		return nil, fmt.Errorf("packed relocs: want APS2 magic, got %q", data[:min(4, len(data))])
	}
	s := &sleb{b: data, pos: 4}
	total, err := s.next()
	if err != nil {
		return nil, err
	}
	if total < 0 || total > maxPackedRelocs {
		return nil, fmt.Errorf("packed relocs: implausible count %d", total)
	}
	offset, err := s.next()
	if err != nil {
		return nil, err
	}

	out := make([]Reloc, 0, total)
	var addend int64
	for int64(len(out)) < total {
		groupSize, err := s.next()
		if err != nil {
			return nil, err
		}
		if groupSize <= 0 || groupSize > total-int64(len(out)) {
			return nil, fmt.Errorf("packed relocs: bad group size %d", groupSize)
		}
		flags, err := s.next()
		if err != nil {
			return nil, err
		}

		var groupOffsetDelta, groupInfo int64
		if flags&apsGroupedByOffsetDelta != 0 {
			if groupOffsetDelta, err = s.next(); err != nil {
				return nil, err
			}
		}
		if flags&apsGroupedByInfo != 0 {
			if groupInfo, err = s.next(); err != nil {
				return nil, err
			}
		}
		if flags&apsGroupHasAddend != 0 && flags&apsGroupedByAddend != 0 {
			d, err := s.next()
			if err != nil {
				return nil, err
			}
			addend += d
		}
		if flags&apsGroupHasAddend == 0 {
			addend = 0
		}

		for i := int64(0); i < groupSize; i++ {
			if flags&apsGroupedByOffsetDelta != 0 {
				offset += groupOffsetDelta
			} else {
				d, err := s.next()
				if err != nil {
					return nil, err
				}
				offset += d
			}
			info := groupInfo
			if flags&apsGroupedByInfo == 0 {
				if info, err = s.next(); err != nil {
					return nil, err
				}
			}
			a := int64(0)
			if flags&apsGroupHasAddend != 0 {
				if flags&apsGroupedByAddend == 0 {
					d, err := s.next()
					if err != nil {
						return nil, err
					}
					addend += d
				}
				a = addend
			} else if implicit != nil {
				// REL form: the value already at the patch site is the addend.
				a = implicit(uint64(offset))
			}
			out = append(out, Reloc{
				Offset: uint64(offset),
				Type:   elf.R_AARCH64(uint64(info) & 0xffffffff),
				Sym:    uint32(uint64(info) >> 32),
				Addend: a,
			})
		}
	}
	return out, nil
}

// decodeRELR expands an SHT_RELR section. Every entry is an R_AARCH64_RELATIVE
// with an implicit addend; the section encodes only the addresses. An even word
// is an address that resets the cursor, an odd word is a 63-bit bitmap of the
// 8-byte slots following the cursor.
func decodeRELR(data []byte, implicit func(vaddr uint64) int64) []Reloc {
	var out []Reloc
	emit := func(at uint64) {
		a := int64(0)
		if implicit != nil {
			a = implicit(at)
		}
		out = append(out, Reloc{Offset: at, Type: elf.R_AARCH64_RELATIVE, Addend: a})
	}
	var where uint64
	for off := 0; off+8 <= len(data); off += 8 {
		e := binary.LittleEndian.Uint64(data[off:])
		if e&1 == 0 { // address entry
			where = e
			emit(where)
			where += 8
			continue
		}
		at := where
		for bits := e >> 1; bits != 0; bits >>= 1 {
			if bits&1 != 0 {
				emit(at)
			}
			at += 8
		}
		where += 63 * 8
	}
	return out
}

// decodeREL expands a plain SHT_REL section (16-byte entries, implicit addend).
func decodeREL(data []byte, implicit func(vaddr uint64) int64) []Reloc {
	var out []Reloc
	for off := 0; off+16 <= len(data); off += 16 {
		rOff := binary.LittleEndian.Uint64(data[off:])
		rInfo := binary.LittleEndian.Uint64(data[off+8:])
		a := int64(0)
		if implicit != nil {
			a = implicit(rOff)
		}
		out = append(out, Reloc{
			Offset: rOff,
			Type:   elf.R_AARCH64(rInfo & 0xffffffff),
			Sym:    uint32(rInfo >> 32),
			Addend: a,
		})
	}
	return out
}

// implicitAddendFunc reads the value already stored at an image-relative vaddr
// in the file image. REL and RELR carry no explicit addend — whatever the
// linker left at the patch site is it.
func implicitAddendFunc(f *elf.File) func(uint64) int64 {
	return func(vaddr uint64) int64 {
		for _, p := range f.Progs {
			if p.Type != elf.PT_LOAD || vaddr < p.Vaddr || vaddr+8 > p.Vaddr+p.Filesz {
				continue
			}
			var b [8]byte
			if _, err := p.ReadAt(b[:], int64(vaddr-p.Vaddr)); err != nil {
				return 0
			}
			return int64(binary.LittleEndian.Uint64(b[:]))
		}
		return 0 // .bss or unmapped: nothing was stored there
	}
}
