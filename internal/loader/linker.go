package loader

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/sisi0318/gonidbg/internal/emu"
)

// Resolver maps an imported symbol name to a guest address (e.g. a bionic
// export or an SVC trampoline). ok=false means unresolved.
// weak reports whether this is a weak undefined reference; a resolver must
// return ok=false for those unless it has a genuine definition, so the linker
// can bind them to 0 as the ABI requires.
type Resolver func(name string, weak bool) (addr uint64, ok bool)

// Apply maps the image's PT_LOAD segments into the backend at `base` and
// performs all dynamic relocations. After this the module's code/data is live
// in guest memory; init_array still needs to be executed by the caller.
//
// Only the 4 relocation types this target actually uses are handled (verified
// via cmd/loadplan): RELATIVE, GLOB_DAT, JUMP_SLOT, ABS64.
func (img *Image) Apply(be emu.Backend, base uint64, resolve Resolver) error {
	raw, err := os.ReadFile(img.Path)
	if err != nil {
		return fmt.Errorf("read %s: %w", img.Path, err)
	}

	// 1. Map segments writable, copy file contents (MemSz>FileSz => .bss zeroed
	//    automatically since fresh guest pages read as 0).
	for _, s := range img.Segments {
		va := base + pageDown(s.Vaddr)
		sz := pageUp(s.Vaddr+s.MemSz) - pageDown(s.Vaddr)
		if err := be.MemMap(va, sz, emu.ProtRead|emu.ProtWrite|emu.ProtExec); err != nil {
			return fmt.Errorf("map seg @0x%x: %w", va, err)
		}
		if s.FileSz > 0 {
			if err := be.MemWrite(base+s.Vaddr, raw[s.Off:s.Off+s.FileSz]); err != nil {
				return fmt.Errorf("write seg @0x%x: %w", base+s.Vaddr, err)
			}
		}
	}

	// 2. Relocations.
	for _, r := range img.Relocs {
		target := base + r.Offset
		switch r.Type {
		case elf.R_AARCH64_RELATIVE:
			if err := put64(be, target, base+uint64(r.Addend)); err != nil {
				return err
			}
		case elf.R_AARCH64_GLOB_DAT, elf.R_AARCH64_JUMP_SLOT:
			val, err := img.symValue(r.Sym, base, resolve)
			if err != nil {
				return err
			}
			if err := put64(be, target, val+uint64(r.Addend)); err != nil {
				return err
			}
		case elf.R_AARCH64_ABS64:
			val, err := img.symValue(r.Sym, base, resolve)
			if err != nil {
				return err
			}
			if err := put64(be, target, val+uint64(r.Addend)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unhandled reloc type %s at 0x%x", r.Type, r.Offset)
		}
	}

	// 3. Re-protect segments to their declared permissions.
	for _, s := range img.Segments {
		va := base + pageDown(s.Vaddr)
		sz := pageUp(s.Vaddr+s.MemSz) - pageDown(s.Vaddr)
		if err := be.MemProtect(va, sz, protOf(s.Flags)); err != nil {
			return fmt.Errorf("protect seg @0x%x: %w", va, err)
		}
	}
	return nil
}

// symValue resolves a relocation's symbol: defined symbols => base+value,
// imported (undef) => via the resolver.
func (img *Image) symValue(sym uint32, base uint64, resolve Resolver) (uint64, error) {
	if int(sym) >= len(img.Syms) {
		return 0, fmt.Errorf("reloc sym index %d out of range", sym)
	}
	s := img.Syms[sym]
	if !s.Undef {
		if s.Absolute {
			return s.Value, nil // SHN_ABS: not relative to the load bias
		}
		return base + s.Value, nil
	}
	weak := s.Bind == elf.STB_WEAK
	if resolve != nil {
		if v, ok := resolve(s.Name, weak); ok {
			return v, nil
		}
	}
	// An unresolved *weak* undefined symbol binds to 0 — that is the whole point
	// of a weak reference, and the canonical `if (&sym) sym();` probe depends on
	// it. Failing the link instead breaks libraries that legitimately reference
	// optional libc (__cxa_thread_atexit_impl, getauxval) or the classic
	// __gmon_start__ / _ITM_* stubs nothing ever defines.
	if weak {
		return 0, nil
	}
	return 0, fmt.Errorf("unresolved import %q", s.Name)
}

func put64(be emu.Backend, addr, val uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], val)
	return be.MemWrite(addr, b[:])
}

func protOf(f elf.ProgFlag) int {
	p := 0
	if f&elf.PF_R != 0 {
		p |= emu.ProtRead
	}
	if f&elf.PF_W != 0 {
		p |= emu.ProtWrite
	}
	if f&elf.PF_X != 0 {
		p |= emu.ProtExec
	}
	return p
}
