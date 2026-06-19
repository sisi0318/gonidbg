// Package memory manages the guest virtual address space: a page-granular
// region allocator backing the mmap/munmap/mprotect/brk syscalls and the
// loader's segment placement. It mirrors unidbg's allocator (a monotonic
// MMAP_BASE with a free list), but only tracks address ranges + protection —
// the actual bytes live in the CPU backend's memory. Pure Go, unit-tested.
package memory

import (
	"fmt"
	"sort"
)

const (
	PageSize = 0x1000
	// MmapBase matches unidbg's default ARM64 mmap base so guest pointers land
	// in the same range the original .so was reverse-engineered against.
	MmapBase = 0x40000000
	// StackBase / StackSize match unidbg's ARM64 defaults.
	StackTopBase = 0x7ffff0000000
	StackSize    = 0x80000 // 512 KiB
)

// Region is one mapped range.
type Region struct {
	Addr uint64
	Size uint64
	Prot int
	Desc string // e.g. "[stack]", "libc.so", "mmap"
}

func (r Region) End() uint64 { return r.Addr + r.Size }

// Space is the guest address space allocator.
type Space struct {
	regions []Region
	mmapTop uint64
}

func NewSpace() *Space { return &Space{mmapTop: MmapBase} }

func pageUp(x uint64) uint64 { return (x + PageSize - 1) &^ (PageSize - 1) }

// Map reserves an explicit fixed range (used by the loader for PT_LOAD
// segments at their bias). Errors on overlap.
func (s *Space) Map(addr, size uint64, prot int, desc string) error {
	addr &^= PageSize - 1
	size = pageUp(size)
	if size == 0 {
		return fmt.Errorf("memory: zero-size map at 0x%x", addr)
	}
	for _, r := range s.regions {
		if addr < r.End() && r.Addr < addr+size {
			return fmt.Errorf("memory: map 0x%x+0x%x overlaps %s@0x%x", addr, size, r.Desc, r.Addr)
		}
	}
	s.insert(Region{addr, size, prot, desc})
	return nil
}

// Mmap allocates size bytes at the next free MMAP_BASE-relative address,
// returning the base. Mirrors unidbg's anonymous mmap path.
func (s *Space) Mmap(size uint64, prot int, desc string) uint64 {
	size = pageUp(size)
	addr := s.mmapTop
	s.mmapTop += size
	s.insert(Region{addr, size, prot, desc})
	return addr
}

// Munmap releases [addr,addr+size). Partial unmaps split the region.
func (s *Space) Munmap(addr, size uint64) {
	addr &^= PageSize - 1
	size = pageUp(size)
	end := addr + size
	var out []Region
	for _, r := range s.regions {
		if addr >= r.End() || end <= r.Addr { // disjoint
			out = append(out, r)
			continue
		}
		if r.Addr < addr { // keep head
			out = append(out, Region{r.Addr, addr - r.Addr, r.Prot, r.Desc})
		}
		if end < r.End() { // keep tail
			out = append(out, Region{end, r.End() - end, r.Prot, r.Desc})
		}
	}
	s.regions = out
	s.sortRegions()
}

// Protect changes protection over a range that must already be mapped.
func (s *Space) Protect(addr, size uint64, prot int) error {
	addr &^= PageSize - 1
	end := addr + pageUp(size)
	hit := false
	for i := range s.regions {
		r := &s.regions[i]
		if r.Addr >= addr && r.End() <= end {
			r.Prot = prot
			hit = true
		}
	}
	if !hit {
		return fmt.Errorf("memory: mprotect 0x%x+0x%x covers no full region", addr, size)
	}
	return nil
}

// Find returns the region containing addr, if any.
func (s *Space) Find(addr uint64) (Region, bool) {
	i := sort.Search(len(s.regions), func(i int) bool { return s.regions[i].End() > addr })
	if i < len(s.regions) && s.regions[i].Addr <= addr {
		return s.regions[i], true
	}
	return Region{}, false
}

func (s *Space) Regions() []Region { return s.regions }

func (s *Space) insert(r Region) {
	s.regions = append(s.regions, r)
	s.sortRegions()
}

func (s *Space) sortRegions() {
	sort.Slice(s.regions, func(i, j int) bool { return s.regions[i].Addr < s.regions[j].Addr })
}
