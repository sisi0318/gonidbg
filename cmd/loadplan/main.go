// loadplan: print the linker load plan for an ELF — segments, relocation
// histogram (linker complexity), import/export counts, init functions.
//
// Usage: loadplan <path/to/lib.so>
package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/sisi0318/gonidbg/internal/loader"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: loadplan <path/to/lib.so>")
		os.Exit(2)
	}
	path := os.Args[1]
	img, err := loader.Parse(path)
	if err != nil {
		fmt.Println("parse:", err)
		os.Exit(1)
	}

	fmt.Printf("== %s ==\nmachine=%s load span=0x%x (%d KiB)\n",
		img.Path, img.Machine, img.LoadSpan, img.LoadSpan/1024)

	fmt.Printf("\n== PT_LOAD segments (%d) ==\n", len(img.Segments))
	for _, s := range img.Segments {
		fmt.Printf("  vaddr=0x%-8x filesz=0x%-7x memsz=0x%-7x flags=%s\n",
			s.Vaddr, s.FileSz, s.MemSz, s.Flags)
	}

	fmt.Printf("\n== relocations: %d total ==\n", len(img.Relocs))
	hist := img.RelocHistogram()
	type kv struct {
		t elf_R
		n int
	}
	var rows []kv
	for t, n := range hist {
		rows = append(rows, kv{elf_R(t), n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	for _, r := range rows {
		fmt.Printf("  %-28s %d\n", r.t, r.n)
	}
	fmt.Printf("  -> symbol-resolving relocs (bounded by imports): %d\n", img.SymbolRelocCount())

	fmt.Printf("\n== linkage ==\n")
	fmt.Printf("  DT_NEEDED:   %v\n", img.Needed)
	fmt.Printf("  imports:     %d undefined symbols\n", len(img.Imports))
	fmt.Printf("  exports:     %d named symbols\n", len(img.Exports))
	fmt.Printf("  init_array:  %d functions\n", len(img.InitArray))
	if img.Init != 0 {
		fmt.Printf("  DT_INIT:     0x%x\n", img.Init)
	}
}

// alias so we can print the elf.R_AARCH64 Stringer without importing twice.
type elf_R = interface{ String() string }
