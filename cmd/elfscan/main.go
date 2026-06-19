// elfscan: scope an AArch64 .so before loading it in gonidbg. Lists needed
// libraries, imported (undefined) symbols (grouped), exports, and init
// functions. Pure stdlib (debug/elf), no cgo.
//
// Usage: elfscan <path/to/lib.so>
package main

import (
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: elfscan <path/to/lib.so>")
		os.Exit(2)
	}
	path := os.Args[1]
	f, err := elf.Open(path)
	if err != nil {
		fmt.Println("open:", err)
		os.Exit(1)
	}
	defer f.Close()

	fmt.Printf("== ELF ==\nclass=%s machine=%s type=%s entry=0x%x\n",
		f.Class, f.Machine, f.Type, f.Entry)

	// DT_NEEDED
	needed, _ := f.DynString(elf.DT_NEEDED)
	fmt.Printf("\n== DT_NEEDED (%d) ==\n", len(needed))
	for _, n := range needed {
		fmt.Println("  ", n)
	}

	dyn, err := f.DynamicSymbols()
	if err != nil {
		fmt.Println("dynsyms:", err)
		os.Exit(1)
	}

	var imports []elf.Symbol // undefined => must be provided by linker
	var exports []elf.Symbol
	for _, s := range dyn {
		if s.Section == elf.SHN_UNDEF && s.Name != "" {
			imports = append(imports, s)
		} else if s.Section != elf.SHN_UNDEF && s.Name != "" &&
			elf.ST_BIND(s.Info) == elf.STB_GLOBAL {
			exports = append(exports, s)
		}
	}
	sort.Slice(imports, func(i, j int) bool { return imports[i].Name < imports[j].Name })

	// Group imports by likely library / category.
	cat := map[string][]string{}
	for _, s := range imports {
		cat[classify(s.Name)] = append(cat[classify(s.Name)], s.Name)
	}
	fmt.Printf("\n== IMPORTED (undefined) symbols: %d total ==\n", len(imports))
	var keys []string
	for k := range cat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("\n-- %s (%d) --\n", k, len(cat[k]))
		fmt.Println("  " + strings.Join(cat[k], ", "))
	}

	fmt.Printf("\n== EXPORTED global symbols: %d (showing JNI/init-ish) ==\n", len(exports))
	for _, s := range exports {
		if strings.Contains(s.Name, "JNI") || strings.HasPrefix(s.Name, "Java_") ||
			strings.Contains(strings.ToLower(s.Name), "init") {
			fmt.Printf("  0x%-8x %s\n", s.Value, s.Name)
		}
	}

	// init / init_array
	fmt.Printf("\n== init ==\n")
	if v, err := f.DynValue(elf.DT_INIT); err == nil && len(v) > 0 && v[0] != 0 {
		fmt.Printf("  DT_INIT      0x%x\n", v[0])
	}
	if v, err := f.DynValue(elf.DT_INIT_ARRAY); err == nil && len(v) > 0 {
		sz, _ := f.DynValue(elf.DT_INIT_ARRAYSZ)
		n := uint64(0)
		if len(sz) > 0 {
			n = sz[0] / 8
		}
		fmt.Printf("  DT_INIT_ARRAY 0x%x  count=%d\n", v[0], n)
	}

	// sections overview (sizes => emulator memory budget)
	fmt.Printf("\n== sections ==\n")
	for _, sec := range f.Sections {
		if sec.Size == 0 {
			continue
		}
		switch sec.Name {
		case ".text", ".data", ".bss", ".rodata", ".plt", ".got", ".data.rel.ro",
			".init_array", ".dynsym", ".dynstr", ".rela.dyn", ".rela.plt":
			fmt.Printf("  %-14s addr=0x%-8x size=0x%x\n", sec.Name, sec.Addr, sec.Size)
		}
	}
}

func classify(name string) string {
	libc := map[string]bool{
		"malloc": true, "free": true, "calloc": true, "realloc": true,
		"memcpy": true, "memmove": true, "memset": true, "memcmp": true,
		"strlen": true, "strcmp": true, "strncmp": true, "strcpy": true, "strcat": true,
		"strdup": true, "strchr": true, "strstr": true, "strtol": true,
		"open": true, "close": true, "read": true, "write": true, "lseek": true,
		"mmap": true, "munmap": true, "mprotect": true, "madvise": true,
		"abort": true, "exit": true, "__errno": true,
	}
	pthread := strings.HasPrefix(name, "pthread_")
	switch {
	case libc[name]:
		return "libc-mem/str/io"
	case pthread:
		return "libc-pthread"
	case strings.HasPrefix(name, "__"):
		return "libc-internal(__)"
	case strings.HasPrefix(name, "Jni") || strings.HasPrefix(name, "_JNI") ||
		strings.Contains(name, "JavaVM") || strings.Contains(name, "JNIEnv"):
		return "JNI"
	case strings.HasPrefix(name, "A") && strings.ToUpper(name[:1]) == name[:1]:
		return "android-NDK?"
	default:
		return "other-libc/ndk"
	}
}
