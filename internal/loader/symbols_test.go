package loader

import (
	"debug/elf"
	"os"
	"testing"
)

const libcSO = "../../assets/android/sdk23/lib64/libc.so"

// TestExportsExcludeNonAddresses guards against re-polluting the global symbol
// table with entries whose Value is not an image-relative address. Every export
// gets base+Value registered in the emulator, so an SHN_ABS version
// pseudo-symbol like "LIBC" (value 0) used to resolve to the load bias itself.
func TestExportsExcludeNonAddresses(t *testing.T) {
	if _, err := os.Stat(libcSO); err != nil {
		t.Skipf("bundled .so not present: %v", err)
	}
	img, err := Parse(libcSO)
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Exports) == 0 {
		t.Fatal("no exports parsed at all")
	}
	for _, name := range []string{"LIBC", "LIBC_PRIVATE"} {
		if _, ok := img.Exports[name]; ok {
			t.Errorf("%q is an SHN_ABS version pseudo-symbol and must not be exported", name)
		}
	}
	// Cross-check against the symbol table: nothing absolute, TLS or local may
	// have made it into Exports.
	for _, s := range img.Syms {
		if s.Name == "" || s.Undef {
			continue
		}
		if _, ok := img.Exports[s.Name]; !ok {
			continue
		}
		if s.Absolute {
			t.Errorf("exported %q despite SHN_ABS", s.Name)
		}
		if s.Type == elf.STT_TLS {
			t.Errorf("exported %q despite STT_TLS (value is a TLS offset)", s.Name)
		}
		if s.Bind == elf.STB_LOCAL {
			t.Errorf("exported %q despite STB_LOCAL", s.Name)
		}
	}
}

// TestWeakUndefResolvesToZero: a weak undefined symbol that no resolver
// supplies must bind to 0, not fail the link. `if (&sym) sym();` is the whole
// reason weak references exist, and libraries here really do carry them
// (__cxa_thread_atexit_impl, __gmon_start__).
func TestWeakUndefResolvesToZero(t *testing.T) {
	img := &Image{Syms: []Sym{
		{Name: ""},
		{Name: "weak_missing", Undef: true, Bind: elf.STB_WEAK},
		{Name: "strong_missing", Undef: true, Bind: elf.STB_GLOBAL},
		{Name: "abs_const", Value: 0x1234, Absolute: true, Bind: elf.STB_GLOBAL},
		{Name: "normal", Value: 0x40, Bind: elf.STB_GLOBAL},
	}}
	const base = 0x12340000
	noResolve := func(string, bool) (uint64, bool) { return 0, false }

	if v, err := img.symValue(1, base, noResolve); err != nil || v != 0 {
		t.Errorf("weak undef: got (%#x, %v), want (0, nil)", v, err)
	}
	if _, err := img.symValue(2, base, noResolve); err == nil {
		t.Error("strong undef: expected an error, got nil")
	}
	if v, err := img.symValue(3, base, noResolve); err != nil || v != 0x1234 {
		t.Errorf("SHN_ABS: got (%#x, %v), want (0x1234, nil) — the load bias must not be added", v, err)
	}
	if v, err := img.symValue(4, base, noResolve); err != nil || v != base+0x40 {
		t.Errorf("normal: got (%#x, %v), want (%#x, nil)", v, err, base+0x40)
	}
}
