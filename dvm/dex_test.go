package dvm

import (
	"os"
	"testing"
)

// TestLoadDex parses a real classes.dex and checks classes/methods/fields are
// registered with sane metadata. Provide one via $GONIDBG_TEST_DEX (extract
// classes.dex from any APK); the test skips if unset so it needs no bundled DEX.
func TestLoadDex(t *testing.T) {
	path := os.Getenv("GONIDBG_TEST_DEX")
	if path == "" {
		t.Skip("set GONIDBG_TEST_DEX=/path/to/classes.dex to exercise the DEX loader")
	}
	vm := NewVM()
	n, err := vm.LoadDexFile(path)
	if err != nil {
		t.Fatalf("LoadDexFile: %v", err)
	}
	if n == 0 {
		t.Fatal("no class definitions parsed")
	}

	withMethods, withFields := 0, 0
	var sample *Class
	for _, c := range vm.Classes() {
		if len(c.Methods()) > 0 {
			withMethods++
			if sample == nil {
				sample = c
			}
		}
		if len(c.Fields()) > 0 {
			withFields++
		}
	}
	if withMethods == 0 {
		t.Fatal("no class registered any methods")
	}
	// java/lang/Object is referenced by essentially every dex.
	if _, ok := vm.LookupClass("java/lang/Object"); !ok {
		t.Fatal("java/lang/Object not present in parsed metadata")
	}
	// a parsed method signature should look like a JNI descriptor "(...)...".
	sig := sample.Methods()[0].Sig
	if len(sig) == 0 || sig[0] != '(' {
		t.Fatalf("method sig %q does not look like a JNI descriptor", sig)
	}
	t.Logf("dex ok: %d class defs, %d classes registered (%d with methods, %d with fields); sample %s.%s%s",
		n, len(vm.Classes()), withMethods, withFields, sample.Name, sample.Methods()[0].Name, sig)
}
