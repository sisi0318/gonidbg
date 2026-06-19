package emu

import (
	"fmt"
	"os"
	"strings"
)

// This file is the engine-selection layer — the Go analogue of unidbg's
// backend factory registry (com.github.unidbg.arm.backend.BackendFactory),
// where you pick the CPU engine at VM creation. Each concrete backend lives in
// its own build-tag-gated file and registers itself from an init():
//
//	unicorn_cgo.go   (//go:build unicorn)   -> Register("unicorn", ...)
//	dynarmic_cgo.go  (//go:build dynarmic)  -> Register("dynarmic", ...)
//
// So which engines exist in a binary is decided at build time (`-tags`), and
// which one is used is decided at run time (arg / $GONIDBG_ENGINE / default).
// A pure-Go build registers nothing; New then returns ErrNoBackend, exactly as
// the old stub backend did.

// Factory builds a fresh backend instance.
type Factory func() (Backend, error)

var (
	registry = map[string]Factory{}
	regOrder []string // registration order, for deterministic listing/fallback
)

// Register makes a backend available under name (called from a backend's
// init()). Duplicate names overwrite but keep their first position in the order.
func Register(name string, f Factory) {
	if f == nil {
		return
	}
	name = strings.ToLower(name)
	if _, dup := registry[name]; !dup {
		regOrder = append(regOrder, name)
	}
	registry[name] = f
}

// Available lists the engines compiled into this binary, in registration order.
func Available() []string { return append([]string(nil), regOrder...) }

// defaultPreference is the order tried when no engine is requested explicitly.
// Unicorn is the proven default (produces verified signatures); dynarmic is
// opt-in here — faster, but newer in this port. If only one is compiled in,
// that one wins regardless of this order.
var defaultPreference = []string{"unicorn", "dynarmic"}

// New returns the default backend (NewNamed with an empty name).
func New() (Backend, error) { return NewNamed("") }

// Resolve reports which engine name NewNamed(name) would pick, without building
// it — handy for logging the active engine. Selection order:
//  1. the explicit name argument, if non-empty;
//  2. else $GONIDBG_ENGINE;
//  3. else the first of defaultPreference that is compiled in;
//  4. else the first registered engine.
func Resolve(name string) (string, error) {
	if name == "" {
		name = strings.TrimSpace(os.Getenv("GONIDBG_ENGINE"))
	}
	if name == "" {
		for _, p := range defaultPreference {
			if _, ok := registry[p]; ok {
				return p, nil
			}
		}
		if len(regOrder) > 0 {
			return regOrder[0], nil
		}
		return "", ErrNoBackend
	}
	name = strings.ToLower(name)
	if _, ok := registry[name]; !ok {
		if len(regOrder) == 0 {
			return "", fmt.Errorf("emu: engine %q requested but none compiled in; build with -tags unicorn and/or -tags dynarmic", name)
		}
		return "", fmt.Errorf("emu: engine %q not compiled in (available: %s); rebuild with -tags %s",
			name, strings.Join(regOrder, ", "), name)
	}
	return name, nil
}

// NewNamed builds the engine selected by Resolve(name).
func NewNamed(name string) (Backend, error) {
	chosen, err := Resolve(name)
	if err != nil {
		return nil, err
	}
	return registry[chosen]()
}
