package emulator

import (
	"os"
	"path/filepath"
)

// Locate finds a data directory named `name` (e.g. "assets") by checking, in
// order: the cwd, the parent of cwd, and the executable's dir / its parents.
// This lets binaries find their data wherever it's reasonably placed (next to
// the exe or up a level) without a hardcoded path. Returns `name` unchanged if
// nothing matches (caller can still error clearly).
func Locate(name string) string {
	cands := []string{name, filepath.Join("..", name)}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(d, name),
			filepath.Join(d, "..", name),
			filepath.Join(d, "..", "..", name),
		)
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return name
}

// LocateFile is like Locate but for a file searched inside a located
// directory `dir` (e.g. LocateFile("libs", "libfoo.so")).
func LocateFile(dir, file string) string {
	return filepath.Join(Locate(dir), file)
}
