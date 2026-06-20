// Package vfs is the guest-visible filesystem. Bionic libc (which we emulate)
// opens real paths during startup — /system/lib64/libc.so, /proc/self/maps,
// /dev/__properties__, /system/build.prop, etc. The VFS resolves those guest
// paths to either an extracted sdk23 asset (see go/assets) or synthetic
// content. This mirrors unidbg's AndroidResolver + the IOResolver chain.
package vfs

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// VFS maps guest absolute paths to host bytes.
type VFS struct {
	assetRoot string                            // host dir holding android/sdk23/...
	synth     map[string]func() ([]byte, error) // guest path -> generator
	pid       int
	procName  string // emulated process name (/proc/self/cmdline, status)
	// fallback is consulted after synth + asset mappings miss. (content, true,
	// err) supplies/denies a path; (nil, false, nil) falls through. Set by the
	// emulator from Config.FileResolver.
	fallback func(guest string) ([]byte, bool, error)
}

// SetFallback installs a last-resort resolver for guest paths the built-in
// synthetic + asset mappings don't cover (the host app's IOResolver).
func (v *VFS) SetFallback(fn func(guest string) ([]byte, bool, error)) { v.fallback = fn }

// New roots the VFS at the extracted asset directory (the parent of
// "android/sdk23"). sdk level 23, ARM64 => lib64. procName is the emulated
// process name reported via /proc/self/*; empty falls back to a default.
func New(assetRoot string, pid int, procName string) *VFS {
	if procName == "" {
		procName = "com.gonidbg.app"
	}
	v := &VFS{assetRoot: assetRoot, pid: pid, procName: procName, synth: map[string]func() ([]byte, error){}}
	v.registerSynthetic()
	return v
}

// guest path -> host asset path. Returns "" if no static mapping.
func (v *VFS) hostPath(guest string) string {
	guest = path.Clean(guest)
	sdk := filepath.Join(v.assetRoot, "android", "sdk23")
	switch {
	case strings.HasPrefix(guest, "/system/lib64/"):
		return filepath.Join(sdk, "lib64", path.Base(guest))
	case strings.HasPrefix(guest, "/apex/com.android.runtime/lib64/"):
		return filepath.Join(sdk, "lib64", path.Base(guest))
	case guest == "/dev/__properties__":
		return filepath.Join(sdk, "dev", "__properties__")
	case guest == "/proc/stat":
		return filepath.Join(sdk, "proc", "stat")
	case strings.HasPrefix(guest, "/system/usr/share/zoneinfo/"):
		return filepath.Join(sdk, "system", "usr", "share", "zoneinfo", path.Base(guest))
	}
	return ""
}

// Read returns the bytes backing a guest path, trying synthetic generators
// first, then static asset mappings.
func (v *VFS) Read(guest string) ([]byte, error) {
	guest = path.Clean(guest)
	// The host app's resolver wins (unidbg's IOResolver runs before the built-in
	// /proc generators) so it can override e.g. /proc/self/maps with a curated
	// blob. Only consulted when set (Config.FileResolver), so default behavior is
	// unchanged.
	if v.fallback != nil {
		if data, ok, err := v.fallback(guest); ok {
			return data, err
		}
	}
	if gen, ok := v.synth[guest]; ok {
		return gen()
	}
	if hp := v.hostPath(guest); hp != "" {
		return os.ReadFile(hp)
	}
	return nil, fmt.Errorf("vfs: no such file: %s", guest)
}

// Exists reports whether a guest path resolves (for faccessat/stat).
func (v *VFS) Exists(guest string) bool {
	guest = path.Clean(guest)
	if _, ok := v.synth[guest]; ok {
		return true
	}
	if hp := v.hostPath(guest); hp != "" {
		_, err := os.Stat(hp)
		return err == nil
	}
	if v.fallback != nil {
		if _, ok, err := v.fallback(guest); ok && err == nil {
			return true
		}
	}
	return false
}

// registerSynthetic installs the /proc/self and properties files bionic reads.
// These mirror what unidbg's ByteArrayFileIO / driver resolvers synthesize.
func (v *VFS) registerSynthetic() {
	v.synth["/proc/self/cmdline"] = func() ([]byte, error) {
		return append([]byte(v.procName), 0), nil
	}
	v.synth["/proc/self/status"] = func() ([]byte, error) {
		comm := v.procName // /proc/*/status Name is the (≤15 char) comm
		if len(comm) > 15 {
			comm = comm[len(comm)-15:]
		}
		return []byte(fmt.Sprintf("Name:\t%s\nPid:\t%d\nPPid:\t1\nTracerPid:\t0\nUid:\t10000\t10000\t10000\t10000\n", comm, v.pid)), nil
	}
	// /proc/self/maps is filled by the loader once modules are mapped; a stub
	// keeps early reads from failing.
	v.synth["/proc/self/maps"] = func() ([]byte, error) { return []byte{}, nil }
	v.synth["/proc/self/auxv"] = func() ([]byte, error) { return []byte{}, nil }
	v.synth["/proc/sys/kernel/random/boot_id"] = func() ([]byte, error) {
		return []byte("00000000-0000-0000-0000-000000000000\n"), nil
	}
}

// SetMaps lets the loader publish the real /proc/self/maps after mapping.
func (v *VFS) SetMaps(content string) {
	v.synth["/proc/self/maps"] = func() ([]byte, error) { return []byte(content), nil }
}
