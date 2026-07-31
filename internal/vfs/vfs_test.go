package vfs

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestHostPathStaysInAssetRoot guards a sandbox escape: guest paths come from
// the emulated .so, which is untrusted, and hostPath used path.Base (POSIX —
// splits on '/' only) before handing the result to filepath.Join (which on
// Windows treats '\' as a separator and cleans ".." away). So
// "/system/lib64/..\..\..\Windows\win.ini" resolved to a real host file
// outside the asset root. Forward-slash traversal was already blocked.
func TestHostPathStaysInAssetRoot(t *testing.T) {
	root := t.TempDir()
	v := New(root, 1, "test")
	sdk := filepath.Join(root, "android", "sdk23")

	escapes := []string{
		`/system/lib64/..\..\..\..\..\..\Windows\win.ini`,
		`/system/lib64/x\..\..\..\..\..\..\..\Users\me\.ssh\id_rsa`,
		`/system/lib64/..\..\secret`,
		`/apex/com.android.runtime/lib64/..\..\..\..\secret`,
		`/system/usr/share/zoneinfo/..\..\..\..\secret`,
		"/system/lib64/../../../../../../etc/passwd",
		"/system/lib64/subdir/../../../etc/passwd",
	}
	for _, guest := range escapes {
		got := v.hostPath(guest)
		if got == "" {
			continue // rejected outright, which is the intended outcome
		}
		if !strings.HasPrefix(got, sdk+string(filepath.Separator)) {
			t.Errorf("escape: %q -> %q, which is outside %q", guest, got, sdk)
		}
	}
}

func TestHostPathResolvesRealAssets(t *testing.T) {
	root := t.TempDir()
	v := New(root, 1, "test")
	sdk := filepath.Join(root, "android", "sdk23")

	cases := map[string]string{
		"/system/lib64/libc.so":                    filepath.Join(sdk, "lib64", "libc.so"),
		"/system/lib64/./libm.so":                  filepath.Join(sdk, "lib64", "libm.so"),
		"/apex/com.android.runtime/lib64/libdl.so": filepath.Join(sdk, "lib64", "libdl.so"),
		"/dev/__properties__":                      filepath.Join(sdk, "dev", "__properties__"),
		"/proc/stat":                               filepath.Join(sdk, "proc", "stat"),
		"/system/usr/share/zoneinfo/tzdata":        filepath.Join(sdk, "system", "usr", "share", "zoneinfo", "tzdata"),
		"/system/lib64/subdir/../libssl.so":        filepath.Join(sdk, "lib64", "libssl.so"),
		"/nope/not/mapped":                         "",
	}
	for guest, want := range cases {
		if got := v.hostPath(guest); got != want {
			t.Errorf("hostPath(%q) = %q, want %q", guest, got, want)
		}
	}
}
