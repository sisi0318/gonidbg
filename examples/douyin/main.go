//go:build unicorn || dynarmic

// Real-world example: drive a production, obfuscated Android native library
// (com.bytedance...metasec "MS") through gonidbg's general API to reproduce the
// X-* request signature headers — the original motivating use case, rebuilt on
// top of the open-source framework.
//
// The .so is NOT shipped with gonidbg (it is third-party/proprietary). Provide
// your own copy and pass its path:
//
//	go run -tags unicorn ./examples/douyin -so /path/to/libmetasec_ml.so
//
// This contains no signing algorithm (that lives inside the .so) and no
// third-party code — only the loader driver and the JNI handler (jni.go) that
// models the Java calls the library makes.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sisi0318/gonidbg/emulator"
)

// sign entry inside libmetasec_ml.so (Douyin 37.4.0); a non-exported function
// located by reverse engineering, called by module base + offset.
const signOffset = 0x2A45F0

func main() {
	so := flag.String("so", "dy/libmetasec_ml.so", "path to libmetasec_ml.so (NOT included with gonidbg — bring your own)")
	engine := flag.String("engine", "", "CPU engine: unicorn | dynarmic (default: auto)")
	verbose := flag.Bool("v", false, "verbose syscall/JNI tracing")
	flag.Parse()

	if _, err := os.Stat(*so); err != nil {
		fmt.Fprintf(os.Stderr, "target .so not found at %q: %v\n", *so, err)
		fmt.Fprintln(os.Stderr, "this example needs a libmetasec_ml.so you provide via -so; it is not part of gonidbg.")
		os.Exit(2)
	}

	e, err := emulator.New(emulator.Config{
		SOPath:      *so,
		AssetRoot:   emulator.Locate("assets"),
		ProcessName: "com.ss.android.ugc.aweme",
		JNI:         douyinJni{},
		Engine:      *engine,
		Verbose:     *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "boot:", err)
		os.Exit(1)
	}
	defer e.Close()
	fmt.Printf("engine=%s  booted (bionic + .so linked, init_array + JNI_OnLoad done)\n\n", e.Engine())

	// A request to sign: full query string + a content-type "cookie" field. The
	// library returns 0 for minimal/incomplete inputs (its own behavior).
	url := "https://api5-core-lf.amemv.com/aweme/v2/feed/?app_name=aweme&aid=1128"
	cookie := "content-type\r\napplication/json; charset=UTF-8\r\n"

	raw, err := sign(e, url, cookie)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
	fmt.Println("=== signature headers ===")
	for k, v := range parseHeaders(raw) {
		fmt.Printf("%-12s %s\n", k, v)
	}
}

// sign writes (url, cookie) into guest memory, calls the sign function at
// module base + signOffset, and reads back the returned C-string (the X-* blob).
// This is exactly unidbg's module.callFunction(offset, ...) pattern, expressed
// with gonidbg's general API — no signing-specific framework code.
func sign(e *emulator.Emulator, url, cookie string) (string, error) {
	m := e.MainModule()
	if m == nil {
		return "", fmt.Errorf("target .so not loaded")
	}
	urlPtr := e.WriteCStringAlloc(url)
	ckPtr := e.WriteCStringAlloc(cookie)
	ret, err := e.CallOffset(m, signOffset, urlPtr, ckPtr)
	if err != nil {
		return "", err
	}
	if exited, code := e.GuestExited(); exited {
		return "", fmt.Errorf("guest exit_group(%d) during sign", code)
	}
	addr := ret & 0xFFFFFFFF // result pointer (low 32 bits)
	if addr == 0 {
		return "", fmt.Errorf("sign returned NULL (check inputs / JNI handler)")
	}
	return e.ReadCStr(addr)
}

// parseHeaders splits the "key\nvalue\nkey\nvalue..." blob into a map.
func parseHeaders(raw string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for i := 0; i+1 < len(parts); i += 2 {
		if k := strings.TrimSpace(parts[i]); k != "" {
			out[k] = parts[i+1]
		}
	}
	return out
}
