//go:build unicorn || dynarmic

// gonidbg: load an AArch64 Android .so and call one of its exported functions
// with integer arguments — a small driver over the emulator API.
//
//	gonidbg [-engine unicorn|dynarmic] [-assets DIR] [-v] <lib.so> <symbol> [intarg...]
//
// Example:
//	gonidbg examples/native/native.so add 2 3      ->  add(...) = 5
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sisi0318/gonidbg/emulator"
)

func main() {
	engine := flag.String("engine", "", "CPU engine: unicorn | dynarmic (default: auto / $GONIDBG_ENGINE)")
	assets := flag.String("assets", "", "android sdk23 asset root (auto-located if empty)")
	verbose := flag.Bool("v", false, "verbose syscall/JNI tracing")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gonidbg [flags] <lib.so> <symbol> [intarg...]")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		os.Exit(2)
	}
	soPath, symbol := args[0], args[1]

	var callArgs []uint64
	for _, a := range args[2:] {
		v, err := strconv.ParseUint(strings.TrimSpace(a), 0, 64) // accepts 0x.. hex too
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad integer arg %q: %v\n", a, err)
			os.Exit(2)
		}
		callArgs = append(callArgs, v)
	}

	assetRoot := *assets
	if assetRoot == "" {
		assetRoot = emulator.Locate("assets")
	}

	e, err := emulator.New(emulator.Config{
		SOPath:    soPath,
		AssetRoot: assetRoot,
		Engine:    *engine,
		Verbose:   *verbose,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "boot:", err)
		os.Exit(1)
	}
	defer e.Close()
	fmt.Printf("engine=%s  loaded=%s\n", e.Engine(), soPath)

	ret, err := e.CallSymbol(symbol, callArgs...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "call:", err)
		os.Exit(1)
	}
	fmt.Printf("%s(%v) = %d  (0x%x)\n", symbol, callArgs, int64(ret), ret)
}
