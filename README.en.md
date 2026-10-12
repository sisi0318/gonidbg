[简体中文](README.md) | **English**

# gonidbg

[![CI](https://github.com/sisi0318/gonidbg/actions/workflows/ci.yml/badge.svg)](https://github.com/sisi0318/gonidbg/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sisi0318/gonidbg.svg)](https://pkg.go.dev/github.com/sisi0318/gonidbg)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

gonidbg is a small Go reimplementation of [unidbg](https://github.com/zhkl0228/unidbg): it loads an Android AArch64 native library (`.so`) and calls its functions on your host machine, without a JVM, a device, or Android. It sets up just enough of an Android process around the `.so` (a dynamic linker, real bionic libc, a subset of Linux syscalls, and a JNI/JavaVM) so you can call the library's exports from Go and read and write its memory.

Like unidbg, the CPU engine is swappable, and one of them is built in: a pure-Go AArch64 interpreter with no external dependencies, so `CGO_ENABLED=0 go build` gives a single binary that still executes real AArch64 code. You can also plug in [Unicorn](https://www.unicorn-engine.org/) or a statically linked [dynarmic](https://github.com/lioncash/dynarmic) JIT. You decide which ones to compile in, and which one to use at runtime.

```go
e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so"})
defer e.Close()
sum, _ := e.CallSymbol("add", 2, 3) // -> 5, executed as real AArch64 code
```

> Current status: all three engines work end to end. They load and link bionic and the target `.so`, run `init_array` and `JNI_OnLoad`, call exports, and handle syscalls and JNI. It's only a subset of unidbg, so see [Compared to unidbg](#compared-to-unidbg) for what's missing.

---

## Why

unidbg is the de-facto tool for emulating Android native libraries, but it runs on a JVM and pulls in a fairly large stack. gonidbg tries to do the core of the same job in Go:

- No JVM. The build output is a single Go binary, so startup is fast and memory use is low.
- Works with no dependencies. `CGO_ENABLED=0 go build ./cmd/gonidbg` produces a binary that loads a `.so` and executes its native code, with no zig, no `unicorn.dll` and no C toolchain.
- Swappable engine. The built-in pure-Go interpreter (`interp`) is always there; Unicorn is stable and becomes the default once installed; dynarmic is a JIT and much faster on warm calls. Choose at build time or at runtime, much like unidbg's backends.
- Reuses real bionic. It loads and emulates `libc/libm/libdl` from an AOSP sysroot instead of reimplementing libc.
- Small codebase. The framework itself is a few thousand lines of reasonably readable Go; the CPU layer is a pure-Go AArch64 interpreter plus two thin shims for the external engines.

## Features

- AArch64 ELF loading + dynamic linking (`RELATIVE` / `JUMP_SLOT` / `GLOB_DAT` / `ABS64`), `DT_INIT` + `init_array`.
- Real bionic `libc/libm/libdl` reuse (bundled AOSP sdk23 sysroot); cross-module symbol resolution.
- Linux/AArch64 syscall subset (mmap/mprotect/openat/read/write/clock_gettime/getrandom/futex/…), served against a small virtual filesystem (`/system/lib64`, `/proc/self/*`, properties, tzdata).
- JNI/JavaVM: a guest `JNIEnv`/`JavaVM` whose calls trap back to a Go handler you implement (`FindClass`, `GetMethodID`, `Call*Method*`, `RegisterNatives`, strings, byte arrays, …).
- Call native functions by symbol or by module offset, pass up to 8 integer args, and read the return value.
- Replace a native function with a Go callback (`Replace`, entry hook), or **inline hook** (`HookAddr`, per-instruction) to rewrite registers / redirect PC; both invalidate the code cache automatically.
- Range and memory-access hooks: `HookRange`, `HookMemRead`, `HookMemWrite`.
- **Snapshot / restore**: take a `Snapshot` once after init, then `Restore` before each reused call to rewind CPU, writable memory and brk to a pristine state (for pooled sign services).
- **Console debugger**: breakpoints / single-step / registers / memory (I/O is injectable for scripting).
- Load **real class/method/field metadata from a classes.dex** (`Config.DexPath` / `LoadDex`): FindClass/GetMethodID/GetFieldID resolve against true signatures and superclasses (metadata only, no bytecode).
- Memory helpers: alloc, read/write bytes, C-strings, and LE integers.
- Per-instruction trace, plus a full instruction-stream trace (`TraceInsns`: per-instruction offset + opcode + register deltas + call/syscall annotations, Tenet-style, diffable against a real-device trace).
- Selectable engine: the pure-Go interpreter needs no build tag; add `-tags unicorn` and/or `-tags dynarmic`, then choose at runtime with `-engine` / `$GONIDBG_ENGINE`.

> `HookAddr` / `HookRange` / `HookMemRead` / `HookMemWrite`, the full instruction trace and the console debugger all need per-instruction hooks, which `interp` and Unicorn provide and dynarmic does not (it is a block JIT). `Replace` goes through an svc trampoline and works on all three.

## Quick start

### Prerequisites

- Go 1.24+ — that is the whole list for a pure-Go build.

For the Unicorn or dynarmic engines, additionally:

- [zig](https://ziglang.org/download/) on `PATH`, used as the C/C++ cross-compiler for cgo (no gcc or MSVC needed).
- Unicorn: the build script vendors it via `pip install unicorn` automatically.
- dynarmic: run `./build-dynarmic.sh` once to vendor and statically build it. See [BUILD.md](BUILD.md).

### Build & run the example

Pure Go, nothing to install:

```bash
go run ./cmd/gonidbg examples/native/native.so add 2 3   # add([2 3]) = 5
go run ./cmd/gonidbg examples/native/native.so fib 20    # fib([20]) = 6765
```

To include the Unicorn or dynarmic engines, use the build scripts (cgo
environment in [BUILD.md](BUILD.md)):

```bash
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\build.ps1            # -> bin\gonidbg.exe (unicorn)
.\bin\gonidbg.exe examples\native\native.so add 2 3

# Linux / macOS / git-bash
./build.sh
./bin/gonidbg examples/native/native.so fib 20
```

Full demo (loads the bundled `native.so`, calls exports, an imported `strlen`, a pointer-out function, and a Go `Replace` hook):

```bash
go run ./examples/run        # add -tags unicorn / -tags dynarmic to switch engine
# engine: interp
# add(2, 3)      = 5
# fib(20)        = 6765
# slen(...)      = 14
# sum_into -> *out = 42
# add(2, 3) after Replace = 23  (Go hook: a*10+b)
```

## Library usage

```go
import "github.com/sisi0318/gonidbg/emulator"

e, err := emulator.New(emulator.Config{
    SOPath:    "libfoo.so",        // loaded + init_array + JNI_OnLoad at boot
    AssetRoot: emulator.Locate("assets"),
    Engine:    "",                 // "interp" | "unicorn" | "dynarmic" | "" = auto
})
if err != nil { panic(err) }
defer e.Close()

// Call an export by name (up to 8 integer/pointer args, returns X0).
r, _ := e.CallSymbol("add", 2, 3)

// Call a non-exported entry by module offset (unidbg's callFunction(offset)).
r, _ = e.CallOffset(nil /*main module*/, 0x1234, argPtr)

// Exchange memory.
p := e.WriteCStringAlloc("hello")
n, _ := e.CallSymbol("strlen_wrapper", p)
out := e.Malloc(4); _, _ = e.CallSymbol("sum_into", out, 20, 22)
v, _ := e.ReadU32(out)

// Replace a native function with Go (hook).
e.ReplaceSymbol("add", func(h *emulator.Hook) uint64 { return h.Arg(0) + h.Arg(1) })
```

### Modeling the Java side (JNI)

Native libraries call back into Java via JNI. Implement `dvm.Jni` (or embed `dvm.AbstractJni` and override the few methods your library uses), then pass it in `Config.JNI`:

```go
type MyJni struct{ dvm.AbstractJni }

func (MyJni) CallStaticObjectMethodV(vm *dvm.VM, cls *dvm.Class, sig string, va *dvm.VaList) *dvm.Object {
    if sig == "com/example/App->token()Ljava/lang/String;" {
        return &dvm.Object{Class: vm.ResolveClass("java/lang/String"), Value: "secret"}
    }
    return nil
}

e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so", JNI: MyJni{}})
```

This is how unidbg's `AbstractJni` works: the guest's `RegisterNatives`/`GetMethodID`/`Call*Method` route to your switch on the `"class->method(sig)"` string.

## CPU engines

| engine | build tag | linkage | speed (warm) | license |
|---|---|---|---|---|
| **interp** (pure Go) | none, always available | **no dependency** (pure Go, no cgo) | ~9.6 ms/call | Apache-2.0 |
| **Unicorn2** | `-tags unicorn` | runtime `dlopen` of libunicorn | ~13 ms/call | GPLv2 |
| **dynarmic** | `-tags dynarmic` | **static** (C++ via zig) | ~2.1 ms/call | 0BSD |

- Build several into one binary (`-tags "unicorn dynarmic"`) and pick at runtime: `gonidbg -engine interp …` or `GONIDBG_ENGINE=interp`. With no tags you get `interp` alone, and it is the default; with Unicorn present, Unicorn wins.
- The speeds above are all three engines measured on one machine: a single sign call on a real production obfuscated `.so`, ~2.9M instructions, reusing the emulator. The interpreter also starts an order of magnitude faster (~9 ms vs ~120 ms) with no JIT warm-up and no shared library to load, and because its per-instruction hooks are ordinary Go calls rather than cgo round-trips, a full instruction trace is an order of magnitude faster than Unicorn's.
- Why the interpreter cannot catch dynarmic, and what catching it would cost, is measured in [internal/arm64/PERF.md](internal/arm64/PERF.md); the benchmarks are `go test -run X -bench . ./internal/arm64`.
- The pure-Go engine also drops two cgo headaches: no dedicated engine thread on Windows, and writing to a code page invalidates its decoded instructions automatically (self-modifying code needs no explicit cache flush).
- Licensing note: Unicorn is GPLv2, and statically linking it would make the combined binary GPLv2, so gonidbg keeps it behind a runtime `dlopen` boundary. dynarmic is 0BSD (permissive), so the static build has no copyleft entanglement. The pure-Go `interp` is this repository's own code (Apache-2.0), with none either. See [BUILD.md](BUILD.md) for building dynarmic.

### How correctness is established

The real risk in writing your own CPU is being quietly wrong, so `interp` is calibrated against Unicorn:

- Differential test: take a random instruction encoding, execute exactly one instruction on both engines from the same random starting state, then compare every general-purpose register, all 32 vector registers and the memory touched (`internal/emu/diff_test.go`; over 3M sampled instructions agree exactly so far).
- Real workload: the 8 signature headers from that production `.so` match Unicorn byte for byte, and a census confirms the decoder covers every one of the 51M instructions it executes (39,891 distinct encodings) — the differential test can only prove that the instructions it *accepts* are right, so a missing one has to be caught this way.

## How it works

`emulator.New` mirrors unidbg's `Emulator` setup:

1. Address space: reserve the guest stack, TLS (`TPIDR_EL0` plus a `pthread_internal_t`), and an SVC-trampoline region, then pick the CPU backend.
2. Load and link: first the real bionic `libc/libm/libdl`, then your `.so`, parsing the ELF, mapping segments, applying relocations, and resolving symbols across modules. Unresolved imports get an `svc` trampoline that traps to Go.
3. Initialize: run `DT_INIT` and `init_array`, plus `JNI_OnLoad` (if the library exports it) with a synthesized `JavaVM`.
4. Call: `CallSymbol`/`CallOffset` put the args in `X0..X7`, set `LR` to a sentinel, and run until return. An SVC trap is dispatched to the syscall layer (`internal/kernel`), the JNI layer, or a Go-implemented libc or replaced function.

Guest memory and registers are exchanged through the `Backend` interface, which all three engines implement. The pure-Go `interp` keeps the guest address space in a three-level page table (fronted by small direct-mapped TLBs) and decodes each executable page into an array of instructions the first time it runs, so its hot loop is a cache lookup plus an indirect call. The dynarmic backend serves guest memory through a direct page table, so the JIT'd code reads and writes host memory directly and only SVC traps cross back into Go.

### Layout

```
gonidbg/
├── emulator/     public API: New, LoadLibrary, CallSymbol/CallOffset, Replace, memory helpers
├── dvm/          public: fake Dalvik VM — VM, Object, Class, Jni, AbstractJni, VaList
├── internal/
│   ├── arm64/    pure-Go AArch64 interpreter (CPU + paged memory, no cgo)
│   ├── emu/      CPU backend interface + registry; interp (pure Go), unicorn (cgo), dynarmic (cgo/C++)
│   ├── loader/   ELF parsing + dynamic linker
│   ├── kernel/   AArch64 Linux syscall subset
│   ├── memory/   guest address-space allocator
│   └── vfs/      guest virtual filesystem (/system/lib64, /proc/self, properties, tzdata)
├── cmd/
│   ├── gonidbg/  CLI: load a .so and call a symbol
│   ├── elfscan/  analyze a .so (imports/exports/init)
│   ├── loadplan/ relocation histogram / link complexity
│   ├── bsmoke/   engine self-test
│   └── ucthread/ minimal engine self-test
├── examples/native/  a tiny AArch64 .so (source + prebuilt) used by the example + test
└── assets/android/sdk23/  bundled AOSP bionic sysroot (see NOTICE)
```

## Compared to unidbg

Implemented: AArch64 ELF load and dynamic linking, real bionic reuse, a built-in pure-Go AArch64 interpreter (no dependencies) plus selectable Unicorn/dynarmic backends, a Linux syscall subset (including uname/sysinfo/getdents64/readlinkat/statx/prlimit64/sched_getaffinity), JNI/JavaVM with a Go handler (strings, byte and object arrays, exceptions, more Call variants), call by symbol or offset, function `Replace` plus inline hooks (`HookAddr`), a console debugger (breakpoints/step/registers/memory), loading real class/method/field metadata from a classes.dex, memory helpers, and instruction trace.

Not yet (roadmap, and PRs are welcome):

- ARM32; only AArch64 for now.
- JNI and syscalls are still subsets: they cover common usage, not all ~232 JNI slots or the full syscall table.
- DEX is metadata-only. It parses classes/methods/fields (signatures, superclasses) so FindClass/GetMethodID/GetFieldID resolve, but it does not execute DEX bytecode (no JVM); model Java-side behavior with a `dvm.Jni` handler.
- Inline hooks and the console debugger need per-instruction hooks, which `interp` and Unicorn both provide and dynarmic does not (it is a block JIT).
- The pure-Go interpreter targets the same CPU Unicorn models: no FEAT_FP16 (half-precision arithmetic), no FEAT_LSE (CAS/SWP/LDADD), no pointer authentication and no SVE. Those raise a clear "unimplemented instruction" error rather than computing something wrong.
- Truly concurrent threads (there is now a single-core cooperative scheduler — `pthread_create` makes a fiber, the scheduler time-slices and saves/restores CPU context at futex/sleep — but not real concurrency), signals, and iOS / Mach-O.

## Building from source / engines

See [BUILD.md](BUILD.md) for the full toolchain (zig as the C/C++ compiler), the pure-Go and engine layers, the static dynarmic build (`build-dynarmic.sh`), and the Windows/Linux notes.

```bash
# Pure Go: builds and tests anywhere, and this is already a working emulator
# (the interp engine):
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go run ./cmd/gonidbg examples/native/native.so add 2 3   # -> 5

# External-engine integration tests (load the bundled native.so and run it):
go test -tags unicorn  ./emulator
go test -tags dynarmic ./emulator

# Pure-Go engine vs Unicorn, one instruction at a time (20k by default):
go test -tags unicorn -run TestDiffUnicorn ./internal/emu
GONIDBG_DIFF_N=1000000 GONIDBG_DIFF_SEED=7 go test -tags unicorn -timeout 2h -run TestDiffUnicorn ./internal/emu
```

## Credits & license

gonidbg builds on:

- [unidbg](https://github.com/zhkl0228/unidbg) (Apache-2.0): the project this reimplements.
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn) (GPLv2): an optional CPU backend, loaded at runtime, and the reference the pure-Go interpreter is validated against.
- [dynarmic](https://github.com/lioncash/dynarmic) (0BSD): the optional JIT CPU backend.
- AOSP bionic (Apache-2.0) and others: the bundled sysroot under `assets/`. See [NOTICE](NOTICE).

gonidbg's own code is licensed under Apache-2.0 (see [LICENSE](LICENSE)). The engine licenses differ, as noted above: the Unicorn backend is loaded dynamically to keep its GPLv2 at a library boundary, while the dynarmic backend is permissive.

## Disclaimer

gonidbg is a research and education tool for analyzing native libraries you are authorized to study. The repo contains no third-party application code or proprietary binaries, only a generic emulation framework and a tiny example library built from the source in this repo. Use it responsibly and in compliance with applicable law and the terms of any software you analyze.
