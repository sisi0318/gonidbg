[简体中文](README.md) | **English**

# gonidbg

[![CI](https://github.com/sisi0318/gonidbg/actions/workflows/ci.yml/badge.svg)](https://github.com/sisi0318/gonidbg/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sisi0318/gonidbg.svg)](https://pkg.go.dev/github.com/sisi0318/gonidbg)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**A minimal [unidbg](https://github.com/zhkl0228/unidbg) in Go** — load an Android AArch64 native library (`.so`) and run its functions on your host, with **no JVM, no device, and no Android**. gonidbg fakes just enough of an Android process (a dynamic linker, real bionic libc, the Linux syscall surface, and a JNI/JavaVM) for a native library to believe it is running on a phone, then lets you call its functions from Go and exchange memory.

Like unidbg, the CPU engine is **pluggable**: a [Unicorn](https://www.unicorn-engine.org/) interpreter or a statically-linked [dynarmic](https://github.com/lioncash/dynarmic) JIT, chosen at build time and/or run time.

```go
e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so"})
defer e.Close()
sum, _ := e.CallSymbol("add", 2, 3) // -> 5, executed as real AArch64 code
```

> Status: works end-to-end on both engines (loads + links bionic and your `.so`, runs `init_array`/`JNI_OnLoad`, calls exports, services syscalls and JNI). It is a *minimal* unidbg — see [Compared to unidbg](#compared-to-unidbg) for what is and isn't there.

---

## Why

unidbg is the de-facto tool for emulating Android native libraries, but it needs a JVM and pulls in a large stack. gonidbg targets the same core idea in Go:

- **No JVM** — a single Go binary, fast cold start, low memory.
- **Pluggable engine** — Unicorn (stable, default) *or* dynarmic (JIT, ~5–9× faster on warm calls); pick per build or at runtime, exactly like unidbg's backends.
- **Reuses real bionic** — `libc/libm/libdl` from an AOSP sysroot are loaded and emulated, so you don't reimplement libc.
- **Small, hackable core** — the whole framework is a few thousand lines of readable Go plus two thin CPU-engine shims.

## Features

- AArch64 ELF loading + dynamic linking (`RELATIVE` / `JUMP_SLOT` / `GLOB_DAT` / `ABS64`), `DT_INIT` + `init_array`.
- Real bionic `libc/libm/libdl` reuse (bundled AOSP sdk23 sysroot); cross-module symbol resolution.
- Linux/AArch64 syscall subset (mmap/mprotect/openat/read/write/clock_gettime/getrandom/futex/…), served against a small virtual filesystem (`/system/lib64`, `/proc/self/*`, properties, tzdata).
- JNI/JavaVM: a guest `JNIEnv`/`JavaVM` whose calls trap back to a Go handler you implement (`FindClass`, `GetMethodID`, `Call*Method*`, `RegisterNatives`, strings, byte arrays, …).
- Call native functions **by symbol** or **by module offset**; pass up to 8 integer args, read the return.
- **Replace** a native function with a Go callback (unidbg-style hook), with automatic code-cache invalidation.
- Memory helpers: alloc, read/write bytes, C-strings, and LE integers.
- Per-instruction **trace** (Unicorn).
- Selectable engine: build with `-tags unicorn`, `-tags dynarmic`, or both and choose at runtime with `-engine` / `$GONIDBG_ENGINE`.

## Quick start

### Prerequisites

- **Go** 1.24+
- **[zig](https://ziglang.org/download/)** on `PATH` (used as the C/C++ cross-compiler for cgo — no gcc/MSVC needed)
- One CPU engine:
  - **Unicorn** (default): the build script vendors it via `pip install unicorn` automatically.
  - **dynarmic** (optional, faster): run `./build-dynarmic.sh` once to vendor + statically build it. See [BUILD.md](BUILD.md).

### Build & run the example

```bash
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\build.ps1            # -> bin\gonidbg.exe (unicorn)
.\bin\gonidbg.exe examples\native\native.so add 2 3            # add([2 3]) = 5

# Linux / macOS / git-bash
./build.sh
./bin/gonidbg examples/native/native.so fib 20                  # fib([20]) = 6765
```

Full demo (loads the bundled `native.so`, calls exports, an imported `strlen`, a pointer-out function, and a Go `Replace` hook):

```bash
go run -tags unicorn ./examples/run    # (set the cgo env from BUILD.md; or use the built binary)
# engine: unicorn
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
    Engine:    "",                 // "unicorn" | "dynarmic" | "" = auto
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

This is exactly unidbg's `AbstractJni` pattern: the guest's `RegisterNatives`/`GetMethodID`/`Call*Method` route to your switch on the `"class->method(sig)"` string.

## CPU engines

| engine | build tag | linkage | speed (warm) | license |
|---|---|---|---|---|
| **Unicorn2** | `-tags unicorn` | runtime `dlopen` of libunicorn | ~20 ms/call | GPLv2 |
| **dynarmic** | `-tags dynarmic` | **static** (C++ via zig) | ~2–4 ms/call | 0BSD |

- Build both into one binary (`-tags "unicorn dynarmic"`) and pick at runtime: `gonidbg -engine dynarmic …` or `GONIDBG_ENGINE=dynarmic`.
- First call on a fresh emulator is ~hundreds of ms (dynarmic compiles JIT / Unicorn warms up); reuse the emulator and subsequent calls are fast.
- **Licensing note:** Unicorn is **GPLv2** — statically linking it makes the combined binary GPLv2; gonidbg keeps it behind a runtime `dlopen` boundary. dynarmic is **0BSD** (permissive), so the static-dynarmic build has no copyleft entanglement. See [BUILD.md](BUILD.md) for building dynarmic.

## How it works

`emulator.New` mirrors unidbg's `Emulator` setup:

1. **Address space** — reserve guest stack, TLS (`TPIDR_EL0` + a `pthread_internal_t`), and an SVC-trampoline region; pick the CPU backend.
2. **Load + link** real bionic `libc/libm/libdl`, then your `.so`: parse ELF, map segments, apply relocations, resolve symbols across modules. Unresolved imports get an `svc` trampoline that traps to Go.
3. **Initialize** — run `DT_INIT` + `init_array`, and `JNI_OnLoad` (if exported) with a synthesized `JavaVM`.
4. **Call** — `CallSymbol`/`CallOffset` set args in `X0..X7`, set `LR` to a sentinel, and run until return. SVC traps dispatch to either the **syscall** layer (`internal/kernel`) or the **JNI** layer, or a Go-implemented libc/replaced function.

Guest memory and registers are exchanged through the `Backend` interface, which both engine shims implement. The dynarmic backend serves guest memory through a direct **page table** so JIT'd code reads/writes host memory without callbacks (only SVC traps cross into Go).

### Layout

```
gonidbg/
├── emulator/     public API: New, LoadLibrary, CallSymbol/CallOffset, Replace, memory helpers
├── dvm/          public: fake Dalvik VM — VM, Object, Class, Jni, AbstractJni, VaList
├── internal/
│   ├── emu/      CPU backend interface + registry; unicorn (cgo) and dynarmic (cgo/C++) shims
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

**Implemented:** AArch64 ELF load + dynamic linking · real bionic reuse · selectable Unicorn/dynarmic backend · Linux syscall subset · JNI/JavaVM with a Go handler · call by symbol/offset · function `Replace` (Go hook) · memory helpers · instruction trace.

**Not yet (roadmap / PRs welcome):**

- ARM32 (AArch64 only today).
- Full JNI surface (a working subset of `JNINativeInterface` is implemented, not all ~232 slots).
- Full syscall table (a few dozen, not unidbg's complete set).
- APK/DEX-backed VM (gonidbg's `dvm` is synthetic — you model Java in Go; it does not parse classes out of an APK).
- Mid-function/inline hooks (only function-entry `Replace`), interactive console debugger, signals, real threads (`pthread_create` is a no-op).
- iOS / Mach-O.

## Building from source / engines

See **[BUILD.md](BUILD.md)** for the full toolchain (zig as the C/C++ compiler), the pure-Go vs engine layers, the static dynarmic build (`build-dynarmic.sh`), and Windows/Linux notes.

```bash
# pure-Go layer builds and tests anywhere (no engine, no cgo):
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...

# engine integration test (loads the bundled native.so and runs it):
go test -tags unicorn  ./emulator
go test -tags dynarmic ./emulator
```

## Credits & license

gonidbg stands on the shoulders of:

- **[unidbg](https://github.com/zhkl0228/unidbg)** (Apache-2.0) — the design this reimplements.
- **[Unicorn Engine](https://github.com/unicorn-engine/unicorn)** (GPLv2) — the default CPU backend (runtime-loaded).
- **[dynarmic](https://github.com/lioncash/dynarmic)** (0BSD) — the optional JIT CPU backend.
- **AOSP bionic** (Apache-2.0) and friends — the bundled sysroot under `assets/`. See [NOTICE](NOTICE).

gonidbg's own code is licensed under **Apache-2.0** (see [LICENSE](LICENSE)). Note the per-engine licensing above: the Unicorn backend is dynamically loaded to keep its GPLv2 at a library boundary; the dynarmic backend is permissive.

## Disclaimer

gonidbg is a research/education tool for analyzing native libraries you are authorized to study. It contains **no third-party application code or proprietary binaries** — only a generic emulation framework and a tiny example library built from the source in this repo. Use it responsibly and in compliance with applicable law and the terms of any software you analyze.
