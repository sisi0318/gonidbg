# examples/douyin — real-world validation

This example drives a **production, heavily-obfuscated** Android native library
through gonidbg's *general* public API and reproduces the `X-*` request
signature headers it produces on-device. It exists to prove the open-source
framework handles a real, hostile target — not just the toy `examples/native`.

It is built entirely on the public API, with **no signing-specific framework
code**:

- `jni.go` — a `dvm.Jni` handler modeling the handful of Java calls the library
  makes during `JNI_OnLoad` + signing (the unidbg `AbstractJni` pattern).
- `main.go` — loads the `.so`, then `CallOffset(mainModule, 0x2A45F0, url, cookie)`
  and reads the returned C-string. That's `module.callFunction(offset, …)` in
  unidbg terms, expressed with `emulator.CallOffset` + the memory helpers.

## You must supply the `.so`

The target library is **third-party / proprietary and is NOT included** in this
repository (and is git-ignored). Provide your own copy:

```bash
go run -tags unicorn  ./examples/douyin -so /path/to/libmetasec_ml.so
go run -tags dynarmic ./examples/douyin -so /path/to/libmetasec_ml.so   # same result
```

Expected output (values vary per call by timestamp/nonce):

```
engine=unicorn  booted (bionic + .so linked, init_array + JNI_OnLoad done)

=== signature headers ===
X-Gorgon     840400470000b2b2ba5e643fdd8a8639aa9a1a192c13....
X-Khronos    17818826xx
X-Argus      ...
X-Ladon      ...
X-Medusa     ...
X-Perseus    ...
X-Helios     ...
X-Neptune    -11|50:51:59
```

The fixed prefix of `X-Gorgon` (and `X-Neptune`) is identical across runs and
across engines, matching the on-device / unidbg reference; the tail varies with
the timestamp. This containing **no algorithm of its own** — the signing logic
lives inside the `.so`; gonidbg only loads, links, and executes it, servicing
its syscalls and JNI calls.

## Notes / authorized use

- This is a research/education demonstration of the emulator. Use it only with
  software you are authorized to analyze, and in compliance with applicable law
  and the relevant terms of service.
- Nothing here is specific to one app beyond `jni.go`'s call signatures and the
  `0x2A41F0` entry offset; point it at a different `.so` and write a matching
  `dvm.Jni` handler to emulate something else.
