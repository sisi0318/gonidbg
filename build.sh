#!/usr/bin/env bash
# build.sh — build gonidbg (cgo + libunicorn via zig cc).
#
#   Windows (git-bash) : libunicorn vendored at C:/ucvendor (auto via pip if missing).
#   Linux              : libunicorn headers from the pip wheel; libunicorn.so at runtime.
#
# Usage:
#   ./build.sh                       # unicorn engine -> ./bin
#   WITH_DYNARMIC=1 ./build.sh       # also link static dynarmic (run build-dynarmic.sh first)
#   OUT=dist ./build.sh              # custom output dir
set -euo pipefail
cd "$(dirname "$0")"
OUT="${OUT:-bin}"
mkdir -p "$OUT"

command -v go  >/dev/null || { echo "need 'go' in PATH"; exit 1; }
command -v zig >/dev/null || { echo "need 'zig' in PATH (zig cc as C compiler)"; exit 1; }

EXE=""
case "$(uname -s)" in
  *NT*|*MINGW*|*MSYS*)  # Windows / git-bash
    EXE=".exe"
    UC="C:/ucvendor"
    if [ ! -f "$UC/unicorn.dll" ]; then
      echo "[setup] vendoring libunicorn via pip..."
      python -m pip install --quiet unicorn
      pkg=$(python -c "import unicorn,os;print(os.path.dirname(unicorn.__file__))")
      mkdir -p "$UC/include"; cp -r "$pkg/include/unicorn" "$UC/include/"; cp "$pkg/lib/unicorn.dll" "$UC/"
    fi
    export CC="zig cc" CXX="zig c++"
    export CGO_CFLAGS="-I$UC/include -fno-sanitize=undefined -fno-stack-protector"
    UCLIB="$UC/unicorn.dll"
    ;;
  *)  # Linux / macOS
    pkg=$(python3 -c "import unicorn,os;print(os.path.dirname(unicorn.__file__))" 2>/dev/null || true)
    if [ -n "$pkg" ]; then
      export CGO_CFLAGS="-I$pkg/include -fno-sanitize=undefined"
      UCLIB=$(ls "$pkg"/lib/libunicorn.so* 2>/dev/null | head -1 || true)
    else
      echo "[warn] python unicorn wheel not found; relying on system libunicorn headers"
    fi
    ;;
esac
export CGO_CFLAGS_ALLOW='.*'

# Optional second engine: WITH_DYNARMIC=1 also links the statically-built
# dynarmic JIT (run ./build-dynarmic.sh first to vendor its .a libs).
TAGS="unicorn"
if [ "${WITH_DYNARMIC:-0}" = "1" ]; then
  TAGS="unicorn dynarmic"
  DYN_SRC="${DYN_SRC:-/c/dynsrc}"
  DYN_VENDOR="${DYN_VENDOR:-/c/dynvendor}"
  export CGO_CXXFLAGS="-I$DYN_SRC/src -std=c++20 ${CGO_CXXFLAGS:-}"
  export CGO_LDFLAGS="-L$DYN_VENDOR/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++ ${CGO_LDFLAGS:-}"
  echo "[build] dynarmic engine enabled (vendor: $DYN_VENDOR/lib)"
fi

echo "[build] gonidbg$EXE  (CLI, engine, -tags \"$TAGS\")"
CGO_ENABLED=1 go build -tags "$TAGS" -o "$OUT/gonidbg$EXE" ./cmd/gonidbg

echo "[build] elfscan$EXE / loadplan$EXE  (pure-Go analysis tools)"
CGO_ENABLED=0 go build -o "$OUT/elfscan$EXE"  ./cmd/elfscan
CGO_ENABLED=0 go build -o "$OUT/loadplan$EXE" ./cmd/loadplan

# ship the unicorn lib next to the exes so they run without extra env
[ -n "${UCLIB:-}" ] && [ -f "$UCLIB" ] && cp "$UCLIB" "$OUT/" && echo "[copy] $(basename "$UCLIB") -> $OUT/"

echo "[ok] built into $OUT:"; ls -la "$OUT"
echo "run:  ./$OUT/gonidbg$EXE examples/native/native.so add 2 3"
echo "note: on Linux, set LD_LIBRARY_PATH=$OUT (or install libunicorn) so the .so is found"
