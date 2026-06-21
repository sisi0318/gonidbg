#!/usr/bin/env bash
# build.sh — build gonidbg (cgo + libunicorn via zig cc).
#
#   Windows (git-bash) : libunicorn vendored at C:/ucvendor (auto via pip if missing).
#   Linux              : libunicorn headers from the pip wheel; libunicorn.so at runtime.
#
# Usage:
#   ./build.sh                                  # unicorn engine -> ./bin
#   WITH_DYNARMIC=1 ./build.sh                  # also link static dynarmic (run build-dynarmic.sh first)
#   WITH_DYNARMIC=1 WITH_SERVER=1 ./build.sh    # also build the dy-server -> ./bin/douyin
#   OUT=dist ./build.sh                         # custom output dir
#
# For the Douyin sign server with the dynarmic engine, on the machine you'll run on:
#   ./build-dynarmic.sh                         # builds libdynarmic.a (for THIS cpu)
#   WITH_DYNARMIC=1 WITH_SERVER=1 ./build.sh    # -> ./bin/douyin (+ gonidbg CLI)
set -euo pipefail
cd "$(dirname "$0")"
OUT="${OUT:-bin}"
mkdir -p "$OUT"

command -v go  >/dev/null || { echo "need 'go' in PATH"; exit 1; }
command -v zig >/dev/null || { echo "need 'zig' in PATH (zig cc as C compiler)"; exit 1; }

# Portable CPU baseline. zig defaults to -mcpu=native, baking the BUILD machine's
# AVX2/BMI2/... into the cgo (and statically-linked dynarmic) code — the binary
# then SIGILLs ("Illegal instruction (core dumped)") on a machine with an older or
# more limited CPU. Pin a generic x86-64 baseline so the binary is portable.
# Override with MCPU=x86_64_v2 (faster, still runs on ~any x86-64 since ~2009).
MCPU="${MCPU:-baseline}"
MFLAG="-mcpu=$MCPU"

# dynarmic vendor dirs: Windows git-bash uses C:/ (ASCII path for cgo); Linux/macOS
# use $HOME. Must match what ./build-dynarmic.sh wrote (DYN_VENDOR).
if command -v cygpath >/dev/null 2>&1; then
  DYN_SRC="${DYN_SRC:-/c/dynsrc}"; DYN_VENDOR="${DYN_VENDOR:-/c/dynvendor}"
else
  DYN_SRC="${DYN_SRC:-$HOME/dynsrc}"; DYN_VENDOR="${DYN_VENDOR:-$HOME/dynvendor}"
fi

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
    export CGO_CFLAGS="-I$UC/include -fno-sanitize=undefined -fno-stack-protector $MFLAG"
    UCLIB="$UC/unicorn.dll"
    ;;
  *)  # Linux / macOS
    export CC="${CC:-zig cc}" CXX="${CXX:-zig c++}"
    pkg=$(python3 -c "import unicorn,os;print(os.path.dirname(unicorn.__file__))" 2>/dev/null || true)
    if [ -n "$pkg" ]; then
      export CGO_CFLAGS="-I$pkg/include -fno-sanitize=undefined $MFLAG"
      UCLIB=$(ls "$pkg"/lib/libunicorn.so* 2>/dev/null | head -1 || true)
    else
      echo "[warn] python unicorn wheel not found; relying on system libunicorn headers"
      export CGO_CFLAGS="$MFLAG"
    fi
    ;;
esac
export CGO_CFLAGS_ALLOW='.*'

# Optional second engine: WITH_DYNARMIC=1 also links the statically-built
# dynarmic JIT (run ./build-dynarmic.sh first to vendor its .a libs).
TAGS="unicorn"
if [ "${WITH_DYNARMIC:-0}" = "1" ]; then
  TAGS="unicorn dynarmic"
  if [ ! -f "$DYN_VENDOR/lib/libdynarmic.a" ]; then
    echo "[error] $DYN_VENDOR/lib/libdynarmic.a not found — run ./build-dynarmic.sh first"
    echo "        (set DYN_VENDOR to where it was vendored)."
    exit 1
  fi
  export CGO_CXXFLAGS="-I$DYN_SRC/src -std=c++20 $MFLAG ${CGO_CXXFLAGS:-}"
  export CGO_LDFLAGS="-L$DYN_VENDOR/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++ ${CGO_LDFLAGS:-}"
  echo "[build] dynarmic engine enabled (vendor: $DYN_VENDOR/lib)"
  echo "[build] NOTE: the linked libdynarmic.a must have been built at a compatible CPU"
  echo "        level — ./build-dynarmic.sh pins MCPU=$MCPU (rebuild it if you change MCPU)."
fi

echo "[build] gonidbg$EXE  (CLI, engine, -tags \"$TAGS\")"
CGO_ENABLED=1 go build -tags "$TAGS" -o "$OUT/gonidbg$EXE" ./cmd/gonidbg

# Optional: the Douyin X-* HTTP sign server (examples/dy-server -> "douyin").
if [ "${WITH_SERVER:-0}" = "1" ]; then
  echo "[build] douyin$EXE  (dy-server HTTP sign service, -tags \"$TAGS\")"
  CGO_ENABLED=1 go build -tags "$TAGS" -o "$OUT/douyin$EXE" ./examples/dy-server
fi

echo "[build] elfscan$EXE / loadplan$EXE  (pure-Go analysis tools)"
CGO_ENABLED=0 go build -o "$OUT/elfscan$EXE"  ./cmd/elfscan
CGO_ENABLED=0 go build -o "$OUT/loadplan$EXE" ./cmd/loadplan

# ship the unicorn lib next to the exes so they run without extra env
[ -n "${UCLIB:-}" ] && [ -f "$UCLIB" ] && cp "$UCLIB" "$OUT/" && echo "[copy] $(basename "$UCLIB") -> $OUT/"

echo "[ok] built into $OUT:"; ls -la "$OUT"
echo "run:  ./$OUT/gonidbg$EXE examples/native/native.so add 2 3"
echo "note: on Linux, set LD_LIBRARY_PATH=$OUT (or install libunicorn) so the .so is found"
