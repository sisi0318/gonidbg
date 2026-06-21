#!/usr/bin/env bash
# setup-build-linux.sh — install the Go + Zig toolchain (and a python venv with
# cmake/ninja/unicorn) needed to build gonidbg / examples/dy-server ON this Linux
# machine.
#
# WHY build on the target machine: "Illegal instruction (core dumped)" means the
# binary used a CPU instruction the run machine lacks. zig defaults to
# -mcpu=native, so building HERE targets THIS CPU exactly — it can't emit
# instructions this machine doesn't have. (Shipping a binary built elsewhere
# instead needs -mcpu=baseline AND a baseline-rebuilt libdynarmic.a; building on
# target sidesteps all of that.)
#
# Usage:
#   ./setup-build-linux.sh
#   GO_VERSION=1.26.0 ZIG_VERSION=0.16.0 ./setup-build-linux.sh
set -euo pipefail

GO_VERSION="${GO_VERSION:-1.26.0}"
ZIG_VERSION="${ZIG_VERSION:-0.16.0}"

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
case "$(uname -m)" in
  x86_64)  GOARCH=amd64; ZARCH=x86_64 ;;
  aarch64) GOARCH=arm64; ZARCH=aarch64 ;;
  *) echo "unsupported arch: $(uname -m)"; exit 1 ;;
esac

need() { command -v "$1" >/dev/null 2>&1; }
need wget || need curl || { echo "need wget or curl"; exit 1; }
dl() { if need wget; then wget -qO "$2" "$1"; else curl -fSL -o "$2" "$1"; fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ---- Go -> /usr/local/go ----
if need go && go version 2>/dev/null | grep -q "go${GO_VERSION}"; then
  echo "[go]  go${GO_VERSION} already present: $(go version)"
else
  echo "[go]  installing go${GO_VERSION} -> /usr/local/go"
  dl "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" "$TMP/go.tgz"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "$TMP/go.tgz"
fi

# ---- Zig -> /usr/local/zig ----
ZDIR="zig-${ZARCH}-linux-${ZIG_VERSION}"
if need zig && zig version 2>/dev/null | grep -q "^${ZIG_VERSION}"; then
  echo "[zig] zig ${ZIG_VERSION} already present: $(zig version)"
else
  echo "[zig] installing zig ${ZIG_VERSION} -> /usr/local/zig"
  dl "https://ziglang.org/download/${ZIG_VERSION}/${ZDIR}.tar.xz" "$TMP/zig.tar.xz"
  tar -C "$TMP" -xf "$TMP/zig.tar.xz"           # extracts $TMP/$ZDIR/
  $SUDO rm -rf /usr/local/zig
  $SUDO mv "$TMP/$ZDIR" /usr/local/zig          # (your draft cd'd in first -> mv failed)
fi

# ---- PATH (current shell + ~/.bashrc, idempotent) ----
add_path() {
  case ":$PATH:" in *":$1:"*) ;; *) export PATH="$1:$PATH" ;; esac
  grep -qsF "PATH=\"$1:" ~/.bashrc || echo "export PATH=\"$1:\$PATH\"" >> ~/.bashrc
}
add_path /usr/local/go/bin
add_path /usr/local/zig

# ---- python venv + cmake/ninja (dynarmic) + unicorn wheel (unicorn engine) ----
echo "[py]  python venv -> ~/.venv  (cmake, ninja, unicorn)"
python3 -m venv "$HOME/.venv"
# shellcheck disable=SC1091
source "$HOME/.venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet cmake ninja unicorn

echo ""
echo "[ok] toolchain ready:"
echo "     go : $(/usr/local/go/bin/go version)"
echo "     zig: $(/usr/local/zig/zig version)"
echo ""
echo "Next — open a new shell (or: source ~/.bashrc && source ~/.venv/bin/activate),"
echo "then build dy-server ON THIS MACHINE (cwd = the gonidbg repo):"
echo ""
echo "  # --- unicorn engine (recommended for a server: no C++/dynarmic build) ---"
echo "  pkg=\$(python3 -c 'import unicorn,os;print(os.path.dirname(unicorn.__file__))')"
echo "  export CC='zig cc' CXX='zig c++' CGO_ENABLED=1 CGO_CFLAGS_ALLOW='.*'"
echo "  export CGO_CFLAGS=\"-I\$pkg/include -fno-sanitize=undefined\""
echo "  go build -tags unicorn -o douyin ./examples/dy-server"
echo "  cp \"\$pkg\"/lib/libunicorn.so* .          # ship the lib next to the binary"
echo "  LD_LIBRARY_PATH=. ./douyin -so ./libmetasec_ml.so -port 13145 -pool 2"
echo ""
echo "  # --- dynarmic engine (faster JIT; heavier build) ---"
echo "  ./build-dynarmic.sh                       # builds libdynarmic.a for THIS cpu"
echo "  export CC='zig cc' CXX='zig c++' CGO_ENABLED=1 CGO_CFLAGS_ALLOW='.*'"
echo "  export CGO_CXXFLAGS=\"-I\${DYN_SRC:-/c/dynsrc}/src -std=c++20\""
echo "  export CGO_LDFLAGS=\"-L\${DYN_VENDOR:-/c/dynvendor}/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++\""
echo "  go build -tags dynarmic -o douyin ./examples/dy-server"
echo ""
echo "Note: building here uses -mcpu=native (this CPU) — no portability flags needed."
echo "      On Linux you may also just use system gcc (apt install build-essential),"
echo "      which defaults to a portable baseline; then drop CC/CXX=zig."
