#!/usr/bin/env bash
# build-dynarmic.sh — vendor + statically build dynarmic for the "dynarmic" CPU
# engine, then print the CGO_* env to build the Go server against it.
#
# dynarmic has no C API and is a CMake/C++20 project, so this:
#   1. ensures cmake + ninja (via pip, like the unicorn setup),
#   2. clones dynarmic (shallow, with its bundled externals),
#   3. fetches Boost headers (dynarmic needs Boost.ICL/variant — header-only),
#   4. patches fmt for a clang-20 consteval incompatibility (fmt 10.1.0),
#   5. builds the static libs with zig as the C/C++/ASM compiler + archiver,
#   6. collects the libs + interface headers into an ASCII vendor dir.
#
# Output vendor dir (ASCII path — this repo's path has non-ASCII chars, which
# cgo's flag check rejects, so we vendor to C:/dynvendor like C:/ucvendor):
#   $DYN_VENDOR/include   dynarmic interface headers (for CGO_CXXFLAGS -I)
#   $DYN_VENDOR/lib       libdynarmic.a + deps        (for CGO_LDFLAGS -L)
#
# Usage:  ./build-dynarmic.sh            # full vendor + build
# Env:    DYN_SRC (clone dir), DYN_VENDOR (output), BOOST_VER, JOBS
set -euo pipefail

# Vendor dirs: Windows git-bash uses C:/ (ASCII path — cgo rejects this repo's
# non-ASCII path); Linux/macOS use $HOME. Override with DYN_SRC / DYN_VENDOR.
if command -v cygpath >/dev/null 2>&1; then
  DYN_SRC="${DYN_SRC:-/c/dynsrc}"; DYN_VENDOR="${DYN_VENDOR:-/c/dynvendor}"
else
  DYN_SRC="${DYN_SRC:-$HOME/dynsrc}"; DYN_VENDOR="${DYN_VENDOR:-$HOME/dynvendor}"
fi
BOOST_VER="${BOOST_VER:-1.84.0}"
BOOST_US="${BOOST_VER//./_}"           # 1.84.0 -> 1_84_0
JOBS="${JOBS:-4}"                      # keep modest: parallel `zig cc` can race on Windows
DYN_REPO="${DYN_REPO:-https://github.com/lioncash/dynarmic.git}"

# Cross-compile knobs (all unset => native host build, byte-for-byte as before).
# Set ZIG_TARGET to a zig triple (e.g. x86_64-linux-gnu) to build the static libs
# for another OS/arch: the cc/c++ wrappers get "-target <triple>", and CMake is put
# in cross mode (CMAKE_SYSTEM_NAME/PROCESSOR) so it picks the matching dynarmic
# backend and skips host try-run checks. Pick a separate DYN_VENDOR per target.
ZIG_TARGET="${ZIG_TARGET:-}"
CROSS_SYSTEM_NAME="${CROSS_SYSTEM_NAME:-Linux}"
CROSS_SYSTEM_PROCESSOR="${CROSS_SYSTEM_PROCESSOR:-x86_64}"
TFLAG=""; [ -n "$ZIG_TARGET" ] && TFLAG="-target $ZIG_TARGET"
# Portable CPU baseline (native builds only; a cross -target already defaults to a
# generic baseline). zig defaults to -mcpu=native, which bakes the BUILD host's
# AVX2/BMI2/... into libdynarmic.a — the Go binary then dies with "Illegal
# instruction (core dumped)" when run on a machine with an older/limited CPU.
# Pin a generic baseline so the lib is portable. Override: MCPU=x86_64_v2 (faster).
MCPU="${MCPU:-baseline}"
CFLAG=""; [ -z "$ZIG_TARGET" ] && CFLAG="-mcpu=$MCPU"
# separate build dir per target so a cross configure never clashes with the host
# CMakeCache (CMAKE_SYSTEM_NAME can't change in place); unset => "$DYN_SRC/build".
BUILD_DIR="$DYN_SRC/build${ZIG_TARGET:+-$ZIG_TARGET}"

command -v zig >/dev/null || { echo "need 'zig' in PATH"; exit 1; }
command -v git >/dev/null || { echo "need 'git' in PATH"; exit 1; }
command -v python >/dev/null || command -v python3 >/dev/null || { echo "need python (for cmake/ninja)"; exit 1; }
PY=$(command -v python || command -v python3)

# 1) cmake + ninja via pip (idempotent)
"$PY" -m pip install --quiet cmake ninja
CMAKE=$("$PY" -c 'import cmake,os;print(os.path.join(os.path.dirname(cmake.__file__),"data","bin","cmake"))')
NINJA=$("$PY" -c 'import ninja,os;print(os.path.join(ninja.BIN_DIR,"ninja"))')
echo "[tools] cmake=$CMAKE"
echo "[tools] ninja=$NINJA"

# 2) clone dynarmic (shallow, recursive) if missing
if [ ! -f "$DYN_SRC/CMakeLists.txt" ]; then
  echo "[clone] $DYN_REPO -> $DYN_SRC"
  git clone --depth 1 --recurse-submodules --shallow-submodules "$DYN_REPO" "$DYN_SRC"
fi

# 3) Boost headers (unified distribution has a single boost/ tree)
BOOST_INC="$DYN_SRC/boostinc/boost_${BOOST_US}"
if [ ! -d "$BOOST_INC/boost" ]; then
  echo "[boost] fetching $BOOST_VER headers"
  curl -fSL --retry 2 -o "$DYN_SRC/boost.tar.gz" \
    "https://archives.boost.io/release/${BOOST_VER}/source/boost_${BOOST_US}.tar.gz"
  mkdir -p "$DYN_SRC/boostinc"
  tar xzf "$DYN_SRC/boost.tar.gz" -C "$DYN_SRC/boostinc" "boost_${BOOST_US}/boost"
fi

# 4) patch fmt 10.1.0 for modern clang / libc++ (zig ships clang 20 + libc++ 20):
#  (a) "call to consteval function ... is not a constant expression": force fmt's
#      non-consteval path (safe runtime format-string checks).
#  (b) <__std_stream> not found: libc++ 20 removed that internal header; fmt only
#      used it for a Windows-console-unicode optimization we don't need, so drop
#      the libc++ Windows branches (fall back to the generic path).
FMT_CORE="$DYN_SRC/externals/fmt/include/fmt/core.h"
FMT_OSTREAM="$DYN_SRC/externals/fmt/include/fmt/ostream.h"
if ! grep -q '0 && (FMT_GCC_VERSION >= 1000' "$FMT_CORE"; then
  echo "[patch] fmt core.h: disable consteval (clang compat)"
  sed -i 's/#  if ((FMT_GCC_VERSION >= 1000/#  if (0 \&\& (FMT_GCC_VERSION >= 1000/' "$FMT_CORE"
  sed -i 's/      (defined(__cpp_consteval) &&/      (0 \&\& defined(__cpp_consteval) \&\&/' "$FMT_CORE"
fi
if ! grep -q 'defined(_LIBCPP_VERSION) && 0' "$FMT_OSTREAM"; then
  echo "[patch] fmt ostream.h: drop libc++ <__std_stream> branches"
  sed -i 's/defined(_WIN32) && defined(_LIBCPP_VERSION)/defined(_WIN32) \&\& defined(_LIBCPP_VERSION) \&\& 0/g' "$FMT_OSTREAM"
fi
#  (c) mcl: clang>=18 won't match its template-template pattern against
#      std::integer_sequence; add a concrete specialization (all dynarmic uses).
MCL_LS="$DYN_SRC/externals/mcl/include/mcl/mp/typelist/lift_sequence.hpp"
if ! grep -q 'integer_sequence<T, values...>' "$MCL_LS"; then
  echo "[patch] mcl lift_sequence.hpp: concrete std::integer_sequence specialization"
  sed -i 's/#include <type_traits>/#include <type_traits>\n#include <utility>/' "$MCL_LS"
  awk '1; /^struct lift_sequence_impl<VLT<T, values...>> \{/{f=1} f&&/^};/&&!done{print "";print "template<class T, T... values>";print "struct lift_sequence_impl<std::integer_sequence<T, values...>> {";print "    using type = list<std::integral_constant<T, values>...>;";print "};";done=1}' "$MCL_LS" > "$MCL_LS.tmp" && mv "$MCL_LS.tmp" "$MCL_LS"
fi

# 5) zig compiler/archiver wrappers (cmake needs single-executable tools; zig
#    doesn't dispatch on argv[0], so wrap "zig cc/c++/ar/ranlib").
ZIGW_DIR="$DYN_SRC/zigwrap"; mkdir -p "$ZIGW_DIR"
ZIGEXE=$(cygpath -w "$(command -v zig)" 2>/dev/null || command -v zig)
# cc/c++/asm carry the cross "-target" (if any); ar/ranlib are format-agnostic.
mkcmd() { printf '@echo off\r\n"%s" %s %s %%*\r\n' "$ZIGEXE" "$1" "$2" > "$ZIGW_DIR/zig-$3.cmd"; }
if command -v cygpath >/dev/null; then            # Windows: .cmd wrappers
  mkcmd cc "$TFLAG $CFLAG" cc; mkcmd c++ "$TFLAG $CFLAG" cxx; mkcmd ar "" ar; mkcmd ranlib "" ranlib
  CC_W="$ZIGW_DIR/zig-cc.cmd"; CXX_W="$ZIGW_DIR/zig-cxx.cmd"
  AR_W="$ZIGW_DIR/zig-ar.cmd"; RANLIB_W="$ZIGW_DIR/zig-ranlib.cmd"
else                                              # POSIX: .sh wrappers
  printf '#!/usr/bin/env bash\nexec zig cc %s %s "$@"\n'  "$TFLAG" "$CFLAG" > "$ZIGW_DIR/zig-cc";     chmod +x "$ZIGW_DIR/zig-cc"
  printf '#!/usr/bin/env bash\nexec zig c++ %s %s "$@"\n' "$TFLAG" "$CFLAG" > "$ZIGW_DIR/zig-cxx";    chmod +x "$ZIGW_DIR/zig-cxx"
  printf '#!/usr/bin/env bash\nexec zig ar "$@"\n'              > "$ZIGW_DIR/zig-ar";     chmod +x "$ZIGW_DIR/zig-ar"
  printf '#!/usr/bin/env bash\nexec zig ranlib "$@"\n'         > "$ZIGW_DIR/zig-ranlib"; chmod +x "$ZIGW_DIR/zig-ranlib"
  CC_W="$ZIGW_DIR/zig-cc"; CXX_W="$ZIGW_DIR/zig-cxx"; AR_W="$ZIGW_DIR/zig-ar"; RANLIB_W="$ZIGW_DIR/zig-ranlib"
fi

# 6) configure + build the static dynarmic lib. A toolchain file is the reliable
#    way to pin zig's ar/ranlib: CMake's bin-utils detection can't derive an
#    archiver from "zig cc" and otherwise bakes CMAKE_AR-NOTFOUND into the rules.
cat > "$DYN_SRC/zig-toolchain.cmake" <<EOF
set(CMAKE_C_COMPILER   "$CC_W")
set(CMAKE_CXX_COMPILER "$CXX_W")
set(CMAKE_ASM_COMPILER "$CC_W")
set(CMAKE_AR     "$AR_W"     CACHE FILEPATH "Archiver" FORCE)
set(CMAKE_RANLIB "$RANLIB_W" CACHE FILEPATH "Ranlib"   FORCE)
EOF
if [ -n "$ZIG_TARGET" ]; then                     # cross: put CMake in cross mode
  cat >> "$DYN_SRC/zig-toolchain.cmake" <<EOF
set(CMAKE_SYSTEM_NAME $CROSS_SYSTEM_NAME)
set(CMAKE_SYSTEM_PROCESSOR $CROSS_SYSTEM_PROCESSOR)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
EOF
  echo "[cross] ZIG_TARGET=$ZIG_TARGET  system=$CROSS_SYSTEM_NAME/$CROSS_SYSTEM_PROCESSOR"
fi
export ZIG_GLOBAL_CACHE_DIR="$DYN_SRC/.zigcache"
echo "[cmake] configure -> $BUILD_DIR"
"$CMAKE" -G Ninja -S "$DYN_SRC" -B "$BUILD_DIR" \
  -DCMAKE_TOOLCHAIN_FILE="$DYN_SRC/zig-toolchain.cmake" \
  -DCMAKE_MAKE_PROGRAM="$NINJA" \
  -DCMAKE_BUILD_TYPE=Release -DDYNARMIC_TESTS=OFF -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_POLICY_DEFAULT_CMP0167=OLD -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DBoost_INCLUDE_DIR="$BOOST_INC"
echo "[ninja] build dynarmic (-j$JOBS)"
"$NINJA" -C "$BUILD_DIR" dynarmic -j "$JOBS"

# 7) collect libs + headers into the ASCII vendor dir
echo "[vendor] -> $DYN_VENDOR"
rm -rf "$DYN_VENDOR"; mkdir -p "$DYN_VENDOR/lib" "$DYN_VENDOR/include"
find "$BUILD_DIR" -name '*.a' -exec cp {} "$DYN_VENDOR/lib/" \;
cp -r "$DYN_SRC/src/dynarmic" "$DYN_VENDOR/include/"   # dynarmic/interface/* headers

echo ""
echo "[ok] dynarmic vendored. libs:"
ls -1 "$DYN_VENDOR/lib"
echo ""
echo "Now build the dynarmic-engine binaries (libs match this build's MCPU=$MCPU):"
echo "  DYN_SRC=$DYN_SRC DYN_VENDOR=$DYN_VENDOR MCPU=$MCPU WITH_DYNARMIC=1 WITH_SERVER=1 ./build.sh"
echo "  -> ./bin/douyin  (dy-server)  and  ./bin/gonidbg  (CLI)"
echo ""
echo "Or build the server directly:"
echo "  export CC=\"zig cc\" CXX=\"zig c++\" CGO_ENABLED=1 CGO_CFLAGS_ALLOW=.*"
echo "  export CGO_CXXFLAGS=\"-I$DYN_VENDOR/include -std=c++20 -mcpu=$MCPU\""
echo "  export CGO_LDFLAGS=\"-L$DYN_VENDOR/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++\""
echo "  go build -tags dynarmic -o douyin ./examples/dy-server"
