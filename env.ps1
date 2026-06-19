# env.ps1 — set up the cgo environment for building/running gonidbg, so plain
# `go build` / `go run` / `go test` work with an engine. Run it once per shell:
#
#   .\env.ps1            # both engines (unicorn + dynarmic)
#   .\env.ps1 unicorn
#   .\env.ps1 dynarmic
#
# It sets process environment variables, so they persist for the rest of THIS
# PowerShell session. Afterwards just:
#
#   go run -tags "unicorn dynarmic" .\examples\douyin -so D:\path\libmetasec_ml.so
#   go test -tags dynarmic .\emulator
#
# Override vendor locations with $env:UC_VENDOR / $env:DYN_SRC / $env:DYN_VENDOR.

param(
    [ValidateSet("unicorn", "dynarmic", "both")]
    [string]$Engine = "both"
)

$uc        = if ($env:UC_VENDOR)  { $env:UC_VENDOR }  else { "C:/ucvendor" }
$dynSrc    = if ($env:DYN_SRC)    { $env:DYN_SRC }    else { "C:/dynsrc" }
$dynVendor = if ($env:DYN_VENDOR) { $env:DYN_VENDOR } else { "C:/dynvendor" }

# zig as the C/C++ compiler — avoids the stray 32-bit gcc that causes
# "cc1.exe: 64-bit mode not compiled in" / missing g++.
$env:CC               = "zig cc"
$env:CXX              = "zig c++"
$env:CGO_ENABLED      = "1"
$env:CGO_CFLAGS_ALLOW = ".*"
# reset engine-specific flags so a previous selection doesn't leak in
$env:CGO_CFLAGS = ""; $env:CGO_CXXFLAGS = ""; $env:CGO_LDFLAGS = ""

$wantUC  = $Engine -in @("unicorn", "both")
$wantDyn = $Engine -in @("dynarmic", "both")

if ($wantUC) {
    $env:CGO_CFLAGS      = "-I$uc/include -fno-sanitize=undefined -fno-stack-protector"
    $env:GONIDBG_UNICORN = "$uc/unicorn.dll"
}
if ($wantDyn) {
    $env:CGO_CXXFLAGS = "-I$dynSrc/src -std=c++20"
    $env:CGO_LDFLAGS  = "-L$dynVendor/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++"
}

# sanity checks — warn (don't fail) so you know what's missing
if (-not (Get-Command zig -ErrorAction SilentlyContinue)) {
    Write-Warning "zig not found on PATH (install zig; see BUILD.md)"
}
if ($wantUC -and -not (Test-Path "$uc/unicorn.dll")) {
    Write-Warning "unicorn not vendored at $uc — run .\build.ps1 once (it pip-installs unicorn)"
}
if ($wantDyn -and -not (Test-Path "$dynVendor/lib/libdynarmic.a")) {
    Write-Warning "dynarmic not built at $dynVendor — run .\build-dynarmic.sh (via git-bash) first"
}

$tags = if ($Engine -eq "both") { "unicorn dynarmic" } else { $Engine }
Write-Host "[env] gonidbg cgo env set for: $Engine   (persists in this session)"
Write-Host "      CC=$($env:CC)  CXX=$($env:CXX)"
Write-Host "      try:  go run -tags `"$tags`" .\examples\run"
