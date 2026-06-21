# run.ps1 — run a gonidbg command/example with all the cgo env for a chosen engine.
#
# Usage:
#   .\run.ps1 dynarmic ./examples/douyin -so D:\path\to\libmetasec_ml.so
#   .\run.ps1 unicorn  ./examples/douyin -so D:\path\to\libmetasec_ml.so
#   .\run.ps1 unicorn  ./cmd/gonidbg examples/native/native.so add 2 3
#   .\run.ps1 dynarmic ./examples/run
#
# Override vendor locations with $env:UC_VENDOR / $env:DYN_SRC / $env:DYN_VENDOR.

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("unicorn", "dynarmic")]
    [string]$Engine,
    [Parameter(ValueFromRemainingArguments = $true)]
    $Rest
)

Set-Location -LiteralPath $PSScriptRoot

# Common: use zig as the C/C++ compiler (no gcc/MSVC; avoids the stray 32-bit
# gcc that triggers "cc1.exe: 64-bit mode not compiled in" / "g++ not found").
$env:CC = "zig cc"
$env:CXX = "zig c++"
$env:CGO_ENABLED = "1"
$env:CGO_CFLAGS_ALLOW = ".*"
# Portable CPU baseline. zig defaults to -mcpu=native, which bakes the BUILD
# machine's AVX2/BMI2/... into the cgo + dynarmic code; the binary then dies with
# "Illegal instruction (core dumped)" when copied to a machine with an older or
# more limited CPU. Pin a generic x86-64 baseline so it runs anywhere. Override
# with $env:GONIDBG_MCPU=x86_64_v2 (a bit faster, still very portable).
$mcpu = if ($env:GONIDBG_MCPU) { "-mcpu=$($env:GONIDBG_MCPU)" } else { "-mcpu=baseline" }
# clear engine-specific vars so a previous run doesn't leak in
$env:CGO_CFLAGS = ""; $env:CGO_CXXFLAGS = ""; $env:CGO_LDFLAGS = ""

if ($Engine -eq "dynarmic") {
    $dynSrc    = if ($env:DYN_SRC)    { $env:DYN_SRC }    else { "C:/dynsrc" }
    $dynVendor = if ($env:DYN_VENDOR) { $env:DYN_VENDOR } else { "C:/dynvendor" }
    if (-not (Test-Path "$dynVendor/lib/libdynarmic.a")) {
        throw "dynarmic libs not found in $dynVendor/lib — run ./build-dynarmic.sh first (or set `$env:DYN_VENDOR)."
    }
    $env:CGO_CFLAGS   = "$mcpu"
    $env:CGO_CXXFLAGS = "-I$dynSrc/src -std=c++20 $mcpu"
    $env:CGO_LDFLAGS  = "-L$dynVendor/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++"
}
else {
    $uc = if ($env:UC_VENDOR) { $env:UC_VENDOR } else { "C:/ucvendor" }
    $env:CGO_CFLAGS = "-I$uc/include -fno-sanitize=undefined -fno-stack-protector $mcpu"
    $env:GONIDBG_UNICORN = "$uc/unicorn.dll"
}

Write-Host "[run] engine=$Engine  go run -tags $Engine $Rest"
go run -tags "$Engine" @Rest
