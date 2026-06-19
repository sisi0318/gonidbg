# Dev helper: build+run a gonidbg command with the Unicorn engine on Windows.
#
# Prereqs (one-time):
#   1) zig in PATH                 (zig cc as the C compiler)
#   2) libunicorn at C:\ucvendor   (pip install unicorn; copy site-packages\unicorn\
#      include\ and unicorn.dll into C:\ucvendor)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\win-run.ps1                                  # run the example
#   powershell -ExecutionPolicy Bypass -File .\win-run.ps1 gonidbg examples\native\native.so add 2 3
#   powershell -ExecutionPolicy Bypass -File .\win-run.ps1 elfscan examples\native\native.so

param(
    [string]$Cmd = "example",
    [Parameter(ValueFromRemainingArguments=$true)] $Rest
)

$env:CGO_ENABLED      = "1"
$env:CC               = "zig cc"
$env:CXX              = "zig c++"
$env:CGO_CFLAGS       = "-IC:/ucvendor/include -fno-sanitize=undefined -fno-stack-protector"
$env:CGO_CFLAGS_ALLOW = ".*"
$env:GONIDBG_UNICORN  = "C:/ucvendor/unicorn.dll"   # unicorn.dll loaded at runtime

Set-Location -LiteralPath $PSScriptRoot   # so ./assets and ./examples resolve

if ($Cmd -eq "example") {
    go run -tags unicorn ./examples/run @Rest
} else {
    go run -tags unicorn "./cmd/$Cmd" @Rest
}
