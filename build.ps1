<#
build.ps1 — build gonidbg on Windows.

  CPU 引擎 = libunicorn 经 cgo(用 zig cc 当 C 编译器,无需 gcc/MSVC)。
  产物输出到 .\bin\:
    gonidbg.exe                 CLI(引擎,-tags unicorn)
    elfscan.exe, loadplan.exe   纯 Go 分析工具
    unicorn.dll                 拷到 exe 旁,运行时直接可用

用法:
  powershell -ExecutionPolicy Bypass -File .\build.ps1
  powershell -ExecutionPolicy Bypass -File .\build.ps1 -Dynarmic   # 再静态链接 dynarmic 引擎(先跑 build-dynarmic.sh)
  powershell -ExecutionPolicy Bypass -File .\build.ps1 -Linux      # 另外交叉编译 Linux 版
  powershell -ExecutionPolicy Bypass -File .\build.ps1 -OutDir dist
#>
param(
    [string]$OutDir = "bin",
    [switch]$Linux,
    [switch]$Dynarmic   # also link the static dynarmic JIT engine (run build-dynarmic.sh first)
)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$UC  = "C:\ucvendor"            # vendored libunicorn (headers + dll)
$UCi = "C:/ucvendor/include"    # 正斜杠,供 cgo -I 使用(ASCII 路径,避开中文工程路径)

function Need($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "PATH 中找不到必需工具: $name"
    }
}
Need go
Need zig

# 1) 确保 libunicorn 已就位(缺则用 Python wheel 一次性 vendoring)
if (-not (Test-Path "$UC\unicorn.dll")) {
    Write-Host "[setup] $UC 不存在 -> 通过 'pip install unicorn' 取预编译库..."
    Need python
    python -m pip install --quiet unicorn
    $pkg = (python -c "import unicorn,os;print(os.path.dirname(unicorn.__file__))").Trim()
    New-Item -ItemType Directory -Force -Path "$UC\include" | Out-Null
    Copy-Item -Recurse -Force "$pkg\include\unicorn" "$UC\include\"
    Copy-Item -Force "$pkg\lib\unicorn.dll" "$UC\"
    Write-Host "[setup] 已从 $pkg vendoring 到 $UC"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 2) 引擎构建(cgo,经 zig cc)
$env:CC               = "zig cc"
$env:CXX              = "zig c++"
$env:CGO_CFLAGS       = "-I$UCi -fno-sanitize=undefined -fno-stack-protector"
$env:CGO_CFLAGS_ALLOW = ".*"
$env:CGO_ENABLED      = "1"
$env:GOOS = "windows"; $env:GOARCH = "amd64"

# 可选第二引擎:-Dynarmic 也静态链接 dynarmic JIT(先跑 ./build-dynarmic.sh)
$Tags = "unicorn"
if ($Dynarmic) {
    $Tags = "unicorn dynarmic"
    $DynSrc    = if ($env:DYN_SRC)    { $env:DYN_SRC }    else { "C:/dynsrc" }
    $DynVendor = if ($env:DYN_VENDOR) { $env:DYN_VENDOR } else { "C:/dynvendor" }
    $env:CGO_CXXFLAGS = "-I$DynSrc/src -std=c++20"
    $env:CGO_LDFLAGS  = "-L$DynVendor/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++"
    Write-Host "[build] dynarmic engine enabled (vendor: $DynVendor/lib)"
}

Write-Host "[build] gonidbg.exe  (CLI, engine, -tags `"$Tags`")"
go build -tags "$Tags" -o "$OutDir\gonidbg.exe" ./cmd/gonidbg

# 3) 纯 Go 分析工具(无 cgo)
$env:CGO_ENABLED = "0"
Write-Host "[build] elfscan.exe / loadplan.exe  (pure-Go)"
go build -o "$OutDir\elfscan.exe"  ./cmd/elfscan
go build -o "$OutDir\loadplan.exe" ./cmd/loadplan

# 4) 把 unicorn.dll 放到 exe 旁,运行时无需再设 GONIDBG_UNICORN
Copy-Item -Force "$UC\unicorn.dll" "$OutDir\"

# 5) 可选:交叉编译 Linux 版(目标机运行时需有 libunicorn.so)
if ($Linux) {
    Write-Host "[build] gonidbg-linux  (cross, -tags unicorn)"
    $env:CGO_ENABLED = "1"; $env:GOOS = "linux"; $env:GOARCH = "amd64"
    $env:CC = "zig cc -target x86_64-linux-gnu"; $env:CXX = "zig c++ -target x86_64-linux-gnu"
    go build -tags unicorn -o "$OutDir\gonidbg-linux" ./cmd/gonidbg
}

Write-Host ""
Write-Host "[ok] 产物在 $PSScriptRoot\$OutDir :"
Get-ChildItem $OutDir | Select-Object Name, @{n='Size'; e={ "{0:N0}" -f $_.Length }} | Format-Table -AutoSize
Write-Host "运行:  .\$OutDir\gonidbg.exe examples\native\native.so add 2 3"
