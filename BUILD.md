# 构建说明(含 CPU 引擎)

本项目分两层:**纯 Go 层**(loader/memory/kernel/dvm/vfs/emulator,无 cgo)和 **CPU 引擎层**(`internal/emu`,cgo)。引擎可选,像原版 unidbg 一样在构建期选编译哪些、运行期选用哪个:

| 引擎 | 构建标签 | 形态 | 说明 |
|---|---|---|---|
| **Unicorn2** | `-tags unicorn` | 运行时 `dlopen` libunicorn | 解释执行,成熟稳定,默认 |
| **dynarmic** | `-tags dynarmic` | **静态链接**(C++,经 zig) | JIT,更快;见下方 [dynarmic 引擎](#dynarmic-引擎静态链接) |

两个都编进去:`-tags "unicorn dynarmic"`,运行期用 `-engine unicorn|dynarmic`(或环境变量 `GONIDBG_ENGINE`)选择;`gonidbg -engine ...` 会打印当前引擎。不带任何引擎标签则是纯 Go 构建(可编译/单测,但创建模拟器会返回"无引擎"错误)。

## 0. 一次性准备 Unicorn(本机已完成,换机器需重做)

```bash
pip install unicorn          # 得到预编译原生库 + 头文件
# 拷到一个【纯 ASCII】路径(本项目路径含中文,cgo 标志校验会拒绝中文路径)
#   site-packages/unicorn/include/  -> C:/ucvendor/include/
#   site-packages/unicorn/unicorn.dll, unicorn.lib -> C:/ucvendor/
```

C 编译器:本机用 **`zig cc`**(zig 0.15.2 已在 PATH)。无需单独装 gcc。

## 1. 纯 Go 层(默认,随处可build/test)

```bash
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...        # 含 memory 分配器、linker 对真 .so 的重定位测试
go run ./cmd/elfscan               # .so 导入面分析
go run ./cmd/loadplan              # 链接复杂度(重定位直方图)
```

## 2. 引擎层(`-tags unicorn`,cgo)

统一的环境变量(libunicorn 运行时 `LoadLibrary`/`dlopen` 加载,**不在链接期引入 import 库**,只需头文件):

```bash
export CC="zig cc" CGO_ENABLED=1
export CGO_CFLAGS="-IC:/ucvendor/include -fno-sanitize=undefined -fno-stack-protector"
export CGO_CFLAGS_ALLOW='.*'
```

- `-fno-sanitize=undefined`:zig cc 默认开 UBSan,不关会在链接期缺 `__ubsan_*`。
- 运行期定位 DLL:同目录放 `unicorn.dll`,或设 `GONIDBG_UNICORN=路径`,或回退 `C:/ucvendor/unicorn.dll`。

### Windows 构建(可编译)

```bash
GOOS=windows go build -tags unicorn ./...
go build -tags unicorn ./cmd/ucsmoke   # cgo+unicorn 管线自检(纯 C 版已验证 add x0,#1 => 11)
```

### Linux 交叉编译(部署目标,推荐运行环境)

```bash
CC="zig cc -target x86_64-linux-gnu" CXX="zig c++ -target x86_64-linux-gnu" \
  GOOS=linux GOARCH=amd64 go build -tags unicorn -o gonidbg ./cmd/gonidbg
# 目标机:apt install libunicorn 或带上 libunicorn.so;然后 ./gonidbg
```

## Windows / Linux 都能运行(关键:引擎跑在专属 C 线程)

`unicorn.dll` 用 `VirtualAlloc(MEM_RESERVE)` + **VEH** 惰性提交 guest 内存页。难点:**Go 运行时在自己管理的线程上会抢先把这个访问异常当成崩溃**(实测:即便 cgo 注册 first=1 的 VEH 也抢不过;主线程上 `uc_mem_map` 直接崩)。

**解法**([uc_shim.c](internal/emu/uc_shim.c)):把 unicorn 引擎**关在一个 `CreateThread` 起的专属 C 线程**里,Go 端每个后端操作经"命令泵"marshal 到该线程执行。要点:

- 引擎线程上的 `uc_*` 是 **C→C 直调**,不经过 Go 的 cgocall SEH 包裹;其 fault 的 PC 落在 unicorn.dll 里 → Go 异常处理器放行 → unicorn 自己的 VEH 提交页面。
- 中断/代码 hook 回调在引擎线程上运行;回调里再调后端(读写寄存器/内存、**甚至现场 mmap 新区**)会被检测到"已在引擎线程"从而直接执行,不入队、不死锁。
- **已实测通过**([cmd/bsmoke](cmd/bsmoke/main.go)):`svc#0` 触发回调 → 回调内 `MemMap` 新区 + 读写 + 改寄存器 → 继续执行,`x0==16`、回写 `deadbeef` 正确。

平台差异都在 C 里:**Linux 无此冲突**(Go 用 `sigfwdgo` 把 SIGSEGV 转给 unicorn),所以 Linux 版不用线程泵、直接调用。Go 侧代码完全一致。

> 仍建议**生产部署在 Linux**(与原项目一致、性能/信号模型更自然);Windows 现在可以本地开发自测了。
> `cmd/ucthread` 是最小验证(裸 C 线程跑通 `add x0,#1`);`cmd/bsmoke` 是经 `emu.Backend` 的完整自测(`-tags unicorn` 或 `-tags dynarmic` 都可跑)。

## dynarmic 引擎(静态链接)

dynarmic 是 ARM JIT(yuzu/citra/unidbg 同款),比 Unicorn 解释器快。它只有 C++20 API、无 C API,所以本项目用一层 C++ shim([`internal/emu/dyn_shim.cpp`](internal/emu/dyn_shim.cpp))包成 C ABI 给 cgo 调,并**静态链接**进二进制。guest 内存用页表回调实现(C++ 内,不跨 cgo),只有 SVC 才回到 Go。

### 1. 一次性:vendoring + 编译 dynarmic 静态库

一条命令(自动装 cmake/ninja、克隆 dynarmic、取 Boost 头、打 fmt/mcl 的 clang 兼容补丁、用 zig 编译,产物收集到 `C:/dynvendor`):

```bash
./build-dynarmic.sh
# 关键环境变量:DYN_SRC(源码)、DYN_VENDOR(输出,默认 C:/dynvendor)、BOOST_VER、JOBS
```

产物:`C:/dynvendor/lib/{libdynarmic,libmcl,libfmt,libZydis,libZycore}.a`。头文件直接用 dynarmic 源码树的 `…/src`。

> 脚本里几个**绕坑**(zig=clang20 + libc++20 对老依赖较严):用 toolchain 文件钉死 `zig ar/ranlib`(否则 `CMAKE_AR-NOTFOUND`);patch fmt 关 consteval、去掉 libc++ 已删的 `<__std_stream>`;给 mcl 加一个 `std::integer_sequence` 具体特化。并行编译用 `-j4`(过高会触发 zig 缓存竞争 `error: Unexpected`)。

### 2. 用 dynarmic 构建 Go 服务

```bash
export CC="zig cc" CXX="zig c++" CGO_ENABLED=1 CGO_CFLAGS_ALLOW='.*'
export CGO_CXXFLAGS="-IC:/dynsrc/src -std=c++20"
export CGO_LDFLAGS="-LC:/dynvendor/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++"
go build -tags dynarmic -o bin/gonidbg.exe ./cmd/gonidbg            # 仅 dynarmic
go run  -tags dynarmic ./cmd/gonidbg examples/native/native.so add 2 3
```

### 3. 两个引擎都编进一个二进制(运行期可切)

合并两套 cgo flag(Unicorn 运行时加载,无需 `-l`;dynarmic 静态链接):

```bash
export CC="zig cc" CXX="zig c++" CGO_ENABLED=1 CGO_CFLAGS_ALLOW='.*'
export CGO_CFLAGS="-IC:/ucvendor/include -fno-sanitize=undefined -fno-stack-protector"
export CGO_CXXFLAGS="-IC:/dynsrc/src -std=c++20"
export CGO_LDFLAGS="-LC:/dynvendor/lib -ldynarmic -lmcl -lfmt -lZydis -lZycore -lc++"
go build -tags "unicorn dynarmic" -o bin/gonidbg.exe ./cmd/gonidbg

./bin/gonidbg.exe -engine unicorn  examples/native/native.so add 2 3
./bin/gonidbg.exe -engine dynarmic examples/native/native.so add 2 3   # 两引擎结果一致
```

> Windows 上 `build.ps1 -Dynarmic` / 任意平台 `WITH_DYNARMIC=1 ./build.sh` 会自动带上 dynarmic 引擎(需先跑过 `build-dynarmic.sh`)。
> dynarmic 库用 zig(clang + libc++)编译,cgo 链接也用 zig,C++ ABI 一致;最终链接需 `-lc++`(zig 自带 libc++)。
