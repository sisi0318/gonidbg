**简体中文** | [English](README.en.md)

# gonidbg

[![CI](https://github.com/sisi0318/gonidbg/actions/workflows/ci.yml/badge.svg)](https://github.com/sisi0318/gonidbg/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sisi0318/gonidbg.svg)](https://pkg.go.dev/github.com/sisi0318/gonidbg)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

gonidbg 是 [unidbg](https://github.com/zhkl0228/unidbg) 的一个 Go 精简实现:在本机加载一个 Android AArch64 native 库(`.so`),不借助 JVM、真机或 Android 系统就能直接调用里面的函数。它给这个 `.so` 搭出一套够用的 Android 进程环境(动态链接器、真实的 bionic libc、一部分 Linux 系统调用、JNI/JavaVM),你就能从 Go 里调它的导出函数、读写它的内存。

和 unidbg 一样,CPU 引擎可以替换:[Unicorn](https://www.unicorn-engine.org/) 解释器,或静态链接的 [dynarmic](https://github.com/lioncash/dynarmic) JIT。编译时决定打包哪个,运行时决定用哪个。

```go
e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so"})
defer e.Close()
sum, _ := e.CallSymbol("add", 2, 3) // -> 5,作为真实 AArch64 代码执行
```

> 当前状态:两个引擎都能完整跑通,具体包括加载并链接 bionic 和目标 `.so`、执行 `init_array` 与 `JNI_OnLoad`、调用导出函数、处理 syscall 与 JNI。它是 unidbg 的一个子集,缺哪些能力见 [对标 unidbg](#对标-unidbg)。

---

## 为什么

unidbg 是模拟 Android native 库的事实标准,但它跑在 JVM 上,依赖也偏重。gonidbg 想用 Go 把最核心的那部分重新做一遍:

- 不需要 JVM。编译产物就是单个 Go 二进制,启动快、占用低。
- 引擎可换。Unicorn 稳定,作为默认;dynarmic 是 JIT,热路径上快 5–9 倍;编译期或运行期都能选,跟 unidbg 的 backend 思路一致。
- 复用真实 bionic。直接加载并模拟执行 AOSP sysroot 里的 `libc/libm/libdl`,省得自己重写一套 libc。
- 代码量小。框架本体是几千行还算好读的 Go,外加两个很薄的 CPU 引擎 shim。

## 特性

- AArch64 ELF 加载与动态链接(`RELATIVE` / `JUMP_SLOT` / `GLOB_DAT` / `ABS64`),`DT_INIT` + `init_array`。
- 复用真实 bionic `libc/libm/libdl`(内置 AOSP sdk23 sysroot),支持跨模块符号解析。
- Linux/AArch64 系统调用子集(mmap/mprotect/openat/read/write/clock_gettime/getrandom/futex/…),配一套小型虚拟文件系统(`/system/lib64`、`/proc/self/*`、属性、tzdata)。
- JNI/JavaVM:guest 的 `JNIEnv`/`JavaVM` 调用会陷回到你用 Go 实现的处理器(`FindClass`、`GetMethodID`、`Call*Method*`、`RegisterNatives`、字符串、字节数组等)。
- 按符号名或按模块偏移调用 native 函数,最多 8 个整型参数,可读取返回值。
- 用 Go 回调替换(Replace)某个 native 函数(unidbg 式 hook),并自动让代码缓存失效。
- 内存助手:分配、读写字节、C 字符串、小端整数。
- 单指令 trace(Unicorn)。
- 引擎可选:`-tags unicorn`、`-tags dynarmic`,或两个都编进去,运行期用 `-engine` / `$GONIDBG_ENGINE` 选择。

## 快速开始

### 前置条件

- Go 1.24+
- [zig](https://ziglang.org/download/),需在 `PATH` 中,用作 cgo 的 C/C++ 交叉编译器,不需要 gcc 或 MSVC。
- 一个 CPU 引擎:
  - Unicorn(默认):构建脚本会用 `pip install unicorn` 自动 vendoring。
  - dynarmic(可选,更快):跑一次 `./build-dynarmic.sh` 完成 vendoring 和静态编译,详见 [BUILD.md](BUILD.md)。

### 构建并运行示例

```bash
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File .\build.ps1            # -> bin\gonidbg.exe (unicorn)
.\bin\gonidbg.exe examples\native\native.so add 2 3            # add([2 3]) = 5

# Linux / macOS / git-bash
./build.sh
./bin/gonidbg examples/native/native.so fib 20                  # fib([20]) = 6765
```

完整演示(加载内置 `native.so`,调用导出函数、一个被 import 的 `strlen`、一个写指针的函数,以及一个 Go `Replace` hook):

```bash
go run -tags unicorn ./examples/run    # (cgo 环境变量见 BUILD.md;或直接用编好的二进制)
# engine: unicorn
# add(2, 3)      = 5
# fib(20)        = 6765
# slen(...)      = 14
# sum_into -> *out = 42
# add(2, 3) after Replace = 23  (Go hook: a*10+b)
```

## 作为库使用

```go
import "github.com/sisi0318/gonidbg/emulator"

e, err := emulator.New(emulator.Config{
    SOPath:    "libfoo.so",        // 启动时加载并跑 init_array + JNI_OnLoad
    AssetRoot: emulator.Locate("assets"),
    Engine:    "",                 // "unicorn" | "dynarmic" | "" = 自动
})
if err != nil { panic(err) }
defer e.Close()

// 按名调用导出函数(最多 8 个整型/指针参数,返回 X0)。
r, _ := e.CallSymbol("add", 2, 3)

// 按模块偏移调用非导出入口(= unidbg 的 callFunction(offset))。
r, _ = e.CallOffset(nil /*主模块*/, 0x1234, argPtr)

// 交换内存。
p := e.WriteCStringAlloc("hello")
n, _ := e.CallSymbol("strlen_wrapper", p)
out := e.Malloc(4); _, _ = e.CallSymbol("sum_into", out, 20, 22)
v, _ := e.ReadU32(out)

// 用 Go 替换一个 native 函数(hook)。
e.ReplaceSymbol("add", func(h *emulator.Hook) uint64 { return h.Arg(0) + h.Arg(1) })
```

### 给 Java 侧建模(JNI)

native 库会通过 JNI 回调 Java。实现 `dvm.Jni`(或 embed `dvm.AbstractJni`,只重写你的库会用到的那几个方法),再传进 `Config.JNI`:

```go
type MyJni struct{ dvm.AbstractJni }

func (MyJni) CallStaticObjectMethodV(vm *dvm.VM, cls *dvm.Class, sig string, va *dvm.VaList) *dvm.Object {
    if sig == "com/example/App->token()Ljava/lang/String;" {
        return &dvm.Object{Class: vm.ResolveClass("java/lang/String"), Value: "secret"}
    }
    return nil
}

e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so", JNI: MyJni{}})
```

这就是 unidbg 里 `AbstractJni` 的用法:guest 的 `RegisterNatives`/`GetMethodID`/`Call*Method` 会按 `"类->方法(签名)"` 这样的字符串路由到你的 switch。

> 真实案例见 [`examples/douyin`](examples/douyin):用上面这套通用 API,在一个生产级混淆 `.so` 上复现请求签名头(该 `.so` 是第三方专有文件,不随仓库分发,需要自备)。

## CPU 引擎

| 引擎 | 构建标签 | 链接方式 | 速度(热路径) | 许可证 |
|---|---|---|---|---|
| **Unicorn2** | `-tags unicorn` | 运行时 `dlopen` libunicorn | ~20 ms/次 | GPLv2 |
| **dynarmic** | `-tags dynarmic` | **静态链接**(C++ via zig) | ~2–4 ms/次 | 0BSD |

- 两个引擎可以编进同一个二进制(`-tags "unicorn dynarmic"`),运行期再选:`gonidbg -engine dynarmic …` 或 `GONIDBG_ENGINE=dynarmic`。
- 每个模拟器第一次调用要花几百毫秒(dynarmic 现编 JIT,Unicorn 预热),之后复用同一个模拟器就很快了。
- 许可证提示:Unicorn 是 GPLv2,静态链接它会让整个二进制都变成 GPLv2,所以 gonidbg 把它放在运行时 `dlopen` 的边界之后。dynarmic 是 0BSD(宽松许可),静态链接 dynarmic 不会带来 copyleft 牵连。dynarmic 的构建见 [BUILD.md](BUILD.md)。

## 工作原理

`emulator.New` 对照 unidbg `Emulator` 的启动流程:

1. 地址空间:铺好 guest 栈、TLS(`TPIDR_EL0` 加一个 `pthread_internal_t`)和 SVC 跳板区,并选定 CPU 后端。
2. 加载与链接:先处理真实 bionic 的 `libc/libm/libdl`,再处理你的 `.so`,也就是解析 ELF、映射段、处理重定位、跨模块解析符号;没解析到的 import 指向一个 `svc` 跳板,陷回 Go。
3. 初始化:跑 `DT_INIT` 和 `init_array`,如果导出了 `JNI_OnLoad` 也一并调用(传入合成的 `JavaVM`)。
4. 调用:`CallSymbol`/`CallOffset` 把参数写进 `X0..X7`,把 `LR` 设成哨兵地址,然后一直跑到返回。SVC 陷入之后再分派给 syscall 层(`internal/kernel`)、JNI 层,或某个用 Go 实现的 libc 函数、被 Replace 的函数。

guest 的内存和寄存器通过 `Backend` 接口交换,两个引擎 shim 都实现了这个接口。dynarmic 后端给 JIT 提供了一张直接访存的页表,生成的代码可以直接读写宿主内存,只有遇到 SVC 才陷回 Go。

### 目录结构

```
gonidbg/
├── emulator/     公开 API:New、LoadLibrary、CallSymbol/CallOffset、Replace、内存助手
├── dvm/          公开:假 Dalvik VM —— VM、Object、Class、Jni、AbstractJni、VaList
├── internal/
│   ├── emu/      CPU 后端接口 + 注册表;unicorn(cgo)与 dynarmic(cgo/C++)shim
│   ├── loader/   ELF 解析 + 动态链接器
│   ├── kernel/   AArch64 Linux 系统调用子集
│   ├── memory/   guest 地址空间分配器
│   └── vfs/      guest 虚拟文件系统(/system/lib64、/proc/self、属性、tzdata)
├── cmd/
│   ├── gonidbg/  CLI:加载 .so 并调用某个符号
│   ├── elfscan/  分析 .so(导入/导出/init)
│   ├── loadplan/ 重定位直方图 / 链接复杂度
│   ├── bsmoke/   引擎自检
│   └── ucthread/ 最小引擎自检
├── examples/
│   ├── native/   一个自建的小 AArch64 .so(源码 + 预编译),供示例 + 测试用
│   └── douyin/   真实案例:在一个生产 .so 上复现签名(.so 需自备,不入库)
└── assets/android/sdk23/  内置 AOSP bionic sysroot(见 NOTICE)
```

## 对标 unidbg

已实现的部分:AArch64 ELF 加载与动态链接、复用真实 bionic、可选 Unicorn / dynarmic 后端、Linux syscall 子集、带 Go 处理器的 JNI/JavaVM、按名或按偏移调用、函数 `Replace`(Go hook)、内存助手、指令 trace。

还没做的(算是路线图,也欢迎 PR):

- ARM32,目前只支持 AArch64。
- 完整的 JNI 面,现在只实现了 `JNINativeInterface` 里够用的一个子集,不是全部约 232 个槽位。
- 完整的 syscall 表,现在是几十个,不是 unidbg 的全集。
- 由 APK/DEX 驱动的 VM。gonidbg 的 `dvm` 是合成的,需要你在 Go 里给 Java 侧建模,它不会从 APK 里解析真实的类。
- 函数中部或内联 hook(目前只有函数入口的 `Replace`)、交互式控制台调试器、信号、真正的线程(`pthread_create` 现在是 no-op)。
- iOS / Mach-O。

## 从源码构建 / 引擎

完整的工具链(用 zig 当 C/C++ 编译器)、纯 Go 层与引擎层、静态 dynarmic 构建(`build-dynarmic.sh`)以及 Windows/Linux 说明,都在 [BUILD.md](BUILD.md) 里。

```bash
# 纯 Go 层随处可 build/test(无引擎、无 cgo):
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...

# 引擎集成测试(加载内置 native.so 并运行):
go test -tags unicorn  ./emulator
go test -tags dynarmic ./emulator
```

## 致谢与许可证

- [unidbg](https://github.com/zhkl0228/unidbg)(Apache-2.0):本项目重新实现的对象。
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn)(GPLv2):默认 CPU 后端,运行时加载。
- [dynarmic](https://github.com/lioncash/dynarmic)(0BSD):可选的 JIT CPU 后端。
- AOSP bionic(Apache-2.0)等:`assets/` 下内置的 sysroot,见 [NOTICE](NOTICE)。

gonidbg 自身的代码采用 Apache-2.0(见 [LICENSE](LICENSE))。引擎的许可证各不相同,见上表:Unicorn 后端走动态加载,把它的 GPLv2 限制在库边界之内;dynarmic 后端是宽松许可。

## 免责声明

gonidbg 是一个科研和教育用途的工具,用来分析你有权研究的 native 库。仓库里不含任何第三方应用的代码或专有二进制,只有一套通用的模拟框架,以及一个用本仓库源码自建的小示例库。请合理使用,并遵守适用的法律以及你所分析软件的相关条款。
