// Package emulator is gonidbg's high-level API: a minimal unidbg in Go. It boots
// an emulated AArch64 Android process, maps + links real bionic (libc/libm/libdl)
// and your target .so into guest memory through a selectable CPU backend
// (Unicorn or dynarmic), services Linux syscalls and the JNI/JavaVM surface, and
// lets you call native functions by symbol or offset and exchange memory.
//
// Typical use:
//
//	e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so"})
//	defer e.Close()
//	ret, _ := e.CallSymbol("add", 2, 3)   // -> 5
//
// It is engine-agnostic and JVM-free: a single Go binary, fast cold start.
package emulator

import (
	"encoding/binary"
	"fmt"
	"path/filepath"

	"github.com/sisi0318/gonidbg/dvm"
	"github.com/sisi0318/gonidbg/internal/emu"
	"github.com/sisi0318/gonidbg/internal/kernel"
	"github.com/sisi0318/gonidbg/internal/loader"
	"github.com/sisi0318/gonidbg/internal/memory"
	"github.com/sisi0318/gonidbg/internal/vfs"
)

// Config controls how an Emulator boots.
type Config struct {
	// AssetRoot is the directory containing android/sdk23/... (bionic libs +
	// synthetic /proc, properties, tzdata). Empty = auto-locate (see Locate).
	AssetRoot string
	// SOPath is an optional "main" shared object to load+init at boot (its
	// DT_INIT/init_array run, and JNI_OnLoad if exported). Empty = boot bionic
	// only; load libraries yourself with LoadLibrary.
	SOPath string
	// JNI is the Java callback handler the guest's JNIEnv calls dispatch to.
	// nil = dvm.AbstractJni{} (everything returns null/0). Implement dvm.Jni (or
	// embed dvm.AbstractJni and override a few methods) to model the Java side.
	JNI dvm.Jni
	// DexPath optionally loads a classes.dex at boot so FindClass/GetMethodID/
	// GetFieldID resolve against real class/method/field metadata (signatures,
	// superclasses) instead of being synthesized. Metadata only — no bytecode.
	DexPath string
	// ProcessName is the emulated process name reported via /proc/self/* etc.
	ProcessName string
	// Pid reported to the guest (getpid/gettid/...). 0 = a default.
	Pid int
	// Engine selects the CPU backend: "unicorn" | "dynarmic" | "" (auto /
	// $GONIDBG_ENGINE / first compiled in).
	Engine string
	// Verbose logs each syscall / JNI call / unresolved import.
	Verbose bool
}

const defaultPid = 28859

// Memory layout (guest), kept clear of each other and of the mmap arena.
const (
	moduleBase = 0x12000000 // modules loaded from here, upward
	stubBase   = 0x60000000 // svc trampolines for unresolved imports
	stubSize   = 0x00100000
	stackBase  = 0xC0000000 // 8 MiB stack
	stackSize  = 0x00800000
	tlsBase    = 0xD0000000 // thread-local storage block
	tlsSize    = 0x00010000
	sentinel   = 0xFFFFFF00 // LR for top-level calls; emu stops when PC hits it
)

// Module is one loaded shared object.
type Module struct {
	Name string
	Base uint64
	Img  *loader.Image
}

// Emulator is one isolated guest process.
type Emulator struct {
	cfg    Config
	engine string // resolved CPU engine name ("unicorn" / "dynarmic")
	be     emu.Backend
	mem    *memory.Space
	vm     *dvm.VM
	fs     *vfs.VFS
	kctx   *kernel.Context

	modules  []*Module
	main     *Module           // the Config.SOPath module, if any
	syms     map[string]uint64 // global export table
	nextBase uint64
	nextStub uint64
	stubs    map[uint64]string // svc addr -> import/JNI name
	stubHits map[string]int
	scCount  int // syscalls in current CallFunc (runaway guard)

	jniEnv      uint64         // guest JNIEnv* (points to a stub function table)
	javaVM      uint64         // guest JavaVM*
	getEnvStub  uint64         // JavaVM->GetEnv svc stub (special-cased)
	jniDispatch map[uint64]int // JNIEnv stub addr -> JNINativeInterface index
	classRefs   map[string]dvm.Ref
	classMeta   *dvm.Class             // java/lang/Class
	natives     map[string]uint64      // "class.name+sig" -> registered native fn ptr
	methods     map[dvm.Ref]*methodRef // jmethodID -> (class, method)
	arrayPins   map[uint64]dvm.Ref     // GetByteArrayElements ptr -> array ref (copy-back)
	pendingExc  bool                   // a pending JNI exception (Throw/ThrowNew)

	hostByName map[string]hostFn // libc funcs we implement in Go (override bionic)
	hostImpl   map[uint64]hostFn // svc addr -> host impl
	replaced   map[uint64]hostFn // user Replace()d functions (svc addr -> Go impl)
	atRandom   uint64            // guest ptr to 16 "random" bytes (AT_RANDOM)
}

// hostFn is a native function implemented on the Go side (args in X0.., ret X0).
type hostFn func(e *Emulator, b emu.Backend)

// Modules returns the loaded modules in load order.
func (e *Emulator) Modules() []*Module { return e.modules }

// MainModule returns the Config.SOPath module (nil if none was given).
func (e *Emulator) MainModule() *Module { return e.main }

// VM returns the fake Dalvik VM (class registry + handle table).
func (e *Emulator) VM() *dvm.VM { return e.vm }

// LoadDex parses a classes.dex and registers its classes/methods/fields into the
// VM (metadata only — no bytecode execution). Returns the class count.
func (e *Emulator) LoadDex(path string) (int, error) { return e.vm.LoadDexFile(path) }

// GuestExited reports whether the guest called exit/exit_group and its code.
func (e *Emulator) GuestExited() (bool, int) { return e.kctx.Exited, e.kctx.ExitCode }

// Engine reports which CPU engine this emulator is running on ("unicorn" /
// "dynarmic"), as resolved from Config.Engine / $GONIDBG_ENGINE / the default.
func (e *Emulator) Engine() string { return e.engine }

// New boots an emulator: prepares the address space, maps bionic, and (if
// Config.SOPath is set) loads + initializes the main library.
func New(cfg Config) (*Emulator, error) {
	engine, err := emu.Resolve(cfg.Engine)
	if err != nil {
		return nil, fmt.Errorf("backend: %w", err)
	}
	be, err := emu.NewNamed(engine)
	if err != nil {
		return nil, fmt.Errorf("backend(%s): %w", engine, err)
	}
	pid := cfg.Pid
	if pid == 0 {
		pid = defaultPid
	}
	e := &Emulator{
		cfg:         cfg,
		engine:      engine,
		be:          be,
		mem:         memory.NewSpace(),
		vm:          dvm.NewVM(),
		fs:          vfs.New(cfg.AssetRoot, pid, cfg.ProcessName),
		syms:        map[string]uint64{},
		nextBase:    moduleBase,
		nextStub:    stubBase,
		stubs:       map[uint64]string{},
		stubHits:    map[string]int{},
		hostByName:  map[string]hostFn{},
		hostImpl:    map[uint64]hostFn{},
		replaced:    map[uint64]hostFn{},
		jniDispatch: map[uint64]int{},
		classRefs:   map[string]dvm.Ref{},
		natives:     map[string]uint64{},
		methods:     map[dvm.Ref]*methodRef{},
		arrayPins:   map[uint64]dvm.Ref{},
	}
	e.classMeta = e.vm.ResolveClass("java/lang/Class")
	if cfg.JNI != nil {
		e.vm.SetJni(cfg.JNI)
	} else {
		e.vm.SetJni(dvm.AbstractJni{})
	}
	if cfg.DexPath != "" {
		nc, derr := e.vm.LoadDexFile(cfg.DexPath)
		if derr != nil {
			return nil, fmt.Errorf("load dex: %w", derr)
		}
		if cfg.Verbose {
			fmt.Printf("[dex] %s -> %d classes\n", cfg.DexPath, nc)
		}
	}
	registerHostFns(e) // libc functions we implement in Go (need no libc init)
	e.kctx = &kernel.Context{B: be, Mem: e.mem, VFS: e.fs, Pid: pid, Verbose: cfg.Verbose}

	// Reserve fixed regions.
	if err := be.MemMap(stubBase, stubSize, emu.ProtAll); err != nil {
		return nil, fmt.Errorf("map stubs: %w", err)
	}
	if err := be.MemMap(stackBase, stackSize, emu.ProtRead|emu.ProtWrite); err != nil {
		return nil, fmt.Errorf("map stack: %w", err)
	}
	if err := be.MemMap(tlsBase, tlsSize, emu.ProtRead|emu.ProtWrite); err != nil {
		return nil, fmt.Errorf("map tls: %w", err)
	}
	// SP near top of stack (16-aligned).
	_ = be.RegWrite(emu.RegSP, stackBase+stackSize-0x200)

	// bionic TLS: TPIDR_EL0 -> slot array; slot[TLS_SLOT_THREAD_ID] -> a mapped
	// pthread_internal_t (zeroed). Without this, libc reads a NULL thread ptr
	// and faults writing thread-local fields. The struct lives inside the TLS
	// region so its fields are always mapped.
	const (
		tlsSlotSelf     = 0 // __get_tls()[0] = tls base
		tlsSlotThreadID = 1 // -> pthread_internal_t*
		pthreadStruct   = tlsBase + 0x1000
	)
	_ = be.RegWrite(emu.RegTPIDR_EL0, tlsBase)
	_ = putU64(be, tlsBase+tlsSlotSelf*8, tlsBase)
	_ = putU64(be, tlsBase+tlsSlotThreadID*8, pthreadStruct)

	// Route SVC: distinguish import-stub calls (by PC) from real syscalls.
	if _, err := be.HookInterrupt(e.onInterrupt); err != nil {
		return nil, err
	}
	// Diagnose unmapped/protected accesses during bring-up.
	if _, err := be.HookMemInvalid(func(b emu.Backend, typ int, addr uint64, size int, val int64) bool {
		pc, _ := b.RegRead(emu.RegPC)
		if e.cfg.Verbose {
			fmt.Printf("[mem] INVALID access type=%d addr=0x%x size=%d value=0x%x pc=0x%x (%s)\n",
				typ, addr, size, uint64(val), pc, e.NearestSym(pc))
		}
		return false // do not auto-recover; surface the error
	}); err != nil {
		return nil, err
	}

	if err := e.boot(); err != nil {
		_ = be.Close()
		return nil, err
	}
	return e, nil
}

// boot maps bionic, then (if configured) loads + initializes the main library.
func (e *Emulator) boot() error {
	lib := e.cfg.AssetRoot + "/android/sdk23/lib64/"
	for _, l := range []string{"libc.so", "libm.so", "libdl.so"} {
		if _, err := e.LoadModule(lib+l, l); err != nil {
			return fmt.Errorf("load %s: %w", l, err)
		}
	}
	if e.cfg.SOPath == "" {
		return nil // bionic only; caller will LoadLibrary explicitly
	}
	m, err := e.LoadLibrary(e.cfg.SOPath)
	if err != nil {
		return err
	}
	e.main = m
	return nil
}

// LoadLibrary maps + links a shared object, runs its initializers (DT_INIT +
// init_array) and, if it exports JNI_OnLoad, calls that with the JavaVM.
// Analogous to unidbg's Emulator.loadLibrary. Returns the loaded Module.
func (e *Emulator) LoadLibrary(path string) (*Module, error) {
	m, err := e.LoadModule(path, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	if err := e.RunInit(m); err != nil {
		return nil, err
	}
	if jni, ok := e.Sym("JNI_OnLoad"); ok {
		if _, err := e.CallFunc(jni, e.JavaVM(), 0); err != nil {
			return nil, fmt.Errorf("JNI_OnLoad: %w", err)
		}
		if exited, code := e.GuestExited(); exited {
			return nil, fmt.Errorf("guest exit_group(%d) during JNI_OnLoad", code)
		}
	}
	return m, nil
}

// LoadModule maps + links a shared object and records its exports (no init run).
func (e *Emulator) LoadModule(path, name string) (*Module, error) {
	img, err := loader.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	base := e.nextBase
	span := (img.LoadSpan + 0xfff) &^ 0xfff
	e.nextBase = base + span + 0x100000 // gap between modules

	if err := img.Apply(e.be, base, e.resolveSymbol); err != nil {
		return nil, fmt.Errorf("link %s: %w", name, err)
	}
	for n, off := range img.Exports {
		if _, exists := e.syms[n]; !exists {
			e.syms[n] = base + off
		}
	}
	m := &Module{Name: name, Base: base, Img: img}
	e.modules = append(e.modules, m)
	if e.cfg.Verbose {
		fmt.Printf("[load] %-20s base=0x%x span=0x%x exports=%d\n", name, base, span, len(img.Exports))
	}
	return m, nil
}

// resolveSymbol satisfies loader.Resolver: global export, else a svc stub.
func (e *Emulator) resolveSymbol(name string) (uint64, bool) {
	if fn, ok := e.hostByName[name]; ok { // Go override for libc funcs needing init
		a := e.makeStub("host:" + name)
		e.hostImpl[a] = fn
		return a, true
	}
	if a, ok := e.syms[name]; ok {
		return a, true
	}
	return e.makeStub(name), true
}

// makeStub emits `svc #0 ; ret` at a fresh stub address (traps to onInterrupt,
// which returns to the caller). Used for unresolved imports and JNI table slots.
func (e *Emulator) makeStub(name string) uint64 {
	a := e.nextStub
	e.nextStub += 8
	_ = e.be.MemWrite(a, []byte{0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6})
	e.stubs[a] = name
	return a
}

// SetupJNI builds a minimal JavaVM + JNIEnv in guest memory: both are pointers
// to function tables filled with svc stubs, so any vm->/env-> call traps to Go.
// GetEnv is special-cased to hand back the JNIEnv. Sets e.javaVM.
func (e *Emulator) SetupJNI() uint64 {
	const envSlots = 256 // > 232 JNINativeInterface entries
	envTable := e.Alloc(envSlots*8, emu.ProtRead|emu.ProtWrite)
	for i := 0; i < envSlots; i++ {
		stub := e.makeStub(fmt.Sprintf("JNIEnv[%d]", i))
		e.jniDispatch[stub] = i // dispatched in onInterrupt -> handleJNI
		_ = putU64(e.be, envTable+uint64(i)*8, stub)
	}
	envPtr := e.Alloc(8, emu.ProtRead|emu.ProtWrite)
	_ = putU64(e.be, envPtr, envTable)
	e.jniEnv = envPtr

	const vmSlots = 16 // JNIInvokeInterface
	vmTable := e.Alloc(vmSlots*8, emu.ProtRead|emu.ProtWrite)
	for i := 0; i < vmSlots; i++ {
		_ = putU64(e.be, vmTable+uint64(i)*8, e.makeStub(fmt.Sprintf("JavaVM[%d]", i)))
	}
	e.getEnvStub = e.makeStub("JavaVM!GetEnv")
	_ = putU64(e.be, vmTable+6*8, e.getEnvStub) // GetEnv
	_ = putU64(e.be, vmTable+4*8, e.getEnvStub) // AttachCurrentThread (also yields env)
	vmPtr := e.Alloc(8, emu.ProtRead|emu.ProtWrite)
	_ = putU64(e.be, vmPtr, vmTable)
	e.javaVM = vmPtr
	return vmPtr
}

// JavaVM returns the guest JavaVM*, building the JNI tables on first use.
func (e *Emulator) JavaVM() uint64 {
	if e.javaVM == 0 {
		e.SetupJNI()
	}
	return e.javaVM
}

// JNIEnv returns the guest JNIEnv* (a pointer to the function table), building
// the JNI tables on first use. Pass it to native functions that take a JNIEnv*.
func (e *Emulator) JNIEnv() uint64 {
	if e.jniEnv == 0 {
		e.SetupJNI()
	}
	return e.jniEnv
}

// Sym returns a resolved global symbol address.
func (e *Emulator) Sym(name string) (uint64, bool) { a, ok := e.syms[name]; return a, ok }

// onInterrupt handles SVC: a stub call (unresolved import) or a real syscall.
func (e *Emulator) onInterrupt(b emu.Backend, intno uint32) {
	pc, _ := b.RegRead(emu.RegPC)
	svc := pc - 4            // unicorn advances PC past the svc
	if svc == e.getEnvStub { // JavaVM->GetEnv(vm, void** env, version)
		envpp, _ := b.RegRead(emu.RegX1)
		_ = putU64(b, envpp, e.jniEnv)
		_ = b.RegWrite(emu.RegX0, 0) // JNI_OK
		return
	}
	if fn, ok := e.replaced[svc]; ok { // user Replace()d function
		fn(e, b)
		return
	}
	if idx, ok := e.jniDispatch[svc]; ok { // JNIEnv->function(...)
		e.handleJNI(idx, b)
		return
	}
	if fn, ok := e.hostImpl[svc]; ok { // Go-implemented libc function
		fn(e, b)
		return
	}
	if name, ok := e.stubs[svc]; ok {
		e.stubHits[name]++
		if e.cfg.Verbose {
			fmt.Printf("[stub] %s() -> 0\n", name)
		}
		_ = b.RegWrite(emu.RegX0, 0) // optimistic default
		return
	}
	e.scCount++
	if e.scCount > 200000 {
		fmt.Println("[guard] runaway syscalls — stopping emulation")
		_ = b.Stop()
		return
	}
	e.kctx.Dispatch()
}

// CallFunc invokes guest code at addr with up to 8 integer args (X0..X7),
// returning X0. LR is set to a sentinel so emulation stops on return.
func (e *Emulator) CallFunc(addr uint64, args ...uint64) (uint64, error) {
	regs := []emu.Reg{emu.RegX0, emu.RegX1, emu.RegX2, emu.RegX3, emu.RegX4, emu.RegX5, emu.RegX6, emu.RegX7}
	if len(args) > len(regs) {
		return 0, fmt.Errorf("CallFunc: >8 args not supported")
	}
	for i, a := range args {
		if err := e.be.RegWrite(regs[i], a); err != nil {
			return 0, err
		}
	}
	if err := e.be.RegWrite(emu.RegLR, sentinel); err != nil {
		return 0, err
	}
	e.scCount = 0
	if err := e.be.Start(addr, sentinel); err != nil {
		return 0, fmt.Errorf("emu_start @0x%x: %w", addr, err)
	}
	return e.be.RegRead(emu.RegX0)
}

// CallSymbol calls an exported function by name with up to 8 integer args.
func (e *Emulator) CallSymbol(name string, args ...uint64) (uint64, error) {
	addr, ok := e.Sym(name)
	if !ok {
		return 0, fmt.Errorf("symbol %q not found", name)
	}
	return e.CallFunc(addr, args...)
}

// CallOffset calls a function at module base + offset — for non-exported entry
// points located by reverse engineering (unidbg's module.callFunction(offset)).
// A nil module means the main module (Config.SOPath).
func (e *Emulator) CallOffset(m *Module, offset uint64, args ...uint64) (uint64, error) {
	if m == nil {
		m = e.main
	}
	if m == nil {
		return 0, fmt.Errorf("CallOffset: no module (set Config.SOPath or pass a module)")
	}
	return e.CallFunc(m.Base+offset, args...)
}

// NearestSym maps a guest address to "module!symbol+0xNN" for diagnostics.
func (e *Emulator) NearestSym(addr uint64) string {
	for _, m := range e.modules {
		if addr < m.Base || addr >= m.Base+m.Img.LoadSpan {
			continue
		}
		rel := addr - m.Base
		bestName, bestOff := "", uint64(0)
		for n, off := range m.Img.Exports {
			if off <= rel && off >= bestOff {
				bestName, bestOff = n, off
			}
		}
		if bestName == "" {
			return fmt.Sprintf("%s+0x%x", m.Name, rel)
		}
		return fmt.Sprintf("%s!%s+0x%x", m.Name, bestName, rel-bestOff)
	}
	return fmt.Sprintf("0x%x", addr)
}

// RunInit runs a module's DT_INIT then its init_array (in order), like the
// dynamic linker. Stops at the first failure.
func (e *Emulator) RunInit(m *Module) error {
	if m.Img.Init != 0 {
		if _, err := e.CallFunc(m.Base + m.Img.Init); err != nil {
			return fmt.Errorf("%s DT_INIT: %w", m.Name, err)
		}
	}
	ptrs, err := e.InitArrayPtrs(m)
	if err != nil {
		return err
	}
	for i, addr := range ptrs {
		if _, err := e.CallFunc(addr); err != nil {
			return fmt.Errorf("%s init_array[%d] @0x%x: %w", m.Name, i, addr, err)
		}
	}
	return nil
}

func putU64(be emu.Backend, addr, val uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], val)
	return be.MemWrite(addr, b[:])
}

// InitArrayPtrs reads the module's init_array function pointers from guest
// memory AFTER relocation (on AArch64 the file section is zeros; RELATIVE
// addends written by the linker hold the real, base-relative pointers).
func (e *Emulator) InitArrayPtrs(m *Module) ([]uint64, error) {
	var ptrs []uint64
	for i := 0; i < m.Img.InitArrayLen; i++ {
		b, err := e.be.MemRead(m.Base+m.Img.InitArrayAddr+uint64(i)*8, 8)
		if err != nil {
			return nil, err
		}
		ptrs = append(ptrs, binary.LittleEndian.Uint64(b))
	}
	return ptrs, nil
}

// Close releases the backend.
func (e *Emulator) Close() error {
	if e.be != nil {
		return e.be.Close()
	}
	return nil
}
