package emulator

import (
	"fmt"

	"github.com/sisi0318/gonidbg/dvm"
	"github.com/sisi0318/gonidbg/internal/emu"
)

// This file is gonidbg's reverse JNI bridge: invoking a native method that the
// .so registered with RegisterNatives, *from Go*. It is the inverse of
// jni_dispatch.go (the .so calling into Java). unidbg exposes this as
// DvmObject.callJniMethod / callJniMethodObject; here it is CallNative*.
//
// A registered native is just a C function fn(JNIEnv* env, jclass/jobject self,
// <args...>). We box the Java-typed args into guest handles/primitives, set up
// the AAPCS64 call (env in X0, receiver in X1, args in X2.. then the stack),
// run it, and hand back X0. While it runs, the .so makes the usual re-entrant
// JNIEnv up-calls, which jni_dispatch.go routes to the dvm.Jni handler.

// argKind tags a JavaArg's payload.
type argKind int

const (
	argInt argKind = iota
	argLong
	argBool
	argRef    // an existing jobject/jclass/jstring handle
	argString // boxed to a fresh jstring
	argBytes  // boxed to a fresh jbyteArray
	argObject // boxed to a fresh jobject
)

// JavaArg is one argument to a native method invoked from Go via CallNative*.
// Build one with ArgInt/ArgLong/ArgBool/ArgString/ArgBytes/ArgObject/ArgRef.
type JavaArg struct {
	kind argKind
	u    uint64
	s    string
	b    []byte
	obj  *dvm.Object
}

// ArgInt passes a jint.
func ArgInt(v int32) JavaArg { return JavaArg{kind: argInt, u: uint64(uint32(v))} }

// ArgLong passes a jlong.
func ArgLong(v int64) JavaArg { return JavaArg{kind: argLong, u: uint64(v)} }

// ArgBool passes a jboolean (0/1).
func ArgBool(v bool) JavaArg {
	if v {
		return JavaArg{kind: argBool, u: 1}
	}
	return JavaArg{kind: argBool, u: 0}
}

// ArgString boxes s as a jstring for the call.
func ArgString(s string) JavaArg { return JavaArg{kind: argString, s: s} }

// ArgBytes boxes b as a jbyteArray for the call.
func ArgBytes(b []byte) JavaArg { return JavaArg{kind: argBytes, b: b} }

// ArgObject boxes o (a *dvm.Object) as a fresh jobject handle for the call.
func ArgObject(o *dvm.Object) JavaArg { return JavaArg{kind: argObject, obj: o} }

// ArgRef passes an existing handle (e.g. a cached instance from NewInstance, or
// a jclass) directly, preserving object identity across calls.
func ArgRef(r dvm.Ref) JavaArg { return JavaArg{kind: argRef, u: uint64(r)} }

// boxArg lowers a JavaArg to the integer register value the native expects.
func (e *Emulator) boxArg(a JavaArg) uint64 {
	switch a.kind {
	case argString:
		return uint64(dvm.NewString(e.vm, a.s))
	case argBytes:
		return uint64(dvm.NewByteArray(e.vm, a.b))
	case argObject:
		if a.obj == nil {
			return 0
		}
		return uint64(e.vm.Box(a.obj))
	default: // argInt, argLong, argBool, argRef
		return a.u
	}
}

// CallNativeStatic invokes a RegisterNatives'd static native method
// (className/name/sig) with Java-typed args, returning the raw X0 result (a
// jobject handle for object returns, the value for primitive returns).
func (e *Emulator) CallNativeStatic(className, name, sig string, args ...JavaArg) (uint64, error) {
	return e.callNative(className, name, sig, uint64(e.classRef(className)), args)
}

// CallNativeInstance invokes a RegisterNatives'd instance native method on the
// receiver jobject handle (thiz). className must match the class the method was
// registered under.
func (e *Emulator) CallNativeInstance(thiz dvm.Ref, className, name, sig string, args ...JavaArg) (uint64, error) {
	return e.callNative(className, name, sig, uint64(thiz), args)
}

// NativeObject derefs a native return handle (from CallNative*) to its boxed
// Object — nil for a void/null return.
func (e *Emulator) NativeObject(ret uint64) *dvm.Object { return e.vm.Deref(dvm.Ref(int32(ret))) }

// HasNativeMethod reports whether class.name+sig was registered via
// RegisterNatives (so CallNative* can invoke it). Use it to pick between
// version-specific method variants (e.g. initContext vs initNativeContext).
func (e *Emulator) HasNativeMethod(className, name, sig string) bool {
	_, ok := e.natives[className+"."+name+sig]
	return ok
}

func (e *Emulator) callNative(className, name, sig string, receiver uint64, args []JavaArg) (uint64, error) {
	key := className + "." + name + sig
	fn, ok := e.natives[key]
	if !ok {
		return 0, fmt.Errorf("native method %q not registered (RegisterNatives not seen, or rejected by AcceptMethod)", key)
	}
	regs := make([]uint64, 0, len(args)+2)
	regs = append(regs, e.JNIEnv(), receiver)
	for _, a := range args {
		regs = append(regs, e.boxArg(a))
	}
	if e.cfg.Verbose {
		fmt.Printf("[call] %s (fn=0x%x, %d args)\n", key, fn, len(args))
	}
	ret, err := e.callFuncStack(fn, regs)
	if err != nil {
		return 0, fmt.Errorf("call %s: %w", key, err)
	}
	if exited, code := e.GuestExited(); exited {
		return 0, fmt.Errorf("guest exit_group(%d) during %s", code, key)
	}
	return ret, nil
}

// callFuncStack is CallFunc with support for more than 8 integer args: the
// first 8 go in X0..X7, the rest are spilled to the stack per AAPCS64.
func (e *Emulator) callFuncStack(addr uint64, args []uint64) (uint64, error) {
	if len(args) <= 8 {
		return e.CallFunc(addr, args...)
	}
	spill := args[8:]
	origSP, err := e.be.RegRead(emu.RegSP)
	if err != nil {
		return 0, err
	}
	space := (uint64(len(spill))*8 + 15) &^ 15 // 16-byte aligned
	sp := origSP - space
	for i, v := range spill {
		if err := putU64(e.be, sp+uint64(i)*8, v); err != nil {
			return 0, err
		}
	}
	if err := e.be.RegWrite(emu.RegSP, sp); err != nil {
		return 0, err
	}
	ret, callErr := e.CallFunc(addr, args[:8]...)
	_ = e.be.RegWrite(emu.RegSP, origSP) // restore the caller's stack
	return ret, callErr
}
