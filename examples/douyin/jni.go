//go:build unicorn || dynarmic

package main

import (
	"path/filepath"
	"strconv"

	"github.com/sisi0318/gonidbg/dvm"
)

// douyinJni models the exact set of Java callbacks the target library makes
// during JNI_OnLoad + signing. It embeds dvm.AbstractJni and overrides only the
// methods the .so actually invokes — the standard gonidbg/unidbg pattern. This
// is hand-written from observing the library's JNI calls; it contains no
// third-party code and no signing algorithm (that lives inside the .so).
type douyinJni struct{ dvm.AbstractJni }

func (j douyinJni) CallStaticObjectMethodV(vm *dvm.VM, cls *dvm.Class, sig string, va *dvm.VaList) *dvm.Object {
	switch sig {
	case "com/bytedance/mobsec/metasec/ml/MS->b(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;":
		switch va.GetIntArg(0) {
		case 0x1000000E:
			return &dvm.Object{Class: vm.ResolveClass("java/lang/Long"), Value: int64(2)}
		case 0x10003:
			abs, _ := filepath.Abs("test_path")
			return &dvm.Object{Class: vm.ResolveClass("java/lang/String"), Value: abs}
		case 0x2000001, 0x2000002:
			return &dvm.Object{Class: vm.ResolveClass("java/lang/String"), Value: "armeabi"}
		}
	case "java/lang/Integer->valueOf(I)Ljava/lang/Integer;":
		return &dvm.Object{Class: vm.ResolveClass("java/lang/Integer"), Value: va.GetIntArg(0)}
	case "java/lang/Thread->currentThread()Ljava/lang/Thread;":
		return &dvm.Object{Class: vm.ResolveClass("java/lang/Thread"), Value: "main"}
	}
	return j.AbstractJni.CallStaticObjectMethodV(vm, cls, sig, va)
}

func (j douyinJni) CallLongMethodV(vm *dvm.VM, obj *dvm.Object, sig string, va *dvm.VaList) int64 {
	if sig == "java/lang/Long->longValue()J" {
		if v, ok := obj.Value.(int64); ok {
			return v
		}
	}
	return j.AbstractJni.CallLongMethodV(vm, obj, sig, va)
}

func (j douyinJni) CallObjectMethodV(vm *dvm.VM, obj *dvm.Object, sig string, va *dvm.VaList) *dvm.Object {
	switch sig {
	case "java/lang/Integer->getBytes(Ljava/lang/String;)[B":
		return &dvm.Object{Class: vm.ResolveClass("[B"), Value: []byte(strconv.Itoa(int(va.GetIntArg(0))))}
	case "java/lang/String->getBytes(Ljava/lang/String;)[B", "java/lang/String->getBytes()[B":
		if s, ok := obj.Value.(string); ok {
			return &dvm.Object{Class: vm.ResolveClass("[B"), Value: []byte(s)}
		}
	case "java/lang/String->toString()Ljava/lang/String;":
		return obj
	case "java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;":
		ste := vm.ResolveClass("java/lang/StackTraceElement")
		return &dvm.Object{Class: vm.ResolveClass("[Ljava/lang/StackTraceElement;"), Value: []*dvm.Object{
			{Class: ste, Value: "dalvik.system.VMStack"},
			{Class: ste, Value: "java.lang.Thread"},
		}}
	}
	return j.AbstractJni.CallObjectMethodV(vm, obj, sig, va)
}
