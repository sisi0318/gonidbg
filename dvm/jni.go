package dvm

// AbstractJni is the default JNI handler: AcceptMethod returns true and every
// Java call returns null/0/false. Embed it in your own handler and override
// only the methods your native library actually invokes — exactly unidbg's
// AbstractJni pattern.
//
//	type MyJni struct{ dvm.AbstractJni }
//	func (MyJni) CallStaticObjectMethodV(vm *dvm.VM, cls *dvm.Class, sig string, va *dvm.VaList) *dvm.Object {
//	    if sig == "com/example/App->name()Ljava/lang/String;" {
//	        return &dvm.Object{Class: vm.ResolveClass("java/lang/String"), Value: "demo"}
//	    }
//	    return nil
//	}
type AbstractJni struct{}

func (AbstractJni) AcceptMethod(*VM, *Class, string, bool) bool { return true }

func (AbstractJni) CallObjectMethodV(*VM, *Object, string, *VaList) *Object { return nil }
func (AbstractJni) CallBooleanMethodV(*VM, *Object, string, *VaList) bool   { return false }
func (AbstractJni) CallIntMethodV(*VM, *Object, string, *VaList) int32      { return 0 }
func (AbstractJni) CallLongMethodV(*VM, *Object, string, *VaList) int64     { return 0 }
func (AbstractJni) CallVoidMethodV(*VM, *Object, string, *VaList)           {}

func (AbstractJni) CallStaticObjectMethodV(*VM, *Class, string, *VaList) *Object { return nil }
func (AbstractJni) CallStaticIntMethodV(*VM, *Class, string, *VaList) int32      { return 0 }
func (AbstractJni) CallStaticVoidMethodV(*VM, *Class, string, *VaList)           {}

func (AbstractJni) GetObjectField(*VM, *Object, string) *Object      { return nil }
func (AbstractJni) GetIntField(*VM, *Object, string) int32           { return 0 }
func (AbstractJni) SetObjectField(*VM, *Object, string, *Object)     {}
func (AbstractJni) GetStaticObjectField(*VM, *Class, string) *Object { return nil }
func (AbstractJni) GetStaticIntField(*VM, *Class, string) int32      { return 0 }

func (AbstractJni) NewObjectV(*VM, *Class, string, *VaList) *Object { return nil }
