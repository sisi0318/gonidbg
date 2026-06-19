package dvm

// AbstractJni is the default no-op JNI handler: every Java call returns
// null/0. Embed it in your own handler and override only the methods your
// native library actually invokes — exactly unidbg's AbstractJni pattern.
//
//	type MyJni struct{ dvm.AbstractJni }
//	func (MyJni) CallStaticObjectMethodV(vm *dvm.VM, cls *dvm.Class, sig string, va *dvm.VaList) *dvm.Object {
//	    if sig == "com/example/App->name()Ljava/lang/String;" {
//	        return &dvm.Object{Class: vm.ResolveClass("java/lang/String"), Value: "demo"}
//	    }
//	    return nil
//	}
type AbstractJni struct{}

func (AbstractJni) CallStaticObjectMethodV(*VM, *Class, string, *VaList) *Object { return nil }
func (AbstractJni) CallObjectMethodV(*VM, *Object, string, *VaList) *Object      { return nil }
func (AbstractJni) CallLongMethodV(*VM, *Object, string, *VaList) int64          { return 0 }
func (AbstractJni) GetStaticObjectField(*VM, *Class, string) *Object             { return nil }
