// Package dvm is the fake Dalvik/ART runtime: the JavaVM + JNIEnv the native
// library talks to. It is unidbg's single biggest value-add and the bulk of a
// Go port's hand-written code.
//
// How it works (same shape as unidbg):
//   - A JNIEnv struct lives in guest memory; each of its ~232 function-pointer
//     slots points at an SVC trampoline. When the .so calls e.g.
//     CallStaticObjectMethodV, the SVC traps to the host, we read the args from
//     registers/varargs, look up the target by its "class->method(sig)" string,
//     and invoke a Jni callback (below). The return value is boxed back into a
//     guest jobject handle.
//   - Objects never live in guest memory; they are Go values held in a
//     registry and referenced by opaque integer handles (jobject/jclass/jstring
//     are just those handles). This is exactly unidbg's DvmObject model.
package dvm

import (
	"fmt"
	"sync"
)

// Ref is an opaque guest-side handle (jobject/jclass/jstring/jarray).
type Ref int32

// Object is any boxed Java value.
type Object struct {
	Class *Class
	Value any // Go-side payload: string, []byte, int64, *Class, or arbitrary
}

// Class is a resolved Java class plus its registered methods/fields.
type Class struct {
	Name    string
	Super   *Class
	methods map[string]*Method // key: "name(sig)"
	fields  map[string]*Field
}

type Method struct {
	ID        Ref
	Name, Sig string
	Static    bool
}

type Field struct {
	ID        Ref
	Name, Sig string
	Static    bool
}

// Jni is the host callback surface, mirroring unidbg's AbstractJni. the host app
// overrides a handful of these; everything else falls through to defaults.
type Jni interface {
	CallStaticObjectMethodV(vm *VM, cls *Class, sig string, args *VaList) *Object
	CallObjectMethodV(vm *VM, obj *Object, sig string, args *VaList) *Object
	CallLongMethodV(vm *VM, obj *Object, sig string, args *VaList) int64
	GetStaticObjectField(vm *VM, cls *Class, sig string) *Object
	// ... extend with the other Call*/Get* forms as the .so exercises them.
}

// VM is the JavaVM: class registry + handle table.
type VM struct {
	mu      sync.Mutex
	classes map[string]*Class
	objs    map[Ref]*Object
	nextRef Ref
	nextID  Ref
	jni     Jni
}

func NewVM() *VM {
	return &VM{
		classes: map[string]*Class{},
		objs:    map[Ref]*Object{},
		nextRef: 0x100,    // start handles away from 0/low ints
		nextID:  0x7000_0001,
	}
}

func (vm *VM) SetJni(j Jni) { vm.jni = j }
func (vm *VM) Jni() Jni     { return vm.jni }

// ResolveClass registers (or returns) a class by JNI name ("a/b/C").
func (vm *VM) ResolveClass(name string, super ...*Class) *Class {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if c, ok := vm.classes[name]; ok {
		return c
	}
	c := &Class{Name: name, methods: map[string]*Method{}, fields: map[string]*Field{}}
	if len(super) > 0 {
		c.Super = super[0]
	}
	vm.classes[name] = c
	return c
}

// NewObject boxes a Go value as an instance of cls and returns a handle.
func (vm *VM) NewObject(cls *Class, value any) Ref {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	r := vm.nextRef
	vm.nextRef++
	vm.objs[r] = &Object{Class: cls, Value: value}
	return r
}

// Box registers an already-constructed Object and returns a fresh handle.
func (vm *VM) Box(o *Object) Ref {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	r := vm.nextRef
	vm.nextRef++
	vm.objs[r] = o
	return r
}

// Deref resolves a handle back to its object (nil for 0/unknown).
func (vm *VM) Deref(r Ref) *Object {
	if r == 0 {
		return nil
	}
	vm.mu.Lock()
	defer vm.mu.Unlock()
	return vm.objs[r]
}

// MethodID / FieldID interning, keyed by "name(sig)".
func (c *Class) MethodID(vm *VM, name, sig string, static bool) *Method {
	key := name + sig
	if m, ok := c.methods[key]; ok {
		return m
	}
	vm.mu.Lock()
	id := vm.nextID
	vm.nextID++
	vm.mu.Unlock()
	m := &Method{ID: id, Name: name, Sig: sig, Static: static}
	c.methods[key] = m
	return m
}

func (c *Class) String() string { return c.Name }

// Helpers to build common boxed values, matching the host app's usage.
func NewString(vm *VM, s string) Ref {
	return vm.NewObject(vm.ResolveClass("java/lang/String"), s)
}
func NewByteArray(vm *VM, b []byte) Ref {
	return vm.NewObject(vm.ResolveClass("[B"), b)
}
func NewLong(vm *VM, v int64) Ref {
	return vm.NewObject(vm.ResolveClass("java/lang/Long"), v)
}
func NewInteger(vm *VM, v int32) Ref {
	return vm.NewObject(vm.ResolveClass("java/lang/Integer"), v)
}

// MethodSig formats the "class->method(sig)" key the way unidbg dispatches and
// the host app's switch statements expect.
func MethodSig(cls *Class, nameSig string) string {
	return fmt.Sprintf("%s->%s", cls.Name, nameSig)
}
