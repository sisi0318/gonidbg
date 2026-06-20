package emulator

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/sisi0318/gonidbg/dvm"
	"github.com/sisi0318/gonidbg/internal/emu"
)

func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

// utf16le encodes s as little-endian UTF-16 (no terminator) for JNI jchar* APIs.
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[i*2:], c)
	}
	return out
}

type methodRef struct {
	cls *dvm.Class
	m   *dvm.Method
}

type fieldRef struct {
	cls *dvm.Class
	f   *dvm.Field
}

// decodeVaList extracts n general-purpose (int/long/pointer) varargs from an
// AAPCS64 __va_list:
//
//	struct { void* __stack; void* __gr_top; void* __vr_top; int __gr_offs; int __vr_offs; }
//
// GP args live at __gr_top + __gr_offs (offs negative, counting up to 0); once
// exhausted they come from __stack. (MS.b's args are all GP, so FP/__vr is
// unused here.)
func (e *Emulator) decodeVaList(vaPtr uint64, n int) []uint64 {
	hdr, err := e.be.MemRead(vaPtr, 32)
	if err != nil {
		return make([]uint64, n)
	}
	grTop := le64(hdr[8:])
	stack := le64(hdr[0:])
	grOffs := int64(int32(binary.LittleEndian.Uint32(hdr[24:])))
	out := make([]uint64, n)
	stackPos := stack
	for i := 0; i < n; i++ {
		if grOffs < 0 {
			if v, err := e.be.MemRead(uint64(int64(grTop)+grOffs), 8); err == nil {
				out[i] = le64(v)
			}
			grOffs += 8
		} else {
			if v, err := e.be.MemRead(stackPos, 8); err == nil {
				out[i] = le64(v)
			}
			stackPos += 8
		}
	}
	return out
}

// JNINativeInterface slot indices (0-based within the struct; first 4 reserved).
const (
	jniGetVersion            = 4
	jniFindClass             = 6
	jniExceptionOccurred     = 15
	jniExceptionDescribe     = 16
	jniExceptionClear        = 17
	jniNewGlobalRef          = 21
	jniDeleteGlobalRef       = 22
	jniDeleteLocalRef        = 23
	jniIsSameObject          = 24
	jniNewLocalRef           = 25
	jniGetObjectClass        = 31
	jniGetMethodID           = 33
	jniGetFieldID            = 94
	jniGetStaticMethodID     = 113
	jniGetStaticFieldID      = 144
	jniNewStringUTF          = 167
	jniGetStringUTFLength    = 168
	jniGetStringUTFChars     = 169
	jniReleaseStringUTFChrs  = 170
	jniGetArrayLength        = 171
	jniNewObjectArray        = 172
	jniGetObjectArrayElement = 173
	jniSetObjectArrayElement = 174
	jniNewByteArray          = 176
	jniGetByteArrayElements  = 184
	jniRelByteArrayElements  = 192
	jniGetByteArrayRegion    = 200
	jniSetByteArrayRegion    = 208
	jniRegisterNatives       = 215
	jniGetJavaVM             = 219
	jniExceptionCheck        = 228
)

var jniNames = map[int]string{
	4: "GetVersion", 6: "FindClass", 10: "GetSuperclass", 11: "IsAssignableFrom",
	13: "Throw", 14: "ThrowNew",
	15: "ExceptionOccurred", 16: "ExceptionDescribe", 17: "ExceptionClear",
	19: "PushLocalFrame", 20: "PopLocalFrame", 21: "NewGlobalRef", 22: "DeleteGlobalRef",
	23: "DeleteLocalRef", 24: "IsSameObject", 25: "NewLocalRef", 26: "EnsureLocalCapacity",
	27: "AllocObject", 28: "NewObject", 29: "NewObjectV", 30: "NewObjectA",
	31: "GetObjectClass", 32: "IsInstanceOf", 33: "GetMethodID",
	34: "CallObjectMethod", 35: "CallObjectMethodV", 37: "CallBooleanMethod", 38: "CallBooleanMethodV",
	49: "CallIntMethod", 50: "CallIntMethodV", 52: "CallLongMethod", 53: "CallLongMethodV",
	61: "CallVoidMethod", 62: "CallVoidMethodV",
	94: "GetFieldID", 113: "GetStaticMethodID", 114: "CallStaticObjectMethod",
	115: "CallStaticObjectMethodV", 144: "GetStaticFieldID", 164: "GetStringLength",
	165: "GetStringChars", 166: "ReleaseStringChars",
	167: "NewStringUTF", 168: "GetStringUTFLength", 169: "GetStringUTFChars",
	170: "ReleaseStringUTFChars", 171: "GetArrayLength",
	172: "NewObjectArray", 173: "GetObjectArrayElement", 174: "SetObjectArrayElement",
	176: "NewByteArray",
	184: "GetByteArrayElements", 192: "ReleaseByteArrayElements", 200: "GetByteArrayRegion",
	208: "SetByteArrayRegion", 215: "RegisterNatives", 217: "MonitorEnter", 218: "MonitorExit",
	219: "GetJavaVM", 220: "GetStringRegion", 221: "GetStringUTFRegion",
	228: "ExceptionCheck", 232: "GetObjectRefType",
}

func jniLabel(idx int) string {
	if n := jniNames[idx]; n != "" {
		return n
	}
	return fmt.Sprintf("JNIEnv[%d]", idx)
}

// arg reads JNIEnv-call argument n (n=1 is the first real arg; X0 is JNIEnv*).
func (e *Emulator) jarg(b emu.Backend, n int) uint64 {
	regs := []emu.Reg{emu.RegX0, emu.RegX1, emu.RegX2, emu.RegX3, emu.RegX4, emu.RegX5, emu.RegX6, emu.RegX7}
	v, _ := b.RegRead(regs[n])
	return v
}

// handleJNI dispatches a JNIEnv function call (by table index) to the dvm layer.
func (e *Emulator) handleJNI(idx int, b emu.Backend) {
	ret := uint64(0)
	detail := "" // extra context for the trace line (class/method names, args)
	switch idx {
	case jniGetVersion:
		ret = 0x00010006 // JNI_VERSION_1_6

	case jniFindClass:
		name, _ := e.ReadCStr(e.jarg(b, 1))
		if e.classAllowed(name) {
			ret = uint64(e.classRef(name))
		} else {
			// A filtered class is "not found" — per JNI that means a pending
			// NoClassDefFoundError. unidbg's addFilterFoundClass works this way.
			e.pendingExc = true
		}
		detail = fmt.Sprintf("%q", name)

	case jniGetObjectClass:
		o := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1))))
		if o != nil && o.Class != nil {
			ret = uint64(e.classRef(o.Class.Name))
		}

	case 10: // GetSuperclass
		cls := e.derefClass(e.jarg(b, 1))
		if cls != nil && cls.Name != "java/lang/Object" {
			ret = uint64(e.classRef("java/lang/Object"))
		}

	case 11, 32: // IsAssignableFrom, IsInstanceOf
		ret = 1

	case jniGetMethodID, jniGetStaticMethodID:
		cls := e.derefClass(e.jarg(b, 1))
		name, _ := e.ReadCStr(e.jarg(b, 2))
		sig, _ := e.ReadCStr(e.jarg(b, 3))
		if cls != nil {
			m := cls.MethodID(e.vm, name, sig, idx == jniGetStaticMethodID)
			e.methods[m.ID] = &methodRef{cls: cls, m: m}
			ret = uint64(m.ID)
			detail = fmt.Sprintf("%s.%s%s", cls.Name, name, sig)
		}

	case 114, 115: // CallStaticObjectMethod[V](env, clazz, methodID, args/va_list)
		ret, detail = e.callStatic(b, idx == 115)
	case 129, 130, 131: // CallStaticIntMethod[V/A]
		if cls, sig, va := e.callStaticInfo(b, idx == 130); cls != nil {
			ret = uint64(uint32(e.vm.Jni().CallStaticIntMethodV(e.vm, cls, sig, va)))
			detail = sig
		}
	case 141, 142, 143: // CallStaticVoidMethod[V/A]
		if cls, sig, va := e.callStaticInfo(b, idx == 142); cls != nil {
			e.vm.Jni().CallStaticVoidMethodV(e.vm, cls, sig, va)
			detail = sig
		}

	case 34, 35: // CallObjectMethod[V] (instance) -> the Jni handler.CallObjectMethodV
		if obj, sig, va := e.callInstanceInfo(b, idx == 35); obj != nil {
			if o := e.vm.Jni().CallObjectMethodV(e.vm, obj, sig, va); o != nil {
				ret = uint64(e.vm.Box(o))
			}
			detail = sig
		}

	case 37, 38: // CallBooleanMethod[V] (instance)
		if obj, sig, va := e.callInstanceInfo(b, idx == 38); obj != nil {
			if e.vm.Jni().CallBooleanMethodV(e.vm, obj, sig, va) {
				ret = 1
			}
			detail = sig
		}
	case 49, 50: // CallIntMethod[V] (instance)
		if obj, sig, va := e.callInstanceInfo(b, idx == 50); obj != nil {
			ret = uint64(uint32(e.vm.Jni().CallIntMethodV(e.vm, obj, sig, va)))
			detail = sig
		}
	case 52, 53: // CallLongMethod[V] (instance)
		if obj, sig, va := e.callInstanceInfo(b, idx == 53); obj != nil {
			ret = uint64(e.vm.Jni().CallLongMethodV(e.vm, obj, sig, va))
			detail = sig
		}
	case 61, 62: // CallVoidMethod[V] (instance)
		if obj, sig, va := e.callInstanceInfo(b, idx == 62); obj != nil {
			e.vm.Jni().CallVoidMethodV(e.vm, obj, sig, va)
			detail = sig
		}

	case 19, 20, 26, 27: // Push/PopLocalFrame, EnsureLocalCapacity, AllocObject
		ret = 0
	case 232: // GetObjectRefType -> JNILocalRefType
		ret = 1

	case jniGetFieldID, jniGetStaticFieldID:
		// Intern a real field id keyed to (class, name, sig) so the field
		// getters/setters below can rebuild the "Class->name:Sig" lookup string.
		cls := e.derefClass(e.jarg(b, 1))
		name, _ := e.ReadCStr(e.jarg(b, 2))
		sig, _ := e.ReadCStr(e.jarg(b, 3))
		if cls != nil {
			f := cls.FieldID(e.vm, name, sig, idx == jniGetStaticFieldID)
			e.fields[f.ID] = &fieldRef{cls: cls, f: f}
			ret = uint64(f.ID)
			detail = fmt.Sprintf("%s.%s:%s", cls.Name, name, sig)
		}

	case 95: // GetObjectField(obj, fieldID) -> Jni.GetObjectField
		if obj, sig := e.fieldInfo(b); obj != nil {
			if o := e.vm.Jni().GetObjectField(e.vm, obj, sig); o != nil {
				ret = uint64(e.vm.Box(o))
			}
			detail = sig
		}
	case 100: // GetIntField
		if obj, sig := e.fieldInfo(b); obj != nil {
			ret = uint64(uint32(e.vm.Jni().GetIntField(e.vm, obj, sig)))
			detail = sig
		}
	case 104: // SetObjectField(obj, fieldID, val)
		if obj, sig := e.fieldInfo(b); obj != nil {
			val := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 3))))
			e.vm.Jni().SetObjectField(e.vm, obj, sig, val)
			detail = sig
		}
	case 145: // GetStaticObjectField(cls, fieldID)
		if cls, sig := e.staticFieldInfo(b); sig != "" {
			if o := e.vm.Jni().GetStaticObjectField(e.vm, cls, sig); o != nil {
				ret = uint64(e.vm.Box(o))
			}
			detail = sig
		}
	case 150: // GetStaticIntField
		if cls, sig := e.staticFieldInfo(b); sig != "" {
			ret = uint64(uint32(e.vm.Jni().GetStaticIntField(e.vm, cls, sig)))
			detail = sig
		}

	case jniRegisterNatives:
		// (clazz, JNINativeMethod* methods, jint count). Record name+sig->fnPtr
		// so we can invoke registered natives (e.g. y2.a for warmup).
		cls := e.derefClass(e.jarg(b, 1))
		methods := e.jarg(b, 2)
		count := e.jarg(b, 3)
		clsName := "?"
		if cls != nil {
			clsName = cls.Name
		}
		for i := uint64(0); i < count && i < 256; i++ {
			ent, _ := b.MemRead(methods+i*24, 24)
			namePtr := le64(ent[0:])
			sigPtr := le64(ent[8:])
			fnPtr := le64(ent[16:])
			name, _ := e.ReadCStr(namePtr)
			sig, _ := e.ReadCStr(sigPtr)
			if cls != nil && !e.vm.Jni().AcceptMethod(e.vm, cls, clsName+"->"+name+sig, false) {
				if e.cfg.Verbose {
					fmt.Printf("[JNI]   reject %s->%s%s\n", clsName, name, sig)
				}
				continue
			}
			key := clsName + "." + name + sig
			e.natives[key] = fnPtr
			if e.cfg.Verbose {
				fmt.Printf("[JNI]   register %s -> 0x%x\n", key, fnPtr)
			}
		}
		detail = fmt.Sprintf("%s count=%d", clsName, count)
		ret = 0

	case jniNewStringUTF:
		s, _ := e.ReadCStr(e.jarg(b, 1))
		ret = uint64(dvm.NewString(e.vm, s))

	case 164: // GetStringLength (UTF-16 units; ASCII approx)
		ret = uint64(len([]rune(e.gstr(e.jarg(b, 1)))))
	case jniGetStringUTFLength:
		ret = uint64(len(e.gstr(e.jarg(b, 1))))
	case jniGetStringUTFChars: // (jstring, jboolean* isCopy) -> char*
		s := e.gstr(e.jarg(b, 1))
		ret = e.WriteScratch(append([]byte(s), 0))
		if cp := e.jarg(b, 2); cp != 0 {
			_ = e.be.MemWrite(cp, []byte{1})
		}
	case jniReleaseStringUTFChrs:
		ret = 0

	case jniGetArrayLength:
		o := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1))))
		if o != nil {
			switch v := o.Value.(type) {
			case []byte:
				ret = uint64(len(v))
			case []*dvm.Object:
				ret = uint64(len(v))
			case []dvm.Ref:
				ret = uint64(len(v))
			}
		}

	case jniNewObjectArray: // (jsize len, jclass elem, jobject init) -> jobjectArray
		n := int(int32(e.jarg(b, 1)))
		initRef := dvm.Ref(int32(e.jarg(b, 3)))
		if n < 0 {
			n = 0
		}
		arr := make([]dvm.Ref, n)
		for i := range arr {
			arr[i] = initRef
		}
		ret = uint64(e.vm.NewObject(e.vm.ResolveClass("[Ljava/lang/Object;"), arr))
	case jniGetObjectArrayElement: // (jobjectArray, jsize idx) -> jobject
		if o := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1)))); o != nil {
			if a, ok := o.Value.([]dvm.Ref); ok {
				if i := int(int32(e.jarg(b, 2))); i >= 0 && i < len(a) {
					ret = uint64(a[i])
				}
			}
		}
	case jniSetObjectArrayElement: // (jobjectArray, jsize idx, jobject val)
		if o := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1)))); o != nil {
			if a, ok := o.Value.([]dvm.Ref); ok {
				if i := int(int32(e.jarg(b, 2))); i >= 0 && i < len(a) {
					a[i] = dvm.Ref(int32(e.jarg(b, 3)))
				}
			}
		}
	case jniNewByteArray:
		ret = uint64(dvm.NewByteArray(e.vm, make([]byte, e.jarg(b, 1))))
	case jniGetByteArrayElements: // (jarray, jboolean* isCopy) -> jbyte*
		data := e.gbytes(e.jarg(b, 1))
		p := e.WriteScratch(data)
		e.arrayPins[p] = dvm.Ref(int32(e.jarg(b, 1)))
		ret = p
		if cp := e.jarg(b, 2); cp != 0 {
			_ = e.be.MemWrite(cp, []byte{1})
		}
	case jniRelByteArrayElements: // (jarray, jbyte* elems, jint mode) — copy back unless JNI_ABORT
		arr, ptr, mode := e.jarg(b, 1), e.jarg(b, 2), e.jarg(b, 3)
		if mode != 2 { // 2 = JNI_ABORT
			if o := e.vm.Deref(dvm.Ref(int32(arr))); o != nil {
				if bs, ok := o.Value.([]byte); ok {
					if d, err := e.be.MemRead(ptr, uint64(len(bs))); err == nil {
						copy(bs, d)
					}
				}
			}
		}
		delete(e.arrayPins, ptr)
	case jniGetByteArrayRegion: // (jarray, start, len, buf)
		data := e.gbytes(e.jarg(b, 1))
		start, ln, buf := e.jarg(b, 2), e.jarg(b, 3), e.jarg(b, 4)
		if int(start+ln) <= len(data) {
			_ = e.be.MemWrite(buf, data[start:start+ln])
		}
	case jniSetByteArrayRegion: // (jarray, start, len, buf)
		o := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1))))
		start, ln, buf := e.jarg(b, 2), e.jarg(b, 3), e.jarg(b, 4)
		if o != nil {
			if bs, ok := o.Value.([]byte); ok && int(start+ln) <= len(bs) {
				if d, err := e.be.MemRead(buf, ln); err == nil {
					copy(bs[start:], d)
				}
			}
		}

	case jniNewGlobalRef, jniNewLocalRef:
		ret = e.jarg(b, 1) // same handle

	case 13, 14: // Throw, ThrowNew -> record a pending exception
		e.pendingExc = true
		detail = "(pending exception set)"
	case jniExceptionCheck: // jboolean
		if e.pendingExc {
			ret = 1
		}
	case jniExceptionOccurred: // jthrowable (non-null handle if pending)
		if e.pendingExc {
			ret = 1
		}
	case jniExceptionClear, jniExceptionDescribe:
		e.pendingExc = false
	case jniDeleteGlobalRef, jniDeleteLocalRef:
		ret = 0

	case 28, 29, 30: // NewObject[V/A](clazz, methodID, ...) -> Jni.NewObjectV, else fresh boxed object
		if cls := e.derefClass(e.jarg(b, 1)); cls != nil {
			sig := cls.Name + "-><init>"
			args := make([]uint64, 8)
			if mr := e.methods[dvm.Ref(int32(e.jarg(b, 2)))]; mr != nil {
				sig = cls.Name + "->" + mr.m.Name + mr.m.Sig
				if idx == 29 { // NewObjectV: va_list at arg3
					args = e.decodeVaList(e.jarg(b, 3), 8)
				} else {
					args = []uint64{e.jarg(b, 3), e.jarg(b, 4), e.jarg(b, 5), e.jarg(b, 6), e.jarg(b, 7)}
				}
			}
			if o := e.vm.Jni().NewObjectV(e.vm, cls, sig, dvm.NewVaList(e.vm, args)); o != nil {
				ret = uint64(e.vm.Box(o))
			} else {
				ret = uint64(e.vm.NewObject(cls, nil))
			}
			detail = sig
		}

	case 217, 218: // MonitorEnter / MonitorExit
		ret = 0

	case 165: // GetStringChars (jstring, isCopy*) -> jchar* (UTF-16LE)
		ret = e.WriteScratch(append(utf16le(e.gstr(e.jarg(b, 1))), 0, 0))
		if cp := e.jarg(b, 2); cp != 0 {
			_ = e.be.MemWrite(cp, []byte{1})
		}
	case 166: // ReleaseStringChars
		ret = 0
	case 220: // GetStringRegion(str, start, len, buf) -> UTF-16LE into buf
		r := []rune(e.gstr(e.jarg(b, 1)))
		start, ln, buf := int(e.jarg(b, 2)), int(e.jarg(b, 3)), e.jarg(b, 4)
		if start >= 0 && start+ln <= len(r) {
			_ = e.be.MemWrite(buf, utf16le(string(r[start:start+ln])))
		}
	case 221: // GetStringUTFRegion(str, start, len, buf) -> UTF-8 into buf
		r := []rune(e.gstr(e.jarg(b, 1)))
		start, ln, buf := int(e.jarg(b, 2)), int(e.jarg(b, 3)), e.jarg(b, 4)
		if start >= 0 && start+ln <= len(r) {
			_ = e.be.MemWrite(buf, append([]byte(string(r[start:start+ln])), 0))
		}

	case jniGetJavaVM:
		// (JNIEnv*, JavaVM** out) -> *out = javaVM, return 0
		_ = putU64(b, e.jarg(b, 1), e.javaVM)
		ret = 0

	case jniIsSameObject:
		if e.jarg(b, 1) == e.jarg(b, 2) {
			ret = 1
		}

	default:
		detail = "(unhandled)"
		ret = 0
	}
	if e.cfg.Verbose { // one line per JNI call — the complete JNI trace
		if detail != "" {
			fmt.Printf("[JNI] %-24s %s -> 0x%x\n", jniLabel(idx), detail, ret)
		} else {
			fmt.Printf("[JNI] %-24s -> 0x%x\n", jniLabel(idx), ret)
		}
	}
	_ = b.RegWrite(emu.RegX0, ret)
}

// callStatic handles CallStaticObjectMethod[V] by dispatching to the Jni
// handler (your dvm.Jni), then boxing the returned object as a guest handle.
// Returns the result handle and a trace detail string.
func (e *Emulator) callStatic(b emu.Backend, isV bool) (uint64, string) {
	cls, sig, va := e.callStaticInfo(b, isV)
	if cls == nil {
		return 0, "<unknown methodID>"
	}
	obj := e.vm.Jni().CallStaticObjectMethodV(e.vm, cls, sig, va)
	if obj == nil {
		return 0, sig
	}
	return uint64(e.vm.Box(obj)), sig
}

// callStaticInfo decodes a static Call<Type>Method[V]: returns the class, the
// "Class->name+sig" key, and the decoded args.
func (e *Emulator) callStaticInfo(b emu.Backend, isV bool) (*dvm.Class, string, *dvm.VaList) {
	mr := e.methods[dvm.Ref(int32(e.jarg(b, 2)))]
	if mr == nil {
		return nil, "", nil
	}
	var args []uint64
	if isV {
		args = e.decodeVaList(e.jarg(b, 3), 8)
	} else {
		args = []uint64{e.jarg(b, 3), e.jarg(b, 4), e.jarg(b, 5), e.jarg(b, 6), e.jarg(b, 7)}
	}
	return mr.cls, mr.cls.Name + "->" + mr.m.Name + mr.m.Sig, dvm.NewVaList(e.vm, args)
}

// fieldInfo decodes an instance field access (obj at arg1, fieldID at arg2)
// into the target object and its "Class->name:Sig" lookup string.
func (e *Emulator) fieldInfo(b emu.Backend) (*dvm.Object, string) {
	obj := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1))))
	fr := e.fields[dvm.Ref(int32(e.jarg(b, 2)))]
	if obj == nil || fr == nil {
		return nil, ""
	}
	return obj, fr.cls.Name + "->" + fr.f.Name + ":" + fr.f.Sig
}

// staticFieldInfo decodes a static field access (class at arg1, fieldID at arg2).
func (e *Emulator) staticFieldInfo(b emu.Backend) (*dvm.Class, string) {
	fr := e.fields[dvm.Ref(int32(e.jarg(b, 2)))]
	if fr == nil {
		return e.derefClass(e.jarg(b, 1)), ""
	}
	return fr.cls, fr.cls.Name + "->" + fr.f.Name + ":" + fr.f.Sig
}

// classAllowed reports whether FindClass should report a class as found. With
// no filter set every class is found; with a filter (SetFoundClassFilter) only
// the listed classes are — mirroring unidbg's addFilterFoundClass.
func (e *Emulator) classAllowed(name string) bool {
	if e.classFilter == nil {
		return true
	}
	return e.classFilter[name]
}

func (e *Emulator) gstr(ref uint64) string {
	if o := e.vm.Deref(dvm.Ref(int32(ref))); o != nil {
		if s, ok := o.Value.(string); ok {
			return s
		}
	}
	return ""
}

func (e *Emulator) gbytes(ref uint64) []byte {
	if o := e.vm.Deref(dvm.Ref(int32(ref))); o != nil {
		if b, ok := o.Value.([]byte); ok {
			return b
		}
	}
	return nil
}

// callInstanceInfo decodes an instance Call<Type>Method[V]: returns the target
// object, the "class->name+sig" key, and the decoded args.
func (e *Emulator) callInstanceInfo(b emu.Backend, isV bool) (*dvm.Object, string, *dvm.VaList) {
	obj := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1))))
	mr := e.methods[dvm.Ref(int32(e.jarg(b, 2)))]
	if obj == nil || mr == nil {
		return nil, "", nil
	}
	var args []uint64
	if isV {
		args = e.decodeVaList(e.jarg(b, 3), 8)
	} else {
		args = []uint64{e.jarg(b, 3), e.jarg(b, 4), e.jarg(b, 5), e.jarg(b, 6), e.jarg(b, 7)}
	}
	return obj, mr.cls.Name + "->" + mr.m.Name + mr.m.Sig, dvm.NewVaList(e.vm, args)
}

// classRef returns (interning) a jclass handle for a class name.
func (e *Emulator) classRef(name string) dvm.Ref {
	if r, ok := e.classRefs[name]; ok {
		return r
	}
	cls := e.vm.ResolveClass(name)
	r := e.vm.NewObject(e.classMeta, cls)
	e.classRefs[name] = r
	return r
}

// derefClass resolves a jclass handle back to its *dvm.Class.
func (e *Emulator) derefClass(ref uint64) *dvm.Class {
	o := e.vm.Deref(dvm.Ref(int32(ref)))
	if o == nil {
		return nil
	}
	if c, ok := o.Value.(*dvm.Class); ok {
		return c
	}
	return nil
}
