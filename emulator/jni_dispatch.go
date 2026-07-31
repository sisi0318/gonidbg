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
		// Walk the real Super chain that LoadDex populates; only fall back to
		// Object when a class has no recorded superclass. Returning Object for
		// everything makes an ancestry walk terminate after one hop, so an
		// integrity check looking for a specific ancestor never finds it.
		if cls := e.derefClass(e.jarg(b, 1)); cls != nil {
			switch {
			case cls.Super != nil:
				ret = uint64(e.classRef(cls.Super.Name))
			case cls.Name != "java/lang/Object":
				ret = uint64(e.classRef("java/lang/Object"))
			}
		}

	case 11: // IsAssignableFrom(sub, sup)
		if isAssignable(e.derefClass(e.jarg(b, 1)), e.derefClass(e.jarg(b, 2))) {
			ret = 1
		}
	case 32: // IsInstanceOf(obj, clazz) — NULL is an instance of anything, per JNI
		o := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1))))
		if o == nil {
			ret = 1
		} else if isAssignable(o.Class, e.derefClass(e.jarg(b, 2))) {
			ret = 1
		}

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

	case 114, 115, 116: // CallStaticObjectMethod[V/A]
		ret, detail = e.callStatic(b, modeOf(idx, 114))
	case 129, 130, 131: // CallStaticIntMethod[V/A]
		if cls, sig, va := e.callStaticInfo(b, modeOf(idx, 129)); cls != nil {
			ret = uint64(uint32(e.vm.Jni().CallStaticIntMethodV(e.vm, cls, sig, va)))
			detail = sig
		}
	case 141, 142, 143: // CallStaticVoidMethod[V/A]
		if cls, sig, va := e.callStaticInfo(b, modeOf(idx, 141)); cls != nil {
			e.vm.Jni().CallStaticVoidMethodV(e.vm, cls, sig, va)
			detail = sig
		}

	case 34, 35, 36: // CallObjectMethod[V/A] (instance)
		if obj, sig, va := e.callInstanceInfo(b, modeOf(idx, 34)); obj != nil {
			if o := e.vm.Jni().CallObjectMethodV(e.vm, obj, sig, va); o != nil {
				ret = uint64(e.vm.Box(o))
			}
			detail = sig
		}

	case 37, 38, 39: // CallBooleanMethod[V/A] (instance)
		if obj, sig, va := e.callInstanceInfo(b, modeOf(idx, 37)); obj != nil {
			if e.vm.Jni().CallBooleanMethodV(e.vm, obj, sig, va) {
				ret = 1
			}
			detail = sig
		}
	case 49, 50, 51: // CallIntMethod[V/A] (instance)
		if obj, sig, va := e.callInstanceInfo(b, modeOf(idx, 49)); obj != nil {
			ret = uint64(uint32(e.vm.Jni().CallIntMethodV(e.vm, obj, sig, va)))
			detail = sig
		}
	case 52, 53, 54: // CallLongMethod[V/A] (instance)
		if obj, sig, va := e.callInstanceInfo(b, modeOf(idx, 52)); obj != nil {
			ret = uint64(e.vm.Jni().CallLongMethodV(e.vm, obj, sig, va))
			detail = sig
		}
	case 61, 62, 63: // CallVoidMethod[V/A] (instance)
		if obj, sig, va := e.callInstanceInfo(b, modeOf(idx, 61)); obj != nil {
			e.vm.Jni().CallVoidMethodV(e.vm, obj, sig, va)
			detail = sig
		}

	case 19, 26: // PushLocalFrame, EnsureLocalCapacity -> JNI_OK
		ret = 0
	case 20: // PopLocalFrame(result) -> the result, migrated to the outer frame
		// There are no real local frames here, so the handle survives as-is.
		// Returning 0 instead loses the value in the standard glue idiom
		// `return env->PopLocalFrame(build_result(env));`.
		ret = e.jarg(b, 1)
	case 27: // AllocObject(clazz) -> uninitialised instance
		if cls := e.derefClass(e.jarg(b, 1)); cls != nil {
			ret = uint64(e.vm.NewObject(cls, nil))
		}
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

	// Instance fields. The nine JNI types are laid out contiguously — Object,
	// Boolean, Byte, Char, Short, Int, Long, Float, Double — as getters at
	// 95..103 and setters at 104..112, so one arm covers all of them. Only
	// Object/Int used to be implemented; everything else fell through to the
	// default and returned 0, which breaks the native-peer idiom (SetLongField
	// then GetLongField) with a NULL dereference far from the cause.
	case 95, 96, 97, 98, 99, 100, 101, 102, 103:
		if obj, sig := e.fieldInfo(b); obj != nil {
			ret, detail = e.getField(obj, sig, idx-95), sig
		}
	case 104, 105, 106, 107, 108, 109, 110, 111, 112:
		if obj, sig := e.fieldInfo(b); obj != nil {
			e.setField(obj, sig, idx-104, e.jarg(b, 3))
			detail = sig
		}
	// Static fields: getters 145..153, setters 154..162, same type order.
	case 145, 146, 147, 148, 149, 150, 151, 152, 153:
		if cls, sig := e.staticFieldInfo(b); sig != "" {
			ret, detail = e.getStaticField(cls, sig, idx-145), sig
		}
	case 154, 155, 156, 157, 158, 159, 160, 161, 162:
		if _, sig := e.staticFieldInfo(b); sig != "" {
			e.staticFields[sig] = e.jarg(b, 3)
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
		if n := int64(int32(count)); n < 0 {
			count = 0
		} else {
			count = uint64(n)
		}
		for i := uint64(0); i < count; i++ {
			// MemRead returns (nil, err) on a fault; indexing that panics the
			// host. A bogus count, or a table ending at a mapping boundary, is
			// entirely guest-controlled, so stop rather than crash.
			ent, err := b.MemRead(methods+i*24, 24)
			if err != nil || len(ent) < 24 {
				if e.cfg.Verbose {
					fmt.Printf("[JNI]   RegisterNatives: entry %d unreadable, stopping\n", i)
				}
				break
			}
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

	case 164: // GetStringLength -> UTF-16 code units, not runes
		// A supplementary character is one rune but *two* UTF-16 units. Counting
		// runes under-reports, and the guest then sizes its jchar buffer from
		// this value before calling GetStringRegion.
		ret = uint64(len(utf16.Encode([]rune(e.gstr(e.jarg(b, 1))))))
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
		n := jsize(e.jarg(b, 1))
		initRef := dvm.Ref(int32(e.jarg(b, 3)))
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
		// jsize is a signed 32-bit count. Feeding the raw register to make()
		// turns NewByteArray(env, -1) into a 4 GiB allocation or an unrecoverable
		// makeslice panic. NewObjectArray already clamped; this didn't.
		ret = uint64(dvm.NewByteArray(e.vm, make([]byte, jsize(e.jarg(b, 1)))))
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
		if s, end, ok := jregion(e.jarg(b, 2), e.jarg(b, 3), len(data)); ok {
			_ = e.be.MemWrite(e.jarg(b, 4), data[s:end])
		}
	case jniSetByteArrayRegion: // (jarray, start, len, buf)
		if o := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1)))); o != nil {
			if bs, isB := o.Value.([]byte); isB {
				if s, end, ok := jregion(e.jarg(b, 2), e.jarg(b, 3), len(bs)); ok {
					if d, err := e.be.MemRead(e.jarg(b, 4), uint64(end-s)); err == nil {
						copy(bs[s:end], d)
					}
				}
			}
		}

	case jniNewGlobalRef, jniNewLocalRef, 226: // ...and NewWeakGlobalRef
		ret = e.jarg(b, 1) // same handle

	case 163: // NewString(const jchar* unicode, jsize len) -> jstring
		n := int(int32(e.jarg(b, 2)))
		if n < 0 {
			n = 0
		}
		s := ""
		if raw, err := e.be.MemRead(e.jarg(b, 1), uint64(n)*2); err == nil {
			u := make([]uint16, n)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(raw[i*2:])
			}
			s = string(utf16.Decode(u))
		}
		ret = uint64(dvm.NewString(e.vm, s))

	// Get/ReleasePrimitiveArrayCritical and Get/ReleaseStringCritical. These are
	// the *preferred* zero-copy paths in crypto/hashing natives, and falling
	// through to the default handed the guest a NULL it dereferenced
	// immediately. Same copy-in/copy-out shape as the byte-array variants.
	case 222: // GetPrimitiveArrayCritical(array, isCopy*) -> void*
		data := e.gbytes(e.jarg(b, 1))
		p := e.WriteScratch(data)
		e.arrayPins[p] = dvm.Ref(int32(e.jarg(b, 1)))
		ret = p
		if cp := e.jarg(b, 2); cp != 0 {
			_ = e.be.MemWrite(cp, []byte{0}) // not a copy, as far as the guest knows
		}
	case 223: // ReleasePrimitiveArrayCritical(array, carray, mode)
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
	case 224: // GetStringCritical(str, isCopy*) -> const jchar*
		ret = e.WriteScratch(append(utf16le(e.gstr(e.jarg(b, 1))), 0, 0))
		if cp := e.jarg(b, 2); cp != 0 {
			_ = e.be.MemWrite(cp, []byte{0})
		}
	case 225, 227: // ReleaseStringCritical, DeleteWeakGlobalRef
		ret = 0

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
				args = e.callArgs(b, modeOf(idx, 28), 3)
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
	// GetString[UTF]Region index in UTF-16 code units, per the JNI spec — not in
	// runes. Indexing runes and then re-encoding emitted two units for each
	// supplementary character, writing 2 bytes past a buffer the guest had sized
	// from GetStringLength and corrupting its heap header.
	case 220: // GetStringRegion(str, start, len, buf) -> UTF-16LE into buf
		u := utf16.Encode([]rune(e.gstr(e.jarg(b, 1))))
		if s, end, ok := jregion(e.jarg(b, 2), e.jarg(b, 3), len(u)); ok {
			out := make([]byte, (end-s)*2)
			for i, c := range u[s:end] {
				binary.LittleEndian.PutUint16(out[i*2:], c)
			}
			_ = e.be.MemWrite(e.jarg(b, 4), out)
		}
	case 221: // GetStringUTFRegion(str, start, len, buf) -> UTF-8 into buf
		u := utf16.Encode([]rune(e.gstr(e.jarg(b, 1))))
		if s, end, ok := jregion(e.jarg(b, 2), e.jarg(b, 3), len(u)); ok {
			_ = e.be.MemWrite(e.jarg(b, 4), append([]byte(string(utf16.Decode(u[s:end]))), 0))
		}

	case jniGetJavaVM:
		// (JNIEnv*, JavaVM** out) -> *out = javaVM, return 0
		_ = putU64(b, e.jarg(b, 1), e.javaVM)
		ret = 0

	case jniIsSameObject:
		// Compare identity, not handle: Box mints a fresh handle every time the
		// same *Object comes back from a Jni handler, so a tamper check that
		// caches a jobject and re-fetches it would otherwise always see "these
		// differ" and take its environment-was-swapped branch.
		a, c := e.jarg(b, 1), e.jarg(b, 2)
		oa, oc := e.vm.Deref(dvm.Ref(int32(a))), e.vm.Deref(dvm.Ref(int32(c)))
		if a == c || (oa != nil && oa == oc) {
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
func (e *Emulator) callStatic(b emu.Backend, mode callMode) (uint64, string) {
	cls, sig, va := e.callStaticInfo(b, mode)
	if cls == nil {
		return 0, "<unknown methodID>"
	}
	obj := e.vm.Jni().CallStaticObjectMethodV(e.vm, cls, sig, va)
	if obj == nil {
		return 0, sig
	}
	return uint64(e.vm.Box(obj)), sig
}

// callMode says how a Call<Type>Method variant passes its arguments. The three
// forms always occupy consecutive JNIEnv slots: plain (registers), V (a
// va_list*), A (a jvalue[]). The A forms used to be lumped in with the plain
// ones, so the jvalue pointer itself was decoded as the first argument and the
// rest came from stale callee registers — a handler then ran on garbage and
// returned a plausible, wrong answer with nothing logged.
type callMode int

const (
	modeDirect callMode = iota
	modeV
	modeA
)

// modeOf maps a Call<Type>Method slot to its argument form, given the slot of
// the plain variant.
func modeOf(idx, base int) callMode { return callMode(idx - base) }

// callArgs decodes the argument list for a call in the given form. argPtr is
// the JNIEnv argument index holding the va_list / jvalue array (or the first
// value argument in the plain form).
func (e *Emulator) callArgs(b emu.Backend, mode callMode, argPtr int) []uint64 {
	switch mode {
	case modeV:
		return e.decodeVaList(e.jarg(b, argPtr), 8)
	case modeA:
		return e.decodeJValues(e.jarg(b, argPtr), 8)
	default:
		out := make([]uint64, 0, 8-argPtr)
		for i := argPtr; i <= 7; i++ {
			out = append(out, e.jarg(b, i))
		}
		return out
	}
}

// decodeJValues reads up to n 8-byte jvalue slots from a const jvalue* array.
// Read one slot at a time: MemRead is all-or-nothing, and a real array is
// usually shorter than the 8 slots we speculatively want.
func (e *Emulator) decodeJValues(p uint64, n int) []uint64 {
	out := make([]uint64, n)
	if p == 0 {
		return out
	}
	for i := 0; i < n; i++ {
		v, err := e.be.MemRead(p+uint64(i)*8, 8)
		if err != nil {
			break
		}
		out[i] = le64(v)
	}
	return out
}

// callStaticInfo decodes a static Call<Type>Method[V/A]: returns the class, the
// "Class->name+sig" key, and the decoded args.
func (e *Emulator) callStaticInfo(b emu.Backend, mode callMode) (*dvm.Class, string, *dvm.VaList) {
	mr := e.methods[dvm.Ref(int32(e.jarg(b, 2)))]
	if mr == nil {
		return nil, "", nil
	}
	args := e.callArgs(b, mode, 3)
	return mr.cls, mr.cls.Name + "->" + mr.m.Name + mr.m.Sig, dvm.NewVaList(e.vm, args)
}

// maxJArray caps a guest-supplied array length. jsize is a signed 32-bit count,
// so a negative or absurd value reaching make() is either an unrecoverable
// makeslice panic or a multi-GiB allocation — from one guest register.
const maxJArray = 1 << 26 // 64 Mi elements

// jsize narrows a raw register to a sane, non-negative JNI array length.
func jsize(raw uint64) int {
	n := int(int32(raw))
	if n < 0 {
		return 0
	}
	if n > maxJArray {
		return maxJArray
	}
	return n
}

// jregion decodes a (start, len) array/string region pair against a container
// of length n, reporting whether it is wholly in bounds. Both come straight
// from guest registers, so the arithmetic is done in int64 to keep a large or
// negative value from wrapping past the bounds check and panicking the host.
func jregion(rawStart, rawLen uint64, n int) (start, end int, ok bool) {
	s, l := int64(int32(rawStart)), int64(int32(rawLen))
	if s < 0 || l < 0 || s+l > int64(n) {
		return 0, 0, false
	}
	return int(s), int(s + l), true
}

// isAssignable reports whether sub is target or descends from it, walking the
// Super chain LoadDex records. Everything is assignable to java/lang/Object.
//
// This used to be hard-coded true, which sends type-dispatch glue
// (`if (IsInstanceOf(o, String)) ... else if (IsInstanceOf(o, byte[])) ...`)
// down the first branch unconditionally. An unknown class errs on the side of
// true so a host that hasn't modelled its hierarchy keeps the old behaviour.
func isAssignable(sub, target *dvm.Class) bool {
	if sub == nil || target == nil {
		return true
	}
	if target.Name == "java/lang/Object" {
		return true
	}
	for c, depth := sub, 0; c != nil && depth < 64; c, depth = c.Super, depth+1 {
		if c.Name == target.Name {
			return true
		}
	}
	// A nil Super means no ancestry was ever recorded for sub (no DEX loaded),
	// so "no" would be a guess. Only answer no when we actually walked a chain.
	return sub.Super == nil
}

// JNI field type kinds, in the order the JNINativeInterface lays them out
// (getters 95..103 / 145..153, setters 104..112 / 154..162).
const (
	fkObject = iota
	fkBoolean
	fkByte
	fkChar
	fkShort
	fkInt
	fkLong
	fkFloat
	fkDouble
)

// narrowField truncates a raw 64-bit field value to the width the JNI type
// returns in X0. Object/Long/Float/Double are already full-width.
func narrowField(v uint64, kind int) uint64 {
	switch kind {
	case fkBoolean:
		if v&0xff != 0 {
			return 1
		}
		return 0
	case fkByte:
		return uint64(uint32(int32(int8(v))))
	case fkChar:
		return uint64(uint16(v))
	case fkShort:
		return uint64(uint32(int32(int16(v))))
	case fkInt:
		return uint64(uint32(v))
	}
	return v
}

// getField reads an instance field. A value the guest itself wrote wins; only
// when there is none do we ask the Jni handler, so a host still gets to model
// fields the guest only ever reads.
func (e *Emulator) getField(obj *dvm.Object, sig string, kind int) uint64 {
	if v, ok := obj.Field(sig); ok {
		raw, _ := v.(uint64)
		return narrowField(raw, kind)
	}
	switch kind {
	case fkObject:
		if o := e.vm.Jni().GetObjectField(e.vm, obj, sig); o != nil {
			return uint64(e.vm.Box(o))
		}
	case fkBoolean:
		if e.vm.Jni().GetBooleanField(e.vm, obj, sig) {
			return 1
		}
	case fkLong:
		return uint64(e.vm.Jni().GetLongField(e.vm, obj, sig))
	case fkByte, fkChar, fkShort, fkInt:
		return narrowField(uint64(uint32(e.vm.Jni().GetIntField(e.vm, obj, sig))), kind)
	}
	return 0
}

// setField records an instance field write so a later get reads it back, and
// still notifies the Jni handler for object fields (hosts observe those).
func (e *Emulator) setField(obj *dvm.Object, sig string, kind int, raw uint64) {
	obj.SetField(sig, raw)
	if kind == fkObject {
		e.vm.Jni().SetObjectField(e.vm, obj, sig, e.vm.Deref(dvm.Ref(int32(raw))))
	}
}

// getStaticField mirrors getField for static fields. Static writes live in an
// emulator-level map that Snapshot/Restore rewinds — dvm.Class is deliberately
// never rewound, so storing them there would leak state between pooled calls.
func (e *Emulator) getStaticField(cls *dvm.Class, sig string, kind int) uint64 {
	if raw, ok := e.staticFields[sig]; ok {
		return narrowField(raw, kind)
	}
	switch kind {
	case fkObject:
		if o := e.vm.Jni().GetStaticObjectField(e.vm, cls, sig); o != nil {
			return uint64(e.vm.Box(o))
		}
	case fkLong:
		return uint64(e.vm.Jni().GetStaticLongField(e.vm, cls, sig))
	case fkBoolean, fkByte, fkChar, fkShort, fkInt:
		return narrowField(uint64(uint32(e.vm.Jni().GetStaticIntField(e.vm, cls, sig))), kind)
	}
	return 0
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
func (e *Emulator) callInstanceInfo(b emu.Backend, mode callMode) (*dvm.Object, string, *dvm.VaList) {
	obj := e.vm.Deref(dvm.Ref(int32(e.jarg(b, 1))))
	mr := e.methods[dvm.Ref(int32(e.jarg(b, 2)))]
	if obj == nil || mr == nil {
		return nil, "", nil
	}
	args := e.callArgs(b, mode, 3)
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
