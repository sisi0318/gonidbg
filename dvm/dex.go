package dvm

import (
	"encoding/binary"
	"fmt"
	"os"
)

// DEX (Dalvik EXecutable) metadata loader. It parses a classes.dex and
// registers its classes, methods, and fields into the VM, so FindClass /
// GetMethodID / GetFieldID resolve against real APK metadata (with correct
// signatures and superclasses) instead of being synthesized on demand. This is
// metadata only — gonidbg does not execute DEX bytecode (no JVM); you still
// model behavior with a dvm.Jni handler. Analogous to unidbg loading a DexClass.

const dexNoIndex = 0xffffffff

// LoadDexFile parses a .dex file and registers its classes/methods/fields.
// Returns the number of class definitions found.
func (vm *VM) LoadDexFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return vm.LoadDex(data)
}

// LoadDex parses raw .dex bytes and registers classes/methods/fields.
func (vm *VM) LoadDex(d []byte) (n int, err error) {
	defer func() { // malformed input -> error, never panic
		if r := recover(); r != nil {
			err = fmt.Errorf("dex: malformed (%v)", r)
		}
	}()
	if len(d) < 112 || string(d[0:4]) != "dex\n" {
		return 0, fmt.Errorf("dex: bad magic")
	}
	le := binary.LittleEndian
	u32 := func(off uint32) uint32 { return le.Uint32(d[off:]) }

	stringIdsOff := u32(60)
	typeIdsOff := u32(68)
	protoIdsOff := u32(76)
	fieldIdsSize, fieldIdsOff := u32(80), u32(84)
	methodIdsSize, methodIdsOff := u32(88), u32(92)
	classDefsSize, classDefsOff := u32(96), u32(100)

	// uleb128 decode at p, returns value + next position.
	uleb := func(p uint32) (uint32, uint32) {
		var v uint32
		var shift uint
		for {
			b := d[p]
			p++
			v |= uint32(b&0x7f) << shift
			if b&0x80 == 0 {
				break
			}
			shift += 7
		}
		return v, p
	}
	// string by id (string_data_item: uleb size + MUTF-8, NUL-terminated).
	str := func(idx uint32) string {
		off := u32(stringIdsOff + idx*4)
		_, p := uleb(off) // skip utf16 length
		start := p
		for d[p] != 0 {
			p++
		}
		return string(d[start:p]) // MUTF-8 ~= UTF-8 for identifier text
	}
	typeDesc := func(typeIdx uint32) string { return str(u32(typeIdsOff + typeIdx*4)) }
	// "Lpkg/Class;" -> "pkg/Class"; primitives/arrays kept as-is.
	descToName := func(s string) string {
		if len(s) > 2 && s[0] == 'L' && s[len(s)-1] == ';' {
			return s[1 : len(s)-1]
		}
		return s
	}
	// proto -> JNI signature "(params)ret" (raw descriptors, as JNI expects).
	protoSig := func(protoIdx uint32) string {
		base := protoIdsOff + protoIdx*12
		retIdx := u32(base + 4)
		paramsOff := u32(base + 8)
		sig := "("
		if paramsOff != 0 {
			cnt := u32(paramsOff)
			for i := uint32(0); i < cnt; i++ {
				ti := uint32(le.Uint16(d[paramsOff+4+i*2:]))
				sig += typeDesc(ti)
			}
		}
		return sig + ")" + typeDesc(retIdx)
	}

	// Register every referenced method, grouped by its defining class.
	for i := uint32(0); i < methodIdsSize; i++ {
		base := methodIdsOff + i*8
		clsIdx := uint32(le.Uint16(d[base:]))
		protoIdx := uint32(le.Uint16(d[base+2:]))
		nameIdx := u32(base + 4)
		cls := vm.ResolveClass(descToName(typeDesc(clsIdx)))
		cls.MethodID(vm, str(nameIdx), protoSig(protoIdx), false)
	}
	// Register every referenced field, grouped by its defining class.
	for i := uint32(0); i < fieldIdsSize; i++ {
		base := fieldIdsOff + i*8
		clsIdx := uint32(le.Uint16(d[base:]))
		typeIdx := uint32(le.Uint16(d[base+2:]))
		nameIdx := u32(base + 4)
		cls := vm.ResolveClass(descToName(typeDesc(clsIdx)))
		cls.FieldID(vm, str(nameIdx), typeDesc(typeIdx), false)
	}
	// Class defs carry the superclass relationship.
	for i := uint32(0); i < classDefsSize; i++ {
		base := classDefsOff + i*32
		clsIdx := u32(base)
		superIdx := u32(base + 8)
		cls := vm.ResolveClass(descToName(typeDesc(clsIdx)))
		if superIdx != dexNoIndex {
			cls.Super = vm.ResolveClass(descToName(typeDesc(superIdx)))
		}
	}
	return int(classDefsSize), nil
}
