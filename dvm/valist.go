package dvm

// VaList is the decoded variadic argument list passed to Call*MethodV. The
// JNIEnv trampoline decodes guest registers/stack into this; handlers read it
// positionally, exactly like unidbg's VaList.getIntArg(i) etc.
type VaList struct {
	vm   *VM
	args []uint64
}

func NewVaList(vm *VM, args []uint64) *VaList { return &VaList{vm: vm, args: args} }

func (v *VaList) GetIntArg(i int) int32 {
	if i < 0 || i >= len(v.args) {
		return 0
	}
	return int32(uint32(v.args[i]))
}

func (v *VaList) GetLongArg(i int) int64 {
	if i < 0 || i >= len(v.args) {
		return 0
	}
	return int64(v.args[i])
}

// GetObjectArg resolves an argument that is a guest object handle.
func (v *VaList) GetObjectArg(i int) *Object {
	if i < 0 || i >= len(v.args) {
		return nil
	}
	return v.vm.Deref(Ref(int32(v.args[i])))
}

// GetStringArg is a convenience for string-typed object args.
func (v *VaList) GetStringArg(i int) string {
	o := v.GetObjectArg(i)
	if o == nil {
		return ""
	}
	if s, ok := o.Value.(string); ok {
		return s
	}
	return ""
}
