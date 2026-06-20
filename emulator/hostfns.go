package emulator

import (
	"fmt"

	"github.com/sisi0318/gonidbg/internal/emu"
)

// registerHostFns registers libc functions we implement in Go because bionic's
// versions need a fully bootstrapped libc (which we don't run). They override
// the real bionic exports during symbol resolution. Add more here as the .so
// exercises libc internals (e.g. __system_property_get, pthread_once, ...).
func registerHostFns(e *Emulator) {
	// AT_RANDOM target: 16 bytes used by stack-guard / canary setup.
	e.atRandom = e.Alloc(16, emu.ProtRead|emu.ProtWrite)
	_ = e.be.MemWrite(e.atRandom, []byte("gonidbg-randseed"))

	e.hostByName["getauxval"] = hostGetauxval

	// pthread_create can't run a real thread (we can't nest uc_emu_start), so we
	// no-op it as success. Threads the .so spawns (watchdogs / bg init) are
	// skipped; revisit if the call path needs a thread's output.
	e.hostByName["pthread_create"] = hostPthreadCreate
	e.hostByName["pthread_join"] = hostRet0
	e.hostByName["pthread_detach"] = hostRet0

	// __system_property_get: only override (for the loaded .so) when the host app
	// supplies a provider; otherwise leave it to the bundled /dev/__properties__.
	if e.cfg.PropertyProvider != nil {
		e.hostByName["__system_property_get"] = hostSystemPropertyGet
	}
}

// hostSystemPropertyGet implements __system_property_get(name, value) via
// Config.PropertyProvider: write the value (NUL-terminated, PROP_VALUE_MAX-1)
// and return its length, or 0 when the provider doesn't supply the key.
func hostSystemPropertyGet(e *Emulator, b emu.Backend) {
	namePtr, _ := b.RegRead(emu.RegX0)
	buf, _ := b.RegRead(emu.RegX1)
	name, _ := e.ReadCStr(namePtr)
	v, ok := e.cfg.PropertyProvider(name)
	if !ok {
		if buf != 0 {
			_ = e.be.MemWrite(buf, []byte{0})
		}
		_ = b.RegWrite(emu.RegX0, 0)
		return
	}
	if len(v) > 91 { // PROP_VALUE_MAX (92) minus the NUL
		v = v[:91]
	}
	if buf != 0 {
		_ = e.be.MemWrite(buf, append([]byte(v), 0))
	}
	_ = b.RegWrite(emu.RegX0, uint64(len(v)))
}

// hostPthreadCreate(thread*, attr, start, arg) registers the start routine as a
// scheduler fiber (its own stack + CPU context) and returns success with a fake
// tid. We can't run guest threads concurrently, so the fiber runs cooperatively
// later, when RunThreads drives the scheduler (see scheduler.go).
func hostPthreadCreate(e *Emulator, b emu.Backend) {
	thr, _ := b.RegRead(emu.RegX0)
	routine, _ := b.RegRead(emu.RegX2)
	arg, _ := b.RegRead(emu.RegX3)
	f := e.newFiber(routine, arg)
	if e.cfg.Verbose {
		fmt.Printf("[pthread_create] fiber %d routine=0x%x (%s) arg=0x%x\n", f.id, routine, e.NearestSym(routine), arg)
	}
	if thr != 0 {
		_ = putU64(b, thr, uint64(0x7300|f.id)) // fake pthread_t (distinct per fiber)
	}
	_ = b.RegWrite(emu.RegX0, 0)
}

func hostRet0(e *Emulator, b emu.Backend) { _ = b.RegWrite(emu.RegX0, 0) }

// hostGetauxval implements getauxval(type) without bionic's __libc_auxv.
func hostGetauxval(e *Emulator, b emu.Backend) {
	t, _ := b.RegRead(emu.RegX0)
	var v uint64
	switch t {
	case 6: // AT_PAGESZ
		v = 0x1000
	case 16: // AT_HWCAP  (0 = advertise no optional CPU features)
		v = 0
	case 26: // AT_HWCAP2
		v = 0
	case 23: // AT_SECURE
		v = 0
	case 25: // AT_RANDOM -> pointer to 16 random bytes
		v = e.atRandom
	default:
		v = 0
	}
	_ = b.RegWrite(emu.RegX0, v)
}
