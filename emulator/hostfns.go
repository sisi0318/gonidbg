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
}

// hostPthreadCreate(thread*, attr, start, arg) -> write fake tid, return 0.
func hostPthreadCreate(e *Emulator, b emu.Backend) {
	thr, _ := b.RegRead(emu.RegX0)
	routine, _ := b.RegRead(emu.RegX2)
	arg, _ := b.RegRead(emu.RegX3)
	if e.cfg.Verbose {
		fmt.Printf("[pthread_create] routine=0x%x (%s) arg=0x%x\n", routine, e.NearestSym(routine), arg)
	}
	if thr != 0 {
		_ = putU64(b, thr, 0x7355) // fake pthread_t
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
