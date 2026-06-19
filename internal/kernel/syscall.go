// Package kernel emulates the Linux ARM64 syscall interface reached via the
// SVC instruction. The CPU backend's interrupt hook calls Dispatch, which
// reads x8 (syscall number) + x0..x5 (args) and writes the result back to x0 —
// exactly what unidbg's ARM64SyscallHandler does.
//
// the target .so does not issue syscalls directly; the *bionic libc* we
// emulate does, on its behalf. So the set that actually fires is "whatever
// libc.so/libm.so touch during JNI_OnLoad + the target call" — a few dozen, not
// the full table. Numbers below are the AArch64 (asm-generic) ABI.
package kernel

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/sisi0318/gonidbg/internal/emu"
	"github.com/sisi0318/gonidbg/internal/memory"
	"github.com/sisi0318/gonidbg/internal/vfs"
)

// BrkBase is the guest program-break heap origin (clear of modules/mmap arena).
const BrkBase = 0x30000000

// AArch64 syscall numbers (asm-generic unistd). Only the ones unidbg's handler
// implements / that bionic is likely to invoke on the call path are listed.
const (
	SYS_getcwd          = 17
	SYS_mkdirat         = 34
	SYS_ioctl           = 29
	SYS_faccessat       = 48
	SYS_openat          = 56
	SYS_close           = 57
	SYS_pipe2           = 59
	SYS_getdents64      = 61
	SYS_lseek           = 62
	SYS_read            = 63
	SYS_write           = 64
	SYS_writev          = 66
	SYS_pread64         = 67
	SYS_ppoll           = 73
	SYS_readlinkat      = 78
	SYS_newfstatat      = 79
	SYS_fstat           = 80
	SYS_exit            = 93
	SYS_exit_group      = 94
	SYS_set_tid_address = 96
	SYS_futex           = 98
	SYS_set_robust_list = 99
	SYS_nanosleep       = 101
	SYS_clock_gettime   = 113
	SYS_gettimeofday    = 169
	SYS_sched_yield     = 124
	SYS_kill            = 129
	SYS_rt_sigaction    = 134
	SYS_rt_sigprocmask  = 135
	SYS_rt_sigtimedwait = 137
	SYS_tgkill          = 131
	SYS_uname           = 160
	SYS_getpid          = 172
	SYS_getppid         = 173
	SYS_getuid          = 174
	SYS_geteuid         = 175
	SYS_gettid          = 178
	SYS_sysinfo         = 179
	SYS_brk             = 214
	SYS_munmap          = 215
	SYS_mremap          = 216
	SYS_clone           = 220
	SYS_mmap            = 222
	SYS_mprotect        = 226
	SYS_madvise         = 233
	SYS_prctl           = 167
	SYS_prlimit64       = 261
	SYS_getrandom       = 278
	SYS_statx           = 291
	// sockets (bionic on android routes these as real syscalls)
	SYS_socket  = 198
	SYS_connect = 203
)

// errno values (negated on return per Linux convention).
const (
	ENOSYS = 38
	EPERM  = 1
	EBADF  = 9
	ENOENT = 2
)

// Context is the state a syscall handler operates on.
type Context struct {
	B       emu.Backend
	Mem     *memory.Space
	VFS     *vfs.VFS
	Pid     int
	Verbose bool

	brkCur   uint64 // current program break (0 = uninitialized)
	Exited   bool   // guest called exit/exit_group
	ExitCode int

	files  map[int32]*openFile
	nextFd int32
	wfiles map[string][]byte // writable in-memory FS overlay (e.g. /mssdk/ml/*)
	dirs   map[string]bool   // directories created via mkdirat
}

type openFile struct {
	path     string
	data     []byte // read-only snapshot (VFS files)
	pos      int64
	writable bool // backed by Context.wfiles[path]
}

func (c *Context) fdTable() map[int32]*openFile {
	if c.files == nil {
		c.files = map[int32]*openFile{}
		c.nextFd = 100
	}
	return c.files
}

// Handler implements one syscall. args are x0..x5. Return value goes to x0
// (negative = -errno).
type Handler func(c *Context, args [6]uint64) int64

// table maps syscall number -> handler. Unimplemented numbers fall through to
// a logged ENOSYS, which is how you discover the next syscall to implement when
// bringing a new .so up.
var table = map[uint64]Handler{
	SYS_getpid:        func(c *Context, _ [6]uint64) int64 { return int64(c.Pid) },
	SYS_getppid:       func(c *Context, _ [6]uint64) int64 { return 1 },
	SYS_gettid:        func(c *Context, _ [6]uint64) int64 { return int64(c.Pid) },
	SYS_getuid:        func(c *Context, _ [6]uint64) int64 { return 10000 },
	SYS_geteuid:       func(c *Context, _ [6]uint64) int64 { return 10000 },
	SYS_sched_yield:   func(c *Context, _ [6]uint64) int64 { return 0 },
	SYS_set_tid_address: func(c *Context, _ [6]uint64) int64 { return int64(c.Pid) },
	SYS_set_robust_list: func(c *Context, _ [6]uint64) int64 { return 0 },
	SYS_rt_sigaction:  func(c *Context, _ [6]uint64) int64 { return 0 },
	SYS_rt_sigprocmask: func(c *Context, _ [6]uint64) int64 { return 0 },
	SYS_prctl:         func(c *Context, _ [6]uint64) int64 { return 0 },
	SYS_madvise:       func(c *Context, _ [6]uint64) int64 { return 0 },

	SYS_mmap:     sysMmap,
	SYS_munmap:   sysMunmap,
	SYS_mprotect: sysMprotect,

	SYS_exit:       sysExit,
	SYS_exit_group: sysExit,

	// The remaining ones below need full implementations (memory + vfs + clock).
	// They are intentionally left as TODO stubs so an un-implemented call is
	// loud rather than silently wrong.
	SYS_brk:           sysBrk,
	SYS_openat:        sysOpenat,
	SYS_close:         sysClose,
	SYS_read:          sysRead,
	SYS_write:         sysWrite,
	SYS_writev:        sysWritev,
	SYS_readlinkat:    todo("readlinkat"),
	SYS_newfstatat:    sysNewfstatat,
	SYS_fstat:         sysFstat,
	SYS_faccessat:     sysFaccessat,
	SYS_mkdirat:       sysMkdirat,
	SYS_lseek:         sysLseek,
	SYS_getdents64:    todo("getdents64"),
	SYS_clock_gettime: sysClockGettime,
	SYS_gettimeofday:  sysGettimeofday,
	SYS_uname:         todo("uname"),
	SYS_sysinfo:       todo("sysinfo"),
	SYS_getrandom:     sysGetrandom,
	SYS_prlimit64:     todo("prlimit64"),
	SYS_futex:         sysFutex,
	SYS_ioctl:         todo("ioctl"),
	SYS_statx:         todo("statx"),
}

// Names is the reverse map for tracing.
var Names = map[uint64]string{
	SYS_getcwd: "getcwd", SYS_ioctl: "ioctl", SYS_faccessat: "faccessat",
	SYS_openat: "openat", SYS_close: "close", SYS_getdents64: "getdents64",
	SYS_lseek: "lseek", SYS_read: "read", SYS_write: "write", SYS_writev: "writev",
	SYS_pread64: "pread64", SYS_ppoll: "ppoll", SYS_readlinkat: "readlinkat",
	SYS_newfstatat: "newfstatat", SYS_fstat: "fstat", SYS_exit: "exit",
	SYS_exit_group: "exit_group", SYS_set_tid_address: "set_tid_address",
	SYS_futex: "futex", SYS_set_robust_list: "set_robust_list",
	SYS_clock_gettime: "clock_gettime", SYS_uname: "uname", SYS_getpid: "getpid",
	SYS_getppid: "getppid", SYS_getuid: "getuid", SYS_geteuid: "geteuid",
	SYS_gettid: "gettid", SYS_sysinfo: "sysinfo", SYS_brk: "brk",
	SYS_munmap: "munmap", SYS_mremap: "mremap", SYS_mmap: "mmap",
	SYS_mprotect: "mprotect", SYS_madvise: "madvise", SYS_prctl: "prctl",
	SYS_prlimit64: "prlimit64", SYS_getrandom: "getrandom", SYS_statx: "statx",
	SYS_socket: "socket", SYS_connect: "connect", SYS_rt_sigaction: "rt_sigaction",
	SYS_rt_sigprocmask: "rt_sigprocmask", SYS_sched_yield: "sched_yield",
}

// Dispatch reads the syscall number + args from the backend, runs the handler,
// and writes the result to x0. Register it via Backend.HookInterrupt.
func (c *Context) Dispatch() {
	num, _ := c.B.RegRead(emu.RegX8)
	var args [6]uint64
	for i, r := range []emu.Reg{emu.RegX0, emu.RegX1, emu.RegX2, emu.RegX3, emu.RegX4, emu.RegX5} {
		args[i], _ = c.B.RegRead(r)
	}
	h, ok := table[num]
	var ret int64
	if !ok || h == nil {
		if c.Verbose {
			fmt.Printf("[syscall] UNIMPLEMENTED #%d (%s) args=%v\n", num, Names[num], args)
		}
		ret = -ENOSYS
	} else {
		ret = h(c, args)
	}
	c.B.RegWrite(emu.RegX0, uint64(ret))
}

const mapFixed = 0x10

func sysMmap(c *Context, a [6]uint64) int64 {
	// addr, length, prot, flags, fd, offset
	hint := a[0]
	length := pageUp(a[1])
	prot := int(a[2])
	flags := a[3]
	var addr uint64
	if flags&mapFixed != 0 && hint != 0 {
		addr = hint &^ 0xfff
		c.Mem.Munmap(addr, length) // drop any prior mapping under MAP_FIXED
		_ = c.Mem.Map(addr, length, prot, "mmap-fixed")
		c.B.MemUnmap(addr, length)
	} else {
		addr = c.Mem.Mmap(length, prot, "mmap")
	}
	if err := c.B.MemMap(addr, length, prot|emu.ProtRead); err != nil {
		return -ENOSYS
	}
	return int64(addr)
}

// sysWrite/sysWritev capture the .so's own log output (it logs to fd 1/2 and
// to logd before bailing) — invaluable for seeing why it exits.
func sysWrite(c *Context, a [6]uint64) int64 {
	fd, buf, n := a[0], a[1], a[2]
	// writable file fd -> store into the overlay
	if f := c.fdTable()[int32(fd)]; f != nil && f.writable {
		d, err := c.B.MemRead(buf, n)
		if err != nil {
			return -EBADF
		}
		w := c.wstore()
		cur := w[f.path]
		end := f.pos + int64(len(d))
		if int64(len(cur)) < end {
			nb := make([]byte, end)
			copy(nb, cur)
			cur = nb
		}
		copy(cur[f.pos:end], d)
		w[f.path] = cur
		f.pos = end
		return int64(len(d))
	}
	// otherwise it's stdout/stderr/log -> surface it only when tracing
	if c.Verbose && n > 0 && n < 0x10000 {
		if d, err := c.B.MemRead(buf, n); err == nil {
			fmt.Printf("[write fd=%d] %s\n", fd, string(d))
		}
	}
	return int64(n)
}

func sysWritev(c *Context, a [6]uint64) int64 {
	fd, iov, cnt := a[0], a[1], a[2]
	wf := c.fdTable()[int32(fd)]
	total := int64(0)
	for i := uint64(0); i < cnt && i < 64; i++ {
		ent, err := c.B.MemRead(iov+i*16, 16)
		if err != nil {
			break
		}
		base := binary.LittleEndian.Uint64(ent[0:])
		ln := binary.LittleEndian.Uint64(ent[8:])
		if ln == 0 || ln >= 0x10000 {
			continue
		}
		d, err := c.B.MemRead(base, ln)
		if err != nil {
			continue
		}
		if wf != nil && wf.writable { // append to the writable file overlay
			w := c.wstore()
			w[wf.path] = append(w[wf.path], d...)
			wf.pos += int64(len(d))
		} else if c.Verbose {
			fmt.Printf("[writev fd=%d] %s\n", fd, string(d))
		}
		total += int64(ln)
	}
	return total
}

// readCStr reads a NUL-terminated guest string (for path args).
func (c *Context) readCStr(addr uint64) string {
	var out []byte
	for i := 0; i < 4096; i++ {
		b, err := c.B.MemRead(addr+uint64(len(out)), 1)
		if err != nil || b[0] == 0 {
			break
		}
		out = append(out, b[0])
	}
	return string(out)
}

// open flags (asm-generic).
const (
	oWRONLY = 0x1
	oRDWR   = 0x2
	oCREAT  = 0x40
	oTRUNC  = 0x200
	oAPPEND = 0x400
)

func (c *Context) wstore() map[string][]byte {
	if c.wfiles == nil {
		c.wfiles = map[string][]byte{}
	}
	return c.wfiles
}

func sysOpenat(c *Context, a [6]uint64) int64 {
	path := c.readCStr(a[1])
	flags := a[2]
	t := c.fdTable()
	fd := c.nextFd

	if flags&(oWRONLY|oRDWR|oCREAT) != 0 { // writable
		w := c.wstore()
		if _, ok := w[path]; !ok || flags&oTRUNC != 0 {
			w[path] = nil
		}
		of := &openFile{path: path, writable: true}
		if flags&oAPPEND != 0 {
			of.pos = int64(len(w[path]))
		}
		c.nextFd++
		t[fd] = of
		if c.Verbose {
			fmt.Printf("[openat:w] %q -> fd=%d\n", path, fd)
		}
		return int64(fd)
	}

	data, err := c.VFS.Read(path)
	if err != nil {
		if w, ok := c.wstore()[path]; ok { // previously written file
			data = w
		} else {
			if c.Verbose {
				fmt.Printf("[openat] %q -> ENOENT\n", path)
			}
			return -ENOENT
		}
	}
	c.nextFd++
	t[fd] = &openFile{path: path, data: data}
	if c.Verbose {
		fmt.Printf("[openat] %q -> fd=%d (%d bytes)\n", path, fd, len(data))
	}
	return int64(fd)
}

func (c *Context) fileData(f *openFile) []byte {
	if f.writable {
		return c.wstore()[f.path]
	}
	return f.data
}

func sysRead(c *Context, a [6]uint64) int64 {
	f := c.fdTable()[int32(a[0])]
	if f == nil {
		return -EBADF
	}
	data := c.fileData(f)
	n := int64(a[2])
	if rem := int64(len(data)) - f.pos; n > rem {
		n = rem
	}
	if n <= 0 {
		return 0
	}
	c.B.MemWrite(a[1], data[f.pos:f.pos+n])
	f.pos += n
	return n
}

func sysClose(c *Context, a [6]uint64) int64 {
	delete(c.fdTable(), int32(a[0]))
	return 0
}

func sysMkdirat(c *Context, a [6]uint64) int64 {
	path := c.readCStr(a[1])
	if c.dirs == nil {
		c.dirs = map[string]bool{}
	}
	c.dirs[path] = true
	if c.Verbose {
		fmt.Printf("[mkdirat] %q -> 0\n", path)
	}
	return 0
}

func sysLseek(c *Context, a [6]uint64) int64 {
	f := c.fdTable()[int32(a[0])]
	if f == nil {
		return -EBADF
	}
	off, whence := int64(a[1]), a[2]
	switch whence {
	case 0: // SEEK_SET
		f.pos = off
	case 1: // SEEK_CUR
		f.pos += off
	case 2: // SEEK_END
		f.pos = int64(len(c.fileData(f))) + off
	}
	return f.pos
}

func sysFaccessat(c *Context, a [6]uint64) int64 {
	path := c.readCStr(a[1])
	if c.VFS.Exists(path) || c.dirs[path] {
		return 0
	}
	if _, ok := c.wstore()[path]; ok {
		return 0
	}
	return -ENOENT
}

// writeStat fills a Linux arm64 `struct stat` (128 bytes).
func writeStat(c *Context, addr uint64, size int64, isDir bool) {
	var st [128]byte
	mode := uint32(0x81a4) // S_IFREG|0644
	if isDir {
		mode = 0x41ed // S_IFDIR|0755
	}
	binary.LittleEndian.PutUint32(st[16:], mode)                   // st_mode
	binary.LittleEndian.PutUint64(st[48:], uint64(size))           // st_size
	binary.LittleEndian.PutUint32(st[56:], 0x1000)                 // st_blksize
	binary.LittleEndian.PutUint64(st[64:], uint64((size+511)/512)) // st_blocks
	c.B.MemWrite(addr, st[:])
}

func sysFstat(c *Context, a [6]uint64) int64 {
	f := c.fdTable()[int32(a[0])]
	if f == nil {
		return -EBADF
	}
	writeStat(c, a[1], int64(len(c.fileData(f))), false)
	return 0
}

func sysNewfstatat(c *Context, a [6]uint64) int64 {
	path := c.readCStr(a[1])
	if c.dirs[path] {
		writeStat(c, a[2], 4096, true)
		if c.Verbose {
			fmt.Printf("[newfstatat] %q -> dir\n", path)
		}
		return 0
	}
	var size int64 = -1
	if data, err := c.VFS.Read(path); err == nil {
		size = int64(len(data))
	} else if w, ok := c.wstore()[path]; ok {
		size = int64(len(w))
	}
	if size < 0 {
		if c.Verbose {
			fmt.Printf("[newfstatat] %q -> ENOENT\n", path)
		}
		return -ENOENT
	}
	writeStat(c, a[2], size, false)
	if c.Verbose {
		fmt.Printf("[newfstatat] %q -> size=%d\n", path, size)
	}
	return 0
}

func sysFutex(c *Context, a [6]uint64) int64 {
	op := a[1] & 0x7f
	if c.Verbose {
		name := map[uint64]string{0: "WAIT", 1: "WAKE", 9: "WAKE_OP", 6: "WAIT_BITSET", 7: "WAKE_BITSET"}[op]
		fmt.Printf("[futex] uaddr=0x%x op=%d(%s) val=%d\n", a[0], op, name, a[2])
	}
	return 0
}

func sysExit(c *Context, a [6]uint64) int64 {
	c.Exited = true
	c.ExitCode = int(int32(a[0]))
	fmt.Printf("[syscall] exit_group(%d) — guest requested exit; stopping\n", c.ExitCode)
	_ = c.B.Stop()
	return 0
}

func sysBrk(c *Context, a [6]uint64) int64 {
	if c.brkCur == 0 {
		c.brkCur = BrkBase
	}
	want := a[0]
	if want == 0 || want < BrkBase {
		return int64(c.brkCur)
	}
	if hi, lo := pageUp(want), pageUp(c.brkCur); hi > lo {
		if err := c.B.MemMap(lo, hi-lo, emu.ProtRead|emu.ProtWrite); err != nil {
			return int64(c.brkCur)
		}
	}
	c.brkCur = want
	return int64(want)
}

func sysClockGettime(c *Context, a [6]uint64) int64 {
	now := time.Now()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:], uint64(now.Unix()))
	binary.LittleEndian.PutUint64(b[8:], uint64(now.Nanosecond()))
	c.B.MemWrite(a[1], b[:])
	return 0
}

func sysGettimeofday(c *Context, a [6]uint64) int64 {
	now := time.Now()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:], uint64(now.Unix()))
	binary.LittleEndian.PutUint64(b[8:], uint64(now.Nanosecond()/1000)) // usec
	c.B.MemWrite(a[0], b[:])
	return 0
}

// sysGetrandom fills the buffer with a deterministic-ish stream (good enough for
// emulation; not cryptographically meaningful here).
func sysGetrandom(c *Context, a [6]uint64) int64 {
	n := a[1]
	buf := make([]byte, n)
	seed := byte(a[0] ^ n)
	for i := range buf {
		seed = seed*31 + 7
		buf[i] = seed
	}
	c.B.MemWrite(a[0], buf)
	return int64(n)
}

func sysMunmap(c *Context, a [6]uint64) int64 {
	c.Mem.Munmap(a[0], a[1])
	c.B.MemUnmap(a[0], pageUp(a[1]))
	return 0
}

func sysMprotect(c *Context, a [6]uint64) int64 {
	// Page-granular protect on the backend; mem.Space bookkeeping is best-effort
	// (bionic protects sub-ranges of larger mappings, e.g. thread stack guards).
	_ = c.Mem.Protect(a[0], a[1], int(a[2]))
	if err := c.B.MemProtect(a[0]&^0xfff, pageUp(a[1]), int(a[2])); err != nil {
		return -EPERM
	}
	return 0
}

func todo(name string) Handler {
	return func(c *Context, _ [6]uint64) int64 {
		if c.Verbose {
			fmt.Printf("[syscall] TODO %s -> stub 0\n", name)
		}
		return 0 // optimistic stub; replace with a real impl when it matters
	}
}

func pageUp(x uint64) uint64 { return (x + 0xfff) &^ 0xfff }
