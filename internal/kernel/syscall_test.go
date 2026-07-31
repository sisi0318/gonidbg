package kernel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/sisi0318/gonidbg/internal/emu"
)

// memBE is an in-memory emu.Backend (sparse pages) for exercising syscall
// handlers without a CPU engine. lastWrite records the most recent MemWrite so
// a test can assert how many bytes a handler put into guest memory.
type memBE struct {
	pages     map[uint64][]byte
	regs      map[emu.Reg]uint64
	lastWrite int
	// failWritesAfter, when >= 0, makes MemWrite fail once this many calls have
	// succeeded — for exercising the partially-unmapped-destination paths.
	failWritesAfter int
	writes          int
}

func newMemBE() *memBE {
	return &memBE{pages: map[uint64][]byte{}, regs: map[emu.Reg]uint64{}, failWritesAfter: -1}
}

func (m *memBE) page(a uint64) []byte {
	p := a &^ 0xfff
	pg := m.pages[p]
	if pg == nil {
		pg = make([]byte, 0x1000)
		m.pages[p] = pg
	}
	return pg
}
func (m *memBE) MemWrite(addr uint64, data []byte) error {
	if m.failWritesAfter >= 0 && m.writes >= m.failWritesAfter {
		return fmt.Errorf("mem_write @%#x: unmapped", addr)
	}
	m.writes++
	m.lastWrite = len(data)
	for i, b := range data {
		a := addr + uint64(i)
		m.page(a)[a&0xfff] = b
	}
	return nil
}
func (m *memBE) MemRead(addr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range out {
		a := addr + uint64(i)
		out[i] = m.page(a)[a&0xfff]
	}
	return out, nil
}
func (m *memBE) RegRead(r emu.Reg) (uint64, error)       { return m.regs[r], nil }
func (m *memBE) RegWrite(r emu.Reg, v uint64) error      { m.regs[r] = v; return nil }
func (m *memBE) MemMap(uint64, uint64, int) error        { return nil }
func (m *memBE) MemUnmap(uint64, uint64) error           { return nil }
func (m *memBE) MemProtect(uint64, uint64, int) error    { return nil }
func (m *memBE) ReadGPRegs() ([34]uint64, error)         { return [34]uint64{}, nil }
func (m *memBE) Start(uint64, uint64) error              { return nil }
func (m *memBE) StartCount(uint64, uint64, uint64) error { return nil }
func (m *memBE) Stop() error                             { return nil }
func (m *memBE) SaveContext() (emu.CPUContext, error)    { return nil, nil }
func (m *memBE) RestoreContext(emu.CPUContext) error     { return nil }
func (m *memBE) FlushCache() error                       { return nil }
func (m *memBE) Close() error                            { return nil }
func (m *memBE) HookCode(uint64, uint64, emu.CodeHookFunc) (emu.HookHandle, error) {
	return nil, nil
}
func (m *memBE) HookInterrupt(emu.InterruptHookFunc) (emu.HookHandle, error) { return nil, nil }
func (m *memBE) HookMemInvalid(func(emu.Backend, int, uint64, int, int64) bool) (emu.HookHandle, error) {
	return nil, nil
}
func (m *memBE) HookMemRead(uint64, uint64, func(emu.Backend, uint64, int)) (emu.HookHandle, error) {
	return nil, nil
}
func (m *memBE) HookMemWrite(uint64, uint64, func(emu.Backend, uint64, int, int64)) (emu.HookHandle, error) {
	return nil, nil
}

func newCtx(be *memBE) *Context { return &Context{B: be, Pid: 1} }

// TestSysinfoWriteLength pins sizeof(struct sysinfo) on LP64. The handler used
// to write 128 bytes into the 112-byte struct, and bionic's get_nprocs() puts
// that struct on the stack — so the 16-byte overhang landed on the caller's
// stack canary and aborted the guest on every call.
func TestSysinfoWriteLength(t *testing.T) {
	be := newMemBE()
	c := newCtx(be)
	if ret := sysSysinfo(c, [6]uint64{0x40000000}); ret != 0 {
		t.Fatalf("sysinfo returned %d", ret)
	}
	if be.lastWrite != 112 {
		t.Errorf("wrote %d bytes, want 112 (sizeof struct sysinfo on LP64)", be.lastWrite)
	}
}

// TestGetrandomNotPeriodic guards the replaced PRNG. The old stream iterated
// seed = seed*31+7 over a byte; because 31^8 == 1 (mod 256) and the affine sum
// is 128, x8 == x0+128 and x16 == x0 — so any buffer was one 16-byte block
// repeated, and a 16-byte key had only 256 possible values.
func TestGetrandomNotPeriodic(t *testing.T) {
	for _, seed := range []int64{0, 12345} { // 0 = host entropy, else pinned
		be := newMemBE()
		c := newCtx(be)
		c.RandSeed = seed

		const n = 64
		if ret := sysGetrandom(c, [6]uint64{0x40000000, n}); ret != n {
			t.Fatalf("seed %d: getrandom returned %d, want %d", seed, ret, n)
		}
		buf, _ := be.MemRead(0x40000000, n)

		for _, period := range []int{8, 16, 32} {
			for off := 0; off+2*period <= n; off += period {
				a, b := buf[off:off+period], buf[off+period:off+2*period]
				if bytes.Equal(a, b) {
					t.Errorf("seed %d: bytes repeat with period %d at offset %d", seed, period, off)
				}
			}
		}
		if bytes.Count(buf, []byte{0}) > n/4 {
			t.Errorf("seed %d: implausibly many zero bytes: %x", seed, buf)
		}
	}
}

// TestGetrandomPinnedIsReproducible: RandSeed exists so a replay run reproduces
// the guest's nonces, and Restore must rewind the stream for a pooled instance.
func TestGetrandomPinnedIsReproducible(t *testing.T) {
	draw := func(c *Context, be *memBE) []byte {
		if ret := sysGetrandom(c, [6]uint64{0x40000000, 32}); ret != 32 {
			t.Fatalf("getrandom returned %d", ret)
		}
		b, _ := be.MemRead(0x40000000, 32)
		return b
	}

	be1, be2 := newMemBE(), newMemBE()
	c1, c2 := newCtx(be1), newCtx(be2)
	c1.RandSeed, c2.RandSeed = 99, 99
	if a, b := draw(c1, be1), draw(c2, be2); !bytes.Equal(a, b) {
		t.Errorf("same seed gave different streams:\n %x\n %x", a, b)
	}

	// Successive draws must advance, and Restore must rewind to the snapshot.
	be := newMemBE()
	c := newCtx(be)
	c.RandSeed = 7
	first := draw(c, be)
	snap := c.Snapshot()
	second := draw(c, be)
	if bytes.Equal(first, second) {
		t.Error("consecutive draws returned the same bytes; the stream is not advancing")
	}
	c.Restore(snap)
	if got := draw(c, be); !bytes.Equal(got, second) {
		t.Errorf("Restore did not rewind the stream:\n got  %x\n want %x", got, second)
	}
}

// TestCloseRejectsBadFd: close() used to delete a missing key and report
// success, which both masks guest use-after-close and fails the
// `close(-1) == -1 && errno == EBADF` probe anti-emulation code uses.
func TestCloseRejectsBadFd(t *testing.T) {
	c := newCtx(newMemBE())
	for _, fd := range []uint64{4242, ^uint64(0) /* -1 */} {
		if ret := sysClose(c, [6]uint64{fd}); ret != -EBADF {
			t.Errorf("close(%d) = %d, want -EBADF (%d)", int32(fd), ret, -EBADF)
		}
	}
	// stdio is never in the table but is always valid to the guest.
	if ret := sysClose(c, [6]uint64{2}); ret != 0 {
		t.Errorf("close(2) = %d, want 0", ret)
	}
}

// TestWriteRejectsBadFd: same shape — write() to a never-opened fd reported the
// full byte count.
func TestWriteRejectsBadFd(t *testing.T) {
	c := newCtx(newMemBE())
	for _, fd := range []uint64{4242, ^uint64(0) /* -1 */} {
		if ret := sysWrite(c, [6]uint64{fd, 0x40000000, 16}); ret != -EBADF {
			t.Errorf("write(%d,..) = %d, want -EBADF (%d)", int32(fd), ret, -EBADF)
		}
	}
	if ret := sysWrite(c, [6]uint64{1, 0x40000000, 16}); ret != 16 {
		t.Errorf("write(stdout,..) = %d, want 16", ret)
	}
}

// TestFstatStdio: fstat on stdio must succeed — bionic's stdio buffering does
// `if (fstat(2,&st) < 0)` and gives up when it fails — and no stat may report
// st_nlink 0, which marks a deleted inode.
func TestFstatStdio(t *testing.T) {
	be := newMemBE()
	c := newCtx(be)
	if ret := sysFstat(c, [6]uint64{2, 0x40000000}); ret != 0 {
		t.Fatalf("fstat(2) = %d, want 0", ret)
	}
	st, _ := be.MemRead(0x40000000, 128)
	if nlink := binary.LittleEndian.Uint32(st[20:]); nlink == 0 {
		t.Error("st_nlink is 0, which means a deleted inode")
	}
	if ino := binary.LittleEndian.Uint64(st[8:]); ino == 0 {
		t.Error("st_ino is 0, so every file looks like the same file")
	}
	if mode := binary.LittleEndian.Uint32(st[16:]); mode&0xf000 != 0x2000 {
		t.Errorf("st_mode %#x is not S_IFCHR", mode)
	}
	if ret := sysFstat(c, [6]uint64{4242, 0x40000000}); ret != -EBADF {
		t.Errorf("fstat(4242) = %d, want -EBADF", ret)
	}
}

// TestInoDistinguishesPaths: (st_dev, st_ino) dedupe must not collapse two
// different files onto one identity.
func TestInoDistinguishesPaths(t *testing.T) {
	a, b := inoFor("/system/lib64/libc.so"), inoFor("/system/lib64/libm.so")
	if a == b {
		t.Errorf("libc.so and libm.so share inode %d", a)
	}
	if a == 0 || b == 0 {
		t.Error("inode 0 is never valid")
	}
	if inoFor("/x") != inoFor("/x") {
		t.Error("inode is not stable for the same path")
	}
}

// TestReadReportsWriteFault: read() used to advance the file position and
// report success even when the destination write faulted, so the guest believed
// it had bytes it never received.
func TestReadReportsWriteFault(t *testing.T) {
	be := newMemBE()
	c := newCtx(be)
	fd := int32(100)
	c.fdTable()[fd] = &openFile{path: "/x", data: []byte("hello world")}

	be.failWritesAfter = 0
	if ret := sysRead(c, [6]uint64{uint64(fd), 0x40000000, 5}); ret != -EFAULT {
		t.Errorf("read = %d, want -EFAULT (%d)", ret, -EFAULT)
	}
	if pos := c.fdTable()[fd].pos; pos != 0 {
		t.Errorf("file position advanced to %d despite the fault", pos)
	}
}

// TestGetrandomHugeLength: the length is guest-controlled, and the handler used
// to make([]byte, n) with it — a bogus n was an unrecoverable OOM, not an error
// a caller could handle. Now it fills in bounded chunks and stops at the first
// MemWrite failure, so an absurd length costs one chunk and a short count
// rather than a multi-GiB allocation.
func TestGetrandomHugeLength(t *testing.T) {
	be := newMemBE()
	be.failWritesAfter = 1 // let the first chunk land, then fault
	c := newCtx(be)
	c.RandSeed = 1

	ret := sysGetrandom(c, [6]uint64{0x40000000, ^uint64(0)})
	if ret <= 0 {
		t.Fatalf("returned %d, want a short positive count", ret)
	}
	if ret > 1<<20 {
		t.Errorf("returned %d bytes; the handler is not stopping at the first fault", ret)
	}
}

// A destination that is unwritable from the first byte is -EFAULT, as on Linux.
// The old handler discarded the MemWrite error and reported full success.
func TestGetrandomUnwritableDest(t *testing.T) {
	be := newMemBE()
	be.failWritesAfter = 0
	c := newCtx(be)
	c.RandSeed = 1
	if ret := sysGetrandom(c, [6]uint64{0x40000000, 32}); ret != -EFAULT {
		t.Errorf("returned %d, want -EFAULT (%d)", ret, -EFAULT)
	}
}
