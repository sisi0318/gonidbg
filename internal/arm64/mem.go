package arm64

import (
	"encoding/binary"
	"fmt"
)

// Guest memory: 4 KiB pages behind a three-level radix table over a 48-bit
// address space, fronted by small direct-mapped TLBs for the hot load/store
// paths.
//
// Two invariants carry the self-modifying-code handling:
//   - a page whose instructions have been decoded (page.code != nil) is never
//     in the write TLB, so every guest store to it takes the slow path, which
//     drops the decoded instructions;
//   - host writes (MemWrite) drop them too.
//
// So unlike Unicorn, patching code never needs an explicit cache flush.
//
// Page contents are allocated on first write; until then a page reads as
// zeros, which keeps large reservations (the 8 MiB stack, mmap arenas) cheap.

const (
	PageBits = 12
	PageSize = 1 << PageBits
	pageMask = PageSize - 1

	ProtRead  = 1
	ProtWrite = 2
	ProtExec  = 4
	ProtAll   = ProtRead | ProtWrite | ProtExec

	vpnBits = 48 - PageBits
	tlbSize = 256
	tlbMask = tlbSize - 1
	noVPN   = ^uint64(0)
)

// Memory access kinds, numbered like Unicorn's uc_mem_type so hook callbacks
// see the same values on either engine.
const (
	MemRead          = 16
	MemWrite         = 17
	MemFetch         = 18
	MemReadUnmapped  = 19
	MemWriteUnmapped = 20
	MemFetchUnmapped = 21
	MemWriteProt     = 22
	MemReadProt      = 23
	MemFetchProt     = 24
)

var zeroPage [PageSize]byte

type page struct {
	data *[PageSize]byte // nil until first written: reads as zeros
	prot uint8
	code *codePage // decoded instructions, nil until executed
}

type (
	ptL3 [4096]*page
	ptL2 [4096]*ptL3
)

// The zero value of tlbEntry names page 0 with a nil backing array, which
// would nil-dereference on the fast path, so Memory must not be used before
// init has written the noVPN sentinel into every slot. CPU.New and CPU.Release
// are the only places that build one.
type tlbEntry struct {
	vpn  uint64
	data *[PageSize]byte
}

// MemHookFunc observes a valid guest access. value is the data being stored
// (writes only).
type MemHookFunc func(addr uint64, size int, value int64)

// InvalidHookFunc is consulted on an unmapped or protection-violating guest
// access; returning true retries the access once (e.g. after mapping it).
type InvalidHookFunc func(kind int, addr uint64, size int, value int64) bool

type memHook struct {
	begin, end uint64
	fn         MemHookFunc
}

type invalidHook struct{ fn InvalidHookFunc }

// Memory is a guest address space.
type Memory struct {
	l1   [1 << (vpnBits - 24)]*ptL2
	rtlb [tlbSize]tlbEntry
	wtlb [tlbSize]tlbEntry

	// fetch cache: the code page the CPU is executing from (see CPU.Run).
	fetchVPN  uint64
	fetchCode *codePage

	invalid []*invalidHook
	rhooks  []*memHook
	whooks  []*memHook

	pc *uint64 // the CPU's PC, for fault reports
}

func (m *Memory) init(pc *uint64) {
	m.pc = pc
	m.flushTLB()
}

func (m *Memory) flushTLB() {
	for i := range m.rtlb {
		m.rtlb[i].vpn = noVPN
		m.wtlb[i].vpn = noVPN
	}
	m.fetchVPN = noVPN
	m.fetchCode = nil
}

func (m *Memory) lookup(vpn uint64) *page {
	if vpn>>vpnBits != 0 {
		return nil
	}
	l2 := m.l1[vpn>>24]
	if l2 == nil {
		return nil
	}
	l3 := l2[(vpn>>12)&0xfff]
	if l3 == nil {
		return nil
	}
	return l3[vpn&0xfff]
}

func (m *Memory) setPage(vpn uint64, p *page) {
	l2 := m.l1[vpn>>24]
	if l2 == nil {
		if p == nil {
			return
		}
		l2 = new(ptL2)
		m.l1[vpn>>24] = l2
	}
	l3 := l2[(vpn>>12)&0xfff]
	if l3 == nil {
		if p == nil {
			return
		}
		l3 = new(ptL3)
		l2[(vpn>>12)&0xfff] = l3
	}
	l3[vpn&0xfff] = p
}

// rangeVPNs validates a page-aligned [addr, addr+size) range the way Unicorn
// does and returns its first and one-past-last page numbers.
func rangeVPNs(op string, addr, size uint64) (uint64, uint64, error) {
	if size == 0 || addr&pageMask != 0 || size&pageMask != 0 {
		return 0, 0, fmt.Errorf("%s 0x%x+0x%x: not page aligned", op, addr, size)
	}
	end := addr + size
	if end < addr || (end-1)>>48 != 0 {
		return 0, 0, fmt.Errorf("%s 0x%x+0x%x: outside the 48-bit address space", op, addr, size)
	}
	return addr >> PageBits, end >> PageBits, nil
}

// Map maps [addr, addr+size) with prot. Like Unicorn it rejects unaligned
// ranges and any overlap with an existing mapping.
func (m *Memory) Map(addr, size uint64, prot int) error {
	lo, hi, err := rangeVPNs("map", addr, size)
	if err != nil {
		return err
	}
	if prot&^ProtAll != 0 {
		return fmt.Errorf("map 0x%x: bad prot %#x", addr, prot)
	}
	for v := lo; v < hi; v++ {
		if m.lookup(v) != nil {
			return fmt.Errorf("map 0x%x+0x%x: overlaps mapped page 0x%x", addr, size, v<<PageBits)
		}
	}
	for v := lo; v < hi; v++ {
		m.setPage(v, &page{prot: uint8(prot)})
	}
	return nil
}

func (m *Memory) checkMapped(op string, addr, size uint64) (uint64, uint64, error) {
	lo, hi, err := rangeVPNs(op, addr, size)
	if err != nil {
		return 0, 0, err
	}
	for v := lo; v < hi; v++ {
		if m.lookup(v) == nil {
			return 0, 0, fmt.Errorf("%s 0x%x+0x%x: page 0x%x not mapped", op, addr, size, v<<PageBits)
		}
	}
	return lo, hi, nil
}

// Unmap removes [addr, addr+size), which must be fully mapped.
func (m *Memory) Unmap(addr, size uint64) error {
	lo, hi, err := m.checkMapped("unmap", addr, size)
	if err != nil {
		return err
	}
	for v := lo; v < hi; v++ {
		m.setPage(v, nil)
	}
	m.flushTLB()
	return nil
}

// Protect changes the protection of [addr, addr+size), which must be mapped.
func (m *Memory) Protect(addr, size uint64, prot int) error {
	if prot&^ProtAll != 0 {
		return fmt.Errorf("protect 0x%x: bad prot %#x", addr, prot)
	}
	lo, hi, err := m.checkMapped("protect", addr, size)
	if err != nil {
		return err
	}
	for v := lo; v < hi; v++ {
		m.lookup(v).prot = uint8(prot)
	}
	m.flushTLB()
	return nil
}

// Mapped reports whether addr is mapped.
func (m *Memory) Mapped(addr uint64) bool { return m.lookup(addr>>PageBits) != nil }

// writable returns p's backing array, allocating it on first use.
func (m *Memory) writable(vpn uint64, p *page) *[PageSize]byte {
	if p.data == nil {
		p.data = new([PageSize]byte)
		// a read TLB entry may still point at the shared zero page
		if e := &m.rtlb[vpn&tlbMask]; e.vpn == vpn {
			e.vpn = noVPN
		}
	}
	if p.code != nil {
		m.dropCode(vpn, p)
	}
	return p.data
}

func (m *Memory) dropCode(vpn uint64, p *page) {
	p.code = nil
	if m.fetchVPN == vpn {
		m.fetchVPN = noVPN
		m.fetchCode = nil
	}
}

// DropCode discards every decoded instruction (Backend.FlushCache).
func (m *Memory) DropCode() {
	for _, l2 := range m.l1 {
		if l2 == nil {
			continue
		}
		for _, l3 := range l2 {
			if l3 == nil {
				continue
			}
			for _, p := range l3 {
				if p != nil {
					p.code = nil
				}
			}
		}
	}
	m.fetchVPN = noVPN
	m.fetchCode = nil
}

// HostRead copies guest memory into dst, ignoring protection (like
// uc_mem_read). Every touched page must be mapped.
func (m *Memory) HostRead(addr uint64, dst []byte) error {
	if err := m.hostCheck("read", addr, uint64(len(dst))); err != nil {
		return err
	}
	for i := 0; i < len(dst); {
		a := addr + uint64(i)
		off := int(a & pageMask)
		n := min(PageSize-off, len(dst)-i)
		if d := m.lookup(a >> PageBits).data; d != nil {
			copy(dst[i:i+n], d[off:])
		} else {
			clear(dst[i : i+n])
		}
		i += n
	}
	return nil
}

// HostWrite copies src into guest memory, ignoring protection (like
// uc_mem_write). Decoded instructions on the touched pages are dropped.
func (m *Memory) HostWrite(addr uint64, src []byte) error {
	if err := m.hostCheck("write", addr, uint64(len(src))); err != nil {
		return err
	}
	for i := 0; i < len(src); {
		a := addr + uint64(i)
		off := int(a & pageMask)
		n := min(PageSize-off, len(src)-i)
		vpn := a >> PageBits
		copy(m.writable(vpn, m.lookup(vpn))[off:], src[i:i+n])
		i += n
	}
	return nil
}

func (m *Memory) hostCheck(op string, addr, n uint64) error {
	if n == 0 {
		return nil
	}
	if addr+n < addr {
		return fmt.Errorf("mem %s 0x%x+0x%x: wraps", op, addr, n)
	}
	for v := addr >> PageBits; v <= (addr+n-1)>>PageBits; v++ {
		if m.lookup(v) == nil {
			return fmt.Errorf("mem %s 0x%x+0x%x: unmapped at 0x%x", op, addr, n, max(v<<PageBits, addr))
		}
	}
	return nil
}

// ---- guest accesses --------------------------------------------------------

// Fault is a guest memory access the address space could not satisfy.
type Fault struct {
	Kind int // MemReadUnmapped, MemWriteProt, ...
	Addr uint64
	Size int
	PC   uint64
}

func (f *Fault) Error() string {
	what := map[int]string{
		MemReadUnmapped: "read from unmapped", MemWriteUnmapped: "write to unmapped",
		MemFetchUnmapped: "fetch from unmapped", MemReadProt: "read from non-readable",
		MemWriteProt: "write to non-writable", MemFetchProt: "fetch from non-executable",
	}[f.Kind]
	return fmt.Sprintf("%s memory 0x%x (size %d) at pc=0x%x", what, f.Addr, f.Size, f.PC)
}

// guestPage resolves the page for a guest access of kind (MemRead/MemWrite/
// MemFetch), consulting the invalid-access hooks and panicking with *Fault if
// the access cannot proceed.
func (m *Memory) guestPage(kind int, addr uint64, size int, value int64) *page {
	need, unmapped, prot := uint8(ProtRead), MemReadUnmapped, MemReadProt
	switch kind {
	case MemWrite:
		need, unmapped, prot = ProtWrite, MemWriteUnmapped, MemWriteProt
	case MemFetch:
		need, unmapped, prot = ProtExec, MemFetchUnmapped, MemFetchProt
	}
	for retry := 0; ; retry++ {
		p := m.lookup(addr >> PageBits)
		fk := 0
		switch {
		case p == nil:
			fk = unmapped
		case p.prot&need == 0:
			fk = prot
		default:
			return p
		}
		handled := false
		if retry == 0 {
			for _, h := range m.invalid {
				if h.fn(fk, addr, size, value) {
					handled = true
				}
			}
		}
		if !handled {
			panic(&Fault{Kind: fk, Addr: addr, Size: size, PC: *m.pc})
		}
	}
}

func callMemHooks(hs []*memHook, addr uint64, size int, value int64) {
	for _, h := range hs {
		// begin > end means everywhere, matching unicorn's bound check
		if h.begin > h.end || (addr >= h.begin && addr <= h.end) {
			h.fn(addr, size, value)
		}
	}
}

func (m *Memory) readSlow(addr uint64, size int) uint64 {
	off := addr & pageMask
	if off <= PageSize-uint64(size) {
		vpn := addr >> PageBits
		p := m.guestPage(MemRead, addr, size, 0)
		if len(m.rhooks) != 0 {
			callMemHooks(m.rhooks, addr, size, 0)
			// The hook runs arbitrary caller code. It may have written this
			// page for the first time -- in which case the pointer resolved
			// above still aimed at the shared zero page and the read would
			// return a stale zero -- or unmapped or remapped it. Resolve again.
			p = m.guestPage(MemRead, addr, size, 0)
		} else {
			m.rtlb[vpn&tlbMask] = tlbEntry{vpn, pageData(p)}
		}
		return loadN(pageData(p)[off:], size)
	}
	// crosses a page boundary: check both pages before touching anything
	m.guestPage(MemRead, addr, size, 0)
	m.guestPage(MemRead, (addr|pageMask)+1, size, 0)
	if len(m.rhooks) != 0 {
		callMemHooks(m.rhooks, addr, size, 0)
	}
	var v uint64
	for k := 0; k < size; k++ {
		a := addr + uint64(k)
		// A hook may have unmapped one of the pages after both were validated.
		// The access is already in flight, so the byte reads as zero instead
		// of faulting half way through.
		if p := m.lookup(a >> PageBits); p != nil && p.data != nil {
			v |= uint64(p.data[a&pageMask]) << (8 * k)
		}
	}
	return v
}

// pageData is p's backing array, or the shared zero page when p has never been
// written. Never write through the result.
func pageData(p *page) *[PageSize]byte {
	if p.data == nil {
		return &zeroPage
	}
	return p.data
}

func (m *Memory) writeSlow(addr uint64, size int, v uint64) {
	off := addr & pageMask
	if off <= PageSize-uint64(size) {
		vpn := addr >> PageBits
		p := m.guestPage(MemWrite, addr, size, int64(v))
		if len(m.whooks) != 0 {
			callMemHooks(m.whooks, addr, size, int64(v))
			p = m.guestPage(MemWrite, addr, size, int64(v)) // the hook may have remapped it
		}
		data := m.writable(vpn, p)
		if len(m.whooks) == 0 {
			m.wtlb[vpn&tlbMask] = tlbEntry{vpn, data}
		}
		storeN(data[off:], size, v)
		return
	}
	m.guestPage(MemWrite, addr, size, int64(v))
	m.guestPage(MemWrite, (addr|pageMask)+1, size, int64(v))
	if len(m.whooks) != 0 {
		callMemHooks(m.whooks, addr, size, int64(v))
	}
	for k := 0; k < size; k++ {
		a := addr + uint64(k)
		vpn := a >> PageBits
		p := m.lookup(vpn)
		if p == nil { // unmapped by a hook mid-access; drop the byte
			continue
		}
		m.writable(vpn, p)[a&pageMask] = byte(v >> (8 * k))
	}
}

func loadN(b []byte, size int) uint64 {
	switch size {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(b))
	case 4:
		return uint64(binary.LittleEndian.Uint32(b))
	default:
		return binary.LittleEndian.Uint64(b)
	}
}

func storeN(b []byte, size int, v uint64) {
	switch size {
	case 1:
		b[0] = byte(v)
	case 2:
		binary.LittleEndian.PutUint16(b, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(b, uint32(v))
	default:
		binary.LittleEndian.PutUint64(b, v)
	}
}

// Fast paths: a TLB hit on an access that stays inside one page.

func (m *Memory) Read8(a uint64) uint8 {
	if e := &m.rtlb[(a>>PageBits)&tlbMask]; e.vpn == a>>PageBits {
		return e.data[a&pageMask]
	}
	return uint8(m.readSlow(a, 1))
}

func (m *Memory) Read16(a uint64) uint16 {
	if e := &m.rtlb[(a>>PageBits)&tlbMask]; e.vpn == a>>PageBits && a&pageMask <= PageSize-2 {
		return binary.LittleEndian.Uint16(e.data[a&pageMask:])
	}
	return uint16(m.readSlow(a, 2))
}

func (m *Memory) Read32(a uint64) uint32 {
	if e := &m.rtlb[(a>>PageBits)&tlbMask]; e.vpn == a>>PageBits && a&pageMask <= PageSize-4 {
		return binary.LittleEndian.Uint32(e.data[a&pageMask:])
	}
	return uint32(m.readSlow(a, 4))
}

func (m *Memory) Read64(a uint64) uint64 {
	if e := &m.rtlb[(a>>PageBits)&tlbMask]; e.vpn == a>>PageBits && a&pageMask <= PageSize-8 {
		return binary.LittleEndian.Uint64(e.data[a&pageMask:])
	}
	return m.readSlow(a, 8)
}

func (m *Memory) Write8(a uint64, v uint8) {
	if e := &m.wtlb[(a>>PageBits)&tlbMask]; e.vpn == a>>PageBits {
		e.data[a&pageMask] = v
		return
	}
	m.writeSlow(a, 1, uint64(v))
}

func (m *Memory) Write16(a uint64, v uint16) {
	if e := &m.wtlb[(a>>PageBits)&tlbMask]; e.vpn == a>>PageBits && a&pageMask <= PageSize-2 {
		binary.LittleEndian.PutUint16(e.data[a&pageMask:], v)
		return
	}
	m.writeSlow(a, 2, uint64(v))
}

func (m *Memory) Write32(a uint64, v uint32) {
	if e := &m.wtlb[(a>>PageBits)&tlbMask]; e.vpn == a>>PageBits && a&pageMask <= PageSize-4 {
		binary.LittleEndian.PutUint32(e.data[a&pageMask:], v)
		return
	}
	m.writeSlow(a, 4, uint64(v))
}

func (m *Memory) Write64(a uint64, v uint64) {
	if e := &m.wtlb[(a>>PageBits)&tlbMask]; e.vpn == a>>PageBits && a&pageMask <= PageSize-8 {
		binary.LittleEndian.PutUint64(e.data[a&pageMask:], v)
		return
	}
	m.writeSlow(a, 8, v)
}

// ReadN / WriteN take the access size at run time (1, 2, 4 or 8 bytes).
func (m *Memory) ReadN(a uint64, size int) uint64 {
	switch size {
	case 1:
		return uint64(m.Read8(a))
	case 2:
		return uint64(m.Read16(a))
	case 4:
		return uint64(m.Read32(a))
	default:
		return m.Read64(a)
	}
}

func (m *Memory) WriteN(a uint64, size int, v uint64) {
	switch size {
	case 1:
		m.Write8(a, uint8(v))
	case 2:
		m.Write16(a, uint16(v))
	case 4:
		m.Write32(a, uint32(v))
	default:
		m.Write64(a, v)
	}
}

// checkWrite validates a guest store of size bytes at addr without performing
// it, so a multi-part store (pairs, vectors, DC ZVA) can't fault half-way.
func (m *Memory) checkWrite(addr uint64, size int) {
	m.guestPage(MemWrite, addr, size, 0)
	if last := addr + uint64(size) - 1; last>>PageBits != addr>>PageBits {
		m.guestPage(MemWrite, last, size, 0)
	}
}

// ---- hooks -------------------------------------------------------------------

func (m *Memory) AddInvalidHook(fn InvalidHookFunc) func() {
	h := &invalidHook{fn}
	m.invalid = append(m.invalid, h)
	return func() {
		out := make([]*invalidHook, 0, len(m.invalid))
		for _, x := range m.invalid {
			if x != h {
				out = append(out, x)
			}
		}
		m.invalid = out
	}
}

// AddReadHook / AddWriteHook observe valid accesses in [begin, end]
// (begin > end: everywhere). While any is installed, accesses of that kind
// bypass the TLB so every one reaches the hook.
func (m *Memory) AddReadHook(begin, end uint64, fn MemHookFunc) func() {
	h := &memHook{begin, end, fn}
	m.rhooks = append(m.rhooks, h)
	m.flushTLB()
	return func() { m.rhooks = removeHook(m.rhooks, h) }
}

func (m *Memory) AddWriteHook(begin, end uint64, fn MemHookFunc) func() {
	h := &memHook{begin, end, fn}
	m.whooks = append(m.whooks, h)
	m.flushTLB()
	return func() { m.whooks = removeHook(m.whooks, h) }
}

func removeHook(hs []*memHook, h *memHook) []*memHook {
	out := make([]*memHook, 0, len(hs))
	for _, x := range hs {
		if x != h {
			out = append(out, x)
		}
	}
	return out
}
