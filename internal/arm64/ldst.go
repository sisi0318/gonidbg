package arm64

// ---- loads and stores ------------------------------------------------------

// Addressing modes, kept in inst.cond.
const (
	modeOff  = 0 // base + imm
	modePre  = 1 // base + imm, writeback
	modePost = 2 // base, writeback base + imm
	modeReg  = 3 // base + extend(Rm) << amt
)

// Value extension applied to an integer load, kept in inst.sh.
const (
	extZero   = 0 // zero-extend to 64
	extSign   = 1 // sign-extend to 64
	extSign32 = 2 // sign-extend within 32, upper half zero
)

func decodeLdSt(in *inst, raw uint32, pc uint64) {
	switch {
	case raw&0x3f000000 == 0x08000000: // load/store exclusive
		decodeExclusive(in, raw)
	case raw&0x3b000000 == 0x18000000: // LDR (literal), integer and SIMD&FP
		decodeLiteral(in, raw, pc)
	case raw&0x38000000 == 0x28000000: // load/store pair
		decodePair(in, raw)
	case raw&0x3b000000 == 0x38000000: // register, unscaled / indexed / register offset
		if (raw>>21)&1 == 1 && (raw>>10)&3 == 0 {
			decodeAtomic(in, raw)
			return
		}
		decodeRegForm(in, raw)
	case raw&0x3b000000 == 0x39000000: // register, unsigned immediate
		decodeUnsignedImm(in, raw)
	case raw&0xbf000000 == 0x0c000000: // AdvSIMD load/store multiple structures
		// Bit 23 selects the post-index variant, so it must stay out of the
		// mask; bits 29:24 (001100) are what identify the group.
		decodeSIMDMulti(in, raw)
	}
}

// ldstKind resolves the size (bytes) and extension of an integer or vector
// load/store from size:opc. ok is false for unallocated encodings; prfm marks
// PRFM, which this CPU treats as a NOP.
func ldstKind(size, opc uint32, vec bool) (bytes int, ext uint8, load, prfm, ok bool) {
	if vec {
		if opc&2 != 0 { // 128-bit, only with size == 00
			if size != 0 {
				return
			}
			return 16, extZero, opc&1 == 1, false, true
		}
		return 1 << size, extZero, opc&1 == 1, false, true
	}
	switch opc {
	case 0:
		return 1 << size, extZero, false, false, true
	case 1:
		return 1 << size, extZero, true, false, true
	case 2:
		if size == 3 {
			return 0, 0, false, true, true // PRFM
		}
		return 1 << size, extSign, true, false, true
	default:
		if size >= 2 {
			return // LDRSW (32-bit dest) and size 11 are unallocated here
		}
		return 1 << size, extSign32, true, false, true
	}
}

func decodeRegForm(in *inst, raw uint32) {
	size, vec, opc := raw>>30, (raw>>26)&1 == 1, (raw>>22)&3
	bytes, ext, load, prfm, ok := ldstKind(size, opc, vec)
	if !ok {
		return
	}
	in.rn = xsp(raw >> 5)
	in.sz, in.sh = uint8(bytes), ext

	if (raw>>21)&1 == 1 { // register offset
		if (raw>>10)&3 != 2 {
			return
		}
		option := (raw >> 13) & 7
		if option&2 == 0 { // only [X|W]{,S}XT{W,X}: option 010,011,110,111
			return
		}
		in.cond = modeReg
		in.rm = xr(raw >> 16)
		in.sh = ext
		in.ra = uint8(option)
		if (raw>>12)&1 == 1 {
			in.amt = uint8(size)
			if vec && opc&2 != 0 {
				in.amt = 4
			}
		}
	} else {
		switch (raw >> 10) & 3 {
		case 2: // LDTR/STTR: no SIMD&FP and no prefetch variant exists
			if vec || prfm {
				return
			}
			in.cond = modeOff
		case 0: // LDUR/STUR/PRFUM
			in.cond = modeOff
		case 1:
			if prfm {
				return // PRFM has no writeback form
			}
			in.cond = modePost
		case 3:
			if prfm {
				return
			}
			in.cond = modePre
		}
		in.imm = sext(uint64((raw>>12)&0x1ff), 9)
	}
	if prfm {
		in.fn = opNop
		return
	}
	in.setLdSt(raw, vec, load)
}

func decodeUnsignedImm(in *inst, raw uint32) {
	size, vec, opc := raw>>30, (raw>>26)&1 == 1, (raw>>22)&3
	bytes, ext, load, prfm, ok := ldstKind(size, opc, vec)
	if !ok {
		return
	}
	scale := size
	if vec && opc&2 != 0 {
		scale = 4
	}
	in.rn = xsp(raw >> 5)
	in.sz, in.sh = uint8(bytes), ext
	in.cond = modeOff
	in.imm = uint64((raw>>10)&0xfff) << scale
	if prfm {
		in.fn = opNop
		return
	}
	in.setLdSt(raw, vec, load)
}

// setLdSt picks the handler for an already-classified register load/store.
func (in *inst) setLdSt(raw uint32, vec, load bool) {
	if vec {
		in.rd = uint8(raw & 31)
	} else if load {
		in.rd = xw(raw)
	} else {
		in.rd = xr(raw)
	}
	switch {
	case vec && load:
		in.fn = [4]func(*CPU, *inst){opVLoadOff, opVLoadWb, opVLoadWb, opVLoadReg}[in.cond]
	case vec:
		in.fn = [4]func(*CPU, *inst){opVStoreOff, opVStoreWb, opVStoreWb, opVStoreReg}[in.cond]
	case load:
		in.fn = [4]func(*CPU, *inst){opLoadOff, opLoadWb, opLoadWb, opLoadReg}[in.cond]
	default:
		in.fn = [4]func(*CPU, *inst){opStoreOff, opStoreWb, opStoreWb, opStoreReg}[in.cond]
	}
}

func decodeLiteral(in *inst, raw uint32, pc uint64) {
	opc, vec := raw>>30, (raw>>26)&1 == 1
	addr := pc + sext(uint64((raw>>5)&0x7ffff)<<2, 21)
	in.imm, in.cond = addr, modeOff
	in.rn = rZR // literal addressing has no base register
	switch {
	case vec:
		if opc > 2 {
			return
		}
		in.sz, in.rd = uint8(4<<opc), uint8(raw&31)
		in.fn = opVLoadOff
	case opc == 3:
		in.fn = opNop // PRFM (literal)
	default:
		in.sz, in.rd = []uint8{4, 8, 4}[opc], xw(raw)
		if opc == 2 {
			in.sh = extSign // LDRSW
		}
		in.fn = opLoadOff
	}
}

func decodePair(in *inst, raw uint32) {
	opc, vec, l := raw>>30, (raw>>26)&1 == 1, (raw>>22)&1 == 1
	if opc == 3 || (vec && opc == 2 && false) {
		return
	}
	var bytes int
	if vec {
		if opc > 2 {
			return
		}
		bytes = 4 << opc
	} else {
		switch opc {
		case 0:
			bytes = 4
		case 1: // LDPSW (load only)
			if !l {
				return
			}
			bytes = 4
			in.sh = extSign
		case 2:
			bytes = 8
		}
	}
	scale := 2
	for 1<<scale < bytes {
		scale++
	}
	switch (raw >> 23) & 3 {
	case 0: // STNP/LDNP: no allocate, otherwise identical
		if !vec && opc == 1 {
			return // there is no non-temporal LDPSW
		}
		in.cond = modeOff
	case 1:
		in.cond = modePost
	case 2:
		in.cond = modeOff
	case 3:
		in.cond = modePre
	}
	in.imm = sext(uint64((raw>>15)&0x7f), 7) << scale
	in.rn = xsp(raw >> 5)
	in.sz = uint8(bytes)
	if vec {
		in.rd, in.ra = uint8(raw&31), uint8((raw>>10)&31)
	} else if l {
		in.rd, in.ra = xw(raw), xw(raw>>10)
	} else {
		in.rd, in.ra = xr(raw), xr(raw>>10)
	}
	switch {
	case vec && l:
		in.fn = opVLoadPair
	case vec:
		in.fn = opVStorePair
	case l:
		in.fn = opLoadPair
	default:
		in.fn = opStorePair
	}
}

// addrOff/addrReg compute the effective address; writeback is applied after
// the access so a fault leaves the base register untouched.
func (c *CPU) addrFor(i *inst) uint64 {
	if i.cond == modePost {
		return c.R[i.rn]
	}
	return c.R[i.rn] + i.imm
}

func (c *CPU) writeback(i *inst, addr uint64) {
	switch i.cond {
	case modePre:
		c.R[i.rn] = addr
	case modePost:
		c.R[i.rn] = addr + i.imm
	}
}

func (c *CPU) ldInt(i *inst, addr uint64) {
	v := c.Mem.ReadN(addr, int(i.sz))
	switch i.sh {
	case extSign:
		v = sext(v, uint(i.sz)*8)
	case extSign32:
		v = uint64(uint32(sext(v, uint(i.sz)*8)))
	}
	c.R[i.rd] = v
}

func opLoadOff(c *CPU, i *inst) {
	c.ldInt(i, c.R[i.rn]+i.imm)
	c.PC += 4
}

func opLoadWb(c *CPU, i *inst) {
	addr := c.addrFor(i)
	c.ldInt(i, addr)
	c.writeback(i, addr)
	c.PC += 4
}

func opLoadReg(c *CPU, i *inst) {
	c.ldInt(i, c.R[i.rn]+extend(c.R[i.rm], i.ra)<<i.amt)
	c.PC += 4
}

func opStoreOff(c *CPU, i *inst) {
	c.Mem.WriteN(c.R[i.rn]+i.imm, int(i.sz), c.R[i.rd])
	c.PC += 4
}

func opStoreWb(c *CPU, i *inst) {
	addr := c.addrFor(i)
	c.Mem.WriteN(addr, int(i.sz), c.R[i.rd])
	c.writeback(i, addr)
	c.PC += 4
}

func opStoreReg(c *CPU, i *inst) {
	c.Mem.WriteN(c.R[i.rn]+extend(c.R[i.rm], i.ra)<<i.amt, int(i.sz), c.R[i.rd])
	c.PC += 4
}

// vector loads/stores zero the unwritten high lanes, as the architecture
// requires for every SIMD&FP destination write.
func (c *CPU) vLoad(i *inst, addr uint64) {
	if i.sz == 16 {
		c.Mem.guestPage(MemRead, addr, 16, 0)
		c.V[i.rd] = Vec{c.Mem.Read64(addr), c.Mem.Read64(addr + 8)}
		return
	}
	c.V[i.rd] = Vec{c.Mem.ReadN(addr, int(i.sz)), 0}
}

func (c *CPU) vStore(i *inst, addr uint64) {
	if i.sz == 16 {
		c.Mem.checkWrite(addr, 16)
		c.Mem.Write64(addr, c.V[i.rd][0])
		c.Mem.Write64(addr+8, c.V[i.rd][1])
		return
	}
	c.Mem.WriteN(addr, int(i.sz), c.V[i.rd][0])
}

func opVLoadOff(c *CPU, i *inst) {
	c.vLoad(i, c.R[i.rn]+i.imm)
	c.PC += 4
}

func opVLoadWb(c *CPU, i *inst) {
	addr := c.addrFor(i)
	c.vLoad(i, addr)
	c.writeback(i, addr)
	c.PC += 4
}

func opVLoadReg(c *CPU, i *inst) {
	c.vLoad(i, c.R[i.rn]+extend(c.R[i.rm], i.ra)<<i.amt)
	c.PC += 4
}

func opVStoreOff(c *CPU, i *inst) {
	c.vStore(i, c.R[i.rn]+i.imm)
	c.PC += 4
}

func opVStoreWb(c *CPU, i *inst) {
	addr := c.addrFor(i)
	c.vStore(i, addr)
	c.writeback(i, addr)
	c.PC += 4
}

func opVStoreReg(c *CPU, i *inst) {
	c.vStore(i, c.R[i.rn]+extend(c.R[i.rm], i.ra)<<i.amt)
	c.PC += 4
}

func opLoadPair(c *CPU, i *inst) {
	addr := c.addrFor(i)
	n := int(i.sz)
	c.Mem.guestPage(MemRead, addr, 2*n, 0)
	v1 := c.Mem.ReadN(addr, n)
	v2 := c.Mem.ReadN(addr+uint64(n), n)
	if i.sh == extSign {
		v1, v2 = sext(v1, uint(n)*8), sext(v2, uint(n)*8)
	}
	c.R[i.rd], c.R[i.ra] = v1, v2
	c.writeback(i, addr)
	c.PC += 4
}

func opStorePair(c *CPU, i *inst) {
	addr := c.addrFor(i)
	n := int(i.sz)
	c.Mem.checkWrite(addr, 2*n)
	c.Mem.WriteN(addr, n, c.R[i.rd])
	c.Mem.WriteN(addr+uint64(n), n, c.R[i.ra])
	c.writeback(i, addr)
	c.PC += 4
}

func opVLoadPair(c *CPU, i *inst) {
	addr := c.addrFor(i)
	n := uint64(i.sz)
	c.Mem.guestPage(MemRead, addr, int(2*n), 0)
	if n == 16 {
		c.V[i.rd] = Vec{c.Mem.Read64(addr), c.Mem.Read64(addr + 8)}
		c.V[i.ra] = Vec{c.Mem.Read64(addr + 16), c.Mem.Read64(addr + 24)}
	} else {
		c.V[i.rd] = Vec{c.Mem.ReadN(addr, int(n)), 0}
		c.V[i.ra] = Vec{c.Mem.ReadN(addr+n, int(n)), 0}
	}
	c.writeback(i, addr)
	c.PC += 4
}

func opVStorePair(c *CPU, i *inst) {
	addr := c.addrFor(i)
	n := uint64(i.sz)
	c.Mem.checkWrite(addr, int(2*n))
	if n == 16 {
		c.Mem.Write64(addr, c.V[i.rd][0])
		c.Mem.Write64(addr+8, c.V[i.rd][1])
		c.Mem.Write64(addr+16, c.V[i.ra][0])
		c.Mem.Write64(addr+24, c.V[i.ra][1])
	} else {
		c.Mem.WriteN(addr, int(n), c.V[i.rd][0])
		c.Mem.WriteN(addr+n, int(n), c.V[i.ra][0])
	}
	c.writeback(i, addr)
	c.PC += 4
}

// ---- exclusives and atomics ------------------------------------------------

func decodeExclusive(in *inst, raw uint32) {
	size := raw >> 30
	o2, l, o1 := (raw>>23)&1, (raw>>22)&1, (raw>>21)&1
	in.rn = xsp(raw >> 5)
	in.sz = uint8(1 << size)

	switch {
	case o2 == 1 && o1 == 1: // CAS, CASA, CASL, CASAL
		if !featLSE || (raw>>10)&31 != 31 {
			return
		}
		in.rd, in.rm = xr(raw), xr(raw>>16) // Rt = new value, Rs = compare value
		in.ra = xw(raw >> 16)               // Rs is written back with the old value
		in.fn = opCas
	case o2 == 1 && o1 == 0: // STLR / LDAR
		// o0 == 0 selects STLLR/LDLAR, which need FEAT_LOR.
		if (raw>>15)&1 == 0 || (raw>>16)&31 != 31 || (raw>>10)&31 != 31 {
			return
		}
		if l == 1 {
			in.rd, in.cond, in.sh = xw(raw), modeOff, extZero
			in.fn = opLoadOff
		} else {
			in.rd, in.cond = xr(raw), modeOff
			in.fn = opStoreOff
		}
	case o1 == 0: // LDXR/LDAXR, STXR/STLXR
		if (raw>>10)&31 != 31 {
			return
		}
		if l == 1 {
			if (raw>>16)&31 != 31 {
				return
			}
			in.rd = xw(raw)
			in.fn = opLdxr
		} else {
			in.rd, in.ra = xr(raw), xw(raw>>16)
			in.fn = opStxr
		}
	default: // LDXP/LDAXP, STXP/STLXP
		if size < 2 {
			return
		}
		if l == 1 {
			if (raw>>16)&31 != 31 {
				return
			}
			in.rd, in.rm = xw(raw), xw(raw>>10)
			in.fn = opLdxp
		} else {
			in.rd, in.rm, in.ra = xr(raw), xr(raw>>10), xw(raw>>16)
			in.fn = opStxp
		}
	}
}

func opLdxr(c *CPU, i *inst) {
	addr := c.R[i.rn]
	v := c.Mem.ReadN(addr, int(i.sz))
	c.R[i.rd] = v
	c.exclAddr, c.exclVal, c.exclSize, c.exclValid = addr, v, int(i.sz), true
	c.PC += 4
}

func opLdxp(c *CPU, i *inst) {
	addr := c.R[i.rn]
	n := int(i.sz)
	c.Mem.guestPage(MemRead, addr, 2*n, 0)
	v1 := c.Mem.ReadN(addr, n)
	v2 := c.Mem.ReadN(addr+uint64(n), n)
	c.R[i.rd], c.R[i.rm] = v1, v2
	c.exclAddr, c.exclVal, c.exclVal2, c.exclSize, c.exclValid = addr, v1, v2, 2*n, true
	c.PC += 4
}

// Single hardware thread: a store-exclusive succeeds whenever it pairs with a
// load-exclusive to the same address and size, and fails otherwise (which is
// what makes a CLREX-then-STXR sequence report failure like real hardware).
// A failed store-exclusive performs no memory access, so it cannot fault even
// if the address is unmapped — verified against unicorn.
func (c *CPU) exclusiveOK(addr uint64, size int) bool {
	ok := c.exclValid && c.exclAddr == addr && c.exclSize == size
	c.exclValid = false
	return ok
}

func opStxr(c *CPU, i *inst) {
	addr := c.R[i.rn]
	if c.exclusiveOK(addr, int(i.sz)) {
		c.Mem.WriteN(addr, int(i.sz), c.R[i.rd])
		c.R[i.ra] = 0
	} else {
		c.R[i.ra] = 1
	}
	c.PC += 4
}

func opStxp(c *CPU, i *inst) {
	addr := c.R[i.rn]
	n := int(i.sz)
	if c.exclusiveOK(addr, 2*n) {
		c.Mem.checkWrite(addr, 2*n)
		c.Mem.WriteN(addr, n, c.R[i.rd])
		c.Mem.WriteN(addr+uint64(n), n, c.R[i.rm])
		c.R[i.ra] = 0
	} else {
		c.R[i.ra] = 1
	}
	c.PC += 4
}

func opCas(c *CPU, i *inst) {
	addr := c.R[i.rn]
	old := c.Mem.ReadN(addr, int(i.sz))
	cmp := c.R[i.rm]
	if i.sz < 8 {
		cmp &= 1<<(8*uint(i.sz)) - 1
	}
	if old == cmp {
		c.Mem.WriteN(addr, int(i.sz), c.R[i.rd])
	}
	c.R[i.ra] = old
	c.PC += 4
}

// LSE read-modify-write atomics (LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/
// LDUMAX/LDUMIN and SWP), including their ST* aliases (Rt == XZR).
// featLSE reports whether the modeled CPU has FEAT_LSE. Unicorn — the engine
// this interpreter is validated against — models a CPU without it, so the
// large-system atomics are undefined instructions there. The implementations
// below are kept ready for the day the reference CPU gains them.
const featLSE = false

func decodeAtomic(in *inst, raw uint32) {
	if !featLSE || (raw>>26)&1 != 0 { // vector: unallocated here
		return
	}
	size, o3, opc := raw>>30, (raw>>15)&1, (raw>>12)&7
	in.sz = uint8(1 << size)
	in.rn = xsp(raw >> 5)
	in.rm = xr(raw >> 16) // Rs: the operand
	in.rd = xw(raw)       // Rt: the old value
	switch {
	case o3 == 0:
		in.sh = uint8(opc)
		in.fn = opLdAtomic
	case opc == 0:
		in.fn = opSwp
	}
}

func opSwp(c *CPU, i *inst) {
	addr := c.R[i.rn]
	old := c.Mem.ReadN(addr, int(i.sz))
	c.Mem.WriteN(addr, int(i.sz), c.R[i.rm])
	c.R[i.rd] = old
	c.PC += 4
}

func opLdAtomic(c *CPU, i *inst) {
	addr := c.R[i.rn]
	n := uint(i.sz) * 8
	old := c.Mem.ReadN(addr, int(i.sz))
	s := c.R[i.rm]
	var v uint64
	switch i.sh {
	case 0:
		v = old + s
	case 1:
		v = old &^ s
	case 2:
		v = old ^ s
	case 3:
		v = old | s
	case 4: // LDSMAX
		if int64(sext(old, n)) < int64(sext(s, n)) {
			v = s
		} else {
			v = old
		}
	case 5: // LDSMIN
		if int64(sext(old, n)) > int64(sext(s, n)) {
			v = s
		} else {
			v = old
		}
	case 6: // LDUMAX
		if old < s&mask(n) {
			v = s
		} else {
			v = old
		}
	default: // LDUMIN
		if old > s&mask(n) {
			v = s
		} else {
			v = old
		}
	}
	c.Mem.WriteN(addr, int(i.sz), v)
	c.R[i.rd] = old
	c.PC += 4
}

func mask(n uint) uint64 {
	if n >= 64 {
		return ^uint64(0)
	}
	return 1<<n - 1
}

// ---- AdvSIMD load/store multiple structures --------------------------------

func decodeSIMDMulti(in *inst, raw uint32) {
	l, opcode, size, q := (raw>>22)&1, (raw>>12)&15, (raw>>10)&3, (raw>>30)&1
	var regs, group int
	switch opcode {
	case 0b0000:
		regs, group = 4, 4 // ST4/LD4
	case 0b0010:
		regs, group = 4, 1 // ST1/LD1, 4 registers
	case 0b0100:
		regs, group = 3, 3 // ST3/LD3
	case 0b0110:
		regs, group = 3, 1
	case 0b0111:
		regs, group = 1, 1
	case 0b1000:
		regs, group = 2, 2 // ST2/LD2
	case 0b1010:
		regs, group = 2, 1
	default:
		return
	}
	if group >= 2 && q == 0 && size == 3 {
		return // a single 64-bit element per register cannot be de-interleaved
	}
	if (raw>>21)&1 != 0 {
		return // reserved in both variants
	}
	if (raw>>23)&1 == 0 && (raw>>16)&0x3f != 0 {
		return // no-offset variant: bits 21:16 are reserved and must be zero
	}
	in.rd = uint8(raw & 31)
	in.rn = xsp(raw >> 5)
	in.sz = uint8(size)    // element size log2
	in.sh = uint8(regs)    // registers transferred
	in.ra = uint8(group)   // 1 = contiguous (LD1/ST1), else interleaved
	in.amt = uint8(8 << q) // bytes per register
	if (raw>>23)&1 == 1 {  // post-index
		in.cond = modePost
		if rm := (raw >> 16) & 31; rm == 31 {
			in.imm = uint64(regs) * uint64(8<<q) // immediate: all bytes transferred
		} else {
			in.rm = xr(rm)
			in.cond = modeReg // register post-index
		}
	} else {
		in.cond = modeOff
	}
	if l == 1 {
		in.fn = opSIMDLoadMulti
	} else {
		in.fn = opSIMDStoreMulti
	}
}

// simdMultiStep returns the lane size in bytes, lanes per register, and the
// total byte count of a load/store multiple.
func simdMultiParams(i *inst) (esize int, lanes int, total int) {
	esize = 1 << i.sz
	lanes = int(i.amt) / esize
	total = int(i.sh) * int(i.amt)
	return
}

func (c *CPU) simdAdvance(i *inst, base uint64, total int) {
	switch i.cond {
	case modePost:
		c.R[i.rn] = base + i.imm
	case modeReg:
		c.R[i.rn] = base + c.R[i.rm]
	}
	_ = total
}

func opSIMDLoadMulti(c *CPU, i *inst) {
	base := c.R[i.rn]
	esize, lanes, total := simdMultiParams(i)
	c.Mem.guestPage(MemRead, base, total, 0)
	regs := int(i.sh)
	var out [4]Vec
	addr := base
	if i.ra == 1 { // contiguous
		for r := 0; r < regs; r++ {
			for l := 0; l < lanes; l++ {
				setLane(&out[r], esize, l, c.Mem.ReadN(addr, esize))
				addr += uint64(esize)
			}
		}
	} else { // de-interleave
		for l := 0; l < lanes; l++ {
			for r := 0; r < regs; r++ {
				setLane(&out[r], esize, l, c.Mem.ReadN(addr, esize))
				addr += uint64(esize)
			}
		}
	}
	for r := 0; r < regs; r++ {
		c.V[(int(i.rd)+r)&31] = out[r]
	}
	c.simdAdvance(i, base, total)
	c.PC += 4
}

func opSIMDStoreMulti(c *CPU, i *inst) {
	base := c.R[i.rn]
	esize, lanes, total := simdMultiParams(i)
	c.Mem.checkWrite(base, total)
	regs := int(i.sh)
	addr := base
	if i.ra == 1 {
		for r := 0; r < regs; r++ {
			v := c.V[(int(i.rd)+r)&31]
			for l := 0; l < lanes; l++ {
				c.Mem.WriteN(addr, esize, getLane(v, esize, l))
				addr += uint64(esize)
			}
		}
	} else {
		for l := 0; l < lanes; l++ {
			for r := 0; r < regs; r++ {
				c.Mem.WriteN(addr, esize, getLane(c.V[(int(i.rd)+r)&31], esize, l))
				addr += uint64(esize)
			}
		}
	}
	c.simdAdvance(i, base, total)
	c.PC += 4
}
