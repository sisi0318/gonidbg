package arm64

import "math/bits"

// decode fills in for the instruction raw at pc, leaving in.fn nil when the
// encoding is unallocated or unimplemented. The structure follows the A64
// top-level encoding table (op0 = bits 28:25).
func decode(in *inst, raw uint32, pc uint64) {
	switch (raw >> 25) & 0xf {
	case 0b1000, 0b1001:
		decodeDPImm(in, raw, pc)
	case 0b1010, 0b1011:
		decodeBranchSys(in, raw, pc)
	case 0b0100, 0b0110, 0b1100, 0b1110:
		decodeLdSt(in, raw, pc)
	case 0b0101, 0b1101:
		decodeDPReg(in, raw)
	case 0b0111, 0b1111:
		decodeSIMDFP(in, raw)
	}
}

// ---- data processing (immediate) -------------------------------------------

func decodeDPImm(in *inst, raw uint32, pc uint64) {
	sf := raw>>31 == 1
	rd, rn := raw&31, (raw>>5)&31
	switch (raw >> 23) & 7 {
	case 0, 1: // ADR, ADRP
		imm := sext(uint64((raw>>5)&0x7ffff)<<2|uint64((raw>>29)&3), 21)
		in.rd = xw(rd)
		if raw>>31 == 0 {
			in.imm = pc + imm
		} else {
			in.imm = pc&^0xfff + imm<<12
		}
		in.fn = opMovImm

	case 2: // ADD/ADDS/SUB/SUBS (immediate)
		imm := uint64((raw >> 10) & 0xfff)
		if (raw>>22)&1 == 1 {
			imm <<= 12
		}
		in.imm = imm
		in.rn = xsp(rn)
		s := (raw >> 29) & 1
		if s == 1 {
			in.rd = xw(rd)
		} else {
			in.rd = xsp(rd)
		}
		in.fn = pick4x2(sf, (raw>>29)&3, opAddImm64, opAddsImm64, opSubImm64, opSubsImm64,
			opAddImm32, opAddsImm32, opSubImm32, opSubsImm32)

	case 4: // AND/ORR/EOR/ANDS (immediate)
		n := (raw >> 22) & 1
		if !sf && n == 1 {
			return
		}
		size := uint(32)
		if sf {
			size = 64
		}
		wmask, _, ok := decodeBitMasks(n, (raw>>10)&63, (raw>>16)&63, true, size)
		if !ok {
			return
		}
		in.imm = wmask
		in.rn = xr(rn)
		opc := (raw >> 29) & 3
		if opc == 3 {
			in.rd = xw(rd)
		} else {
			in.rd = xsp(rd)
		}
		in.fn = pick4x2(sf, opc, opAndImm64, opOrrImm64, opEorImm64, opAndsImm64,
			opAndImm32, opOrrImm32, opEorImm32, opAndsImm32)

	case 5: // MOVN/MOVZ/MOVK
		opc := (raw >> 29) & 3
		hw := (raw >> 21) & 3
		if opc == 1 || (!sf && hw >= 2) {
			return
		}
		shift := hw * 16
		imm := uint64((raw>>5)&0xffff) << shift
		in.rd = xw(rd)
		switch opc {
		case 0: // MOVN
			imm = ^imm
			if !sf {
				imm = uint64(uint32(imm))
			}
			in.imm = imm
			in.fn = opMovImm
		case 2: // MOVZ
			in.imm = imm
			in.fn = opMovImm
		case 3: // MOVK
			in.rn = xr(rd)
			in.imm = imm
			in.imm2 = ^(uint64(0xffff) << shift)
			if sf {
				in.fn = opMovk64
			} else {
				in.fn = opMovk32
			}
		}

	case 6: // SBFM/BFM/UBFM
		opc := (raw >> 29) & 3
		n := (raw >> 22) & 1
		immr, imms := (raw>>16)&63, (raw>>10)&63
		size := uint(64)
		if !sf {
			size = 32
			if immr >= 32 || imms >= 32 {
				return
			}
		}
		if opc == 3 || (sf && n == 0) || (!sf && n == 1) {
			return
		}
		wmask, tmask, ok := decodeBitMasks(n, imms, immr, false, size)
		if !ok {
			return
		}
		in.rd, in.rn = xw(rd), xr(rn)
		in.imm, in.imm2 = wmask, tmask
		in.amt, in.sh = uint8(immr), uint8(imms)
		if opc == 1 {
			in.ra = xr(rd) // BFM reads its destination
		}
		in.fn = pick4x2(sf, opc, opSbfm64, opBfm64, opUbfm64, nil, opSbfm32, opBfm32, opUbfm32, nil)

	case 7: // EXTR
		if (raw>>29)&3 != 0 || (raw>>21)&1 != 0 {
			return
		}
		n := (raw >> 22) & 1
		imms := (raw >> 10) & 63
		if (sf && n == 0) || (!sf && (n == 1 || imms >= 32)) {
			return
		}
		in.rd, in.rn, in.rm = xw(rd), xr(rn), xr((raw>>16)&31)
		in.amt = uint8(imms)
		if sf {
			in.fn = opExtr64
		} else {
			in.fn = opExtr32
		}
	}
}

// pick4x2 selects one of four 64-bit or four 32-bit handlers by a 2-bit field.
func pick4x2(sf bool, sel uint32, a, b, c, d, a32, b32, c32, d32 func(*CPU, *inst)) func(*CPU, *inst) {
	if sf {
		return [4]func(*CPU, *inst){a, b, c, d}[sel&3]
	}
	return [4]func(*CPU, *inst){a32, b32, c32, d32}[sel&3]
}

// decodeBitMasks is the architectural DecodeBitMasks: the (wmask, tmask) pair
// for logical immediates and bitfield moves.
func decodeBitMasks(immN, imms, immr uint32, immediate bool, m uint) (uint64, uint64, bool) {
	l := 31 - bits.LeadingZeros32((immN<<6)|(^imms&63))
	if l < 1 || 1<<l > int(m) {
		return 0, 0, false
	}
	levels := uint32(1)<<l - 1
	if immediate && imms&levels == levels {
		return 0, 0, false
	}
	s := imms & levels
	r := immr & levels
	d := (s - r) & levels
	esize := uint(1) << l
	emask := uint64(1)<<esize - 1
	if esize == 64 {
		emask = ^uint64(0)
	}
	welem := uint64(1)<<(s+1) - 1
	if s+1 == 64 {
		welem = ^uint64(0)
	}
	telem := uint64(1)<<(d+1) - 1
	if d+1 == 64 {
		telem = ^uint64(0)
	}
	// rotate welem right by r within esize bits
	if r != 0 {
		welem = (welem>>r | welem<<(esize-uint(r))) & emask
	}
	wmask, tmask := replicate(welem, esize, m), replicate(telem, esize, m)
	return wmask, tmask, true
}

func replicate(v uint64, esize, m uint) uint64 {
	out := uint64(0)
	for i := uint(0); i < m; i += esize {
		out |= v << i
	}
	if m == 32 {
		out = uint64(uint32(out))
	}
	return out
}

func opMovImm(c *CPU, i *inst) { c.R[i.rd] = i.imm; c.PC += 4 }

func opAddImm64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] + i.imm; c.PC += 4 }
func opSubImm64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] - i.imm; c.PC += 4 }
func opAddImm32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) + uint32(i.imm)); c.PC += 4 }
func opSubImm32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) - uint32(i.imm)); c.PC += 4 }

func opAddsImm64(c *CPU, i *inst) {
	r, f := addFlags64(c.R[i.rn], i.imm, 0)
	c.R[i.rd], c.NZCV = r, f
	c.PC += 4
}

func opSubsImm64(c *CPU, i *inst) {
	r, f := addFlags64(c.R[i.rn], ^i.imm, 1)
	c.R[i.rd], c.NZCV = r, f
	c.PC += 4
}

func opAddsImm32(c *CPU, i *inst) {
	r, f := addFlags32(uint32(c.R[i.rn]), uint32(i.imm), 0)
	c.R[i.rd], c.NZCV = uint64(r), f
	c.PC += 4
}

func opSubsImm32(c *CPU, i *inst) {
	r, f := addFlags32(uint32(c.R[i.rn]), ^uint32(i.imm), 1)
	c.R[i.rd], c.NZCV = uint64(r), f
	c.PC += 4
}

func opAndImm64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] & i.imm; c.PC += 4 }
func opOrrImm64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] | i.imm; c.PC += 4 }
func opEorImm64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] ^ i.imm; c.PC += 4 }
func opAndImm32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) & uint32(i.imm)); c.PC += 4 }
func opOrrImm32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) | uint32(i.imm)); c.PC += 4 }
func opEorImm32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) ^ uint32(i.imm)); c.PC += 4 }

func opAndsImm64(c *CPU, i *inst) {
	r := c.R[i.rn] & i.imm
	c.R[i.rd], c.NZCV = r, logicFlags64(r)
	c.PC += 4
}

func opAndsImm32(c *CPU, i *inst) {
	r := uint32(c.R[i.rn]) & uint32(i.imm)
	c.R[i.rd], c.NZCV = uint64(r), logicFlags32(r)
	c.PC += 4
}

func opMovk64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn]&i.imm2 | i.imm; c.PC += 4 }
func opMovk32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]&i.imm2 | i.imm)); c.PC += 4 }

// Bitfield moves, straight from the pseudocode: imm = wmask, imm2 = tmask,
// amt = immr (rotate), sh = imms (sign bit position for SBFM).
func opUbfm64(c *CPU, i *inst) {
	c.R[i.rd] = bits.RotateLeft64(c.R[i.rn], -int(i.amt)) & i.imm & i.imm2
	c.PC += 4
}

func opUbfm32(c *CPU, i *inst) {
	c.R[i.rd] = uint64(bits.RotateLeft32(uint32(c.R[i.rn]), -int(i.amt))) & i.imm & i.imm2
	c.PC += 4
}

func opSbfm64(c *CPU, i *inst) {
	src := c.R[i.rn]
	bot := bits.RotateLeft64(src, -int(i.amt)) & i.imm
	top := uint64(int64(src<<(63-i.sh)) >> 63)
	c.R[i.rd] = top&^i.imm2 | bot&i.imm2
	c.PC += 4
}

func opSbfm32(c *CPU, i *inst) {
	src := uint32(c.R[i.rn])
	bot := uint64(bits.RotateLeft32(src, -int(i.amt))) & i.imm
	top := uint64(uint32(int32(src<<(31-i.sh)) >> 31))
	c.R[i.rd] = (top&^i.imm2 | bot&i.imm2) & 0xffffffff
	c.PC += 4
}

func opBfm64(c *CPU, i *inst) {
	dst := c.R[i.ra]
	bot := dst&^i.imm | bits.RotateLeft64(c.R[i.rn], -int(i.amt))&i.imm
	c.R[i.rd] = dst&^i.imm2 | bot&i.imm2
	c.PC += 4
}

func opBfm32(c *CPU, i *inst) {
	dst := uint64(uint32(c.R[i.ra]))
	bot := dst&^i.imm | uint64(bits.RotateLeft32(uint32(c.R[i.rn]), -int(i.amt)))&i.imm
	c.R[i.rd] = (dst&^i.imm2 | bot&i.imm2) & 0xffffffff
	c.PC += 4
}

func opExtr64(c *CPU, i *inst) {
	c.R[i.rd] = c.R[i.rm]>>i.amt | c.R[i.rn]<<(64-uint(i.amt))
	c.PC += 4
}

func opExtr32(c *CPU, i *inst) {
	c.R[i.rd] = uint64(uint32(c.R[i.rm])>>i.amt | uint32(c.R[i.rn])<<(32-uint(i.amt)))
	c.PC += 4
}

// ---- branches, exception generation, system --------------------------------

func decodeBranchSys(in *inst, raw uint32, pc uint64) {
	switch {
	case raw&0x7c000000 == 0x14000000: // B, BL
		in.imm = pc + sext(uint64(raw&0x3ffffff)<<2, 28)
		if raw>>31 == 0 {
			in.fn = opB
		} else {
			in.imm2 = pc + 4
			in.fn = opBL
		}
	case raw&0x7e000000 == 0x34000000: // CBZ, CBNZ
		in.imm = pc + sext(uint64((raw>>5)&0x7ffff)<<2, 21)
		in.rn = xr(raw)
		in.fn = pick4x2(raw>>31 == 1, (raw>>24)&1, opCbz64, opCbnz64, nil, nil, opCbz32, opCbnz32, nil, nil)
	case raw&0x7e000000 == 0x36000000: // TBZ, TBNZ
		in.imm = pc + sext(uint64((raw>>5)&0x3fff)<<2, 16)
		in.rn = xr(raw)
		in.amt = uint8((raw>>31)<<5 | (raw>>19)&31)
		if (raw>>24)&1 == 0 {
			in.fn = opTbz
		} else {
			in.fn = opTbnz
		}
	case raw&0xff000010 == 0x54000000: // B.cond (bit 4 set is BC.cond, FEAT_HBC)
		in.imm = pc + sext(uint64((raw>>5)&0x7ffff)<<2, 21)
		in.cond = uint8(raw & 15)
		in.fn = opBcond
	case raw&0xff000000 == 0xd4000000: // exception generation
		decodeException(in, raw)
	case raw&0xfe000000 == 0xd6000000: // branch (register)
		decodeBranchReg(in, raw)
	case raw&0xffc00000 == 0xd5000000: // system
		decodeSystem(in, raw)
	}
}

func opB(c *CPU, i *inst)  { c.PC = i.imm }
func opBL(c *CPU, i *inst) { c.R[rLR] = i.imm2; c.PC = i.imm }

func opBcond(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.PC = i.imm
	} else {
		c.PC += 4
	}
}

func opCbz64(c *CPU, i *inst) {
	if c.R[i.rn] == 0 {
		c.PC = i.imm
	} else {
		c.PC += 4
	}
}

func opCbnz64(c *CPU, i *inst) {
	if c.R[i.rn] != 0 {
		c.PC = i.imm
	} else {
		c.PC += 4
	}
}

func opCbz32(c *CPU, i *inst) {
	if uint32(c.R[i.rn]) == 0 {
		c.PC = i.imm
	} else {
		c.PC += 4
	}
}

func opCbnz32(c *CPU, i *inst) {
	if uint32(c.R[i.rn]) != 0 {
		c.PC = i.imm
	} else {
		c.PC += 4
	}
}

func opTbz(c *CPU, i *inst) {
	if (c.R[i.rn]>>i.amt)&1 == 0 {
		c.PC = i.imm
	} else {
		c.PC += 4
	}
}

func opTbnz(c *CPU, i *inst) {
	if (c.R[i.rn]>>i.amt)&1 != 0 {
		c.PC = i.imm
	} else {
		c.PC += 4
	}
}

func decodeBranchReg(in *inst, raw uint32) {
	opc := (raw >> 21) & 15
	if (raw>>16)&31 != 31 || (raw>>10)&63 != 0 || raw&31 != 0 {
		return // pointer-authenticated forms: not implemented (as on Cortex-A72)
	}
	in.rn = xr(raw >> 5)
	switch opc {
	case 0:
		in.fn = opBr
	case 1:
		in.fn = opBlr
	case 2:
		in.fn = opBr // RET
	}
}

// A misaligned target is caught by the run loop, which has to check every PC
// anyway (see CPU.Run).
func opBr(c *CPU, i *inst) { c.PC = c.R[i.rn] }

func opBlr(c *CPU, i *inst) {
	t := c.R[i.rn]
	c.R[rLR] = c.PC + 4
	c.PC = t
}

func decodeException(in *inst, raw uint32) {
	opc, ll := (raw>>21)&7, raw&3
	if (raw>>2)&7 != 0 {
		return
	}
	switch {
	case opc == 0 && ll == 1:
		in.fn = opSvc
	case opc == 1 && ll == 0:
		in.fn = opBrk
	case opc == 2 && ll == 0:
		in.fn = opHlt
	}
}

func opSvc(c *CPU, i *inst) { c.PC += 4; c.raise(ExcpSWI) }
func opBrk(c *CPU, i *inst) { c.raise(ExcpBKPT) }
func opHlt(c *CPU, i *inst) { c.raise(ExcpHLT) }

func opNop(c *CPU, i *inst) { c.PC += 4 }

func opClrex(c *CPU, i *inst) { c.exclValid = false; c.PC += 4 }

// System register encodings: op0:op1:CRn:CRm:op2.
func sysreg(op0, op1, crn, crm, op2 uint32) uint32 {
	return op0<<14 | op1<<11 | crn<<7 | crm<<3 | op2
}

var (
	regNZCV        = sysreg(3, 3, 4, 2, 0)
	regFPCR        = sysreg(3, 3, 4, 4, 0)
	regFPSR        = sysreg(3, 3, 4, 4, 1)
	regTPIDR       = sysreg(3, 3, 13, 0, 2)
	regTPIDRRO     = sysreg(3, 3, 13, 0, 3)
	regCTR         = sysreg(3, 3, 0, 0, 1)
	regDCZID       = sysreg(3, 3, 0, 0, 7)
	regCNTFRQ      = sysreg(3, 3, 14, 0, 0)
	regCNTPCT      = sysreg(3, 3, 14, 0, 1)
	regCNTVCT      = sysreg(3, 3, 14, 0, 2)
	regMIDR        = sysreg(3, 0, 0, 0, 0)
	regMPIDR       = sysreg(3, 0, 0, 0, 5)
	regREVIDR      = sysreg(3, 0, 0, 0, 6)
	regCurrentEL   = sysreg(3, 0, 4, 2, 2)
	regIDAA64PFR0  = sysreg(3, 0, 0, 4, 0)
	regIDAA64PFR1  = sysreg(3, 0, 0, 4, 1)
	regIDAA64ISAR0 = sysreg(3, 0, 0, 6, 0)
	regIDAA64ISAR1 = sysreg(3, 0, 0, 6, 1)
	regIDAA64MMFR0 = sysreg(3, 0, 0, 7, 0)
)

// Read-only ID values: a Cortex-A72, the CPU model Unicorn emulates.
var constSysregs = map[uint32]uint64{
	regCTR:         0x8444c004,
	regDCZID:       4, // DC ZVA block = 4 words << 4 = 64 bytes
	regCNTFRQ:      62500000,
	regMIDR:        0x410fd083,
	regMPIDR:       0x80000000,
	regREVIDR:      0,
	regCurrentEL:   0,
	regIDAA64PFR0:  0x00002222,
	regIDAA64PFR1:  0,
	regIDAA64ISAR0: 0x00011120,
	regIDAA64ISAR1: 0,
	regIDAA64MMFR0: 0x00001124,
}

const dczvaBytes = 64

func decodeSystem(in *inst, raw uint32) {
	l := (raw >> 21) & 1
	op0 := (raw >> 19) & 3
	op1, crn, crm, op2 := (raw>>16)&7, (raw>>12)&15, (raw>>8)&15, (raw>>5)&7
	rt := raw & 31
	switch {
	case l == 0 && op0 == 0 && crn == 2 && op1 == 3 && rt == 31: // HINT (NOP, YIELD, PACIASP, BTI, ...)
		in.fn = opNop
	case l == 0 && op0 == 0 && crn == 3 && op1 == 3 && rt == 31: // barriers
		switch op2 {
		case 2:
			in.fn = opClrex
		case 4, 5, 6, 7: // DSB, DMB, ISB, SB: ordering is a no-op on one core
			in.fn = opNop
		}
	case l == 0 && op0 == 0 && crn == 4 && rt == 31: // MSR (immediate) to PSTATE
		if op1 == 3 && (op2 == 6 || op2 == 7) { // DAIFSet / DAIFClr
			in.fn = opNop
		}
	case op0 == 1: // SYS / SYSL
		if l == 1 {
			return
		}
		if op1 == 3 && crn == 7 && crm == 4 && op2 == 1 { // DC ZVA
			in.rn = xr(rt)
			in.fn = opDcZva
			return
		}
		in.fn = opNop // other cache maintenance: no effect on an emulator
	case op0 >= 2: // MRS / MSR (register)
		reg := sysreg(op0, op1, crn, crm, op2)
		in.imm = uint64(reg)
		if l == 1 {
			in.rd = xw(rt)
			if _, ok := constSysregs[reg]; ok {
				in.imm2 = constSysregs[reg]
				in.fn = opMovImm2
				return
			}
			switch reg {
			case regNZCV, regFPCR, regFPSR, regTPIDR, regTPIDRRO, regCNTPCT, regCNTVCT:
				in.fn = opMrs
			}
		} else {
			in.rn = xr(rt)
			switch reg {
			case regNZCV, regFPCR, regFPSR, regTPIDR:
				in.fn = opMsr
			}
		}
	}
}

func opMovImm2(c *CPU, i *inst) { c.R[i.rd] = i.imm2; c.PC += 4 }

func opMrs(c *CPU, i *inst) {
	var v uint64
	switch uint32(i.imm) {
	case regNZCV:
		v = uint64(c.NZCV)
	case regFPCR:
		v = uint64(c.FPCR)
	case regFPSR:
		v = uint64(c.FPSR)
	case regTPIDR:
		v = c.TPIDR
	case regTPIDRRO:
		v = c.TPIDRRO
	case regCNTPCT, regCNTVCT:
		v = c.icount
	}
	c.R[i.rd] = v
	c.PC += 4
}

func opMsr(c *CPU, i *inst) {
	v := c.R[i.rn]
	switch uint32(i.imm) {
	case regNZCV:
		c.NZCV = uint32(v) & 0xf0000000
	case regFPCR:
		c.FPCR = uint32(v) & fpcrMask
	case regFPSR:
		c.FPSR = uint32(v) & fpsrMask
	case regTPIDR:
		c.TPIDR = v
	}
	c.PC += 4
}

// Writable FPCR/FPSR bits (AHP DN FZ RMode Stride Len FZ16 IDE IXE UFE OFE
// DZE IOE / QC IDC IXC UFC OFC DZC IOC), as QEMU masks them.
const (
	fpcrMask = 0x07ff9f00
	fpsrMask = 0xf800009f
)

func opDcZva(c *CPU, i *inst) {
	a := c.R[i.rn] &^ (dczvaBytes - 1)
	c.Mem.checkWrite(a, dczvaBytes)
	for k := uint64(0); k < dczvaBytes; k += 8 {
		c.Mem.Write64(a+k, 0)
	}
	c.PC += 4
}
