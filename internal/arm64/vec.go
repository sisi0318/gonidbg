package arm64

import "math/bits"

// ---- SIMD lane access ------------------------------------------------------
// esize is the lane width in bytes; idx counts lanes from the low end.

func getLane(v Vec, esize, idx int) uint64 {
	bitoff := uint(idx * esize * 8)
	return (v[bitoff>>6] >> (bitoff & 63)) & mask(uint(esize)*8)
}

func setLane(v *Vec, esize, idx int, val uint64) {
	bitoff := uint(idx * esize * 8)
	m := mask(uint(esize) * 8)
	sh := bitoff & 63
	w := &v[bitoff>>6]
	*w = *w&^(m<<sh) | (val&m)<<sh
}

// sxLane sign-extends a lane value of esize bytes.
func sxLane(v uint64, esize int) int64 { return int64(sext(v, uint(esize)*8)) }

// ---- dispatcher ------------------------------------------------------------

func decodeSIMDFP(in *inst, raw uint32) {
	switch {
	// scalar floating point
	case raw&0x5f200000 == 0x1e200000: // FP (register) group
		decodeFP(in, raw)
	case raw&0x5f200000 == 0x1e000000: // FP <-> fixed-point
		decodeFPFixed(in, raw)
	case raw&0x5f000000 == 0x1f000000: // FP data-processing (3 source)
		decodeFP3(in, raw)

	// AdvSIMD scalar
	case raw&0xdf200400 == 0x5e200400:
		decodeSIMD3Same(in, raw, true)
	case raw&0xdf3e0c00 == 0x5e200800:
		decodeSIMD2Misc(in, raw, true)
	case raw&0xdf3e0c00 == 0x5e300800:
		decodeSIMDPairScalar(in, raw)
	case raw&0xdfe08400 == 0x5e000400:
		decodeSIMDCopy(in, raw, true)
	case raw&0xdf800400 == 0x5f000400:
		decodeSIMDShiftImm(in, raw, true)
	case raw&0xdf000400 == 0x5f000000:
		decodeSIMDIndexed(in, raw, true)

	// AdvSIMD vector
	case raw&0x9f200400 == 0x0e200400:
		decodeSIMD3Same(in, raw, false)
	case raw&0x9f200c00 == 0x0e200000:
		decodeSIMD3Diff(in, raw)
	case raw&0x9f3e0c00 == 0x0e200800:
		decodeSIMD2Misc(in, raw, false)
	case raw&0x9f3e0c00 == 0x0e300800:
		decodeSIMDAcross(in, raw)
	case raw&0x9fe08400 == 0x0e000400:
		decodeSIMDCopy(in, raw, false)
	case raw&0x9ff80400 == 0x0f000400:
		decodeSIMDModImm(in, raw)
	case raw&0x9f800400 == 0x0f000400:
		decodeSIMDShiftImm(in, raw, false)
	case raw&0x9f000400 == 0x0f000000:
		decodeSIMDIndexed(in, raw, false)
	case raw&0xbfe08400 == 0x2e000000:
		decodeSIMDExt(in, raw)
	case raw&0xbf208c00 == 0x0e000800:
		decodeSIMDPermute(in, raw)
	case raw&0xbf208c00 == 0x0e000000:
		decodeSIMDTable(in, raw)
	}
}

// vecOf returns the operand registers and lane geometry shared by most
// AdvSIMD encodings. For scalar forms there is exactly one lane.
func simdGeom(in *inst, raw uint32, scalar bool, size uint32) (lanes int) {
	in.rd, in.rn, in.rm = uint8(raw&31), uint8((raw>>5)&31), uint8((raw>>16)&31)
	in.sz = uint8(size)
	if scalar {
		lanes = 1
	} else {
		q := (raw >> 30) & 1
		lanes = int(8<<q) >> size
	}
	in.amt = uint8(lanes)
	return lanes
}

// ---- 3 same ----------------------------------------------------------------

// SIMD integer operations, numbered U<<5|opcode as in the encoding.
const (
	sAND    = 0b000011
	sBIC    = 0b100011 // marker: size selects AND/BIC/ORR/ORN within opcode 00011
	sADD    = 0b010000
	sSUB    = 0b110000
	sCMGT   = 0b000110
	sCMGE   = 0b000111
	sCMHI   = 0b100110
	sCMHS   = 0b100111
	sCMTST  = 0b010001
	sCMEQ   = 0b110001
	sSSHL   = 0b001000
	sUSHL   = 0b101000
	sSMAX   = 0b001100
	sSMIN   = 0b001101
	sUMAX   = 0b101100
	sUMIN   = 0b101101
	sMUL    = 0b010011
	sMLA    = 0b010010
	sMLS    = 0b110010
	sADDP   = 0b010111
	sSABD   = 0b001110
	sUABD   = 0b101110
	sSABA   = 0b001111
	sUABA   = 0b101111
	sSQADD  = 0b000001
	sUQADD  = 0b100001
	sSQSUB  = 0b000101
	sUQSUB  = 0b100101
	sSHADD  = 0b000000
	sUHADD  = 0b100000
	sSHSUB  = 0b000100
	sUHSUB  = 0b100100
	sSRHADD = 0b000010
	sURHADD = 0b100010
	sSMAXP  = 0b010100
	sSMINP  = 0b010101
	sUMAXP  = 0b110100
	sUMINP  = 0b110101
	sPMUL   = 0b110011
)

// bitwise ops on the full register, selected by size when opcode == 00011
const (
	bwAND = iota
	bwBIC
	bwORR
	bwORN
	bwEOR
	bwBSL
	bwBIT
	bwBIF
)

func decodeSIMD3Same(in *inst, raw uint32, scalar bool) {
	u, size, opcode := (raw>>29)&1, (raw>>22)&3, (raw>>11)&31
	sel := u<<5 | opcode

	// floating point subgroup: opcode 11000..11111 with bit 23 selecting the
	// single/double family (half precision lives in the "3 same FP16" group).
	if opcode >= 0b11000 {
		decodeSIMD3SameFP(in, raw, scalar, u, size, opcode)
		return
	}
	if opcode == 0b00011 { // bitwise, operates on the whole register
		if scalar {
			return // there is no scalar bitwise three-same
		}
		in.rd, in.rn, in.rm = uint8(raw&31), uint8((raw>>5)&31), uint8((raw>>16)&31)
		in.imm = uint64(u<<2 | size)
		if (raw>>30)&1 == 1 {
			in.fn = opSimdBitwiseQ
		} else {
			in.fn = opSimdBitwiseD
		}
		return
	}
	if scalar {
		// scalar integer 3-same is defined only for the saturating/shift ops and
		// for ADD/SUB/CMP at size 11
		switch sel {
		case sADD, sSUB, sCMGT, sCMGE, sCMHI, sCMHS, sCMTST, sCMEQ, sSSHL, sUSHL:
			if size != 3 {
				return
			}
		case sSQADD, sUQADD, sSQSUB, sUQSUB:
			// the saturating forms exist for every lane width
		default:
			return
		}
	}
	if size == 3 && !scalar && (raw>>30)&1 == 0 {
		return // 1 x 64-bit lane in a D register is unallocated
	}
	switch sel {
	case sADD, sSUB, sCMGT, sCMGE, sCMHI, sCMHS, sCMTST, sCMEQ, sSSHL, sUSHL,
		sSQADD, sUQADD, sSQSUB, sUQSUB:
		// these are the only three-same integer ops with a 64-bit lane form
	case sSMAX, sSMIN, sUMAX, sUMIN, sSABD, sUABD, sSABA, sUABA,
		sSHADD, sUHADD, sSHSUB, sUHSUB, sSRHADD, sURHADD, sMUL, sMLA, sMLS:
		if size == 3 {
			return
		}
	case sPMUL:
		if size != 0 { // polynomial multiply is 8-bit only
			return
		}
	case sADDP:
		if scalar {
			return
		}
	case sSMAXP, sSMINP, sUMAXP, sUMINP:
		if scalar || size == 3 {
			return
		}
	default:
		return
	}
	lanes := simdGeom(in, raw, scalar, size)
	in.imm = uint64(sel)
	if sel == sADDP || sel == sSMAXP || sel == sSMINP || sel == sUMAXP || sel == sUMINP {
		in.fn = opSimdPairwise
		return
	}
	_ = lanes
	in.fn = opSimd3Same
}

func opSimdBitwiseD(c *CPU, i *inst) {
	a, b := c.V[i.rn][0], c.V[i.rm][0]
	c.V[i.rd] = Vec{bitwiseOp(int(i.imm), c.V[i.rd][0], a, b), 0}
	c.PC += 4
}

func opSimdBitwiseQ(c *CPU, i *inst) {
	n, m, d := c.V[i.rn], c.V[i.rm], c.V[i.rd]
	c.V[i.rd] = Vec{bitwiseOp(int(i.imm), d[0], n[0], m[0]), bitwiseOp(int(i.imm), d[1], n[1], m[1])}
	c.PC += 4
}

func bitwiseOp(op int, dst, a, b uint64) uint64 {
	switch op {
	case bwAND:
		return a & b
	case bwBIC:
		return a &^ b
	case bwORR:
		return a | b
	case bwORN:
		return a | ^b
	case bwEOR:
		return a ^ b
	case bwBSL: // dst selects: set -> first source, clear -> second
		return a&dst | b&^dst
	case bwBIT:
		return dst&^b | a&b
	default: // bwBIF
		return dst&b | a&^b
	}
}

func opSimd3Same(c *CPU, i *inst) {
	esize := 1 << i.sz
	lanes := int(i.amt)
	n, m, d := c.V[i.rn], c.V[i.rm], c.V[i.rd]
	var out Vec
	for l := 0; l < lanes; l++ {
		a, b := getLane(n, esize, l), getLane(m, esize, l)
		setLane(&out, esize, l, simdALU(uint32(i.imm), a, b, getLane(d, esize, l), esize))
	}
	c.V[i.rd] = out
	c.PC += 4
}

func simdALU(sel uint32, a, b, dst uint64, esize int) uint64 {
	n := uint(esize) * 8
	switch sel {
	case sADD:
		return a + b
	case sSUB:
		return a - b
	case sMUL:
		return a * b
	case sMLA:
		return dst + a*b
	case sMLS:
		return dst - a*b
	case sCMEQ:
		return boolLane(a&mask(n) == b&mask(n), n)
	case sCMTST:
		return boolLane(a&b != 0, n)
	case sCMGT:
		return boolLane(sxLane(a, esize) > sxLane(b, esize), n)
	case sCMGE:
		return boolLane(sxLane(a, esize) >= sxLane(b, esize), n)
	case sCMHI:
		return boolLane(a > b, n)
	case sCMHS:
		return boolLane(a >= b, n)
	case sSMAX:
		return maxS(a, b, esize)
	case sSMIN:
		return minS(a, b, esize)
	case sUMAX:
		if a > b {
			return a
		}
		return b
	case sUMIN:
		if a < b {
			return a
		}
		return b
	case sSSHL:
		return shiftLane(a, int8(b), n, true)
	case sUSHL:
		return shiftLane(a, int8(b), n, false)
	case sSABD:
		x, y := sxLane(a, esize), sxLane(b, esize)
		if x < y {
			x, y = y, x
		}
		return uint64(x - y)
	case sUABD:
		if a < b {
			a, b = b, a
		}
		return a - b
	case sSABA:
		x, y := sxLane(a, esize), sxLane(b, esize)
		if x < y {
			x, y = y, x
		}
		return dst + uint64(x-y)
	case sUABA:
		if a < b {
			a, b = b, a
		}
		return dst + a - b
	case sSQADD:
		if esize == 8 {
			return satAddS64(int64(a), int64(b))
		}
		return satS(sxLane(a, esize)+sxLane(b, esize), n)
	case sSQSUB:
		if esize == 8 {
			return satSubS64(int64(a), int64(b))
		}
		return satS(sxLane(a, esize)-sxLane(b, esize), n)
	case sUQADD:
		r := a + b
		if r&^mask(n) != 0 || r < a {
			return mask(n)
		}
		return r
	case sUQSUB:
		if a < b {
			return 0
		}
		return a - b
	case sSHADD:
		return uint64((sxLane(a, esize) + sxLane(b, esize)) >> 1)
	case sUHADD:
		return (a + b) >> 1
	case sSHSUB:
		return uint64((sxLane(a, esize) - sxLane(b, esize)) >> 1)
	case sUHSUB:
		return uint64((int64(a) - int64(b)) >> 1)
	case sSRHADD:
		return uint64((sxLane(a, esize) + sxLane(b, esize) + 1) >> 1)
	case sURHADD:
		return (a + b + 1) >> 1
	case sPMUL:
		var r uint64
		for k := uint(0); k < 8; k++ {
			if b>>k&1 != 0 {
				r ^= a << k
			}
		}
		return r
	}
	return 0
}

func boolLane(v bool, n uint) uint64 {
	if v {
		return mask(n)
	}
	return 0
}

func maxS(a, b uint64, esize int) uint64 {
	if sxLane(a, esize) >= sxLane(b, esize) {
		return a
	}
	return b
}

func minS(a, b uint64, esize int) uint64 {
	if sxLane(a, esize) <= sxLane(b, esize) {
		return a
	}
	return b
}

// shiftLane implements the SSHL/USHL byte-signed shift amount: left for
// positive, right (arithmetic when signed) for negative, zero when the
// magnitude exceeds the lane width.
func shiftLane(v uint64, amt int8, n uint, signed bool) uint64 {
	if amt >= 0 {
		if uint(amt) >= n {
			return 0
		}
		return v << uint(amt)
	}
	sh := uint(-int(amt))
	if signed {
		s := int64(sext(v, n))
		if sh >= n {
			sh = n - 1
		}
		return uint64(s >> sh)
	}
	if sh >= n {
		return 0
	}
	return v >> sh
}

// satAddS64 / satSubS64 saturate 64-bit signed lanes. The narrower widths can
// compute in int64 and clamp afterwards, but at 64 bits the arithmetic itself
// wraps, so the overflow has to be detected from the operand signs.
func satAddS64(a, b int64) uint64 {
	r := a + b
	if a > 0 && b > 0 && r < 0 {
		return 0x7fffffffffffffff
	}
	if a < 0 && b < 0 && r >= 0 {
		return 0x8000000000000000
	}
	return uint64(r)
}

func satSubS64(a, b int64) uint64 {
	r := a - b
	if a >= 0 && b < 0 && r < 0 {
		return 0x7fffffffffffffff
	}
	if a < 0 && b > 0 && r >= 0 {
		return 0x8000000000000000
	}
	return uint64(r)
}

func satS(v int64, n uint) uint64 {
	hi := int64(mask(n - 1))
	if v > hi {
		return uint64(hi)
	}
	if lo := -hi - 1; v < lo {
		return uint64(lo) & mask(n)
	}
	return uint64(v) & mask(n)
}

// pairwise ops read lanes from the concatenation of Rn and Rm
func opSimdPairwise(c *CPU, i *inst) {
	esize := 1 << i.sz
	lanes := int(i.amt)
	src := [2]Vec{c.V[i.rn], c.V[i.rm]}
	var out Vec
	for l := 0; l < lanes; l++ {
		p := l * 2
		v := src[p/lanes]
		a, b := getLane(v, esize, (p%lanes)), getLane(v, esize, (p%lanes)+1)
		var r uint64
		switch i.imm {
		case sADDP:
			r = a + b
		case sSMAXP:
			r = maxS(a, b, esize)
		case sSMINP:
			r = minS(a, b, esize)
		case sUMAXP:
			r = a
			if b > a {
				r = b
			}
		case sUMINP:
			r = a
			if b < a {
				r = b
			}
		}
		setLane(&out, esize, l, r)
	}
	c.V[i.rd] = out
	c.PC += 4
}

// ---- 3 different (widening) ------------------------------------------------

func decodeSIMD3Diff(in *inst, raw uint32) {
	u, size, opcode := (raw>>29)&1, (raw>>22)&3, (raw>>12)&15
	if size == 3 {
		return
	}
	switch opcode {
	// SADDL/UADDL, SADDW/UADDW, SSUBL/USUBL, SSUBW/USUBW, ADDHN, SABAL/UABAL,
	// SUBHN, SABDL/UABDL, SMLAL/UMLAL, SMLSL/UMLSL, SMULL/UMULL. The
	// saturating-doubling forms and PMULL are not implemented.
	case 0b0000, 0b0001, 0b0010, 0b0011, 0b0100, 0b0101, 0b0110, 0b0111,
		0b1000, 0b1010, 0b1100:
	default:
		return
	}
	in.rd, in.rn, in.rm = uint8(raw&31), uint8((raw>>5)&31), uint8((raw>>16)&31)
	in.sz = uint8(size)
	in.sh = uint8((raw >> 30) & 1) // Q: operate on the high half
	in.imm = uint64(u<<4 | opcode)
	in.fn = opSimd3Diff
}

func opSimd3Diff(c *CPU, i *inst) {
	esize := 1 << i.sz
	lanes := 8 / esize
	base := 0
	if i.sh == 1 {
		base = lanes
	}
	n, m := c.V[i.rn], c.V[i.rm]
	u := i.imm>>4 != 0
	var out Vec
	if op := i.imm & 0xf; op == 0b0100 || op == 0b0110 {
		// narrowing: the result is half-width, so the "2" form keeps the
		// existing low half of the destination instead of operating on it
		if i.sh == 1 {
			out = c.V[i.rd]
		}
		for l := 0; l < lanes; l++ {
			var r uint64
			if op == 0b0100 {
				r = getLane(n, esize*2, l) + getLane(m, esize*2, l)
			} else {
				r = getLane(n, esize*2, l) - getLane(m, esize*2, l)
			}
			if u { // RADDHN / RSUBHN round instead of truncating
				r += 1 << (uint(esize)*8 - 1)
			}
			setLane(&out, esize, base+l, r>>(uint(esize)*8))
		}
		c.V[i.rd] = out
		c.PC += 4
		return
	}
	for l := 0; l < lanes; l++ {
		a := getLane(n, esize, base+l)
		b := getLane(m, esize, base+l)
		wide := func(v uint64) uint64 {
			if u {
				return v
			}
			return uint64(sxLane(v, esize))
		}
		aw, bw := wide(a), wide(b)
		if i.imm&0xf == 0b0001 || i.imm&0xf == 0b0011 { // ADDW/SUBW: Rn is already wide
			aw = getLane(n, esize*2, l)
		}
		absDiff := func() uint64 {
			if u {
				if a < b {
					return b - a
				}
				return a - b
			}
			x, y := sxLane(a, esize), sxLane(b, esize)
			if x < y {
				x, y = y, x
			}
			return uint64(x - y)
		}
		var r uint64
		switch i.imm & 0xf {
		case 0b0000, 0b0001: // SADDL/UADDL, SADDW/UADDW
			r = aw + bw
		case 0b0010, 0b0011: // SSUBL/USUBL, SSUBW/USUBW
			r = aw - bw
		case 0b0101: // SABAL/UABAL
			r = getLane(c.V[i.rd], esize*2, l) + absDiff()
		case 0b0111: // SABDL/UABDL
			r = absDiff()
		case 0b1000: // SMLAL/UMLAL
			r = getLane(c.V[i.rd], esize*2, l) + aw*bw
		case 0b1010: // SMLSL/UMLSL
			r = getLane(c.V[i.rd], esize*2, l) - aw*bw
		case 0b1100: // SMULL/UMULL
			r = aw * bw
		}
		setLane(&out, esize*2, l, r)
	}
	c.V[i.rd] = out
	c.PC += 4
}

// ---- 2-register misc -------------------------------------------------------

const (
	mREV64 = 0b000000
	mREV16 = 0b000001
	mREV32 = 0b100000
	mCNT   = 0b100101
	mNOT   = 0b100101 // size 00 -> NOT (same opcode as CNT with U=1); see decode
	mXTN   = 0b100100
	mNEG   = 0b101011
	mABS   = 0b001011
	mCMEQ0 = 0b001001
	mCMGT0 = 0b001000
	mCMGE0 = 0b101000
	mCMLE0 = 0b101001
	mCMLT0 = 0b001010
	mCLZ   = 0b100100
	mSHLL  = 0b110011
)

func decodeSIMD2Misc(in *inst, raw uint32, scalar bool) {
	u, size, opcode := (raw>>29)&1, (raw>>22)&3, (raw>>12)&31
	sel := u<<5 | opcode
	// The integer half of this group is opcodes 00000..01011 plus the narrowing
	// and widening forms XTN/SHLL/SQXTN; everything else is floating point.
	isInt := opcode <= 0b01011 || opcode == 0b10010 || opcode == 0b10011 || opcode == 0b10100
	if !isInt {
		decodeSIMD2MiscFP(in, raw, scalar, u, size, opcode)
		return
	}
	switch sel {
	case 0b000000, 0b000001, 0b100000: // REV64, REV16, REV32
		var container uint32
		switch sel {
		case 0b000000:
			container = 8
			if size == 3 {
				return
			}
		case 0b000001:
			container = 2
			if size != 0 {
				return
			}
		default:
			container = 4
			if size >= 2 {
				return
			}
		}
		if scalar {
			return
		}
		simdGeom(in, raw, false, size)
		in.imm2 = uint64(container)
		in.fn = opSimdRev
		return
	case 0b000100: // CLS
		in.imm = 0b000100
	case 0b100100: // CLZ
		in.imm = mCLZ
	case 0b000101: // CNT / NOT(size 00, U=1 handled below)
		if size != 0 {
			return
		}
		in.imm = 0b000101
	case 0b100101: // NOT (size 00) / RBIT (size 01)
		if size == 0 {
			in.imm = 0b100101
		} else if size == 1 {
			in.imm = 0b100101 | 0x40
		} else {
			return
		}
	case 0b001000, 0b001001, 0b001010, 0b101000, 0b101001: // CMGT/CMEQ/CMLT/CMGE/CMLE vs 0
		in.imm = uint64(sel)
	case 0b001011: // ABS
		in.imm = mABS
	case 0b101011: // NEG
		in.imm = mNEG
	case 0b010010, 0b110010: // XTN/SQXTN family
		if size == 3 {
			return
		}
		in.imm = uint64(sel)
	case 0b010100, 0b110100: // SQXTN / UQXTN handled with XTN semantics
		if size == 3 {
			return
		}
		in.imm = uint64(sel)
	case 0b110011: // SHLL
		if size == 3 {
			return
		}
		in.imm = mSHLL
	default:
		return
	}
	if !scalar {
		if size == 3 && (raw>>30)&1 == 0 {
			return // a single 64-bit lane in a D register is unallocated
		}
		if sel == 0b000100 || sel == 0b100100 { // CLS / CLZ
			if size == 3 {
				return
			}
		}
	}
	if scalar {
		// Scalar two-register misc is limited to the compare-against-zero forms,
		// ABS/NEG (64-bit only) and the saturating narrowing ones; REV*, CLS,
		// CLZ, CNT, NOT, RBIT and SHLL are vector-only.
		switch sel {
		case 0b001000, 0b001001, 0b001010, 0b101000, 0b101001, 0b001011, 0b101011:
			if size != 3 {
				return
			}
		case 0b110010, 0b010100, 0b110100: // SQXTUN, SQXTN, UQXTN
			// plain XTN (0b010010) is vector only
		default:
			return
		}
	}
	simdGeom(in, raw, scalar, size)
	in.sh = uint8((raw >> 30) & 1)
	in.fn = opSimd2Misc
}

func opSimd2Misc(c *CPU, i *inst) {
	esize := 1 << i.sz
	lanes := int(i.amt)
	n := c.V[i.rn]
	var out Vec
	switch i.imm {
	case 0b010010, 0b110010, 0b010100, 0b110100: // XTN / XTN2 / SQXTN / UQXTN
		// narrow 2*esize source lanes into esize destination lanes
		dlanes := 8 / esize
		if i.amt == 1 {
			dlanes = 1 // scalar form: one lane, upper bits cleared
		}
		out = c.V[i.rd]
		if i.sh == 0 || i.amt == 1 {
			out = Vec{}
		}
		base := 0
		if i.sh == 1 && i.amt != 1 {
			base = dlanes
		}
		for l := 0; l < dlanes; l++ {
			v := getLane(n, esize*2, l)
			switch i.imm {
			case 0b110100: // UQXTN
				if v > mask(uint(esize)*8) {
					v = mask(uint(esize) * 8)
				}
			case 0b010100: // SQXTN
				v = satS(sxLane(v, esize*2), uint(esize)*8)
			case 0b110010: // SQXTUN: signed source, unsigned saturation
				s := sxLane(v, esize*2)
				switch {
				case s < 0:
					v = 0
				case uint64(s) > mask(uint(esize)*8):
					v = mask(uint(esize) * 8)
				default:
					v = uint64(s)
				}
			}
			setLane(&out, esize, base+l, v)
		}
		c.V[i.rd] = out
		c.PC += 4
		return
	case mSHLL:
		dlanes := 8 / esize
		base := 0
		if i.sh == 1 {
			base = dlanes
		}
		for l := 0; l < dlanes; l++ {
			setLane(&out, esize*2, l, getLane(n, esize, base+l)<<(uint(esize)*8))
		}
		c.V[i.rd] = out
		c.PC += 4
		return
	}
	for l := 0; l < lanes; l++ {
		a := getLane(n, esize, l)
		nb := uint(esize) * 8
		var r uint64
		switch i.imm {
		case 0b000100: // CLS
			v := a & mask(nb)
			r = uint64(bits.LeadingZeros64((v^v>>1)&mask(nb-1)) - int(64-nb) - 1)
		case mCLZ:
			r = uint64(bits.LeadingZeros64(a&mask(nb)) - int(64-nb))
		case 0b000101: // CNT
			r = uint64(bits.OnesCount64(a & mask(nb)))
		case 0b100101: // NOT
			r = ^a
		case 0b100101 | 0x40: // RBIT
			r = bits.Reverse64(a) >> (64 - nb)
		case mABS:
			s := sxLane(a, esize)
			if s < 0 {
				s = -s
			}
			r = uint64(s)
		case mNEG:
			r = -a
		case mCMGT0:
			r = boolLane(sxLane(a, esize) > 0, nb)
		case mCMGE0:
			r = boolLane(sxLane(a, esize) >= 0, nb)
		case mCMEQ0:
			r = boolLane(a&mask(nb) == 0, nb)
		case mCMLE0:
			r = boolLane(sxLane(a, esize) <= 0, nb)
		case mCMLT0:
			r = boolLane(sxLane(a, esize) < 0, nb)
		}
		setLane(&out, esize, l, r)
	}
	c.V[i.rd] = out
	c.PC += 4
}

// opSimdRev implements REV16/REV32/REV64: inside each container, reverse the
// order of the elements. imm2 holds the container size in bytes.
func opSimdRev(c *CPU, i *inst) {
	esize := 1 << i.sz
	per := int(i.imm2) / esize // elements per container
	n := c.V[i.rn]
	var out Vec
	for l := 0; l < int(i.amt); l++ {
		base := l / per * per
		setLane(&out, esize, l, getLane(n, esize, base+per-1-l%per))
	}
	c.V[i.rd] = out
	c.PC += 4
}

// ---- across lanes ----------------------------------------------------------

func decodeSIMDAcross(in *inst, raw uint32) {
	u, size, opcode := (raw>>29)&1, (raw>>22)&3, (raw>>12)&31
	switch u<<5 | opcode {
	case 0b000011, 0b100011: // SADDLV / UADDLV
	case 0b001010, 0b101010: // SMAXV / UMAXV
	case 0b011010, 0b111010: // SMINV / UMINV
	case 0b011011: // ADDV
	default:
		decodeSIMDAcrossFP(in, raw, u, size, opcode)
		return
	}
	if size == 3 || (size == 2 && (raw>>30)&1 == 0) {
		return
	}
	simdGeom(in, raw, false, size)
	in.imm = uint64(u<<5 | opcode)
	in.fn = opSimdAcross
}

func opSimdAcross(c *CPU, i *inst) {
	esize := 1 << i.sz
	lanes := int(i.amt)
	n := c.V[i.rn]
	widen := i.imm == 0b000011 || i.imm == 0b100011
	var acc uint64
	for l := 0; l < lanes; l++ {
		v := getLane(n, esize, l)
		switch i.imm {
		case 0b000011: // SADDLV
			acc += uint64(sxLane(v, esize))
		case 0b100011: // UADDLV
			acc += v
		case 0b011011: // ADDV
			acc += v
		case 0b001010: // SMAXV
			if l == 0 || sxLane(v, esize) > sxLane(acc, esize) {
				acc = v
			}
		case 0b101010: // UMAXV
			if v > acc {
				acc = v
			}
		case 0b011010: // SMINV
			if l == 0 || sxLane(v, esize) < sxLane(acc, esize) {
				acc = v
			}
		case 0b111010: // UMINV
			if l == 0 || v < acc {
				acc = v
			}
		}
	}
	dsize := esize
	if widen {
		dsize = esize * 2
	}
	var out Vec
	setLane(&out, dsize, 0, acc)
	c.V[i.rd] = out
	c.PC += 4
}

// ---- copy (DUP / INS / SMOV / UMOV) ----------------------------------------

// decodeSIMDCopy handles both copy groups. The vector group (bits 28:24 =
// 01110) holds DUP, SMOV, UMOV and both INS forms; the scalar group (11110)
// holds only DUP (element), so every other encoding there is unallocated.
func decodeSIMDCopy(in *inst, raw uint32, scalar bool) {
	op, imm5, imm4, q := (raw>>29)&1, (raw>>16)&31, (raw>>11)&15, (raw>>30)&1
	size := 0
	for size < 4 && imm5>>uint(size)&1 == 0 {
		size++
	}
	if size > 3 {
		return
	}
	in.rd, in.rn = uint8(raw&31), uint8((raw>>5)&31)
	in.sz = uint8(size)
	in.amt = uint8(imm5 >> uint(size+1)) // element index, or INS destination lane
	lanes := int(8<<q) >> size

	if scalar {
		if op != 0 || imm4 != 0 {
			return
		}
		in.fn = opSimdDupElemScalar
		return
	}
	if op == 1 { // INS (element): vector only, and only in the 128-bit form
		if q == 0 {
			return
		}
		in.sh = uint8(imm4 >> uint(size)) // source lane index
		in.fn = opSimdInsElem
		return
	}
	switch imm4 {
	case 0: // DUP (element)
		if size == 3 && q == 0 {
			return
		}
		in.imm = uint64(lanes)
		in.fn = opSimdDupElem
	case 1: // DUP (general register)
		if size == 3 && q == 0 {
			return
		}
		in.rn = xr(raw >> 5)
		in.imm = uint64(lanes)
		in.fn = opSimdDupGen
	case 3: // INS (general register)
		if q == 0 {
			return
		}
		in.rn = xr(raw >> 5)
		in.fn = opSimdInsGen
	case 5: // SMOV
		if size == 3 || (size == 2 && q == 0) {
			return
		}
		in.rd = xw(raw)
		if q == 1 {
			in.fn = opSimdSmov64
		} else {
			in.fn = opSimdSmov32
		}
	case 7: // UMOV
		if (size == 3) != (q == 1) {
			return // W destination for B/H/S, X destination for D
		}
		in.rd = xw(raw)
		in.fn = opSimdUmov
	}
}

func opSimdDupElem(c *CPU, i *inst) {
	esize := 1 << i.sz
	v := getLane(c.V[i.rn], esize, int(i.amt))
	var out Vec
	for l := 0; l < int(i.imm); l++ {
		setLane(&out, esize, l, v)
	}
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdDupElemScalar(c *CPU, i *inst) {
	esize := 1 << i.sz
	var out Vec
	setLane(&out, esize, 0, getLane(c.V[i.rn], esize, int(i.amt)))
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdDupGen(c *CPU, i *inst) {
	esize := 1 << i.sz
	v := c.R[i.rn]
	var out Vec
	for l := 0; l < int(i.imm); l++ {
		setLane(&out, esize, l, v)
	}
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdInsElem(c *CPU, i *inst) {
	esize := 1 << i.sz
	v := getLane(c.V[i.rn], esize, int(i.sh))
	out := c.V[i.rd]
	setLane(&out, esize, int(i.amt), v)
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdInsGen(c *CPU, i *inst) {
	esize := 1 << i.sz
	out := c.V[i.rd]
	setLane(&out, esize, int(i.amt), c.R[i.rn])
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdUmov(c *CPU, i *inst) {
	c.R[i.rd] = getLane(c.V[i.rn], 1<<i.sz, int(i.amt))
	c.PC += 4
}

func opSimdSmov64(c *CPU, i *inst) {
	esize := 1 << i.sz
	c.R[i.rd] = uint64(sxLane(getLane(c.V[i.rn], esize, int(i.amt)), esize))
	c.PC += 4
}

func opSimdSmov32(c *CPU, i *inst) {
	esize := 1 << i.sz
	c.R[i.rd] = uint64(uint32(sxLane(getLane(c.V[i.rn], esize, int(i.amt)), esize)))
	c.PC += 4
}

// ---- modified immediate ----------------------------------------------------

func decodeSIMDModImm(in *inst, raw uint32) {
	op, cmode, o2, q := (raw>>29)&1, (raw>>12)&15, (raw>>11)&1, (raw>>30)&1
	imm8 := (raw>>5)&0x1f | (raw>>11)&0xe0
	if o2 != 0 {
		return // o2 selects the half-precision FMOV, which needs FEAT_FP16
	}
	if cmode == 15 && op == 1 && q == 0 {
		return // FMOV Vd.2D exists only in the 128-bit form
	}
	imm, ok := advSIMDExpandImm(op, cmode, uint64(imm8))
	if !ok {
		return
	}
	in.rd = uint8(raw & 31)
	in.imm = imm
	in.sh = uint8(q)
	// cmode 0xx1 / 10x1 with op=0 -> ORR immediate; with op=1 -> BIC immediate
	switch {
	case cmode&9 == 1 || cmode&13 == 9: // cmode 0xx1 / 10x1: ORR / BIC
		if op == 0 {
			in.fn = opSimdOrrImm
		} else {
			in.fn = opSimdBicImm
		}
	default: // MOVI / MVNI
		if op == 1 && cmode>>1 != 7 {
			in.imm = ^imm // MVNI
		}
		in.fn = opSimdMovImm
	}
}

// advSIMDExpandImm is the architectural AdvSIMDExpandImm, returning the
// replicated 64-bit element value.
func advSIMDExpandImm(op, cmode uint32, imm8 uint64) (uint64, bool) {
	rep32 := func(v uint64) uint64 { return v<<32 | v }
	rep16 := func(v uint64) uint64 { v &= 0xffff; return v<<48 | v<<32 | v<<16 | v }
	rep8 := func(v uint64) uint64 {
		v &= 0xff
		v |= v << 8
		v |= v << 16
		return v | v<<32
	}
	switch cmode >> 1 {
	case 0:
		return rep32(imm8), true
	case 1:
		return rep32(imm8 << 8), true
	case 2:
		return rep32(imm8 << 16), true
	case 3:
		return rep32(imm8 << 24), true
	case 4:
		return rep16(imm8), true
	case 5:
		return rep16(imm8 << 8), true
	case 6:
		if cmode&1 == 0 {
			return rep32(imm8<<8 | 0xff), true
		}
		return rep32(imm8<<16 | 0xffff), true
	case 7:
		switch {
		case cmode&1 == 0 && op == 0:
			return rep8(imm8), true
		case cmode&1 == 0 && op == 1: // MOVI (64-bit byte mask)
			var v uint64
			for k := uint(0); k < 8; k++ {
				if imm8>>k&1 != 0 {
					v |= 0xff << (8 * k)
				}
			}
			return v, true
		case op == 0: // FMOV single precision
			f := imm8>>7<<31 | (^(imm8>>6)&1)<<30 | (imm8>>6&1)*0x1f<<25 | (imm8&0x3f)<<19
			return rep32(f), true
		default: // FMOV double precision
			return imm8>>7<<63 | (^(imm8>>6)&1)<<62 | (imm8>>6&1)*0xff<<54 | (imm8&0x3f)<<48, true
		}
	}
	return 0, false
}

func opSimdMovImm(c *CPU, i *inst) {
	if i.sh == 1 {
		c.V[i.rd] = Vec{i.imm, i.imm}
	} else {
		c.V[i.rd] = Vec{i.imm, 0}
	}
	c.PC += 4
}

func opSimdOrrImm(c *CPU, i *inst) {
	c.V[i.rd][0] |= i.imm
	if i.sh == 1 {
		c.V[i.rd][1] |= i.imm
	} else {
		c.V[i.rd][1] = 0
	}
	c.PC += 4
}

func opSimdBicImm(c *CPU, i *inst) {
	c.V[i.rd][0] &^= i.imm
	if i.sh == 1 {
		c.V[i.rd][1] &^= i.imm
	} else {
		c.V[i.rd][1] = 0
	}
	c.PC += 4
}

// ---- shift by immediate ----------------------------------------------------

// AdvSIMD shift-by-immediate selectors, numbered U<<5|opcode.
const (
	shSSHR  = 0b000000
	shUSHR  = 0b100000
	shSSRA  = 0b000010
	shUSRA  = 0b100010
	shSRI   = 0b101000
	shSHL   = 0b001010
	shSLI   = 0b101010
	shSHRN  = 0b010000
	shRSHRN = 0b010001
	shSSHLL = 0b010100
	shUSHLL = 0b110100
)

func decodeSIMDShiftImm(in *inst, raw uint32, scalar bool) {
	u, immh, immb, opcode, q := (raw>>29)&1, (raw>>19)&15, (raw>>16)&7, (raw>>11)&31, (raw>>30)&1
	if immh == 0 {
		return
	}
	size := 3
	switch {
	case immh&8 != 0:
		size = 3
	case immh&4 != 0:
		size = 2
	case immh&2 != 0:
		size = 1
	default:
		size = 0
	}
	if !scalar && size == 3 && q == 0 {
		return
	}
	esize := uint32(8 << size)
	shiftR := esize*2 - (immh<<3 | immb)
	shiftL := (immh<<3 | immb) - esize
	in.rd, in.rn = uint8(raw&31), uint8((raw>>5)&31)
	in.sz = uint8(size)
	if scalar {
		in.amt = 1
	} else {
		in.amt = uint8(int(8<<q) >> size)
	}
	in.sh = uint8(q)
	sel := u<<5 | opcode
	in.imm = uint64(sel)
	switch sel {
	case shSSHR, shUSHR, shSSRA, shUSRA, shSRI:
		in.imm2 = uint64(shiftR)
	case shSHL, shSLI:
		in.imm2 = uint64(shiftL)
	case shSSHLL, shUSHLL: // SXTL / UXTL are these with shift 0
		if scalar || size == 3 {
			return
		}
		in.imm2 = uint64(shiftL)
		in.fn = opSimdShllImm
		return
	case shSHRN, shRSHRN:
		if scalar || size == 3 {
			return
		}
		in.imm2 = uint64(shiftR)
		in.fn = opSimdShrnImm
		return
	default:
		return
	}
	if scalar && immh&8 == 0 {
		return // scalar SSHR/USHR/SHL/... are 64-bit only
	}
	in.fn = opSimdShiftImm
}

func opSimdShiftImm(c *CPU, i *inst) {
	esize := 1 << i.sz
	nb := uint(esize) * 8
	lanes := int(i.amt)
	n, d := c.V[i.rn], c.V[i.rd]
	var out Vec
	for l := 0; l < lanes; l++ {
		a := getLane(n, esize, l)
		var r uint64
		switch i.imm {
		case shSSHR:
			r = uint64(sxLane(a, esize) >> i.imm2)
		case shUSHR:
			r = a >> i.imm2
			if i.imm2 >= uint64(nb) {
				r = 0
			}
		case shSSRA:
			r = getLane(d, esize, l) + uint64(sxLane(a, esize)>>i.imm2)
		case shUSRA:
			v := a >> i.imm2
			if i.imm2 >= uint64(nb) {
				v = 0
			}
			r = getLane(d, esize, l) + v
		case shSHL:
			r = a << i.imm2
		case shSRI:
			m := mask(nb) >> i.imm2
			r = getLane(d, esize, l)&^m | (a>>i.imm2)&m
		case shSLI:
			m := mask(nb) << i.imm2
			r = getLane(d, esize, l)&^m | (a<<i.imm2)&m
		}
		setLane(&out, esize, l, r)
	}
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdShllImm(c *CPU, i *inst) {
	esize := 1 << i.sz
	lanes := 8 / esize
	base := 0
	if i.sh == 1 {
		base = lanes
	}
	n := c.V[i.rn]
	var out Vec
	for l := 0; l < lanes; l++ {
		v := getLane(n, esize, base+l)
		if i.imm == shSSHLL {
			v = uint64(sxLane(v, esize))
		}
		setLane(&out, esize*2, l, v<<i.imm2)
	}
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdShrnImm(c *CPU, i *inst) {
	esize := 1 << i.sz
	lanes := 8 / esize
	base := 0
	out := c.V[i.rd]
	if i.sh == 1 {
		base = lanes
	} else {
		out = Vec{}
	}
	n := c.V[i.rn]
	for l := 0; l < lanes; l++ {
		v := getLane(n, esize*2, l)
		r := v >> i.imm2
		if i.imm == shRSHRN { // round
			r = (v + 1<<(i.imm2-1)) >> i.imm2
		}
		setLane(&out, esize, base+l, r)
	}
	c.V[i.rd] = out
	c.PC += 4
}

// ---- EXT, permute, table lookup -------------------------------------------

func decodeSIMDExt(in *inst, raw uint32) {
	if (raw>>22)&3 != 0 || (raw>>31)&1 != 0 {
		return
	}
	q, imm4 := (raw>>30)&1, (raw>>11)&15
	if q == 0 && imm4 >= 8 {
		return
	}
	in.rd, in.rn, in.rm = uint8(raw&31), uint8((raw>>5)&31), uint8((raw>>16)&31)
	in.imm = uint64(imm4)
	in.sh = uint8(q)
	in.fn = opSimdExt
}

func opSimdExt(c *CPU, i *inst) {
	size := 8 << i.sh
	var buf [32]byte
	putVec(buf[:16], c.V[i.rn])
	putVec(buf[16:], c.V[i.rm])
	if i.sh == 0 {
		putVec(buf[8:24], c.V[i.rm]) // D form: operands are 8 bytes each
	}
	var out Vec
	var tmp [16]byte
	copy(tmp[:size], buf[i.imm:int(i.imm)+size])
	out = loadVec(tmp[:])
	c.V[i.rd] = out
	c.PC += 4
}

func putVec(b []byte, v Vec) {
	for k := 0; k < 8; k++ {
		b[k] = byte(v[0] >> (8 * k))
		b[8+k] = byte(v[1] >> (8 * k))
	}
}

func loadVec(b []byte) Vec {
	var v Vec
	for k := 0; k < 8; k++ {
		v[0] |= uint64(b[k]) << (8 * k)
		v[1] |= uint64(b[8+k]) << (8 * k)
	}
	return v
}

func decodeSIMDPermute(in *inst, raw uint32) {
	size, opcode, q := (raw>>22)&3, (raw>>12)&7, (raw>>30)&1
	if size == 3 && q == 0 {
		return
	}
	switch opcode {
	case 1, 2, 3, 5, 6, 7: // UZP1, TRN1, ZIP1, UZP2, TRN2, ZIP2
	default:
		return
	}
	simdGeom(in, raw, false, size)
	in.imm = uint64(opcode)
	in.fn = opSimdPermute
}

func opSimdPermute(c *CPU, i *inst) {
	esize := 1 << i.sz
	lanes := int(i.amt)
	n, m := c.V[i.rn], c.V[i.rm]
	part := int(i.imm >> 2) // 0 for *1 forms, 1 for *2 forms
	var out Vec
	switch i.imm & 3 {
	case 1: // UZP
		for l := 0; l < lanes; l++ {
			idx := 2*l + part
			v := n
			if idx >= lanes {
				v, idx = m, idx-lanes
			}
			setLane(&out, esize, l, getLane(v, esize, idx))
		}
	case 2: // TRN
		for l := 0; l < lanes/2; l++ {
			setLane(&out, esize, 2*l, getLane(n, esize, 2*l+part))
			setLane(&out, esize, 2*l+1, getLane(m, esize, 2*l+part))
		}
	case 3: // ZIP
		base := part * lanes / 2
		for l := 0; l < lanes/2; l++ {
			setLane(&out, esize, 2*l, getLane(n, esize, base+l))
			setLane(&out, esize, 2*l+1, getLane(m, esize, base+l))
		}
	}
	c.V[i.rd] = out
	c.PC += 4
}

func decodeSIMDTable(in *inst, raw uint32) {
	if (raw>>22)&3 != 0 {
		return
	}
	in.rd, in.rn, in.rm = uint8(raw&31), uint8((raw>>5)&31), uint8((raw>>16)&31)
	in.sh = uint8((raw >> 30) & 1)    // Q
	in.imm = uint64((raw >> 13) & 3)  // len: tables - 1
	in.imm2 = uint64((raw >> 12) & 1) // op: 0 = TBL (zero fill), 1 = TBX (keep)
	in.fn = opSimdTable
}

func opSimdTable(c *CPU, i *inst) {
	lanes := 8 << i.sh
	tables := int(i.imm) + 1
	var tbl [64]byte
	for t := 0; t < tables; t++ {
		putVec(tbl[t*16:], c.V[(int(i.rn)+t)&31])
	}
	limit := uint64(tables * 16)
	idx := c.V[i.rm]
	out := c.V[i.rd]
	if i.imm2 == 0 {
		out = Vec{}
	}
	for l := 0; l < lanes; l++ {
		k := getLane(idx, 1, l)
		if k < limit {
			setLane(&out, 1, l, uint64(tbl[k]))
		}
	}
	if i.sh == 0 {
		out[1] = 0
	}
	c.V[i.rd] = out
	c.PC += 4
}
