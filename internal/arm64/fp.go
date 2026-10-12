package arm64

import "math"

// Floating point. Single-precision operations are carried out in float32 so
// they round once, as the architecture requires; double-precision in float64.
// FPCR is honoured only for the rounding mode of explicit rounding
// instructions — the default (round-to-nearest-even, no flush-to-zero) is what
// Android code runs with, and matches Go's native arithmetic.

// FP operand types (bits 23:22 of the scalar encodings).
const (
	ftSingle = 0
	ftDouble = 1
	ftHalf   = 3
)

// rounding modes
const (
	rmNearest = iota // ties to even
	rmPlus
	rmMinus
	rmZero
	rmAway // ties away from zero
)

// f32 and b32 convert between a single-precision lane and float64. NaNs go
// across bit by bit rather than through the hardware conversion, which quietens
// a signaling NaN on the way up — and the architecture distinguishes the two: a
// signaling NaN makes an operation invalid (default NaN), a quiet one
// propagates.
func f32(b uint64) float64 {
	u := uint32(b)
	if u&0x7f800000 == 0x7f800000 && u&0x007fffff != 0 { // NaN
		return math.Float64frombits(uint64(u>>31)<<63 | 0x7ff<<52 | uint64(u&0x7fffff)<<29)
	}
	return float64(math.Float32frombits(u))
}

func b32(v float64) uint64 {
	u := math.Float64bits(v)
	if u&0x7ff0000000000000 == 0x7ff0000000000000 && u&0xfffffffffffff != 0 { // NaN
		frac := uint32(u>>29) & 0x7fffff
		if frac == 0 {
			frac = 0x400000 // never let the payload collapse into an infinity
		}
		return uint64(uint32(u>>63)<<31 | 0x7f800000 | frac)
	}
	return uint64(math.Float32bits(float32(v)))
}

func f64(b uint64) float64 { return math.Float64frombits(b) }
func b64(v float64) uint64 { return math.Float64bits(v) }

// isSignalingNaN reports whether v is a signaling NaN (quiet bit clear).
func isSignalingNaN(v float64) bool {
	u := math.Float64bits(v)
	return u&0x7ff0000000000000 == 0x7ff0000000000000 && u&0xfffffffffffff != 0 && u&(1<<51) == 0
}

// half-precision conversion (IEEE 754 binary16)
func f16(b uint64) float64 {
	h := uint16(b)
	sign := uint64(h>>15) << 63
	exp := int((h >> 10) & 0x1f)
	frac := uint64(h & 0x3ff)
	switch {
	case exp == 0:
		if frac == 0 {
			return math.Float64frombits(sign)
		}
		// subnormal: normalise
		e := -1
		for frac&0x400 == 0 {
			frac <<= 1
			e++
		}
		frac &= 0x3ff
		return math.Float64frombits(sign | uint64(1023-15-e)<<52 | frac<<42)
	case exp == 0x1f:
		if frac == 0 {
			return math.Float64frombits(sign | 0x7ff<<52)
		}
		return math.Float64frombits(sign | 0x7ff<<52 | frac<<42)
	default:
		return math.Float64frombits(sign | uint64(exp-15+1023)<<52 | frac<<42)
	}
}

func b16(v float64) uint64 {
	bits := math.Float64bits(v)
	sign := uint16(bits>>63) << 15
	exp := int((bits>>52)&0x7ff) - 1023
	frac := bits & (1<<52 - 1)
	switch {
	case math.IsNaN(v):
		return uint64(sign | 0x7e00)
	case math.IsInf(v, 0):
		return uint64(sign | 0x7c00)
	case v == 0:
		return uint64(sign)
	case exp > 15:
		return uint64(sign | 0x7c00)
	case exp < -24:
		return uint64(sign)
	case exp < -14: // subnormal
		sh := uint(-exp - 14)
		m := (frac | 1<<52) >> (42 + sh)
		return uint64(sign | uint16(m))
	default:
		// round to nearest even on the 10-bit significand
		m := frac >> 42
		rem := frac & (1<<42 - 1)
		if rem > 1<<41 || (rem == 1<<41 && m&1 == 1) {
			m++
			if m == 1<<10 {
				m = 0
				exp++
				if exp > 15 {
					return uint64(sign | 0x7c00)
				}
			}
		}
		return uint64(sign | uint16(exp+15)<<10 | uint16(m))
	}
}

// fpType holds the load/store/arith helpers for one operand type.
type fpOps struct {
	get func(uint64) float64
	put func(float64) uint64
	sz  int // bytes
}

var fpTypes = [4]fpOps{
	ftSingle: {f32, b32, 4},
	ftDouble: {f64, b64, 8},
	ftHalf:   {f16, b16, 2},
}

// single-precision results must round through float32
func (o fpOps) round(v float64) float64 {
	if o.sz == 4 {
		return float64(float32(v))
	}
	if o.sz == 2 {
		return f16(b16(v))
	}
	return v
}

func vfpExpandImm(imm8 uint64, ft int) uint64 {
	sign, exphi, frac := imm8>>7, (imm8>>6)&1, imm8&0x3f
	switch ft {
	case ftSingle:
		e := uint64(0)
		if exphi == 1 {
			e = 0x1f
		}
		return sign<<31 | (exphi^1)<<30 | e<<25 | frac<<19
	case ftDouble:
		e := uint64(0)
		if exphi == 1 {
			e = 0xff
		}
		return sign<<63 | (exphi^1)<<62 | e<<54 | frac<<48
	default:
		e := uint64(0)
		if exphi == 1 {
			e = 3
		}
		return sign<<15 | (exphi^1)<<14 | e<<12 | frac<<6
	}
}

// ---- scalar FP decode ------------------------------------------------------

func decodeFP(in *inst, raw uint32) {
	// Bit 31 is M (must be zero) in every group here except the integer
	// conversions, where it is sf and selects the 32- or 64-bit register.
	// Rejecting it outright would silently drop every 64-bit FMOV, FCVT and
	// SCVTF — which no amount of random differential testing would reveal,
	// since an instruction this decoder refuses is never offered as a case.
	m := (raw >> 31) & 1
	if (raw>>29)&1 != 0 { // S must be zero
		return
	}
	ft := int((raw >> 22) & 3)
	if ft == 2 {
		return
	}
	// Half-precision arithmetic is FEAT_FP16, which the CPU this interpreter
	// models does not have: only FCVT converts to and from half. Everything
	// else with type == 11 is undefined here.
	half := ft == ftHalf
	in.sz = uint8(ft)
	in.rd, in.rn, in.rm = uint8(raw&31), uint8((raw>>5)&31), uint8((raw>>16)&31)
	// Dispatch follows the encoding table exactly: bits 11:10 pick the group,
	// and within group 00 the next bits down separate FP immediate, compare,
	// one-source and the integer conversions. Loose masks here would accept
	// unallocated encodings that a real engine rejects.
	switch (raw >> 10) & 3 {
	case 1: // FP conditional compare (bit 4 picks FCCMP vs FCCMPE, same NZCV)
		if m != 0 || half {
			return
		}
		in.cond = uint8((raw >> 12) & 15)
		in.amt = uint8(raw & 15)
		in.fn = opFccmp
	case 2: // FP data-processing (2 source)
		opcode := (raw >> 12) & 15
		if m != 0 || half || opcode > 8 {
			return
		}
		in.imm = uint64(opcode)
		in.fn = opFP2
	case 3: // FP conditional select
		if m != 0 || half {
			return
		}
		in.cond = uint8((raw >> 12) & 15)
		in.fn = opFcsel
	case 0:
		switch {
		case (raw>>12)&1 == 1: // FP immediate
			if m != 0 || half || (raw>>5)&31 != 0 {
				return
			}
			in.imm = vfpExpandImm(uint64((raw>>13)&0xff), ft)
			in.fn = opFmovImm
		case (raw>>13)&1 == 1: // FP compare
			if m != 0 || half || (raw>>14)&3 != 0 || raw&7 != 0 {
				return
			}
			in.sh = uint8((raw >> 3) & 1) // compare against zero
			in.fn = opFcmp
		case (raw>>14)&1 == 1: // FP data-processing (1 source)
			if m != 0 {
				return
			}
			opcode := (raw >> 15) & 63
			if opcode>>2 == 1 { // FCVT between FP types
				dst := int(opcode & 3)
				if dst == 2 || dst == ft {
					return
				}
				in.sh = uint8(dst)
				in.fn = opFcvtFP
				return
			}
			if half {
				return
			}
			switch opcode {
			case 0, 1, 2, 3, 8, 9, 10, 11, 12, 14, 15:
				in.imm = uint64(opcode)
				in.fn = opFP1
			}
		case (raw>>15)&1 == 0: // conversion between FP and integer
			decodeFPInt(in, raw, ft)
			if half && in.fn != nil {
				in.fn = nil // FP16 <-> integer is FEAT_FP16
			}
		}
	}
}

func opFmovImm(c *CPU, i *inst) {
	c.V[i.rd] = Vec{i.imm, 0}
	c.PC += 4
}

// fpCompare yields the NZCV encoding of an AArch64 floating-point comparison.
func fpCompare(a, b float64) uint32 {
	switch {
	case math.IsNaN(a) || math.IsNaN(b):
		return flagC | flagV
	case a == b:
		return flagZ | flagC
	case a < b:
		return flagN
	default:
		return flagC
	}
}

func opFcmp(c *CPU, i *inst) {
	o := fpTypes[i.sz]
	a := o.get(c.V[i.rn][0])
	b := 0.0
	if i.sh == 0 {
		b = o.get(c.V[i.rm][0])
	}
	c.NZCV = fpCompare(a, b)
	c.PC += 4
}

func opFccmp(c *CPU, i *inst) {
	if !c.cond(i.cond) {
		c.NZCV = uint32(i.amt) << 28
	} else {
		o := fpTypes[i.sz]
		c.NZCV = fpCompare(o.get(c.V[i.rn][0]), o.get(c.V[i.rm][0]))
	}
	c.PC += 4
}

func opFcsel(c *CPU, i *inst) {
	src := i.rm
	if c.cond(i.cond) {
		src = i.rn
	}
	c.V[i.rd] = Vec{c.V[src][0] & mask(uint(fpTypes[i.sz].sz)*8), 0}
	c.PC += 4
}

func opFcvtFP(c *CPU, i *inst) {
	v := fpTypes[i.sz].get(c.V[i.rn][0])
	c.V[i.rd] = Vec{fpTypes[i.sh].put(v), 0}
	c.PC += 4
}

func opFP1(c *CPU, i *inst) {
	o := fpTypes[i.sz]
	a := o.get(c.V[i.rn][0])
	var r float64
	switch i.imm {
	case 0: // FMOV
		c.V[i.rd] = Vec{c.V[i.rn][0] & mask(uint(o.sz)*8), 0}
		c.PC += 4
		return
	case 1:
		r = math.Abs(a)
	case 2:
		r = -a
	case 3:
		r = nanFix(math.Sqrt(a), a)
	case 8:
		r = roundFP(a, rmNearest)
	case 9:
		r = roundFP(a, rmPlus)
	case 10:
		r = roundFP(a, rmMinus)
	case 11:
		r = roundFP(a, rmZero)
	case 12:
		r = roundFP(a, rmAway)
	case 14, 15: // FRINTX / FRINTI: use the FPCR rounding mode
		r = roundFP(a, fpcrRMode(c.FPCR))
	}
	c.V[i.rd] = Vec{o.put(o.round(r)), 0}
	c.PC += 4
}

func fpcrRMode(fpcr uint32) int {
	switch (fpcr >> 22) & 3 {
	case 0:
		return rmNearest
	case 1:
		return rmPlus
	case 2:
		return rmMinus
	default:
		return rmZero
	}
}

func roundFP(v float64, mode int) float64 {
	switch mode {
	case rmNearest:
		return math.RoundToEven(v)
	case rmPlus:
		return math.Ceil(v)
	case rmMinus:
		return math.Floor(v)
	case rmZero:
		return math.Trunc(v)
	default:
		return math.Round(v)
	}
}

func opFP2(c *CPU, i *inst) {
	o := fpTypes[i.sz]
	a, b := o.get(c.V[i.rn][0]), o.get(c.V[i.rm][0])
	var r float64
	switch i.imm {
	case 0:
		r = fpMul(a, b, o)
	case 1:
		r = fpDiv(a, b, o)
	case 2:
		r = fpAdd(a, b, o)
	case 3:
		r = fpSub(a, b, o)
	case 4:
		r = fpMax(a, b)
	case 5:
		r = fpMin(a, b)
	case 6:
		r = fpMaxNum(a, b)
	case 7:
		r = fpMinNum(a, b)
	case 8:
		r = -fpMul(a, b, o)
	}
	c.V[i.rd] = Vec{o.put(r), 0}
	c.PC += 4
}

// defaultNaN is the AArch64 default quiet NaN (positive). An invalid operation
// produces it; the host FPU does not necessarily agree — x86's SQRTSD returns
// the indefinite QNaN with the sign bit *set* — so every result that can be a
// NaN goes through nanFix.
var defaultNaN = math.Float64frombits(0x7ff8000000000000)

// nanFix applies the architectural NaN rules (FPProcessNaNs): a signaling
// input NaN wins over a quiet one whatever the operand order, is quietened,
// and propagates; a quiet one propagates unchanged; otherwise the operation
// was invalid and the result is the default NaN. ins must be in the order the
// architecture inspects the operands, which for a multiply-add is addend
// first.
func nanFix(res float64, ins ...float64) float64 {
	if !math.IsNaN(res) {
		return res
	}
	for _, v := range ins {
		if isSignalingNaN(v) {
			return math.Float64frombits(math.Float64bits(v) | 1<<51)
		}
	}
	for _, v := range ins {
		if math.IsNaN(v) {
			return v
		}
	}
	return defaultNaN
}

func fpAdd(a, b float64, o fpOps) float64 {
	if o.sz == 4 {
		return nanFix(float64(float32(a)+float32(b)), a, b)
	}
	return nanFix(a+b, a, b)
}

func fpSub(a, b float64, o fpOps) float64 {
	if o.sz == 4 {
		return nanFix(float64(float32(a)-float32(b)), a, b)
	}
	return nanFix(a-b, a, b)
}

func fpMul(a, b float64, o fpOps) float64 {
	if o.sz == 4 {
		return nanFix(float64(float32(a)*float32(b)), a, b)
	}
	return nanFix(a*b, a, b)
}

func fpDiv(a, b float64, o fpOps) float64 {
	if o.sz == 4 {
		return nanFix(float64(float32(a)/float32(b)), a, b)
	}
	return nanFix(a/b, a, b)
}

// FMAX/FMIN propagate NaN; FMAXNM/FMINNM return the number when one side is a
// quiet NaN.
func fpMax(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return nanFix(defaultNaN, a, b)
	}
	if a == 0 && b == 0 {
		if math.Signbit(a) {
			return b
		}
		return a
	}
	return math.Max(a, b)
}

func fpMin(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return nanFix(defaultNaN, a, b)
	}
	if a == 0 && b == 0 {
		if math.Signbit(a) {
			return a
		}
		return b
	}
	return math.Min(a, b)
}

// FMAXNM/FMINNM return the number when one side is a *quiet* NaN; a signaling
// NaN is still an invalid operation.
func fpMaxNum(a, b float64) float64 {
	if isSignalingNaN(a) || isSignalingNaN(b) {
		return nanFix(defaultNaN, a, b)
	}
	if math.IsNaN(a) {
		return b
	}
	if math.IsNaN(b) {
		return a
	}
	return fpMax(a, b)
}

func fpMinNum(a, b float64) float64 {
	if isSignalingNaN(a) || isSignalingNaN(b) {
		return nanFix(defaultNaN, a, b)
	}
	if math.IsNaN(a) {
		return b
	}
	if math.IsNaN(b) {
		return a
	}
	return fpMin(a, b)
}

func decodeFP3(in *inst, raw uint32) {
	if (raw>>31)&1 != 0 || (raw>>29)&1 != 0 {
		return
	}
	ft := int((raw >> 22) & 3)
	if ft == 2 || ft == ftHalf {
		return
	}
	in.sz = uint8(ft)
	in.rd, in.rn, in.rm, in.ra = uint8(raw&31), uint8((raw>>5)&31), uint8((raw>>16)&31), uint8((raw>>10)&31)
	in.imm = uint64((raw>>21)&1<<1 | (raw>>15)&1)
	in.fn = opFP3
}

func opFP3(c *CPU, i *inst) {
	o := fpTypes[i.sz]
	a, b, acc := o.get(c.V[i.rn][0]), o.get(c.V[i.rm][0]), o.get(c.V[i.ra][0])
	var r float64
	switch i.imm {
	case 0: // FMADD
		r = fma(a, b, acc, o)
	case 1: // FMSUB
		r = fma(-a, b, acc, o)
	case 2: // FNMADD
		r = fma(-a, b, -acc, o)
	default: // FNMSUB
		r = fma(a, b, -acc, o)
	}
	c.V[i.rd] = Vec{o.put(r), 0}
	c.PC += 4
}

// fma is a fused multiply-add: one rounding, as FMADD requires.
func fma(a, b, acc float64, o fpOps) float64 {
	if o.sz == 4 {
		// float32 FMA: math.FMA of the widened operands is exactly rounded in
		// float64, and float64 carries more than 2*24+2 bits, so narrowing the
		// result afterwards does not double-round.
		return nanFix(float64(float32(math.FMA(a, b, acc))), acc, a, b)
	}
	return nanFix(math.FMA(a, b, acc), acc, a, b)
}

// ---- FP <-> integer --------------------------------------------------------

func decodeFPInt(in *inst, raw uint32, ft int) {
	sf, rmode, opcode := (raw>>31)&1, (raw>>19)&3, (raw>>16)&7
	in.sh = uint8(sf)
	switch rmode<<3 | opcode {
	case 0b00110: // FMOV (to general)
		if (ft == ftSingle) != (sf == 0) {
			return
		}
		in.rd = xw(raw)
		in.fn = opFmovToGen
		return
	case 0b00111: // FMOV (from general)
		if (ft == ftSingle) != (sf == 0) {
			return
		}
		in.rn = xr(raw >> 5)
		in.fn = opFmovFromGen
		return
	case 0b01110: // FMOV Xd, Vn.D[1]
		if ft != 2 || sf == 0 {
			return
		}
		in.rd = xw(raw)
		in.fn = opFmovToGenHi
		return
	case 0b01111: // FMOV Vd.D[1], Xn
		if ft != 2 || sf == 0 {
			return
		}
		in.rn = xr(raw >> 5)
		in.fn = opFmovFromGenHi
		return
	}
	if ft == 2 {
		return
	}
	var mode int
	switch rmode {
	case 0:
		mode = rmNearest
	case 1:
		mode = rmPlus
	case 2:
		mode = rmMinus
	default:
		mode = rmZero
	}
	switch opcode {
	case 0, 1: // FCVT{N,P,M,Z}{S,U}
		in.rd = xw(raw)
		in.imm = uint64(mode)
		in.imm2 = uint64(opcode) // 0 signed, 1 unsigned
		in.fn = opFcvtToInt
	case 2, 3: // SCVTF / UCVTF
		if rmode != 0 {
			return
		}
		in.rn = xr(raw >> 5)
		in.imm2 = uint64(opcode - 2)
		in.fn = opCvtfFromInt
	case 4, 5: // FCVTA{S,U}
		if rmode != 0 {
			return
		}
		in.rd = xw(raw)
		in.imm = rmAway
		in.imm2 = uint64(opcode - 4)
		in.fn = opFcvtToInt
	}
}

func opFmovToGen(c *CPU, i *inst) {
	if i.sh == 0 {
		c.R[i.rd] = c.V[i.rn][0] & 0xffffffff
	} else {
		c.R[i.rd] = c.V[i.rn][0]
	}
	c.PC += 4
}

func opFmovFromGen(c *CPU, i *inst) {
	if i.sh == 0 {
		c.V[i.rd] = Vec{c.R[i.rn] & 0xffffffff, 0}
	} else {
		c.V[i.rd] = Vec{c.R[i.rn], 0}
	}
	c.PC += 4
}

func opFmovToGenHi(c *CPU, i *inst)   { c.R[i.rd] = c.V[i.rn][1]; c.PC += 4 }
func opFmovFromGenHi(c *CPU, i *inst) { c.V[i.rd][1] = c.R[i.rn]; c.PC += 4 }

func opFcvtToInt(c *CPU, i *inst) {
	v := fpTypes[i.sz].get(c.V[i.rn][0])
	n := uint(32)
	if i.sh == 1 {
		n = 64
	}
	c.R[i.rd] = fpToInt(v, i.imm2 == 0, n, int(i.imm))
	c.PC += 4
}

func opCvtfFromInt(c *CPU, i *inst) {
	var v float64
	if i.imm2 == 0 { // signed
		if i.sh == 1 {
			v = float64(int64(c.R[i.rn]))
		} else {
			v = float64(int32(c.R[i.rn]))
		}
	} else {
		if i.sh == 1 {
			v = float64(c.R[i.rn])
		} else {
			v = float64(uint32(c.R[i.rn]))
		}
	}
	c.V[i.rd] = Vec{fpTypes[i.sz].put(v), 0}
	c.PC += 4
}

// fpToInt converts with the given rounding mode and saturates, as FCVT* do.
func fpToInt(v float64, signed bool, n uint, mode int) uint64 {
	if math.IsNaN(v) {
		return 0
	}
	r := roundFP(v, mode)
	if signed {
		hi := float64(int64(mask(n - 1)))
		lo := -hi - 1
		if r >= hi {
			return mask(n-1) & mask(n)
		}
		if r <= lo {
			return (^mask(n - 1)) & mask(n)
		}
		return uint64(int64(r)) & mask(n)
	}
	if r <= 0 {
		return 0
	}
	if n == 64 {
		if r >= 18446744073709551616.0 {
			return ^uint64(0)
		}
		return uint64(r)
	}
	if r >= float64(mask(n)+1) {
		return mask(n)
	}
	return uint64(r)
}

// FP <-> fixed point
func decodeFPFixed(in *inst, raw uint32) {
	sf, rmode, opcode, scale := (raw>>31)&1, (raw>>19)&3, (raw>>16)&7, (raw>>10)&63
	ft := int((raw >> 22) & 3)
	if ft == 2 || ft == ftHalf || (raw>>29)&1 != 0 || (raw>>21)&1 != 0 {
		return
	}
	if sf == 0 && scale < 32 {
		return
	}
	in.sz = uint8(ft)
	in.sh = uint8(sf)
	in.rd, in.rn = uint8(raw&31), uint8((raw>>5)&31)
	in.imm = uint64(64 - scale) // fractional bits
	switch rmode<<3 | opcode {
	case 0b00010, 0b00011: // SCVTF / UCVTF (fixed)
		in.rn = xr(raw >> 5)
		in.imm2 = uint64(opcode - 2)
		in.fn = opCvtfFixed
	case 0b11000, 0b11001: // FCVTZS / FCVTZU (fixed)
		in.rd = xw(raw)
		in.imm2 = uint64(opcode)
		in.fn = opFcvtzFixed
	}
}

func opCvtfFixed(c *CPU, i *inst) {
	var v float64
	if i.imm2 == 0 {
		if i.sh == 1 {
			v = float64(int64(c.R[i.rn]))
		} else {
			v = float64(int32(c.R[i.rn]))
		}
	} else {
		if i.sh == 1 {
			v = float64(c.R[i.rn])
		} else {
			v = float64(uint32(c.R[i.rn]))
		}
	}
	v /= math.Ldexp(1, int(i.imm))
	c.V[i.rd] = Vec{fpTypes[i.sz].put(v), 0}
	c.PC += 4
}

func opFcvtzFixed(c *CPU, i *inst) {
	v := fpTypes[i.sz].get(c.V[i.rn][0])
	v = math.Ldexp(v, int(i.imm))
	n := uint(32)
	if i.sh == 1 {
		n = 64
	}
	c.R[i.rd] = fpToInt(v, i.imm2 == 0, n, rmZero)
	c.PC += 4
}

// ---- SIMD floating point ---------------------------------------------------

// vector FP operation selectors
const (
	vfADD = iota
	vfSUB
	vfMUL
	vfDIV
	vfMLA
	vfMLS
	vfMAX
	vfMIN
	vfMAXNM
	vfMINNM
	vfCMEQ
	vfCMGE
	vfCMGT
	vfACGE
	vfACGT
	vfABD
	vfADDP
	vfMULX
	vfRECPS
	vfRSQRTS
	vfMAXP
	vfMINP
	vfMAXNMP
	vfMINNMP
)

func decodeSIMD3SameFP(in *inst, raw uint32, scalar bool, u, size, opcode uint32) {
	a, sz := size>>1, size&1
	var op int
	switch u<<4 | a<<3 | (opcode & 7) {
	case 0b00000: // FMAXNM
		op = vfMAXNM
	case 0b01000:
		op = vfMINNM
	case 0b00001:
		op = vfMLA
	case 0b01001:
		op = vfMLS
	case 0b00010:
		op = vfADD
	case 0b01010:
		op = vfSUB
	case 0b00011:
		op = vfMULX
	case 0b00100:
		op = vfCMEQ
	case 0b00110:
		op = vfMAX
	case 0b01110:
		op = vfMIN
	case 0b00111:
		op = vfRECPS
	case 0b01111:
		op = vfRSQRTS
	case 0b10000:
		op = vfMAXNMP
	case 0b11000:
		op = vfMINNMP
	case 0b10010:
		op = vfADDP
	case 0b11010:
		op = vfABD
	case 0b10011:
		op = vfMUL
	case 0b10100:
		op = vfCMGE
	case 0b11100:
		op = vfCMGT
	case 0b10101:
		op = vfACGE
	case 0b11101:
		op = vfACGT
	case 0b10110:
		op = vfMAXP
	case 0b11110:
		op = vfMINP
	case 0b10111:
		op = vfDIV
	default:
		return
	}
	if scalar && !scalarFP3Same(op) {
		return
	}
	esize := uint32(2 + sz) // log2 bytes: 2 = single, 3 = double
	if !scalar && esize == 3 && (raw>>30)&1 == 0 {
		return
	}
	simdGeom(in, raw, scalar, esize)
	in.imm = uint64(op)
	switch op {
	case vfADDP, vfMAXP, vfMINP, vfMAXNMP, vfMINNMP:
		in.fn = opSimdFPPairwise
	default:
		in.fn = opSimdFP3
	}
}

// scalarFP3Same reports whether op exists in the AdvSIMD *scalar* three-same
// encoding. Most FP operations there (FADD, FMUL, FDIV, FMLA, ...) are
// vector-only — the scalar spellings live in the FP two-source group instead.
func scalarFP3Same(op int) bool {
	switch op {
	case vfMULX, vfCMEQ, vfRECPS, vfRSQRTS, vfCMGE, vfACGE, vfABD, vfCMGT, vfACGT:
		return true
	}
	return false
}

func fpVecOp(op int, a, b, dst float64, o fpOps) float64 {
	switch op {
	case vfADD:
		return fpAdd(a, b, o)
	case vfSUB:
		return fpSub(a, b, o)
	case vfMUL:
		return fpMul(a, b, o)
	case vfDIV:
		return fpDiv(a, b, o)
	case vfMLA:
		return fma(a, b, dst, o)
	case vfMLS:
		return fma(-a, b, dst, o)
	case vfMAX:
		return fpMax(a, b)
	case vfMIN:
		return fpMin(a, b)
	case vfMAXNM:
		return fpMaxNum(a, b)
	case vfMINNM:
		return fpMinNum(a, b)
	case vfABD:
		return math.Abs(fpSub(a, b, o))
	case vfRECPS, vfRSQRTS:
		// FPRecipStepFused / FPRSqrtStepFused. Both negate op1 first, and the
		// negation happens *before* NaN processing — so a negative NaN comes
		// back positive. A zero against an infinity gives the step constant
		// rather than the NaN that 2 - (0 * inf) would produce.
		na := -a
		if math.IsNaN(na) || math.IsNaN(b) {
			return nanFix(defaultNaN, na, b)
		}
		if (math.IsInf(na, 0) && b == 0) || (na == 0 && math.IsInf(b, 0)) {
			if op == vfRECPS {
				return 2
			}
			return 1.5
		}
		if op == vfRECPS {
			return fma(na, b, 2, o) // fused: the product is not rounded first
		}
		// (3 + na*b)/2 with a single rounding. Halving the fused sum is exact
		// (the sum is never subnormal: it is either zero or bounded below by
		// the cancellation limit of a double product), so this is exact
		// whenever the sum itself is representable.
		if r := fma(na, b, 3, o); !math.IsInf(r, 0) {
			return r / 2
		}
		// The sum overflowed, yet the halved result may still be finite. At
		// that magnitude the 3 is negligible and b is necessarily large, so
		// halving b first is exact — unlike in the general case, where b can
		// be subnormal and would lose its last bit.
		return fma(na, b/2, 1.5, o)
	case vfMULX:
		// FMULX turns the invalid zero-times-infinity into +-2.0
		if (a == 0 && math.IsInf(b, 0)) || (math.IsInf(a, 0) && b == 0) {
			if math.Signbit(a) != math.Signbit(b) {
				return -2
			}
			return 2
		}
		return fpMul(a, b, o)
	}
	return 0
}

func fpVecCmp(op int, a, b float64) bool {
	switch op {
	case vfCMEQ:
		return a == b
	case vfCMGE:
		return a >= b
	case vfCMGT:
		return a > b
	case vfACGE:
		return math.Abs(a) >= math.Abs(b)
	default:
		return math.Abs(a) > math.Abs(b)
	}
}

func opSimdFP3(c *CPU, i *inst) {
	esize := 1 << i.sz
	o := fpTypes[ftSingle]
	if esize == 8 {
		o = fpTypes[ftDouble]
	}
	lanes := int(i.amt)
	n, m, d := c.V[i.rn], c.V[i.rm], c.V[i.rd]
	op := int(i.imm)
	var out Vec
	for l := 0; l < lanes; l++ {
		a, b := o.get(getLane(n, esize, l)), o.get(getLane(m, esize, l))
		switch op {
		case vfCMEQ, vfCMGE, vfCMGT, vfACGE, vfACGT:
			setLane(&out, esize, l, boolLane(fpVecCmp(op, a, b), uint(esize)*8))
		default:
			r := fpVecOp(op, a, b, o.get(getLane(d, esize, l)), o)
			setLane(&out, esize, l, o.put(r))
		}
	}
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdFPPairwise(c *CPU, i *inst) {
	esize := 1 << i.sz
	o := fpTypes[ftSingle]
	if esize == 8 {
		o = fpTypes[ftDouble]
	}
	lanes := int(i.amt)
	src := [2]Vec{c.V[i.rn], c.V[i.rm]}
	var out Vec
	for l := 0; l < lanes; l++ {
		p := l * 2
		v := src[p/lanes]
		a := o.get(getLane(v, esize, p%lanes))
		b := o.get(getLane(v, esize, p%lanes+1))
		var r float64
		switch i.imm {
		case vfADDP:
			r = fpAdd(a, b, o)
		case vfMAXP:
			r = fpMax(a, b)
		case vfMINP:
			r = fpMin(a, b)
		case vfMAXNMP:
			r = fpMaxNum(a, b)
		case vfMINNMP:
			r = fpMinNum(a, b)
		}
		setLane(&out, esize, l, o.put(r))
	}
	c.V[i.rd] = out
	c.PC += 4
}

// scalar pairwise (ADDP / FADDP / FMAXP ... with one destination lane)
func decodeSIMDPairScalar(in *inst, raw uint32) {
	u, size, opcode := (raw>>29)&1, (raw>>22)&3, (raw>>12)&31
	in.rd, in.rn = uint8(raw&31), uint8((raw>>5)&31)
	switch {
	case u == 0 && opcode == 0b11011: // ADDP (scalar, 2 x 64-bit)
		if size != 3 {
			return
		}
		in.sz = 3
		in.fn = opSimdAddpScalar
	case u == 1 && (opcode == 0b01101 || opcode == 0b01111 || opcode == 0b01100 || opcode == 0b01110):
		// FADDP / FMAXP / FMAXNMP / FMINP / FMINNMP (scalar)
		sz := size & 1
		in.sz = uint8(2 + sz)
		switch size>>1<<3 | (opcode & 7) {
		case 0b0101:
			in.imm = vfADDP
		case 0b0111:
			in.imm = vfMAXP
		case 0b1111:
			in.imm = vfMINP
		case 0b0100:
			in.imm = vfMAXNMP
		case 0b1100:
			in.imm = vfMINNMP
		default:
			return
		}
		in.fn = opSimdFPPairScalar
	}
}

func opSimdAddpScalar(c *CPU, i *inst) {
	n := c.V[i.rn]
	c.V[i.rd] = Vec{n[0] + n[1], 0}
	c.PC += 4
}

func opSimdFPPairScalar(c *CPU, i *inst) {
	esize := 1 << i.sz
	o := fpTypes[ftSingle]
	if esize == 8 {
		o = fpTypes[ftDouble]
	}
	n := c.V[i.rn]
	a, b := o.get(getLane(n, esize, 0)), o.get(getLane(n, esize, 1))
	var r float64
	switch i.imm {
	case vfADDP:
		r = fpAdd(a, b, o)
	case vfMAXP:
		r = fpMax(a, b)
	case vfMINP:
		r = fpMin(a, b)
	case vfMAXNMP:
		r = fpMaxNum(a, b)
	case vfMINNMP:
		r = fpMinNum(a, b)
	}
	c.V[i.rd] = Vec{o.put(r), 0}
	c.PC += 4
}

// 2-register misc, FP subgroup
const (
	vmFABS = iota
	vmFNEG
	vmFSQRT
	vmFCVTZS
	vmFCVTZU
	vmSCVTF
	vmUCVTF
	vmFCMEQ0
	vmFCMGE0
	vmFCMGT0
	vmFCMLE0
	vmFCMLT0
	vmFRINTN
	vmFRINTP
	vmFRINTM
	vmFRINTZ
	vmFRINTA
	vmFRINTI
	vmFCVTAS
	vmFCVTAU
	vmFCVTNS
	vmFCVTNU
	vmFCVTMS
	vmFCVTMU
	vmFCVTPS
	vmFCVTPU
	vmFCVTL
	vmFCVTN
)

// decodeSIMD2MiscFP decodes the floating-point half of two-register misc. Bit
// 23 ("a") discriminates opcodes alongside U — including for the compare-with-
// zero and FABS/FNEG rows, which exist only with a == 1 — and bit 22 selects
// single or double precision.
func decodeSIMD2MiscFP(in *inst, raw uint32, scalar bool, u, size, opcode uint32) {
	a, sz := size>>1, size&1
	var op int
	switch u<<6 | a<<5 | opcode {
	case 0b0101100:
		op = vmFCMGT0
	case 0b0101101:
		op = vmFCMEQ0
	case 0b0101110:
		op = vmFCMLT0
	case 0b0101111:
		op = vmFABS
	case 0b0011000:
		op = vmFRINTN
	case 0b0011001:
		op = vmFRINTM
	case 0b0011010:
		op = vmFCVTNS
	case 0b0011011:
		op = vmFCVTMS
	case 0b0011100:
		op = vmFCVTAS
	case 0b0011101:
		op = vmSCVTF
	case 0b0111000:
		op = vmFRINTP
	case 0b0111001:
		op = vmFRINTZ
	case 0b0111010:
		op = vmFCVTPS
	case 0b0111011:
		op = vmFCVTZS
	case 0b1101100:
		op = vmFCMGE0
	case 0b1101101:
		op = vmFCMLE0
	case 0b1101111:
		op = vmFNEG
	case 0b1011000:
		op = vmFRINTA
	case 0b1011001:
		op = vmFRINTI
	case 0b1011010:
		op = vmFCVTNU
	case 0b1011011:
		op = vmFCVTMU
	case 0b1011100:
		op = vmFCVTAU
	case 0b1011101:
		op = vmUCVTF
	case 0b1111010:
		op = vmFCVTPU
	case 0b1111011:
		op = vmFCVTZU
	case 0b1111111:
		op = vmFSQRT
	case 0b0010111: // FCVTL / FCVTL2 (size selects source width)
		if scalar {
			return
		}
		in.rd, in.rn = uint8(raw&31), uint8((raw>>5)&31)
		in.sz = uint8(2 + sz)
		in.sh = uint8((raw >> 30) & 1)
		in.imm = vmFCVTL
		in.fn = opSimdFcvtWiden
		return
	case 0b0010110: // FCVTN / FCVTN2
		if scalar {
			return
		}
		in.rd, in.rn = uint8(raw&31), uint8((raw>>5)&31)
		in.sz = uint8(2 + sz)
		in.sh = uint8((raw >> 30) & 1)
		in.imm = vmFCVTN
		in.fn = opSimdFcvtNarrow
		return
	default:
		return
	}
	if scalar && !scalarFP2Misc(op) {
		return
	}
	esize := uint32(2 + sz)
	if !scalar && esize == 3 && (raw>>30)&1 == 0 {
		return
	}
	simdGeom(in, raw, scalar, esize)
	in.imm = uint64(op)
	in.fn = opSimd2MiscFP
}

// scalarFP2Misc reports whether op exists in the AdvSIMD *scalar* two-register
// misc encoding: the conversions and the compare-against-zero forms do, while
// FABS/FNEG/FSQRT/FRINT* are vector-only (their scalar spellings are in the FP
// one-source group).
func scalarFP2Misc(op int) bool {
	switch op {
	case vmFABS, vmFNEG, vmFSQRT, vmFRINTN, vmFRINTP, vmFRINTM, vmFRINTZ, vmFRINTA, vmFRINTI:
		return false
	}
	return true
}

func opSimd2MiscFP(c *CPU, i *inst) {
	esize := 1 << i.sz
	o := fpTypes[ftSingle]
	if esize == 8 {
		o = fpTypes[ftDouble]
	}
	lanes := int(i.amt)
	n := c.V[i.rn]
	nb := uint(esize) * 8
	var out Vec
	for l := 0; l < lanes; l++ {
		raw := getLane(n, esize, l)
		a := o.get(raw)
		var r uint64
		switch i.imm {
		case vmFABS:
			r = o.put(math.Abs(a))
		case vmFNEG:
			r = o.put(-a)
		case vmFSQRT:
			r = o.put(nanFix(math.Sqrt(a), a))
		case vmFRINTN:
			r = o.put(roundFP(a, rmNearest))
		case vmFRINTP:
			r = o.put(roundFP(a, rmPlus))
		case vmFRINTM:
			r = o.put(roundFP(a, rmMinus))
		case vmFRINTZ:
			r = o.put(roundFP(a, rmZero))
		case vmFRINTA:
			r = o.put(roundFP(a, rmAway))
		case vmFRINTI:
			r = o.put(roundFP(a, fpcrRMode(c.FPCR)))
		case vmFCVTZS:
			r = fpToInt(a, true, nb, rmZero)
		case vmFCVTZU:
			r = fpToInt(a, false, nb, rmZero)
		case vmFCVTNS:
			r = fpToInt(a, true, nb, rmNearest)
		case vmFCVTNU:
			r = fpToInt(a, false, nb, rmNearest)
		case vmFCVTMS:
			r = fpToInt(a, true, nb, rmMinus)
		case vmFCVTMU:
			r = fpToInt(a, false, nb, rmMinus)
		case vmFCVTPS:
			r = fpToInt(a, true, nb, rmPlus)
		case vmFCVTPU:
			r = fpToInt(a, false, nb, rmPlus)
		case vmFCVTAS:
			r = fpToInt(a, true, nb, rmAway)
		case vmFCVTAU:
			r = fpToInt(a, false, nb, rmAway)
		case vmSCVTF:
			if esize == 8 {
				r = o.put(float64(int64(raw)))
			} else {
				r = o.put(float64(int32(uint32(raw))))
			}
		case vmUCVTF:
			if esize == 8 {
				r = o.put(float64(raw))
			} else {
				r = o.put(float64(uint32(raw)))
			}
		case vmFCMEQ0:
			r = boolLane(a == 0, nb)
		case vmFCMGE0:
			r = boolLane(a >= 0, nb)
		case vmFCMGT0:
			r = boolLane(a > 0, nb)
		case vmFCMLE0:
			r = boolLane(a <= 0, nb)
		case vmFCMLT0:
			r = boolLane(a < 0, nb)
		}
		setLane(&out, esize, l, r)
	}
	c.V[i.rd] = out
	c.PC += 4
}

// FCVTL: widen half->single or single->double
func opSimdFcvtWiden(c *CPU, i *inst) {
	src := 2
	if i.sz == 3 {
		src = 4
	}
	lanes := 8 / src
	base := 0
	if i.sh == 1 {
		base = lanes
	}
	from := fpTypes[ftHalf]
	to := fpTypes[ftSingle]
	if src == 4 {
		from, to = fpTypes[ftSingle], fpTypes[ftDouble]
	}
	n := c.V[i.rn]
	var out Vec
	for l := 0; l < lanes; l++ {
		out1 := to.put(from.get(getLane(n, src, base+l)))
		setLane(&out, src*2, l, out1)
	}
	c.V[i.rd] = out
	c.PC += 4
}

// FCVTN: narrow single->half or double->single
func opSimdFcvtNarrow(c *CPU, i *inst) {
	dst := 2
	if i.sz == 3 {
		dst = 4
	}
	lanes := 8 / dst
	base := 0
	out := c.V[i.rd]
	if i.sh == 1 {
		base = lanes
	} else {
		out = Vec{}
	}
	from := fpTypes[ftSingle]
	to := fpTypes[ftHalf]
	if dst == 4 {
		from, to = fpTypes[ftDouble], fpTypes[ftSingle]
	}
	n := c.V[i.rn]
	for l := 0; l < lanes; l++ {
		setLane(&out, dst, base+l, to.put(from.get(getLane(n, dst*2, l))))
	}
	c.V[i.rd] = out
	c.PC += 4
}

// across lanes, FP subgroup (FMAXNMV / FMAXV / FMINNMV / FMINV)
func decodeSIMDAcrossFP(in *inst, raw uint32, u, size, opcode uint32) {
	if u != 1 || (opcode != 0b01100 && opcode != 0b01111) {
		return
	}
	sz := size & 1
	if sz != 0 || (raw>>30)&1 == 0 {
		return // only the 4 x single-precision form exists
	}
	simdGeom(in, raw, false, 2)
	if opcode == 0b01100 {
		if size>>1 == 0 {
			in.imm = vfMAXNM
		} else {
			in.imm = vfMINNM
		}
	} else {
		if size>>1 == 0 {
			in.imm = vfMAX
		} else {
			in.imm = vfMIN
		}
	}
	in.fn = opSimdFPAcross
}

func opSimdFPAcross(c *CPU, i *inst) {
	o := fpTypes[ftSingle]
	n := c.V[i.rn]
	acc := o.get(getLane(n, 4, 0))
	for l := 1; l < int(i.amt); l++ {
		v := o.get(getLane(n, 4, l))
		switch i.imm {
		case vfMAX:
			acc = fpMax(acc, v)
		case vfMIN:
			acc = fpMin(acc, v)
		case vfMAXNM:
			acc = fpMaxNum(acc, v)
		case vfMINNM:
			acc = fpMinNum(acc, v)
		}
	}
	c.V[i.rd] = Vec{o.put(acc), 0}
	c.PC += 4
}

// ---- indexed element -------------------------------------------------------

func decodeSIMDIndexed(in *inst, raw uint32, scalar bool) {
	u, size, l, m, opcode, h := (raw>>29)&1, (raw>>22)&3, (raw>>21)&1, (raw>>20)&1, (raw>>12)&15, (raw>>11)&1
	rmlo := (raw >> 16) & 15
	var rm, index uint32
	switch size {
	case 1: // 16-bit elements
		rm, index = rmlo, h<<2|l<<1|m
	case 2: // 32-bit
		rm, index = m<<4|rmlo, h<<1|l
	case 3: // 64-bit
		if l != 0 {
			return
		}
		rm, index = m<<4|rmlo, h
	default:
		return
	}
	in.rd, in.rn, in.rm = uint8(raw&31), uint8((raw>>5)&31), uint8(rm)
	in.ra = uint8(index)

	// FP forms: FMLA/FMLS/FMUL/FMULX with size as sz
	switch u<<4 | opcode {
	case 0b00001, 0b00101, 0b01001, 0b11001: // FMLA, FMLS, FMUL (U=0), FMULX (U=1)
		if size < 2 {
			return
		}
		esize := size
		if !scalar && esize == 3 && (raw>>30)&1 == 0 {
			return
		}
		in.sz = uint8(esize)
		if scalar {
			in.amt = 1
		} else {
			in.amt = uint8(int(8<<((raw>>30)&1)) >> esize)
		}
		switch opcode {
		case 0b0001:
			in.imm = vfMLA
		case 0b0101:
			in.imm = vfMLS
		case 0b1001:
			if u == 1 {
				in.imm = vfMULX
			} else {
				in.imm = vfMUL
			}
		}
		in.fn = opSimdFPIndexed
		return
	}
	// integer MUL / MLA / MLS by element
	switch u<<4 | opcode {
	case 0b01000: // MUL
		in.imm = sMUL
	case 0b10000: // MLA
		in.imm = sMLA
	case 0b10100: // MLS
		in.imm = sMLS
	default:
		return
	}
	if scalar || size == 0 || size == 3 {
		return
	}
	in.sz = uint8(size)
	in.amt = uint8(int(8<<((raw>>30)&1)) >> size)
	in.fn = opSimdIntIndexed
}

func opSimdFPIndexed(c *CPU, i *inst) {
	esize := 1 << i.sz
	o := fpTypes[ftSingle]
	if esize == 8 {
		o = fpTypes[ftDouble]
	}
	b := o.get(getLane(c.V[i.rm], esize, int(i.ra)))
	n, d := c.V[i.rn], c.V[i.rd]
	var out Vec
	for l := 0; l < int(i.amt); l++ {
		a := o.get(getLane(n, esize, l))
		r := fpVecOp(int(i.imm), a, b, o.get(getLane(d, esize, l)), o)
		setLane(&out, esize, l, o.put(r))
	}
	c.V[i.rd] = out
	c.PC += 4
}

func opSimdIntIndexed(c *CPU, i *inst) {
	esize := 1 << i.sz
	b := getLane(c.V[i.rm], esize, int(i.ra))
	n, d := c.V[i.rn], c.V[i.rd]
	var out Vec
	for l := 0; l < int(i.amt); l++ {
		a := getLane(n, esize, l)
		setLane(&out, esize, l, simdALU(uint32(i.imm), a, b, getLane(d, esize, l), esize))
	}
	c.V[i.rd] = out
	c.PC += 4
}
