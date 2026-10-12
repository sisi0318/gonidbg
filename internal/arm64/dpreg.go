package arm64

import (
	"hash/crc32"
	"math/bits"
)

// ---- data processing (register) --------------------------------------------

func decodeDPReg(in *inst, raw uint32) {
	sf := raw>>31 == 1
	rd, rn, rm := raw&31, (raw>>5)&31, (raw>>16)&31
	op1 := (raw >> 28) & 1
	op2 := (raw >> 21) & 15
	if op1 == 0 {
		switch {
		case op2&8 == 0: // logical (shifted register)
			imm6 := (raw >> 10) & 63
			if !sf && imm6 >= 32 {
				return
			}
			in.rd, in.rn, in.rm = xw(rd), xr(rn), xr(rm)
			in.sh, in.amt = uint8((raw>>22)&3), uint8(imm6)
			opc := (raw>>29)&3<<1 | (raw>>21)&1
			if opc == 2 && rn == 31 && imm6 == 0 { // MOV (register)
				if sf {
					in.fn = opMovReg64
				} else {
					in.fn = opMovReg32
				}
				return
			}
			if sf {
				in.fn = [8]func(*CPU, *inst){opAndReg64, opBicReg64, opOrrReg64, opOrnReg64,
					opEorReg64, opEonReg64, opAndsReg64, opBicsReg64}[opc]
			} else {
				in.fn = [8]func(*CPU, *inst){opAndReg32, opBicReg32, opOrrReg32, opOrnReg32,
					opEorReg32, opEonReg32, opAndsReg32, opBicsReg32}[opc]
			}
		case op2&1 == 0: // add/sub (shifted register)
			sh := (raw >> 22) & 3
			imm6 := (raw >> 10) & 63
			if sh == 3 || (!sf && imm6 >= 32) {
				return
			}
			in.rd, in.rn, in.rm = xw(rd), xr(rn), xr(rm)
			in.sh, in.amt = uint8(sh), uint8(imm6)
			in.fn = pick4x2(sf, (raw>>29)&3, opAddReg64, opAddsReg64, opSubReg64, opSubsReg64,
				opAddReg32, opAddsReg32, opSubReg32, opSubsReg32)
		default: // add/sub (extended register)
			imm3 := (raw >> 10) & 7
			if (raw>>22)&3 != 0 || imm3 > 4 {
				return
			}
			in.rn, in.rm = xsp(rn), xr(rm)
			if (raw>>29)&1 == 1 {
				in.rd = xw(rd)
			} else {
				in.rd = xsp(rd)
			}
			in.sh, in.amt = uint8((raw>>13)&7), uint8(imm3)
			in.fn = pick4x2(sf, (raw>>29)&3, opAddExt64, opAddsExt64, opSubExt64, opSubsExt64,
				opAddExt32, opAddsExt32, opSubExt32, opSubsExt32)
		}
		return
	}
	switch {
	case op2 == 0: // ADC/ADCS/SBC/SBCS
		if (raw>>10)&63 != 0 {
			return
		}
		in.rd, in.rn, in.rm = xw(rd), xr(rn), xr(rm)
		in.fn = pick4x2(sf, (raw>>29)&3, opAdc64, opAdcs64, opSbc64, opSbcs64,
			opAdc32, opAdcs32, opSbc32, opSbcs32)
	case op2 == 2: // CCMN/CCMP (register / immediate)
		if (raw>>29)&1 != 1 || (raw>>10)&1 != 0 || (raw>>4)&1 != 0 {
			return
		}
		in.rn = xr(rn)
		in.cond = uint8((raw >> 12) & 15)
		in.amt = uint8(raw & 15) // nzcv when the condition fails
		in.rm = xr(rm)
		in.imm = uint64(rm) // imm5
		imm := (raw >> 11) & 1
		sel := (raw>>30)&1<<1 | imm
		in.fn = pick4x2(sf, sel, opCcmnReg64, opCcmnImm64, opCcmpReg64, opCcmpImm64,
			opCcmnReg32, opCcmnImm32, opCcmpReg32, opCcmpImm32)
	case op2 == 4: // CSEL/CSINC/CSINV/CSNEG
		if (raw>>29)&1 != 0 || (raw>>11)&1 != 0 {
			return
		}
		in.rd, in.rn, in.rm = xw(rd), xr(rn), xr(rm)
		in.cond = uint8((raw >> 12) & 15)
		sel := (raw>>30)&1<<1 | (raw>>10)&1
		in.fn = pick4x2(sf, sel, opCsel64, opCsinc64, opCsinv64, opCsneg64,
			opCsel32, opCsinc32, opCsinv32, opCsneg32)
	case op2 == 6:
		in.rd, in.rn, in.rm = xw(rd), xr(rn), xr(rm)
		if (raw>>29)&1 != 0 {
			return
		}
		if (raw>>30)&1 == 0 {
			decodeDP2(in, raw, sf)
		} else {
			decodeDP1(in, raw, sf)
		}
	case op2&8 != 0: // data processing (3 source)
		if (raw>>29)&3 != 0 {
			return
		}
		in.rd, in.rn, in.rm, in.ra = xw(rd), xr(rn), xr(rm), xr((raw>>10)&31)
		op31, o0 := (raw>>21)&7, (raw>>15)&1
		switch op31<<1 | o0 {
		case 0:
			in.fn = pick(sf, opMadd64, opMadd32)
		case 1:
			in.fn = pick(sf, opMsub64, opMsub32)
		}
		if !sf {
			return
		}
		switch op31<<1 | o0 {
		case 2:
			in.fn = opSmaddl
		case 3:
			in.fn = opSmsubl
		case 4:
			in.fn = opSmulh
		case 10:
			in.fn = opUmaddl
		case 11:
			in.fn = opUmsubl
		case 12:
			in.fn = opUmulh
		}
	}
}

func pick(sf bool, a, b func(*CPU, *inst)) func(*CPU, *inst) {
	if sf {
		return a
	}
	return b
}

func decodeDP2(in *inst, raw uint32, sf bool) {
	switch op := (raw >> 10) & 63; op {
	case 2:
		in.fn = pick(sf, opUdiv64, opUdiv32)
	case 3:
		in.fn = pick(sf, opSdiv64, opSdiv32)
	case 8, 9, 10, 11:
		in.sh = uint8(op & 3)
		in.fn = pick(sf, opShiftV64, opShiftV32)
	case 16, 17, 18, 19, 20, 21, 22, 23: // CRC32{B,H,W,X}, CRC32C{B,H,W,X}
		sz := op & 3
		if (sz == 3) != sf {
			return
		}
		in.sz = uint8(1 << sz)
		if op&4 == 0 {
			in.fn = opCrc32
		} else {
			in.fn = opCrc32c
		}
	}
}

func decodeDP1(in *inst, raw uint32, sf bool) {
	if (raw>>16)&31 != 0 {
		return // PAC / other opcode2 groups
	}
	switch (raw >> 10) & 63 {
	case 0:
		in.fn = pick(sf, opRbit64, opRbit32)
	case 1:
		in.fn = pick(sf, opRev16_64, opRev16_32)
	case 2:
		in.fn = pick(sf, opRev32_64, opRev32)
	case 3:
		if sf {
			in.fn = opRev64
		}
	case 4:
		in.fn = pick(sf, opClz64, opClz32)
	case 5:
		in.fn = pick(sf, opCls64, opCls32)
	}
}

// shifted-register operand (sh: 0 LSL, 1 LSR, 2 ASR, 3 ROR)
func (c *CPU) shOp64(i *inst) uint64 {
	v := c.R[i.rm]
	switch i.sh {
	case 0:
		return v << i.amt
	case 1:
		return v >> i.amt
	case 2:
		return uint64(int64(v) >> i.amt)
	default:
		return bits.RotateLeft64(v, -int(i.amt))
	}
}

func (c *CPU) shOp32(i *inst) uint32 {
	v := uint32(c.R[i.rm])
	switch i.sh {
	case 0:
		return v << i.amt
	case 1:
		return v >> i.amt
	case 2:
		return uint32(int32(v) >> i.amt)
	default:
		return bits.RotateLeft32(v, -int(i.amt))
	}
}

// extended-register operand (sh: option, amt: left shift)
func (c *CPU) extOp(i *inst) uint64 {
	return extend(c.R[i.rm], i.sh) << i.amt
}

func extend(v uint64, option uint8) uint64 {
	switch option & 7 {
	case 0:
		return uint64(uint8(v))
	case 1:
		return uint64(uint16(v))
	case 2:
		return uint64(uint32(v))
	case 4:
		return uint64(int8(v))
	case 5:
		return uint64(int16(v))
	case 6:
		return uint64(int32(v))
	default:
		return v
	}
}

func opMovReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rm]; c.PC += 4 }
func opMovReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rm])); c.PC += 4 }

func opAndReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] & c.shOp64(i); c.PC += 4 }
func opBicReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] &^ c.shOp64(i); c.PC += 4 }
func opOrrReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] | c.shOp64(i); c.PC += 4 }
func opOrnReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] | ^c.shOp64(i); c.PC += 4 }
func opEorReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] ^ c.shOp64(i); c.PC += 4 }
func opEonReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] ^ ^c.shOp64(i); c.PC += 4 }

func opAndsReg64(c *CPU, i *inst) {
	r := c.R[i.rn] & c.shOp64(i)
	c.R[i.rd], c.NZCV = r, logicFlags64(r)
	c.PC += 4
}

func opBicsReg64(c *CPU, i *inst) {
	r := c.R[i.rn] &^ c.shOp64(i)
	c.R[i.rd], c.NZCV = r, logicFlags64(r)
	c.PC += 4
}

func opAndReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) & c.shOp32(i)); c.PC += 4 }
func opBicReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) &^ c.shOp32(i)); c.PC += 4 }
func opOrrReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) | c.shOp32(i)); c.PC += 4 }
func opOrnReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) | ^c.shOp32(i)); c.PC += 4 }
func opEorReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) ^ c.shOp32(i)); c.PC += 4 }
func opEonReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) ^ ^c.shOp32(i)); c.PC += 4 }

func opAndsReg32(c *CPU, i *inst) {
	r := uint32(c.R[i.rn]) & c.shOp32(i)
	c.R[i.rd], c.NZCV = uint64(r), logicFlags32(r)
	c.PC += 4
}

func opBicsReg32(c *CPU, i *inst) {
	r := uint32(c.R[i.rn]) &^ c.shOp32(i)
	c.R[i.rd], c.NZCV = uint64(r), logicFlags32(r)
	c.PC += 4
}

func opAddReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] + c.shOp64(i); c.PC += 4 }
func opSubReg64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] - c.shOp64(i); c.PC += 4 }
func opAddReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) + c.shOp32(i)); c.PC += 4 }
func opSubReg32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn]) - c.shOp32(i)); c.PC += 4 }

func opAddsReg64(c *CPU, i *inst) {
	r, f := addFlags64(c.R[i.rn], c.shOp64(i), 0)
	c.R[i.rd], c.NZCV = r, f
	c.PC += 4
}

func opSubsReg64(c *CPU, i *inst) {
	r, f := addFlags64(c.R[i.rn], ^c.shOp64(i), 1)
	c.R[i.rd], c.NZCV = r, f
	c.PC += 4
}

func opAddsReg32(c *CPU, i *inst) {
	r, f := addFlags32(uint32(c.R[i.rn]), c.shOp32(i), 0)
	c.R[i.rd], c.NZCV = uint64(r), f
	c.PC += 4
}

func opSubsReg32(c *CPU, i *inst) {
	r, f := addFlags32(uint32(c.R[i.rn]), ^c.shOp32(i), 1)
	c.R[i.rd], c.NZCV = uint64(r), f
	c.PC += 4
}

func opAddExt64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] + c.extOp(i); c.PC += 4 }
func opSubExt64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] - c.extOp(i); c.PC += 4 }
func opAddExt32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn] + c.extOp(i))); c.PC += 4 }
func opSubExt32(c *CPU, i *inst) { c.R[i.rd] = uint64(uint32(c.R[i.rn] - c.extOp(i))); c.PC += 4 }

func opAddsExt64(c *CPU, i *inst) {
	r, f := addFlags64(c.R[i.rn], c.extOp(i), 0)
	c.R[i.rd], c.NZCV = r, f
	c.PC += 4
}

func opSubsExt64(c *CPU, i *inst) {
	r, f := addFlags64(c.R[i.rn], ^c.extOp(i), 1)
	c.R[i.rd], c.NZCV = r, f
	c.PC += 4
}

func opAddsExt32(c *CPU, i *inst) {
	r, f := addFlags32(uint32(c.R[i.rn]), uint32(c.extOp(i)), 0)
	c.R[i.rd], c.NZCV = uint64(r), f
	c.PC += 4
}

func opSubsExt32(c *CPU, i *inst) {
	r, f := addFlags32(uint32(c.R[i.rn]), ^uint32(c.extOp(i)), 1)
	c.R[i.rd], c.NZCV = uint64(r), f
	c.PC += 4
}

func opAdc64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] + c.R[i.rm] + c.carry(); c.PC += 4 }
func opSbc64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.rn] + ^c.R[i.rm] + c.carry(); c.PC += 4 }
func opAdc32(c *CPU, i *inst) {
	c.R[i.rd] = uint64(uint32(c.R[i.rn] + c.R[i.rm] + c.carry()))
	c.PC += 4
}
func opSbc32(c *CPU, i *inst) {
	c.R[i.rd] = uint64(uint32(c.R[i.rn] + ^c.R[i.rm] + c.carry()))
	c.PC += 4
}

func opAdcs64(c *CPU, i *inst) {
	r, f := addFlags64(c.R[i.rn], c.R[i.rm], c.carry())
	c.R[i.rd], c.NZCV = r, f
	c.PC += 4
}

func opSbcs64(c *CPU, i *inst) {
	r, f := addFlags64(c.R[i.rn], ^c.R[i.rm], c.carry())
	c.R[i.rd], c.NZCV = r, f
	c.PC += 4
}

func opAdcs32(c *CPU, i *inst) {
	r, f := addFlags32(uint32(c.R[i.rn]), uint32(c.R[i.rm]), uint32(c.carry()))
	c.R[i.rd], c.NZCV = uint64(r), f
	c.PC += 4
}

func opSbcs32(c *CPU, i *inst) {
	r, f := addFlags32(uint32(c.R[i.rn]), ^uint32(c.R[i.rm]), uint32(c.carry()))
	c.R[i.rd], c.NZCV = uint64(r), f
	c.PC += 4
}

// conditional compare: amt holds the fallback NZCV, imm the imm5 operand
func (c *CPU) ccmp64(i *inst, b uint64, neg bool) {
	if !c.cond(i.cond) {
		c.NZCV = uint32(i.amt) << 28
	} else if neg {
		_, c.NZCV = addFlags64(c.R[i.rn], ^b, 1)
	} else {
		_, c.NZCV = addFlags64(c.R[i.rn], b, 0)
	}
	c.PC += 4
}

func (c *CPU) ccmp32(i *inst, b uint32, neg bool) {
	if !c.cond(i.cond) {
		c.NZCV = uint32(i.amt) << 28
	} else if neg {
		_, c.NZCV = addFlags32(uint32(c.R[i.rn]), ^b, 1)
	} else {
		_, c.NZCV = addFlags32(uint32(c.R[i.rn]), b, 0)
	}
	c.PC += 4
}

func opCcmpReg64(c *CPU, i *inst) { c.ccmp64(i, c.R[i.rm], true) }
func opCcmpImm64(c *CPU, i *inst) { c.ccmp64(i, i.imm, true) }
func opCcmnReg64(c *CPU, i *inst) { c.ccmp64(i, c.R[i.rm], false) }
func opCcmnImm64(c *CPU, i *inst) { c.ccmp64(i, i.imm, false) }
func opCcmpReg32(c *CPU, i *inst) { c.ccmp32(i, uint32(c.R[i.rm]), true) }
func opCcmpImm32(c *CPU, i *inst) { c.ccmp32(i, uint32(i.imm), true) }
func opCcmnReg32(c *CPU, i *inst) { c.ccmp32(i, uint32(c.R[i.rm]), false) }
func opCcmnImm32(c *CPU, i *inst) { c.ccmp32(i, uint32(i.imm), false) }

func opCsel64(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.R[i.rd] = c.R[i.rn]
	} else {
		c.R[i.rd] = c.R[i.rm]
	}
	c.PC += 4
}

func opCsinc64(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.R[i.rd] = c.R[i.rn]
	} else {
		c.R[i.rd] = c.R[i.rm] + 1
	}
	c.PC += 4
}

func opCsinv64(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.R[i.rd] = c.R[i.rn]
	} else {
		c.R[i.rd] = ^c.R[i.rm]
	}
	c.PC += 4
}

func opCsneg64(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.R[i.rd] = c.R[i.rn]
	} else {
		c.R[i.rd] = -c.R[i.rm]
	}
	c.PC += 4
}

func opCsel32(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.R[i.rd] = uint64(uint32(c.R[i.rn]))
	} else {
		c.R[i.rd] = uint64(uint32(c.R[i.rm]))
	}
	c.PC += 4
}

func opCsinc32(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.R[i.rd] = uint64(uint32(c.R[i.rn]))
	} else {
		c.R[i.rd] = uint64(uint32(c.R[i.rm]) + 1)
	}
	c.PC += 4
}

func opCsinv32(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.R[i.rd] = uint64(uint32(c.R[i.rn]))
	} else {
		c.R[i.rd] = uint64(^uint32(c.R[i.rm]))
	}
	c.PC += 4
}

func opCsneg32(c *CPU, i *inst) {
	if c.cond(i.cond) {
		c.R[i.rd] = uint64(uint32(c.R[i.rn]))
	} else {
		c.R[i.rd] = uint64(-uint32(c.R[i.rm]))
	}
	c.PC += 4
}

func opUdiv64(c *CPU, i *inst) {
	d := c.R[i.rm]
	if d == 0 {
		c.R[i.rd] = 0
	} else {
		c.R[i.rd] = c.R[i.rn] / d
	}
	c.PC += 4
}

func opUdiv32(c *CPU, i *inst) {
	d := uint32(c.R[i.rm])
	if d == 0 {
		c.R[i.rd] = 0
	} else {
		c.R[i.rd] = uint64(uint32(c.R[i.rn]) / d)
	}
	c.PC += 4
}

func opSdiv64(c *CPU, i *inst) {
	d := int64(c.R[i.rm])
	if d == 0 {
		c.R[i.rd] = 0
	} else {
		c.R[i.rd] = uint64(int64(c.R[i.rn]) / d) // MinInt64 / -1 wraps, as on hardware
	}
	c.PC += 4
}

func opSdiv32(c *CPU, i *inst) {
	d := int32(c.R[i.rm])
	if d == 0 {
		c.R[i.rd] = 0
	} else {
		c.R[i.rd] = uint64(uint32(int32(c.R[i.rn]) / d))
	}
	c.PC += 4
}

// LSLV/LSRV/ASRV/RORV: sh selects the shift type, amount = Rm mod datasize
func opShiftV64(c *CPU, i *inst) {
	v, n := c.R[i.rn], c.R[i.rm]&63
	switch i.sh {
	case 0:
		v <<= n
	case 1:
		v >>= n
	case 2:
		v = uint64(int64(v) >> n)
	default:
		v = bits.RotateLeft64(v, -int(n))
	}
	c.R[i.rd] = v
	c.PC += 4
}

func opShiftV32(c *CPU, i *inst) {
	v, n := uint32(c.R[i.rn]), c.R[i.rm]&31
	switch i.sh {
	case 0:
		v <<= n
	case 1:
		v >>= n
	case 2:
		v = uint32(int32(v) >> n)
	default:
		v = bits.RotateLeft32(v, -int(n))
	}
	c.R[i.rd] = uint64(v)
	c.PC += 4
}

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// CRC32 instructions take and return the raw (non-inverted) accumulator;
// hash/crc32's Update inverts on entry and exit, so undo that.
func crcUpdate(tab *crc32.Table, acc uint32, v uint64, n int) uint32 {
	var b [8]byte
	for k := 0; k < n; k++ {
		b[k] = byte(v >> (8 * k))
	}
	return ^crc32.Update(^acc, tab, b[:n])
}

func opCrc32(c *CPU, i *inst) {
	c.R[i.rd] = uint64(crcUpdate(crc32.IEEETable, uint32(c.R[i.rn]), c.R[i.rm], int(i.sz)))
	c.PC += 4
}

func opCrc32c(c *CPU, i *inst) {
	c.R[i.rd] = uint64(crcUpdate(crc32cTable, uint32(c.R[i.rn]), c.R[i.rm], int(i.sz)))
	c.PC += 4
}

func opRbit64(c *CPU, i *inst) { c.R[i.rd] = bits.Reverse64(c.R[i.rn]); c.PC += 4 }
func opRbit32(c *CPU, i *inst) { c.R[i.rd] = uint64(bits.Reverse32(uint32(c.R[i.rn]))); c.PC += 4 }
func opRev64(c *CPU, i *inst)  { c.R[i.rd] = bits.ReverseBytes64(c.R[i.rn]); c.PC += 4 }
func opRev32(c *CPU, i *inst) {
	c.R[i.rd] = uint64(bits.ReverseBytes32(uint32(c.R[i.rn])))
	c.PC += 4
}

func opRev32_64(c *CPU, i *inst) { // REV32 Xd: bytes reversed within each word
	v := bits.ReverseBytes64(c.R[i.rn])
	c.R[i.rd] = v<<32 | v>>32
	c.PC += 4
}

func opRev16_64(c *CPU, i *inst) {
	v := c.R[i.rn]
	c.R[i.rd] = (v&0x00ff00ff00ff00ff)<<8 | (v>>8)&0x00ff00ff00ff00ff
	c.PC += 4
}

func opRev16_32(c *CPU, i *inst) {
	v := uint32(c.R[i.rn])
	c.R[i.rd] = uint64((v&0x00ff00ff)<<8 | (v>>8)&0x00ff00ff)
	c.PC += 4
}

func opClz64(c *CPU, i *inst) { c.R[i.rd] = uint64(bits.LeadingZeros64(c.R[i.rn])); c.PC += 4 }
func opClz32(c *CPU, i *inst) { c.R[i.rd] = uint64(bits.LeadingZeros32(uint32(c.R[i.rn]))); c.PC += 4 }

func opCls64(c *CPU, i *inst) {
	v := c.R[i.rn]
	c.R[i.rd] = uint64(bits.LeadingZeros64((v^v>>1)&(1<<63-1)) - 1)
	c.PC += 4
}

func opCls32(c *CPU, i *inst) {
	v := uint32(c.R[i.rn])
	c.R[i.rd] = uint64(bits.LeadingZeros32((v^v>>1)&(1<<31-1)) - 1)
	c.PC += 4
}

func opMadd64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.ra] + c.R[i.rn]*c.R[i.rm]; c.PC += 4 }
func opMsub64(c *CPU, i *inst) { c.R[i.rd] = c.R[i.ra] - c.R[i.rn]*c.R[i.rm]; c.PC += 4 }
func opMadd32(c *CPU, i *inst) {
	c.R[i.rd] = uint64(uint32(c.R[i.ra]) + uint32(c.R[i.rn])*uint32(c.R[i.rm]))
	c.PC += 4
}
func opMsub32(c *CPU, i *inst) {
	c.R[i.rd] = uint64(uint32(c.R[i.ra]) - uint32(c.R[i.rn])*uint32(c.R[i.rm]))
	c.PC += 4
}

func opSmaddl(c *CPU, i *inst) {
	c.R[i.rd] = c.R[i.ra] + uint64(int64(int32(c.R[i.rn]))*int64(int32(c.R[i.rm])))
	c.PC += 4
}

func opSmsubl(c *CPU, i *inst) {
	c.R[i.rd] = c.R[i.ra] - uint64(int64(int32(c.R[i.rn]))*int64(int32(c.R[i.rm])))
	c.PC += 4
}

func opUmaddl(c *CPU, i *inst) {
	c.R[i.rd] = c.R[i.ra] + uint64(uint32(c.R[i.rn]))*uint64(uint32(c.R[i.rm]))
	c.PC += 4
}

func opUmsubl(c *CPU, i *inst) {
	c.R[i.rd] = c.R[i.ra] - uint64(uint32(c.R[i.rn]))*uint64(uint32(c.R[i.rm]))
	c.PC += 4
}

func opUmulh(c *CPU, i *inst) {
	hi, _ := bits.Mul64(c.R[i.rn], c.R[i.rm])
	c.R[i.rd] = hi
	c.PC += 4
}

func opSmulh(c *CPU, i *inst) {
	a, b := c.R[i.rn], c.R[i.rm]
	hi, _ := bits.Mul64(a, b)
	// signed correction: subtract b if a < 0, a if b < 0
	hi -= b & uint64(int64(a)>>63)
	hi -= a & uint64(int64(b)>>63)
	c.R[i.rd] = hi
	c.PC += 4
}
