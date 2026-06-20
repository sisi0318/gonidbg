package emulator

import (
	"bufio"
	"fmt"
	"io"

	"github.com/sisi0318/gonidbg/internal/emu"
)

// This file implements a full instruction-stream tracer: every guest
// instruction executed in a chosen range is logged with its PC, opcode, the
// register file deltas it produced, and symbol annotations for calls/syscalls.
// The format is a clean cousin of a Frida/Tenet execution trace — designed to
// diff an emulated run against a real-device trace to find where they diverge —
// but it is gonidbg's own, built on the engine's per-instruction code hook.
//
// It needs the Unicorn engine (dynarmic is a block JIT with no per-instruction
// hook). Tracing is slow (one register-file read per instruction) and produces
// large output; wrap the writer in your own gzip/buffer if you like.

// gpRegNames indexes the [34]uint64 ReadGPRegs returns.
var gpRegNames = [34]string{
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
	"x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
	"x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
	"sp", "pc", "nzcv",
}

const gpIdxPC = 32 // pc is carried in the line prefix, not repeated as a delta

type insnTracer struct {
	e       *Emulator
	w       *bufio.Writer
	base    uint64     // module base, for module-relative offsets
	prev    [34]uint64 // register file as of the previous traced instruction
	started bool
	buf     []byte // reusable line scratch
}

// TraceInsns installs a full instruction tracer over [start, end) and writes the
// trace to w. base is subtracted from each PC so the trace uses module-relative
// offsets (pass the module base). Returns a stop function that removes the hook
// and flushes; call it after the traced call returns. Unicorn only.
func (e *Emulator) TraceInsns(w io.Writer, start, end, base uint64) (func(), error) {
	if e.engine != "unicorn" {
		return nil, fmt.Errorf("TraceInsns: full instruction trace requires the unicorn engine (current %q)", e.engine)
	}
	t := &insnTracer{e: e, w: bufio.NewWriterSize(w, 1<<20), base: base, buf: make([]byte, 0, 256)}
	fmt.Fprintf(t.w, "# gonidbg instruction trace  base=0x%x range=[0x%x,0x%x)\n", base, start, end)
	h, err := e.be.HookCode(start, end, func(b emu.Backend, addr uint64, size uint32) {
		t.onInsn(addr)
	})
	if err != nil {
		return nil, err
	}
	return func() {
		_ = h.Remove()
		_ = t.w.Flush()
	}, nil
}

// onInsn fires at the start of each in-range instruction.
func (t *insnTracer) onInsn(pc uint64) {
	regs, err := t.e.be.ReadGPRegs()
	if err != nil {
		return
	}
	var op uint32
	if b, err := t.e.be.MemRead(pc, 4); err == nil && len(b) == 4 {
		op = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	}

	// Line: "0x<off> :<opcode>  <changed regs since prev>"
	t.buf = t.buf[:0]
	t.buf = append(t.buf, '0', 'x')
	t.buf = appendHex(t.buf, pc-t.base, 0)
	t.buf = append(t.buf, ' ', ':')
	t.buf = appendHex(t.buf, uint64(op), 8)
	t.buf = append(t.buf, ' ')
	for i := 0; i < 34; i++ {
		if i == gpIdxPC {
			continue // pc is the line prefix
		}
		if !t.started || regs[i] != t.prev[i] {
			t.buf = append(t.buf, gpRegNames[i]...)
			t.buf = append(t.buf, '=', '0', 'x')
			t.buf = appendHex(t.buf, regs[i], 16)
			t.buf = append(t.buf, ',')
		}
	}
	t.buf = append(t.buf, '\n')
	_, _ = t.w.Write(t.buf)

	t.annotate(pc, op, regs)

	t.prev = regs
	t.started = true
}

// annotate emits a sym: line for control-flow / syscall instructions, resolving
// targets through the module symbol table.
func (t *insnTracer) annotate(pc uint64, op uint32, regs [34]uint64) {
	switch {
	case op&0xFC000000 == 0x94000000: // BL imm26 (direct call)
		off := int64(int32(op<<6) >> 6) // sign-extend imm26
		target := uint64(int64(pc) + off*4)
		fmt.Fprintf(t.w, "sym:call 0x%x %s\n", target-t.base, t.e.NearestSym(target))
	case op&0xFFFFFC1F == 0xD63F0000: // BLR Xn (indirect call)
		n := (op >> 5) & 0x1f
		target := regs[n]
		fmt.Fprintf(t.w, "sym:call x%d 0x%x %s\n", n, target, t.e.NearestSym(target))
	case op == 0xD4000001: // SVC #0 (syscall / trampoline)
		fmt.Fprintf(t.w, "sym:svc x8=%d (%s)\n", regs[8], t.e.NearestSym(pc))
	}
}

// appendHex appends val as lowercase hex, left-padded with zeros to at least
// width digits (width 0 = no padding).
func appendHex(b []byte, val uint64, width int) []byte {
	var tmp [16]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = "0123456789abcdef"[val&0xf]
		val >>= 4
		if val == 0 {
			break
		}
	}
	for n := len(tmp) - i; n < width; n++ {
		b = append(b, '0')
	}
	return append(b, tmp[i:]...)
}
