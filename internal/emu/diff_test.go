//go:build unicorn

// Differential test: run one instruction at a time on the pure-Go interpreter
// and on Unicorn from identical CPU and memory state, then compare everything
// observable. Unicorn is the reference the interpreter has to match, so this is
// what makes the interpreter trustworthy — a wrong flag or a wrong lane shows
// up here instead of as a silently wrong signature.
//
//	go test -tags unicorn -run TestDiffUnicorn ./internal/emu
//	GONIDBG_DIFF_N=2000000 go test -tags unicorn -run TestDiffUnicorn -timeout 2h ./internal/emu
//
// Observing the vector registers needs no extra backend API: a preamble loads
// V0..V31 and X0..X30 from guest memory, and a postamble stores V0..V31 back,
// so the whole register file travels through memory that both engines expose.
package emu

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"

	"github.com/sisi0318/gonidbg/internal/arm64"
)

const (
	dCode = 0x10000 // code page
	dData = 0x40000 // compared window (16 KiB)
	dAux  = 0x50000 // init block + vector dump, never compared

	dWindow = 0x4000         // bytes of dData compared after each case
	dPtr    = dData + 0x2000 // pointer registers aim here: the window's middle

	dTest = dCode + 0x100 // the instruction under test
	dPost = dCode + 0x200 // vector dump postamble
	dEnd  = dCode + 0x240

	dInit = dAux         // 32 x 16 B vector init, then 31 x 8 B X init
	dXoff = 512          // X init offset inside the init block
	dDump = dAux + 0x800 // 32 x 16 B vector dump
)

// Preamble then postamble, as assembled by clang for:
//
//	ldp q0, q1, [x0, #0] ... ldp q30, q31, [x0, #480]   // V0..V31 <- init
//	ldr x1, [x0, #520]   ... ldr x30, [x0, #752]        // X1..X30 <- init
//	ldr x0,  [x0, #512]                                 // X0 last: it is the base
//	(dPost) stp q0, q1, [x0, #0] ... stp q30, q31, [x0, #480]
var diffPrePost = [63]uint32{
	0xad400400, 0xad410c02, 0xad421404, 0xad431c06, 0xad442408, 0xad452c0a,
	0xad46340c, 0xad473c0e, 0xad484410, 0xad494c12, 0xad4a5414, 0xad4b5c16,
	0xad4c6418, 0xad4d6c1a, 0xad4e741c, 0xad4f7c1e, 0xf9410401, 0xf9410802,
	0xf9410c03, 0xf9411004, 0xf9411405, 0xf9411806, 0xf9411c07, 0xf9412008,
	0xf9412409, 0xf941280a, 0xf9412c0b, 0xf941300c, 0xf941340d, 0xf941380e,
	0xf9413c0f, 0xf9414010, 0xf9414411, 0xf9414812, 0xf9414c13, 0xf9415014,
	0xf9415415, 0xf9415816, 0xf9415c17, 0xf9416018, 0xf9416419, 0xf941681a,
	0xf9416c1b, 0xf941701c, 0xf941741d, 0xf941781e, 0xf9410000, 0xad000400,
	0xad010c02, 0xad021404, 0xad031c06, 0xad042408, 0xad052c0a, 0xad06340c,
	0xad073c0e, 0xad084410, 0xad094c12, 0xad0a5414, 0xad0b5c16, 0xad0c6418,
	0xad0d6c1a, 0xad0e741c, 0xad0f7c1e,
}

const nPre = 47 // preamble instructions; the rest is the postamble

// diffState is one randomized starting point for the CPU.
type diffState struct {
	v     [32]arm64.Vec
	x     [31]uint64
	sp    uint64
	nzcv  uint32
	tpidr uint64
}

// result is everything observable after the instruction under test.
type result struct {
	failed bool
	regs   [34]uint64
	vdump  []byte
	window []byte
}

type diffEngine struct {
	name string
	b    Backend
}

func newDiffEngine(t *testing.T, name string) *diffEngine {
	b, err := NewNamed(name)
	if err != nil {
		t.Fatalf("engine %s: %v", name, err)
	}
	// Read+execute only: a stray store from the instruction under test would
	// otherwise corrupt the preamble and wreck every later case.
	if err := b.MemMap(dCode, 0x1000, ProtRead|ProtExec); err != nil {
		t.Fatalf("%s: map code: %v", name, err)
	}
	if err := b.MemMap(dData, dWindow, ProtRead|ProtWrite); err != nil {
		t.Fatalf("%s: map data: %v", name, err)
	}
	if err := b.MemMap(dAux, 0x1000, ProtRead|ProtWrite); err != nil {
		t.Fatalf("%s: map aux: %v", name, err)
	}
	// NOP-fill the page first: Start(dCode, dTest) runs until PC reaches dTest,
	// so the gap between the end of the preamble and the test slot has to be
	// executable padding rather than the zero word (an undefined instruction).
	code := make([]byte, 0x1000)
	for i := 0; i < len(code); i += 4 {
		binary.LittleEndian.PutUint32(code[i:], 0xd503201f) // NOP
	}
	for i := 0; i < nPre; i++ {
		binary.LittleEndian.PutUint32(code[4*i:], diffPrePost[i])
	}
	// CLREX right after the preamble: the exclusive monitor is engine state
	// that survives between cases, and QEMU starts it at address -1, so without
	// this a test operand of 0xffff...ffff would arm it on unicorn only.
	binary.LittleEndian.PutUint32(code[4*nPre:], 0xd5033f5f)
	if err := b.MemWrite(dCode, code); err != nil {
		t.Fatalf("%s: write preamble: %v", name, err)
	}
	post := make([]byte, 4*(len(diffPrePost)-nPre))
	for i := nPre; i < len(diffPrePost); i++ {
		binary.LittleEndian.PutUint32(post[4*(i-nPre):], diffPrePost[i])
	}
	if err := b.MemWrite(dPost, post); err != nil {
		t.Fatalf("%s: write postamble: %v", name, err)
	}
	return &diffEngine{name: name, b: b}
}

var zeroWindow = make([]byte, dWindow)

// run executes one instruction from state st and reports what changed.
func (e *diffEngine) run(st *diffState, insn uint32) (*result, error) {
	b := e.b
	// The whole aux page is rewritten, not just the init block: a literal load
	// in the instruction under test can read the vector dump area, whose
	// contents would otherwise depend on the previous case.
	init := make([]byte, 0x1000)
	for i, v := range st.v {
		binary.LittleEndian.PutUint64(init[16*i:], v[0])
		binary.LittleEndian.PutUint64(init[16*i+8:], v[1])
	}
	for i, v := range st.x {
		binary.LittleEndian.PutUint64(init[dXoff+8*i:], v)
	}
	var ib [4]byte
	binary.LittleEndian.PutUint32(ib[:], insn)
	for _, op := range []func() error{
		func() error { return b.MemWrite(dTest, ib[:]) },
		func() error { return b.MemWrite(dInit, init) },
		func() error { return b.MemWrite(dData, zeroWindow) },
		func() error { return b.RegWrite(RegX0, dInit) },
		func() error { return b.Start(dCode, dTest) }, // preamble
		func() error { return b.RegWrite(RegSP, st.sp) },
		func() error { return b.RegWrite(RegNZCV, uint64(st.nzcv)) },
		func() error { return b.RegWrite(RegTPIDR_EL0, st.tpidr) },
	} {
		if err := op(); err != nil {
			return nil, fmt.Errorf("%s: setup: %w", e.name, err)
		}
	}

	res := &result{}
	res.failed = b.StartCount(dTest, 0, 1) != nil

	regs, err := b.ReadGPRegs()
	if err != nil {
		return nil, fmt.Errorf("%s: read regs: %w", e.name, err)
	}
	res.regs = regs
	if res.failed {
		// A faulting instruction leaves architecturally unspecified state; the
		// comparison only checks that both engines agree it faulted.
		return res, nil
	}
	if err := b.RegWrite(RegX0, dDump); err != nil {
		return nil, fmt.Errorf("%s: set dump base: %w", e.name, err)
	}
	if err := b.Start(dPost, dEnd); err != nil {
		return nil, fmt.Errorf("%s: postamble: %w", e.name, err)
	}
	if res.vdump, err = b.MemRead(dDump, 512); err != nil {
		return nil, fmt.Errorf("%s: read vdump: %w", e.name, err)
	}
	if res.window, err = b.MemRead(dData, dWindow); err != nil {
		return nil, fmt.Errorf("%s: read window: %w", e.name, err)
	}
	return res, nil
}

var gpNames = [34]string{
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
	"x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
	"x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
	"sp", "pc", "nzcv",
}

// isBranch reports whether raw writes PC. A taken branch leaves PC on an
// address that is almost never mapped, and Unicorn reports the failed prefetch
// of the *next* instruction as an error even though the branch itself retired.
// For these the comparison uses the register file (PC and LR are the whole
// observable effect) and ignores the fault flag.
func isBranch(raw uint32) bool {
	switch {
	case raw&0x7c000000 == 0x14000000: // B, BL
		return true
	case raw&0xff000000 == 0x54000000: // B.cond
		return true
	case raw&0x7e000000 == 0x34000000: // CBZ, CBNZ
		return true
	case raw&0x7e000000 == 0x36000000: // TBZ, TBNZ
		return true
	case raw&0xfe000000 == 0xd6000000: // BR, BLR, RET
		return true
	}
	return false
}

// diff describes how two results disagree ("" when they match).
func diff(raw uint32, want, got *result) string {
	if isBranch(raw) {
		for i := range want.regs {
			if want.regs[i] != got.regs[i] {
				return fmt.Sprintf("\n    %s: unicorn=%#x interp=%#x", gpNames[i], want.regs[i], got.regs[i])
			}
		}
		return ""
	}
	if want.failed != got.failed {
		return fmt.Sprintf("fault disagreement: unicorn=%v interp=%v", want.failed, got.failed)
	}
	if want.failed {
		return ""
	}
	var msgs []string
	for i := range want.regs {
		if want.regs[i] != got.regs[i] {
			msgs = append(msgs, fmt.Sprintf("%s: unicorn=%#x interp=%#x", gpNames[i], want.regs[i], got.regs[i]))
		}
	}
	for i := 0; i < 32; i++ {
		w, g := want.vdump[16*i:16*i+16], got.vdump[16*i:16*i+16]
		if !bytes.Equal(w, g) {
			msgs = append(msgs, fmt.Sprintf("v%d: unicorn=%x interp=%x", i, w, g))
		}
	}
	if !bytes.Equal(want.window, got.window) {
		for i := range want.window {
			if want.window[i] != got.window[i] {
				msgs = append(msgs, fmt.Sprintf("mem[%#x]: unicorn=%#02x interp=%#02x (+%d more bytes)",
					dData+i, want.window[i], got.window[i], countDiff(want.window, got.window)-1))
				break
			}
		}
	}
	if len(msgs) == 0 {
		return ""
	}
	out := ""
	for i, m := range msgs {
		if i == 6 {
			out += fmt.Sprintf("\n    ... and %d more", len(msgs)-6)
			break
		}
		out += "\n    " + m
	}
	return out
}

func countDiff(a, b []byte) int {
	n := 0
	for i := range a {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}

// randomState builds a starting point that makes memory instructions likely to
// land inside the compared window: every other X register points at the middle
// of it, the rest hold small values and edge-case bit patterns so they work as
// indices, shift amounts and operands.
func randomState(rng *rand.Rand) *diffState {
	st := &diffState{sp: dPtr, nzcv: uint32(rng.UintN(16)) << 28, tpidr: 0xd0000000}
	patterns := []uint64{0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 0xff, 0x7f, 0x80,
		0xffff, 0xffffffff, 0x8000000000000000, 0xfffffffffffffffe, 0x5555555555555555}
	for i := range st.x {
		switch {
		case i%2 == 0:
			st.x[i] = dPtr + uint64(16*rng.IntN(32)) - 256
		case rng.IntN(2) == 0:
			st.x[i] = patterns[rng.IntN(len(patterns))]
		default:
			st.x[i] = rng.Uint64()
		}
	}
	for i := range st.v {
		switch rng.IntN(4) {
		case 0:
			st.v[i] = arm64.Vec{0, 0}
		case 1: // small floats and integers
			st.v[i] = arm64.Vec{uint64(rng.Uint32N(0x4000_0000)), uint64(rng.Uint32N(0x4000_0000))}
		default:
			st.v[i] = arm64.Vec{rng.Uint64(), rng.Uint64()}
		}
	}
	return st
}

// sysregField is the o0:op1:CRn:CRm:op2 field of an MRS/MSR encoding.
func sysregField(raw uint32) uint32 { return (raw >> 5) & 0xffff }

func sysregOf(op0, op1, crn, crm, op2 uint32) uint32 {
	return op0<<14 | op1<<11 | crn<<7 | crm<<3 | op2
}

// excluded skips encodings whose behavior legitimately differs between the two
// engines, so the test reports only real interpreter bugs.
func excluded(raw uint32) bool {
	switch {
	case raw&0xff000000 == 0xd4000000:
		return true // SVC/BRK/HLT: delivered to hooks, not compared here
	case raw&0xfff00000 == 0xd5300000: // MRS
		f := sysregField(raw)
		// the counters advance differently on an interpreter and a JIT
		return f == sysregOf(3, 3, 14, 0, 1) || f == sysregOf(3, 3, 14, 0, 2)
	case raw&0xfff80000 == 0xd5080000, raw&0xfff80000 == 0xd5880000: // SYS/SYSL
		// cache maintenance is EL-dependent; DC ZVA is the one the workload uses
		return sysregField(raw) != sysregOf(1, 3, 7, 4, 1)
	case raw&0x38000000 == 0x28000000: // load/store pair
		rt, rt2, rn := raw&31, (raw>>10)&31, (raw>>5)&31
		load, wb := (raw>>22)&1 == 1, (raw>>23)&1 == 1
		// CONSTRAINED UNPREDICTABLE: a load pair into one register twice, or a
		// writeback whose base is also a destination. Engines may differ.
		if load && rt == rt2 {
			return true
		}
		if wb && rn != 31 && (rn == rt || (load && rn == rt2)) {
			return true
		}
		return false
	case raw&0xfffff01f == 0xd503201f: // HINT
		crm, op2 := (raw>>8)&15, (raw>>5)&7
		// WFE/WFI/SEV/SEVL suspend or signal on a real engine
		return crm == 0 && op2 >= 2
	}
	return false
}

func TestDiffUnicorn(t *testing.T) {
	n := 20000
	if s := os.Getenv("GONIDBG_DIFF_N"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("GONIDBG_DIFF_N: %v", err)
		}
		n = v
	}
	if testing.Short() {
		n = 500
	}
	seed := uint64(1)
	if s := os.Getenv("GONIDBG_DIFF_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			t.Fatalf("GONIDBG_DIFF_SEED: %v", err)
		}
		seed = v
	}

	// GONIDBG_DIFF_INSN pins one encoding and hammers it with random operand
	// states — the way to chase down a single mismatch found by a wide sweep.
	var pinned uint32
	if v := os.Getenv("GONIDBG_DIFF_INSN"); v != "" {
		x, err := strconv.ParseUint(v, 0, 32)
		if err != nil {
			t.Fatalf("GONIDBG_DIFF_INSN: %v", err)
		}
		pinned = uint32(x)
		if !arm64.Decodable(pinned) {
			t.Fatalf("GONIDBG_DIFF_INSN %#08x: the interpreter does not decode it", pinned)
		}
	}

	ref := newDiffEngine(t, "unicorn")
	defer ref.b.Close()
	got := newDiffEngine(t, "interp")
	defer got.b.Close()

	rng := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	tested, failures := 0, 0
	for tested < n {
		insn := rng.Uint32()
		if pinned != 0 {
			insn = pinned
		} else if !arm64.Decodable(insn) || excluded(insn) {
			continue
		}
		tested++
		st := randomState(rng)
		want, err := ref.run(st, insn)
		if err != nil {
			t.Fatal(err)
		}
		have, err := got.run(st, insn)
		if err != nil {
			t.Fatal(err)
		}
		if d := diff(insn, want, have); d != "" {
			failures++
			if failures <= 20 {
				extra := ""
				if pinned != 0 { // chasing one encoding: show its operands
					rn, rm := (insn>>5)&31, (insn>>16)&31
					extra = fmt.Sprintf("\n    in: v%d=%016x%016x v%d=%016x%016x x%d=%#x x%d=%#x",
						rn, st.v[rn][1], st.v[rn][0], rm, st.v[rm][1], st.v[rm][0],
						rn, st.x[rn], rm, st.x[rm])
				}
				t.Errorf("insn %#08x (seed %d, case %d) differs:%s%s", insn, seed, tested, d, extra)
			}
		}
	}
	t.Logf("compared %d instructions against unicorn, %d mismatched", tested, failures)
	if failures > 20 {
		t.Errorf("%d mismatches total (only the first 20 shown)", failures)
	}
}
