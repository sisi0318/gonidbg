package emulator

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/sisi0318/gonidbg/internal/emu"
)

// Debugger is a small gdb-style console debugger: breakpoints, single-step,
// register and memory inspection. When a breakpoint hits (or in step mode) it
// drops into an interactive prompt that reads commands from In and writes to
// Out (default stdin/stdout; set them to drive it from a test or a script).
//
// Commands: c (continue) · s (step) · r (regs) · x ADDR LEN (hexdump) ·
//
//	b ADDR (breakpoint) · q (stop).
//
// Requires the Unicorn engine (it uses a per-instruction code hook); dynarmic
// has no such hook.
type Debugger struct {
	e      *Emulator
	bps    map[uint64]bool
	step   bool
	remove func()
	sc     *bufio.Scanner

	In  io.Reader // command input  (default os.Stdin)
	Out io.Writer // command output (default os.Stdout)
}

// NewDebugger attaches a debugger (installs the per-instruction hook).
func (e *Emulator) NewDebugger() (*Debugger, error) {
	if e.engine != "unicorn" {
		return nil, fmt.Errorf("debugger requires the unicorn engine (current %q)", e.engine)
	}
	d := &Debugger{e: e, bps: map[uint64]bool{}, In: os.Stdin, Out: os.Stdout}
	h, err := e.be.HookCode(1, 0, func(b emu.Backend, addr uint64, size uint32) { // begin>end => global
		if d.step || d.bps[addr] {
			d.repl(addr)
		}
	})
	if err != nil {
		return nil, err
	}
	d.remove = func() { _ = h.Remove() }
	return d, nil
}

// Break sets a breakpoint at a guest address.
func (d *Debugger) Break(addr uint64) { d.bps[addr] = true }

// BreakSymbol sets a breakpoint at an exported symbol.
func (d *Debugger) BreakSymbol(name string) error {
	addr, ok := d.e.Sym(name)
	if !ok {
		return fmt.Errorf("symbol %q not found", name)
	}
	d.bps[addr] = true
	return nil
}

// Detach removes the debugger's hook.
func (d *Debugger) Detach() {
	if d.remove != nil {
		d.remove()
		d.remove = nil
	}
}

func (d *Debugger) repl(pc uint64) {
	if d.sc == nil {
		d.sc = bufio.NewScanner(d.In)
	}
	fmt.Fprintf(d.Out, "\n* break @ 0x%x  %s\n", pc, d.e.NearestSym(pc))
	for {
		fmt.Fprint(d.Out, "(gonidbg) ")
		if !d.sc.Scan() { // EOF -> detach and continue
			d.step = false
			return
		}
		f := strings.Fields(strings.TrimSpace(d.sc.Text()))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "c", "cont", "continue":
			d.step = false
			return
		case "s", "si", "step":
			d.step = true
			return
		case "r", "reg", "regs":
			d.printRegs()
		case "x", "mem":
			d.printMem(f)
		case "b", "break":
			if len(f) > 1 {
				if a, err := strconv.ParseUint(strings.TrimPrefix(f[1], "0x"), 16, 64); err == nil {
					d.bps[a] = true
					fmt.Fprintf(d.Out, "breakpoint @ 0x%x\n", a)
				}
			}
		case "q", "quit", "kill":
			_ = d.e.be.Stop()
			d.step = false
			return
		default:
			fmt.Fprintln(d.Out, "commands: c(ontinue) s(tep) r(egs) x ADDR LEN  b ADDR  q(uit)")
		}
	}
}

func (d *Debugger) printRegs() {
	rd := func(r emu.Reg) uint64 { v, _ := d.e.be.RegRead(r); return v }
	for i := 0; i <= 10; i++ {
		fmt.Fprintf(d.Out, "X%-2d=0x%016x  ", i, rd(emu.RegX0+emu.Reg(i)))
		if i%4 == 3 {
			fmt.Fprintln(d.Out)
		}
	}
	fmt.Fprintf(d.Out, "\nSP =0x%016x  LR =0x%016x  PC =0x%016x\n", rd(emu.RegSP), rd(emu.RegLR), rd(emu.RegPC))
}

func (d *Debugger) printMem(f []string) {
	if len(f) < 2 {
		fmt.Fprintln(d.Out, "usage: x ADDR [LEN]")
		return
	}
	addr, err := strconv.ParseUint(strings.TrimPrefix(f[1], "0x"), 16, 64)
	if err != nil {
		fmt.Fprintln(d.Out, "bad address")
		return
	}
	n := uint64(32)
	if len(f) > 2 {
		if v, err := strconv.ParseUint(f[2], 0, 64); err == nil {
			n = v
		}
	}
	data, err := d.e.be.MemRead(addr, n)
	if err != nil {
		fmt.Fprintf(d.Out, "read error: %v\n", err)
		return
	}
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(d.Out, "0x%08x  % x\n", addr+uint64(i), data[i:end])
	}
}
