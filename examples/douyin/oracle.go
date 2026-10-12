package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/sisi0318/gonidbg/emulator"
)

func rd8le(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	v := uint64(0)
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// installProbe logs every VM-program entry (sub_2AB64C) with the live head of the body buffer
// (0x4050a000) and protobuf (0x4052d000), to locate the VM that produces a8bbb28b (ph5-1st cipher),
// and dumps that producer VM's entry state for offline lifting. Env A8DUMP=<n> dumps entry #n.
func installProbe(e *emulator.Emulator, m *emulator.Module) {
	rel := func(a uint64) uint64 {
		if a >= m.Base && a < m.Base+0x400000 {
			return a - m.Base
		}
		return a
	}
	dumpN := -1
	if s := os.Getenv("A8DUMP"); s != "" {
		fmt.Sscanf(s, "%d", &dumpN)
	}
	// Dump the FP-serializer state at the moment the body buffer 0x4050a000 first leaves its
	// placeholder d0837b12 (= the encrypt about to write it; protobuf already built). This isolates
	// the encrypt (protobuf+nonce -> a8bbb28b) from the FP build, so it can be run/lifted standalone.
	encDumped := false
	ccoreDumped := false
	med751Dumped := false
	medphDumped := false
	helvmDumped := false
	ph7Dumped := false
	pPhDumped := false
	bcN := 0
	bcGated := false
	kvmDumped := false
	cvmDumped := false
	cvmN := 0
	dumped2c := false
	dumped13 := false
	dumpedPrecip := false
	var orchCtx uint64
	cipN := 0
	keyTraced := false
	ecbN := 0
	dumpState := func(h *emulator.Hook, tag string) {
		dr := func(lo, hi uint64) []byte {
			var b []byte
			for a := lo; a < hi; a += 0x1000 {
				pg, err := h.Emu().ReadBytes(a, 0x1000)
				if err != nil {
					pg = make([]byte, 0x1000)
				}
				b = append(b, pg...)
			}
			return b
		}
		// x23 = current regfile (handler entry convention)
		x23 := h.Reg(23)
		rf, _ := h.Emu().ReadBytes(x23, 8*256)
		_ = os.WriteFile(tag+"_rf.bin", rf, 0644)
		_ = os.WriteFile(tag+"_heap.bin", dr(0x40400000, 0x40c00000), 0644)
		_ = os.WriteFile(tag+"_lowheap.bin", dr(0x40100000, 0x40400000), 0644)
		_ = os.WriteFile(tag+"_stack.bin", dr(0xc07e0000, 0xc0800000), 0644)
		// the relocated .so runtime image (handler tables/GOT with absolute pointers)
		_ = os.WriteFile(tag+"_so.bin", dr(m.Base, m.Base+0x400000), 0644)
		_ = os.WriteFile(tag+"_base.txt", []byte(fmt.Sprintf("%#x", m.Base)), 0644)
	}
	// [MEDCAP] Medusa body-cipher native-lift capture. Gate at the inner-VM's first read of the
	// device plaintext (2c481f6e @ 0x4016e180, pc=0x1703d4) — the cipher entry, with device_pt in
	// init memory (device-parameterizable). Dump native state + GP regs + gate the trace, then
	// return early (skip all the Perseus/other hooks so the trace is ONLY the Medusa cipher).
	if os.Getenv("MEDCAP") != "" {
		medGated := false
		medStopped := false
		xmBuilt := false
		readCtr := 0
		gateN := 1 // gate at the GATEN-th VM-init-done device_pt read (env MEDGATEN); find via xmBuilt report
		if s := os.Getenv("MEDGATEN"); s != "" {
			fmt.Sscanf(s, "%d", &gateN)
		}
		// detect when the X-Medusa post-XOR body (07f15365..) lands at 0x401646a0; report how many
		// device_pt reads preceded it -> pick MEDGATEN just below that to gate near the cipher.
		_, _ = e.HookMemWrite(0x401646a0, 0x401646a8, func(h *emulator.Hook, addr uint64, size int, value int64) {
			if xmBuilt {
				return
			}
			b, _ := h.Emu().ReadBytes(0x401646a0, 4)
			if len(b) == 4 && b[0] == 0x07 && b[1] == 0xf1 && b[2] == 0x53 && b[3] == 0x65 {
				xmBuilt = true
				fmt.Printf("[MEDCAP] X-Medusa body BUILT at 0x401646a0 after %d device_pt reads (medGated=%v)\n", readCtr, medGated)
			}
		})
		_, _ = e.HookMemRead(0x4016e180, 0x4016e190, func(h *emulator.Hook, addr uint64, size int) {
			if medGated {
				return
			}
			pc := h.PC() - m.Base
			if pc != 0x1703d4 {
				return
			}
			pt, _ := h.Emu().ReadBytes(0x4016e180, 4)
			if len(pt) != 4 || pt[0] != 0x2c || pt[1] != 0x48 || pt[2] != 0x1f || pt[3] != 0x6e {
				return
			}
			readCtr++
			if readCtr < gateN {
				return
			}
			// Gate only AFTER the device-independent VM-global init (the .bss singleton @0x12827f10
			// gets set; it's 0 during the early protobuf phase). The first device_pt read is too early
			// (before this init) -> arm_exec's replay can't reconstruct the skipped init. Waiting for
			// the global to be non-zero gives a clean post-init capture, closer to the body cipher.
			g, _ := h.Emu().ReadBytes(0x12827f20, 8)
			if len(g) != 8 || (g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0 && g[6] == 0 && g[7] == 0) {
				return
			}
			dumpState(h, "med")
			// the Medusa cipher (CFF inner VM) calls into a 0x60000000-region code/vtable mapping
			// (function pointers like 0x600008c0 live in heap objects) — dump it for the lift.
			genDump := func(lo, hi uint64) []byte {
				var b []byte
				for a := lo; a < hi; a += 0x1000 {
					pg, e := h.Emu().ReadBytes(a, 0x1000)
					if e != nil {
						pg = make([]byte, 0x1000)
					}
					b = append(b, pg...)
				}
				return b
			}
			bbAtGate, _ := h.Emu().ReadBytes(0x401646a0, 16)
			fmt.Printf("[MEDCAP] 0x401646a0 at gate = %x (07f15365.. => X-Medusa already built BEFORE gate)\n", bbAtGate)
			_ = os.WriteFile("med_gen.bin", genDump(0x60000000, 0x60800000), 0644)
			var sb []byte
			for i := 0; i < 34; i++ {
				sb = append(sb, []byte(fmt.Sprintf("%d=%x\n", i, h.Reg(i)))...)
			}
			_ = os.WriteFile("med_gpregs.txt", sb, 0644)
			emulator.TraceGate = true
			medGated = true
			fmt.Printf("[MEDCAP] gated @pc=%#x device_pt-ready, trace ON\n", pc)
		})
		// [W408] does the real run write the divergence word 0x401408c8 (mine=0x24, real=0x20) AFTER
		// the gate? If yes -> med_exec misses it (control-flow/pointer divergence); if never -> gate
		// dump captured a stale value. Log the writer PC + value.
		w408 := 0
		_, _ = e.HookMemWrite(0x40142010, 0x40142028, func(h *emulator.Hook, addr uint64, size int, value int64) {
			if medGated && w408 < 12 {
				pcRel := h.PC() - m.Base
				inSO := h.PC() >= m.Base && h.PC() < m.Base+0x400000
				fmt.Printf("[W408] addr=%#x sz=%d val=%#x pc=%#x inSO=%v\n", addr, size, uint64(value), pcRel, inSO)
				w408++
			}
		})
		_ = medStopped
		return
	}
	_, _ = e.HookRange(m.Base+0x2aa000, m.Base+0x2c2000, func(h *emulator.Hook, addr uint64) {
		if encDumped {
			return
		}
		// cheap pre-filter: protobuf head built (08 01) — only then do the expensive completeness check
		pbh, _ := h.Emu().ReadBytes(0x4052d000, 2)
		if len(pbh) != 2 || pbh[0] != 0x08 || pbh[1] != 0x01 {
			return
		}
		// protobuf complete when the JSON tail "false}" is present in the protobuf region (f4 written last)
		pbtail, _ := h.Emu().ReadBytes(0x4052d000+300, 262)
		if !bytes.Contains(pbtail, []byte("false}")) {
			return
		}
		pcb, _ := h.Emu().ReadBytes(h.Reg(19), 4)
		ib, _ := h.Emu().ReadBytes(h.Reg(20), 8)
		bh, _ := h.Emu().ReadBytes(0x4050a000, 8)
		fmt.Printf("[ENC-ENTRY] ecbN=%d handler@%#x VMpc=%x instrArr=%#x body=%x\n", ecbN, rel(addr), pcb, rel(rd8le(ib)), bh)
		dumpState(h, "enc")
		// also dump native GP registers at the trace start, for the lifter's initial state
		var sb []byte
		for i := 0; i < 34; i++ {
			sb = append(sb, []byte(fmt.Sprintf("%d=%x\n", i, h.Reg(i)))...)
		}
		_ = os.WriteFile("enc_gpregs.txt", sb, 0644)
		// emulator.TraceGate = true // (off: this run only needs the rf_at_2c / rf_after_2c dumps)
		encDumped = true
	})
	// [BODYWR]: who writes the ciphertext body to 0x4050a000? (placeholder d0837b12 -> 09ac3193 = the
	// MAIN encryption). Log the writing PC so we can locate + reverse the core body cipher.
	bodyWrN := 0
	mencDumped := false
	_, _ = e.HookMemWrite(0x4050a000, 0x4050a008, func(h *emulator.Hook, addr uint64, size int, value int64) {
		if !encDumped {
			return
		}
		// the main body cipher writes the ciphertext via SB handler 0x2ad9b0 — capture its VM context
		// (x20=instrArr ptr, x19=pc ptr, x23=regfile) + dump state, so we can lift the core cipher.
		if h.PC() == m.Base+0x2ad9b0 && !mencDumped {
			ib, _ := h.Emu().ReadBytes(h.Reg(20), 8)
			pcb, _ := h.Emu().ReadBytes(h.Reg(19), 4)
			instrArr := rd8le(ib)
			x23 := h.Reg(23)
			rf, _ := h.Emu().ReadBytes(x23, 8*256)
			drm2 := func(lo, hi uint64) []byte {
				var b []byte
				for a := lo; a < hi; a += 0x1000 {
					pg, e := h.Emu().ReadBytes(a, 0x1000)
					if e != nil {
						pg = make([]byte, 0x1000)
					}
					b = append(b, pg...)
				}
				return b
			}
			_ = os.WriteFile("menc_rf.bin", rf, 0644)
			_ = os.WriteFile("menc_heap.bin", drm2(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("menc_low.bin", drm2(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("menc_stack.bin", drm2(0xc07e0000, 0xc0800000), 0644)
			_ = os.WriteFile("menc_meta.txt", []byte(fmt.Sprintf("instrArr=%#x pc=%d x19=%#x x20=%#x x23=%#x", rel(instrArr), int32(rd8le(pcb)), h.Reg(19), h.Reg(20), x23)), 0644)
			fmt.Printf("[MENC] main-encryption VM: instrArr=%#x pc=%d x23=%#x\n", rel(instrArr), int32(rd8le(pcb)), x23)
			mencDumped = true
		}
		if bodyWrN <= 30 {
			fmt.Printf("[BODYWR] pc=%#x lr=%#x addr=%#x sz=%d val=%#x\n", rel(h.PC()), rel(h.LR()), addr, size, uint64(value))
			bodyWrN++
		}
	})
	// [MEDFIND] discovery: locate where the X-Medusa body176 / header / post-XOR buffer is assembled,
	// and by which native PC. body176=cipher(device_pt); header=count+12; postXOR=base64-input.
	medFind := map[string]bool{}
	medPats := map[string][]byte{
		"body176": {0xc2, 0x36, 0xa4, 0xfe, 0x8e, 0x66, 0x53, 0x68},
		"header":  {0x07, 0x00, 0x00, 0x00, 0x6b, 0x9a, 0x2b, 0x2a},
		"postXOR": {0x07, 0xf1, 0x53, 0x65, 0x6b, 0x6b, 0x78, 0x4f},
	}
	medChk := func(h *emulator.Hook, addr uint64) {
		win, _ := h.Emu().ReadBytes(addr&^63, 128)
		for tag, pat := range medPats {
			if medFind[tag] {
				continue
			}
			if idx := bytes.Index(win, pat); idx >= 0 {
				fmt.Printf("[MEDFIND] %s @buf=%#x pc=%#x lr=%#x\n", tag, (addr&^63)+uint64(idx), rel(h.PC()), rel(h.LR()))
				medFind[tag] = true
			}
		}
	}
	_, _ = e.HookMemWrite(0x40140000, 0x401a0000, func(h *emulator.Hook, addr uint64, size int, value int64) {
		medChk(h, addr)
	})
	// [MEDBODY] trace distinct PCs writing the X-Medusa body buffer (0x401646a0..); reveals the body
	// cipher output + assembly. On the XOR-khronos write (pc=0x2ad9b0), dump the buffer state.
	medBodyPCs := map[uint64]bool{}
	medBodyDumped := false
	_, _ = e.HookMemWrite(0x40164680, 0x40164790, func(h *emulator.Hook, addr uint64, size int, value int64) {
		pc := h.PC() - m.Base
		if !medBodyPCs[pc] {
			medBodyPCs[pc] = true
			fmt.Printf("[MEDBODY] writer pc=%#x lr=%#x addr=%#x sz=%d\n", pc, rel(h.LR()), addr, size)
		}
		// when the post-XOR head appears, dump the finalized 214-byte buffer (base64 input)
		if !medBodyDumped {
			b, _ := h.Emu().ReadBytes(0x401646a0, 8)
			if len(b) == 8 && b[0] == 0x07 && b[1] == 0xf1 && b[2] == 0x53 && b[3] == 0x65 {
				buf, _ := h.Emu().ReadBytes(0x401646a0, 214)
				_ = os.WriteFile("med_body214.bin", buf, 0644)
				fmt.Printf("[MEDBODY] dumped finalized 214B base64-input @0x401646a0\n")
				medBodyDumped = true
			}
		}
	})
	// [BODY176] find where the X-Medusa body176 (c236a4fe.. pre-XOR, the device-cipher output) is first
	// written + the VM (instrArr/pc) producing it -> the cipher entry to gate at (short clean replay).
	body176Found := false
	_, _ = e.HookMemWrite(0x40800000, 0x40c00000, func(h *emulator.Hook, addr uint64, size int, value int64) {
		if body176Found {
			return
		}
		b, _ := h.Emu().ReadBytes(addr&^7, 16)
		if i := bytes.Index(b, []byte{0xc2, 0x36, 0xa4, 0xfe, 0x8e, 0x66, 0x53, 0x68}); i >= 0 {
			body176Found = true
			ib, _ := h.Emu().ReadBytes(h.Reg(20), 8)
			pcb, _ := h.Emu().ReadBytes(h.Reg(19), 4)
			var ia uint64
			var pcv int32
			if len(ib) == 8 {
				ia = rd8le(ib)
			}
			if len(pcb) == 4 {
				pcv = int32(rd8le(pcb))
			}
			fmt.Printf("[BODY176] @buf=%#x writer-pc=%#x lr=%#x VM_ia=%#x VM_pc=%d x23=%#x\n",
				(addr&^7)+uint64(i), rel(h.PC()), rel(h.LR()), rel(ia), pcv, h.Reg(23))
		}
	})
	// [IVM]: the inner VM (0x2db000) main-encryption bytecode lives at ~0x475dxxxx (out of heap). The
	// HookAddr on the decoder fails to install, so use HookMemRead on the bytecode region: on the first
	// read after ENC-ENTRY, dump a chunk around it (the inner-VM bytecode) + the decode table.
	ivmN := 0
	_, _ = e.HookMemRead(0x40140000, 0x40540000, func(h *emulator.Hook, addr uint64, size int) {
		if !encDumped || ivmN >= 10 {
			return
		}
		pc := h.PC() - m.Base
		if pc < 0x2dbb00 || pc > 0x2dbca0 { // only the inner-VM decoder's reads
			return
		}
		x9, x10, x11 := h.Reg(9), h.Reg(10), h.Reg(11)
		if ivmN == 0 {
			bc, _ := h.Emu().ReadBytes(x10&^0xff, 0x800)
			tbl, _ := h.Emu().ReadBytes(x11, 0x300)
			_ = os.WriteFile("ivm_bytecode.bin", bc, 0644)
			_ = os.WriteFile("ivm_table.bin", tbl, 0644)
		}
		fmt.Printf("[IVMCTX] #%d pc=%#x readaddr=%#x x9=%#x x10=%#x x11=%#x x12=%#x\n",
			ivmN, pc, addr, x9, x10, x11, h.Reg(12))
		ivmN++
	})
	// [SBOX]: sub_2caa60's table lookup (ldrb w8,[x8,x3] @0x2caae0) — x3=table base, x8=index. If a
	// 256-byte table, it's the SubBytes S-box of the FP-serializer/main-encryption. Dump it.
	sboxN := 0
	_, _ = e.HookAddr(m.Base+0x2caae0, func(h *emulator.Hook) {
		if sboxN >= 12 {
			return
		}
		x3, x8 := h.Reg(3), h.Reg(8)
		tbl, _ := h.Emu().ReadBytes(x3, 256)
		fmt.Printf("[SBOX] #%d table@%#x idx=%#x head=%x\n", sboxN, rel(x3), x8, tbl[:24])
		if sboxN == 0 {
			_ = os.WriteFile("sbox_table.bin", tbl, 0644)
		}
		sboxN++
	})
	// [ENCTRACE]: gate the instruction trace to START at the main encryption's first protobuf read
	// (after ENC-ENTRY = protobuf complete) -> enc_trace.txt captures protobuf->ciphertext for the lift.
	_ = 0 // [ENCTRACE] disabled (the trace HookInsns blocked the [IVM] HookAddr); IVM hook needs no trace
	// [aes] AES-128 (sub_243084): input block (x1) + first/last roundkey (x0+0xf0). Count all calls
	// to see if Helios (or anything besides Medusa's 22) uses this white-box AES.
	aesN := 0
	_, _ = e.HookAddr(m.Base+0x243084, func(h *emulator.Hook) {
		x0, x1 := h.Arg(0), h.Arg(1)
		in, _ := h.Emu().ReadBytes(x1, 16)
		rk0, _ := h.Emu().ReadBytes(x0+0xf0, 16)
		rkL, _ := h.Emu().ReadBytes(x0+0xf0+160, 16)
		fmt.Printf("[aes #%d] x1=%#x in=%x rk0=%x rkL=%x\n", aesN, rel(x1), in, rk0, rkL)
		aesN++
	})
	// [md5] MD5 compress sub_243ac0(state=x0, block=x1): when the block is the Helios key
	// material (rand4 + "482431"), walk the FP chain to locate the Helios builder function.
	heliosSeen := false
	_, _ = e.HookAddr(m.Base+0x243ac0, func(h *emulator.Hook) {
		blk, _ := h.Emu().ReadBytes(h.Arg(1), 32)
		fmt.Printf("[md5blk] blk=%x lr=%#x\n", blk, rel(h.LR()))
		if !heliosSeen && len(blk) >= 11 && string(blk[4:10]) == "482431" && blk[10] == 0x80 {
			heliosSeen = true
			fmt.Printf("[HELIOS] key block=%x rand4=%x\n", blk[:10], blk[:4])
			dr := func(lo, hi uint64) []byte {
				var b []byte
				for a := lo; a < hi; a += 0x1000 {
					pg, err := h.Emu().ReadBytes(a, 0x1000)
					if err != nil {
						pg = make([]byte, 0x1000)
					}
					b = append(b, pg...)
				}
				return b
			}
			_ = os.WriteFile("hel_heap.bin", dr(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("hel_low.bin", dr(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("hel_stack.bin", dr(0xc07e0000, 0xc0800000), 0644)
			// emulator.TraceGate = true // (off: Perseus-capture run, trace not needed)
		}
	})
	// [memrd] who reads the device buffer @0x4016e180? buf0=73d5.. = ciphertext (AES reads it);
	// buf0=2c48.. = plaintext (the X-Medusa body cipher reads it). Dedup by (pc, is-plaintext).
	seenRd := map[uint64]bool{}
	_, _ = e.HookMemRead(0x4016e180, 0x4016e400, func(h *emulator.Hook, addr uint64, size int) {
		cur, _ := h.Emu().ReadBytes(0x4016e180, 4)
		rpc := rel(h.PC())
		k := rpc << 1
		if len(cur) > 0 && cur[0] == 0x2c {
			k |= 1
		}
		if seenRd[k] {
			return
		}
		seenRd[k] = true
		fmt.Printf("[memrd] pc=%#x reads=%#x sz=%d buf0=%x\n", rpc, rel(addr), size, cur)
	})
	// Capture the lazily-generated VM bytecode of the body-cipher program (0x40751800) + cipher-core
	// region AS the VM fetches it (the slots are zero in static snapshots). Dedup by 48-byte slot.
	medProg := map[uint64][]byte{}
	_, _ = e.HookMemRead(0x40751800, 0x40790000, func(h *emulator.Hook, addr uint64, size int) {
		slot := 0x40751800 + ((addr-0x40751800)/48)*48
		if _, ok := medProg[slot]; !ok {
			b, _ := h.Emu().ReadBytes(slot, 48)
			medProg[slot] = b
		}
	})
	// [KEYWR] capture the per-run body-cipher KEY build: the key is DERIVED at 0x40154200 then
	// memcpy'd to 0x40154140 — hook both regions to capture the derivation at the source.
	_, _ = e.HookMemWrite(0x40154130, 0x40154230, func(h *emulator.Hook, addr uint64, size int, value int64) {
		fmt.Printf("[KEYWR] pc=%#x addr=%#x sz=%d val=%016x x0=%#x x1=%#x x2=%#x lr=%#x\n",
			rel(h.PC()), addr, size, uint64(value), h.Reg(0), h.Reg(1), h.Reg(2), rel(h.LR()))
		// Capture the RIGHT key-build VM: when an in-.so handler (SB) writes the key bytes, dump its
		// regfile (x23) + memory + log instrArr context (x0/pcval), and gate the trace for the lift.
		if !keyTraced && addr >= 0x40154218 && addr <= 0x4015421f && h.Reg(0) >= 0x40a80000 && h.Reg(0) < 0x40a90000 {
			dd := func(name string, lo, hi uint64) {
				var b []byte
				for a := lo; a < hi; a += 0x1000 {
					pg, e := h.Emu().ReadBytes(a, 0x1000)
					if e != nil {
						pg = make([]byte, 0x1000)
					}
					b = append(b, pg...)
				}
				_ = os.WriteFile(name, b, 0644)
			}
			rf, _ := h.Emu().ReadBytes(h.Reg(23), 8*256)
			_ = os.WriteFile("kb_rf.bin", rf, 0644)
			dd("kb_heap.bin", 0x40400000, 0x40c00000)
			dd("kb_low.bin", 0x40100000, 0x40400000)
			dd("kb_stack.bin", 0xc07e0000, 0xc0800000)
			pcv, _ := h.Emu().ReadBytes(h.Reg(19), 4)
			fmt.Printf("[KB] pc=%#x x0=%#x x19=%#x x20=%#x x23=%#x pcval=%x\n", rel(h.PC()), h.Reg(0), h.Reg(19), h.Reg(20), h.Reg(23), pcv)
			emulator.TraceGate = true
			keyTraced = true
		}
	})
	// [ecb] — hook the builtin dispatcher sub_2ECB10 to capture the encrypt's dispatch sequence
	// (word0 -> base_table[word0] -> obj+56=v4 -> off_368810[v4]=builtin, or v4!=0 = nested VM).
	_, _ = e.HookAddr(m.Base+0x2ecb10, func(h *emulator.Hook) {
		// rf_after_2c: fires on the FIRST dispatch AFTER the encrypt-core's 0x2c (any word0) — captures
		// 0x2c's scatter output so we can model sub_2a0a34 in pure Python.
		// precip snapshot at the dispatch RIGHT AFTER the encrypt-core's 0x2c (event-based, robust to
		// per-run address shifts): 0x2c's structure is built, orchestration is past it. The driver
		// resumes here, auto-resolves the rest (nested VMs + cipher loop) -> body, SKIPPING 0x2c.
		if encDumped && dumped2c && !dumped13 && h.Reg(1) == orchCtx {
			ctx := h.Reg(1)
			drp := func(lo, hi uint64) []byte {
				var b []byte
				for a := lo; a < hi; a += 0x1000 {
					pg, e := h.Emu().ReadBytes(a, 0x1000)
					if e != nil {
						pg = make([]byte, 0x1000)
					}
					b = append(b, pg...)
				}
				return b
			}
			rfb, _ := h.Emu().ReadBytes(ctx+0x6050, 8*256)
			pcb, _ := h.Emu().ReadBytes(ctx, 4)
			_ = os.WriteFile("precip_rf.bin", rfb, 0644)
			_ = os.WriteFile("precip_heap.bin", drp(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("precip_low.bin", drp(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("precip_stack.bin", drp(0xc07e0000, 0xc0800000), 0644)
			bh4, _ := h.Emu().ReadBytes(0x4050a000, 8)
			_ = os.WriteFile("precip_meta.txt", []byte(fmt.Sprintf("ctx=%#x pc=%d body=%x", ctx, int32(rd8le(pcb)), bh4)), 0644)
			fmt.Printf("[PRECIP] after-0x2c: ctx=%#x VMpc=%d body=%x\n", ctx, int32(rd8le(pcb)), bh4)
			dumped13 = true
		}
		a1, a3 := h.Arg(0), h.Arg(2)
		p1, _ := h.Emu().ReadBytes(a1+8, 8)
		obj := rd8le(p1)
		p2, _ := h.Emu().ReadBytes(obj, 8)
		base := rd8le(p2)
		p3, _ := h.Emu().ReadBytes(base+8*a3, 8)
		v3 := rd8le(p3)
		p4, _ := h.Emu().ReadBytes(v3+56, 8)
		v4 := rd8le(p4)
		fp, _ := h.Emu().ReadBytes(v3, 8)
		fn := rd8le(fp)
		subIA := uint64(0)
		if v4 != 0 {
			ia, _ := h.Emu().ReadBytes(v3+8, 8)
			iap := rd8le(ia)
			iab, _ := h.Emu().ReadBytes(iap, 8)
			subIA = rd8le(iab)
		}
		bh, _ := h.Emu().ReadBytes(0x4050a000, 4)
		// Capture the regfile (ctx=x1=arg1, regfile@+0x6050) around the encrypt-core's 0x2c builtin
		// (sub_2a0a34): inputs at the 0x2c dispatch, outputs at the following 0x13 dispatch. This
		// lets us model 0x2c's scatter (rf[8/0xb/0xe/0x1b/0x1e]) in pure Python.
		if encDumped && a3 == 0x2c && !dumped2c {
			orchCtx = h.Reg(1) // the orchestration's ctx (0x2c is dispatched BY the orchestration)
			rfb, _ := h.Emu().ReadBytes(orchCtx+0x6050, 8*256)
			_ = os.WriteFile("rf_at_2c.bin", rfb, 0644)
			dumped2c = true
		}
		_ = dumpedPrecip
		// [MOVESRC]: log the 0x6 MOVE's dst(rf8)/src(rf9) in the encrypt core — the src is the buffer
		// holding the ciphertext body (09ac3193) built by the MAIN encryption (upstream of here).
		if encDumped && a3 == 0x6 {
			rf8b, _ := h.Emu().ReadBytes(h.Reg(1)+0x6050+8*8, 8)
			rf9b, _ := h.Emu().ReadBytes(h.Reg(1)+0x6050+9*8, 8)
			dst, src := rd8le(rf8b), rd8le(rf9b)
			// read the src buffer's data ptr (C++ buffer obj: data@+16) + first bytes
			dp, _ := h.Emu().ReadBytes(src+16, 8)
			data := rd8le(dp)
			pre, _ := h.Emu().ReadBytes(data, 16)
			fmt.Printf("[MOVESRC] dst=%#x src=%#x src.data=%#x bytes=%x\n", rel(dst), rel(src), rel(data), pre)
		}
		// cipA/cipB: full heap at the 1st vs last cipher (0x4076b760) dispatch -> diff reveals the
		// state buffer + the MixColumns round writes (deterministic, so the diff is meaningful).
		if encDumped && subIA == 0x4076b760 {
			cipN++
			drc := func(lo, hi uint64) []byte {
				var b []byte
				for a := lo; a < hi; a += 0x1000 {
					pg, e := h.Emu().ReadBytes(a, 0x1000)
					if e != nil {
						pg = make([]byte, 0x1000)
					}
					b = append(b, pg...)
				}
				return b
			}
			if cipN == 1 {
				_ = os.WriteFile("cipA_heap.bin", drc(0x40400000, 0x40c00000), 0644)
			}
			if cipN == 128 {
				_ = os.WriteFile("cipB_heap.bin", drc(0x40400000, 0x40c00000), 0644)
				fmt.Printf("[CIPAB] dumped heap at cipher#1 and #128\n")
			}
		}
		// [CIO]: at every nested-VM dispatch in the encrypt core, log the shared regfile r[5..11]
		// (the cipher's input block) + body[0:8]. Offline: the cipher = the repeated subIA; this
		// validates enc_cipher_core.py against the real 128 I/O pairs + reveals the loop's body addressing.
		if encDumped && v4 != 0 {
			rfreg, _ := h.Emu().ReadBytes(h.Reg(1)+0x6050+5*8, 7*8)
			b8, _ := h.Emu().ReadBytes(0x4050a000, 8)
			fmt.Printf("[CIO] sub=%#x r5_11=%x body=%x\n", rel(subIA), rfreg, b8)
		}
		fmt.Printf("[ecb #%d] word0=%#x v4=%d builtin=%#x subIA=%#x body=%x\n", ecbN, a3, v4, rel(fn), rel(subIA), bh)
		ecbN++
	})
	n := 0
	_, _ = e.HookAddr(m.Base+0x2ab64c, func(h *emulator.Hook) {
		x0 := h.Arg(0)
		ib, _ := h.Emu().ReadBytes(x0, 8)
		ia := rd8le(ib)
		body, _ := h.Emu().ReadBytes(0x4050a000, 8)
		pbh, _ := h.Emu().ReadBytes(0x4052d000, 4)
		pcb, _ := h.Emu().ReadBytes(h.Arg(1), 4)
		pc := uint64(0)
		if len(pcb) == 4 {
			pc = uint64(pcb[0]) | uint64(pcb[1])<<8 | uint64(pcb[2])<<16 | uint64(pcb[3])<<24
		}
		fmt.Printf("[vm #%d] ia=%#x pc=%#x body=%x pb=%x\n", n, rel(ia), pc, body, pbh)
		// dump the cipher-core nested VM (0x4076b760) entry state on its first call (confirm GF mul + lift)
		if ia == 0x4076b760 && !ccoreDumped {
			base := h.Arg(1)
			x23 := base + 0x6050
			dr := func(lo, hi uint64) []byte {
				var b []byte
				for a := lo; a < hi; a += 0x1000 {
					pg, err := h.Emu().ReadBytes(a, 0x1000)
					if err != nil {
						pg = make([]byte, 0x1000)
					}
					b = append(b, pg...)
				}
				return b
			}
			rf, _ := h.Emu().ReadBytes(x23, 8*256)
			_ = os.WriteFile("ccore_rf.bin", rf, 0644)
			_ = os.WriteFile("ccore_heap.bin", dr(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("ccore_lowheap.bin", dr(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("ccore_stack.bin", dr(0xc07e0000, 0xc0800000), 0644)
			fmt.Printf("[CCORE] dumped cipher-core entry #%d base=%#x x23=%#x\n", n, rel(base), rel(x23))
			ccoreDumped = true
		}
		drm := func(lo, hi uint64) []byte {
			var b []byte
			for a := lo; a < hi; a += 0x1000 {
				pg, err := h.Emu().ReadBytes(a, 0x1000)
				if err != nil {
					pg = make([]byte, 0x1000)
				}
				b = append(b, pg...)
			}
			return b
		}
		// Gate the trace ON at the body-cipher VM entry, to capture the per-run key-build into 0x40154140.
		if ia == 0x40751800 && !bcGated {
			emulator.TraceGate = true
			bcGated = true
			fmt.Println("[BCGATE] trace ON at body-cipher VM entry (capture key-build)")
		}
		// Medusa body-cipher stage 0x40751800 pc=0x4b1 (first body cipher after the 256x S-box build)
		if ia == 0x40751800 && pc == 0x4b1 && !med751Dumped {
			base := h.Arg(1)
			rf, _ := h.Emu().ReadBytes(base+0x6050, 8*256)
			_ = os.WriteFile("med_rf.bin", rf, 0644)
			_ = os.WriteFile("med_heap.bin", drm(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("med_lowheap.bin", drm(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("med_stack.bin", drm(0xc07e0000, 0xc0800000), 0644)
			fmt.Printf("[MED751] dumped #%d ia=%#x pc=%#x base=%#x\n", n, rel(ia), pc, base)
			med751Dumped = true
		}
		// Capture the FIRST 4 body-cipher (0x40751800) invocations to lift each KEY:
		// Medusa-body / Perseus-body / ... use the same program with different 19-byte keys.
		if ia == 0x40751800 && pc == 0x4b1 && bcN < 4 {
			base := h.Arg(1)
			suf := fmt.Sprintf("%d", bcN)
			rf, _ := h.Emu().ReadBytes(base+0x6050, 8*256)
			_ = os.WriteFile("bc"+suf+"_rf.bin", rf, 0644)
			_ = os.WriteFile("bc"+suf+"_heap.bin", drm(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("bc"+suf+"_low.bin", drm(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("bc"+suf+"_stack.bin", drm(0xc07e0000, 0xc0800000), 0644)
			fmt.Printf("[BC%d] body-cipher ia=%#x base=%#x\n", bcN, rel(ia), base)
			bcN++
		}
		// Medusa ph6 stage 0x40900000 (first occurrence) — the chained-boolean cipher
		if ia == 0x40900000 && !medphDumped {
			base := h.Arg(1)
			rf, _ := h.Emu().ReadBytes(base+0x6050, 8*256)
			_ = os.WriteFile("medph_rf.bin", rf, 0644)
			_ = os.WriteFile("medph_heap.bin", drm(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("medph_lowheap.bin", drm(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("medph_stack.bin", drm(0xc07e0000, 0xc0800000), 0644)
			img := make([]byte, 0x40790000-0x40751800)
			for slot, b := range medProg {
				copy(img[slot-0x40751800:], b)
			}
			_ = os.WriteFile("med_prog.bin", img, 0644)
			fmt.Printf("[MEDPH] dumped #%d ia=%#x pc=%#x base=%#x med_prog_slots=%d\n", n, rel(ia), pc, base, len(medProg))
			medphDumped = true
		}
		// Helios cipher VM entry (instrArr 0x4050ac00) — capture clean entry rf+mem to lift it.
		if ia == 0x4050ac00 && !helvmDumped {
			base := h.Arg(1)
			rf, _ := h.Emu().ReadBytes(base+0x6050, 8*256)
			_ = os.WriteFile("helvm_rf.bin", rf, 0644)
			_ = os.WriteFile("helvm_heap.bin", drm(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("helvm_low.bin", drm(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("helvm_stack.bin", drm(0xc07e0000, 0xc0800000), 0644)
			fmt.Printf("[HELVM] dumped #%d ia=%#x pc=%#x base=%#x\n", n, rel(ia), pc, base)
			emulator.TraceGate = true // trace the Helios cipher VM from its clean pc=0 entry (same run)
			helvmDumped = true
		}
		// Perseus ph6b (E_in assembler) instrArr 0x40900000 at pc=10047 (run_endtoend's STEP1 entry)
		if ia == 0x40900000 && pc == 10047 && !pPhDumped {
			base := h.Arg(1)
			rf, _ := h.Emu().ReadBytes(base+0x6050, 8*256)
			_ = os.WriteFile("pph6b_rf.bin", rf, 0644)
			_ = os.WriteFile("pph6b_heap.bin", drm(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("pph6b_lowheap.bin", drm(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("pph6b_stack.bin", drm(0xc07e0000, 0xc0800000), 0644)
			fmt.Printf("[PPH6B] dumped ia=%#x pc=%#x base=%#x\n", rel(ia), pc, base)
			pPhDumped = true
		}
		// Perseus ph7 (encrypt + base64 -> X-Perseus) instrArr 0x4075b800 (run_endtoend's STEP2)
		if ia == 0x4075b800 && !ph7Dumped {
			base := h.Arg(1)
			rf, _ := h.Emu().ReadBytes(base+0x6050, 8*256)
			_ = os.WriteFile("pph7_rf.bin", rf, 0644)
			_ = os.WriteFile("pph7_heap.bin", drm(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("pph7_lowheap.bin", drm(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("pph7_stack.bin", drm(0xc07e0000, 0xc0800000), 0644)
			fmt.Printf("[PPH7] dumped ia=%#x pc=%#x base=%#x\n", rel(ia), pc, base)
			ph7Dumped = true
		}
		// key-build VM (instrArr 0x40a8axxx) — capture entry to lift the per-run body-cipher key derivation.
		if ia >= 0x40a8a000 && ia < 0x40a8c000 && !kvmDumped {
			base := h.Arg(1)
			rf, _ := h.Emu().ReadBytes(base+0x6050, 8*256)
			_ = os.WriteFile("kvm_rf.bin", rf, 0644)
			_ = os.WriteFile("kvm_heap.bin", drm(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("kvm_low.bin", drm(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("kvm_stack.bin", drm(0xc07e0000, 0xc0800000), 0644)
			fmt.Printf("[KVM] ia=%#x pc=%#x base=%#x\n", rel(ia), pc, base)
			emulator.TraceGate = true // trace the key-build VM from its clean pc=0 entry (trace-driven lift)
			kvmDumped = true
		}
		// Perseus encrypt CIPHER VM (instrArr 0x4076b760, called 128x in the encrypt core) — capture
		// the clean entry of the FIRST call + gate the trace, to lift the core cipher (like body_cipher).
		if ia == 0x4076b760 {
			cvmN++
			if !cvmDumped {
				base := h.Arg(1)
				rf, _ := h.Emu().ReadBytes(base+0x6050, 8*256)
				_ = os.WriteFile("cvm_rf.bin", rf, 0644)
				_ = os.WriteFile("cvm_heap.bin", drm(0x40400000, 0x40c00000), 0644)
				_ = os.WriteFile("cvm_low.bin", drm(0x40100000, 0x40400000), 0644)
				_ = os.WriteFile("cvm_stack.bin", drm(0xc07e0000, 0xc0800000), 0644)
				bh, _ := h.Emu().ReadBytes(0x4050a000, 16)
				fmt.Printf("[CVM] call#%d ia=%#x pc=%#x base=%#x body=%x\n", cvmN, rel(ia), pc, base, bh)
				emulator.TraceGate = true // trace this cipher-VM call from its clean entry (trace-driven lift)
				cvmDumped = true
			}
		}
		if n == dumpN {
			base := h.Arg(1)
			x23 := base + 0x6050
			dr := func(lo, hi uint64) []byte {
				var b []byte
				for a := lo; a < hi; a += 0x1000 {
					pg, err := h.Emu().ReadBytes(a, 0x1000)
					if err != nil {
						pg = make([]byte, 0x1000)
					}
					b = append(b, pg...)
				}
				return b
			}
			rf, _ := h.Emu().ReadBytes(x23, 8*256)
			_ = os.WriteFile("a8vm_rf.bin", rf, 0644)
			_ = os.WriteFile("a8vm_heap.bin", dr(0x40400000, 0x40c00000), 0644)
			_ = os.WriteFile("a8vm_lowheap.bin", dr(0x40100000, 0x40400000), 0644)
			_ = os.WriteFile("a8vm_stack.bin", dr(0xc07e0000, 0xc0800000), 0644)
			fmt.Printf("[A8DUMP] dumped entry #%d ia=%#x pc=%#x base=%#x x23=%#x\n", n, rel(ia), pc, rel(base), rel(x23))
		}
		n++
	})
}
