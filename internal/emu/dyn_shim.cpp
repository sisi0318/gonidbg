//go:build dynarmic

// C++ implementation of the dyn_shim C ABI: a Dynarmic::A64::Jit plus an owned
// guest-memory page map. See dyn_shim.h for the design rationale.
#include "dyn_shim.h"

#include "dynarmic/interface/A64/a64.h"
#include "dynarmic/interface/A64/config.h"
#include "dynarmic/interface/exclusive_monitor.h"
#include "dynarmic/interface/halt_reason.h"

#include <cstdlib>
#include <cstring>
#include <optional>
#include <unordered_map>
#include <vector>

using namespace Dynarmic;

// Go trampolines (exported from dynarmic_cgo.go). Named goDyn* so they never
// collide with the unicorn backend's goCodeHook/goIntrHook/goMemHook when both
// engines are compiled into the same binary.
extern "C" void goDynIntrHook(uint64_t cbid, uint32_t swi);
extern "C" int  goDynMemHook(uint64_t cbid, int type, uint64_t addr, int size, int64_t value);

namespace {

constexpr uint64_t PAGE = 0x1000;

// Guest address space bits for the direct page table. The signer's layout tops
// out at the TLS block (~0xD001_0000), so 32 bits covers everything; addresses
// beyond fall back to the slow callbacks (silently_mirror_page_table = false).
// Table size = 2^(PT_BITS-12) pointers = 1M * 8 = 8 MiB per engine.
constexpr unsigned PT_BITS = 32;

// Mem is the guest address space: a map of page-base -> 4 KiB host buffer, plus
// a flat page table of those host pointers that dynarmic reads/writes DIRECTLY
// from JIT'd code (no callback) — the difference between JIT speed and
// interpreter speed. The unordered_map owns the buffers; ptbl mirrors them for
// the fast path. Pages are created on map() and on any write; reads of unmapped
// pages yield 0. Code fetches of an unmapped page return nullopt so dynarmic
// raises a NoExecuteFault — that's how a return to the call sentinel stops a run.
struct Mem {
	std::unordered_map<uint64_t, uint8_t *> pages;
	std::vector<void *> ptbl; // [va>>12] -> host page; consumed by config.page_table

	Mem() : ptbl(size_t(1) << (PT_BITS - 12), nullptr) {}

	~Mem() {
		for (auto &kv : pages) std::free(kv.second);
	}

	uint8_t *page(uint64_t va, bool create) {
		uint64_t pg = va >> 12;
		auto it = pages.find(pg);
		if (it != pages.end()) return it->second;
		if (!create) return nullptr;
		uint8_t *buf = static_cast<uint8_t *>(std::calloc(1, PAGE));
		pages[pg] = buf;
		if (pg < ptbl.size()) ptbl[pg] = buf; // expose to the JIT fast path
		return buf;
	}

	void map(uint64_t addr, uint64_t size) {
		uint64_t a = addr & ~(PAGE - 1);
		uint64_t end = (addr + size + PAGE - 1) & ~(PAGE - 1);
		for (uint64_t p = a; p < end; p += PAGE) page(p, true);
	}

	void unmap(uint64_t addr, uint64_t size) {
		uint64_t a = addr & ~(PAGE - 1);
		uint64_t end = (addr + size + PAGE - 1) & ~(PAGE - 1);
		for (uint64_t p = a; p < end; p += PAGE) {
			uint64_t pg = p >> 12;
			if (pg < ptbl.size()) ptbl[pg] = nullptr; // drop from the fast path first
			auto it = pages.find(pg);
			if (it != pages.end()) {
				std::free(it->second);
				pages.erase(it);
			}
		}
	}

	bool mapped(uint64_t va) { return page(va, false) != nullptr; }

	void read(uint64_t addr, void *dst, uint64_t n) {
		uint8_t *d = static_cast<uint8_t *>(dst);
		for (uint64_t i = 0; i < n;) {
			uint64_t va = addr + i;
			uint8_t *pg = page(va, false);
			uint64_t off = va & (PAGE - 1);
			uint64_t chunk = PAGE - off;
			if (chunk > n - i) chunk = n - i;
			if (pg) std::memcpy(d + i, pg + off, chunk);
			else std::memset(d + i, 0, chunk);
			i += chunk;
		}
	}

	void write(uint64_t addr, const void *src, uint64_t n) {
		const uint8_t *s = static_cast<const uint8_t *>(src);
		for (uint64_t i = 0; i < n;) {
			uint64_t va = addr + i;
			uint8_t *pg = page(va, true); // writes create pages (heap/brk growth)
			uint64_t off = va & (PAGE - 1);
			uint64_t chunk = PAGE - off;
			if (chunk > n - i) chunk = n - i;
			std::memcpy(pg + off, s + i, chunk);
			i += chunk;
		}
	}

	template <typename T>
	T readT(uint64_t va) {
		T v{};
		read(va, &v, sizeof(T));
		return v;
	}
	template <typename T>
	void writeT(uint64_t va, T v) {
		write(va, &v, sizeof(T));
	}
};

struct Engine; // fwd

struct Callbacks final : public A64::UserCallbacks {
	Engine *e = nullptr;

	std::optional<std::uint32_t> MemoryReadCode(A64::VAddr vaddr) override;

	std::uint8_t  MemoryRead8(A64::VAddr v) override;
	std::uint16_t MemoryRead16(A64::VAddr v) override;
	std::uint32_t MemoryRead32(A64::VAddr v) override;
	std::uint64_t MemoryRead64(A64::VAddr v) override;
	A64::Vector   MemoryRead128(A64::VAddr v) override;

	void MemoryWrite8(A64::VAddr v, std::uint8_t value) override;
	void MemoryWrite16(A64::VAddr v, std::uint16_t value) override;
	void MemoryWrite32(A64::VAddr v, std::uint32_t value) override;
	void MemoryWrite64(A64::VAddr v, std::uint64_t value) override;
	void MemoryWrite128(A64::VAddr v, A64::Vector value) override;

	// Single-core emulation: exclusive stores always succeed (do the write).
	bool MemoryWriteExclusive8(A64::VAddr v, std::uint8_t value, std::uint8_t) override { MemoryWrite8(v, value); return true; }
	bool MemoryWriteExclusive16(A64::VAddr v, std::uint16_t value, std::uint16_t) override { MemoryWrite16(v, value); return true; }
	bool MemoryWriteExclusive32(A64::VAddr v, std::uint32_t value, std::uint32_t) override { MemoryWrite32(v, value); return true; }
	bool MemoryWriteExclusive64(A64::VAddr v, std::uint64_t value, std::uint64_t) override { MemoryWrite64(v, value); return true; }
	bool MemoryWriteExclusive128(A64::VAddr v, A64::Vector value, A64::Vector) override { MemoryWrite128(v, value); return true; }

	void InterpreterFallback(A64::VAddr pc, size_t) override;
	void CallSVC(std::uint32_t swi) override;
	void ExceptionRaised(A64::VAddr pc, A64::Exception exception) override;

	void AddTicks(std::uint64_t ticks) override;
	std::uint64_t GetTicksRemaining() override;
	std::uint64_t GetCNTPCT() override { return ticks_total; }

	std::uint64_t ticks_total = 0;
};

struct Engine {
	Mem mem;
	Callbacks cb;
	A64::UserConfig config;
	A64::Jit *jit = nullptr;
	ExclusiveMonitor *monitor = nullptr; // required once the guest uses LDXR/STXR

	std::uint64_t tpidr_el0 = 0;
	std::uint64_t until = 0;          // PC that means "call returned" -> stop
	std::uint64_t intr_cbid = 0;      // Go SVC hook id
	std::uint64_t mem_cbid = 0;       // Go unmapped-access hook id
	std::uint64_t budget = 0;         // remaining instruction budget (runaway guard)
	bool stop_requested = false;      // dyn_emu_stop called from a callback
	bool fault = false;               // unexpected NoExecuteFault (bad jump)
};

// ---- Callbacks -> Engine memory / Go --------------------------------------
std::optional<std::uint32_t> Callbacks::MemoryReadCode(A64::VAddr vaddr) {
	// Treat the call's `until` address as a no-execute trap so a return to it
	// stops the run cleanly — works whether or not that page is mapped (unicorn's
	// emu_start(begin, until) has this built in; dynarmic does not).
	if (vaddr == e->until || !e->mem.mapped(vaddr)) return std::nullopt;
	return e->mem.readT<std::uint32_t>(vaddr);
}

std::uint8_t  Callbacks::MemoryRead8(A64::VAddr v)  { return e->mem.readT<std::uint8_t>(v); }
std::uint16_t Callbacks::MemoryRead16(A64::VAddr v) { return e->mem.readT<std::uint16_t>(v); }
std::uint32_t Callbacks::MemoryRead32(A64::VAddr v) { return e->mem.readT<std::uint32_t>(v); }
std::uint64_t Callbacks::MemoryRead64(A64::VAddr v) { return e->mem.readT<std::uint64_t>(v); }
A64::Vector   Callbacks::MemoryRead128(A64::VAddr v) {
	A64::Vector r;
	r[0] = e->mem.readT<std::uint64_t>(v);
	r[1] = e->mem.readT<std::uint64_t>(v + 8);
	return r;
}

void Callbacks::MemoryWrite8(A64::VAddr v, std::uint8_t value)   { e->mem.writeT<std::uint8_t>(v, value); }
void Callbacks::MemoryWrite16(A64::VAddr v, std::uint16_t value) { e->mem.writeT<std::uint16_t>(v, value); }
void Callbacks::MemoryWrite32(A64::VAddr v, std::uint32_t value) { e->mem.writeT<std::uint32_t>(v, value); }
void Callbacks::MemoryWrite64(A64::VAddr v, std::uint64_t value) { e->mem.writeT<std::uint64_t>(v, value); }
void Callbacks::MemoryWrite128(A64::VAddr v, A64::Vector value) {
	e->mem.writeT<std::uint64_t>(v, value[0]);
	e->mem.writeT<std::uint64_t>(v + 8, value[1]);
}

void Callbacks::InterpreterFallback(A64::VAddr, size_t) {
	// Never expected in practice; stop rather than silently misbehave.
	e->fault = true;
	e->jit->HaltExecution();
}

void Callbacks::CallSVC(std::uint32_t swi) {
	goDynIntrHook(e->intr_cbid, swi); // Go reads x8/x0.. and services the syscall
}

void Callbacks::ExceptionRaised(A64::VAddr pc, A64::Exception exception) {
	if (exception == A64::Exception::NoExecuteFault) {
		// A code fetch hit an unmapped page. If it's the call sentinel, that's a
		// normal return; otherwise it's a bad jump. Either way, stop.
		if (pc != e->until) e->fault = true;
		e->jit->HaltExecution();
		return;
	}
	// Other exceptions (hint instrs etc.) are not hooked by default; ignore.
}

void Callbacks::AddTicks(std::uint64_t ticks) {
	ticks_total += ticks;
	if (ticks >= e->budget) e->budget = 0;
	else e->budget -= ticks;
}

std::uint64_t Callbacks::GetTicksRemaining() {
	return e->budget; // 0 -> Run returns; dyn_emu_start reports DYN_ERR_RUN
}

A64::Jit *make_jit(Engine *e) {
	e->cb.e = e;
	e->monitor = new ExclusiveMonitor(1); // single core (processor_id 0)
	e->config = A64::UserConfig{};
	e->config.callbacks = &e->cb;
	e->config.tpidr_el0 = &e->tpidr_el0;
	e->config.global_monitor = e->monitor; // LDXR/STXR support (bionic atomics)
	// Direct page-table memory: the JIT reads/writes mapped pages with plain host
	// loads/stores (no callback) — this is what makes dynarmic fast. Callbacks
	// remain the fallback for unmapped pages and accesses that straddle a page
	// boundary (our pages aren't contiguous in host memory).
	e->config.page_table = e->mem.ptbl.data();
	e->config.page_table_address_space_bits = PT_BITS;
	e->config.silently_mirror_page_table = false; // out-of-range addr -> callback (correct)
	e->config.absolute_offset_page_table = false; // host = ptbl[addr>>12] + (addr & 0xFFF)
	e->config.detect_misaligned_access_via_page_table = 8 | 16 | 32 | 64 | 128;
	e->config.only_detect_misalignment_via_page_table_on_page_boundary = true;
	return new A64::Jit(e->config);
}

} // namespace

// ---- C ABI ----------------------------------------------------------------
extern "C" {

dyn_engine *dyn_new(void) {
	Engine *e = new (std::nothrow) Engine();
	if (!e) return nullptr;
	e->jit = make_jit(e);
	if (!e->jit) {
		delete e;
		return nullptr;
	}
	return reinterpret_cast<dyn_engine *>(e);
}

void dyn_free(dyn_engine *h) {
	Engine *e = reinterpret_cast<Engine *>(h);
	if (!e) return;
	delete e->jit;
	delete e->monitor;
	delete e;
}

const char *dyn_strerror(int code) {
	switch (code) {
	case DYN_OK:        return "ok";
	case DYN_ERR_REG:   return "bad register id";
	case DYN_ERR_NOMEM: return "out of memory";
	case DYN_ERR_RUN:   return "instruction budget exhausted before reaching return address";
	default:            return "error";
	}
}

int dyn_reg_read(dyn_engine *h, int regid, uint64_t *val) {
	Engine *e = reinterpret_cast<Engine *>(h);
	if (regid >= 0 && regid <= 30) { *val = e->jit->GetRegister((size_t)regid); return DYN_OK; }
	switch (regid) {
	case DYN_REG_SP:        *val = e->jit->GetSP(); return DYN_OK;
	case DYN_REG_PC:        *val = e->jit->GetPC(); return DYN_OK;
	case DYN_REG_NZCV:      *val = e->jit->GetPstate() & 0xF0000000u; return DYN_OK;
	case DYN_REG_TPIDR_EL0: *val = e->tpidr_el0; return DYN_OK;
	}
	return DYN_ERR_REG;
}

int dyn_reg_write(dyn_engine *h, int regid, uint64_t val) {
	Engine *e = reinterpret_cast<Engine *>(h);
	if (regid >= 0 && regid <= 30) { e->jit->SetRegister((size_t)regid, val); return DYN_OK; }
	switch (regid) {
	case DYN_REG_SP:        e->jit->SetSP(val); return DYN_OK;
	case DYN_REG_PC:        e->jit->SetPC(val); return DYN_OK;
	case DYN_REG_NZCV: {
		std::uint32_t ps = e->jit->GetPstate() & ~0xF0000000u;
		e->jit->SetPstate(ps | (std::uint32_t)(val & 0xF0000000u));
		return DYN_OK;
	}
	case DYN_REG_TPIDR_EL0: e->tpidr_el0 = val; return DYN_OK;
	}
	return DYN_ERR_REG;
}

int dyn_mem_map(dyn_engine *h, uint64_t addr, uint64_t size, uint32_t /*prot*/) {
	reinterpret_cast<Engine *>(h)->mem.map(addr, size);
	return DYN_OK;
}
int dyn_mem_unmap(dyn_engine *h, uint64_t addr, uint64_t size) {
	reinterpret_cast<Engine *>(h)->mem.unmap(addr, size);
	return DYN_OK;
}
int dyn_mem_protect(dyn_engine * /*h*/, uint64_t /*addr*/, uint64_t /*size*/, uint32_t /*prot*/) {
	return DYN_OK; // memory is ours; protection is not enforced (no exec/prot faults needed on the sign path)
}
int dyn_mem_write(dyn_engine *h, uint64_t addr, const void *p, uint64_t n) {
	reinterpret_cast<Engine *>(h)->mem.write(addr, p, n);
	return DYN_OK;
}
int dyn_mem_read(dyn_engine *h, uint64_t addr, void *p, uint64_t n) {
	reinterpret_cast<Engine *>(h)->mem.read(addr, p, n);
	return DYN_OK;
}

int dyn_emu_start(dyn_engine *h, uint64_t begin, uint64_t until) {
	Engine *e = reinterpret_cast<Engine *>(h);
	e->until = until;
	e->stop_requested = false;
	e->fault = false;
	e->budget = (1ull << 32); // runaway guard (~4e9 instructions)
	e->jit->SetPC(begin);
	e->jit->ClearHalt(); // clear any stale halt flag from a previous run
	e->jit->Run();
	uint64_t pc = e->jit->GetPC();
	if (e->stop_requested) return DYN_OK;            // explicit stop (e.g. exit_group)
	if (e->fault) return DYN_ERR_RUN;                // bad jump / interpreter fallback
	if (e->budget == 0 && pc != until) return DYN_ERR_RUN; // runaway guard
	return DYN_OK;                                   // clean return to the sentinel
}

int dyn_emu_stop(dyn_engine *h) {
	Engine *e = reinterpret_cast<Engine *>(h);
	e->stop_requested = true;
	e->jit->HaltExecution();
	return DYN_OK;
}

void dyn_flush_cache(dyn_engine *h) {
	Engine *e = reinterpret_cast<Engine *>(h);
	if (e && e->jit) e->jit->ClearCache(); // drop compiled blocks after a patch
}

void dyn_set_intr_cb(dyn_engine *h, uint64_t cbid) { reinterpret_cast<Engine *>(h)->intr_cbid = cbid; }
void dyn_set_mem_cb(dyn_engine *h, uint64_t cbid)  { reinterpret_cast<Engine *>(h)->mem_cbid = cbid; }

} // extern "C"
