Research artifacts behind PERF.md, kept as .txt so they are not built.

- `dispatch_microbench.go.txt` — floors of every dispatch strategy available in
  pure Go: indirect call, switch, replicated dispatch sites, fused pairs, and
  fusion payoff by coverage. Run it by copying into a scratch package:
  `go test -run X -bench . .`
- `jitspike_*.txt` — the spike proving a pure-Go build (CGO_ENABLED=0, no C
  toolchain) can allocate executable memory, emit x86-64 at run time and call
  it safely under GC and preemption. 1.38 ns entry overhead per call.

Both reproduce the numbers quoted in PERF.md, which is the argument for *not*
building a JIT today.
