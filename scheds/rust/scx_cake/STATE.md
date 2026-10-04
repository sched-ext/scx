# scx_cake — current state

Read first, every session. Rules: repository-root `CLAUDE.md`. Behaviour: `DESIGN.md`.
History: `docs/archive/STATE_ARCHIVE.md`, newest first; grep it, do not read it whole.
Offload rule: once nothing in an entry is owed, move it word for word to the archive
top; owed items move to Owed first.

## Now (2026-10-04)

- Code: `567715cc8` on `RitzDaCat/scx_cake-nightly`, committed locally, not pushed.
  Last upstream merge: PR #3786 (`c410fcbd7`).
- Host: 7.2.9-1-cachyos-custom with
  `docs/research/jit-bitops-prototype/0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch`
  (applies to 7.2.9 with offsets only). `sched_ext.dsq_direct=Y` serves every cake
  DSQ ID, and 7.2.9 sets `SCX_RQ_IN_WAKEUP` only on the core wakeup path: numbers
  from older kernels are not comparable.
- Defaults: native CTZ/POPCNT (auto-detected) and E1 (cached rq clock in
  ops.running). Policy base: the 2026-09-28 pool-serving C entry (archive).
- Test-only flags (the release is flagless): `--native-bitops`, `--portable-bitops`,
  `--native-ring`, `--native-hist`, `--kernel-signals`, `--signal-report`,
  `--handoff-ns`, `--toggle probe=1`, `--inspect-bpf`.
- A/B binaries kept: `target/cake_receipt_builds/cost_c1c1e5aad80f` (base) and
  `cost_400e7a766333` (E1).

## Pattern ledger with kernel requirement (2026-10-04)

"Stock" means any upstream/CachyOS kernel with sched_ext at the stated version;
"custom" means `0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch`.
Levels follow CLAUDE.md's metric order; game frames (level 1) are owed for all.

| Pattern | Kernel needed | Without it | Best evidence | Verdict |
|---|---|---|---|---|
| E1: ops.running reads cached `rq->scx.clock` | Stock ≥ 6.14 | CO-RE falls back to `scx_bpf_now()` | 24-slot appsim: running −3.10 ns [−4.32, −1.91], BPF −1.9 %; frames neutral | **Default** (`567715cc8`); game A/B owed |
| Native CTZ/POPCNT (auto default) | Custom (`bpf_ctz64`, `bpf_popcnt64`) | Portable builtins, auto-selected | running −2.31 ns, select −4.11 / −0.2 (two screens) | Default (auto-detected); game A/B owed |
| `bpf_fastcall` on scalar kfuncs | Custom (`KF_FASTCALL`) | Spills kept; still loads | select −1.08 then +1.82 | No effect |
| Mask removal via verifier return bounds | Custom (bounds) | Stock: native path pruned, portable used; an older custom kernel without bounds fails verification | enqueue −8.2 did not repeat | No effect |
| DSQ direct index (kernel side) | Custom (`sched_ext.dsq_direct`) | Hash lookup | Untested on hardware | Owed (reboot A/B) |
| Input/fence wake signals, IRQ ns | Custom | `--kernel-signals` reports unavailable | VM contract only | Owed (game observe) |
| 7.2.9 `SCX_RQ_IN_WAKEUP` fix | Stock 7.2.9 | Deferred work waits after remote wakeups | Source review | Baseline change |
| Division-free quotients | Portable, or custom MULHI/CLZ | Portable arithmetic | BPF +5.8 %, select +11 ns | Removed |
| Per-CPU claim line | Stock | — | select +3.23, enqueue +71.31 ns | Rejected |
| E2: whole-core word from idle word | Stock | — | select −0.01 ns | No effect |
| K1–K3: inline/aligned/no-SMT idle claim | Custom (not written) | Current kfunc | Perf: claim ≈ 60 % of select | Proposed |

## Evidence, 2026-10-04

Appsim helldivers2-mission-fitted cut to 20 s, `cakebench cost`, all slots valid,
busy 30–31 %. Runs under `scx_cake_bench/runs/`.

| What | Run | Result |
|---|---|---|
| E1 vs base, 12 slots/arm | `cost/20261004T133141_appsim` | running −3.10 ns [−4.32, −1.91]; BPF −0.48 ms/s [−0.90, −0.07]; frames equal |
| E1 screens | `cost/20261004T131835_appsim`, `…T132239_appsim` | running −3.55, −3.26 ns |
| Fastcall, bounds, portable | `cost/20261004T101532_appsim`, `…T101959_appsim`, `…T102143_appsim`, `appsim_fast_20261004T111326` | no stable effect; native vs portable select −4.11 / −0.2 |
| Per-CPU claim line | `cost/20261004T125140_appsim` | select +3.23, enqueue +71.31 ns |
| Select census (probe) | `appsim_fast_20261004T111326/probe.log` | warm claim 71.8 %, home 26.5 %, retake 1.5 %, serial 0 % |
| Where select time goes | `perfmap_20261004_base/report.txt`, `cost/20261004T121113_profile` | idle claim ≈ 60 % of select (leaf 26.7 % of cake time); BPF self ≈ 22 %; running's `scx_bpf_now` ≈ 10 % |

Kernel facts: `scx_bpf_now()` reads the TSC whenever `SCX_RQ_CLK_VALID` is clear
(skipped clock update after wake preemption, balance unpin), common at ops.running.
With NR_CPUS=8192 and CPUMASK_OFFSTACK the scx idle cpu/smt masks are kmalloc(8)
objects that may share a line with others; addresses unverified.

## Owed

1. Game A/B (KovaaK's) for E1 and native bitops, using the kept binaries.
2. Signals observe in a real game; appsim produces no input or fence wakes.
3. DSQ direct A/B: reboot with `sched_ext.dsq_direct=0`.
4. K1–K3 kernel patch (inline claim, aligned masks, claim without the SMT store):
   write, compile-check; the maintainer installs and reboots.
5. `irq_leave` reads 550–1,010 ns/run (09-25 profile: 946 cycles / 600 insns); cause open.
6. Flagless release: decide or remove each test-only flag above.
7. `cake.bpf.c` comment density 0.25, over the 0.20 ceiling (also true before 10-04).
8. Carried from before the 2026-09-26 revert, unverified since (details in the
   archive): `verifier_load_topologies` on multi-LLC, >64-CPU and sparse rows;
   HZ 250/300 stall runs; WoW GPU-bound A/B; OSLTT against `9db04489e`; the §G93
   trace; tester probe logs for §G96.

## Research index

All under `docs/research/jit-bitops-prototype/` unless noted.

| Doc | Finding |
|---|---|
| `GPU_INPUT_IRQ_SIGNALING_2026-10-02.md` | Signals patch + `--kernel-signals`; VM contract passed, no hardware result |
| `SIGNAL_FRESHNESS_CLOCKS_2026-10-02.md` | 33 signals mapped: clocks, staleness, invalidation |
| `GAMING_SIGNAL_PIPELINE_2026-10-02.md` | IRQ/GPU/input wake paths; KWin threads are RR, outside cake |
| `KERNEL_FULL_BUNDLE_2026-10-02.md` | One combined kernel patch for CachyOS 7.2.8 |
| `DSQ_DIRECT_INDEX_2026-10-02.md` | Direct DSQ index; VM passed, no hardware speedup shown |
| `CACHE_HOTPATH_REVIEW_2026-10-02.md` | Cake/kernel cache inventory and ranking |
| `AUTO_NATIVE_BITOPS_2026-10-02.md` | Native CTZ/POPCNT auto-detection |
| `PERFORMANCE_SUMMARY_2026-10-02.md` | Charts and data for the scalar experiments |
| `DEEP_RESEARCH_2026-10-02.md` | Typed DSQ compare backport; bounds patch needs precision tracking |
| `SCALAR_BOUNDS_REFACTOR_2026-10-02.md` | Kernel return bounds; plain mask deletion grows code |
| `INSTRUCTION_PASS_2026-10-02.md` | Selective fastcall; ~1 cycle per native CTZ/CLZ/POPCNT |
| `FASTCALL_SIMULATION_2026-10-01.md`, `FASTCALL_KERNEL_REVIEW_2026-10-01.md` | Unary fastcall patch; no speedup established |
| `ASSEMBLY_PIPELINE_REVIEW_2026-10-01.md` | JIT confirms scalar ops; wrapper cleanup screen |
| `RELEASE_CTZ_CLZ_2026-10-01.md`, `INSTRUCTION_USAGE_REVIEW_2026-10-01.md` | CTZ ring scan and CLZ histograms: faster callbacks, worse tails |
| `REPEAT_5X_2026-10-01.md`, `QUICK_TEST_2026-10-01.md`, `HARDWARE_SMOKE_2026-10-01.md` | Bitops small gain; division-free loss |
| `QUOTIENT_IMPLEMENTATION.md`, `quotient/` | Exact reciprocal division (removed; sources kept) |
| `README.md` | Index of the JIT/bitops experiment |

Documentation map: `docs/README.md`. Supported use: `README.md`.
