# scx_cake — current state

Read first, every session. Rules: repository-root `CLAUDE.md`. Behaviour: `DESIGN.md`.
History: `docs/archive/STATE_ARCHIVE.md`, newest first; grep it, do not read it whole.
Offload rule: once nothing in an entry is owed, move it word for word to the archive
top; owed items move to Owed first.

## Now (2026-10-05)

- Code: `567715cc8` on `RitzDaCat/scx_cake-nightly`, committed locally, not pushed.
  Last upstream merge: PR #3786 (`c410fcbd7`).
- Uncommitted (2026-10-05, arm A′ `88988e81571c`; awaiting the go): wide-host idle
  count by popcount (D), the pool interlock in `update_idle` on every host (F),
  pool tokens checked at `ops.exit`, census identities checked after detach (port
  of the lost `2f4bc9a6c`), `PEND_HEAL` wired, 18 dead census sites removed. Fmt,
  clippy debug and release clean; `cargo test -p scx_cake` 45 pass, 1 ignored.
- Host: 7.2.9-1-cachyos-custom with
  `docs/research/jit-bitops-prototype/0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch`
  (applies to 7.2.9 with offsets only). `sched_ext.dsq_direct=Y` serves every cake
  DSQ ID, and 7.2.9 sets `SCX_RQ_IN_WAKEUP` only on the core wakeup path: numbers
  from older kernels are not comparable.
- Defaults: native CTZ/POPCNT (auto-detected) and E1 (cached rq clock in
  ops.running). Policy base: the 2026-09-28 pool-serving C entry (archive).
- Test-only flags (the release is flagless): `--native-bitops`, `--portable-bitops`,
  `--native-ring`, `--native-hist`, `--kernel-signals`, `--signal-report`,
  `--handoff-ns`, `--toggle probe=1`, `--inspect-bpf`, `--lean-idle` (default `lazy`; silent fallback without the kernel flag).
- A/B binaries: `cost_c1c1e5aad80f` (base) and `cost_400e7a766333` (E1) were lost
  when `target/` was wiped on 2026-10-05 about 11:26 (not by this repo's session);
  rebuild them from those commits (`cakebench cost` builds arms by SHA).

## Pattern ledger with kernel requirement (2026-10-05)

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
| K1–K4: lean idle claim (`SCX_OPS_LEAN_IDLE`, K3 as `_LAZY_SMT`) | Custom: `0001-cake-kernel-full-signals-idle-experimental-cachyos-7.2.9.patch` | Flags ignored; regular claim | Claim ≈ 60 % of select; masks 32 lines apart (10-05); boots on 7.2.9-2-cachyos-custom (10-11). KovaaK's menu, quiet host, 12×30 s ABBA (10-12): `lazy` vs `off` avg FPS +1.4 %, p99 −5.1 %, 1 % low +7.5 %, stddev −18 %, each 16/16 pairs; `on` ≈ `off`. Under 16 nice-10 hogs (98 % busy), 12×30 s: avg +0.25 %, p99.9 −2.4 %, 0.1 % low +6.6 % (32/36), max −16 %; no metric worse | Default `lazy` since 10-12; played-scenario check and `cakebench cost` owed |
| Spread pick: ties in the best tier go to the first CPU above the caller (rotate form B, mask form B2) | Stock | — | select +8.1 / +11.7 / +8.3 ns in three rounds; profile +130 cyc/run (+31 insns, rest stalls); retakes −42 %, evictee claims −31 % (census); total BPF equal or +2.9 %; appsim p99 equal | Rejected at levels 2–3, removed; patch kept in `docs/research/counting-classifiers-20261005/` |
| D+F: wide-host idle count by popcount; `update_idle` pool interlock on every host | Stock (> 64 CPUs) | Global atomic counter; no interlock on wide hosts | Forced-wide on this host, two rounds: `update_idle` −1.09 / −0.64 ns, running −2.69 / −1.05 ns; 0 stalls; one-word arm neutral | Keep (uncommitted); a real > 64-CPU host owed |
| Exit pool check, census identities, detach-first reports | Stock | — | Identities exact in 4 probe slots; pending 0 at every exit; the `-v` events row is no longer 0 0 0 | Keep (uncommitted, diagnostics only) |
| Kernel wake signals (input/fence tags) in a game | Custom | — | KovaaK's 90 s, focused: 0 input- and 0 fence-tagged wakes in 8.4M (input reaches the game through KWin's socket; NVIDIA uses private waits) | Nothing to act on in this stack |
| Wake classes by waker context (in IRQ handler / kthread / game / other) | Stock | — | KovaaK's 90 s census: `dxvk-queue` woken from IRQ context 731k times (GPU completion), mean 0.6 µs, worst 1.08 ms; game-to-game worst 4.8 ms | Classifier works; policy under test |
| IRQ-woken wakes run next (idle CPU, else head of prev with PREEMPT; never an IRQ CPU or a seated stage) | Stock | — | KovaaK's A/B under 16 nice-10 hogs paused after 5 of 8 slots (maintainer's heavy tasks); data not read | Under test |
| Preferred-core re-read at runtime | — | — | Ranking identical on 2026-09-26 and 10-05 (cores 4=5 > 3 > 1 > 2 > 0 > 6 > 7) | Dropped: static here; the startup read is correct |

## Evidence, 2026-10-12: cache-line contention (perf c2c, IBS)

KovaaK's menu + cake (lean `lazy`), 20 s quiet and 20 s under 16 hogs.
Tools and derived reports: `scx_cake_bench/runs/c2c_20261012/` (`capture.sh`
starts perf before attach so BPF symbols resolve; `fields.py` names task_struct
fields from BTF). Kernel code is unnamed (`kptr_restrict=2`).

| HITM loads (quiet) | Share | Note |
|---|---|---|
| Game/Wine userspace | 85.5 % | outside cake |
| Kernel code | 14.0 % | ttwu, rq, task line 0: intrinsic |
| Cake BPF code | 0.5 % | 141 samples; `select_cpu` 96 of them, mean 84 cycles |

Cake's HITMs by cause:
1. Wake classification in `select_cpu`/`select_undecided`: the wakee's
   `se.sum_exec_runtime`, `nvcsw`, `sched_info.{run_delay,pcount}` sit on
   three task_struct lines last written by the CPU the task ran on. About
   half of cake's quiet HITMs. Same reads on the home CPU's running task (`hc`).
2. Global idle line (lean K2): 61 HITMs all readers, cake 22 (smt word 15
   in `select_cpu`/`pick_idle_clean`, cpu word 6 in `claim_warm`). True sharing.
3. Direct `p->scx.slice`/`dsq_vtime` stores (`admit_direct`, `stopping`),
   read remotely by the kernel; also the kernel's deprecation warning.
4. Cake's own globals: small; one queue-signal line (`dispatch_search`,
   `enqueue`) 178 cycles under load. True sharing by design.

## Evidence, 2026-10-05

`cakebench cost`, appsim 20 s slots, all slots valid. A busy host: round 2 had two
outside bursts (enqueue 669k–724k per slot); compare inside one round only.

| What | Run | Result |
|---|---|---|
| Spread census A vs B, probe, 2 slots/arm | `cost/20261005T093740_appsim` | warm-claim failures 2.04, 1.93 → 1.70, 1.80 %; retakes ~100k → ~58k; evictee claims ~111k → ~77k; identities exact |
| Round 1: HEAD / A / B | `cost/20261005T094221_appsim` | select 87.25 / 89.49 / 97.57 ns; enqueue calls −35 % with B; total 26.14 / 27.03 / 27.08 ms/s; p99 0.62 all |
| Round 2: HEAD / A / B2 | `cost/20261005T095506_appsim` | select 91.73 / 90.26 / 102.03 ns; frames unreadable (bursts) |
| Profile A vs B2 | `cost/20261005T100619_profile` | select 870 → 1000 cycles, 1438.6 → 1469.7 insns per run |
| Wide rounds: HEAD / B2, both forced wide | `cost/20261005T101121_appsim`, `…T101840_appsim` | `update_idle` 11.47 → 10.38, 13.08 → 12.44 ns; running 18.06 → 15.37, 22.03 → 20.98 ns |
| Round 3: HEAD / A′ / B2′ at 42 % busy | `cost/20261005T102722_appsim` | select 108.22 / 108.52 / 116.77 ns; `update_idle` 10.26 / 10.14 / 9.99; total 40.91 / 41.04 / 42.10 ms/s; p99 0.62 / 0.63 / 0.62 |
| Mask layout (diagnostic build) | session log | idle mask `0xffff8ddc800b1310`, SMT mask `0xffff8ddc800b1b00`: 32 lines apart |

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
objects that may share a line with others; on 2026-10-05 they sat in different lines.

## Owed

1. Game A/B (KovaaK's) for E1 and native bitops, using the kept binaries.
2. Signals observe in a real game; appsim produces no input or fence wakes.
3. DSQ direct A/B: reboot with `sched_ext.dsq_direct=0`.
4. Lean idle claim K1–K4: written and compile-checked in
   `docs/research/jit-bitops-prototype/0001-cake-kernel-full-signals-idle-experimental-cachyos-7.2.9.patch`.
   The maintainer builds and installs it; then a same-boot `cakebench cost` A/B
   of `--lean-idle off` vs `on` vs `lazy` (K3 hides a just-claimed sibling from
   `cake_core_busy` until that CPU runs). KovaaK's menu A/B done 10-12
   (`scx_cake_bench/runs/kovaaks_leanidle_20261012`, quiet and loaded): `lazy` wins,
   `on` neutral; `lazy` is the default.
5. `irq_leave` reads 550–1,010 ns/run (09-25 profile: 946 cycles / 600 insns); cause open.
6. Flagless release: decide or remove each test-only flag above.
7. `cake.bpf.c` comment density 0.25, over the 0.20 ceiling (also true before 10-04).
8. Carried from before the 2026-09-26 revert, unverified since (details in the
   archive): `verifier_load_topologies` on multi-LLC, >64-CPU and sparse rows;
   HZ 250/300 stall runs; WoW GPU-bound A/B; OSLTT against `9db04489e`; the §G93
   trace; tester probe logs for §G96.
9. Commit go for arm A′ (above); D+F on a real > 64-CPU host (tester).
10. Spread pick: a game A/B only if the retake drop is worth testing in frames
    (patch in `docs/research/counting-classifiers-20261005/`).
11. IRQ-woken wake priority: rerun the KovaaK's A/B on a quiet host. Tools and patch
    scripts: `scx_cake_bench/runs/kovaaks_irqwake_20261005/tools/` (`run.sh`,
    `irq_wake.py`, `diag_wake.py`; set PID/WIN in `kv_ab.py` and `CAKE_DIAG_TGID` per
    launch). Arms `target/cake_receipt_builds/kv-x` (base + diag) and `kv-y` (+ IRQ
    priority). Slots 1–5 of the paused run are in `run1/`, likely skewed.

12. Cache-line follow-ups (evidence 10-12): (a) compute the wake class in
    `ops.stopping(!runnable)` on the task's own CPU (`nvcsw`, `sum_exec_runtime`,
    `sched_info` are final there) and read one word at wake, 3 remote lines to 1;
    (b) skip the smt-word read when no whole-core search follows; (c) setters
    `scx_bpf_task_set_slice/dsq_vtime`. Each needs a KovaaK's A/B.

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
| `../counting-classifiers-20261005/README.md` | Decision data by measurement level, classifiers, counting identities; spread pick rejected, D+F kept |

Documentation map: `docs/README.md`. Supported use: `README.md`.
