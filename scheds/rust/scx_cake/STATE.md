# scx_cake — CURRENT STATE

> [!IMPORTANT]
> **Read this first, every session.** Current status comes first, followed by
> carried obligations and dated rounds. Rules live in repository-root
> `CLAUDE.md`; behaviour in `DESIGN.md`.

## Pattern ledger with kernel requirement (2026-10-04)

"Stock" means any upstream/CachyOS kernel with sched_ext at the stated version;
"custom" means `0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch`.
Levels follow CLAUDE.md's metric order; game frames (level 1) are owed for all.

| Pattern | Kernel needed | Without it | Best evidence | Verdict |
|---|---|---|---|---|
| E1: ops.running reads cached `rq->scx.clock` | Stock ≥ 6.14 | CO-RE falls back to `scx_bpf_now()` | 24-slot appsim: running −3.10 ns [−4.32, −1.91], BPF −1.9 %; frames neutral | **Default in working tree (uncommitted)**; game A/B owed |
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

## Current navigation (reviewed 2026-10-02)

- **2026-10-04 — host kernel 7.2.9-1-cachyos-custom with the full signals patch.**
  Patch `0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch` applies to
  7.2.9 with offsets only. `sched_ext.dsq_direct=Y`: every cake DSQ ID is below 2048,
  so the direct table serves all lookups and older-kernel numbers are not comparable.
  Quick appsim screens (`cakebench cost`, 20 s spec, 2 slots/arm ABBA, all valid,
  busy 30.0–30.7 %; diagnostic, level 3 only):

  | Run (`scx_cake_bench/runs/cost/`) | Arms | Result ns/run (B − A) |
  |---|---|---|
  | `20261004T101532_appsim` | base vs `bpf_fastcall` attribute | select −1.08, enqueue +2.42, dispatch −0.94, running −0.47; all inside slot spread |
  | `20261004T101959_appsim` | fastcall vs fastcall + mask removal (verifier bounds) | enqueue −8.2 (slots apart), but the same fastcall binary read 160.21 two minutes earlier; not established |
  | `20261004T102143_appsim` | native vs `--portable-bitops` | native running −2.31 (slots apart), dispatch +0.39 (slots apart), select/enqueue inside spread |

  Static: fastcall shrinks select_cpu by 8 BPF insns; mask removal grows it by 13.
  Arms are dangling commits `e98aa3cce` (base = working tree), `150591415`
  (fastcall), `96052c562` (fastcall + bounds). Owed: game frames for all three;
  DSQ direct A/B (reboot with `sched_ext.dsq_direct=0`); signals observe in a game.

  7.2.8 → 7.2.9 review for cake: `enqueue_task_scx()` now sets `SCX_RQ_IN_WAKEUP`
  only on the core wakeup path, so deferred actions after a remote (wakelist)
  activation are scheduled instead of waiting for a `task_woken_scx()` that never
  came. That can move cake's remote-wake latency; another reason not to compare
  across kernels. BPF: killable/preemptible verifier rewrites and JIT, gotox
  fixes, memalloc refill lock, hashtab batch resched; no cake-facing change.
  `psi_account_irqtime()` uses `curr`; LLC-bytes topology fix. Nothing to adopt.

  Flags removed (uncommitted): `--division-free` (measured loss: BPF CPU +5.8 %,
  select_cpu +11 ns), `--native-ctz`, `--native-popcnt`. Quotient sources moved to
  `docs/research/jit-bitops-prototype/quotient/`; slice/burst use plain division.
  Verifier load on 7.2.9 passed (18 programs); 38 unit + 3 CLI tests pass.

  Appsim fast set `scx_cake_bench/runs/appsim_fast_20261004T111326` (20 s slots, ABCDDCBA, all 9
  valid, busy 30.1–30.5 %, appsim p99 0.618–0.624 ms in every arm): select ns/run
  base 84.67, fastcall 86.49, fastcall+bounds 85.93, portable 88.78. Fastcall's sign
  flipped versus the first screen and the bounds enqueue −8.2 did not repeat: no
  effect established for either. Native vs portable select −4.11 here, −0.2 in the
  first screen. Probe census (3.07 M selects/20 s): warm claim wins 71.8 %, home
  26.5 %, seat retake 1.5 %, serial 0 %; about one idle claim per select (98.5 %
  won); every select reads the task-age clock and runs the admit division.

  Where select time goes (perf cycles:k, appsim, `runs/perfmap_20261004_base/report.txt`;
  `runs/cost/20261004T121113_profile`): select is 59.3 % of cake time, ~825 cycles
  and ~1,440 instructions per call (IPC ~1.75, kfuncs included). The idle claim
  (`scx_bpf_test_and_clear_cpu_idle`) is ~35.8 % of cake time, about 60 % of select;
  its leaf `scx_idle_test_and_clear_cpu` alone is 26.7 % (locked bit-clear plus SMT
  mask store on lines every CPU's idle transition writes). BPF self time is ~22 %
  (claim_warm 11.1, select 8.9, admit 1.8), insert ~2.2 %. Elsewhere: running's
  `scx_bpf_now` → `native_sched_clock` ~10 % of cake time. `bpf_jiffies64` is
  verifier-inlined, so the task-age read is already a load.

  Rejected 2026-10-04: per-CPU claim line (cake-owned 128 B slot per CPU replacing
  `scx_bpf_test_and_clear_cpu_idle` on one-word hosts; claim = kernel idle bit +
  read-then-xchg on the slot; reset in update_idle(idle) and on an empty dispatch).
  Arm `5f2923496` vs base2 `c1c1e5aad`, `runs/cost/20261004T125140_appsim`, 2 slots/arm,
  all valid, busy 30.4/31.0 %: select +3.23 ns, enqueue +71.31, dispatch +5.89,
  BPF total +6.5 %, appsim p99 unchanged. Likely cause: kernel idle and SMT bits stay
  set until the claimed CPU leaves idle, so other wakers retry claimed CPUs and the
  whole-core preference picks claimed cores. The claim cost is the kernel's; a
  lighter claim kfunc (kernel patch) is the remaining route.

  E1/E2 screens 2026-10-04 (base2 `c1c1e5aad`; appsim 20 s, all slots valid):
  - E1 `400e7a766` — ops.running reads `rq->scx.clock` of the task's CPU through
    `runqueues` instead of `scx_bpf_now()` (the kfunc reads the TSC whenever
    `SCX_RQ_CLK_VALID` is clear: skipped clock update after wake-preempt, or a
    balance unpin). running ns/run −3.55 (`runs/cost/20261004T131835_appsim`,
    slots 19.5–20.4 vs 23.3–23.7) and −3.26 reversed (`…T132239_appsim`, 20.9–21.5
    vs 23.6–25.2). Other callbacks mixed across the two runs; appsim p99 unchanged.
    Candidate default; game frames owed. Stamp can be one rq-clock update old.
    24-slot A/B (`runs/cost/20261004T133141_appsim`, 12 slots/arm, interleaved
    ABBA, all valid, busy 30.30 vs 30.30 %): running −3.10 ns, 95 % bootstrap CI
    [−4.32, −1.91]; cake BPF total −0.48 ms/s [−0.90, −0.07] (−1.9 %); select,
    enqueue, dispatch, stopping CIs include zero. Frames: p99, p999, sigma and
    chain p50/p99 identical; frames over 2× median 6 in base (2 slots) vs 0 in E1,
    too few to call. E1 per-slot running is bimodal (18.6–24.3): the gain depends
    on how often the kernel clock is invalid in that slot.
  - E2 `9c460cbe3` — whole-core word derived from the idle word with the uniform
    SMT shift instead of reading the kernel SMT mask: no effect (select −0.01).
  - E1+E2 `4333675d0`: running −2.40, select −1.13; one of its two slots showed no
    running gain.
  Kernel facts: with NR_CPUS=8192 and CPUMASK_OFFSTACK the scx idle cpu/smt masks
  are kmalloc(8) objects (cpumask_size() = nr_cpu_ids bits), so they can share a
  line with each other and unrelated objects; addresses unverified (kptrs read
  as 0 from userspace; default-rate perf c2c too sparse).

- [GPU/input/IRQ signaling implementation](docs/research/jit-bitops-prototype/GPU_INPUT_IRQ_SIGNALING_2026-10-02.md):
  inclusive kernel patch plus Cake off/observe/on integration. Default remains
  off; native CTZ/POPCNT still auto-detect. Ordinary VM production/fallback
  checks and the 20-case signal contract passed; no hardware performance result.
  Debug and additional CPU/configuration coverage remain pending. Cargo clean
  removed build images/logs; persistent VM receipts and test sources survived,
  and the kernel source/patch were recovered outside Cargo's target directory.
  No host kernel installation. Builds and benchmarks deferred during game testing.

- [Signal locations, freshness and clock accuracy](docs/research/jit-bitops-prototype/SIGNAL_FRESHNESS_CLOCKS_2026-10-02.md):
  33 signals mapped to 35 hashed source files, with update triggers, clock
  domains, staleness, access paths and invalidation rules. Live Vulkan/Wayland
  queries verify timing support and presentation clock; 16 calibration queries
  report 1,376–1,472 ns deviation and a GPU/MONOTONIC offset change of −30,594 ns
  over 3.751 seconds. CSV/JSON, source links, reproducible observer and PNG retained.
  Clock characterization only, not a scheduler/game win. Important distinctions:
  cached rq time versus MONOTONIC, syncobj availability versus completion,
  disabled optional NVIDIA vblank callback, and low-latency2 revision 2.
  No scheduler/kernel/trace-clock or release binary change.

- [GPU/input handoffs and low-latency scheduling signals](docs/research/jit-bitops-prototype/GAMING_SIGNAL_PIPELINE_2026-10-02.md):
  source-backed investigation of IRQs, GPU status, fences, waits, frame timing,
  compositor, mouse and keyboard. Traces a direct NVIDIA completion-to-waiter
  path and KWin's queued input handoff; specifies metadata carried through the
  existing wakeup before CPU selection. Live KWin main/input/display threads
  are RR priority 1, outside Cake's scheduling class. Includes exact state
  boundaries, patch options, costs, freshness and an experiment sequence.
  Research only: no probes attached, signal patches implemented or new latency
  result. Host kernel, scheduler state and repo release unchanged.

- [Single complete kernel research patch](docs/research/jit-bitops-prototype/KERNEL_FULL_BUNDLE_2026-10-02.md):
  scalar instructions, unary fastcall, verifier bounds, typed DSQ comparison
  and direct DSQ index combined for fresh CachyOS 7.2.8-1 sources. Clean apply,
  zero-fuzz/offset patching and reverse checks pass; all eight affected files
  match the prior built/VM-tested candidate. Packaging only: no new build,
  installation or performance claim. Debug gate remains open. Full native
  specialization additionally needs the separate Cake build.

- [Direct DSQ index implementation and simulation](docs/research/jit-bitops-prototype/DSQ_DIRECT_INDEX_2026-10-02.md):
  optional kernel-owned RCU index replaces hashing for low queue IDs, with a
  hash fallback and unchanged release Cake. Six VM configurations passed
  393,216 concurrent lifecycle iterations; all 20 slots in five simulation
  blocks passed checksums and restoration. Emulated wall time changed −0.023%,
  with uncertainty spanning improvement and regression; no hardware speedup
  established. Debug boots expose a POC-selector lock cycle and an early KASAN
  report also observed on the baseline; a clean debug gate remains open.
  Patches, test sources and receipts retained. Host kernel/package unchanged.

- [Caching and hot-path lookup review](docs/research/jit-bitops-prototype/CACHE_HOTPATH_REVIEW_2026-10-02.md):
  inventories current Cake/kernel caches and ranks a kernel-owned direct DSQ
  index first, followed by lookup reuse and shared-line traffic investigation.
  Follow-up distinguishes 100% potential Cake custom-ID coverage from unknown
  hardware hit rates; this host's index working set is three cache lines.
  Freshness, update frequency, historical load costs and coherence limits are explicit.
  This review is source research; the subsequent implementation and simulation
  are linked above.

- [Automatic native bitops for game testing](docs/research/jit-bitops-prototype/AUTO_NATIVE_BITOPS_2026-10-02.md):
  user-requested default now detects CTZ/POPCNT support at startup and falls
  back per operation on unsupported CPUs/kernels. `--portable-bitops` forces
  the old path for comparison; explicit native research flags remain strict.
  Division-free, queue scanning and histograms remain off. Release build,
  40 tests, debug/release Clippy, three host inspection loads, and six VM
  activation/restoration checks passed across patched, unpatched and
  instruction-disabled configurations. Embedded BPF is identical to the
  measured wrapper-cleanup candidate. This is game-test preparation, not
  a new performance result. Use the repo release; the user keeps the system
  CachyOS package unchanged. Older dated opt-in descriptions are historical.

- [Performance findings with charts and data](docs/research/jit-bitops-prototype/PERFORMANCE_SUMMARY_2026-10-02.md):
  five-page chart pack, standalone HTML, CSV and source-hashed JSON consolidate
  the retained scalar experiments. Five-repeat results recomputed from all 40
  receipts: bitops enqueue −5.87 ns/call, running −0.83 ns/call; total BPF CPU
  −0.47% remains uncertain. Division-free averages +5.81%, with higher cost
  in all five blocks.
  Wrapper cleanup p99 −21,850 ns and p99.9 −53,975 ns remain promising two-block
  screen results. Hardware, VM, and static code-generation evidence are separate;
  no new benchmark, kernel change, or broader performance verdict.

- [Deep instruction/kernel research](docs/research/jit-bitops-prototype/DEEP_RESEARCH_2026-10-02.md):
  backported the upstream-accepted typed DSQ comparator into an isolated kernel.
  Actual lookup assembly replaces bcmp with a u64 comparison, inlines hashing,
  and reduces its own stack use from 96 to 32 bytes. 26,248 differential
  executions, 42 Cake inspection loads and 9 activation/restoration checks
  passed. A separate deliberately weakened verifier incorrectly accepts two
  unsafe pruning tests, confirming the bounds patch needs precision tracking;
  accepted negative programs were never executed. Corrected historical perf
  attribution that had included unrelated BPF programs in the Cake denominator.
  No new hardware latency result, default change, or kernel installation.

- [Scalar bounds and native release refactor](docs/research/jit-bitops-prototype/SCALAR_BOUNDS_REFACTOR_2026-10-02.md):
  kernel return bounds and two release refactors built and VM-tested. Simply
  deleting masks grows code; preserving LLVM range knowledge and specializing
  native bitops removes 26 static select_cpu instructions / 126 bytes and 13
  BPF stack accesses on a 16-thread guest. 20,844 differential executions,
  56 Cake inspection loads, 8 activation/restoration checks; unsafe accesses
  still rejected, including forced state-pruning tests. CPU-disabled fallback
  passes. New mask-free native modes deliberately fail on the old kernel.
  Combined/incremental patches and exact release artifacts retained; ordinary
  release/source restored. Host kernel unchanged, hardware latency unmeasured.

- [Further instruction passes and hardware costs](docs/research/jit-bitops-prototype/INSTRUCTION_PASS_2026-10-02.md):
  selective CTZ/POPCNT fastcall avoids the CLZ histogram growth; portable
  fallback outlining increases native counts. Generic wide-ring CTZ prototype
  passed 2,487,612 order/read checks. Native PMU probes measure ~1 cycle for
  dependent CTZ/CLZ/POPCNT and ~2 with result masks; cost ladder §10 updated.
  36 VM loads, 10 VM activation checks and 48/48 host slots passed; 1,496,976
  simulated host frames retained. Quiet-start select_cpu -0.337 ns/call,
  interval [-4.136,+3.461]; separate Blender activity contaminated a block.
  No performance verdict/default change. Ordinary release/source restored;
  host has the original scalar patch, not the later unary KF_FASTCALL patch.

- [Five-block fastcall simulation](docs/research/jit-bitops-prototype/FASTCALL_SIMULATION_2026-10-01.md):
  actual patched kernel in QEMU TCG, 20/20 valid release A/B slots, 60,000
  simulated frames and 320 million fixed-work steps with identical checksums.
  Guest p99 -1,221 ns, jitter +2,481 ns, fixed-work completion +28,321 ns;
  all three paired intervals include zero. No speedup established. LLVM 22.1.8
  `znver5` uses the Zen 4 timing model, so instruction-model output is only a
  coarse proxy. Hardware performance remains unmeasured; host state unchanged.

- [Unary fastcall kernel patch and release audit](docs/research/jit-bitops-prototype/FASTCALL_KERNEL_REVIEW_2026-10-01.md):
  new combined/incremental CachyOS patches and isolated annotated release build.
  Full kernel build, native/fallback/old-kernel VM tests, 18 positive scalar
  executions, 3 expected rejections, 18 Cake inspection loads and 5 activation
  checks passed. Native-bitops select_cpu: -8 static instructions, -9 BPF stack
  accesses; histogram stopping grows by 6 instructions. No hardware performance
  result or default promotion. Ordinary release restored byte-for-byte; host
  kernel untouched. Further DSQ, kick, cpumask and compiler-pattern work is scoped
  in the report, not implemented as new scheduling policy.

- [Actual release assembly and kernel-signal roadmap](docs/research/jit-bitops-prototype/ASSEMBLY_PIPELINE_REVIEW_2026-10-01.md):
  independent CTZ/POPCNT flags and load-only instruction inspection added.
  Actual current-boot JIT confirms all four scalar operations. Removed repeated
  wrapper symbol checks: select_cpu with bitops is 28 bytes / 4 instructions
  smaller. 24/24 normal release slots, 748,484 simulated frames, probes/timing
  off. Wrapper A/B p99 -21,850 ns (both blocks improve), jitter -6,431 ns;
  promising screen at about 49% background busy, not game/default acceptance.
  All flags remain opt-in. IRQ/capacity, GPU-fence and input-wakeup interfaces
  are proposals; no new kernel patch installed. Native scheduling restored.

- [Release CTZ/CLZ rebuild and normal-mode screen](docs/research/jit-bitops-prototype/RELEASE_CTZ_CLZ_2026-10-01.md):
  CTZ queue scanning and CLZ histograms are now available as opt-in flags in
  `target/release/scx_cake`; source and binary retained. 28/28 valid slots,
  873,159 simulated frames. Twelve slots had probe and BPF timing disabled:
  bitops vs default p99 +15,375 ns; adding queue scanning p99 -16,650 ns,
  but mean slot maximum +1,449,200 ns and less background CPU. No fastest-mode
  or default-promotion verdict. Separate instrumented scan dispatch -0.11
  ns/call; CLZ diagnostic stopping -8.87 ns/call. Division-free stays off.
  Native scheduling restored, BPF stats off; new flags remain experimental.

- [Scalar instruction usage audit and expansion experiments](docs/research/jit-bitops-prototype/INSTRUCTION_USAGE_REVIEW_2026-10-01.md):
  three prototypes, 6,922,350 offline checks and 32/32 valid live slots;
  996,188 simulated frames retained. CTZ queue scanning: dispatch -18.05
  ns/call in the non-probe screen, but worse p99.9/0.1% lows and reversal
  with probe enabled. CLZ histograms: stopping -8.21 ns/call, with mixed
  aggregate results and worse frame tails. MULHI vtime is confounded by
  much lighter background load. Unreal/compiler activity prevents acceptance.
  Experiments archived as patches; original scheduler source, release binary
  and embedded BPF restored byte-for-byte. Native scheduling restored.
  Quotient review: per-call reciprocal setup explains the earlier loss;
  select_cpu accounts for about 91% of its extra measured BPF CPU time.

- [October 1 five-repeat scalar comparison](docs/research/jit-bitops-prototype/REPEAT_5X_2026-10-01.md):
  40/40 slots passed, 1,247,480 simulated frames, ten observations per mode.
  Total CPU busy 36.61–38.31%; estimated non-appsim busy 5.21–6.86%.
  Bitops-only: BPF CPU -0.47%, frame p99 -400 ns; enqueue -5.87 and running
  -0.83 ns/call. Aggregate CPU/frame intervals include zero. Division-free
  increased BPF CPU in all five blocks: +5.81% alone, +6.01% with bitops;
  frame p99 +920 / -830 ns, neither established as a frame effect. Flags
  remain off by default. Native scheduling and BPF statistics restored.

- [October 1 quick scalar comparison](docs/research/jit-bitops-prototype/QUICK_TEST_2026-10-01.md):
  eight 15-second appsim slots, 249,495 frames, all modes loaded and exited
  cleanly. Bitops-only BPF CPU time -1.95%, frame p99 -49,250 ns; division-free
  +12.51%, +29,700 ns; both +5.65%, -25,000 ns. Unreal/Discord noise and a
  133,300 ns baseline p99 shift prevent performance acceptance. Flags remain
  off; native scheduling and BPF statistics were restored.

- [October 1 combined-patch live smoke](docs/research/jit-bitops-prototype/HARDWARE_SMOKE_2026-10-01.md):
  booted kernel exposes all four scalar kfuncs. The unchanged September 30
  release build passed verifier loading and ran for 15 seconds with
  `--division-free --native-bitops`, reporting native CLZ/MULHI selection.
  Versioned Cake ops identity and clean native restoration were observed.
  This closes the host-topology native-mode load/activation gate below;
  fresh CLZ/MULHI primitive selftests, JIT dumps and performance remain pending.

- [README.md](README.md): supported use and CLI; [DESIGN.md](DESIGN.md): current policy.
- [Documentation map](docs/README.md): folders, evidence levels and historical records.
- [JIT experiment](docs/research/jit-bitops-prototype/README.md): kernel patches
  and opt-in Cake flags; September 30 patched-hardware primitive smoke passed
  17,340 differential executions and actual TZCNT/POPCNT JIT emission. Noisy
  timings are diagnostic only. Native-mode Cake loading passed on October 1;
  performance acceptance remains pending. This is not part of the default policy.
- [Exact quotient implementation](docs/research/jit-bitops-prototype/QUOTIENT_IMPLEMENTATION.md):
  September 30 normal-build `--division-free` integration replaces four dynamic
  division expressions. Portable/native arithmetic each passed 7,907,120 cases;
  Cake tests, Clippy and release build passed. Additional CLZ/MULHI kernel
  extension passed patch and object compile checks. October 1 native boot and
  Cake verifier/activation passed; fresh primitive JIT verification and
  performance acceptance remain pending.
- Kernel Manager packaging: [one combined CachyOS 7.2.8 patch](docs/research/jit-bitops-prototype/0001-bpf-x86-inline-all-scalar-ops-cachyos-7.2.8.patch)
  includes CTZ/POPCNT/CLZ/MULHI. Clean-source application and byte equivalence
  to the separate patches passed; affected objects recompiled successfully.
  Replace the older local kernel patch entries with this file for a fresh build.
- The September 28 entry below describes the current default. Older entries
  retain their original dates, hashes and claims of uncommitted state; they are
  not instructions to restore an old checkout. The `Owed` section explicitly
  contains carried items that require revalidation.

**2026-09-28 — TESTED POOL-SERVING C POLICY FOR NIGHTLY USER TESTING.** The
pool-tag fix below plus historical C `f3ae91cf2` (claim before move, early
own-queue mark clear, pool-aware continuation kick) is included by default;
normal release builds need no special feature or runtime toggle. This is the
tested C source, not the proposed eager-clear removal experiment.
- KovaaK's Correction Accuracy – Close I idle-player freeplay: two ABBA blocks,
  eight accepted captures, 525,783 frames / 477.138 s, all frames retained.
  Compared with tagfix A `f53aabda9`: FPS +0.250%, mean frame -2,252 ns,
  p99 +845 ns, p99.9 -1,609 ns, mean adjacent-frame jitter +612 ns.
- Noise-model sensitivity: FPS +0.482%, mean frame -4,353 ns, mean jitter
  +398 ns; worst-maximum capture excluded per arm: +0.647%, -5,850 ns, +777 ns.
  These are exploratory analyses; the full eight-capture result stays primary.
- Small measured gains count as useful. Unfiltered tails are mixed and the
  two blocks do not establish repeatability. Frame time is not render-pipeline
  or mouse-to-display latency; no active-aiming/Helldivers or aim-feel verdict.
- Source/activation and normal stops verified in all eight slots; native
  restored after capture. Broader topology, repeated/holdout, and end-to-end
  input-latency validation remain owed. Publication is for user testing.
- [Findings, metric definitions, evidence limits, and proposed follow-up](docs/KOVAAKS_KICK_ABBA_2026-09-28.md).
  Local evidence: `scx_cake_bench/runs/kovaaks_kick_abba_20260928T195312/`.

**2026-09-27 — POOL TOKEN LEAK FIXED (stopping clears slice residue), developed on
`99377e26f` and included in the September 28 nightly update.** The pool token
(`cake_llc_slot.pending`) ran negative on this host: -38 idle
and falling, -34 in 8 s under 16 hogs, unused pools to -364. Cause: `cake_pool_seen` reads
the slice's low 5 bits as a pool tag, and the kernel's runtime charge leaves arbitrary bits
there that reach a reader without a cake insert between: a preempted task kept at the local
head (`put_prev_task_scx`), and every dequeue of a running task (sleep, property change,
class switch), which `put_prev_task_scx` charges again after `ops.stopping`. Effects: the
token never read zero, so every idle dispatch counted the pool (`find_user_dsq`: 13.6 % of
cake time in the idle profile) and the proof reset of `unserved` never fired (self-kicks in
update_idle); on a multi-LLC host false decrements can pass a real pool's token through zero
while it holds a task, which breaks "zero means empty". Fix (one line in ops.stopping): a
runnable task keeps its slice with the tag bits cleared; a stopped one gets 0, which the
kernel's later charges keep at 0 and the next insert replaces. Build `33d88256`.
- Token: 0 idle, follows pooled tasks under load, back to 0 after; 60 s stress (24 hogs,
  fork storm, renice and taskset on running tasks): 0 negative samples, all pools 0 after.
- `cake-bpfstats`, 24 ABBA slots vs HEAD `e76f3225` (`scx_cake_bench/runs/tagfix_ab_20260927/`),
  quiet host (0.4 % busy): dispatch -11.1 ± 2.0 ns (31.5 -> 20.8, 6/6 pairs), stopping
  +0.5 ± 0.2, select_cpu +1.0 ± 0.5, others 0. 16 hogs: update_idle -11.5 ± 3.9 ns
  (31.2 -> 16.0); other callbacks inside noise (slot rates swing 3k-110k/s with the hogs' phase).
- Stall suite, 20 s, no ejections: pool fix 268/279/331/164 ms vs HEAD 275/208/235/203 ms
  (B range before: 135-340); idle 1.11 s, n19 1.09 s.
- Owed: KovaaK's A/B (level 1); verifier load on the multi-LLC, >64-CPU and sparse rows.

Rejected the same day, on appsim frames (`cakebench cost`, arms on top of the tag fix `f53aabda9`):
- Early own-mark clear (`25ce6bac7`: dispatch clears its qmask bit when it took the last task of
  its own queue). Cake CPU -8 to -12 % ms/s, but the frame tail is worse. Pass 1 (Unreal build in
  the background, 84-99 % busy): p99 median 0.748 -> 0.901 ms, 0.1 % low 724 -> 554. Pass 2
  (+16 nice-10 hogs, 100 %): fps 1684 -> 1636, p99 1.552 -> 1.623, 0.1 % low 297 -> 270. The mark
  also drives ops.enqueue's `alone` test (idle kick for a continuation); a stale bit was supplying
  kicks that the tail needs.
- Earliest-free pick at select_cpu's nothing-idle exit (`76542ae5b`, §G57 moved to select so the
  migration happens asleep). p99 0.82 -> 2.08 ms in pass 1; census under appsim + hogs: fps -22.5 %,
  p99 +65 %, 0.1 % low -67 %. Start + grant/2 is smallest on CPUs running short-burst game
  threads: wakes stacked there (own-queue inserts x1.7, wake preempts x2) instead of the pool.
Route census per load, Mermaid flows and patches: `scx_cake_bench/runs/flows_20260927/`
(`flows.json`, `flows.mmd`, `exp2_before_after.mmd`, `tagleak.mmd`, `exp*.patch`).
Measured, for the next round: two thirds of kick calls under appsim (4.5k of 6.9k/s) are pool-
interlock self-kicks (update_idle + pending spin); they can fire while `unserved` still counts a task
another CPU is moving (payoff not measured); the host runs xAPIC (no `x2apic` flag), so every
IPI spins in apic_mem_wait_icr_idle.

Rejected the same day: packing `pending` and `unserved` into one word (one atomic per pool
insert). Hardware bench 2x cheaper per insert, model exact, but in cake no gain: quiet-host
fit enqueue +10.0 ± 6.1 ns, running +5.8 ± 5.8 (24 slots). HEAD's second atomic hits a line
the first just made local (about 4 ns). Design and data: `scx_cake_bench/runs/packab_20260927/`.
Measured cost map (perf, kernel-mode samples resolved against a kallsyms snapshot):
`scx_cake_bench/runs/perfmap_20260927/` (`perfmap.sh`, `perfmap.py`, `annotate.py`).

**2026-09-26 (afternoon) — §G98 ALONE ON `9db04489e` ("B"), uncommitted.** 09-22 was
ejected again overnight (Unreal Editor + python3 + clang++: clang++ weight 11, 41.72 s of
vtime ahead of the frontier, waited 6.130 s). The working tree is 09-22 plus only §G98:
the charge ceiling (`cake_vtime_cap`, `cake_vtime_ceil` in ops.stopping), the rate-band
frontier (`cake_frontier_step/advance/store`, CAS with a stamp), the requeue floor in
ops.enqueue, and `cake_vcap_unit_ns` from the loader. 09-22's full-CPU candidate sweep is
kept; no probe counters. Patch: `history/worktree-patches-2026-09-26/g98-only-on-9db04489e.patch`;
the tested D tree (§G98 + the 09-23..25 work, §G97 removed): `d-restored-tree.patch` there.

KovaaK's (level 1), borderless, uncapped, CPU-bound (GPU 37–77 %), 30 s MangoHud socket
slots, arms alternated ABBA, first second dropped; runs in `scx_cake_bench/runs/kovaaks_*_20260926/`.
Arms: 09-22 `7dcc14e0`, B `66770537` then B2 `10fc3c08` (B plus two comment fixes; BPF
instructions identical to this tree's build), D `dde4a804`. Medians over slots:
- Nice-10 load (16 procs, 20 ms bursts; external CPU 88.6–89.3 %), `ab5_hog3` 6 slots/arm:
  B vs 09-22 avg fps +0.56 % (35/36 slot pairs better or equal), p99 −1.76 % (35/36),
  p99.9 −4.25 %, 1 % low +2.29 %, 0.1 % low +3.89 %, stddev −5.55 % (36/36), max −7.32 %.
  D: avg fps −0.16 % (12/36), p99 −1.36 %, 0.1 % low +2.18 %, max −17.5 %.
- Same load, `ab7_hog_b2`, 8 slots/arm: B2 vs 09-22 avg fps +0.49 % (48/64), p99 −0.69 %,
  p99.9 −0.61 %, 1 % low +0.67 %, 0.1 % low +0.09 %, stddev −3.99 %, max +7.30 % (14/64).
  Max (one frame per slot) flips sign between runs: noise at this n.
- Slots with a ≥ 3 s slow stretch under load (4 runs): 09-22 8/28, D 4/20, B 2/14.
- Quiet host (external 2.2 %), `ab6_quiet3`, 6 slots/arm: B, D and 09-22 within ±0.3 %
  on every median, max within ±3 %; ranges overlap. Equal.
- D under load (`ab3_hog`) had one 0.4 s freeze (24/74/208/65 ms frames); none in B or 09-22.

Stall suite (`runs/g98_20260925/tools/liveness_stress.py`, 20 s):
| scenario | 09-22 | B/B2 | D | EEVDF |
|---|---|---|---|---|
| SCHED_IDLE vs 10 pinned per CPU | ejected 7.0 s | 1.08 s gap | 1.13 s | — |
| nice 19 vs 60 pinned per CPU | ejected 6.5 s | 1.80 s | 1.81 s | — |
| pool, 4 runs | 217 ms; 5.6 s; ejected 7.0 s ×2 | 315/135/340/141 ms | 211/300/265/160 ms | 663 ms |

Checks: fmt; release and debug builds with no scx_cake warnings; clippy findings only
in other crates; `comment_lint` clean (0.26, same as 09-22); `cargo test -p scx_cake` passes
(32 unit, 1 ignored; 1 + 3 integration). Owed: WoW GPU-bound
multi-pass A/B (the §G97 loss was GPU-bound); OSLTT vs 09-22 and EEVDF; the HZ 250/300
stall runs; the verifier load test on the multi-LLC, >64-CPU and sparse rows; the maintainer's go to commit.

**2026-09-26 — REVERTED to `9db04489e` (2026-09-22).** Everything after it (the
2026-09-23..25 nightlies and the uncommitted §G98 work) was reverted; it is kept on branch
`keep/pre-revert-2026-09-26` and in `git stash` ("pre-revert 2026-09-26 …"). Maintainer's
note: Claude Opus 5.5 is of questionable quality for this project; avoid it.

What the reverted rounds showed (full entries: `git stash show -p stash@{0} --
scheds/rust/scx_cake/STATE.md`; data: `scx_cake_bench/runs/wow_*_2026092[56]/`):
- §G97 (interrupt-CPU placement, 09-23) cost WoW about 1.3–1.6 % fps and 5–6 % on p99
  and 1 % low. NVIDIA IRQ 97 lands on CPU 12 in bursts of back-to-back handlers; §G97
  queued the GPU-completion threads (vkd3d_fence, one WoW.exe thread) on CPU 12 for the
  whole burst: wake-to-run p99 about 106 µs against under 1 µs.
- Without §G97, the 09-25 tree with §G98 still trailed 09-22 in the tail over two
  back-to-back pairs: max frame about 45 % longer, frame-time stddev 5–14 % higher,
  0.1 % low 1–4 % lower; average fps within 0.25 %.
- schedstat `run_delay` (thread-health) misses IRQ time between a wakeup and its switch
  (`rq_clock_skip_update`); use tracepoint timing for this class of delay.
- No cake build needs sudo: copy it to `target/cake_receipt_builds/<name>/scx_cake`, run
  `sudo -n /usr/local/libexec/scx-bench-setcap <absolute path>`, start it as the user.
- 09-22 still carries the frontier change behind the 09-25 Unreal Editor `runnable task
  stall`; the §G98 fix for it is in the stash.

The code is `9db04489e`. The entries from 2026-09-22 on and the Owed list below record
the reverted work as history.

**Archive:** `docs/archive/STATE_ARCHIVE.md` holds every settled entry word for word,
newest first: the rounds up to 2026-09-19, the August campaign, the scoreboard (last
sealed 2026-08-23; re-baseline before citing), the ledger and the `§` registry. Search
it with grep; do not read it whole. Older history: `git log -p -- scheds/rust/scx_cake/STATE.md`.

**Offload rule:** once nothing in an entry is owed, move it whole and unchanged to the
top of the archive, in the same session. An item that is still owed moves up to "Owed"
first.

Branch: `RitzDaCat/scx_cake-nightly`. Last upstream merge: PR #3786 (`c410fcbd7`,
2026-09-06). Squash and backup-branch history: the archive's first section. Hashes
from `12803f341` to `f397452b5` are pre-squash commits, kept only on the local branch
`keep/pre-squash-2026-09-25`; the branch carries them as the six commits after
`9db04489e`.

---

## Owed

Items below were owed by the reverted 2026-09-23..26 work; re-check each against
`9db04489e` before acting on it.

- **2026-09-25 (night), §G98, the startup rows and the §G97 removal (uncommitted):** the
  maintainer's go to commit; the game frame A/B (`cakebench game ab`) for the set; the
  independent-review fixes still open (entry below); `cargo test -p scx_cake --
  --ignored verifier_load_topologies` with BPF capabilities (multi-LLC, >64 CPUs, sparse
  ids); an HZ 250/300 host run of the stall scenarios.
- **2026-09-25:** an 8-slot `cakebench cost ee0dbabc7 f9b4d3281 --slots 4` run for
  the four commits of that day (the 2-slot run had one slot in a load burst), on a
  quiet host.
- **2026-09-23 (night):** the "Open" list in that entry below.
- **Carried from the 2026-09-19 entries, now in the archive (not rechecked since):**

> **Unresolved, carried:** in each of the last two rotations one new-arm slot
> dipped at the 0.1 % low (a handful of 0.9–0.97 ms frames whose whole appsim
> chain ran long); old arms show the same frame class (s6_old max 0.90 ms,
> s4_old 0.84 in `rot3`), seven of eight slots per rotation are identical,
> and the 4-slot run of 2026-09-19 dipped on both arms. Not called null: the
> next rotation (or an A/A on `8248fe6c3`) decides whether the new arms carry
> it. Net over the round vs the pushed nightly `e355a60f2`: dispatch 42.7 →
> 32.2 ns/run, total cake BPF 29.4 → 30.1 ms/s (the interlock's +2.8 minus
> these −2.4), frames flat within the carried question.

> Deferred from the layout lens, with a census owed first: lock-free seat
> slot (`pid|seq<<32`, −4 helper calls per stage pair, but a HOLD/RELEASE
> race can lose a reservation: not placement-neutral); stopping precomputing
> stage/starved/subhandoff into the groove to trade four remote-dirty task
> lines for one storage lookup (needs `perf c2c` on those loads).

> Owed: maintainer's push decision; the §G93 trace on a WoW dungeon (gates
> cpu_release's evacuation, unchanged by this round); testers' probe=1 logs
> from a 5800X / 14900K / 7950X3D / Threadripper for §G96; the game-scene
> histograms before any actuation of the floor or the stage boundary (§G37
> Phase A' sweep: `--handoff-ns 800/1464/3000`); the grant timer behind
> `grant_lt_tick`.

> Owed, in order: probe=1 slot in both games (V19's cut rule: fired=0 in
> both games AND one saturated harness slot, with a recorded design reason);
> V18 seat pricing once the sudoers `prog profile` rule carries
> `llc_misses`; V11 race table; the seamlessness council's findings (below,
> when in); then the §G93 trace (`rt_displace_capture.sh 30`) and the
> irq_leave scene-matched bisect from the 09-18 list below.

---

## RESUME HERE

Historical resume marker from September 26. Start with the current navigation
and newest entry above; the following record is retained for its evidence.

**2026-09-26 — §G97 REMOVED (ISR-WAKE PLACEMENT).** Uncommitted, on top of §G98 and the
startup rows (release binary `dde4a804`). §G97 (`3c56bafb2`; its entry is now in the
archive) put a non-stage task woken inside a hardirq on the idle waking CPU, IMMED. Here
NVIDIA IRQ 97 always lands on CPU 12 and fires in bursts of back-to-back handlers
(handler p50 21 µs, next entry 0.3–0.4 µs after each exit, bursts about 80 µs), so the
placed task waited out the burst: in 10 s, 6,491 of 8,841 CPU-12 placements waited over
20 µs (p50 93 µs). The two WoW threads that report GPU completion (vkd3d_fence and an
unnamed WoW.exe thread) went from p99 0.6–0.8 µs to 106–107 µs, woke about 30 % less
often, and GPU busy fell 97.6 → 96.2 %; every other render thread was unchanged. Removed:
`cake_isr_wake_cpu`, its call in `cake_select_cpu`, `CAKE_SITE_ISR_WAKE` and its loader
name, the DESIGN.md paragraph.

WoW at one GPU-bound spot (4K 240 Hz, about 690 fps), one 25 s pass per arm, 20 s
filtered traces. Two sessions: the §G97 passes ran 12–15 min before D, when 09-22 measured
688.0 fps (first and last §G97 passes 0.25 % apart); by the D session the scene ran 1.3 %
faster. Through 09-22 as the common arm, §G97 cost about 1.6 % fps and 6 % p99 and 1 % low:

| build | avg fps | p99 ms | 1 % low | fence p99 µs | tid 11129 p99 µs |
|---|---|---|---|---|---|
| §G98 + §G97 (`1562987c`, two passes) | 676.3 / 678.0 | 1.90 / 1.89 | 527 / 530 | 107.2 | 105.9 |
| 09-22 `9db04489e` (same session as D) | 697.2 | 1.75 | 570 | 0.82 | 0.58 |
| D: §G98 without §G97 (`dde4a804`) | 696.9 | 1.74 | 573 | 0.86 | 0.57 |

§G98 is not involved: the 09-24 nightly, without §G98, showed the same loss (676.7 fps,
p99 1.89 ms). Checks: fmt; clippy debug and release, 0 scx_cake warnings; `cargo test -p
scx_cake` 35 pass; attached twice, the loaded `cake_select_cpu` has no
`cake_isr_wake_cpu`. Data: `scx_cake_bench/runs/wow_versions_20260925/`,
`runs/wow_mech_20260926/`, `runs/wow_dtest_20260926/`; earlier diagnostics in
`runs/wow_live_g98_20260925/` and `runs/wow_quick_ab_20260925/`.

Measurement notes: schedstat `run_delay` misses IRQ time between a wakeup and its switch
(`rq_clock_skip_update`, kernel `core.c:2310` and `:7150`), so thread-health cannot see
this delay; tracepoint timing can. The OSLTT gain credited to §G97 was measured against
the shipped cake 1.2.1, not against its parent: before any interrupt-CPU placement
returns, measure OSLTT against `9db04489e`, and make it burst-aware or uncommitted
(shared queue plus kick).

**2026-09-25 (late night) — STARTUP ROWS: HOST VALUES ONLY.** Uncommitted, loader only,
BPF unchanged. Maintainer's rule: startup shows that cake runs and the host's values;
derived policy goes behind `-v`. The `Vtime cap` row (raw ns, policy with one host input)
is now `Tick         1 ms (HZ 1000)` (`not measured; precise clock used` without a
tick); `-v` adds `   vtime   lead cap = one 4 ms run at the task's weight (65.5 µs –
102.4 ms)`; the `-v` `age` row after Running is gone (the Tick row states the clock).
Proof: fmt; clippy debug and release, 0 scx_cake warnings; `cargo test -p scx_cake` 35
pass (2 new, `rodata::tests`); an unprivileged debug run printed both rows, then stopped
at BPF load (EPERM).

**2026-09-25 (night) — §G98 BOUNDED VTIME LEAD: RATE-BAND FRONTIER.** Uncommitted in
the working tree. Release object vs the measured arm Q2 (`aa9a6b6a0`, scratch; binary
`target/cake_receipt_builds/cost_aa9a6b6a0c8d/scx_cake`): objdiff differs only in
`cake_frontier_step` (an exact early return, review fix) and the probe record's size.
Data and tools: `scx_cake_bench/runs/g98_20260925/`.

Incident: the maintainer's run of the 09-25 nightly (`67295ff5`, Unreal Editor + 12
python3) was ejected: `runnable task stall` (BackgroundWorker, nice 5, 6.436 s). The
stuck workers sat 90.3–92.6 s of vtime ahead of the frontier on per-CPU DSQs. Cause:
`d97e93c3b` (2026-09-06, in every nightly since 09-07) capped F at other CPUs' live
occupant vtime; nothing capped v − F, so a low-weight task running on free CPUs banked
lead at 3.057 − r_F per ns; per-CPU queues have no wall-clock net (§G42's open half).
Not caused by the release/debug split (`ee0dbabc7`): every probe-gated block only
observes (read-only audit).

Rule (council round 2: five lenses, synthesis, critic; no rescue, no polling):
- Ceiling at the charge: `v ≤ F_run + cake_vtime_cap(idx)`; the cap is the charge of one
  longest run (`cake_vcap_unit_ns`, loader rodata from the tick), within
  [`FRONTIER_GRAIN_NS`, `CAKE_VTIME_CAP_MAX_NS` = one nice-19 grant, 102.4 ms].
  SCHED_IDLE shares the nice-19 cap.
- F advances in ops.running within the band [dt >> `RATE_FLOOR_SHIFT`, dt] since its
  last store, stored by CAS with a stamp; the common path (within a grain, floor owes
  under a grain) is two compares, the step is a cold `__noinline`.
- The candidate sweep reads `CAKE_NEIGHBOUR_PROBE_DEPTH` loader-listed peers
  (`cpu_frontier_peer`, topology-aware; unit test over 15 layouts), not every CPU.
- Bound by construction: wait ≤ (`CAKE_FLOOR_WINDOW_NS` << `RATE_FLOOR_SHIFT`) + drain.
- Policy, no measurement: `CAKE_KEY_BUDGET_NS` = half the watchdog (key window vs drain,
  tick, skew, RT hold; the kernel ejects at runnable_at + timeout); `RATE_FLOOR_SHIFT`
  = the largest k with window << k within the budget (static asserts: 4).
- § entries (policy, no measurement): §G98a `CAKE_KEY_BUDGET_NS` = WATCHDOG/2;
  §G98b `CAKE_VTIME_CAP_MAX_NS` = one nice-19 grant (the most lead any weight holds;
  SCHED_IDLE shares it, so its effective weight rises to nice 19's); §G98c
  `FRONTIER_GRAIN_NS` (65 µs, underived since 09-19) gains two roles: the cap floor and,
  << `RATE_FLOOR_SHIFT`, the 1.05 ms floor-store threshold.
- Independent review (non-author, read-only): rule, bound, CAS and peer list correct on
  AMD 1/2/4-CCD +C numbering, 3950X, 7980X, Strix Point, Raptor/Meteor/Arrow Lake, 1-2
  CPUs, sparse ids; fixes applied (early return, dead probe field, comm helper, comments).
  Open: the verifier has not loaded the multi-LLC, >64-CPU and sparse rows (Owed).
- Rejected: C (F = wall clock): three lens models showed game threads lose their wake
  head start under saturation (FIFO order). P (ceiling only): its bound depends on F's
  rate (stalled below).

Results, 2026-09-25, 16-CPU 9800X3D, HZ 1000 (arms HEAD+probe `7bc248a69`, P `483dbda17`,
Q `c811a90f7`, Q2 `aa9a6b6a0`; EEVDF = no scheduler):

| test | EEVDF | HEAD | P | Q / Q2 |
|---|---|---|---|---|
| stall repro, idle host, largest lead | — | 68,735.79 ms | 38.22 ms | 33.60 ms |
| SCHED_IDLE vs 10 pinned per CPU | 9.05 s gap | ejected (6.590 s) | 1.05 s | 1.09 / 1.07 s |
| nice 19 vs 60 pinned per CPU | 11.4 s gap | ejected (6.572 s) | ejected (6.205 s) | 1.81 / 1.80 s |
| nice 19 waking among 64 spinners | 0.60 s | 1.49 s | 0.18 s | 0.28 / 0.31 s |
| nice 5 share vs 4 nice-0 (pure 7.5 %) | 7.50 % | 12.50 / 8.18 % | 13.50 % | 9.53 % (Q) |

Game-facing (metric order: games owed; appsim; wall clocks):
- appsim `cakebench cost` HEAD vs Q2 (`runs/cost/20260925T193741_appsim`, busy 42.9–46.3 %):
  p99 0.6280/0.6274 vs 0.6292/0.6324 ms; 0.1 % low 1366/1360 vs 1357/1318 fps; the Q2
  slots ran 1–3 points busier. ns/run: running 33.1/37.4 vs 32.6/34.0, stopping 18.5/19.3
  vs 20.3/20.9 (the ceiling, +1.4..2.4 ns), dispatch 40.1/40.6 vs 41.2/42.8.
- HEAD/P/Q at matched busy (`20260925T191251_appsim`): total 26.75 / 26.89 / 26.76–27.38
  ms/s, p99 0.620 / 0.619 / 0.619 ms. Q before the fast path: running +3.97 ns under
  Blender (39.56 → 43.53); render 45.10 → 45.24 s (`runs/cost` blender, 2 slots).
- OSLTT input wake (USB fetch → evdev echo, µs, mean/p50/p90/p99): HEAD 41.5/41/51/57.8
  vs Q2 39.6/36/47/52.8 (2 × 100); HEAD 50.6/48/59/92.7 vs Q 50.9/49/59/103.4 (4 × 100,
  p99 inside each arm's round range). USB-to-photon (ms, mean/p99, 3 × 60): EEVDF
  7.623/11.149, HEAD 7.566/10.572, Q 7.704/11.075.


**2026-09-25 — DEDUP, CLAIM AND DISPATCH SHAVES, THE COST TOOL.** Same placement and
scheduling; each commit carries its object proof.

| commit | what | proof |
|---|---|---|
| `f2807609b` | helpers for four repeated idioms: `cake_noisy_word`, `cake_seat_cores`, `cake_seat_idx`, `cake_seat_drop` | objdiff IDENTICAL |
| `87b16b4f8` | `cake_rank_tier` reads the tier count once per call | 8 insns per tier scanned, was 10; four pickers −1..−4 insns |
| `f0dfb4ed7` | `cake_claim_warm` passes `preferred` as the first try's cold set | warm path 45 → 31 BPF slots, 2 fills fewer; a 200,000-case model of both forms matched |
| `f9b4d3281` | the both-empty dispatch test runs in `cake_dispatch`'s frame | empty path 85 → 81 slots and one call fewer; +117 static insns |

Tried and left out: a helper for dispatch's two move-and-serve blocks
(`cake_dispatch_search` 536 → 555 insns, fills 37 → 42); one `home_ok` bool in
`cake_select_cpu` (−3 static insns, hot path unchanged).

Measured: `cakebench cost ee0dbabc7 f9b4d3281 --slots 2`
(`scx_cake_bench/runs/cost/20260925T102205`), all four slots valid. Slot 2 (tip) ran in
an outside load burst (busy 56.6 %, enqueue 48.8k/s against ~5k/s). The matched slots
(3 tip / 4 base, busy 33.8 / 33.9 %): dispatch 36.8 / 35.8, select 91.9 / 94.4, running
30.0 / 30.8 ns/run. Not decided; the 8-slot run is owed.

A second run, `--slots 4` (`runs/cost/20260925T114740_appsim`), stopped in slot 7. The
host was switched off by hand at about 11:53 (the maintainer confirms; not a hang) with
the base arm (`c5afc313`) attached; slot 6's output was lost. Slots 1–5 are valid, and both arms show raised rates:

- enqueue: tip slots 3 and 5 at 14.2k and 195.5k/s against 4.5–7.3k/s; slot 5 also ran
  346.0k running/s against 159.3–168.7k/s;
- dispatch: base slot 1 and tip slots 2 and 5 at 761.7k, 1,465.9k and 425.6k/s against
  158.0–170.1k/s.

Tip slot 2 ran at base enqueue rates (6.2k/s). A read-only review found no behaviour
change in the four commits, so the cause is likely outside load; not decided. The cost
tool records no `noise_class` or `external_cpu_avg_pct`.

`bpftool prog profile` on the loaded build (older than HEAD), per run: select 626
cycles / 1,285 insns, dispatch 703 / 1,566, running 374 / 818, update_idle 347 / 832,
irq_enter 508 / 596, irq_leave 946 / 600. This is the "next" step the 09-18 irq_leave
entry names: the same instruction count and 438 more cycles; the cause stays open.

Tooling: `cakebench cost <A> <B> [--slots N]` (`scx_cake_bench/bench/scx_cake_cost.py`)
builds arms in one parked worktree (`scx_cake_bench/_scratch/worktrees/cost`; a cold
build takes 13 s), grants capabilities, runs a mirrored appsim rotation with bpf_stats,
checks each slot's identity against the loader's `Build SHA256` line and prints one
table. Found on the way: `target/` was wiped at 09:38, a session's `mkdir -p` then
recreated `target/cake_receipt_builds` at mode 755, and the receipt builder refuses any
root that is not 700; `cost` creates the root at 700.

**2026-09-24 — INSTRUCTION ROUND, 13 commits (`8b22c6cd4` … `ee0dbabc7`).** Recorded
2026-09-25 from the commit messages and the saved runs.

| commit | what | result |
|---|---|---|
| `8b22c6cd4` | dispatch: test `pend_spin` before clearing it | objdiff: `cake_dispatch_search` only |
| `7a3bd8d26` | dispatch: inline `cake_wake_serve_stamp` | `cake_dispatch_search` 529 → 545 |
| `0bd25ebd5` | ring walk over marked CPUs only | reverted in `a58cca2ff`: dispatch 29.63 against 28.24 before it |
| `7660314f1` | pool move before the count | reverted in `6282a7ea1`: dispatch 29.63 → 44.06 ns/run |
| `1c21cd199` | probe: the CPU id for `cake_tried` read under the toggle | one insn in each of two functions |
| `13811c96e` | `cake_claim_warm`: prev's seat bit before its seat pid | warm path two loads fewer |
| `3273cc4c9` | `cake_select_cpu`: handler depth tested before the ISR-wake call | warm path 118 → 106 insns, one call fewer |
| `181c3e628` | enqueue: the expiry preempt tests the grant first | pooled wake about 148 → 132 insns |
| `45b72dd96` | `cake_select_undecided`: no idle CPU in scope returns prev first | no-idle path 188 → 125 insns |
| `5c53951eb` | seat: the holder back on its own seat skips storage and the lock | running 165 → 176, stopping 215 → 237 live insns |
| `ee0dbabc7` | release compiles the probe out; debug runs it; `--toggle` removed | `cake_select_cpu` 473 → 384 live insns, no spills |

Data: `scx_cake_bench/runs/opt_bisect_dispatch_20260924` (the two reverts);
`runs/noprobe_rot_20260924`, the toggle build (A, `dd2b92ec`) against a probe-out
prototype (B, `64fee63d`), 4 slots per arm, busy 31.7 / 31.8 %: select 88.2 → 84.1,
dispatch 28.2 → 30.3, running 27.6 → 25.7, stopping 14.1 → 14.1, enqueue 186.0 → 176.9
ns/run.

**2026-09-23 (night) — OPEN-ITEM FIXES (two reviewers each, read-only).**

| commit | what | proof |
|---|---|---|
| `8fd3cc6cf` | black box: `__sync_fetch_and_add` reserves the slot. clang 22 lowered the relaxed `__atomic_fetch_add` to a non-fetching add, so every record went to slot 1 and slots 0, 2, 3 printed zeros (since `77251dd02`) | objdiff: `cake_probe_run` only |
| `2f4bc9a6c` | loader: exit reports after detach. The `-v` events row read `cake_events` before `ops.exit` filled it (8 of 8 saved rows `0 0 0`) | link close → `bpf_scx_unreg` → disable flush waits for `ops.exit`; maps stay mapped |
| `c7a7057c3` | deleted the stale review and topology harnesses | — |
| `3210c8e80` | census `taci_pool` / `taciw_pool`: the pool kicks' claims apart from `taci_notify` | 106 stat-index immediates in 37 functions remapped; `cake_stats` 139 → 141 entries |
| `97e8898a3` | `cake_claim_free` / `cake_offer_remote` add `cake_deep_word()` to the noisy set, as `cake_claim_warm` / `cake_pick_idle_clean` do (§G96 extension, inert here) | these two only; claim_free 180 → 190 insns, spill/fill 4/3 → 3/3; offer_remote 234 → 247, 5/4 → 4/3 |
| next commit | the static assert compares the TACI / TACIW block lengths; two comments | object identical |

Attach checks, 2026-09-23 night, host busy with unrelated work (40.7–80.4 % busy):
- `cakebench try` HEAD `57cd21c70`: verifier accepted, 0 stalls, native restored.
- probe=1 `-v`, one appsim run: black-box records in slots 0–3, none zero; events row
  `select_fallback 317380 keep_last 90 enq_skip_exiting 1166` (was always `0 0 0`).
- bpfstats, appsim helldivers2-mission-fitted 45 s, ABBA then BAAB 60 s apart, base
  `3154a112e` (`e8db9764`) vs tip `57cd21c70` (`e50d6e50`); data
  `scx_cake_bench/runs/openfix_rot_20260923/`. Raw means favour the tip (dispatch −47 %),
  but the base slots drew the busy bursts (mean busy 65.5 vs 50.3 %); dispatch ns/run
  tracks busy (5.10 ns per point, R² 0.77). Busy-adjusted, every callback is level
  (dispatch −1.5 ± 40.5, cpu_release −4.6 ± 12.2 ns); at matched busy dispatch is
  110.8 / 107.3 and 79.2 / 77.5 ns. Kept. On one LLC `cake_offer_remote` is not reached.
- `select_fallback` is not a cake fault: it equals `probe_fired` (317,683) within 0.1 %.
  The neighbour preempt inserts LOCAL_ON to a CPU other than the one select_cpu returned
  (place.bpf.h:485-493); the kernel counts any enqueue off `selected_cpu` as a fallback
  (ext.c:2183-2185). 3.9 % of wakes pay a deferred remote move.

Open:
- `cake_prefer_irq_clean` merges the deep word into the IRQ-hot set: when every candidate
  is deep, the fallback is the whole set and IRQ-hot avoidance is lost, in all four
  pickers. A tiered preference (clean, then not IRQ-hot, then all) is a design choice;
  unmeasured, needs a cpuidle host.
- On a cpuidle host each pool kick now reads `cake_deep_idle_word`, written on every
  deep-idle entry and exit: a likely shared-line miss. Capture owed with §G96.
- No offline policy assertion remains. The deleted harnesses covered `cake_cross_llc`
  wide pairs, the `cake_offer_remote` slot and kick, frontier spans, seat retirement
  races, select_cpu parity with probe on and off, retake exclusions, dispatch_search seat
  cases, `cake_slice_from_service` and the `cake_stage` bound. Elsewhere: the SMT fold
  formula (`layout.rs`, a Rust copy), liveness under affinity churn (CI stress-ng),
  verifier load shapes (`verifier_load_topologies`, `#[ignore]`, manual with BPF caps).
  Rewrite `cake_slice_from_service` and `cake_cross_llc` first, when either changes.
- Stale docs, not from these commits: README.md toggles g85–g89 and llcsplit;
  docs/TOOLING.md "build a PROBE commit" and `--toggle llcsplit=1`.

**2026-09-23 (later) — READABILITY REFACTOR (no scheduling-policy change).** The BPF
source is one translation unit in 12 files, the loader 12 files; every no-change commit
is proven with `bench/objdiff.py` (instructions per function and data layout against the
parent). Base `2a27111df`, tip `0aae3f409`.

| commit | what | proof |
|---|---|---|
| `c45dea62d` | named probe constants, dead `intf.h` constants gone, stale comments | object identical |
| `17cc22855` | 20 helpers for repeated idioms; a site where a helper changed the object kept its open form | object identical |
| `c06be39b2` | `cake.bpf.c` → 11 headers (abi, stats, kfunc, topo, state, task, vtime, seat, probe, place, dispatch); global definitions keep their order | identical except `cake_init`'s error-string line numbers and `.maps` order |
| `6333ed9d4` | one-line kernel-style comments: 703 → 213 comment-only lines (0.28 → 0.09 per code line) | object identical; `try` OK |
| `47804a4ae` | `comment_lint` ceiling 0.20, linear count, trailing comment counts as code | — |
| `5327a1f3f`, `e1333b5ba`, `34ce3abd2` | loader: `main.rs` 2233 → 633 lines; modules cli, host, layout, irq_sinks, privileges, rodata (fills), diag (exit reports); helpers and named numbers | loaded `.rodata` byte-identical except `cake_wake_hop_ns` (live probe p99); startup and probe exit rows identical in shape; same tests |
| `8b3f0dfb5` … `92b90e3d0` | measured phase: `cake_nvcsw`, `cake_vtime_floor` at enqueue and pinned wake, `cake_local_dsq` at the kthread insert, `cake_pool_served` in dispatch (identical), `cake_claim_cold` in `cake_offer_remote` | enqueue 651 → 640 insns, admit_direct / wake_admit / handoff_yields −2 each, pinned −1; stack ops 417 → 398 |
| `125604cd8` | the 2026-09-22 review fixes below, restored | object identical |
| `b36edecd1` | loader: IRQ self-check names CPUs (was `slot{i/2}.{i%2}`); sibling map cached at attach | — |

Measured phase, appsim helldivers2-mission-fitted, ABBA 45 s slots, `cake-bpfstats`
deltas, base `34ce3abd2` (binary `ebf63263`) vs tip `92b90e3d0` (binary `35119da4`), all
slots attached and restored; data `scx_cake_bench/runs/refactor_phaseB_20260923/`:

| arm | select_cpu | enqueue | dispatch | running | stopping | appsim p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| base | 125.1 | 158.4 | 210.3 | 54.7 | 33.0 | 1.62 / 2.08 |
| tip | 115.7 | 137.2 | 183.3 | 50.1 | 30.3 | 1.24 / 1.18 |

Level or better on every callback, so all five stay. The size is not the change:
untouched callbacks (running, stopping, cpu_release) moved 6–8 %, the base slots ran
first and last, and no noise covariate was recorded. Treat it as "no regression" only.

Open, carried:
- The three decision chains `cake_select_cpu`, `cake_enqueue` and `cake_dispatch_search`
  (108–112 code lines each) keep their structure: splitting them moves register
  allocation in the hottest code. A measured restructure is the next readability step.

**2026-09-22 — COMPATIBILITY AND LOADER DIAGNOSTICS (no scheduling-policy change).**

| commit | what | receipt |
|---|---|---|
| `256a69e0e` | `p->on_cpu` read through CO-RE on both layouts (u8 and int flavors); an unknown layout keeps the idle kick | — |
| `879ed9c38` | pre-6.18 kernels: `cake_wake_place` reads the untrusted `rq->curr` fallback itself; the caller passes NULL across the `__arg_trusted` boundary. One extra `cake_cpu_curr` per pool-bound wake on those kernels only | — |
| `9db04489e` | one unsigned `u32` CO-RE `on_cpu` flavor (libbpf narrows an unsigned load to u8; a signed local field refuses the resize); `cake_ops` auto-attach off; startup rows aligned, detail behind `--verbose`; running-binary SHA-256 at startup and in `--version`; compat choices reported from `.bss` after attach | — |
| `125604cd8` | review fixes: enqueue `alone` indentation; the idle log prints the exit cost in use and says it is off above 64 CPUs | release clippy 0 scx_cake warnings, fmt |

None of these is measured; none changes a decision on a ≥6.18 kernel with a u8 `on_cpu`.
