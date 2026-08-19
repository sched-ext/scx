# scx_cake — CURRENT STATE

> [!IMPORTANT]
> **Read this first, every session.** This is the one source of truth, in three parts:
> current state (scoreboard, open gaps, harness routes), then the ledger (one row per
> experiment), then the `§` registry (every `§` pointer in the source resolves there).
> Rules live in `CLAUDE.md`; behaviour in `DESIGN.md`.

**Full history:** `git log -p -- scheds/rust/scx_cake/STATE.md` — plus the retired
`HYPOTHESES.md` and `CAMPAIGN_LEDGER.md` paths, merged into this file 2026-08-18.
This file was compacted 2026-08-12 from 30,510 words; everything cut is in that history.

<details>
<summary><b>Branch and squash history</b></summary>
<br>

Branch: **`RitzDaCat/scx_cake-nightly`** (pushed to fork). History squashed four
times: at `15960cb97` (53 commits → `backup/nightly-53-commits-20260810`), at
`38397bb59` (10 commits → `backup/nightly-10-commits-20260817`), at `c99eb00c7`
(12 commits → `backup/nightly-12-commits-20260818`, after the 2026-08-18 rebase onto
upstream `ff86d6588`; pre-rebase state in `backup/nightly-pre-rebase-20260818`), and
at this commit (17 commits → `backup/nightly-17-commits-20260819`: the R.28 arc —
1.1.3 wallclock campaign, mode-flip root cause, per-task geometry, veto bisect,
live WoW confirm); all hashes cited below resolve via those local backup branches.

</details>

---

## RESUME HERE

| # | item | state | next action |
|---|---|---|---|
| 1 | **G35** in-handler bit from IRQ tracepoints + **G36** tick predictor | Phases A–D LIVE 2026-08-17 (D closes §G34 H3), §G36 BUILT, all gates clean; desktop movable hot-landings staircase **0.80 → 0.66 → 0.23 → 0.17%**, cpu0 timer hits **820 → 4** | captures on disk unscored: `wow-cake-g35d`, `wow-cake-g36`, `g36-desktop` in `~/Documents/Repo/scx_cake_bench/history/wake_latency/`; next action: score vs `wow-cake-g30c`. §G35/§G36 |
| 2 | **G33** sink-ness = IRQ time share, not count | Phase A BUILT, attach-test PASSED 2026-08-17 22:07; 9 s live replica converged **[5, 13]**, mouse CPU 7 never flagged, zero set flap | captures on disk unscored: `wow-cake-g35d`, `wow-cake-g36`, `g36-desktop` in `~/Documents/Repo/scx_cake_bench/history/wake_latency/`; next action: score vs `wow-cake-g30c` — fence tail ≤ g30c, placements on 7 resume, mean unchanged-or-better. §G33 |
| 3 | **G30** sink set is a one-shot sample (WoW find) | Phase B COMPLETE at the wake tier 2026-08-17 (`wow-cake-g30c`, live WoW): fence p99 **31.45 → 1.25 µs**, slow wakes (>20 µs) **478 → 6**, CPU 13 landings **~1050 → 2** | Phase C endpoint: game frame screen (severe-frame ratio, 0.1% low) next time MangoHud is injected. §G30 |
| 4 | **G29** vtime class bits (construct C) | registered | build Phase A: encode + restamp in stopping only, sealed A/A + fnspills |
| 5 | **G28** pre-paid idle exit (construct B) | registered; "no timers" absence amended by maintainer 2026-08-17 | build Phase A: timer + counter, NO kick, arm only ≥ 2 ms frames, A/A screen |
| 6 | **G27** frame-anchored geometry (construct A) | **BUILT + LIVE-SMOKED 2026-08-17** — attached through a real game session, zero stalls, clock tracked 26 Hz–1950 Hz; §G27.1 sleep-majority vote gate + fastest-real-cadence picker with fast-up/slow-down hysteresis, 3 live iterations same day | sealed A/A (expect null), then HD2 easy-scene ABBA. §G27/§G27.1; theory `docs/THEORY_CONSTRUCTS_ABC_2026-08-17.md` |
| 7 | **G26** frame laxity (new input) | registered 2026-08-09, §G26 (registry below), research `docs/RESEARCH_ADPF_LLF_2026-08-09.md` | Phase A: observe-only Vulkan-layer producer, A/A overhead screen, zero scheduler change |
| 8 | syncgate simplification | SLEEPER_LAG passes 98.6%/95.5% — confirmed not a predicate (G10 #8) | simplify |
| 9 | dead-branch deletions | pinned-wake preempt (5th zero dataset) + sibling kick (2nd) — delete-with-no-trade | **ON HOLD** until the receipts audit confirms the zero datasets (`REVIEW_INDEPENDENT_2026-08-17.md` Addendum, in git history); then delete both and run a game screen |
| 10 | **G25** steal-ring bitmask | **LANDED**, verifier accepted, attach smoke passed 2026-08-08 | wake latency on HD2 render roles + P4 bench screen. Prediction on record: ~0.04% of a core quiet, 4.7% invalidated — **expected frame effect near zero; a null confirms the pricing** |
| 11 | **G23** per-line IRQ-sink detection + mask avoidance | built, smoke PASSED, **endpoint unmeasured** | HD2 ABBA during ACTIVE play (P2 needs live mouse input) on `Window & Input` / `main` / `renderer` mean wake + severe-frame screen, then P4 `--blocks 2` bench screen. Receipts + steps: `docs/REVIEW_G21_G23_2026-08-02.md` §resume |

**EXP S.1-1ms (2026-08-19): ❌ FALSIFIED.** Hypothesis was: nightly's extreme-tail loss
vs shipped 1.1.3 (mutex-handoff p999 −37% 6/6; `runs/adhoc_wallclock_113_vs_nightly_20260819`)
is SLICE_NS geometry. Probe SLICE_NS 3000→1000 µs (`092ada871`), 6-slot ABCCBA
(1.1.3 / 3 ms / 1 ms): p999 2.53→2.70 µs (both ~2× 1.1.3's stable 1.36), p99 1.20→**1.85**
(1 ms actively worse), schbench-saturated −18% worse; throughput flat ±4%. Reverted
byte-identical `3df90d103` (39d784f3). Secondary find: 1.1.3's handoff tail is IDENTICAL
across suites (0.85/1.36 µs) while nightly's drifted (p99 0.85→1.20 same code) — the
nightly tail is regime-sensitive, the 1.1.3 tail is not. The gap is structural, not quantum.

**Also open, no owner:** the serial-handoff trade (fires 0.01–0.03% in game regimes —
games-only maintainer call). G25 leftovers: contended regime needs re-pricing with a
**15-reload** arm (128 B stride reversal ledgered as G25.1).

**Diablo IV chop (`docs/ANALYSIS_DIABLO_CHOP_2026-08-02.md`, 12 runs):** 24.92% of frames
> 2× median with CPU 19.5% / GPU 64%. **Cake exonerated at the wake tier**; field narrows
to the present path — KWin-windowed treatment vs engine 30 Hz tick. Bare env collapses the
stall train 20–33×.

---

## Scoreboard

### Benchmarks vs native EEVDF — SEALED exact-pair medians, 8 blocks

| workload | delta | note |
|---|---|---|
| stress-ng-futex | **+57.2%** | **MODE-CONDITIONAL** — same code read 4.73M / 1.42M / 0.35M ops. Never read single-arm |
| schbench-saturated p99 | +49.1% | |
| ccm-cache | +45.9% | zero-sum with ccm-memcpy below |
| stress-ng-cache | +26.5% | |
| perf-sched-pipe usecs/op | +22.7% | CI [+21.1, +24.9], first sealed exact-pair |
| blender-render | +11.9% | CI [+11.8, +12.3] |
| mutex-handoff | +10.3% | CI [+9.1, +12.6] — the Wayland-input shape |
| thread / fork / memcpy-split | +7.5 / +5.5 / +4.5% | |
| **ccm-memcpy** | **−14.9%** | CI [−15.5, −13.0] |
| **schbench-light p99** | **−1.42%** | quiet; **−9.6%** under heavy desktop noise |
| **futex-lock-pi** | **−71.8%** | CI [−72.5, −70.9], recovered from −86.6 by mutation K |

**Stale/unsealed, re-baseline before citing:** perf-memcpy, argon2, x265, sevenzip,
y-cruncher, namd, kernel-defconfig, xz, prime.

### Games — latest valid reads

| run | metric | native | cake | verdict |
|---|---|---|---|---|
| HD2 menu, ABBA 2/arm, 240 Hz VRR, 2026-08-01 (G17) | 240 Hz deadline miss % | 3.019 | **1.419** | **cake 2/2, −53%** |
| same | FT stddev / p99−median | 0.258 / 0.711 | **0.217 / 0.619** | cake 2/2, −16% / −13% |
| same | avg FPS / 0.1% low | 276.3 / 193.3 | 276.3 / 188.6 | tie / overlap |
| HD2 easy scene, ABCCBA, 2026-08-01 (G18/G20) | **0.1% low** | **225.80** | 212.79 / 213.92 | **native 2/2, cake −5.6%** |
| same | 240 Hz deadline miss % | 1.004 | 1.278 / 1.155 | native |
| HD2 live, ABBA, 2026-08-02 (G21) | `main` mean wake | 0.79 / 0.79 | **0.47 / 0.48** | **cake 2/2, −39.9%** |
| same | `renderer` mean wake | 0.91 / 0.83 | **0.66 / 0.64** | cake 2/2, −25.3% |

**WoW wake read (2026-08-17, single-arm cake @ G27.1c build `db0b3636…`, 22 s live play —
attribution only, no native arm):** 29 roles; every high-n role p99 ≤ 2.6 µs except
**vkd3d_fence p99 31.45 / max 255 µs**, 99% of slow wakes targeting idle-shown CPU 13 =
the nvidia IRQ CPU (ISR shadow; cpuidle driver `none` on this host). Off-target fence
wakes: p50 2 / max 11 µs. Sink set empty at attach → §G30. **After G30 Phase B + sink
veto (`wow-cake-g30c`): fence p99 1.25 µs, 6 slow wakes, CPU 13 share 2/50.8k — tail
eliminated at the wake tier; frames unmeasured.** Artifacts:
`~/Documents/Repo/scx_cake_bench/history/wake_latency/wow-cake-{g27tip,g30a,g30b,g30c,g35d,g36}*`.

**Five-domain wake sweep (G17 rotation, delays > 200 µs per 10k transitions):** input
294.6/93.2 → **39.0/47.8** (4.5×), FAudio 288.3/80.8 → **31.7/40.6** (~5×), renderer
124.0/87.0 → **46.7/47.0** (2.2×), vkd3d_queue 42.0/18.7 → **13.2/15.5** (1.5×) — cake 2/2
on all four. Network (n~555) and IO (250× transition mismatch) unusable; `data-loop.0` is
SCHED_FIFO, so cake never schedules it. **Law: cake's advantage scales inversely with the
thread's burst** — G10–G20 optimised the renderer, the longest-burst thread, where the win
is smallest.

---

## Open gaps

1. **Cake loses the EASY scene** — 0.1% low −5.6%, 2/2 no overlap, on a scene where
   native's own tail is already tight. Mechanism unknown; **highest-value target on the
   board.** The G17 frame win and this loss both stand; neither generalises.
2. **ccm-memcpy −14.9%** — pure CPU-share reallocation from cake's sleeper catch-up
   (per-usr-second efficiency equal). Zero-sum, no point fix; four falsified attempts.
   The lever is unlike-type SMT pairing (+73% memcpy pinned) with a **per-TASK** duty
   class — a per-CPU veto regressed futex +57.2 → +29.3.
3. **schbench-light −1.42%** — peer wakes that go global wait for a dispatch event when no
   CPU is idle. Arc CLOSED: seven falsifications; the current point on the frontier is the
   correct trade. **Do not re-attempt wake-service or wake-preempt levers.**
4. **futex-lock-pi −71.8%** — lock-pi pins its workers, so a pinned wake queues behind a
   busy occupant and no CPU may steal it. A sched_ext **semantic gap**; kernel lane
   (a wakeup-equivalent flag for PI re-activations). Accepted known loss.
5. **The renderer wake tail resists everything** — locality (G13), preempt (G14/G15),
   notification (G16) all null; G15 confirmed falsified on input too. 28–32% of slow
   same-CPU wakes have `swapper` as occupant in **both** schedulers — an idle-exit floor
   neither one beats.
6. **`ops.enqueue` reaches 0.142% of a game's dispatches** (vs 23.6% saturated). Every
   enqueue-side routing decision is nearly inert on games; leverage is on the direct
   path in `cake_select_cpu`, which serves 99.86%.
7. **Third arm UNBLOCKED 2026-08-19** — shipped 1.1.3 (`/usr/bin/scx_cake`, sha256
   `56f9e886…`) attaches and runs clean on 7.1.8; the libbpf skeleton warning still
   prints but is non-fatal. First read: quick wallclock ABBA vs nightly HEAD
   (diagnostic tier, `scx_cake_bench_assets/runs/adhoc_wallclock_113_vs_nightly_20260819/`):
   nightly pipe **−16.0%**, memcpy −3.9%, but sched-messaging **+70.5%** (4/4, no
   overlap) — the many-to-many handoff shape regressed vs 1.1.3 and is unscored at
   the sealed tier. n=10 confirm (suite 4, 5×ABBA): schbench-light req p99 **+72%
   10/10** (S sd 7 µs, N sd 459), mutex-handoff p999 **2.0× 10/10** (S sd 0.024 µs),
   p99 **BIMODAL** (4/10 runs match 1.1.3 exactly, 6/10 at 1.2–1.9 µs), pipe −9.7%
   win 10/10. Slice dose falsified (EXP S.1-1ms). **MODE SWITCH ROOT-CAUSED 2026-08-19
   (`mode_probe/` in the run dir): it is `cake_frame_slice_ns`.** Placement exonerated
   (24 runs, pair co-resident on CPU 11 in BOTH modes, sinks 0%). Dose-response with an
   injected 1 kHz sleep-majority crowd, `--verbose` clock log as ground truth: crowd
   binds in one poll (950.8 Hz published) → p99 1.8–2.1; crowd off → 3-poll re-publish
   + ~16 s floor climb → p99 decays to 0.90. A **374.9 Hz desktop voter holds slice at
   2 ms** on this host even quiet — nightly never runs at the 3 ms cap on a live
   desktop. 1.1.3 has no frame clock (constant geometry) — hence its sd ≈ 0. Mechanism:
   any fast desktop crowd tightens patience windows (shifts of `cake_frame_slice_ns`,
   §S.2) for EVERY task; the same-CPU handoff tail pays for it. The registered fix is
   already on the board: §G12 KEYSTONE re-base of `FRAME_*_SHIFT` windows onto the
   occupant's OWN period decouples bystander tasks from the global clock.
8. **Receipts audit** — 5 load-bearing claims (deletion-queue zeros, 1464 ns, SLICE_NS
   dose, §R.17 +28-36%, G17/G21 wins); list + rationale:
   `REVIEW_INDEPENDENT_2026-08-17.md` Addendum (git history).
9. **G17's mechanism is unexplained** — peer share 58.1%→56.9% while the tail fell 17%.
10. **`SLICE_NS`'s vtime-unit role** — the last architectural constant.
11. **Probe-driven `cake_handoff_max_ns`** — forbidden per the −35.66% mutex-handoff
    result; a host-adaptive value needs runtime observation of `used` in ops.stopping,
    not a boot probe (main.rs:159 comment).
12. **`STATE_SLOT_BYTES` sysfs probe** — probe the cache line size at boot instead of
    the hard-coded 128 (intf.h:92).
13. **`CAKE_NEIGHBOUR_PROBE_DEPTH` topology ordering** — order the probe by
    `cpu_sibling` topology already in rodata instead of magic depth 3 (cake.bpf.c:137).

---

## Recently landed

| commit | change |
|---|---|
| `2efcddd26` | README rewritten — upstream framing, standard build/run path |
| `4ee89f966` + `461140b58` | docs restructure — live root + archive shelf; `scratch/`, `kernel-patches/`, `experimental/` deleted |
| `81255405e` | nightly squash — G27–G36 + spread probe/revert, rebased onto upstream `ff86d6588`; detail hashes in `backup/nightly-12-commits-20260818` |
| `76dcd3499` → `7826cfe3a` | spread probe — spread placement, co-location returns off (§R.1 fps A/B); fps INCONCLUSIVE under ~7%/h scene drift; reverted byte-identical (hashes in `backup/nightly-12-commits-20260818`) |
| `764ad82c5` | G26 registered — frame laxity as a new scheduler input |
| `edafb27e5` + `d56ad5131` | **G25** — steal-ring queue hint becomes a u64 bitmask (41 insns, 10 branches, 0 spills; rotate+`ctz` design measured and REJECTED, do not restore) |
| `3fb89cf05` (`6471262e1`, `b607264ad`) | **R.24** cross-multiplied divide elimination in `cake_frame_observe` + handoff-yields; both exact-pairs pass, kept |

Static budget at tip: **5 divides** (re-counted 2026-08-19 post-§R.28; was 11 —
`cake_task_slice` became one subprogram, and fixed windows replaced bss loads).
Spills at tip per `bench/fnspills.py` (2026-08-19): `select_cpu` 4/1, `enqueue`
2/4, `stopping` 1/1, `ring_steal` 1/1, `dispatch`/`running` 0/0; TOTAL 16/10/26.
(The script was BLIND on llvm-objdump 22 until `18581c73c` fixed the regex — any
zero-spill claim made before it is vacuous.)

---

## Harness routes

- **Everything runs `bash cakebench <cmd>`, sudoless.** Never sudo; a privileged step that
  fails is a capability/helper bug.
- **Bench pair:** `artifact ensure` → `native-pair --receipt-b <receipt> --workload X
  --readiness` → `--execute`. Screen at `--blocks 2` (~7 min, diagnostic tier); pay 8
  blocks only for keeps. `--smoke` before any new workload's first transaction.
- **Game:** `cakebench game ab --game <id> [--baseline shipped]`. **ABBA for 2 arms,
  ABCCBA for 3** (tails track slot position). Fast config = 15 s duration + 10 s settle:
  **~1.7 min ABBA, 2.5 min ABCCBA.** Screen on the severe-frame ratio; score on 0.1% low
  and p99.9 − median.
- **Frames are UNATTENDED:** `--mangohud-socket auto` (control socket per game PID),
  `game doctor` for socket health, focus via `kdotool windowactivate`. Never fall back to
  wake latency as an endpoint on the grounds that frames need the maintainer.
  **`--duration 60` max** unless MangoHud's `log_duration=60` is raised first — longer
  arms are rejected `invalid_short_duration`.
- **Wake latency:** `cakebench wake-latency capture --match '<roles>' --duration 22`.
  Post-process retained `perf.data` with `bench/wake_maxdecomp.py` (multi-role, one
  `perf script` pass), `wake_migsplit.py`, `wake_occupant.py` — most questions need **no
  new capture**. `--match` resolves tids at parse time and matches its own cmdline.
- **Load:** `bench/cakeload N` (comm `cakeload`, never a shell spinner — `python3` once
  cost a retraction). **Verify N/N alive before AND after every arm.**
- **Preflight:** `bench/capture_preflight.py` before spending maintainer time. Simulator
  appsim (harness repo: `~/Documents/Repo/scx_cake_bench/bench/appsim`;
  profile→fit→sim→validate) for exploration only — its wake latencies are ~2 µs against
  the real game's ~265 µs, so it is **disqualified for latency**.
- **Build gates, every commit:** zero warnings release **and** debug (`touch
  src/bpf/cake.bpf.c` to force the BPF rebuild), `cargo fmt`, clippy,
  `bench/fnspills.py` per FUNCTION, `bench/comment_lint.py` (density ≤ 0.70, staleness,
  duplication). **Attach-test any commit touching a kfunc binding or subprogram
  boundary** — a census is not evidence the program loads.

### Validity — check before reading any number

- Confirm **scheduler identity and binary sha256** on every arm; ops name is a full
  identity string (`cake_1.2.0_x86_64_...`), so match it by **prefix**.
- Score-bearing rows need a **v5 receipt pair**; check `git_head` inside the built
  receipt — the repo-root shim **discards `SCX_REPO_ROOT`**, only `SCX_CAKE_SOURCE_ROOT`
  is honoured, and the wrong one silently builds the current commit under your label.
- **Scrub every `SCX_CAKE_*` env key** — mere presence makes exact-pair refuse.
- The broker emits JSON three ways: stdout/rc0, stdout/rc2, **stderr/rc2**.
- A missing-capability readiness failure means "rerun `artifact ensure`", never
  "benchmarking is blocked".

### Covariates, not gates

- **Noise is a third measurement.** Record `noise_class` and `external_cpu_avg_pct` on
  every arm and report them; never block on them. Use `ext_cpu_native_med` as the regime
  variable — the cake-side figure is endogenous (cake starves background work).
- **REGIME is the first covariate, ahead of noise.** `vkd3d_fence` wake p99 is **3.16 µs**
  quiet and **~50 µs** under 8-spinner load — 84×. A measurement on a calm machine
  measures the case with nothing to fix.
- **Only interleaved cake-vs-cake separates code from regime.** Cross-run comparisons have
  been confounded by native arms differing 4× from each other.
- Report the **mean** as well as percentiles for wake work — G21's affected wakes sit
  above p99, where p99 understated the win 4×.

---

## The ledger — one row per experiment

**Purpose: spot trends at a glance.** One row per experiment, so the arc, the verdicts,
and the cost read in one pass. Current state is above; the `§` registry below holds the
design rationale. `scx_cake_bench_assets` holds the raw runs.

**Rule for this file: every number is measured, and its EVIDENCE CLASS is named.** A blank
verdict means never measured — not "fine".

### Evidence classes, strongest first

| class | what it can conclude | what it cannot |
|---|---|---|
| **FRAME** | a gaming result (0.1% low, p99.9−median, severe-frame ratio) | — |
| **WAKE** | per-role wake-to-run latency on the real game | that frames moved |
| **CENSUS** | whether a decision fires, and how often | whether it helps |
| **STATIC** | insns, spills, divides — deterministic build attribution | any performance claim |
| **SIM** | load shape only. **Disqualified for latency** (2 µs vs the game's 265 µs) | tails, frames |

Rows outside these classes name their evidence directly: live smoke (attached through a
real session), live replica (loader logic run standalone on the live host), audit
(adversarial review), bench exact-pair (sealed benchmark pair).

### The ledger

| # | change | evidence | verdict | key numbers |
|---|---|---|---|---|
| G10.2/3 | route on burst CLASS, not the wakeup bit | STATIC | **unmeasured** | — |
| G10.4/5 | per-task slice; stages preempt-immune | STATIC | **unmeasured** | +230 insns |
| G10.6 | chain-gate the cadence dose | STATIC | **unmeasured** | 0 spills, 1450 insns |
| G11 s1 | frame clock, minimum selector | WAKE-ish | ❌ **null** | median 4828 µs vs true 5556, oscillating |
| G11 s1b | frame clock, **mode** selector | direct | ✅ | 5533–5580 µs = **0.05–0.4%** error |
| G11 s1c | incumbent hysteresis | direct | ✅ | locked **28 s of 30** |
| G11.1 | exact burst (kill `>>log2`) | STATIC | ✅ | banding ≤2× removed; **1530→1219 insns (−20%)** |
| G11.2 | collapse the PEER arm | CENSUS | ✅ | arm fired 0.19–2.94% |
| G11.3 | wake arm gets the per-task slice | STATIC | **unmeasured** | G10.4 covered only 3 of 6 insert sites |
| G11.4/5 | protection + slice cap → frame fractions | STATIC | **unmeasured** | 1.08× at 180 Hz; corrects 240 Hz |
| G12 | starvation predicate replaces burst class | SIM + CENSUS | ⚠️ **null on sim** | fires 1.48% game / 19.44% saturated (**13× span**) |
| **G13** | **cache-warm home claim** | **WAKE** | ✅ **KEPT** | same-CPU gap **8.9–16.7 → 0.9–4.5 pts**; wake p99 **cake 4/5** |
| G14 | preempt on the continuation arm | WAKE | ❌ **reverted** | renderer unchanged; locality **−2 to −4** on every role |
| G15 | that preempt's guard → waker's own cycle | WAKE | ❌ **reverted** | renderer 41.8→31.1 **but** fence + swapchain lost their wins |
| G16 | kick HOME when home is idle | WAKE | ❌ **reverted** | null — **proved** the kernel already rescheds an idle owner |
| **G17** | **anti-collision: never queue behind a served peer** | **WAKE, interleaved** | ✅ **KEPT** | renderer **−17.3%**, main −21.7%, queue −49.2%, fence −14.0% |
| **G18** | **slice cap takes the PESSIMISTIC frame estimate** | **WAKE, interleaved** | ⚖️ **kept; endpoint untestable** | wake p99 **−16%** 2/2; stalls >2ms **underpowered at n=2** (0–1 per arm) |
| — | **first FRAME read of the campaign** (G17 vs native) | **FRAME** | ⚖️ **tie on score, win on smoothness** | deadline miss **−53%**, FT stddev **−16%**, p99−med **−13%**; 0.1% low + p99.9−med **tied** |
| — | **max-stall decomposition** (retained traces, no capture) | **WAKE** | 🚨 **retracts a headline** | perf arms ring buffers per CPU, so G18's 4.78 ms "residual" was its own attach transient. By RATE cake is **3–5× better** than native, not worse |
| — | **five-domain sweep** (input/audio/net/IO/render, retained) | **WAKE, interleaved** | 🏆 **cake 4 of 7, 2/2 each** | win scales INVERSELY with burst: FAudio 5 us **5.0x**, input 6 us **4.5x**, renderer 40 us **2.2x**. RT audio untouchable, network+IO unmeasurable at this n |
| — | ~~harness is the floor (`python3` holds)~~ | — | ❌ **RETRACTED same day** | `python3` was the 8 SPINNERS (793% of a core, 174 CPU-s of 352). Comm inferred, never checked. `bench/cakeload.c` removes the ambiguity |
| — | **G14/G15/G16 rechecked on input** | **WAKE, cross-run ratio** | ⚪ **no resurrection** | G14 0.20 vs shipped 0.22, G16 0.39, **G15 0.64 — worst on input too, falsification confirmed** |
| — | **input-thread decomposition** (`Window & Input`, retained traces) | **WAKE, interleaved** | 🏆 **cake wins 2/2** | delays >200 us/10k: native 294.6/93.2 vs cake **39.0/47.8** — **4.5x**, no overlap. Never scored before |
| **G20** | **a kthread wake spends an idle CPU, not an occupant** | **WAKE + FRAME** | ❌ **null; mechanism UNTESTED** | wake >200 µs 10.7/12.3 vs G18 18.0/**9.5** — no separation. `DP-2` fired **45×** tonight vs 11,518 this afternoon on the SAME G18 code, so its premise was absent |
| — | **frame ABCCBA, native vs G18 vs G20** | **FRAME** | 🔻 **cake LOSES** | 0.1% low native **225.8** vs G18 212.8 / G20 213.9 — **2/2 no overlap, −5.6%**. Native also wins p99.9−med, deadline miss, stddev, max FT. Easy scene (native 1.00% miss vs 3.02% on 08-01) |
| **G21** | **interrupt-sink avoidance: do not home a latency thread on the GPU IRQ CPU** (§G21) | **WAKE, interleaved** | ✅ **KEPT** | `main` mean wake **−39.9%**, renderer **−25.3%**, 2/2 live HD2; charged migrations +9.7%, `select_cpu` +29 insns |
| G23 | per-line sink detection + `select_cpu_and(nonsink)` (§G23) | CENSUS + STATIC + smoke | **endpoint PENDING** | flags {5,13} where G21's rule saw only 13; receipts `docs/REVIEW_G21_G23_2026-08-02.md` |
| G24 | expense-vs-benefit census (§G24) | CENSUS | ✅ **complete** | pinned-wake preempt **0/0** (fifth zero), sibling kick **0/0**, SLEEPER_LAG passes **98.6%**, steal ring walks **93-98%** for **~1%** hit; `CENSUS_G24_2026-08-02.md` (git history) |
| **G25** | steal-ring queue hint becomes a u64 bitmask (§G25) | STATIC | **LANDED; endpoint unmeasured** | **41 insns, 0 spills**; priced quiet **2.89 → 0.27 ns**, fast **355.33 → 41.07 ns** (the fast row does not transfer); predicted 0.04% of a core quiet to 4.7% contended — a null confirms the pricing |
| G25.1 | §R.10 128 B inter-CPU stride surrendered by the bitmask walk | — | **unmeasured** | contended re-pricing needs the 15-reload arm |
| G26 | frame-laxity input from a Vulkan layer (§G26) | — | **registered** | — |
| **G27** | frame-anchored geometry + §G27.1 vote gate and fastest-real-cadence picker | live smoke | **BUILT + LIVE-SMOKED; endpoint unmeasured** | attached through a real game session, zero stalls, clock tracked **26 Hz–1950 Hz**; endpoint = sealed A/A, then HD2 easy-scene ABBA |
| G28 | pre-paid idle exit (construct B; §G28) | — | **registered** | — |
| G29 | class bits ride the vtime word (construct C; §G29) | — | **registered** | — |
| **G30** | live sink re-probe + sink veto on the waker-anchored returns (§G30) | **WAKE** (live WoW) | ✅ **wake-tier endpoint MET; frames unmeasured** | fence p99 **31.45 → 1.25 µs**, slow wakes **478 → 6**, CPU 13 landings **~1050 → 2** of 50.8k; mean unchanged (p50 0.32 → 0.34 µs) |
| G31 | frame clock latches on vote silence (§G31) | — | **registered** | — |
| G32 | per-task estimators have infinite memory (§G32) | — | **registered** | — |
| **G33** | sink-ness is IRQ time share, not interrupt count (§G33) | live replica | **BUILT + attach-tested; wake A/B unmeasured** | handler time CPU 13 **2.46%**, CPU 5 **2.05%**, **~0.1%** elsewhere; 9 s replica converged [5, 13], mouse CPU 7 never flagged, zero flap; both static Hz constants DELETED |
| G34 | PSI as a scheduler input (§G34) | audit | ❌ **PSI falsified; harvest H1-H6 registered** | all 12 PSI theories killed or fatally weakened; H3 delivered by §G35 Phase D; `docs/SIGNALS_AUDIT_2026-08-17.md` |
| **G35** | live in-handler bit from 4 IRQ tracepoints (§G35) | WAKE (desktop smoke) | **Phases A-D BUILT; WoW endpoint unmeasured** | movable hot-landings **0.80 → 0.66 → 0.23 → 0.17%**, hot max **135 → 15.8 → 8.8 µs**, cpu0 timer hits **820 → 4**; desktop smokes are attribution, not verdicts |
| G36 | tick look-ahead: skip a CPU whose timer fires within the hop horizon (§G36) | STATIC | **BUILT; unmeasured** | `cake_cpu_tick_soon` **28 insns, 0 spills**; enqueue spills 2/4, TOTAL 17/11/28; desktop smoke expects timer-race hits → ~0 |
| R.24 | cross-multiplied divide elimination in `cake_frame_observe` + handoff-yields (§R.24) | bench exact-pair | ✅ **kept** | both exact-pairs pass |
| R.27 | shaped compat ladders for ≤ 6.18 kernels (§R.27) | STATIC + CI | ✅ **CI veristat green ×6** (6.13/6.16/6.18/rolling/for-next/bpf-next, run 32206840388, 2026-08-18) | spills 28 → 26, hot frames flat (`select_cpu` 5, `enqueue` 6); +141 insns of dead arms, pruned at load; dev-kernel bench screen still owed |
| **R.28** | per-task slice cap, fixed patience windows, frame clock demoted to diagnostic (§R.28) | bench dose + n=3 ABBA | ✅ **clock mode mechanism REMOVED; tail gap partially remains; game screen owed** | quiet handoff p99 rests 0.86–0.92 (was 0.85–1.9 drifting); divides 11→5, spills 17/11→16/10; p999 2× + schbench-light +72% vs 1.1.3 persist → IRQ-reactive stack (§G33/§G35/§G36) is the standing suspect |
| — | spread placement, co-location returns off (§R.1 fps A/B) | FRAME | **reverted byte-identical (7826cfe3a; hashes now in backup/nightly-12-commits-20260818)** | fps INCONCLUSIVE: scene drift **~7%/h** (nvidia **5044 → 4695/s**) dominated every arm; placement stayed concentrated on ~7 CPUs with all three co-location returns off |

### The frame result (2026-08-01, the campaign's first)

ABBA, 2 runs/arm, HD2 menu, GPU-bound 97%, 240 Hz VRR, unattended.

```
240 Hz deadline miss %   native 3.019  |  G17 1.419   -53%   G17 2/2
FT stddev ms             native 0.258  |  G17 0.217   -16%   G17 2/2
p99 - median ms          native 0.711  |  G17 0.619   -13%   G17 2/2
0.1% low                 native 193.3  |  G17 188.6          overlap  <- SCORED metric
p99.9 - median ms        native 1.085  |  G17 1.088          overlap  <- SCORED metric
spikes >2x median %      native 0.004  |  G17 0.008          overlap  <- SCREEN metric
```

**Tie on the three metrics GAME-FIRST actually names; clear win on consistency and
deadline adherence.** Caveats that must travel with it: menu scene not gameplay,
GPU-bound so avg FPS cannot separate, n=2, and NOT comparable to the 2026-07-30
war-table numbers.

### Trends

**Renderer wake p99 (cake, real game under load).** Only the interleaved pair is valid;
cross-run rows are shown for completeness and must not be compared to each other.

```
G13  49.8us  ████████████████████   <- interleaved, same run
G17  41.2us  ████████████████       <- interleaved, same run   -17.3%
native 6-9us ███
```

**Object size and safety** — zero spills and zero fills in every function, every commit:

```
G10.6  1450 insns
G11.1  1219   (-20%, exact arithmetic is SMALLER)
G13    1359
G17    1433
```

**Magic-number removal:** 14 flagged → **4 deleted** (`PEER_WAKE_HYSTERESIS_NS`,
`cake_preempt_protect_ns`, `COMPUTE_OCCUPANT_MIN_RAN_NS`, `cake_chain_burst_ns`),
10 remain, ~6 added in legitimate form (dimensionless ratios of a measured frame).
Constant history: git log -- CONSTANTS_AUDIT.md (file retired 2026-08-18).

Campaign-level laws: §G-campaign (registry below).

---

## The `§` registry — hypothesis graph

**The working registry of design rationale — every `§` comment in the source resolves
to a heading here.**

> [!NOTE]
> Compressed 2026-08-12 from 20,608 words; narratives in `git log -p HYPOTHESES.md` and
> `~/.claude/projects/-home-ritz-Documents-Repo-scx/doc-archive-2026-08-12/`. All-FALSIFIED
> parents ⇒ don't build. **Rq** quiet, **Rc** contended.

| block | scope |
|---|---|
| [§G1–§G6](#g1-wake-service-under-load-trunk) | trunk graphs — wake service (N), cache trade (M), ordering (S), game-tail bound (B), spill proxy (P), harness meta (H) |
| [Graph cut](#graph-cut-open-by-prune-value) | the OPEN queue, ranked by prune value |
| [§G7–§G25](#g7--mutex-handoff-p99) | measured campaigns, one entry each — verdicts with numbers; the §G12 KEYSTONE lives here |
| [§G26–§G36](#g26--frame-laxity-input-registered) | registered constructs and live builds — bold status line per entry |
| [§R.1–§R.26](#r--design-rationale-from-source-comments) | design rationale from source comments, incl. the two maintainer rulings (§R.25, §R.26) |
| [§S.1–§S.7](#s--constant-ledger-from-intfh) | constant ledger from `intf.h` |
| [Open review findings](#open-review-findings--review_independent_2026-08-17md) | verified against source, not yet fixed |

---

### §G1. Wake service under load (trunk)

- **N1 CONFIRMED(Rq)** — "wakeups global, continuations local": +57 futex.
- **N2 CONFIRMED** — the sleeper clamp quantizes vtime, erasing deservingness.
- **N3 CONFIRMED(Rq)** — stranded tail wake ≡ storm head; 7 falsifications, Rq only.
- **N4 OPEN (top target)** `<- N1` — under Rc wake-global decays to slice cadence, futex 2.05M→0.35M. OPEN: N4a bounded service, N4b slice waiting, N4c WAKE_DSQ order, N4d audio chain.
- **N5 CONFIRMED** — pinned tasks bypass the wake path; raw-depth preempt: lock-pi −86.6→−71.8.
- **N6 FALSIFIED** — casual `ops.quiescent` costs futex −84%. Re-opens on another hook.
- **N7 OPEN (kernel lane)** — a waker-intent signal escapes N3; needs a kernel patch.

### §G2. Cache/memcpy share trade

- **M1 CONFIRMED** — zero-sum share reallocation, equal efficiency.
- **M2 CONFIRMED** — unlike-type SMT pairing: memcpy **+73%**.
- **M3 FALSIFIED** — stochastic drift; wake remixing defeats it.
- **M4 FALSIFIED** — class marks + veto collide with futex homing (−28 pt).
- **M5 OPEN** `<- M2` — a per-TASK duty class surviving N6.
- **M6 OPEN (kernel lane)** — PMU kfunc for memory-boundness `<- M5`.

### §G4. Ordering structure

- **S0 CONFIRMED** — not tree-free; the difference is SHAPE, so the key is the lever.
- **S1 CONFIRMED(Rq)** — cadence-proportional sleeper depth, futex 1.4M→3.3M (§R.13).
- **S2 OPEN (speculative)** `<- S1` — a 64-DSQ bucket ring at slice/32.
- **S3 OPEN** — futex host MODES: one binary reads 4.7M / 1.4M, cause UNKNOWN.

### §G5. The missing bound (game-tail trunk)

- **B0 CONFIRMED** — a queueing shape: ~4-5 isolated stalls/45 s, 1% low −15.2%.
- **B1 OPEN (trunk)** `<- B0` — no bound on wake→run; EEVDF bounds it three ways.
- **B2 OPEN** — a home-routed wake onto a busy CPU with no idle gets **no kick**; ~0 kills it.
- **B3 OPEN** — vtime seals, but the frontier advances only in `cake_running`; wall-rate tracking kills it.
- **B4 OPEN** — no `.tick`, a multiplier on B2/B3.
- **B5 OPEN** — 1.1.3 is neither fix nor control; attaches again on 7.1.8 (2026-08-19), so it is usable as a third arm.
- **B6 OPEN** — lost zero-spill discipline cannot explain 10-40 ms stalls.

### §G6. The spill law as a proxy

- **P1 FALSIFIED** — "any value across a call spills": `cake_enqueue_wake` keeps `p` in r6 across nine.
- **P2 CONFIRMED** — LLVM evicts a live PARAMETER to hold a compile-time CONSTANT.
- **P3 CONFIRMED** — a decision spills iff it consults the KERNEL mid-flight.
- **P3a FALSIFIED** — the cadence home claim over-claims by construction, futex **−13.29%**. Re-opens only on a censused FIRING RATE.
- **P3b FALSIFIED** — `qmark` is sticky, not `nr_queued != 0`; ~−11 pt.
- **P3c CONFIRMED** — the `enq_flags` literal is free here.
- **P4 OPEN** — the census hides JIT push/pops; check the jited dump.

### §G3. Harness/evidence (meta)

- **H1/H2/H3 CONFIRMED** — aggregates cannot localize, arms need covariates, guards are regime-relative.
- **H4 OPEN** — replay simulator unbuilt.
- **H5 ADOPTED** — the formula is CONDITIONED on regime + workload; the pre-07-24 ledger is void.
- **H6 CONFIRMED** — load predicts cake's delta, rho **−0.42**, n=125; mutex-handoff improves under load, so a global gear is wrong.

---

### Graph cut: OPEN, by prune value

Ordering provisional 2026-08-18 — prune-value ranking is the maintainer's call.

| # | experiment | scores / prunes |
|---|---|---|
| 0 | **§G33 wake A/B** | vs `wow-cake-g30c` (attach-test passed 2026-08-17); scores the IRQ-time-share classifier: fence tail ≤ g30c, placements on CPU 7 resume |
| 1 | **§G35 WoW capture** | `--irq --match 'WoW\|vkd3d'` scores the whole G35 stack (Phase D live; desktop staircase done) |
| 2 | **§G36 relaunch + desktop smoke** | timer-race hits expected → ~0 |
| 3 | **§G30 Phase C** | MangoHud frame screen; also answers the 600 fps co-location question |
| 4 | **B2/B3 discriminators** | two read-only counters, one run; either ~0 prunes B1 |
| 5 | **§G27 endpoint** | easy-scene ABBA on the BUILT geometry; a null prunes "geometry mis-scale" from its mechanism space |
| 6 | **§G26 phases A/B** | a NEW INPUT; prunes that subtree |

*(Then §G28/§G29/§G31 phase As, §G34 H1/H2/H4/H5, §G23 P2-P4, the N4 ladder, §G9.7.)*

---

### §G7 — mutex-handoff p99

**G7.0 CONFIRMED** architectural: native 1.0-1.14 µs vs cake 1.7. **G7.1 STALE** — never
cite the sealed +10.3% row. **G7.2 FALSIFIED**: the split-redirect made mutex *and* pipe
worse. **G7.3 OPEN** — the cut left is structural.

### §G8 — tiered admission

Tier-1 `LOCAL_ON` the waker's CPU: **FALSIFIED AS BUILT, mechanism VINDICATED.** p99 unmoved
at 1.750, pipe +23.14%→**+8.98%** — it never fired, since `futex_wake()` sets no `WF_SYNC`.
The p99 is placement-invariant.

### §G9 — the second mode; co-location asymmetry

- **G9.0 CONFIRMED** — p99 is a SECOND MODE at 1.5-1.6 µs (mass >1.4 µs: 1.53% vs 0.56%).
- **G9.1 CONFIRMED** — co-located cake p99 **760 ns** vs native 1731; the mode IS the split fraction.
- **G9.2 FALSIFIED** — per-CPU emptiness trigger: **futex −99.4%**; fewer threads than CPUs ⇒ empty.
- **G9.4 KEPT then GAME-FAILED** — learned handoff bit; mutex +9.01%, schbench-light −9.40%, HD2 0.1% low **104.15** vs 141.84. Per-CPU, not per-task.
- **G9.5 FALSIFIED** — not one slice; residue **0.71–2.80 ms**.
- **G9.6 KEPT** — liveness term: mutex **+6.29%**, schbench-light **−2.66%**.
- **G9.8 SPECULATIVE** — pass chain depth on as `max(own, waker)`.
- **Floor** — **~606 ns** to sleep; sub-500 ns p99 is unreachable.

#### §G9.3 FALSIFIED — the ≥3/4-idle gate
schbench-light p99 **+10.8%, 4/4**. Seriality is temporal, not load.

#### §G9.7 REGISTERED, pending
Gate on "within a handoff of its OWN burst's end"; endpoint HD2 0.1% low toward **148.8**.

### §G10 — GAMES-ONLY CAKE

Games first, benchmarks second; a bench regression is not a kill.

#### §G10.2 — the burst class
chain 208–415 µs, workers 37–60 µs.

#### §G10.3 — chain priority by routing
Fixes a worker-favouring inversion.

#### §G10.4 — slice as preemption timer
`clamp(2×burst, chain_burst, SLICE_NS)`.

**§G10.4 LIVE DEFECT (found by the 2026-07-30 constant audit) CLOSED — resolved by
§G27.** The audit found flat `SLICE_NS` grants on three of six insert sites (`:603`
co-location, `:823` the main wake arm, `:885` kthread) against the documented
`clamp(2 × burst, chain_burst, SLICE_NS)`. As of 2026-08-18 one flat grant remains,
the kthread wake path (`cake.bpf.c:1177`), and it is deliberate — a kthread has no
meaningful burst. Every other geometry site shifts from `cake_frame_slice_ns` (§G27).

#### §G10.5 — stages are preempt-immune

#### §G10.6 — the direct-path inversion
The gate is CLIFFED, so repair monotonically.

### §G11 — frame clock and burst estimator

The clock takes a MODE, not a minimum — a vote, not a dictator; bucket `period >> 17`,
argmax in the loader (§R.22).

#### §G11.1 CONFIRMED — the estimator banded
`sum_exec >> log2(nvcsw)` skewed four decisions; an exact divide shrank it, **1530 → 1219
insns**.

#### §G11.2 — the dead-mechanism sweep
DELETED the PEER arm (2.94% / 0.19%). KEPT `WAKE_STARVE_WALL_NS` (**0.0013% of a core** —
cost by RATE) and the pinned margin (0 fires may be 0 tries).

#### §G11.4 / §G11.5 — denominated in a FRAME
Occupant protection and the slice cap; at 240 Hz the flat 3 ms cap was ¾ of one.

### §G12 — the starvation predicate

`cake_chain_burst_ns` measured the wrong AXIS; now
`run_delay × nvcsw > sum_exec_runtime × pcount`. Census **1.48% game / 19.44% saturated**.

#### THE KEYSTONE (2026-07-31) — a constant-free starvation signal the kernel already keeps

> [!IMPORTANT]
> **Maintainer direction: eliminate ALL magic numbers. A value tuned to this machine does
> not work on anyone else's.**

The live HD2 capture supplies the replacement. Measure a thread's wake latency **as a
fraction of its own wake period** — dimensionless, per-task, no global clock, no tuned
magnitude. Real data, `hd2-native-20260731`, 30 s, native:

| thread | own period | p99 wait | **missed cycles** |
|---|---|---|---|
| cuda-EvtHandlr | 47.8 µs | 272.79 µs | **5.71×** |
| ad pool !LP worker | 24.3 µs | 128.23 µs | **5.27×** |
| vkd3d_fence | 54.8 µs | 265.62 µs | **4.85×** |
| main | 78.8 µs | 250.09 µs | **3.17×** |
| vkd3d-swapchain | 96.0 µs | 277.95 µs | **2.90×** |
| thread pool worker | 26.5 µs | 14.78 µs | 0.56× |
| vkd3d_queue | 31.3 µs | 2.64 µs | 0.08× |
| renderer | 482.1 µs | 6.13 µs | **0.01×** |
| ModulePrefetch | 305.3 µs | 3.77 µs | 0.01× |

**570× separation, with a clean 5× gap between 0.56 and 2.90.** The threshold is
**1.0** — *a task that waits longer than its own cycle has missed one* — which is a
definition, not a tuning.

**And cake can compute it with ZERO new storage, no map, no per-wake bookkeeping.** The
kernel already maintains both terms in `task_struct`:

```
run_delay  = p->sched_info.run_delay   /* ns runnable-but-not-running, lifetime */
pcount     = p->sched_info.pcount      /* times scheduled in */
mean_wait  = run_delay / pcount
own_period = (now - p->start_time) / nvcsw        /* cake_burst_ns's twin */
starved    ⟺ run_delay * nvcsw > pcount * (now - p->start_time)   /* no divide */
```

**PORTABILITY VERIFIED, and the obvious trap avoided.** `sched_info` is gated by
`CONFIG_SCHED_INFO`, **not** by `CONFIG_SCHEDSTATS` and **not** by the
`kernel.sched_schedstats` sysctl. On this host that sysctl reads **0** and `run_delay`
still advances — proven with three spinners pinned to one CPU: exec +622 ms each,
run_delay +1377 ms each, exactly the 2/3 wait a 3-on-1 contention implies. `PSI`,
`TASKSTATS` and `SCHEDSTATS` all select `SCHED_INFO`, so it is present on essentially
every distro kernel. Guard the read with `bpf_core_field_exists()` regardless, and
degrade to "never starved" if absent.

*A first attempt at this test read zero on an idle `renderer` thread and looked like a
falsification — but its `sum_exec_runtime` was also flat, i.e. the thread simply never
ran. Recorded because the false negative is easy to repeat.*

#### WHAT THE KEYSTONE ELIMINATES

| constant | disposition |
|---|---|
| `cake_chain_burst_ns` (93.7 µs) | **DELETE** — chain membership becomes "is this thread being starved relative to its own cycle", not "is its burst above a magnitude". The capture proved the burst axis is wrong: the whole render chain reads 1.4–64.5 µs and classifies as *worker*. |
| the frame clock, its 2–40 ms band, `FRAME_BUCKET_*` | **LOAD-BEARING** — built as the §G27 engine-cadence clock; 8 geometry sites shift from `cake_frame_slice_ns` (corrected 2026-08-18 from "LIKELY DELETE") |
| `FRAME_*_PROTECT_SHIFT`, `FRAME_SLICE_CAP_SHIFT` | **RE-BASE** onto the occupant's own period instead of a global frame; they stay dimensionless ratios |
| `WAKE_STARVE_WALL_NS` (24 ms) | N of the waiter's own periods |
| `HOME_PREEMPT_YOUNG_NS` | `cake_handoff_yields`' shape — "within one handoff of the end of its own burst" — already in tree |
| `cake_handoff_max_ns` (1464) | let the boot probe drive it (625 ns measured, cross-validates the 606 ns floor) |
| `CAKE_NEIGHBOUR_PROBE_DEPTH` (3) | order by `cpu_sibling` topology, already in rodata |
| `STATE_SLOT_BYTES` (128) | probe the cache line size from sysfs at boot |
| `SLICE_NS` + `SLEEPER_LAG_NS` / `HOME_PREEMPT_BASE_MARGIN_NS` / `DEEP_WAKE_HYSTERESIS_NS` | the vtime-unit family — its own architectural experiment |
| `HOME_PREEMPT_RAN_CREDIT_SHIFT` (1) | **KEEP** — a dimensionless ratio, not a magnitude |

### §G13 — the cache-warm home claim

Claim an idle `prev_cpu` **before** dfl, which reserves what it returns. Same-CPU gap
**8.9–16.7 pts → 0.9–4.5**.

### §G14 / §G15 / §G16 — FALSIFIED, need new evidence

G14's continuation preempt never reached the renderer; G15's waker-cycle guard cost
`vkd3d_fence` its win; G16 (kick HOME when idle) was **null**, since the kernel already
rescheds an idle owner. Kept: "too young" rejects **57.4%** of preempts.

### §G17 — anti-collision

Never queue behind an equally served peer — route those global. Wake p99 renderer
**−17.3%**, but the **mechanism endpoint FAILED**: blocked-by-peer 58.1% → 56.9%.

### §G18 / §G19 — pessimistic frame estimate

Slice cap kept; wake p99 **−16%, 2/2**, endpoint untestable at n=2. G18's 4.78 ms
"residual" was RETRACTED as an attach transient (§R.23).

### §G20 — kthread wakes spend idle CPUs

Cake preempted the renderer **22,800**/22 s vs native 11,383, mostly for `DP-2`. **NULL on
the frame endpoint**, but `DP-2` fired 45× that night: UNTESTED, not disproved.

### §G21 — CONFIRMED 2/2: the GPU IRQ owns a CPU

IRQ 115 fired **1,266,319,129** times on CPU 13, zero elsewhere. Declining to home there:
`main` mean wake **−39.9%**, renderer −25.3%, wakes served +1.5%. **Score on the MEAN; p99
understates it 4×.** An **idle-depth theory was FALSIFIED** — that only tracked IRQ
residency.

The **SMT sibling of a sink is itself degraded at 1.30×** — G21.1, untested.

### §G22 — twenty-investigation game-perf campaign (2026-08-02)

Full board: `CAMPAIGN_G22_INVESTIGATIONS.md` (git history).

### §G23 — every sink, not the loudest (pending)

`<- G21 + G22`. Per-**line** detection (≥1 kHz, ≥95% affinity) finds every sink, where
G21's fair-share test flags only the loudest. **P1 CONFIRMED at smoke**; P2-P4 await the
ABBA.

### §G24 — expense-vs-benefit census (COMPLETE)

`CENSUS_G24_2026-08-02.md` (git history). Pinned-wake preempt **0/0** at a fifth dataset; sibling
kick **0/0**; `SLEEPER_LAG` passes 98.6%, not a predicate; the steal ring walks **93-98%**
of dispatches for a **~1%** hit → §G25.

### §G-campaign — laws the G10-G24 arc established

1. **Regime is the first covariate.** `vkd3d_fence` wake p99: **3.16 µs** quiet, ~50 µs
   loaded, **265 µs** heavily contended — **84×**. A calm-machine game measurement has
   nothing to fix.
2. **`ops.enqueue` sees 0.14% of a game's dispatches** (23.6% saturated). Nearly all of
   cake's routing is inert on a game.
3. **The vtime clamp is decoration on a game** — the target queue already held work
   **163 times in ~7M** direct dispatches (1 in 42,935).
4. **Cake's wake path is not slower than native** — renderer p50 matches to two decimals.
   Only ~4% of wakes go bad.
5. **Cake fixed worker interference and created peer interference**: workers block the
   renderer 8.6% (native 42.5%), peers 58.1% (native 18.9%).
6. ~~**~30% of slow wakes on BOTH schedulers land on an idle CPU** — C-state exit, ~24–93 µs,
   which no placement policy fixes.~~ **FALSIFIED 2026-08-02 by G21.** This host binds **no
   cpuidle driver** (`current_driver = none`), so there is no governor-managed C-state to
   exit, and a within-CPU control puts 15 of 16 CPUs at a 1.0–1.6× ratio. The effect was
   **one CPU** — the GPU interrupt sink — and **a placement policy did fix it**: G21 cut
   `main`'s mean wake −39.9%. "Which no placement policy fixes" was a closed door that was
   never tested.

### §G25 — the steal ring's fifteen probes

`<- G24`. The miss walk probes up to **15 distinct 128 B lines each dirtied by a different
CPU**; one u64 bitmap answers from one. Priced 6 rounds AB/BA: quiet **2.89 → 0.27 ns**,
fast **355.33 → 41.07 ns**, but **the fast row does not transfer** — the shipped walk
reloads the word up to `nr-1` times. `edafb27e5` ships a bit walk, **41 insns / 0 spills**.
**Predicted 0.04% of a core quiet to 4.7% contended, so a null confirms the pricing.**
Open: the §R.10 stride is surrendered, and `fnspills.py` is blind on llvm-objdump 22.

---

### §G26 — frame-laxity input (registered)

**Status: registered; phases A/B are graph-cut item 6.**

The first NEW INPUT: `present_deadline − now − remaining_cpu_work` from a Vulkan layer,
banded as an EDZL override at `cake_wake_preempt`. Phases A observe, B census, C negative
gate, D override. Kills: A/A overhead, or census ≈ 0 in ≥2 modes.

### §G27 — frame-anchored geometry (construct A; registered + BUILT 2026-08-17)

**Status: BUILT 2026-08-17 (§G27.1 picker, 3 live iterations); endpoint pending — HD2
easy-scene ABBA.**

- Hypothesis: the easy-scene 0.1%-low loss comes from patience windows fixed at the 3 ms
  slice while the engine runs faster; anchoring geometry to measured cadence closes ≥ half
  of the −5.6%.
- Built: vote band 25→**2000 Hz** — the clock measures ENGINE cadence, not display
  (uncapped engines hit ~1300 fps; vsync/VRR pin cadence at or near the panel; maintainer
  input 2026-08-17). Floor bootstrap decoupled at 2 ms (`FRAME_FLOOR_BOOT_NS`), else
  vote-free hosts inherit a 250 µs slice cap. `cake_frame_slice_ns = min(¾ × floor,
  SLICE_NS)` published per poll; 8 geometry sites now shift from it. Vote-free regimes
  keep today's geometry EXACTLY (bootstrap = SLICE_NS), so the sealed A/A is null by
  construction. Theory: `docs/THEORY_CONSTRUCTS_ABC_2026-08-17.md`.
- Endpoint: HD2 easy-scene ABBA — screen severe-frame ratio, score 0.1% low.
- Aborts: G17 menu metrics regress at screen; sealed A/A moves (= vote pollution — then
  gate votes on `burst < period/2` before proceeding); clock flaps under vsync toggles.

#### §G27.1 — vote gate + binding-cadence picker (BUILT 2026-08-17, 3 live iterations)
First live contact showed 26 Hz loader crowds winning the argmax mid-game and the
winner flapping game↔desktop every poll; iteration b showed counts swing past 2× both
ways (top-two tie detection rarely fires); iteration c showed one app's own threads
form several fast crowds that hop across any qualify bar, plus one-poll slow blips.
Final shape (maintainer design "promote both", taken fully — the argmax is GONE):
- **Vote gate (BPF):** only a thread that sleeps more than half its life votes.
  `burst < period/2` has nvcsw on both sides, so it reduces to
  `2 × sum_exec >= lifetime ⇒ no vote` — one shift, zero divides, budget stays 11.
- **Picker (loader):** every crowd within 2× of the biggest is a REAL cadence
  (QUALIFY=2); the FASTEST real one is published — every clock consumer is a bound,
  and the fastest cadence binds. An incumbent at least that fast holds while it keeps
  ≥¼ of the biggest crowd's votes (FADE=4).
- **Fast up, slow down:** a faster cadence binds instantly; a slower one must win 3
  consecutive polls (SLOW_POLLS=3), so a one-poll silence cannot publish a slow blip.
Commits `a717e4055` → `c6e97bf47` → `f4bcd88a9`. Endpoint unchanged (§G27).

### §G28 — pre-paid idle exit (construct B; registered; "no timers" absence AMENDED by maintainer 2026-08-17)

**Status: registered.**

- Hypothesis: kicking the predicted wake CPU ~50 µs before the predicted frame wake pays
  the C-state exit early; render/input MEAN wake drops below the idle-exit floor both
  schedulers share (the 28–32% swapper-occupant slow wakes).
- Shape: value concentrates at LOW fps (long gaps reach deep C-states) — timer arms only
  at frame ≥ 2 ms; at 1300 fps it stays off. Cost bound one kick/frame, ~0.04% of a core.
- Phases: A timer + counter, NO kick, A/A overhead screen. B kick, wake-latency capture
  on render roles vs the G21 numbers.
- Aborts: A/A overhead visible in severe-frame ratio; power artifacts in `noise_class`.

### §G29 — class bits ride the vtime word (construct C; registered) `<- M5, M2`

**Status: registered.**

- Hypothesis: a 2-bit duty class in `dsq_vtime`'s low bits (≤ 4 ns, ~4500× under the
  smallest geometry quantity) is M5's per-TASK class with ZERO per-task storage;
  unlike-type SMT pairing (M2: +73%) recovers ccm-memcpy ≥ 5 pts without M4's collision.
- Class source: achieved runtime rate with sibling busy vs idle — two clocks cake already
  stamps. Restamp after stopping's `+=` (addition destroys low bits).
- Phases: A encode + restamp, no consumer — sealed A/A + fnspills. B consumer in
  select_cpu placement only.
- Aborts: any A/A futex drift (+57.2% is mode-conditional); encode adds hot-path spills.

### §G30 — the sink set is a one-shot sample of a time-varying signal (registered 2026-08-17)

**Status: wake-tier endpoint MET (fence p99 31.45 → 1.25 µs); frames unmeasured (Phase C
MangoHud pending); parked-scene fps gap unreproduced.**

- Finding (WoW live, single-arm cake, 22 s capture `wow-cake-g27tip`): the only systematic
  wake tail is vkd3d_fence p99 31 µs / max 255 µs — 478/42k wakes > 20 µs, 99% of them
  targeting CPU 13 with swapper as occupant. CPU 13 hosts the nvidia IRQ (100% pinned,
  3.3–3.9 k/s in-world). cpuidle driver is `none` on this host, so the delay is ISR
  shadow, not C-state exit: the wake is issued from the nvidia ISR on 13, targets 13, and
  the switch waits out the rest of the handler. Fence wakes that ran elsewhere price the
  alternative: p50 2 µs, max 11 µs — off-sink placement caps the tail 23×.
- Diagnosis by elimination: serial-handoff fires ≤ 0.03% in games, the §G13 fast path and
  the ranked pick both honour `cpu_irq_hot`, and the compat kfunc is live on 7.1.8 (args
  struct present in BTF) — so CPU 13 is NOT in this instance's sink set. cake attached
  19:36:10; WoW.exe up since 19:29:32; the 120 ms probe sampled a sub-kHz moment (menu
  frame cap). §G21's first frame win never engages when cake attaches before the game
  renders — which is the daily-driver order.
- Hypothesis: re-probing sinks while the GPU is loaded flags CPU 13, moves fence off it,
  and collapses the tail to the migrated population (p99 31 → ~3 µs, max 255 → ~11 µs) at
  a ~+1.7 µs median cost.
- Phases: A restart-cake live falsification, ZERO code — fresh attach mid-play, 22 s
  recapture, compare the fence tail and mean. B structural, §R.25 shape: the loader
  re-probes on a cadence — fast until the sink set repeats, then slower; any change
  corrects the mask immediately and resets the cadence to fast (no event source exists
  for IRQ rates — lawful timer). `cpu_irq_hot` rodata → .data, mask rebuild off the hot
  path. C endpoint: game frame screen.
- **Phase B BUILT 2026-08-17.** SinkMonitor rides the existing 1 s run loop sharing the
  probe's exact per-line criteria (factored to `sinks_from_deltas`): flag the sample a
  sink qualifies, unflag after 3 consecutive quiet samples (a loading screen must not
  flap the mask), interval doubles per 8 unchanged samples up to 16 s and any change
  resets it. BPF: `cpu_irq_hot`+`cake_sink_gen` moved to bss; `cake_nonsink_rebuild`
  (0 spills, 57 insns) shared by ops.init and a one-compare gen check in the ranked
  pick; select_cpu 4/1 spills unchanged, +9 insns. Gates: both profiles clean, comment
  ratio 0.69, clippy blocked by pre-existing `scx_utils` `derived_hash_with_manual_eq`
  errors (clippy 1.97, not cake). Attach-test pending = the next maintainer relaunch.
- **Phase B attach-tested live 2026-08-17 (`wow-cake-g30b`) — masked paths FIXED, one
  leak found.** The live update works: zero fence wakes emitted off-CPU-13 target 13 any
  more (ranked pick + §G13 fast path honour the republished flags; CPU 2's share even
  recovered mid-capture when the monitor unflagged a stale seed sink). The residual 1059
  fence→13 wakes are 100%-correlated with wakes EMITTED on CPU 13: the serial-handoff
  co-location block returns the waker's CPU with no sink check, and an ISR-origin wake
  mimics the handoff shape (wake-then-block) so the learner saturates on the artifact —
  self-sustaining, since each placement re-teaches the slot. FIX: `!cake_cpu_irq_hot()`
  veto in the serial block AND the frontier-convergence waker return (both waker-anchored,
  both sink-blind; +13 insns select_cpu, spills unchanged). Known residual, accepted: the
  ROUTE_GLOBAL idle-kick (`cake_wake_notify`) can kick a sink under saturation — enqueue
  serves 0.142% of game dispatches and any CPU beats queueing there.
- **Wake-tier endpoint MET 2026-08-17 (`wow-cake-g30c`, third live attach): fence p99
  31.45 → 1.25 µs, slow wakes 478 → 6 (none on CPU 13), CPU 13 landings ~1050 → 2 of
  50.8k.** Mean unchanged (p50 0.32 → 0.34 µs) — the feared off-sink median penalty did
  not materialize. Frames remain unmeasured (Phase C: MangoHud screen).
- **Parked-scene A/B vs EEVDF 2026-08-17 (WoW housing, ~600 fps regime) — fps gap did
  NOT reproduce; my accretion diagnosis was WRONG and is retracted.** Six 22 s slots
  (cake/EEVDF/EEVDF/cake×3 across attaches): nvidia IRQ rate (frame-delivery proxy)
  identical everywhere — 5044/5023/5045/4982/5053/4964 per second (±1%). The
  maintainer-observed 616→580 mean fps did not appear under controlled same-scene
  conditions; scoring it properly still needs MangoHud.
  What DID differ: cake concentrates placement on ~6-7 CPUs at ~45% busy while ~10 sit
  at 0% (EEVDF spreads), with game-thread run_delay 12→350 ms/s varying BY ATTACH
  (learned run-slot/handoff state, §R.1 co-location working as designed — the
  3-5 µs/slice queue-behind-partner trade). I first misread the concentration as
  sink-set accretion (9 CPUs flagged); refuted by per-CPU busy% (the unused CPUs are
  idle-by-choice, not masked) and by recurrence after the bound. The minority bound on
  SinkMonitor flag-up built during that misdiagnosis is retained as a legitimate safety
  invariant (the union of wandering cuts genuinely had no bound), relabeled as such.
  OPEN QUESTION registered: is co-location's queue-behind-partner trade still right in
  a 600 fps regime where waits/slice (~3-5 µs) approach frame slack? Needs a frame
  screen, not wake data, to answer.
- **Spread probe ran same night (commits `76dcd3499` probe / `92f42cce1` revert,
  byte-identical restore verified): fps verdict INCONCLUSIVE.** Ten slots spanning
  ~1 h showed a monotone scene drift (~7%/h, nvidia 5044 → 4695/s) that dominates
  every arm difference — the closing packed slot broke the pack-vs-spread ordering
  and voided the comparison (rotation working as designed). SOLID findings that
  survive the drift: (1) placement stays concentrated on ~7 CPUs even with all three
  co-location returns disabled — the dfl picker's prev-CPU anchoring packs by itself,
  so §R.1's returns are not the packing mechanism, only a refinement of it;
  (2) per-attach game-thread wait growth (12.6 → 442 ms/s over five attaches) tracks
  the same scene drift, not build changes; (3) no arm — cake pack, cake spread,
  EEVDF — showed a gap outside the drift band. The maintainer's 616→580 observation
  remains unreproduced. Next instrument: MangoHud frame screen with fast ABBA
  alternation (drift-immune), when the maintainer opts in.
- **Polish 2026-08-17: rate hysteresis + quiet logging.** Startup logs showed CPU 7
  flapping in and out every few seconds: the USB mouse line polls at exactly 1000 Hz,
  riding the flag threshold. Classifier now returns per-CPU rates
  (`sink_rates_from_deltas`); flag at ≥1 kHz as before, but a flagged sink only counts
  quiet samples below 500 Hz — between the two it holds and the quiet count restarts
  (Schmitt band, same fast-up/slow-down shape as §G27.1c). Set-change log lines moved
  behind `--verbose` like the frame clock; the startup line states the set is tracked
  live.
- Aborts: A leaves fence on 13 (an in-code bypass, not staleness — re-diagnose before B);
  mean wake regression exceeds twice the tail win; B adds any hot-path spill.
- **Phase A RAN 2026-08-17 (`wow-cake-g30a`): relaunch mid-play does NOT fix it — and the
  target histograms explain why.** The probe works; each attach freezes a different
  arbitrary snapshot: first attach excluded {5,7} (both USB lines), second only {5};
  nvidia/CPU 13 missed BOTH because relaunching cake means the game is unfocused, its FPS
  throttles, and the nvidia line drops sub-kHz during the exact probe window — the
  one-shot check structurally cannot see the biggest sink in the daily-driver flow
  (observer effect). CPU 13 keeps ~2% of fence placements and ~40% of those eat the ISR
  shadow (max 602 µs this run; slow wakes 97% on 13). Zero-code path CLOSED; Phase B
  (periodic re-probe, §R.25 shape) is the only fix.

### §G31 — frame clock latches on vote silence (registered 2026-08-17, §R.25 audit)

**Status: registered 2026-08-17; Phase A pending.**

- Finding (verified 2×): `publish_frame_clock` returns before the bss write on an empty
  histogram (main.rs:387-389) and nothing else decays the frame words — when every voter
  exits, the departed game's cadence and tightened slice geometry persist indefinitely.
  Fails conservative (the SLICE_NS min only over-tightens), so borderline not violation.
- Hypothesis: decaying toward the boot state after N consecutive zero-vote polls removes
  a stale bound with zero effect on any hosted-vote regime.
- Phases: A decay after 3 zero-vote polls (mirror SLOW_POLLS), sealed A/A. Aborts: any
  A/A movement (means votes were flowing when assumed silent).

### §G32 — per-task estimators have infinite memory (registered 2026-08-17, §R.25 audit)

**Status: registered 2026-08-17; build only if a real mid-session cadence change is
observed mis-tracked.**

- Finding (verified): `cake_frame_observe`'s vote divides since-birth counters
  (`(now − start_time) / nvcsw`) — a long-lived thread that changes cadence (menu 60 Hz →
  in-world 240 Hz) corrects in time proportional to its age, asymptotically never. Same
  1/lifetime gain in `cake_burst_ns`/`cake_starved`, but the skeptic ruled those OK (live
  recompute; the starvation ratio cancels phase bias). The vote is the exposed case: the
  §G27.1 picker windows the CROWD per poll, never the per-task mean feeding it.
- Hypothesis: a windowed cadence estimate (task-local baseline rebased on epoch/phase
  change) lets the clock track mid-session cadence moves hours into a thread's life.
- Cost note: needs per-task storage cake currently avoids — weigh against G27's live
  26–1950 Hz tracking, which worked because game crowds are wide. Build only if a real
  mid-session cadence change is observed mis-tracked.
- Aborts: any hot-path spill; vote pollution at the picker (§G27 abort inherits).

### §G33 — sink-ness is IRQ time share, not interrupt count (registered 2026-08-17)

**Status: Phase A BUILT + attach-test PASSED 2026-08-17; the registered wake A/B vs
`wow-cake-g30c` is the remaining pending step.**

- Finding (measured 2026-08-17, maintainer question "track all IRQs, avoid 500 Hz too?"):
  count rate mis-prices sinks. This kernel accounts exact per-CPU IRQ time
  (`CONFIG_IRQ_TIME_ACCOUNTING=y`, `/proc/stat` irq+softirq): CPU 13 spends **2.46%** of
  all time in handlers and CPU 5 **2.05%** (live 2 s window: 2.0% / 1.0%) vs **~0.1%**
  on every other CPU — *including CPU 7*, the 1000 Hz mouse line the count classifier
  flags. Occupancy IS the shadow probability: 13's ~2% matches §G30's measured ~2% of
  fence placements there eating the ISR. Count rate flags a harmless CPU (7) and would
  miss a slow-but-heavy handler (500 Hz × 40 µs = 2% shadow, invisible below 1 kHz).
- Hypothesis: classifying sinks by measured IRQ time share — flag ≥1%, hold down to
  0.5% (§G30 Schmitt shape) — steers around every harmful line at any rate, returns
  CPU 7 to the placement pool, and deletes both static Hz constants (the threshold
  becomes the physical harm: probability a wake lands in a handler shadow).
  `/proc/interrupts` stays only to name the flagged device in the log.
- Phases: A loader-only — SinkMonitor input swaps to `/proc/stat` deltas, mask machinery
  untouched; expect set {5,13} with 7 unflagged; wake A/B vs `wow-cake-g30c`: fence tail
  ≤ g30c, placements on 7 resume, mean unchanged-or-better. B tiered preference masks —
  only if some host shows a real middle class (this host is bimodal, 20× separation).
- Aborts: fence p99 > 2× g30c (>2.5 µs); any set flap returns; a hot-path spill.
- **Phase A BUILT 2026-08-17, §R.26-shaped: no thresholds at all.** The cut is the widest
  multiplicative gap in the host's own sorted tick-delta distribution (ratios of raw
  deltas — no clock, no USER_HZ, no percent). Zero deltas rank at half a tick (the
  midpoint of what the window could not resolve), keeping ratios finite so a lone loud
  CPU still separates on a quiet machine. Flag needs 2 consecutive above-cut windows
  (ranking noise never repeats; a real sink always does), release stays 3 — all four
  remaining constants are dimensionless agreement counts. The attach-time probe and the
  whole `/proc/interrupts` parser are DELETED (~90 lines): the scheduler starts
  sink-free and announces the first honest set ~3 s in, which also closes the §G30
  observer effect for good (nothing is ever sampled during launch). Softirq time is
  ingested too — CPU 5's real load (157k softirq vs 30k hardirq ticks since boot) was
  invisible to line counts. 9 s standalone replica on the live host: published set
  converged [5, 13] with two additive changes and zero flap; mouse CPU 7 never flagged.
  Known residuals, accepted: an idle host may briefly flag its loudest (still harmless)
  CPU — costs one deprioritized CPU out of 16 with the machine idle; a genuinely
  half-machine-wide IRQ spread reads untrusted and freezes the previous set. Gates:
  both profiles + clippy zero warnings, BPF object untouched. Pending: relaunch
  attach-test, then the registered wake A/B.
- Attach-test **PASSED 2026-08-17 22:07** — the new binary attached clean; the
  registered wake A/B vs `wow-cake-g30c` is the remaining pending step.

### §G34 — PSI falsified; per-event beats polled (audited 2026-08-17)

**Status: audited 2026-08-17; harvest H3 DELIVERED (§G35 Phase D), H1/H2/H4/H5 pending.**

- Finding (17-agent workflow audit; full verdict `docs/SIGNALS_AUDIT_2026-08-17.md`): all 12
  PSI-based theories killed or fatally weakened by adversarial review. Grounds: (1) every
  decision PSI informs at 500 ms–1 s is available per-event at the decision point in BPF
  (`scx_bpf_cpu_curr` occupant, two-step pick, crowd test); (2) cake deliberately starves
  background work, so global `some` measures "background exists", not "cake failing";
  (3) Steam titles share `app-steam@.service` with client/CEF — no clean game scope exists
  on this host (18.9 s of `full` accrued with no game running); per-scope trigger writes
  EACCES after cap-drop. Do not re-litigate PSI without new host structure.
- Harvest registered (per-event constructs the kills named, all BTF-verified): H1
  `scx_bpf_now` for `bpf_ktime_get_ns` (6 hot sites); H2 qmark bits for custom-DSQ
  `dsq_nr_queued` rhashtable lookups (4 hot sites); H3 two-step nonsink-first kick pick —
  fixes §G30's accepted ROUTE_GLOBAL residual with no new signal, DELIVERED by §G35
  Phase D (`cake_pick_idle_clean`); H4 collapse the double
  idle scan on nonsink miss; H5 `.update_idle` idle counter replacing the serial popcount
  (§R.25-aligned); H6 crowd-membership occupant test (future construct). Sweep keepers:
  per-tid `schedstat` run_delay (0.3 µs, scoring/classification only), `cgroup.events`
  (event-exact game lifecycle), `sched_ext/root/events` (self-diagnosis counter).
- Phases: each H item is its own experiment — hypothesis + A/B per the standard laws;
  H1/H4 mechanical (sealed A/A + appsim), H3 DELIVERED (§G35 Phase D), H2/H5
  need fnspills + attach-test. Aborts: any hot-path spill; sealed A/A movement.

### §G35 — instantaneous handler-shadow bit from IRQ tracepoints (registered 2026-08-17)

**Status: A-D built + attach-tested; desktop hot_at_wake 0.80% → 0.23%; WoW --irq capture
is the endpoint.**

- Hypothesis: BPF programs on `irq_handler_entry/exit` (+ `softirq_entry/exit`) maintaining
  a per-CPU "inside a handler NOW" word that select_cpu reads for free beats the 1 s
  time-share average at avoiding ISR-shadow landings — the event source §R.25 said didn't
  exist for IRQ does exist; this amends that exception. Complements §G33, never replaces
  it: slow signal = chronically loud CPUs (mask), fast bit = loud this instant (last-check).
- Phases: A instrument-only — per-CPU shadow word + counters: how often a wake's chosen CPU
  has the bit set at pick time, and how often the bit flips between pick and landing (the
  race window), zero policy change, sealed A/A for tracepoint overhead (appsim + fence
  capture). B consume: bit veto in the ranked pick / kick targets. Endpoint: wake A/B fence
  tail vs g33 tip; frame screen per GAME-FIRST before scoring.
- Aborts: A/A shows measurable tracepoint overhead; race-flip rate rivals the hit rate (bit
  stale-wrong as often as right); any hot-path spill.
- Cost note: hooks fire at IRQ rate (~kHz × ~tens of ns ≈ 0.002% CPU); one per-CPU word.
- **Phase A built as offline tooling 2026-08-17 — zero scheduler code.** `wake-latency
  capture --irq` records the 4 handler tracepoints; new `cakebench irq-shadow` joins
  handler windows with wakes per target CPU. Desktop smoke (12 s, 118k wakes): 1.2% of
  wakes hit an in-handler CPU; those ran p50 0.85 µs vs 0.37 clean, p99 17.4 vs 3.6 —
  the bit carries real signal. Caveat: the "shadowed" (handler between wake and run)
  bucket is contaminated — any long wait catches a timer tick by chance (flat ~5.3 ms
  cluster); score on hot_at_wake only until the overlap test conditions on the CPU
  being otherwise free. Endpoint needs a WoW-session capture with --irq + --match.
- **Phase B BUILT 2026-08-17 (maintainer waived the WoW go/no-go: "if you see the issue
  on desktop then yeah it could happen in game so fix it").** BPF: `cake_irq_live[]`
  slot-padded per-CPU depth, four `tp_btf` handler-edge progs (11-12 insns, 0 spills
  each; exit guards zero for attach-mid-handler), predicate merged as
  `cake_cpu_irq_bad()` = chronic mask OR live depth at the three §G30 veto sites
  (serial wc, prev-cpu continuation, convergence waker). Wakes issued FROM softirq
  now self-veto waker-anchored returns — the §G30 ISR-mimic, killed per-event. Loader
  attaches the four links after struct_ops, warns and degrades to chronic-only on
  failure. select_cpu 377→396 insns, spills 4/1 unchanged; comment ratio 0.68; both
  profiles + clippy clean. NOT covered yet: the ranked pick and kick targets (Phase C
  if the A/B leaves hot landings there). Pending: relaunch attach-test (verifier on
  tp_btf), then irq-shadow A/B — desktop smoke first, WoW capture scores it.
- **Phase B attach-tested 2026-08-17 22:18** — verifier accepted all four tp_btf progs.
  First desktop smoke moved the right way but inside noise (hot_at_wake 1.19→1.05%,
  p99 17.4→15.1 µs); residual concentrated on cpu0 timer ticks through the ranked pick.
- **Phase C BUILT 2026-08-17 (maintainer: "get that path covered").** After the ranked
  pick/dfl fallback converge (post SYNC re-rank), one live-depth check on the claimed
  CPU; if mid-handler, one `scx_bpf_pick_idle_cpu(p->cpus_ptr)` retry taken only when
  the alternative passes `cake_cpu_irq_bad` (both truths); otherwise the original
  claim stands — an idle CPU behind a µs handler still beats queueing. An abandoned
  claim self-heals on the CPU's next idle entry. select_cpu 396→424 insns, spills 4/1
  unchanged, ratio 0.68, all gates clean. Kick targets remain uncovered (with §G34 H3).
  Pending: relaunch, desktop smoke, WoW capture scores the whole G35 stack.
- **Phase C attach-tested + desktop-scored 2026-08-17 22:22.** Analyzer amended first:
  per-CPU pinned kthreads (ksoftirqd/N, kworker/N:, migration/N, irq/N-) are woken FROM
  the handler and can only run on that CPU — excluded from scoring (the 4% cpu5 spike
  in the raw phasec read was 13.7k such wakes under a network burst, not placement).
  Movable-wake staircase across the three same-day desktop smokes: hot_at_wake
  **0.80% → 0.66% (B) → 0.23% (B+C)**, hot max 135 → 15.8 → 8.8 µs, clean p50 improved
  0.37 → 0.29 µs. Residual 0.23% is mostly cpu0 timer ticks = the check-to-landing race
  floor. Desktop snapshots are attribution, not verdicts — WoW capture
  (`--irq --match 'WoW|vkd3d'`) remains the §G35 endpoint.
- **Phase D BUILT 2026-08-17 — kick targets covered (delivers §G34 H3).**
  `cake_pick_idle_clean()`: idle pick + one retry away from `cake_cpu_irq_bad` (chronic
  OR live), original kept when nothing cleaner is idle (any CPU beats queueing, §G30).
  Used at the three kick/pick sites (wake_notify ROUTE_GLOBAL fallback, kthread enqueue
  pick, enqueue kick_idle) plus a bad-veto on the SMT-sibling kick (checked before
  test_and_clear so the idle claim is never consumed then skipped). Every idle-placement
  path now sees both truths. Spills unchanged everywhere (wake_notify still 0/165→165
  insns tot 1797→1910), ratio 0.68, all gates clean. Pending: relaunch, smoke, WoW.
- **Phase D LIVE 2026-08-17 22:39** (kicks covered, closes §G34 H3): desktop
  movable hot-landings staircase **0.80 → 0.66 → 0.23 → 0.17%** across the four
  same-day smokes, cpu0 timer hits **820 → 4**.

### §G36 — predictive steering: avoid a CPU whose timer fires imminently (registered 2026-08-17)

**Status: BUILT 2026-08-17; pending relaunch + desktop smoke (timer-race hits
expected → ~0).**

- Hypothesis: the timer is the one interrupt scheduled in advance — the per-CPU next
  expiry is kernel state BPF can read (percpu `tick_cpu_device.evtdev->next_event` via
  BTF) — so placement can veto a CPU whose tick fires within the pick-to-landing
  horizon, closing the §G35 race for the timer class. Device IRQs stay unpredictable;
  this is the last buildable rung, everything below is physics.
- Horizon denomination (§R.26): the veto window is the measured pick-to-landing gap
  itself (from the §G35 Phase A race counters / capture join), never a chosen µs value.
- GATE: build only if the WoW `--irq` capture shows timer-race hot landings on game
  threads after Phase D. Desktop 2026-08-17 prices the target at ~4 wakes/12 s — near
  zero; registered for the construct, not the current numbers.
- Aborts: any hot-path spill; sealed A/A movement; percpu deref cost visible in appsim.
- **BUILT 2026-08-17 (maintainer waived the WoW gate: score on desktop).**
  `cake_cpu_tick_soon()` (28 insns, 0 spills): percpu `tick_cpu_device` →
  `evtdev->next_event` vs now + `cake_wake_hop_ns`; horizon = the startup hop probe's
  p99 (the measured pick-to-landing time, §R.26-clean), 0/probe-fail = predictor off;
  `__weak __ksym` + exists-check degrades to off if the symbol ever vanishes. Wired as
  a second trigger + alt-validation in the Phase C ranked-pick retry,
  `cake_pick_idle_clean`, and the sibling-kick veto — pick paths only, NEVER the
  per-wake fast-path predicates (certain ~30 ns per wake against ~1 ns expected win is
  a bad trade there; recorded so it isn't re-litigated). `cake_pick_idle_clean` went
  `__noinline` in the same change — the tick call had cost enqueue a spill inline;
  as a subprogram enqueue is 2/4 (better than pre-D 2/5), wake_notify 133 insns,
  select_cpu 4/1 unchanged, TOTAL 17/11/28. Ratio 0.67, all gates clean.
  Pending: relaunch + desktop smoke (timer-race hits expected → ~0).

---

### §R — Design rationale (from source comments)

#### §R.1 — co-location gate
mutex p99 **1.442 → 0.625 µs**; gates G9.2→G9.6, before dfl.

#### §R.2 — empty-home carve-out
Idle curr, LOCAL wake, sleeper wakee, valve curr; the flap sent global cost **futex 4.8M → 0.98M**.

#### §R.3 — own-first margin
Hysteresis, not slack: earliest-vtime cost **futex −49%**.

#### §R.4 — direct admission
qmark is advisory; confirm via the clamp helper.

#### §R.5 — wake bit as literal
A PRIQ insert reads no positional bits; IMMED trips `WARN_ON_ONCE`.

#### §R.6 — dfl's WAKE_SYNC return
`is_idle` covers a busy CPU, welding **pipe to 196K ops/s**.

#### §R.7 — `ops.dispatch` stages
Own/wake vtime, lockless peeks, steal ring, keep-prev (**+46%**).

#### §R.8 — kfunc bindings (superseded by §R.27)
The 1.1.x flat compat include cost a fifth of `cake_enqueue`'s instructions; 1.2.0
first answered with direct v2 bindings (kernel 7.1+ only), now answered by §R.27's
shaped ladders — same hot-frame codegen, old kernels load again.

#### §R.9 — `SCX_*` as immediates
`bpf_core_enum_value()`, not rodata loads. Permanent `#undef`.

#### §R.10 — cache geometry
128 B slots; `qmark` gates the ring, empty walks cost **199 ns/call**.

#### §R.11 — subprogram cut points
**The rule is the CUT POINT**; only r6–r9 survive a call.

#### §R.12 — `cake_log2_u64` branches
Branchless costs a ~36-insn chain.

#### §R.13 — sleeper clamp, S1 depth
S1d dose ¾ of the unused slice (futex `/8` −16%, `/2` +39%).

#### §R.14 — kthread/pinned wakes
Kthread wakes go direct (kworkers hit **p99 17 ms**); pinned preempt by depth.

#### §R.15 — NO BUCKETS
`OVF_DSQ` was invisible to the ring; tasks sat **>6 s**.

#### §R.16 — starvation escalation
An EMPTY wake queue is a SERVED one; `wake_served` at 0 armed it.

#### §R.17 — direct field writes
The authority check cost **+28–36%** in `ops.stopping`. Maintainer ruling
2026-08-17: sub-scheduler paths are known slow, do not adopt them — direct
writes stay while the kernel keeps the carve-out (`ext.c:7906`, deprecation
warn at load is expected); if removal ever lands, the answer is kernel-lane
(root-only unchecked variant or local patch), NOT the checked kfuncs. Cake's
only checked call is `cake_enable` — once per task birth, cold by design.

#### §R.18 — handoff hint
The one-quantum bit hit **25.44% on schbench**; confidence must repeat.

#### §R.19 — cost of ZERO SPILLS
Restoring the two `4d5b5f96d` decisions costs **3 spills, 4 fills**.

#### §R.20 — convergence arm
Converge on WAKE_SYNC or a proven sleeper.

#### §R.21 — span validation
A narrower `nr_cpu_span` strands work.

#### §R.22 — frame-clock mode
See §G11.

#### §R.23 — decomp guards
perf arms ring buffers sequentially; early waits read long.

#### §R.24 — divide elimination (KEEP)
Two of 11 divides feed only a comparison; pipe/mutex a TIE.

#### §R.25 — maintainer ruling: no one-shot startup checks (2026-08-17)
Anything measured once at startup is wrong the moment the signal moves (§G30: the sink
probe missed nvidia). Time-varying signals are re-checked periodically and corrected;
confidence earns a slower cadence (fast up, slow down — same shape as §G27.1c). One-shot
stays valid only for facts that physically cannot change while attached (cache geometry,
topology).

#### §R.26 — maintainer ruling: static thresholds discard data (2026-08-17)
A unit-carrying constant on a live signal (1000 Hz, 1% share) is a frozen measurement:
it cannot adapt and it throws away the gradient the decision could have steered by
(§G33: the 1 kHz cut flagged a harmless mouse CPU and would miss a 500 Hz heavy
handler). Decisions consume the FULL measured distribution; any cut is derived from
that distribution itself (largest gap, rank, comparison of two measured costs) so no
number claims to know the world in advance. Dimensionless agreement counts (3-poll
release, 8-poll slowdown) survive — they pace confidence, they measure nothing.
Companion to §R.25: that ruling makes checks live, this one makes the VALUES live.

#### §R.27 — compat ladders, shaped (2026-08-18)
Old-kernel support without §R.8's hot-frame tax, by placing each ladder by its shape:
arms that are alternative calls with one argument shape stay inline (the verifier
deletes the untaken arms; register allocation is a single call's); a fallback that
needs its own stack or argument shape (`insert_vtime` args struct, `dsq_peek`
iterator, `cpu_curr` rq deref) lives in a `static __noinline` subprogram so the cost
stays inside that frame. Global subprograms return s32, never void — a pre-6.19
verifier rejects void global functions. Spills 28 → 26, hot frames flat
(`select_cpu` 5, `enqueue` 6); insns 1908 → 2049 are the dead arms, pruned at load.
Experiment: hypothesis — compat via shaped ladders keeps new-kernel codegen and
makes ≤ 6.18 verify; steps — port 5 `cpu_curr` + 3 `peek` + insert family +
`move_to_local` + 3 s32 returns; endpoint — CI veristat green on 6.13/6.16/6.18 with
hot spills flat; abort — any hot-frame spill regression, or a fallback that changes
scheduling behavior on the dev kernel.

#### §R.28 — geometry decoupled from the shared clock (2026-08-19)
The frame clock was the GEOMETRY UNIT: every patience window a shift of
`cake_frame_slice_ns`, so one fast desktop crowd (a 374.9 Hz voter, the mouse at
1 kHz) tightened every task's windows — measured as the 2× handoff-tail mode flip
(`mode_probe/` in the 2026-08-19 run dir). Now: slice cap = half the task's OWN
cycle (`cake_period_ns`, the §G12 KEYSTONE twin divide); occupant-protection and
young-occupant windows = FIXED slice fractions — a per-occupant-period version
inverted semantics for fast occupants (window ~44 ns ⇒ the handoff kick never
fired, p99 2.1) and was reverted same-session; all vtime windows = fixed SLICE_NS.
The clock publishes for --verbose only; §G27's easy-scene endpoint is superseded by
per-task geometry. Object: spills 17/11 → 16/10, divides 11 → **5** (`cake_task_slice`
consolidated to one subprogram). Verdict: quiet handoff p99 rests at 0.86–0.92
(was 0.85–1.9 drifting) and the clock dose is gone, but **p999 2× and
schbench-light +72% persist** — with the crowd control (1.1.3 +0.05 µs vs nightly
+0.9 under 8×1 kHz hrtimer load) the standing suspect is the IRQ-reactive stack
(§G33/§G35/§G36; schbench is pure timer pressure and 1.1.3 ignores IRQs). GAME
SCREEN OWED before keep (GAME-FIRST).

**Bisect 2026-08-19 (4 probe commits, all reverted byte-identical to `0d345ed2…`):**
all-vetoes-off closes EVERYTHING — quiet handoff p99 **0.80** (beats 1.1.3's 0.855),
crowd-immune (0.79 under 8×1 kHz), schbench-light **2548** ≈ 1.1.3's 2540, pipe
2.015 s (best of day). Single-feature-on runs, each independently harmful:
**§G36** tick veto → handoff drift 0.84→1.35 + crowd sensitivity (schbench 2964);
**§G35** live bit → quiet p999 2.7, crowd p999 **4.7**, schbench 3796;
**§G33** chronic sinks → schbench **4472, the full +72% alone**, handoff clean.
Their wake-tier game wins (G21 −39.9% main wake, G30 fence tail, G35 staircase)
stand — this is a GAMES-VS-BENCH TRADE, maintainer's call, no deletion on bench
data. Design cut for the next arc: each veto fires on SIGNAL PRESENCE with no
cost comparison against the alternative placement (claiming a briefly-loud CPU
usually beats queueing) — the §R.26 lens, binary thresholds discarding data.

**Live WoW ABBA closes the trade 2026-08-19 (`wow-vetoAB-s{1..4}` in
`history/wake_latency/`, `--irq`, 22 s slots, active play): the vetoes EARN
THEIR KEEP IN-GAME, 2/2 no overlap on every role.** With vetoes vs all-off:
fence p99 **23–27 → 48 µs**, vkd3d_queue p95 **7.4 → 28–33** (4×), WoW.exe main
p95 14 → 30–32, ThreadPool High p50 **0.86 → 5.0 µs** (6×), same-CPU wakes
86% → 31%. VERDICT under GAME-FIRST: vetoes STAY; the bench/desktop tail cost
(schbench-light +72%, handoff p999 2× vs 1.1.3) is the accepted price, and the
weighed-veto refinement is the registered path to buying both. MangoHud was not
injected — frame screen still owed; wake tier only.

---

### §S — Constant ledger (from `intf.h`)

#### §S.1 — `SLICE_NS = 3 ms`
Dose-responsed U-curve minimum; **1, 2 and 4 ms worse**.

#### §S.2 — slice-relative divisors
Only where the quantity IS a turn.

#### §S.3 — five named literals
Five inline literals named, byte-identical.

#### §S.4 — `WAKE_STARVE_WALL_NS`
`8 * SLICE_NS` is 24 ms only at a 3 ms slice.

#### §S.5 — hardware rodata pair
`cake_handoff_max_ns = 1464`, `cake_preempt_protect_ns = 375000`. As a slice divisor the
first hit **488 ns at 1 ms, under the ~606 ns sleep floor, disabling co-location**.
Loader-driven values cost **mutex −35.66%**.

#### §S.6 — cflags: topology only
Source-only policy; the cache serves stale cflag builds.

#### §S.7 — ids and geometry
`MAX_CPUS = 1024` is a verifier sizing bound, not the DSQ count. `MAX_CPUS + 1` was `OVF_DSQ` (§R.15).

---

### Open review findings — REVIEW_INDEPENDENT_2026-08-17.md

Verified against source, not yet fixed. Each becomes an experiment when picked up:

- **Finding 2** — `cake_system_serial()` denominates in POSSIBLE CPUs, not online.
- **Finding 4** — multi-CCD ring-steal guard returns the wrong sentinel.
- **Finding 5** — `reexec_self()` doc block is attached to the wrong item.
