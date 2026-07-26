# scx_cake — CURRENT STATE (single session entrypoint)

**Read this first, every session.** It replaces re-auditing the corpus and the dated
research docs. Update it whenever a gap closes, a design is adopted/rejected, or the
harness changes. Dated campaign docs live in `docs/archive/` — drill in only when this
file points you there.

Last updated: 2026-07-26 (branch consolidation — the performance leader now
lives on `RitzDaCat/scx_cake-nightly`. Scheduler behavior unchanged since
2026-07-24's **GAME GATE PASSED**; see §2026-07-24 below).

## 2026-07-26 — branch consolidation (no scheduler change)

**There is now exactly ONE working branch: `RitzDaCat/scx_cake-nightly`**, at
the K+L+M+S1d performance leader (`251169c08`). `s1d-restore-20260722` was a
strict descendant of nightly (0 commits on nightly that were not on s1d, 90 the
other way), so this was a pure fast-forward — no history rewrite, no
force-push, nothing rebased. Local nightly is **ahead 90 of
`origin/RitzDaCat/scx_cake-nightly`** and has not been pushed.

Retired: 23 branches (34 → 11) and all 17 stashes, each preserved first as an
`archive/<name>` tag. **`git tag -l 'archive/*'` is the manifest**; revive
anything with `git checkout -b <name> archive/<name>`. Codex's 67 private
`refs/codex/**` static checkpoints — invisible to `git branch`, none reachable
from the quarantine tip — moved to `refs/archive/codex-quarantine-20260722/**`,
following the existing `refs/archive/scx-cleanup-20260714/*` precedent. Also
removed: a dead `fetcher-*` remote pointing at a vanished `/tmp` path, and 81
stale worktree records.

Deliberately KEPT as branches: `main`, `rt-collision-census-20260724` (active
census infra), and the release/upstream-PR set (`scx_cake-1.0.4`,
`RitzDaCat/scx_cake-1.0.5`, `scx_cake_103`, `scx_cake-release-2026-07-01`,
`RitzDaCat/scx_cake`, `pr-3621-cosmos`, `pr-3677-pandamonium`,
`add-scx-gamer`).

## 2026-07-24 — GAME GATE PASSED (Fellowship, parked scene)

**The gate pending since 2026-07-19 is green.** `cakebench game ab --game
fellowship --duration 60 --settle 15`, ABBA (native/cake/cake/native), 2 runs
per arm, receipt `head-9cb7927c53e3-ensure`. VALIDITY: arms report
`scheduler=scx_cake` / `scxctl=cake` vs `native`/`native`; dmesg shows two
clean enable/disable pairs ("unregistered from user space" — **no watchdog
eviction, no runnable-task stall**); `/sys/kernel/sched_ext/root/ops` empty
after.

| metric | native | cake | delta |
|---|---:|---:|---:|
| Avg FPS | 190.548 | 190.778 | +0.12% (tie) |
| 1% low | 151.808 | 153.279 | **+0.97%** |
| 0.1% low | 139.003 | 140.325 | **+0.95%** |
| p99 frame time | 6.588 ms | 6.524 ms | −0.97% |
| p99.9 | 7.194 ms | 7.126 ms | −0.95% |
| Max FT | 9.764 ms | 9.773 ms | tie |
| FT stddev | 0.380 | 0.354 | **−6.8%** |
| FT MAD | 0.115 | 0.098 | **−14.8%** |
| jitter Δ median | 0.211 ms | 0.176 ms | **−16.6%** |
| spikes >1.25× median | 1.206% | 0.942% | **−21.9%** |
| GPU avg | 94.000% | 93.992% | tie |

Cake wins the whole smoothness/tail family and loses nothing. Average FPS ties
because the scene is GPU-bound at 94% — no throughput headroom for a scheduler
to add; what it can do is cut CPU-side jitter, and that is exactly the shape.
The evidence is the *coherence* (stddev, MAD, CV, jitter, spike rate all move
together), not any single metric. **n=2 per arm — this is a strong screen, not
a sealed result.** Parked + GPU-bound is also the easy case; an actively-played
CPU-loaded scene is still unmeasured.

**RT MIGRATION COLLAPSE (n=1 cake, striking, needs replication).** `rt-audit
capture`, same game/scene: kwin main 59 & 76 migrations under native → **0**
under cake; DP-2 18 & 134 → **0**; DP-3 27 & 24 → **0** (libinput logged 4
under cake, proving the counter is live and not artifactually zeroed). CPU% and
switch rates stay comparable. Migrations are the NOISIEST metric measured
(18→134 between two identical native runs), but zero is outside that whole
range and hit three independent threads at once (libinput logged 4 under cake,
proving the counter is live). **Treat as an unexplained OBSERVATION, not a cake
property** — see the falsification immediately below.

**MECHANISM HYPOTHESIS FALSIFIED (kernel source, same day).** The proposed
explanation — "cake keeps CPUs busy where native leaves them idle, so RT's
search finds fewer idle targets and RT threads stop bouncing" — is **wrong**.
RT placement has NO idle-vs-busy distinction: `CPUPRI_IDLE` does not exist in
v7.1 (`git grep CPUPRI_IDLE v7.1 -- kernel/sched/` returns nothing); an idle
CPU and a cake-occupied CPU both sit at `CPUPRI_NORMAL` (0), and `cpupri_set()`
is only called from `inc_rt_prio`/`dec_rt_prio`, so a CPU's level reflects its
RT runqueue and nothing else. **Cake's occupancy pattern is invisible to
`find_lowest_rq`.** COROLLARY — a class of ideas is closed: steering, pinning,
or reserving cake tasks to keep CPUs free of ordinary work CANNOT influence RT
placement; do not spend a candidate on it. Surviving explanations are (a) wake
phase — cake shifts when compositor-feeding ext work completes, so kwin
main/DP-2/DP-3 collide on each other less; (b) `this_cpu` preference in the
domain-walk fallback; (c) noise. After the falsification the prior on "real
mechanism" should be LOWER, not higher. Discriminator (cheap, read-only, no
BPF/receipt/activation): record per-CPU RT *residency* in `rt-audit` and check
whether RT threads are co-resident more often under native.
Full reference: `docs/RT_PLACEMENT_LOGIC_2026-07-24.md`.

**RT supply, characterized:** idle 1.217% of one CPU → **11.388% under game**
(9.4×), ~6,583 RT switches/s, **~17 µs mean burst**, kwin DP-2 alone at
3,775-4,711 sw/s. Kernel RT negligible (0.008-0.248%). Fellowship runs its own
`SCHED_FIFO` prio 83 thread, outranking every compositor/audio thread.

**RT LANE LARGELY CLOSED (kernel-source verified).** `put_prev_task_scx` (v7.1)
re-queues a preempted non-IMMED task with **`SCX_ENQ_HEAD`** — front of its own
CPU's local DSQ, resumed the instant RT finishes. There is no requeue-position
problem to solve. Therefore: **IMMED escape (07-23 doc) is DEAD** — it buys only
the option to run elsewhere during a ~17 µs burst, against migration + cold L2,
which is that doc's own reject condition. **C1 (RT dodge above backlog gate)
DEPRIORITIZED** — wake-path RT collisions are ~1-in-140 even under game.
**The one survivor is A1 (age amnesia):** RT preemption runs cake's full
stopping/running pair, so `cake_running()` re-stamps `run->stamp` and cake's
on-CPU age resets to zero ~6,583×/s under game. That re-opens the
`HOME_PREEMPT_YOUNG_NS` (~94 µs) window and resets mutation M's SLICE/2 gate.
Cake cannot control RT, but this is cake's OWN state being corrupted by an
event it cannot prevent — inside its authority to fix. Census it first
(discriminator: `cake_stopping` with `runnable && p->scx.slice > 0`, split by
`pmark` — set = cake's own kick, clear = foreign preemption).

**FAILED, do not re-derive:** an active-gameplay ABBA at `--duration 90`
produced ZERO valid arms — MangoHud's `~/.config/MangoHud/MangoHud.conf` has
`log_duration=60`, so every arm delivered ~59.7-60.0 s against a required
≥81 s (0.9 × 90) and all four were rejected `invalid_short_duration` into
`runs/game_invalid/`. Use `--duration 60`, or raise `log_duration` first.
Also: `runs/rt_audit/2026-07-24_154123_rt-supply-game-cake-*` is NATIVE data
despite its name (receipt guard refused activation without
`--use-scheduler-runner`); see the `MISLABELED.md` in that directory.

**Next:** replicate the RT-migration result; active-gameplay A/B at a valid
duration; then C2/C3 and Gate 2. The frontier remains N4/contention, not RT.

## 2026-07-24 — ledger was all zeros; regime gate passed

**P1 TOOLING BUG, FIXED.** `bench/scx_cake_ledger.py` read the analysis block
off `COMPLETE.json`, which does not carry one, and defaulted the miss to `0`.
Every one of the 133 sealed rows recorded `b_good_median_pct: 0`,
`ci_lo/ci_hi: 0`, `blocks: null` — a plausible-looking dead heat for every
mutation ever run. H5 designates this the AI-steering data source, so anything
that had learned from it would have concluded no mutation ever moved anything.
Fixed to read `pair_result.json` and to default numerics to `None`; validated
against the sealed pipe transaction (+22.72% CI[+21.08,+24.89], matches the
scoreboard exactly). Ledger now holds 149 complete transactions with real
verdicts. **The fix is UNCOMMITTED in scx_cake_bench_assets**, consistent with
that repo's existing working tree.

**GEAR GATE 1: PASSED.** Offered background load predicts cake's delta —
pooled workload-centred **rho = −0.42, n = 125, t = −5.15**. Per workload
(quiet half → loaded half): futex +10.97 → **−82.15** (rho −0.63, t −4.2,
n=28); pipe +21.27 → +10.14; schbench-light −2.24 → −8.95 (reproduces the
documented −1.4 → −9.6 deepening); **mutex-handoff +0.66 → +7.56 — the only
workload that IMPROVES under load**, and it is the Wayland-input shape.
N4 is therefore confirmed at corpus scale rather than inferred from the
mutation-L survival runs.

**METHOD CORRECTION (binding on all future corpus analysis):**
`ext_cpu_cake_med` is **endogenous** — cake starves background work under
contention (UnrealEditor ~50% on cake's arm vs 260-295% on native's), so the
cake-side noise covariate is co-produced with the delta and must never be used
as a regime variable. Use `ext_cpu_native_med` (load offered under a fixed
reference scheduler). This sharpens H2 into a rule about which covariate is an
input.

**S3 SURVIVES.** Futex quiet-only rows (native ext CPU 3.4-5.2%, n=16) still
span −53.2 .. +61.4. Load does not explain the mode. The ledger independently
reproduces both prior claims: S1 is worth ~+65pt within 07-20, AND pre-S1 head
`6f4252f2` read +57.2 on 07-18 vs −52 for pre-S1 heads on 07-20 at identical
load.

**Consequence for the gear design:** mutex-handoff's inversion means a single
global gear is wrong — the correct target is regime-conditional per workload
*shape*, not a machine-wide contended mode. Gate 2 (`sched.data` retention in
the broker `--observe` path) is now the blocking item; turn it on BEFORE the
next contended capture. Full arc:
`docs/LEDGER_REPAIR_AND_REGIME_GATE_2026-07-24.md`.

**Also this session (review-driven, no scheduler behavior change):** loader
re-execs on `SCX_ECODE_ACT_RESTART` instead of re-entering `Scheduler::init`
— capabilities dropped after attach cannot be regained in-process, so
kernel-requested restart previously failed `EPERM` and killed the scheduler
(`4ae7b9c0d`). DESIGN.md/README.md resynced with the K+L+M+S1d stack
(`42988264d`); README had been advertising pipe as an −11% loss when it is a
+22.7% win. **Open review finding, not yet actioned:** the M8 RT-owned
avoidance in `cake_enqueue` is overridden by the global-backlog gate
(`cake.bpf.c:1219`) — under saturation, wakes are homed onto RT-owned CPUs
anyway, i.e. the RT dodge is inert exactly when the compositor matters most.

## 2026-07-22 re-baseline — codex I-series quarantined, S1d restored

The 2026-07-21/22 codex campaign (43 commits, I1–I30 + N4b/N4d) produced ZERO
measured results: it misread the boot-bound receipt's missing file capabilities
(`artifact_b_capabilities_missing`) as a hard environment blocker, declared all
benchmark routes "fail closed", and stacked unmeasured static-only candidates.
It is quarantined complete (including its uncommitted I28–I30 diff and its
STATE.md rewrite) at `28b6df6cb`, reachable from tag
`archive/codex/scx-cake-nightly-perf-review-20260709` (the branch was retired
2026-07-26; its 67 private `refs/codex/**` static checkpoints were moved to
`refs/archive/codex-quarantine-20260722/**`). Nothing there is validated; its
only measured row was I4 (`c447b9e96`, direct-admission key coherence, 2-block
pipe tie) — a plausible correctness cherry-pick if ever wanted, unmerged.

Working branch at the time was `s1d-restore-20260722` at S1d (`992d88bd1`) — the
last receipted, guard-clean, benchmarked HEAD. (That branch was folded into
`RitzDaCat/scx_cake-nightly` on 2026-07-26; see §2026-07-26 above.) Harness
re-verified this session:
`artifact ensure` rebuilt the current-boot receipt (txn
`20260722T160053Z_head-992d88bd1e29-ensure_4b47d704bb69`, binary `61ddc68c…`),
readiness passed, and a 2-block perf-sched-pipe screen ingested clean
(`runs/exact_pair/exact_pair_20260722T160215Z_c8e22555bb57`): cake
0.786–0.816 usec/op vs native 0.868–1.011, all rows scheduler/hash-valid,
diagnostic_only tier, noise class warn sealed per arm.

Lesson encoded in the sched-ext-dev skill (iron rules 11–12): a
missing-capability readiness failure means "rerun `artifact ensure`", never
"benchmarking is blocked"; static evidence (hashes, disassembly, review
verdicts) is build attribution, not performance evidence.

Next work is unchanged from the 2026-07-20 handoff: S1e promotion gates
(lock-pi guard, 8-block futex confirm, game gate), then the research roadmap.

## Goal

Beat native EEVDF on every benchmark while holding game tails (1%low / p99 / frame-time σ)
— games are the hard constraint; throughput never ships at their expense.

## Scoreboard vs EEVDF — SEALED exact-pair medians (2026-07-17/18, 8 blocks each)

Wins: futex +57.2%, schbench-saturated p99 +49.1%, ccm-cache +45.9%, stress-ng-cache
+26.5%, pipe usecs/op +22.7%, thread +7.5%, fork +5.5%, stress-ng-memcpy (split) +4.5%.
Losses: ccm-memcpy −14.9%, schbench-light p99 −1.42% (quiet; −9.6% under heavy desktop
noise — the frontier trade deepens with contention, 2026-07-19), futex-lock-pi −71.8%
(recovered from −86.6, mutation K kept, see gap 3).
New sealed wins 2026-07-19: blender-render +11.9% CI[+11.8,+12.3] (procedural Cycles
scene, assets/blender/cake_blender_bench.py, sha-sealed); mutex-handoff +10.3%.
(Pre-broker corpus numbers above are superseded; unsealed rows remain for namd,
kernel-defconfig, xz, prime, x265, argon2, sevenzip, y-cruncher.)

**Open gap list (the work):**
1. ccm-memcpy — SEALED 2026-07-18: −14.9% CI[−15.5,−13.0] while ccm-cache +45.8%
   CI[+34.8,+59.8] (same combined workload, 8 blocks each). ATTRIBUTED: pure CPU-share
   reallocation from cake's sleeper catch-up (per-usr-second efficiency equal both
   schedulers; native splits memcpy 365s/cache 108s of the 480 CPU·s pie, cake 323/151).
   Zero-sum — no point fix. FALSIFIED 2026-07-18 (all reverted, commits in history):
   (a) migration affinity — steal-strandedness gate halved migrations 32k→15.5k, memcpy
   unchanged; (b) stochastic SMT pairing drift v1 (avoid hog sibling) — null, every
   queue holds a ~1+1 mix so sibling phase is coin-flip; (c) drift v2 (join hog CPU
   with bursty sibling, segregated fixed point) — memcpy efficiency stayed 384 ops/usr-s,
   segregation never emerged: wake-path remixing defeats expiry-time drift without
   explicit type state; (d) segregation v3 (per-CPU hog marks + wake-path homing veto,
   commit 81d58d83b) — memcpy −16.0% unmoved, and the homing veto REGRESSED futex
   +57.2%→+29.3% (hog-side CPUs are exactly where futex homing must land); reverted.
   LESSON: any wake-path class veto collides with the futex/pipe homing laws — the
   classifier must be per-TASK, not per-CPU, so handoff wakes are exempt. THE lever
   stands: unlike-type SMT pairing (+73% memcpy
   ops/usr-s pinned diagnostic); feasibility arithmetic says a segregated layout beats
   native on BOTH ccm metrics using 347 of 480 CPU·s. Requires explicit duty
   classification (1-bit task state, expiry-vs-block) + deterministic per-class CPU
   assignment — CAPE-lane design work, and the wake path must respect the classes.
2. schbench-light p99 — SEALED 2026-07-18: −1.42% CI[−1.74,−1.26]; the corpus −10.5%
   didn't reproduce under exact pairs. Small real loss. Nulls: steal gate; home-preempt
   margin div 2→4 (−1.59, unchanged).
   **ATTRIBUTED 2026-07-18 (first observatory result, 4-minute observed pair):**
   schbench's own wake→run p99 is 292 µs under cake vs 32 µs under native (9×), p999
   ~2.5 ms ≈ one slice, while cake WINS p50 (0.8 vs 1.0 µs). Mechanism: peer wakes that
   go global under load wait for a dispatch event when no idle CPU exists and the
   preempt margin doesn't fire — worst case one full 3 ms slice. Native's eligibility
   wakeup-preempt bounds this at tens of µs. The lever is bounded global wake service
   (principled per-wake preemption), NOT the home-preempt margin (dose already null).
   Evidence: runs/exact_pair/exact_pair_20260718T225756Z_ddf2c8eb179d arms
   decision_stream.json (broker --observe + bench/scx_cake_decision_stream.py).
   **Preempt-side levers FALSIFIED (both reverted, 2-block screens):** protect window
   slice/8→slice/32 = −18.7%; neighbor-probe preempt (3 extra candidates, unchanged
   protect+margin) = −7.2% then −27.5% on repeat. LAW-shaped conclusion: under desktop
   contention, additional wake-preemption of ANY form churns more than the 292 µs tails
   it rescues — the existing protect+margin sits at a measured optimum. Serving the
   tail needs a non-preempting mechanism (dispatch-side wake-head aging, better idle
   targeting, or accepting −1.4% as the fairness price under load).
   **ARC CLOSED 2026-07-19 — Pareto frontier, seven falsifications (all reverted):**
   dispatch-side doses too: peer hysteresis 1 and 1.5 slices watchdog-STARVE own queues
   (sleeper clamp pins fresh wakes ~1 slice behind own heads — cliff, not dial);
   1-in-4 blind rotation futex −84%; refusal-count strand service futex −83% with
   vtime identity AND −83% with task-pointer identity. Root discovery: a storm head
   PERSISTS precisely because own-first refuses it — head persistence, wait time, and
   vtime deficit all fail to separate "stranded tail wake" from "storm head", because
   they are the SAME state. Serving it faster re-splits converged handoff pairs; the
   schbench-light tail and the futex/pipe/sat wins are one behavior. cake's point on
   this frontier (−1.4% light-tail for +57/+49/+23) is the correct trade. Do NOT
   re-attempt wake-service levers; the only theoretical escape is knowing whether the
   waker will resume (handoff) or not (tail wake) — an intent signal, not a state
   signal (kernel-lane candidate: WF_SYNC-style hint plumbed through kfunc/enqueue
   flags). Chain: commits a4729d2b6→dc0f22012 (all reverted in history).
   Observatory validation: mutation C's observed pair showed schbench p999 486→43 µs,
   proving the mechanism model — the trade is real, not a measurement artifact.
3. ~~perf-sched-pipe latency_per_op contradiction~~ RESOLVED 2026-07-17: first sealed
   exact-pair transaction (8 blocks, 32 arms, interleaved, noise/thermal as covariates)
   shows cake +22.7% median on usecs_per_op (95% CI +21.1..+24.9, all 8 blocks positive)
   vs native EEVDF under active desktop load. Evidence tier diagnostic_only (4/8 blocks
   over the 5% within-label drift limit — noisy regime); rerun on a quiet host for the
   trusted tier. Run: runs/exact_pair/exact_pair_20260717T195140Z_6d5dcf64fbee.
4. Stale/missing native baselines: perf-memcpy (−5.3%, native from 06-22), argon2,
   x265 full-preset, sevenzip, y-cruncher — re-baseline before drawing conclusions.

3. **futex-lock-pi −86.6% CI[−86.7,−86.5] — NEW, SEALED 2026-07-19.** First
   PI-mutex coverage (perf bench futex lock-pi, 16 threads); catastrophic gap on the
   rt-mutex/priority-inheritance path no prior benchmark exercised.
   ATTRIBUTED (observed pair, decision stream): the serial top-waiter handoff wake
   runs at p50 2.3 µs but p99 3.9 ms / max 24 ms under cake vs p99 171 µs native —
   with ~15 CPUs idle. A stalled handoff wake stalls the whole benchmark (the wakee
   IS the new owner). This is a ROUTING defect (wake landing where no idle CPU
   promptly consumes it), not a fairness trade — likely fixable, unlike the closed
   wake-service frontier. Stall forensics (same session): 97% of slow handoff wakes
   were home-routed and served only at the occupant's SLICE EXPIRY (prev_state=R).
   Mutation G (deep-sleeper wakes skip the young preempt gate, margin unchanged):
   lock-pi UNCHANGED −86.7%, schbench-light −12.6%, futex stalled — REVERTED. The
   young gate was not binding; the MARGIN is: the sleeper clamp writes the wakee's
   vtime to the same floor the occupant started from, so the vtime margin cannot rank
   a deep sleeper above a mid-slice occupant — the clamp ERASES the deservingness
   signal preemption needs (same quantization that broke strand-identity).
   Raw-deficit margin (mutation H) TRIED AND FALSIFIED same session: lock-pi
   INVARIANT at −86% across every preempt-side variant (young gate, margin basis,
   sleeper bypass), each also regressing schbench-light ~−11%. CONCLUSION: the serial
   PI handoff wake never traverses the home-preempt decision at all — stop mutating
   that path.
   **ROOT CAUSE FOUND 2026-07-19 (path census, tag `archive/lockpi-path-diag`):** PI
   handoff activations arrive WITHOUT ENQUEUE_WAKEUP — 114k flagless "continuation"
   enqueues vs ~5 flagged wakes per arm. rt-mutex re-activates the granted waiter
   via dequeue/enqueue, not ttwu, so cake's wakeup-bit router classes every serial
   handoff as a hot continuation: home queue, no kick, no preempt, invisible to
   global pickup. Mutation I (reclass flagless enqueues with raw deficit d<0 as
   wakes) FALSIFIED −88%: the granted waiter runs so often its vtime hugs the
   frontier, so depth never matches; the rule instead caught unrelated deep flagless
   enqueues and hurt guards. CORRECT DESIGN (next session): a 1-bit quiescent marker
   — set in ops.quiescent, cleared on enqueue — so "was dequeued asleep" reclasses
   the activation as a wake regardless of flag; no vtime heuristic, no identity.
   Census infra: tag `archive/lockpi-path-diag` (PATH_DIAG map + loader print,
   reusable for any workload by editing the comm filter — `git checkout -b <name>
   archive/lockpi-path-diag` to revive it). Commits 4fa35144a/5a279ef03/
   86e84b1c3 reverted in history.
   **Quiescent marker (mutation J) FALSIFIED 2026-07-19:** lock-pi UNCHANGED — the PI
   dequeue also bypasses ops.quiescent, so the bypass is SYMMETRIC (no wakeup flag in,
   no sleep notification out); and merely REGISTERING ops.quiescent at stage 0 cost
   stress-ng-futex −84% (core fast-path interaction — never register quiescent
   casually). CONCLUSION: lock-pi is unfixable from inside the scheduler — it is a
   sched_ext SEMANTIC GAP. KERNEL-LANE ITEM (standing direction 3): patch
   kernel/sched/ext + rt-mutex so scx ops see PI handoff re-activations (a wakeup-
   equivalent enqueue flag or a dedicated callback). Until then lock-pi stays an
   accepted known loss; census tooling stands ready to verify any kernel patch.
   Commit f066ed46d reverted in history.
   **CENSUS V2 OVERTURNED THE FLAGLESS THEORY (2026-07-19):** the 114k activations DO
   carry the wakeup flag — lock-pi PINS its workers, so nr_cpus_allowed==1 excludes
   them from the wake path, they land in the owner-queue insert with no preempt, and
   no other CPU may steal a pinned task: a pinned wake behind a busy occupant waits
   out the occupant's slice. MUTATION K KEPT (commit f30cac430): pinned-user-wake
   preempt by raw sleep depth — lock-pi −86.6 → −71.8 (8-block trusted CI
   [−72.5,−70.9]), first movement ever; guards clean vs same-regime baseline
   (schbench −8.3 vs baseline −9.6, pipe +10.2, mutex-handoff +6.9). K2 margin dose
   (slice/2→/16) null — the −72 plateau has a different residual; census it next.
   FUTEX GUARD PENDING: unmeasurable 2026-07-19 (P0 bug below); K is structurally
   inert for unpinned futex workers. Game gate also pending before ship.
   **P0 STABILITY BUG (pre-existing, found at BASELINE):** kernel scx watchdog
   ("watchdog failed to check in for 5.001s", ext.c:3498 — the watchdog KWORKER
   starves) kills cake under futex storm + heavy desktop noise; reproduced 3× on
   2026-07-19 including untouched baseline. Investigate with the census (comm filter
   kworker) — pinned-kthread service under storm is the suspect. Counterpoint same session:
   mutex-handoff (condvar+mutex handoff p99, the Wayland-input shape) cake +10.3%
   CI[+9.1,+12.6] — the desktop-input hypothesis validated.

**Pending game gates:** det4 RT-dodge frametime A/B not yet run; cake-ring rewrite's
clean-window game confirmation still pending.

## Research arc (what's adopted / parked / frontier)

- **M-DBLS: REJECTED** (task-storage cost +4.4%; learned preemption kick explosion +174%;
  adaptive slice reproduces the cache/memcpy trade). Infrastructure retained compile-gated
  at stage 0. → `docs/archive/MDBLS_EXPERIMENT_2026-07-11.md`
- **FTOA broad admission: PARKED.** Protected finding: qmark+exact-depth (pipe +4.6% under
  wake pressure, worst −7.9%). Prescribed next step: WAKE_SYNC-partitioned qmark+exact gate.
  → `docs/archive/FTOA_RESEARCH_CONCLUSION_2026-07-12.md`
- **CAPE: CURRENT FRONTIER.** EEVDF-style lag/eligibility/virtual-deadline service law +
  Cake custody; CAPE-Q grouped approximation in `experimental/cape_qfq_s1/`. Offline proofs
  only — H1 (clean perf proof) → I0 (IRQ shadow) → S0/S1/S2 ladder entirely unrun.
  Known deferred bug: lost-update race in `cake_running()` frontier max update.
  → `docs/archive/CAPE_MASTER_ALGORITHM_2026-07-15.md`

## Harness (verified 2026-07-17)

Score-bearing execution is quarantined except the **exact-pair broker**, generalized
2026-07-18 to a workload registry (`bench/scx_cake_exact_pair_broker.py` WORKLOAD_SPECS):
`bash cakebench artifact ensure` → `native-pair --receipt-b <receipt> --workload
{perf-sched-pipe,schbench-light,ccm-memcpy,ccm-cache,...} --readiness` → `--execute`.
Sign convention fixed: b_good_delta_pct is positive-is-better for BOTH metric directions
(the two 2026-07-18-morning ccm analyses on disk predate the fix — flip their sign).
BPF gotcha: helpers called from the 1024-unrolled steal loops must be GLOBAL functions
(non-static __noinline); static → E2BIG at load.
**Sudoless invariant (audited 2026-07-18):** every operation runs as the owning user;
the only elevation is `sudo -n` (non-interactive, can never prompt) to the scoped
NOPASSWD helpers (setcap, scheduler-runner, scxctl get/list/stop). NEVER ask the user
to run sudo, even one-time installs. New suite-local workload tools do NOT get installed
root-owned — register them via the broker's `fixed_user_tool` path (under bench root,
chmod 0555, sha256 sealed into the plan and re-verified per arm). New latency workloads
registered this way 2026-07-18: `mutex-handoff` (condvar/mutex handoff p99, the
Wayland-input shape; `source/mutex_handoff.c`) and `futex-lock-pi` — sealed pairs not
yet run.
**Receipt archival (2026-07-22):** superseded receipt builds no longer accumulate in
`target/cake_receipt_builds` (was 160G / 75 dirs). `bench/scx_cake_receipt_archive.py`
seals each stale dir's hash-verified evidence (~91M: receipt, binaries, logs, manifests,
source snapshot) into `scx_cake_bench_assets/receipts/<txn>/` + a content-addressed
`crate_pool/` (.crate dedupe), appends `receipts/index.jsonl` lineage row, then prunes
the derivable bulk (vendored sources, cargo-target, worktree — all recomputable from
kept evidence). `artifact ensure` runs it automatically (best-effort, non-fatal); the
live boot+HEAD dir is never touched. Fail-closed: nothing pruned without a sealed
`archive_manifest.json`; pruned dirs keep evidence in place plus a `PRUNED.json` pointer.
The `scx-cake-bench` MCP may be disconnected; offline corpus queries:
`history/source_store/scores.jsonl`, `history/ml_suite/change_attempts.jsonl`,
`./cakebench history report|query|learn`, `./cakebench levers`.

**Velocity rules (maintainer direction 2026-07-18 — the work is CODE CHANGES; measurement
serves them, never the reverse):**
1. **Two-tier evidence.** Screen every mutation at `--blocks 2` (~7 min, diagnostic_only
   tier — enough to condemn a null); pay the full 8-block confirmation ONLY for keeps.
   Most mutations are nulls; stop buying trusted-tier evidence for them.
2. **`--smoke` before any new workload's first transaction** (`native-pair --workload X
   --smoke`): one non-scoring run on the live scheduler validates tool/argv/parser in
   minutes. Never let a harness mistake fail a 20-minute transaction again.
3. **Time-box harness work** to what blocks a named measurement; defer everything else.
   A session's primary output is scheduler mutations tried, not harness capability.
4. **Doc tax cap:** STATE delta + memory per session; dated study docs only for
   completed arcs.
5. **Pipeline, don't pause (2026-07-19).** Measurement windows forbid builds/agents/
   repo edits — but they do NOT forbid thinking. The session pattern is:
   (a) BUILD PHASE: design, implement, commit, and receipt-build SEVERAL candidate
   mutations up front (each its own commit; receipts are cheap and coexist);
   (b) MEASURE PHASE: one background script runs the whole verdict queue back-to-back
   — zero gaps between transactions;
   (c) DURING captures: write next-experiment designs and analysis of ALREADY-SEALED
   data to the scratchpad (outside the repo, negligible CPU — lawful), never idle;
   (d) on each verdict, the next candidate's receipt already exists.
   A session that waits on one verdict before designing the next mutation is
   running at half speed.
Remaining tier-2 gaps: no quiet-window job queue (would automate phase b);
one workload per transaction.

## Standing directions from the maintainer (2026-07-17)

1. **Noise is a covariate, never a gate.** Runs proceed under any noise regime; per-arm
   noise (class, external CPU, top processes) is sealed into every row so the
   noise→score relationship is itself learnable for cake AND native EEVDF.
2. **OS-behavior discovery.** The harness should keep learning what else runs during
   benchmarks/games and how it moves scores — the long-term scheduler goal is not only
   accelerating the foreground but *discovering* non-mission-critical background work
   that can be slowed (generalizes the criticality-scoped-protector line from the
   2026-07-09 studies).
3. **Kernel-level escalation.** When scheduler-side levers hit a wall, developing kernel
   patches / new or changed sched_ext kfuncs is in scope to push performance further.
   Kernel tree at `~/Documents/Repo/linux` (matches running kernel); sched_ext core in
   `kernel/sched/ext/ext.c`.

## 2026-07-20 overnight session (true-Rq window) — MODE DISCOVERY + S1 CONFIRMED

**Futex has host-state MODES (same code, same boot, same kernel, native flat 3.0M):**
pre-S1 code read 4.73M on 07-18 (the sealed +57.2), 0.35M under 07-19 Rc, and 1.42M
on 07-20 quiet morning — a within-boot, within-regime mode shift with unknown host
variable (extcpu identical 3-5%; ctxsw signature: winning mode 283M switches, losing
mode 84M — wakes stall behind occupants). ALL pre-S1 heads (pre-K, K, K+L, K+L+M)
read −52% identically; commits exonerated by byte-identical-diff control. The sealed
+57.2 scoreboard entry is MODE-CONDITIONAL; treat historical futex deltas as
mode-tagged, not code-tagged.

**S1 (cadence-proportional sleeper depth, 0ce54fb27) is REAL: +65pt futex recovery**
(1.4M→3.3M, 3× reproduced; 8-block confirm +12.2% CI[+10.1,+13.1] vs native in
today's mode). Mechanism per observed pair: cake serves 100M wakes vs native 70M,
p999 wake→run 6 µs vs native 990 µs (p50 trade 1.56 vs 0.8 µs); migration rate 4.1%
vs 0.3% and still wins. Rare ~0.5-1 s max outliers remain (P0-adjacent, few counts).

**Full Rq screen of HEAD stack (K+L+M+S1), 2-block vs native:** lock-pi −1.21
(from −86.6 — N5b resolved: plateau was regime+mode), pipe +22.2, ccm-cache +49.8,
schbench-sat +49.8, ccm-memcpy −12.8 (unchanged gap), schbench-light −2.24
(8-block TRUSTED CI[−2.41,−1.92]; ~0.8pt worse than pre-stack −1.42 = current cost
of the stack), mutex-handoff −6.8 wide-CI (8-block pending). Bisect within the
stack: L neutral on futex; M +10pt; S1 +55pt.

**Full-coverage screens of HEAD stack completed 12:15Z (2-block, vs native, quiet):**
mutex-handoff +0.57 [−1.96,+2.75] 8-block (the −6.8 screen was noise — TIE);
fork +9.99, thread +8.14, stress-ng-cache +34.3, stress-ng-memcpy +3.83,
blender-render +0.37 [−0.16,+0.89] (down from sealed +11.9 — mode-tag caution,
not a loss). Every registered workload is now screened against the stack: the
only losses anywhere are schbench-light −2.24 (trusted, frontier price) and
ccm-memcpy −12.8 (M5/M6 input-starved).

Pending gates unchanged: game gate before ship; golden-mode (4.7M) host variable
unidentified — next lever for futex is finding/forcing that mode.

## TOP TARGET (2026-07-19): contention collapse — cake's wins are regime-conditional

Covariate evidence (mutation L survival runs, exact_pair 2026-07-19): with UnrealEditor
holding ~3 cores, native runs futex at 2.05M ops/s AND gives the editor 260-295% CPU;
cake collapses to ~350k ops/s (−82%) AND starves the editor to ~50%. Yesterday's futex
+57% was a light-desktop result. Under external compute pressure the wake-global
architecture degrades to slice-cadence service (same mechanism as the P0 192 ms kworker
tails and the schbench-light −1.4→−9.6 regime deepening). The wake-service Pareto
frontier conclusion is REGIME-CONDITIONAL — re-open it for the contended regime with
per-regime evidence. P0 watchdog fix (mutation L, all-kthread local insert, commit
f40192df5): 3/3 storm survival, KEPT pending quiet-regime score check + game gate.
Next: observed pairs across a controlled load ladder (idle → 1-core → 3-core external
compute) to map score-vs-contention curves for cake AND native on futex/pipe/schbench —
then design bounded wake service for the contended regime with the census/graph method.

## Research roadmap (adopted 2026-07-18 — the breakthrough plan)

Diagnosis: every past breakthrough changed the decision STRUCTURE (ring rewrite,
hybrid4, herd-break); knob-space at the current altitude is harvested (corpus keep-rate
~44% for two families, ~0 elsewhere). Months without a breakthrough = no new signal at
the searched altitude. Five directions, ranked:

1. **Decision-level evidence (observatory layer 1 — BUILD FIRST).** Aggregate scores
   average ~10M decisions; the lever hides in WHICH decisions lose. Tracepoint outcome
   stream (wake→run latency, placement survival, post-switch cache) for cake AND native
   on the same workload; cluster cake's losing moments. Precedent: ccm cracked in one
   evening (share attribution) after weeks of aggregate "unfixable".
2. **Offline replay search.** Record per-benchmark traces (wakes, run lengths,
   dependencies); replay under parameterized policies in a simulator that only needs
   rank-preservation; search thousands of candidates/hour, nominate survivors for
   sealed pairs. Formula discovery beyond human enumeration.
3. **New inputs beat new arithmetic.** Cake reads EEVDF's inputs (queues/vtime/run age)
   → EEVDF-equivalent trades. Unexploited: per-task memory-boundness (PMU kfunc —
   kernel lane justified), wake-graph topology (pipeline vs herd), run-length
   distributions, SMT sibling state (+73% memcpy efficiency proven behind it).
4. **Benchmark where headroom is large.** Microbenches are EEVDF-near-optimal (ties
   correct). Real-PC wins live in interference: foreground latency under kbuild,
   app-launch under load, game+background. mutex-handoff (Wayland-input shape) was
   step 1; build a desktop-responsiveness composite next.
5. **Inversion audit.** Past breakthroughs end falsification chains with an inversion.
   Enumerate every current default (own-first dispatch, global wake queue, sleeper
   clamp 1 slice, 3ms slice, steal order, preempt margin) and 2-block-screen each
   opposite that has never been tried — one evening at ~7 min/screen.

## Next harness milestone: the decision observatory (designed 2026-07-17)

Path-for-path cake-vs-EEVDF comparison in three layers: (1) scheduler-agnostic outcome
stream from sched tracepoints — wake→run latency, missed-idle rate, placement survival,
post-switch cache behavior — identical metrics for both schedulers, rows beside the
score; (2) internal attribution — `bpftool prog profile` per cake callback vs
kprobe/fentry histograms on `select_task_rq_fair`/`pick_next_task_fair` etc., plus
fallback-frequency counters both sides; (3) render-bubble attribution — sched_switch +
GPU fence tracepoints splitting scheduling bubbles (ours) from pipeline bubbles
(upstream), wake-chain attributing each preemptor. RT reality: RT runs above sched_ext;
handling = dodge placement (validated det4), userspace config (PipeWire quantum/rtkit),
or the kernel-patch lane (kfunc exposing per-CPU RT pressure to scx).

## Recommended order of attack

1. Observatory layer 1 (roadmap #1) — decision-level outcome stream; first target:
   schbench-light −1.4% (two blind knob doses already null; needs attribution).
2. Inversion audit sweep (roadmap #5) — cheapest possible breakthrough scan.
3. Replay-search prototype (roadmap #2) on the pipe/futex traces.
4. Per-task duty classing for SMT pairing (roadmap #3; per-TASK, handoff-exempt —
   the v3 per-CPU veto's futex regression is the constraint) and the PMU kfunc lane.
5. Desktop-responsiveness composite benchmark (roadmap #4).
6. Game gates before anything ships (unchanged, hard constraint).
