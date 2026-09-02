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
2026-08-25: PR #3767 merged upstream (`4a2ab1fce`) with ALL of nightly's scx_cake
content (subtree hash identical) — nightly reset onto upstream/main; pre-reset state
in `backup/nightly-pre-rebase-20260825`; origin fork NOT yet force-pushed.

</details>

---

## RESUME HERE

**PICKUP 2026-09-02 11:30 — VELOCITY SESSION: 14 constructs g60-g73 built and
snippet-scored against crate 1.1.3 at the KovaaKs menu. Best arm ties 1.1.3 on
1% low / p99 / p99.9 and trails 2% on average fps. Machine on EEVDF, KovaaKs
left open at the menu. Every diagnostic probe (placement census, hold attribution by queue
kind, home-decline reasons, the hitch black box) is gated behind `--toggle
probe=1` and costs nothing off; the winning stack (g65, g69, g71, g75, g77, g79, g81; g76 and g80 are
unconditional) is the DEFAULT, each switchable off with `--toggle gNN=0`; the
experiments (g60-g64, g66-g68, g70, g72-g74, g78, g82) default OFF.**

Rig: `runs/overnight_game_20260901/snip.py <arm> <arm> [<arm>]` — mirrored
slots of `LOG_S` s MangoHud logging driven over the control socket, arms attached
directly from their receipts; `LOG_S=8` for a 50 s screen (1% low, p99 only),
`LOG_S=20` for a 95 s read that can see p99.9. Wake-side tools:
`sib_overlap.py`, `hold_timing.py`, `bench/wake_maxdecomp.py`, the probe census
(`--toggle` on the probe receipts). Diagrams: `runs/overnight_game_20260901/
diagrams/` (nightly pipeline with measured shares, 1.1.3 pipeline, hold timeline,
ledger).

**Mechanism, in the order it was proven.** (1) Nightly runs game threads with a
busy SMT sibling 6.2-6.6% of their run time (1.1.3 1.2%, EEVDF 0.8%); the census
placements (§G53 first-fit, §G54 park) bypass the §G38 whole-core rule. (2) Wake
latency p99 is NOT the gap (nightly equal or better than 1.1.3 per role); the gap
is HOLDS: every render-path delay >300 us is one occupant keeping the CPU for the
whole wait (RenderThread 1 ms, kwin 1.6 ms), 1.1.3 has zero on RenderThread /
dxvk-submit / dxvk-cs. (3) 100% of nightly's wake placements are LOCAL_ON direct
dispatches (home claim 74%, census prev 20%, first-fit 5%); holds sit there, and a
local DSQ is FIFO and owner-only — nothing can steal it. (4) Holder timing: in 80%
of long holds the holder was already running when the wake landed; the wakee was
placed onto its busy peer. Only CLAIMED placement removes it. (5) IPC: 1.1.3 1.55
vs every 1.2.x arm 1.48, +3% cycles for -2% instructions; not SMT (0.4% overlap
under the best arm), not yield (1.1.3's handler is telemetry). OPEN.

| toggle | construct | snippet vs crate 1.1.3 (1% low / p99.9 / avg) | verdict |
|---|---|---|---|
| g60 | whole-core census placement | sibling-busy 6% -> 0.3%; 60 s cycle +30 on 1% low, 15 s cycles mixed | keep as a piece |
| g61 | occupant preempt after insert | null (CPU idle at insert) | drop |
| g62 | census placements claim (atomic) | holds -40%, avg -3%, p99 worst | drop |
| g63 | pool only, no direct dispatch | tail fixed (max 2.1), avg -6% | floor, not a ship |
| g64 | dfl claimed direct + (g65) pool | tail fixed, avg -5%; g64 alone shows the loss is the kernel pick | drop |
| g65 | every enqueued wake global, herd gate off | null alone (enqueue reached by 2%) | needed under g69 |
| g66 | serial handoff arm off | null | drop |
| g67 | census direct paths off, home claim or pool | avg -4%, tail unchanged | drop |
| g68 | EXPERIMENT: KovaaKs tgid VIP (ENQ_PREEMPT, pool head, kick) | 1% low 489 vs 504 off, p99.9 2.34 vs 2.17: self-preemption | negative, learned |
| g69 | **claimed warm placement**: prev claim, whole idle core claim, idle thread claim, else pool | 555 / 1.90 / 684 vs 563 / 1.87 / 699 | **best** with g65 |
| g70 | EXPERIMENT: KovaaKs immune to preempt kicks | null: nothing preempts the game at the menu | learned |
| g71 | idle-side published core/thread words; (d) words choose, kernel bit claims | (a)-(c) leaked tail; **(d) 560 / 1.88 / 685 vs 562 / 1.87 / 700** | **best**: g65+g69+g71d |
| g72 | L2 handoff: same-mm microsecond wakee onto the waker's idle sibling | null on top of g69 | park |
| g73 | distributed claim search from the task's core | 543 / 1.95: negative | drop |

**FIELD RESULT 2026-09-02 evening — Lestat, 9950X3D, DOOM: The Dark Ages
(Uprising), single run each, game lassoed as before. Nightly default build
(g65/g69/g71/g75/g77/g79/g81 on; build identity + kernel still to be confirmed
from his log): 97th 205.55 / avg 170.64 / 1% low 112.03, vs stock 1.2.1
208.44 / 155.45 / 96.79 and crate 1.1.3 208.52 / 170.45 / 113.48. The
regression is repaired in full (+9.8% avg, +15.7% 1% low); level with 1.1.3
inside single-run noise, not ahead. Owed: his identity lines, a second run each,
then the per-LLC pool port onto nightly (§S.8 shape over the g65 pool) — the
piece 1.1.3 still has on two CCDs — and §G52 V-cache preference for unpinned.**

**12:30 UPDATE — g74-g79. The g79 stack (g65+g69+g71d+g75+g76+g77+g79) BEATS
crate 1.1.3 on every column when it does not hitch, 20 s slots ABBA x3
(6 slots/arm): 1% low 578 vs 562, 0.1% low 530 vs 484, p99 1.686 vs 1.708,
p99.9 1.783 vs 1.856, max 2.2 vs 3.3, avg 702 vs 698.** Two of five g79 slots
took ONE 45 ms frame: the FIRST frame of the MangoHud log (elapsed 0.34/0.49 s),
i.e. the CSV-create on the render thread — the wake after that IO is what g79
mishandles; ~2x WAKE_STARVE_WALL_NS. Not reproduced in 9 hunts with perf
recording (`hitch_hunt.py`, `hitch_scope.py` ready). Cake was attached for the
whole of every slot (attach logs end in the clean detach line, nr_rejected 0;
`snip.py` now prints SCHED GONE if not). OPEN, must be closed before g79 ships.

| toggle | construct | read | verdict |
|---|---|---|---|
| g74 | published-burst stacking (queue behind prev when §G57 free_at within 40 us) | avg 680, tail no gain: slice/2 is not a burst | drop |
| g75 | **grooves**: per-task home-miss count skips a failing home claim; last-won CPU tried first | no avg change alone; **with it off the stack collapses (1% low 477, p99.9 2.36)** — the history IS the tail | keep |
| g76 | lean dispatch (counts before iterators/moves), one groove lookup, cpu_idle tracepoint only for g51 | dispatch 120 -> 87 ns; the mark-only fast path stalled the game 20 ms (mark has holes) — pool by COUNT | keep |
| g77 | steal ring skipped on an empty qmask (census-bit contended test tried: stale in the wake-list window, dropped) | equal | keep |
| g78 | rotor on the first whole-core claim + last_win as cpu+1 | 1% low 492: spreading is wrong here | drop; the cpu+1 encoding stays |
| g79 | **seat hold**: a blocking stage-class thread keeps its core; other wakes skip held cores while any other is free | the win above; GameThread migrations were 12,629/28 s vs 1.1.3's 650 | keep, hitch OPEN |

Why the average was behind (thread_cores.py, 1.1.3 vs stack): 1.1.3 GameThread
650 migrations, stack 12,629 — a dxvk/render wake took GameThread's core in its
microsecond gaps and it came back cold 450 times a second: branch misses +34%,
IPC 1.456 vs 1.553. Cache hit rates identical (L1d miss 2.8%, LLC 0.0%), IRQ
identical (nvidia 7.8k/s CPU 13), GPU identical (77%, 2745 MHz).

BPF self-cost (cake-bpfstats, 12 s menu): 1.1.3 96 ms (0.8% CPU: select 58 ns,
dispatch 20, running 26); nightly-off 260 ms; g77b stack 274 ms (select 116,
dispatch 79, update_idle 33, running 58). The remaining average lever is here:
select_cpu's groove storage lookup + rq deref + claims, update_idle's three
atomics, running's frame observe. A symbolized cycles profile needs
`kernel.kptr_restrict=0` (currently 2; module space hides nvidia.ko with the JIT).

Tools added this session (all in `runs/overnight_game_20260901/`): `snip.py`
(one-minute mirrored MangoHud snippets from receipts), `sib_overlap.py`,
`hold_timing.py`, `thread_cores.py`, `sys_ab.sh` (cache/balance/IRQ/GPU),
`hitch_hunt.py` + `hitch_scope.py`, `diagrams/`. Inventory: `docs/TOOLING.md`
(docs/ is gitignored; on disk).

Next: (1) close the g79 hitch (catch it without perf: bpftrace on the render
thread's wake at log start, or make snip.py record the seat word at attach);
(2) BPF self-cost: symbolized profile, then cut select_cpu to one storage
lookup + one claim, update_idle to one atomic; (3) fold the stack into defaults
once (1) closes, then the wallclock guard (`fast_ab.sh`) and a 60 s cycle.
Probe branches: `probe/overnight-20260901-g63` (arms), `probe/g70-arm`.

**PICKUP 2026-09-02 02:30 — OVERNIGHT GAME ROTATION SCORED (maintainer-authorized
unattended run), machine left on EEVDF (detached), Palworld left at its menu.
Seven arms, every one a v5 receipt under `target/baseline_receipts/`: native,
`crate-1.1.3s` (b68cb3c82 = crate scx_cake 1.1.3 + the two 2026-07-28 dumpable
backports, scheduling identical), `stock-1.2.1` (c8728c6b6 = scx tag v1.1.3 =
Lestat's stock), `fix-s8` (f27950e9d), `n0901-off` (HEAD + census no-op),
`n0901-g57`, `n0901-g58` (defaults flipped). 14-slot mirrored cycles
(native A B C D E F F E D C B A native), order rotated between cycles.**

KovaaKs menu, 4 cycles, n=8/arm, 60 s slots, ~45k frames each, all 56 accepted
(`runs/game/kovaaks/2026-09-01-overnight/`, harness matrix):

| arm | avg fps | 1% low | 0.1% low | p99 ms | p99.9 ms |
|---|---|---|---|---|---|
| native | 745.8 | 658.8 | 400.4 | 1.523 | 2.498 |
| crate-1.1.3s | 746.8 | 650.0 | 399.1 | 1.542 | 2.507 |
| stock-1.2.1 | 708.3 | 561.5 | 386.5 | 1.802 | 2.588 |
| fix-s8 | 716.7 | 574.8 | 388.4 | 1.740 | 2.575 |
| n0901-off | 758.4 | 595.0 | 403.7 | 1.683 | 2.477 |
| n0901-g57 | 757.5 | 582.5 | 403.1 | 1.719 | 2.481 |
| n0901-g58 | 755.8 | 566.9 | 402.7 | 1.770 | 2.483 |

Cycle 1 slots 0-3 were a warm-up (690 vs 755 fps); dropping them: native 753.7 /
p99 1.488, crate-1.1.3 754.6 / 1.513, stock-1.2.1 713.4 / 1.722, fix-s8 717.1 /
1.742, off 758.4 / 1.685, g57 757.5 / 1.721, g58 755.8 / 1.772. Slot ranges do not
overlap between the 1.2.1 pair (702-726) and the 1.1.3/native/nightly group
(752-761), at every slot position, both orders.

**Reads.** (1) Lestat's chart reproduces on ONE CCD: 1.2.1 is −5.5% avg fps and
+0.2 ms p99 vs crate 1.1.3 at a 750 fps wake-bound menu, so the loss is not (only)
CCD-blindness. (2) fix-s8 == stock-1.2.1 here (one LLC = one pool), as designed;
the pool fix answers only the two-CCD strand. (3) Nightly recovers the average
(above native) but keeps a p99 0.17 ms wider than 1.1.3 and native — the
remaining 1.2.x gap is a tail, not throughput. (4) g57/g58 do not move the menu;
g58 is the widest p99 of the nightly arms (1.772, one 2.02 slot). (5) One 145 ms
frame on stock-1.2.1 (cycle 1 slot 2) and one 43 ms on native (cycle 3 slot 0):
single spikes on both sides, not a cake signature at n=8.

Palworld menu, 3 cycles, n=6/arm, 120 fps cap, GPU ~39%, ~7.2k frames/slot, all
42 accepted (`runs/game/palworld/2026-09-01-overnight/`): p99 flat 8.73-8.80 ms
on every arm; p99.9 native 9.80, crate-1.1.3 10.25, stock-1.2.1 10.08, fix-s8
10.91, off 9.80, g57 9.63, g58 9.67. Same ordering as KovaaKs at the tail (1.2.1
pair worst, nightly tightest) but 7 frames per 0.1% — direction only.

Noise covariate: FFXI server (`xi_map`) ~16% of one CPU + Discord ~6% for the whole
run, identical across arms. Display idle-dimmed from 23:40; captures unaffected.
Helldivers 2 was attempted and dropped: no `mangohud` launch option and Steam
ignored `-shutdown`, so no layer; Palworld took the second regime.

Rig: `scx_cake_bench/runs/overnight_game_20260901/` — `build_arms.sh`, `arms/*.json`
(receipt paths + hashes), `run_cycles*.sh`, `cycle_<game>_N.log` (per-slot JSON),
`analyze.py`, `stage_import.py` + `staging_map_<game>.tsv` (slot → capture file).
Probe branches local only: `probe/overnight-20260901{,-g57,-g58}`,
`probe/crate-1.1.3-scoreable`; worktrees under the session scratchpad and
`scx-baselines/v1.2.1`, `scx-baselines/v1.1.3-scoreable`.

Owed now: (1) the 1.1.3-vs-1.2.x p99 gap at the menu is the lever for Lestat's
single-CCD loss — bisect it (§G39-B' preempt, GAME class, tick wait bound are the
three things 1.1.3 has, §S.8 comparison); (2) a play-regime rotation (input-live)
before any of g57/g58 ships; (3) the 2026-09-01 owed list below still stands.

**PICKUP 2026-09-01 EOD — three published-state constructs BUILT on nightly
behind toggles, machine left on EEVDF (detached). Nothing scored: the box
carried the FFXI server + browser all evening and the strand rig read 30x
within-arm spread, so every number below is a liveness proof, not a result.**

| toggle | construct | live proof (strand rig, census at detach) |
|---|---|---|
| `g57` | earliest-free pick: `running` publishes `free_at`; a saturated wake scans its LLC mask and queues behind the CPU predicted to free first | saturated peer rig: 19,018 placements = 9.2% of selects |
| `g58` | frame pre-wake (§G28 built + a reservation): `stopping` arms a per-CPU BPF timer at the predicted wake minus lead; the fire reserves + idle-kicks the CPU; `select_cpu` takes the reservation first | idle rig: 14,173 fires, 6,997 takes (precise 1 kHz cadence, ungated); with the argmax-cadence gate the rig thread no longer arms and the box's 252 Hz cadence fires 6-7k/10 s, 0 takes at a 100 us window — window widened to cycle/16, retest owed |
| `g59` | idle-depth pick over the §G51 mirror (forces g51); §G58 reservations skipped by other tasks | attach-clean; INERT here (no cpuidle driver), first-fit by construction |

Wallclock fast ABBA ran the same evening (`runs/toggle_wallclock_20260901/`,
ledger rows G57/G58/G59/stack wc): g57 non-regressing with messaging −8.7%,
g58 inconclusive (one unrepeated 4.10 s pipe slot), g59 null, stack
non-regressing.
Owed, in order: (1) quiet-box strand rig ABBA off/g57 both modes (the latency
endpoint; messaging already passed); (2) g58 retest
with the widened window, then the tail question — two of four idle-rig on-arm
runs read p999 39 us vs off 13-15, always the first arm after a switch; (3) g59
ships to Lestat on the fix branch once (1) settles; (4) hardware audit (§G58/§G59
touch loader probes); (5) census probe revert before any scoring. Fix branch
`fix/cake-1.2.1-llc-overflow` unchanged at `f27950e9d`; today's review +
isolation data under §S.8.

**PICKUP 2026-08-31 — FFXI wake campaign (§G39-B'), machine left on EEVDF
(detached), two probe commits on top of `4951242a4`: `d38308fb3` (census,
revert before scoring) + `6e2653a8b` (§G39-B' behind `--toggle g39b`).**

Census run 20260831 (menu regime, 516k selects): `cake_wake_preempt` was
UNREACHABLE (wp_attempt=0) — home-routed wakees sit in tcpu's own local DSQ,
which no other CPU may serve, yet the notify short-circuited to an idle-CPU
kick that cannot serve them; the wakee waits out the occupant's whole slice.
The play-regime tails (wined3d_cs HOLD 1.6-2.4 ms, 100% of >1 ms events,
runtimes equal = not starvation) are exactly this shape. §G39-B' adds the
preempt attempt at the notify (route != GLOBAL) and in the continuation arm
(census iteration: wine threads ride the continuation arm, starved_turn false,
enqueue_wake never reached). Menu A/B ×2 (eevdf/cake0/cake1): g39b=1 NEUTRAL
at menu, migrations kept (5.4-6.4k vs eevdf 37-44k), 0 preempts fired (regime
too idle to hold >187 us behind a local wakee). Menu p50-p99 gap vs eevdf is
the BPF cost floor (sel 85.8 ns measured) — K2 lane, not BPF-side.

Owed: play-regime 9-min ABBA (fires the preempt — wined3d_cs holds are the
firable shape); pipe weld guard (blocks-2) BEFORE hardwire; iteration-3 knob
if the protect window binds at play: PREEMPT_PROTECT_SHIFT 4 -> 7.
Data: `scx_cake_bench/runs/ffxi_wake_20260830/PLAN_G39B.md` +
`history/wake_latency/ffxi{2,3}-*` + runner logs `g39b2-*`.

**PICKUP 2026-08-21 EOD — machine left on EEVDF, nothing attached, all
background jobs stopped.** Code tip `60b238311` (§G38.1-repaired + §G40; §G39-B
aborted), tip receipt `20260821T155506Z_head-5e0e8244b21a` built + attach-tested.
Three staged actions, in graph-cut order:
1. **R1 rotation** (needs KovaaKs being played, ~3.5 min):
   `bash runs/rotation_r1_staged/r1_rotation.sh` — 3-arm native/G38/tip; draws
   the tip's chain lane, scores §G38.1+§G40 (GameThread p99 128 → toward 6?).
2. **E4a pinned chain3 split** (no game needed, ~3 min): rerun
   `runs/causeb_chain3_20260821/ab.sh` (bug fixed) with stages pinned —
   separates BPF-text pollution from migration-cooling; decides E4's shape.
   Cause B front-end signature already CONFIRMED preliminary (ledger below).
3. **E1 in-game per-thread counters** (`runs/frontend_ipc_20260821/`) — the
   game-side confirm; optional `sudo setcap cap_sys_ptrace+ep /usr/bin/perf`
   first for kwin tids.
Board (live, movable): claude.ai/code/artifact/98701cdf-e541-48c5-8dfc-07109a311dbe

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
| 12 | **G37** adaptive switch-cost floor (`cake_handoff_max_ns`) | registered 2026-08-20, §G37 | build Phase A: observe-only gap EMA, publish nothing, confirm ~1464 convergence on this host |
| 13 | **G38** fully idle core outranks a cache-warm thread | **SCORED 2026-08-21** (live KovaaKs ABCCBA native/base/G38, 25 s slots): chain p50 19.25 → 18.42 µs (native 14.85), doubled cores 0.255 → 0.20 (native 0.04), game IPC 1.108 → 1.150 (native 1.263) — all three endpoints move the right way; ~¼ of the chain gap closed. PARTIAL WIN, KEPT | remaining doubling is `kwin_wayland` (sib-busy ~32%, untouched by G38's sites); next lever picked from the input-pipeline board. Data `runs/g38_idlecore_20260821/`. §G38 |
| 14 | **G38.1** core preference at the raw-pick sites + serial arm | BUILT `ab57ba40a`; **guardrail FIRED**: mutex-handoff **−69.3% [−91.3, −47.3]** — the serial-arm core veto exiled handoff pairs; **veto withdrawn `bd54a03df`**. Attribution pairs 2026-08-21: today's mutex reads −9..−26% on EVERY build incl. pre-G38 `51ee88b21` (−12.5 [−18.4, −6.7]) — mode variance, not a build residual; only the veto's −69.3 stood clear | 3-arm game rotation draws the tip's chain lane. §G38.1 |
| 15 | **G39** chain-successor handoff (construct) | Phase A census PASSED (~100× floor); **Phase B ABORTED `60b238311`** — pipe −36.8% [−42.1, −31.5], ctx +45.9% (§R.6 weld; pipe is SYNC ping-pong); mutex/schbench unaffected isolates the SYNC condition | Phase B' needs a wine-RPC vs data-stream discriminator before retry. §G39 |
| 16 | **G40** kick the idle home (E7 find) | registered + BUILT 2026-08-21, §G40 | `cake_home_notify` `!live` remote branch now kicks tcpu; gates, attach-test, rides the same rotation |
| 17 | **G41** wake-queue occupancy mark | BUILT `1b957daca`, screen PASSED 2026-08-21 (+48.2 vs baseline +41.3, diagnostic), §G41 | game screen: rides the next rotation (R1 already staged covers the tip once rebuilt) |
| 18 | **G42** vtime mis-charge + missing per-CPU wall net | mechanism grounded in source, FIX BUILT (task-CPU slot indexing), repro 3× null, 2026-08-21, §G42 | SOAK: fixed cake attached through normal use with an exit watcher; wall-clock net for per-CPU queues stays open as the second half |
| 19 | **G43** going-idle hint claim (predict-verify audit C1) | registered 2026-08-22, §G43; audit `docs/AUDIT_PREDICT_VERIFY_2026-08-22.md` | build, then on/off `--blocks 2` screen: mutex-handoff + perf-sched-pipe (weld guard) |
| 20 | **G44** qmask answers wake-routing emptiness (audit C3) | wallclock NULL 2026-08-22; **CODE REMOVED 2026-08-23** (toggle audit) — the emptiness question belongs to the M4 consolidation program when it runs | closed |
| 21 | **G45** event-complete idle census for the serial gate (audit C5) | BUILT `0ef821db8`; wallclock lean-positive 2026-08-22 (pipe −3.8, messaging −1.7, memcpy −0.2, all overlap); in the stack winner | sealed `--blocks 2` on the stack config; all-off vs old-tip A/A owed (callback registration cost). §G45 |
| 22 | **G46** departing-slice cache, pid-tagged, per-CPU (audit C4 reshaped) | BUILT `61589428c`; **the campaign's one separated result**: memcpy −7.8% SEPARATED in singles, −5.4% SEPARATED in stack; pipe/messaging lean-positive | sealed `--blocks 2` (ccm-memcpy + mutex-handoff), then game screen — a stale slice is geometry, not just cost. §G46 |
| 23 | **G47** ISR-successor kthread keeps the IRQ CPU | falsified at the KovaaKs frame gate 2026-08-23 (severe frames doubled, zero wake benefit warm); mechanism real only at deep idle; **CODE REMOVED** (toggle audit) | closed — revisit only with §G51 depth model live |
| 24 | **G48** hint-first main placement (component audit) | **CODE REMOVED 2026-08-23** (toggle audit; counter too). History: **LOADED SCREEN FAILED 2026-08-23** (counter `29c18b379`, clean pair): hint word nonzero on 51% of wakes, claims 1.33M/3.54M attempts (37.6%/attempt, 19%/wake), net select_cpu 195→212 ns — claim-FAIL overhead (62% of attempts pay gates + failed test_and_clear + full scan) exceeds hit savings. Toggle stays off. Decision gate → census-claim (§G50 shape) with cheap-fail ordering: census bit read FIRST, gates only behind a set bit | **CLOSED 2026-08-23, all regimes measured**: idle-regime 74.1% claim rate but sel 140 vs 132 ns — the scan a hit skips is already cheap at idle; loaded +17 ns (claim-fail overhead). Mechanism verified, no cost regime exists; §R.29's push principle stands but the mailbox buys nothing. Toggle stays off |
| 26 | **G50** census: claim ABORTED, zero-skip survives (maintainer autopsy) | **claim half ABORTED 2026-08-23, structural** — sel 179→264 ns/call; 84% attempt rate, 17.8% claims; autopsy: no winning regime (light load: scan already cheap; heavy: census empty, gate suffices; middle: contested stale bits → pay both). Gates (~75 ns) approach the scan they skip (109 ns). Walk code REMOVED; zero-skip (census==0 → skip both scans) stays under `--toggle g50`, untested — census never empty under this load | **zero-skip WINS its regime (first pass 2026-08-23)**: schbench-saturated sel 213→73 ns/call (−66%), request p99 −19% first pass DID NOT REPLICATE — BAAB mirrored: sel 200→63 ns SEALED (53/73 vs 195/205, separated), req p99 183.3 vs 172.5 ms inside slot spread 156–192 (variance-dominated, TIE). Callback win real; workload win unproven, needs overnight slot count |
| 29 | **G51** idle-depth model (maintainer-directed) | **BUILT** behind `--toggle g51`: tp_btf/cpu_idle writes cstate into cake_irq_live; loader reads cpuidle exit latencies into rodata; consumer PENDING (census-claim ordering removed with the §G50 abort; next consumer = escape/exile pricing). **INERT ON THIS HOST — cpuidle current_driver is `none`**, degrade verified (logged, attach unaffected) | needs a cpuidle-enabled host or kernel config change (maintainer call) to measure |
| 30 | **G52** preferred-core rank (maintainer-directed) | **BUILT** behind `--toggle g52`: loader reads acpi_cppc/highest_perf per CPU into rodata; consumer PENDING (census-claim tiebreak removed with the §G50 abort). CPPC live on this host. cpuperf_set half DEFERRED: governor `performance` pins 5.53 GHz, unmeasurable here | screens with g50 arm |
| 31 | **M7** runqueues percpu-ksym direct reads (maintainer audit, 13th pass) | **BUILT `28a1b1839`** behind `--toggle m7`; ksym resolves + verifies (probe question answered). First pair INCONCLUSIVE: on-arm ran first and caught noise (p99 0.90 vs 0.63), deltas +8..+15 ns inside the asymmetry — expected effect below single-window sensitivity, same lesson as §M6 | composed m6+m7 mirrored ABBA (clean, 4 slots): sel −4, enq −3, disp −1 ns — coherent direction on every callback, ~1 ms/s total, below hardwire threshold. Both parked toggled off; revisit when the queryless path completes (K1 + F14) |
| 32 | **K1** chronic-sink accounting L3→L2 (maintainer audit, 14th pass) | registered 2026-08-23 | handler-duration accumulation on the existing IRQ edge progs (stamp+subtract, owned line); event-driven window decay (no tick — roll on large stamp gap); BPF bumps cake_sink_gen on flag flip; deletes the loader poll + 1 Hz staleness. ~+20 ns/edge, screen once. K2 (fused kfuncs) + K3 (occupant facts as ops args) are PATCH-GATED options on the maintainer kernel; N1 (core DSQ-emptiness push replacing qmark) recorded, not built |
| 27 | **M2** frame-clock trio is dead plumbing (maintainer audit) | VERIFIED 2026-08-23: cake_frame_ns/floor/slice have zero BPF readers (decl-only; §G11 comment admits it); votes still paid on display threads | decision: demote voting to loader-side telemetry or land a consumer; separate commit + wallclock screen |
| 28 | **M6** occupant mirror — subscribe, don't query (maintainer audit) | **BUILT `9f344d8da`** behind `--toggle m6`; first mirrored ABBA: NULL on the one clean pair (select_cpu 187=187 ns, no coherence tax; slot 3 noise-contaminated) — the deref chains were warm-line cheap in the appsim regime | park pending a quiet-machine screen; handoff_yields stays on deref (needs live sum_exec) |
| 25 | **G49** core-contended via idle-smtmask (component audit) | registered 2026-08-23; same audit | build behind toggle: smtmask bit replaces the sibling cpu_curr deref; A/A + wallclock |
| 33 | **G57** earliest-free pick (published `free_at`) | **BUILT 2026-09-01** behind `--toggle g57`; live: 9.2% of selects placed on the saturated rig; `enqueue` 2→4 static spills (both arms in object). **Wallclock fast ABBA PASSED same day: pipe flat, messaging −8.7% (4/4 on runs faster)** — the time-based herd guard holds where the §S.8 depth gate cost −40% | quiet-box strand rig ABBA both modes (the latency endpoint), then game screen before hardwire |
| 34 | **G58** frame pre-wake = §G28 BUILT + reservation | **BUILT 2026-09-01** behind `--toggle g58`; BPF timer per CPU, argmax-cadence gate, reservation window cycle/16 floored 2x lead; live: 6,997 takes on a 1 kHz cadence (ungated). Wallclock fast ABBA x3: messaging flat, pipe 0 to +8%, one unrepeated 4.10 s slot | retest gated + widened window on the rig; game screen needs a cpuidle host for the C-state half |
| 35 | **G59** idle-depth pick (§G51 consumer) | **BUILT 2026-09-01** behind `--toggle g59` (forces g51); attach-clean, inert on this host; wallclock fast ABBA null (g51 tracepoint cost invisible) | ships to Lestat's 9950X3D with the fix branch; unmeasurable here |

**TOGGLE CAMPAIGN (2026-08-22, maintainer-directed):** §G43–§G46 each sit behind a
`const volatile` rodata toggle (`--toggle gNN=0|1`) so ONE binary serves both arms of
every on/off wallclock pair — the verifier deletes the off arm at attach, and arm
identity is the logged toggle line, not the binary hash. This is a sanctioned exception
to "A/B by commits" (§S.6): rodata arms cannot suffer the stale-object-cache failure
that rule guards against, and the toggles are scaffolding — winners get hardwired and
losers deleted when the campaign closes. Screen: quick wallclock ABBA per toggle
(pipe + messaging + calibrated memcpy, diagnostic tier), then stack the survivors and
re-screen; keeps still owe the sealed/game tiers before scoring.

**Campaign RUN 2026-08-22** (`scx_cake_bench/runs/toggle_wallclock_20260822/`, binary
`61589428c` receipt `0a0223d8d397`, desktop noise, load1 1.5–30 — the herds' own):
G43 lean-NEGATIVE (messaging +10.6% nearly separated against; its registered
mutex+pipe `--blocks 2` endpoint still decides), G44 null, G45 lean-positive 3/3,
**G46 memcpy −7.8% SEPARATED** (only separated single). Stack (g43=0 g45=1 g46=1 vs
tip defaults): pipe −1.3, messaging −3.2 (overlap), **memcpy −5.4 SEPARATED** —
direction held 3/3, the G46 separation reproduced in an independent pair. Zero
stalls across ~25 min attached (doubles as §G42 soak evidence). Diagnostic tier
only: sealed pairs + game screen owed before any toggle is hardwired.

**GAME SCREEN 2026-08-22 (live HD2 gameplay, wake tier — MangoHud unavailable,
maintainer-directed fallback): STACK NON-REGRESSING, leans better.** ABCCBA ×2
(native / tip / stack, 25 s slots, arms = receipt binaries, stack = probe commit
`42f2a1612`, banner-verified per attach). Slow wakes >1 ms/10k, arm medians:
main 18.99 → **13.40**, renderer 19.12 → **11.19**, vkd3d_queue 1.17 → **0.73**
(tip → stack; all-slot-rank consistent, no separation); Window&Input/fence tie;
FAudio "regression" = 1 event in each of 2 slots. Game IPC: native 1.396,
tip 1.552, stack 1.524 — BOTH cake arms beat native in this heavy regime
(reverse of KovaaKs light). Native keeps renderer (7.70). Data:
`runs/toggle_game_wake_20260822/` + `history/wake_latency/hd2tog-*`.

**IRQ-origin service + scheduling volume (same traces, 2026-08-22):** mouse
pipeline (libinput, woken from the USB-hub IRQ CPU 9): p99 **12.0 → 5.0/5.0 µs**
native→tip/stack, max 159 → ~30, IRQ-CPU stranding 6.2% → 0.0% — the KovaaKs
input win reproduces on HD2, toggles indistinguishable. GPU (CPU 13 origin):
vkd3d_fence p99 564 → 351 → **326**, `main` 658 → 420 → **390** (native → tip →
stack; stack best on every game-facing row). Volume per 25 s slot: cake
−28% context switches (8.1M → 5.8M), −16% wakings, softirqs HALVED (733k →
395k), migrations +25% (2.0M → 2.5M); tip ≈ stack on all counts. NEW
OBSERVATION, unowned: cake's sink avoidance displaces nvidia's own kthreads
off CPU 13 — nvidia-modeset p99 78 → ~820 µs, nvidia-drm/timeline 104 → ~890
(stay% 2.5/20 → ~0) — game threads win but the displaced display-service
tail is a possible frame-pacing input; needs a FRAME read to matter.

**SECOND GAME SCREEN 2026-08-22 — LOTR (AppId 2956680, UE + vkd3d, LIGHT
regime ~280% CPU), ABCCBA ×4 (n=8/arm after the maintainer extended play):**
n=8 UPDATE — migrations native 1.37M / tip 1.61M / **stack 1.38M** (stack ≈
native, tip +17%, 7/8 tip slots above all-but-one stack slot — g43-off removes
the premium, near-separated); nvidia cadence sd 408.7/406.0/**391.6**, p99
2149/2121/**2059**, max 3499/3903/**3397** (stack tightest all three, worst
slot 423 < native 437 < tip 536); IPC 1.045/1.085/1.078 — cake > native ~3–4%
solid, tip-vs-stack DEMOTED to tie (scene outliers 1.59/1.29 in rounds 3–4).
First-round detail below.** wake tails near-zero on ALL arms
(0.0–0.5/10k — regime too light to differentiate); game IPC native 1.034 <
tip 1.069 < **stack 1.078** (stack tightest spread); **stack migrations 1.37M
< native 1.42M < tip 1.71M per slot** — first toggle-level VOLUME effect:
g43-off removes cake's migration premium (HD2 heavy: both cake arms +25% vs
native). Mouse service ties native (p99 7.0 vs 7.5 µs; heavy-regime 2.4× win
absent when quiet). GPU-origin lane flips to native when light (fence p99 59
vs 106/120) — the displaced nvidia-kthread pattern reproduces (modeset 21.5 →
~250 µs), now seen in BOTH regimes; frame-pacing question stands. Data:
`runs/toggle_game_wake_20260822/lort-*`, `history/wake_latency/lort-*`.

**IRQ jitter/duration (same traces, corrected aggregation):** handler
durations IDENTICAL all arms both games (nvidia p50 24/p99 ~48 µs, USB 2–4/
4–7 µs) — scheduler-independent, validity anchor. Nvidia IRQ inter-arrival
(pacing proxy), LOTR at near-equal rates: sd 401/399/**387**, p99 2154/2121/
**2048**, max 3408/5054/**3345** native/tip/stack — stack tightest on all
three, tip owns the worst spike. HD2 confounded (rates differ 10–15% by
scene). USB cadence bit-identical (p99 1005 µs all arms). Analyzer:
`runs/toggle_game_wake_20260822/irqjitter.py`.

**FIRST FRAME READ of the toggle campaign — KovaaKs menu ~700 fps, ABCCBA,
n=2/arm, MangoHud per-frame (2026-08-22 23:46–23:50):** native 728 fps /
0.1% low 388.9 / median FT 1.349 ms; tip 705 / 383.4 / 1.394; stack 689 /
377.4 / 1.429. Severe frames: cake arms 0.029% vs native 0.032; worst frame
stack 3.06 < tip 3.11 < native 3.99 ms. **The g43 trade is now MAPPED:**
tip (g43 on) beats stack by ~35 µs/frame in this extreme-fps idle-machine
regime — the hint's design case (scan-free claims at huge wake rates) —
while g43-off wins loaded gameplay (HD2 tails, LOTR migrations) and
wallclock. g45+g46 implicated in no loss anywhere. Menu caveat travels
(G17 class); report `runs/game/kovaaks/2026-08-22/reports/`.

**Isolation pair (stack2): the stack is MORE than G46.** Full stack vs
g43=0+g46=1 (only §G45 differs): pipe −1.5, messaging −5.5 (overlap), memcpy
**−4.4 SEPARATED** — §G45 contributes inside the stack despite its null single.
WARNING for future reads: same-config memcpy wanders 9.4–10.3 s (~5%) ACROSS
pairs — within-pair only; attribution goes to the sealed tier.

**PORTABILITY FIX (2026-08-20): one binary now runs on any machine.** A 1.2.1
package refused a 16-CPU host: `build.rs` baked the build machine's CPU and CCD
counts into the BPF. A binary built on a smaller machine refused to attach; a
binary built on a single-CCD machine lost CCD steal with no warning.

The fix, commit `9e5d31f56`:
- `build.rs` no longer reads the build machine. No topology cflags remain.
- `cpu_steal_order` has a fixed size: `STEAL_SPAN`² = 128² u16 = 32 KB rodata.
- The `#if CAKE_NR_CCDS` forks are gone. One rodata flag, `steal_order_live`,
  replaces them. The loader sets it when the host has >1 LLC and fits the span.
  The verifier then deletes the dead branch on each host at attach.
- Hosts wider than `STEAL_SPAN` use the ring walk. Only `MAX_CPUS` (1024) can
  refuse attach.
- New CLAUDE.md invariant: cake runs on all hardware; per-hardware fast paths
  are rodata-gated, never build-host-shaped.

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

## CAMPAIGN: select_cpu for gaming (opened 2026-08-23, maintainer-directed)

Tonight's evidence: one placement redesign (§G53+§G54) moved game frames more
than any change this month — severe frames 0.062→0.037%, 0.1% low 171→286
fps, switches −5%, dispatch −41%, avg fps unchanged. Placement is the lever.

**TOGGLE AUDIT 2026-08-23** (maintainer order): g43 hint hardwired ON
(campaign scaffolding retired); g44/g47/g48 bodies DELETED (null/falsified/
closed); surviving toggles, each with a reason: g46 (separated win awaiting
its pre-registered seal + game screen), g51/g52 (pillar-4 physics inputs,
consumers scheduled), m6/m7 (parked pending K1/F14 composition). A/A after
audit: sel 83 ns unchanged, spills flat, select_cpu 486 insns.

**REMAINING-TOGGLE BENCHMARK 2026-08-23** (post-hardwire base): g46 net
NEGATIVE on the new base (+2.6k us/s: sel −9 ns but stopping publish +26 ns;
its memcpy workload win needs the registered ccm-memcpy+mutex seal, appsim
cannot see it) — stays off pending that seal. m6+m7 NULL on the new base
(78 vs 77 ns): the mailbox design removed their query sites from the hot
path — cleanup candidates next audit. g51 unmeasurable (no cpuidle driver,
BIOS decision); g52 unmeasurable (consumer deleted, A/A by construction).

**HARDWIRED 2026-08-23** (maintainer order): §G45 census, §G50-R zero-skip,
§G53 census fallback, §G54 self-park mailboxes are DEFAULT cake; toggles
g45/g50/g53/g54/g55 removed. Default-arm confirmation: sel 83 ns @ 151k =
12.5k us/s (was 183 ns / 27.4k), dispatch 219→116 ns, total scheduler cost
−40%, appsim p99 0.678 clean. Pending: EEVDF head-to-head HD2 frames (game
wedged pre-Vulkan after restart churn — needs a human-present launch, FIRST
item next session); longer sealing rotation; K2 for the 8k line.

**Pillars, in priority order:**
1. **Frames are the endpoint.** Every select change screens on the game
   rotation (severe ratio, 0.1% low, and BOTH jitter faces: avg|Δ|/Δp95
   small-wobble vs Δmax big-hitch — §G54 trades the first for the second;
   whether that feels better is a maintainer in-game call).
2. **Seal §G53+§G54**: longer HD2 + KovaaKs rotation, one input-live
   mission, mutex/pipe guards (serial-handoff interplay unmeasured).
3. **Cost floor**: 80 ns now, BPF floor ~65-70; K2 fused place kfunc
   (maintainer kernel patch) + mailbox hit-rate are the path to 8k us/s.
4. **Physics inputs feed parking policy at zero wake cost**: §G51 depth
   (needs BIOS Global C-State Control enabled), §G52 rank, K1 sink
   self-accounting — the idle CPU decides its own quality when parking.
5. **Falsified, do not revisit**: verified claims on the wake path (§G48,
   §G50-claim, §R.29); census-as-identity; unthrottled pre-scan gates.

## Scoreboard

**BLENDER-RED — DOWNGRADED to practical tie 2026-08-23:** on the hardwired select redesign the deficit is −0.21% [−0.29,−0.14] (2 blocks), below the 1% meaningful threshold; the redesign recovered the loss. Bisect deprioritized. Same window: **mutex-handoff +39.67% [+38.4,+41.0]** vs the +10.3% seal — the mailbox design amplifies the handoff shape (migrations −162k); needs an 8-block seal to enter the scoreboard. Original flag: blender-render vs native at HEAD d41b7dd41:
−2.31% then −1.56% [−2.9,−0.3] (2×2-block, second run quiet), cake +78-88k
cpu migrations. The +11.9% seal is 2026-07-19, unscreened for a month; today's
commits cannot change decisions (O1 order-only, M3 identical, toggles off).
Suspect: the month of sink-veto strengthening (quiet-machine exile, §G47's
origin finding). Needs commit bisect over the July→Aug window, 2-block per
step, migrations as the mechanism signature.


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

| hd2-menu 2026-08-23 (game ab ABBA, 2 runs/arm, HEAD 1f1682044) | avg fps / 1% low / 0.1% low / p99 | native 599 / 455 / 366 / 2.23 ms | cake 616 / 527 / 388 / 1.90 ms | ✅ cake sweeps averages; best-run 0.1% ties 398.4; native's weak run was slot 1 (first-slot noise). HEAD healthy in-game — outranks BLENDER-RED per GAME-FIRST |


| run | metric | native | cake | verdict |
|---|---|---|---|---|
| HD2 menu, ABBA 2/arm, 240 Hz VRR, 2026-08-01 (G17) | 240 Hz deadline miss % | 3.019 | **1.419** | **cake 2/2, −53%** |
| same | FT stddev / p99−median | 0.258 / 0.711 | **0.217 / 0.619** | cake 2/2, −16% / −13% |
| same | avg FPS / 0.1% low | 276.3 / 193.3 | 276.3 / 188.6 | tie / overlap |
| HD2 easy scene, ABCCBA, 2026-08-01 (G18/G20) | **0.1% low** | **225.80** | 212.79 / 213.92 | **native 2/2, cake −5.6%** |
| same | 240 Hz deadline miss % | 1.004 | 1.278 / 1.155 | native |
| HD2 live, ABBA, 2026-08-02 (G21) | `main` mean wake | 0.79 / 0.79 | **0.47 / 0.48** | **cake 2/2, −39.9%** |
| same | `renderer` mean wake | 0.91 / 0.83 | **0.66 / 0.64** | cake 2/2, −25.3% |
| KovaaKs live, ABBA 22 s, 2026-08-20 (wake tier) | mouse-IRQ→libinput wake p99 / starts on IRQ CPU | 11 µs / 36.1% | **3 µs / 0.0%** | **cake**; native n=1 slot — eevdf-2 had zero mouse input |
| same | task-graph role wake p99 (TaskGraph/Game/Render) | **2.57 / 1.58 / 0.96** | 5.59–13.07 / 2.73–115 / 2.49–4.44 | **native 2/2 most roles**; cake mig% ×2–3 |

**WoW wake read (2026-08-17, single-arm cake @ G27.1c build `db0b3636…`, 22 s live
play — attribution only, no native arm).** 29 roles. Every high-n role p99 ≤ 2.6 µs
except vkd3d_fence: **p99 31.45 / max 255 µs**. 99% of the slow wakes target
idle-shown CPU 13 — the nvidia IRQ CPU (ISR shadow; cpuidle driver `none` on this
host). Off-target fence wakes: p50 2 / max 11 µs. The sink set was empty at attach
→ §G30. **After G30 Phase B + sink veto (`wow-cake-g30c`): fence p99 1.25 µs,
6 slow wakes, CPU 13 share 2/50.8k.** Tail eliminated at the wake tier; frames
unmeasured. Artifacts:
`~/Documents/Repo/scx_cake_bench/history/wake_latency/wow-cake-{g27tip,g30a,g30b,g30c,g35d,g36}*`.

**Five-domain wake sweep (G17 rotation; delays > 200 µs per 10k transitions,
native → cake):** input 294.6/93.2 → **39.0/47.8** (4.5×), FAudio 288.3/80.8 →
**31.7/40.6** (~5×), renderer 124.0/87.0 → **46.7/47.0** (2.2×), vkd3d_queue
42.0/18.7 → **13.2/15.5** (1.5×) — cake 2/2 on all four. Network (n~555) and IO
(250× transition mismatch) unusable. `data-loop.0` is SCHED_FIFO, so cake never
schedules it. **Law: cake's advantage scales inversely with the thread's burst.**
G10–G20 optimised the renderer — the longest-burst thread, where the win is
smallest.

---

## Open gaps

1. **Cake loses the EASY scene** — 0.1% low −5.6%, 2/2 no overlap, on a scene where
   native's own tail is already tight. Mechanism unknown; **highest-value open
   target.** The G17 frame win and this loss both stand; neither generalises.
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
5. **The renderer wake tail: all levers null so far** — locality (G13), preempt (G14/G15),
   notification (G16) all null; G15 confirmed falsified on input too. 28–32% of slow
   same-CPU wakes have `swapper` as occupant in **both** schedulers — an idle-exit floor
   neither one beats.
6. **`ops.enqueue` reaches 0.142% of a game's dispatches** (vs 23.6% saturated). Every
   enqueue-side routing decision is nearly inert on games; leverage is on the direct
   path in `cake_select_cpu`, which serves 99.86%.
7. **Third arm UNBLOCKED 2026-08-19.** Shipped 1.1.3 (`/usr/bin/scx_cake`, sha256
   `56f9e886…`) attaches and runs clean on 7.1.8. The libbpf skeleton warning still
   prints but is non-fatal.
   - Quick wallclock ABBA vs nightly HEAD (diagnostic tier,
     `scx_cake_bench/runs/adhoc_wallclock_113_vs_nightly_20260819/`): nightly
     pipe **−16.0%**, memcpy −3.9%, sched-messaging **+70.5%** (4/4, no overlap).
     The many-to-many handoff shape regressed vs 1.1.3; unscored at the sealed tier.
   - n=10 confirm (suite 4, 5×ABBA): schbench-light req p99 **+72% 10/10** (S sd
     7 µs, N sd 459), mutex-handoff p999 **2.0× 10/10** (S sd 0.024 µs), p99
     **BIMODAL** (4/10 runs match 1.1.3 exactly, 6/10 at 1.2–1.9 µs), pipe −9.7%
     win 10/10. Slice dose falsified (EXP S.1-1ms).
   - **MODE SWITCH ROOT-CAUSED 2026-08-19** (`mode_probe/` in the run dir): it is
     `cake_frame_slice_ns`. Placement exonerated (24 runs, pair co-resident on
     CPU 11 in both modes, sinks 0%). Dose-response with an injected 1 kHz
     sleep-majority crowd (`--verbose` clock log as ground truth): crowd on binds
     in one poll (950.8 Hz published) → p99 1.8–2.1; crowd off → 3-poll re-publish
     + ~16 s floor climb → p99 decays to 0.90.
   - A 374.9 Hz desktop voter holds the slice at 2 ms on this host even quiet, so
     nightly never runs at the 3 ms cap on a live desktop. 1.1.3 has no frame clock
     (constant geometry) — hence its sd ≈ 0.
   - Mechanism: a fast desktop crowd tightens the patience windows (shifts of
     `cake_frame_slice_ns`, §S.2) for every task; the same-CPU handoff tail pays.
     Registered fix: §G12 KEYSTONE re-bases the `FRAME_*_SHIFT` windows onto the
     occupant's own period, which decouples bystander tasks from the global clock.
   - The KovaaKs live wake A/B (2026-08-20) shows the same shape vs native EEVDF:
     task-graph wake p99 2–5× worse than native while the IRQ-sink half wins
     (ledger row; `runs/kovaaks_irq_wake_20260820/`).
8. **Receipts audit** — 5 load-bearing claims (deletion-queue zeros, 1464 ns, SLICE_NS
   dose, §R.17 +28-36%, G17/G21 wins); list + rationale:
   `REVIEW_INDEPENDENT_2026-08-17.md` Addendum (git history).
9. **G17's mechanism is unexplained** — peer share 58.1%→56.9% while the tail fell 17%.
10. **`SLICE_NS`'s vtime-unit role** — the last architectural constant.
11. **Probe-driven `cake_handoff_max_ns`** — forbidden per the −35.66% mutex-handoff
    result. The runtime-observation path is now registered as **§G37** (adaptive
    switch-cost floor); boot probes stay dead (main.rs:159 comment).
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
design rationale. `scx_cake_bench` holds the raw runs.

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
| — | **KovaaKs wake+IRQ A/B** — eevdf/cake/cake/eevdf, 22 s slots, HEAD `f26d3c6b2` (ops `cake_1.2.1`, kernel-log identity) | **WAKE, interleaved** | ⚖️ **split** | sink machinery works: game-role residency on IRQ CPUs {5, 13} 10–61% native → ~0 cake; mouse-IRQ→libinput p99 **11 → 3 µs**, IRQ-CPU stranding **36.1 → 0.0%**. Bulk UE4 task-graph wakes: native p95/p99 **2–5× tighter**, cake mig% ×2–3 — the gap-#7 many-to-many shape, now shown vs native too. Input intensity uncontrolled per slot (eevdf-2: zero mouse). `runs/kovaaks_irq_wake_20260820/` |
| — | **domain wallclock audit** — sound/network/render/taskgraph/game from the retained g38 traces | **WAKE, interleaved (offline reprocess)** | 🏆 **render + sound wake tails flip to cake at G38** | render: modeset p99 **14.1 → 3.1**, drm/timeline **28.9 → 3.2**, dxvk 3.9–5.3 → 2.9–4.3 (5 of 7 comms win); AudioThread p99 **7.6 → 5.1**. Losses: TaskGraph p99 5.7 → 7.0, **GameThread p99 6.3 → 72.5 at tied p50** (new target), exec +15–42% everywhere, mig ×3–5 all domains. Network n/a this title (NET_RX 3–5 ms/25 s). `runs/domain_audit_20260821/` |
| **G39-A** | chain-successor handoff census (§G39 Phase A, offline, zero code) | **CENSUS** | ✅ **opportunity confirmed ~100× the abort floor** | game↔wineserver **~580k wakes each way/25 s, 80.9–91.9% handoff-shaped** (waker blocks ≤1464 ns, gap p50 0.6–1.1 µs); dxvk-submit→queue 63%, TaskGraph→GameThread 71%. Native same shape (92–97%). `runs/domain_audit_20260821/*.census.json` |
| **G38.1** | core preference at the raw-pick sites + serial arm (§G38.1) | STATIC + attach-test + **bench exact-pair (blocks 2, diagnostic)** | 🚨 **guardrail FIRED → serial veto withdrawn same session** | `cake_pick_idle_escape` 34 insns 0 spills; spills 16/12/28, select_cpu 428→435; attach PASSED 15:26. Guardrail on receipt `ab57ba40a`: **mutex-handoff −69.3% [−91.3, −47.3]** (task_clock −13.6% — pairs waiting), schbench-saturated +11.2% [5.5, 16.9] primary GOOD but context_switches +23.2% vs 5% margin. Repair `bd54a03df`: serial arm sheds the core veto (§R.26 — veto fired on signal presence, no cost comparison); home-claim veto + all pick sites stand; select_cpu →424. Tip re-run owed |
| **G39-B** | WAKE_SYNC joins the serial-handoff arm (§G39 Phase B) | STATIC + attach-test + **bench exact-pair (blocks 2)** | ❌ **ABORTED `60b238311`** (pre-registered abort: pipe regression beyond CI) | built `ec8d24dc6` (SYNC skips `cake_system_serial()`, object byte-identical; two called-subprogram shapes rejected first for select_cpu spills); tip guardrail: **perf-sched-pipe −36.8% [−42.1, −31.5], ctx-sw +45.9%** (sealed +22.7) = the §R.6 weld re-measured — pipe wakes ARE SYNC ping-pong; mutex −9.2 (non-SYNC) and schbench **+42.4 [22.9, 62.0]** unaffected, isolating the SYNC condition. Census + registry stand; Phase B' needs an RPC-vs-stream discriminator |
| — | **cause-B discriminator** — `chain3` microbench (3 unpinned socket stages, FIXED work = identical instruction streams), EEVDF vs tip, per-thread counters | controlled microbench, **n=1/arm PRELIMINARY** (ABBA hung on a tool bug after the cake slot; fixed) | ✅ **front-end pollution CONFIRMED** | stage IPC **−5.5/−9.7/−12.6%** with L1i/kinsn **+19–24%**, br-miss +10–19%, **L1d flat**; smallest stage worst (matches the game's 1.4×→1.19× gradient); e2e p50 near-tie, p99 +21%, one 2.7 ms max. Mechanism split still owed: BPF text vs migration-cooling → **E4a pinned rerun** decides E4's shape. `runs/causeb_chain3_20260821/` |
| **G41** | wake-queue occupancy mark (§G41, predict-verify) | 2-block screen, diagnostic, noise 59% | **BUILT `1b957daca` 2026-08-21; screen PASSED** | schbench-saturated vs native +48.2 [43.2, 53.2] against same-hour baseline +41.3 [36.5, 46.1]; first screen aborted on the §G42 latent stall (attributed away, 1/1 + 1/1); game rotation owed |
| **G42** | vtime mis-charge + no per-CPU wall net (bug) | source + stall dump; repro 3× NULL | **FIX BUILT 2026-08-21, soaking** | remote property change fires running/stopping on the CALLER's CPU; smp-id slot indexing let the caller be charged the target's difference (+3.226 s observed); fix = index by task CPU; §G42 |
| **G40** | kick the idle home (§G40, E7 find) | STATIC + attach-test | **BUILT `c0b6d65d7` 2026-08-21; unscored** | E7: 651/651 slow GameThread wakes (>20 µs; p99 128 vs native 6.1) had idle capacity, ~75% an idle home that `cake_home_notify` never kicked (gap B2 measured); fix = one KICK_IDLE in the `!live` remote branch; tip attach PASSED 15:39, sink set [13] live |
| **G38** | fully idle core outranks a cache-warm thread (§G38) | **WAKE chain + perf-stat IPC, interleaved ABCCBA** (native/base/G38, 25 s live KovaaKs, 2026-08-21) | ⚖️ **partial win, KEPT** | chain p50 base 18.72/19.77 → G38 18.55/18.29 µs vs native 15.51/14.19; doubled cores 0.27/0.24 → **0.20/0.20** (native 0.05/0.03); game IPC 1.104/1.112 → **1.156/1.143** (native 1.238/1.287). All three endpoints move the right way; ~¼ of the gap closed. `kwin_wayland` sib-busy ~32% untouched. Arms: base receipt `head-51ee88b21`, G38 receipt `g38_5be54ef0` (source diffed identical to `dac0be8d8`). `runs/g38_idlecore_20260821/` |

| — | **toggle campaign** — §G43 off / §G44 / §G45 / §G46 on-off ABBA + stack, one binary, arms = rodata toggles | **wallclock, interleaved, diagnostic** | ⚖️ **G46 the one separated result; G45 lean+; G44 null; G43 lean−** | per-arm medians (on vs off): G43 pipe +2.6 msg +10.6 mem +4.8 (all overlap, against); G44 +2.2/+5.6/−1.5 (overlap); G45 −3.8/−1.7/−0.2 (overlap, 3/3 for); G46 −0.7/−2.9/**−7.8 SEPARATED**; stack (g43=0 g45=1 g46=1) −1.3/−3.2/**−5.4 SEPARATED**. `runs/toggle_wallclock_20260822/` |

| G57 wc | earliest-free pick on/off (`--toggle g57`) | WALLCLOCK fast ABBA (on/off/off/on, pipe 3M + messaging g20 x2) | ✅ **non-regressing, messaging faster** | pipe 2.27/2.15 vs 2.24/2.20 s; messaging 0.37-0.38 vs 0.39-0.44 s (every on run beat every off run, −8.7%). `runs/toggle_wallclock_20260901/` |
| G58 wc | frame pre-wake on/off (`--toggle g58`) | WALLCLOCK fast ABBA x3 cycles | ⚠️ **inconclusive** | cycle 1 pipe slot 1 = 4.10 s (unrepeated: re-runs 2.51/2.49 vs off 2.47/2.52 and 2.49/2.36 vs 2.29/2.21); messaging flat all three; fires ~150/s under toggle, takes 0-3 (the elected cadence is not the bench). `runs/toggle_wallclock_20260901/` |
| G59 wc | idle-depth pick on/off (`--toggle g59`, forces g51) | WALLCLOCK fast ABBA | ✅ **null, as designed** | pipe 2.16/2.27 vs 2.21/2.23; messaging 0.40-0.44 vs 0.39-0.41 — the g51 tracepoint cost is invisible; no cpuidle table here |
| stack wc | g57+g58+g59 on/off | WALLCLOCK fast ABBA | ✅ **non-regressing** | pipe 2.41/2.27 vs 2.28/2.30; messaging 0.38-0.41 vs 0.41-0.42 (−4.8%) |
| overnight 0901 | native / crate-1.1.3 / stock-1.2.1 / fix-s8 / nightly off / g57 / g58 — seven receipted arms | **FRAMES, unattended KovaaKs menu, 4 mirrored 14-slot cycles, n=8/arm, 60 s** | ✅ **Lestat's loss reproduced on one CCD** | avg fps 746 / 747 / **708** / 717 / 758 / 758 / 756; p99 1.52 / 1.54 / **1.80** / 1.74 / 1.68 / 1.72 / 1.77 ms; 0.1% low 400 / 399 / 386 / 388 / 404 / 403 / 403. 1.2.1 −5.5% and +0.2 ms p99 vs crate 1.1.3, no slot overlap; fix == stock on one LLC; nightly recovers avg, not the 1.1.3 p99; g57/g58 null-to-worse at the menu. `runs/game/kovaaks/2026-09-01-overnight/` |
| overnight 0901 | same seven arms | **FRAMES, unattended Palworld menu, 3 cycles, n=6/arm, 120 fps cap** | ⚖️ **direction only** | p99 flat 8.73-8.80 ms all arms; p99.9 native 9.80 / 1.1.3 10.25 / 1.2.1 10.08 / fix 10.91 / off 9.80 / g57 9.63 / g58 9.67 (7 frames per 0.1%). `runs/game/palworld/2026-09-01-overnight/` |

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
|  [§G26–§G38](#g26--frame-laxity-input-registered) | registered constructs and live builds — bold status line per entry |
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

### §G37 — adaptive switch-cost floor (registered 2026-08-20)

`cake_handoff_max_ns = 1464` is this machine's number shipped to every machine
(hardware-audit finding #2). It is cake's definition of "a hand-off-sized run" in
three places: the turn floor, the occupant-nearly-done horizon, and the partner
classifier. A boot probe cannot replace it — measured 2026-07-30, −35.66%
mutex-handoff: an idle probe sees only the ~600 ns hardware floor, not the load
tail (Open gaps #11).

- **Hypothesis:** the real switch gap, measured on the switch path itself, converges
  near 1464 on this host and gives other hosts their own correct number.
- **Signal:** gap = new-start − old-start − old-run-length; all three values already
  on the switch path, zero new clock reads. EMA per CPU, folded to ONE global value
  (the classifier needs one yardstick).
- **Dynamics:** fast up, slow down — too low caused the switch storm, too high is
  mild. Continuous measurement; the published floor moves only on the sink-monitor
  cadence (1 s → 16 s with confidence), in steps, inside hard clamps.
- **Phases:** A observe-only (log, publish nothing). B actuate; sealed mutex-handoff
  pair; expect null on this host — the win is portability. C game screen ABBA with
  floor telemetry; motion during scene changes is the thing to watch.
- **Endpoint:** A: converges 1464 ± 25% here. B: mutex-handoff null-or-better.
  C: severe-frame ratio null-or-better, floor stable within a game session.
- **Aborts:** published floor flaps > 1 step/min under game load; mutex-handoff
  regresses; spill or verifier budget blows on the hot path.

---

### §G38 — a fully idle core outranks a cache-warm thread (registered 2026-08-21)

Measured on live KovaaKs (`runs/kovaaks_irqchain_20260821/ANALYSIS_HOPS.md`): cake
runs both threads of a core **0.15-0.18** cores of the time against native's **0.02**,
on a machine with only **2 of 8** physical cores busy. The input reader lands beside a
running sibling on **30%** of its runs (native 10%) and pays **+59%** execution time
there; the task-graph workers land beside one on **22%** (native 0.7%). Two sites rank
cache warmth above core exclusivity: the home claim declines `select_cpu_dfl`'s
fully-idle-core preference by design (§G13), and `ROUTE_GLOBAL` *seeks* the target's
sibling for cold pickup.

- **Hypothesis:** on an idle machine a whole idle core beats a warm thread on a busy
  core; ranking the core first cuts chain-stage execution time with no placement cost.
- **Steps:** `cake_pick_idle_clean` asks `SCX_PICK_IDLE_CORE` first and falls back to
  any idle CPU; the home claim declines a contended core (`cake_core_contended`, one
  `cpu_sibling` read plus the existing `cake_cpu_curr`); `ROUTE_GLOBAL`'s sibling
  preference is ranked BELOW the clean pick instead of above it. No decision deleted.
- **Endpoint:** mouse-IRQ -> game-thread chain p50 (native 14.2 µs, cake 16.7-17.7 µs)
  closes; cores-with-both-threads-busy falls toward native's 0.02; game-process IPC
  null-or-better. Then a KovaaKs frame ABBA.
- **Aborts:** spills rise on `select_cpu`/`enqueue`; stage execution unchanged (the
  co-residency was a symptom, not the cause); saturated-machine regression from losing
  the home claim, watched on schbench-saturated and mutex-handoff.

**Build 2026-08-21:** zero warnings both profiles, clippy clean, spills **16/12/28
unchanged**, `cake_select_cpu` 432 -> **428** insns, total 1988 -> 2001.

**SCORED 2026-08-21 (ABCCBA native/base/G38, 25 s live KovaaKs slots; data
`runs/g38_idlecore_20260821/`): partial win, KEPT.** Chain p50 (mouse IRQ -> game
thread) base 18.72/19.77 → G38 18.55/18.29 µs, native 15.51/14.19 — closes ~¼ of the
gap. Doubled-core mean 0.27/0.24 → 0.20/0.20 (native 0.05/0.03). Whole-game-process
IPC 1.104/1.112 → 1.156/1.143 (native 1.238/1.287) — the IPC endpoint is BETTER, not
just null. Per-stage sibling-idle exec p50: game worker 3.23 → 2.81 µs (native 2.31),
libinput 4.07 → 3.87 (native 3.40), **kwin_wayland flat 10.95 → 10.92 (native 8.26)
with sib-busy ~32% in both cake arms** — G38's three sites never see kwin's placement,
so the residual doubling and the largest per-stage exec loss are the same open front.
Arm identity: base = receipt `head-51ee88b21`; G38 = receipt `g38_5be54ef0`, whose
`source_snapshot` diffs identical to HEAD `dac0be8d8` (the tested commit was amended
into it; binary hashes differ only by build environment).

#### §G38.1 — core preference at the raw-pick sites + serial arm (registered 2026-08-21)

The flow map (`runs/g38_idlecore_20260821/flowmap.md`) found G38's residue: the
kernel's ranked pick is already core-first at flags 0, so the uncovered doubling
sources are the RAW `scx_bpf_pick_idle_cpu(…, 0)` sites and the serial
co-location arm. Kernel fact checked 2026-08-21: `flags & SCX_PICK_IDLE_CORE`
on `select_cpu_and`/dfl is a STRICT core search returning −EBUSY (idle.c:613),
and a raw pick at flags 0 has no core preference at all. The idle sink core
{5,13} poisons a strict CORE pick, so every CORE retry must re-pick
thread-grain when the winner is bad — the pick's test-and-clear consumes the
sink's idle bit, which makes the second CORE try skip it.

- Hypothesis: core-first at the raw-pick retries (`:936`, `:1001`, compat
  `:921`) plus `!cake_core_contended(wc)` on the serial arm cuts the remaining
  doubling (kwin sib-busy 32%) without touching the ranked pick.
- Steps: CORE-first pick with validated thread-grain fallback at the three raw
  sites; one contended-core term on the serial arm; no decision deleted.
- Endpoint: repeat the G38 rotation — kwin sib-busy toward ≤12%, doubled cores
  toward native's 0.04, chain p50; bench guardrail mutex-handoff +
  schbench-saturated null (the serial arm term is the risk).
- Aborts: spills rise; mutex-handoff regresses beyond CI; kwin sib-busy
  unmoved (falsifies the site attribution — the residue is then WAKE_DSQ
  pulls, site D).

#### §G39 — chain-successor handoff (construct; registered 2026-08-21)

The input chain (libinput → kwin → game) repeats 50k×/25 s at fixed depth 3;
every hop is a SYNC wake whose waker blocks immediately. Cake re-places each
hop from scratch; the switch-cost floor for the whole chain is 3 ×
`cake_handoff_max_ns` ≈ 4.4 µs against native's measured 14.2 µs — the only
lever whose ceiling BEATS native rather than matching it (gap #7's shape,
attacked at the chain, not the storm).

- Hypothesis: when a serial-shaped waker SYNC-wakes its successor and blocks
  within `cake_handoff_max_ns`, handing the waker's CPU directly to the
  successor beats any re-placement.
- Phases: A offline census from the retained g38 traces — opportunity rate
  (SYNC wake → waker blocks < 1464 ns) per chain edge, zero code. B the
  handoff arm: §R.18 conf + `cake_handoff_yields` gate the SYNC distrust arm
  (`:912`) into a handoff instead of a re-rank; sibling/sink vetoes retained.
  C chain A/B + frame screen.
- Endpoint: chain p50 below native's 14.2 µs, 2/2 slots; task-graph roles
  null-or-better (the §R.6 weld is the known failure mode — G9.4's per-CPU
  bit game-failed; this one is per-EDGE and conf-gated).
- Aborts: census &lt; 10k opportunities/25 s; any task-graph p99 regression
  &gt; 2×; any hot-path spill; pipe/futex bench regression beyond CI.
- **Phase A PASSED + Phase B BUILT 2026-08-21 (`ec8d24dc6`).** Census (offline,
  `runs/domain_audit_20260821/*.census.json`): game↔wineserver ~580k wakes each
  way/25 s at 80.9–91.9% handoff-shaped, gap p50 0.6–1.1 µs — ~100× the abort
  floor; native shows 92–97% on the same edges. Build: one condition — SYNC
  skips `cake_system_serial()` in the serial arm (the kernel asserts the pair;
  a non-SYNC wake still proves it machine-wide); every other gate stands. Two
  subprogram shapes were tried first and REJECTED: a called `cake_sync_handoff`
  cost select_cpu +1/+2 then +1/+8 spills/fills from the extra clobber point —
  the merged condition is free (16/12/28, 2039 insns, byte-identical counts to
  §G38.1). Guardrails owed: mutex-handoff, schbench-saturated, perf-sched-pipe.
- **Phase B ABORTED 2026-08-21 (`60b238311`), pre-registered condition.** Tip
  guardrail: perf-sched-pipe **−36.8% [−42.1, −31.5]**, ctx-switches +45.9%
  (sealed +22.7) — pipe wakes are `wake_up_interruptible_sync_poll` ping-pong,
  and admitting SYNC to the serial arm welded the pairs (§R.6, re-measured).
  mutex-handoff (futex, non-SYNC, −9.2) and schbench-saturated (+42.4)
  unaffected — the SYNC condition is isolated as the cause. Do NOT retry
  Phase B without a discriminator that admits the wine-RPC edge (successor
  chain, both sides block round-trip) while excluding data-streaming SYNC
  pairs (pipe: consumer drains a buffer the producer keeps filling). Candidate
  discriminators for B': wakee's own conf bit (both sides serial-shaped);
  chain depth ≥ 3 (RPC continues to a third task, pipe bounces between two).
- **Revert confirmed 2026-08-21:** pipe on the reverted tip −12.0 [−13.1,
  −10.8] with ctx-switches +1.6% (was +46) — the weld effect (~25 pts) is
  removed and CI-separated from the aborted build. Today's −12 baseline vs
  the sealed +22.7 is regime-shaped (mutex read −9..−26 across ALL builds
  including pre-G38 the same hour); settle only at the sealed tier if it
  matters (H5: the formula is conditioned on regime + workload).

#### §G40 — kick the idle home (registered + built 2026-08-21) `<- B2, E7`

E7 decomposition (`runs/domain_audit_20260821/*.e7.json`): every one of cake's
651 slow GameThread wakes (>20 µs; p99 128 µs vs native 6.1) happened WITH idle
CPUs free, and ~75% targeted an ALREADY-IDLE home — `cake_home_notify`'s
`!live` branch returned false for a remote idle home, so nothing kicked tcpu
and the queued task waited for the steal ring. This is open-gap B2's measured
cousin, found on the game's main thread.

- Hypothesis: kicking the idle home itself (one `KICK_IDLE` on tcpu) collapses
  the GameThread tail toward native's 6 µs; the B2 discriminator and fix in one.
- Steps: `!live` remote branch kicks tcpu and reports handled; local case
  unchanged; no other route touched.
- Endpoint: GameThread wake p99 ≤ 2× native on the rotation; E7 rerun shows
  idle-home slow wakes → ~0.
- Aborts: any spill; kick-storm visible in schbench-saturated (a kick per
  queued wake is the design cost — census says 1% of GameThread wakes).

#### §G41 — wake-queue occupancy mark (registered 2026-08-21) `<- G25, predict-verify audit`

Every dispatch on every CPU peeks the global WAKE_DSQ (rhashtable lookup plus
a shared head line) even in home-routing regimes where that queue is nearly
always empty. §G25 proved the mark shape for per-CPU queues, where the owner's
unconditional rescan makes a stale-clear bit benign. WAKE_DSQ has no owner —
every consumer gates on the mark — so a stale-clear needs a closing protocol:
the setter marks AFTER the insert, the consumer retires the mark only by
clear (exchange) then re-peek, so a nonempty queue can never end unmarked.

- Hypothesis: one "may hold work" mark in its own §R.10 slot replaces the
  global peek with a word read on the common dispatch, no wake-service change.
- Steps: mark slot + set/retire helpers; dispatch peeks only on mark-or-starved
  (§R.16 cadence = lost-mark backstop, bounded one 24 ms window, no watchdog);
  set at both WAKE_DSQ insert sites (wake arm, anti-collision arm).
- Endpoint: schbench-saturated `--blocks 2` non-regressing (the global-queue
  regime is where a service bug would show); game rides the next rotation.
- Aborts: "runnable task stall" in scx_cake.log; watchdog kill
  (`scheduler == native`); schbench-saturated p99 regression outside noise.

**Outcome 2026-08-21: BUILT `1b957daca`, screened.** First screen ABORTED on
the pre-registered stall (`systemd` 7.05 s, watchdog): dump shows a SINGLE
victim at **+3.226 s vtime debt** (whole pack within +7 ms) parked on sink
CPU 5's per-CPU queue while WAKE_DSQ flowed at 1–7 ms — the §G41 mechanism
uninvolved. Attribution split: baseline clean 1/1, G41 rerun clean 1/1 →
latent pre-existing pathology, filed as §G42. Screen (2 blocks, diagnostic,
noise EXTREME 59% external): usecs_per_op vs native **+48.2 [43.2, 53.2]**
against same-hour baseline **+41.3 [36.5, 46.1]** — non-regressing, CIs
nearly separate in G41's favor. Guardrails noninferior (ctx +38.9 b-good,
task-clock −2.3). Dispatch subprogram 76 insns (was 81), 0 spills. GAME-FIRST:
rides the next rotation before scoring.

#### §G42 — single-event vtime mis-charge + no wall-clock net on per-CPU queues (bug report, 2026-08-21) `<- §G41 abort`

Evidence `runs/exact_pair/exact_pair_20260821T203147Z_1c535c2744be` (b02.p1
dump): one task (`systemd[1003]`, weight 100) at +3.226 s vtime over a pack
spread of 7 ms. Its lifetime sum_exec was ~4.9 s, so the charge shape is
`sum_exec - run[cpu].sum` with a slot residue (~1.7 s) that looks like a
DIFFERENT task's runtime — a stopping without a matching running stamp
(attach/bypass or attribute-change edge, unproven). Second half: WAKE_DSQ
has a 24 ms wall net (§R.16); per-CPU queues have none, so a debted task
waits its full debt in wall time — 7 s beat the 5 s watchdog.

- Hypothesis: `cake_stopping` can fire against a run slot stamped by another
  task; one event is enough to strand its victim past the watchdog.
- Steps: instrument stopping (charge > 1 s traces stamp owner) OR reason the
  ext.c edge to ground; separately price a per-CPU wall-clock net.
- Endpoint: mechanism named, then a bounded charge or a net — maintainer call.
- Aborts: none (observation first; no scheduler change in this phase).

**Mechanism grounded 2026-08-21 (source, Linux 7.2 tree):** a property change
on a RUNNING task (`sched_setscheduler`, `set_user_nice`, cgroup
`sched_move_task`) runs `sched_change_begin/end` on the CALLER's CPU under the
victim's rq lock: `dequeue_task_scx` fires `stopping(false)` and `set_next`
fires `running()` there. Cake indexed both by `bpf_get_smp_processor_id()` —
the CALLER's CPU — so the remote `running()` stamps the caller-CPU slot with
the TARGET's sum, and the CALLER's own next switch-out charges
`caller.sum − target.sum`. systemd (a task that property-changes others
constantly) at 4.9 s lifetime minus a ~1.7 s stamp = the observed +3.2 s.
The direct charge on the target self-masks (the following `running()` drags
the frontier along); the caller-side debt does not — no frontier advance
follows a switch-out.

**Repro: 3 attempts NULL** (~235k forced remote BATCH↔OTHER toggles under
saturated H1 arms; rigs in scratchpad `g42rig*.c`): v1 slot arithmetic went
negative (self-heals via clamps), v2 caller-victim shape also never gapped.
The bad ordering needs conditions not yet identified; the mis-indexing itself
is a defect by inspection regardless.

**FIX BUILT 2026-08-21:** both ops index `cake.run[]` by `p->thread_info.cpu`
(the task's rq CPU — identical on the normal switch path, correct on the
remote path; the remote ping-pong becomes exactly accounted). Gates clean;
`cake_stopping` spills 1 → 0 (dropped the smp-id call). No policy change, so
no game screen owed on its own; rides the §G41 rotation. Confirmation is a
SOAK: fixed cake attached through normal desktop use, watcher on the exit
path — the bug's signature is the watchdog stall, which previously appeared
within ~4 min of one saturated bench.

#### §G43 — going-idle hint: publish at dispatch, claim before the idle scan (registered 2026-08-22) `<- predict-verify audit C1, §G38, §G41`

`cake_wake_notify` and `cake_enqueue`'s kick tail run `cake_pick_idle_clean`
— up to three kernel idle-mask scans plus escapes — on every global wake. The
going-idle moment is already an event cake observes: `cake_dispatch` finds
nothing and prev is not queued. One published word turns the common idle
search into a single test-and-clear (the claim IS the verify, same contract
as the prev-CPU arm). Full audit and the candidate ranking:
`docs/AUDIT_PREDICT_VERIFY_2026-08-22.md`.

- Hypothesis: a going-idle CPU publishing its id lets the wake path claim an
  idle CPU with one test-and-clear instead of a scan; wake cost drops, no
  routing or ranking change (§G38 core preference preserved by the gates).
- Steps: `idle_hint` §R.10 slot; dispatch publishes on going idle
  (test-before-write); `cake_idle_hint_claim` (affinity + irq/tick/core gates,
  test-and-clear, CAS retire so a newer publish survives) ahead of the scan in
  `cake_pick_idle_clean`; no other site touched.
- Endpoint: on/off `--blocks 2` same-hour pairs — mutex-handoff on-arm ≥
  off-arm within CI; perf-sched-pipe non-regressing (the §R.6/§G39 weld guard).
- Aborts: pipe regression outside CI; any new spill in `cake_pick_idle_clean`
  or its callers; "runnable task stall" in scx_cake.log; watchdog kill.
- **Wallclock screen 2026-08-22 (diagnostic): lean NEGATIVE** — on-arm slower 3/3
  (messaging +10.6% nearly separated). The registered mutex-handoff + pipe
  `--blocks 2` endpoint decides; toggle default stays ON until it runs.

#### §G44 — qmask answers wake-routing emptiness (registered 2026-08-22) `<- predict-verify audit C3, §G25`

- Hypothesis: a CLEAR qmask bit already proves the per-CPU DSQ empty, so the
  wake-routing sites (serial block, empty-home test, frontier-convergence
  return) can skip the `dsq_nr_queued` rhashtable lookup; a SET bit still
  verifies with the real count (insert marks before the task lands, §G25).
- Steps: `cake_cpu_dsq_idle()` helper behind `--toggle g44`; three call sites;
  local-DSQ (`LOCAL_ON`) lookups untouched.
- Endpoint: wallclock on/off ABBA — pipe + messaging non-regressing, any win
  kept for the stack arm. Stale-clear misroute is benign: the owner's
  unconditional own-queue peek finds the task next dispatch.
- Aborts: "runnable task stall" in scx_cake.log; watchdog kill; pipe
  regression outside the arm spread. Routing change → game screen before keep.
- **Outcome 2026-08-22: BUILT `f5185af07`, wallclock NULL** (pipe +2.2,
  messaging +5.6, memcpy −1.5, all overlap). Parked off.

#### §G45 — event-complete idle census for the serial gate (registered 2026-08-22) `<- predict-verify audit C5, §R.25`

- Hypothesis: `ops.update_idle` (KEEP_BUILTIN_IDLE) maintaining an idle bitmask
  + count makes `cake_system_serial` one word read instead of
  `get_idle_cpumask` + full cpumask weight per serial-candidate wake.
- Steps: idle words + counter (flip-gated atomics, idempotent, seeded in
  ops.init from the kernel mask); `cake_system_serial` reads the counter when
  `--toggle g45`; callback body prunes to nop when off.
- Endpoint: wallclock on/off ABBA; the off arm still pays the registered
  callback, priced separately by the all-off vs tip A/A.
- Aborts: stall/watchdog; messaging regression outside spread (transition-rate
  atomics are the predicted cost); audit's own gate — if on/off is null, C5 is
  rejected and the callback deleted.
- **Outcome 2026-08-22: BUILT `0ef821db8`, wallclock lean-positive 3/3**
  (pipe −3.8, messaging −1.7, memcpy −0.2, all overlap); rides the stack.
  All-off vs old-tip A/A owed for the bare callback-registration cost.

#### §G46 — departing-slice cache, pid-tagged, per-CPU (registered 2026-08-22) `<- predict-verify audit C4, §R.18`

- Hypothesis: `cake_task_slice` (two divides + a clock read) recomputes at
  every insert what `cake_stopping` could have published; a two-entry
  pid-tagged cache in the run slot (handoff pairs alternate, so one entry
  always misses) serves the insert sites with one load + compare. Per-CPU
  slot state, NOT per-task storage — the audit's tenet blocker dissolves.
- Steps: `slice_cache[2]` words in `cake_run_slot` (owner-written at stopping,
  line already dirty); `cake_task_slice_cached()` at the seven insert sites
  behind `--toggle g46`; kthread flat grant and dispatch keep-prev untouched.
- Endpoint: wallclock on/off ABBA — pipe (the curr==p self-race is the
  hottest consumer); staleness bound is one quantum of estimator drift.
- Aborts: stall/watchdog; any new spill in `cake_enqueue_wake` or
  `cake_select_cpu`; pid-reuse mis-grant is bounded by the cached value being
  a valid slice for some task (≤ SLICE_NS), so no correctness abort.
- **Outcome 2026-08-22: BUILT `61589428c`, the campaign's one separated
  result** — memcpy −7.8% SEPARATED single, −5.4% SEPARATED in the stack;
  pipe/messaging lean-positive. A one-quantum-stale slice is GEOMETRY, not
  just saved arithmetic, so attribution is open; sealed ccm-memcpy +
  mutex-handoff pair, then game screen, before hardwiring.

#### §G47 — ISR-successor kthread keeps the IRQ CPU (registered 2026-08-23, maintainer-directed) `<- §G30, §G35, toggle campaign IRQ finding`

- Hypothesis: the sink veto exiles the ISR's OWN continuation kthreads
  (nvidia-modeset p99 78→~820 µs HD2, 21.5→~250 LOTR, stay% →0) — the GPU-feed
  path — explaining cake's GPU-util gap (87.8 vs 84.6/82.3% KovaaKs menu). A
  kthread woken FROM interrupt context on its own prev CPU keeps that CPU: it
  cannot run before the handler ends (p99 48 µs) and cold remote placement
  costs 250–900 µs.
- Steps: in the kthread wake arm, `cake_irq_live[this].depth && tcpu == this
  && prev == this` → insert LOCAL_ON tcpu, skip the idle pick; behind
  `--toggle g47`.
- Endpoint: KovaaKs menu frame A/B — GPU util gap closes toward native, avg
  fps recovers; nvidia-kthread wake p99 toward native's 21–104 µs; the fence
  tail (wow-cake-g30c class) and game-role sink avoidance MUST hold.
- Aborts: fence-tail regression (the §G30 win is senior); stall/watchdog; any
  new spill in `cake_enqueue`.

#### §G48 — hint-first main placement (registered 2026-08-23, component audit) `<- §G43, AUDIT_COMPONENT_COST`

- Hypothesis: the ranked scan dominates `cake_select_cpu`'s measured 185
  ns/call (28.2 ms/s at 152k wakes/s vs EEVDF select_task_rq_fair 10.2 ms/s,
  bpf_stats + perf, runs/bpfstats_20260823); a §G43 hint claim ahead of
  `select_cpu_and` makes the hit O(1) at unchanged ranking (claim gates =
  scan gates). Campaign target: placement ≤8,000 us/s at held switch rate.
- Probe §G48-P (first): commit that returns prev/dfl with the ranked scan
  deleted, same appsim+bpf_stats window, read ns/call = fixed-path cost;
  revert byte-identical. Placement quality knowingly sacrificed; ns/call is
  the only read.
- Steps: `cake_idle_hint_claim` between home claim and nonsink scan, direct
  insert on hit; behind `--toggle g48`.
- Endpoint: select_cpu ns/call + placement us/s (bpf_stats, appsim window),
  hit rate; context switches and appsim p99/p999 MUST hold.
- Aborts: stall/watchdog; switch-rate regression >5%; new spill in
  `cake_select_cpu`.
- **Progress 2026-08-23:** §G48-P probe `40878f738`→revert (byte-identical
  b6078ab5): fixed path 76 ns, scan 109 ns of 185; probe also showed deleted
  placement costs +67 ms/s in dispatch/enqueue — the scan's decision is
  load-bearing, only its price is the target. Sub-8k therefore ALSO needs
  fixed-path cuts (§G49, O1, F14): 76 ns fixed > 52 ns budget on its own.
  BUILT `5d2c4012c` (+`8e761ef53` word-gate + O1 order fix): loaded on-arm
  202→188 ns/call; off-arm O1 window noise-invalidated (enqueue 117k/s,
  off-profile), mirrored re-run owed. M3 dedup `0030b2a2b`, spills flat.
  Maintainer audit registrations: §G50 (census-zero skip), M2 (dead
  frame-clock plumbing), M1 (serial/convergence double-eval — screen first),
  M4 (G44+F14+F15 as one consolidation program). F14 note: the serial gate's
  two emptiness checks cover two DIFFERENT queues (vtime DSQ + LOCAL_ON);
  merging needs a maintained bit, not a dedup.

#### §M6 — occupant mirror: subscribe, don't query (registered 2026-08-23, maintainer-directed) `<- component audit 8th pass, §R.17, §G45 shape`

- Hypothesis: five rq->curr deref-chain sites (core_contended, handoff_yields,
  occupant_live -> preempt/notify/anti-collision) can read one flat
  cake.run[cpu] line instead: running/stopping already own that line at every
  transition; publishing start-vtime + recip-index + pid costs ~2 stores on an
  already-dirty line. Win = chain and kfunc deletion, NOT locality — remote
  questions stay one remote line.
- Steps: extend cake_run_slot, publish in running/stopping, convert the five
  readers; behind a campaign toggle; fnspills gate on select_cpu.
- Endpoint: select_cpu + dispatch ns/call (bpf_stats appsim window, mirrored
  rotation); per-wake kfunc pulls ~4-5 -> ~1; composes with §G48/§G50.
- Aborts: cake_running/cake_stopping ns/call regression (coherence tax — the
  irq_leave 11->276 ns lesson); any new spill in select_cpu; stall/watchdog.
  §G49 screens after; absorbed if M6 lands.
- Pre-build decisions (maintainer-accepted 2026-08-23): (1) the occupant word
  packs pid-tag + recip-index + class in ONE u64, value 0 = off-mirror — keeps
  the RT-owned-home check in enqueue_wake and zero-vtime conventions correct
  without a second load (§G46 pid<<32 packing is the precedent); (2) geometry
  re-verified against the constant: STATE_SLOT_BYTES=128 so slots are 16
  words; run_slot had 11 pad words, mirror uses 2 — the earlier "3 free"
  figure checked the expression, not the constant. Publication stays
  single-store, benign-stale model preserved. Tax refinement: the slot line is already
  remote-read (stamp in handoff_yields/occupant_live), so M6's net
  lines-touched delta is plausibly negative; hard abort kept regardless.

#### §G56 — FOLD: banded steal (registered 2026-09-01, maintainer-directed "geometry" program) `<- §G25, §G52, longest-paths audit`

- Hypothesis: the steal walk's worst case (31 iterations, up to 31 failed
  move kfuncs on all-stale qmask after a load spike; longest live loop per
  the 2026-09-01 path audit) collapses to one AND + find-first-set per LLC
  band: `qmask & llc_membership_word` jumps straight to the victim. Band
  order = locality order (own LLC first, then foreign LLCs by descending
  CPPC rank under g52 — the first live §G52 consumer — else id order).
- Implementation: behind `--toggle g56`; narrow hosts only (span <= 64, one
  qmask word) — wide hosts keep the §G25 walk; loader fills cpu->LLC map,
  per-LLC qmask words, and band order from RUNTIME topology (portability
  invariant). Stagger = mask-split at own id + two ctz, NOT the
  §G25-REJECTED rotate. Stale bits cost one word-op, not a kfunc.
- Built + attach-smoked 2026-09-01 (g56=1 g52=1, "1 LLC band, order rank",
  10 s clean). fnspills: cake_band_steal 107 insns, 11 spills (vs walk's 5 —
  double table index; optimization owed if the screen keeps it).
- Endpoint: going-idle dispatch ns/call + steal hit rate on the appsim
  regime; wallclock quick ABBA (pipe + messaging + memcpy); frame screen
  before hardwire. Aborts: stall/watchdog; dispatch ns regression; steal
  hit-rate drop vs the walk.
- Sibling program notes: TELEPORT = §M6/§M7 mirrors (parked, compose at the
  screen under load); TIME = per-LLC wake-pool port from the
  `fix/cake-1.2.1-llc-overflow` branch (§S.8, pending the 9950X3D field
  verdict); wide-host hierarchical summary word (O(log) search) recorded,
  not built.

#### §G57 — earliest-free pick: the occupant publishes when it leaves (registered + BUILT 2026-09-01, "nodes that don't talk" program) `<- §S.8 field report, §G17, §M6`

- Hypothesis: the saturated-mask strand (§S.8: a wake behind one busy CPU's
  private queue, no other server) is a missing edge between occupant and
  wakee. `ops.running` writes `free_at = now + slice/2` into the run slot it
  already dirties (uncapped grant = 2x burst, so half is the burst estimate
  with no divide; a capped grant ends at the slice, so the estimate never
  lands after the CPU's next dispatch). A wake with nothing idle in its mask
  scans the affine CPUs of its home LLC (one qword AND, ctz walk, one slot
  read each) and queues behind the earliest. Move only when the gain clears
  `SLICE_NS >> FREE_MOVE_MARGIN_SHIFT` (94 us): a partner about to yield
  keeps the wake home — the t32/t64 herd guard as TIME, replacing the
  fix-branch depth gate that measured messaging t16 −40% when loosened.
- Built behind `--toggle g57`; hook precedes the wake/continuation split in
  `ops.enqueue`; no kick owed (the target dispatches at `free_at` by
  construction, the ring can lift earlier). Stale slots (older than a slice:
  RT or idle occupant) are never targets and never moved from. Narrow hosts.
- Live 2026-09-01: saturated peer rig 19,018 placements (9.2% of selects);
  idle rig 0-83 (correct: nothing saturated). Unscored — box noisy.
- Endpoint: strand rig both modes, quiet box, ABBA off/on: over-1ms and p99
  at or below the fix branch's committed numbers; messaging t16 within the
  off arm's spread; pipe flat.
- Aborts: messaging outside spread (the herd guard failed); any stall; a
  new spill in `cake_select_cpu`.

#### §G58 — frame pre-wake: the scheduler acts before ttwu (registered + BUILT 2026-09-01) `<- §G28 (this is its build), §G54, §G11`

- Hypothesis: §G28 as built, plus a reservation. A display-coupled thread's
  next wake is predictable from its own cycle, so `ops.stopping` on a block
  arms a per-CPU `bpf_timer` (scx_layered precedent; init in the sleepable
  `ops.init`) at `cycle − used − lead`. The fire, if the CPU is idle, writes
  `reserved_pid/until` into the run slot and idle-kicks the CPU, paying the
  C-state exit before the wake. `select_cpu` takes the reservation before
  every other claim; `park_take`/`optimistic_place` skip a CPU reserved for
  another pid inside the window. Lead = 2x deepest cpuidle exit (loader), or
  `PREWAKE_LEAD_DEFAULT_NS` (50 us) without a table; window = cycle >> 4
  floored at 2x lead (prediction error scales with the cycle).
- Gates: the frame-clock vote gate (sleeps most of its life, cycle inside
  the engine band) AND the elected argmax bucket — only the published frame
  cadence arms, so a desktop of 60 Hz sleepers is not a kick storm. No
  clock, no arm. A miss costs one idle kick and one unused window; nothing
  is queued or preempted on a prediction. One divide on the block path,
  under the toggle.
- Live 2026-09-01: ungated, 1 kHz rig cadence: 14,173 fires / 6,997 takes
  per 10 s (~75% of the cadence's wakes landed on the reserved CPU). Gated,
  the box's 252 Hz argmax fired 6-7k per 10 s with 0 takes at the 100 us
  window — widened to cycle/16, retest owed. Two of four on-arm idle-rig
  runs read p999 39 us vs off 13-15 (always the first arm after a switch).
- Endpoint: wake-to-run of the elected cadence thread with deep idle
  available; then a game screen (severe-frame ratio) on a cpuidle host.
  This host has no cpuidle driver, so the C-state half is unmeasurable here.
- Aborts: A/A tail cost on the idle rig; power artifacts; any stall.

#### §G59 — idle-depth pick: the §G51 consumer (registered + BUILT 2026-09-01) `<- §G51, §G53, §G54`

- Hypothesis: among affine idle CPUs, the shallowest C-state (exit latency
  from the loader table via the §G51 mirror) beats census order; a parked
  mailbox CPU deep in idle loses to a shallower affine one. Compares at most
  `DEPTH_SCAN_MAX` (4) candidates; ties keep census order, so an empty table
  IS the §G53 first fit. Composes with §G58 (reserved CPUs skipped in the
  same walk). Forces g51 on.
- Built behind `--toggle g59`; attach-clean; INERT on this host (`cpuidle
  current_driver none`), degrade logged. Unmeasurable here by construction.
- Endpoint: on a cpuidle host, wake-to-run mean and p99 for the cadence
  thread vs g59 off; census of picks that changed. Ships to the 9950X3D
  field test on the fix branch.
- Aborts: any placement change on this host (would prove the gate leaks).

#### §G53 — EEVDF-shape optimistic placement (registered 2026-08-23, maintainer-directed)

- Hypothesis: EEVDF's 66 ns comes from NOT verifying its pick — no gates, no
  claim, collisions absorbed by the queue. Cake's failed fast paths all died
  on verify-and-claim cost (§G48 claim-fail, §G50 claim-race). Census
  first-fit + affinity + direct insert, nothing else, should land 80-110 ns.
- Steps: behind `--toggle g53` (forces g45); census bit -> direct LOCAL
  insert, no test_and_clear, no clean/contended gates; empty census -> scan.
- Endpoint: sel ns/call (mirrored appsim ABBA) + switch rate + tails hold.
- Aborts: stall/watchdog; appsim p99 regression; new spill in select_cpu.

#### §G54 — self-park mailboxes (registered 2026-08-23, maintainer-directed redesign) `<- §R.29, §G53 probe, §G50-R, M7`

- Hypothesis: the wake path can READ a decision instead of making one. Idle
  CPUs evaluate their own gates at idle-entry (free time, local facts) and
  park into per-waker mailboxes (owner-read, no consume atomics — kills the
  §G50 claim race by construction); retract at idle-exit. Wake path: prev
  census-bit optimistic -> own mailbox -> zero-skip -> old ladder. Affinity
  by direct cpus_ptr bitmap read (no kfunc). §G53 measured optimism at 77
  ns incl. insert with dispatch halved and −7% switches; producer gating +
  prev-warmth + retraction attack its tail residue.
- Steps: behind `--toggle g54` (forces g45); producer in update_idle,
  rotor-distributed slots, park idx in cake_irq_live; consumer subprogram.
- Endpoint: select_cpu <8,000 us/s loaded (<=52 ns/call) with switch rate
  and appsim p99/p999 held; schbench-saturated pair must not regress.
- Aborts: stall/watchdog; p99 regression beyond slot-position band; new
  spill in cake_select_cpu; update_idle ns/call regression >2x.
- **First mirrored ABBA 2026-08-23:** sel 92/92 ns on-arm (vs off 163 avg) =
  13.6k us/s — half of baseline, above the 8k target. Tails FIXED vs §G53:
  end-slot p99 0.676/0.682 against the 0.93 position band — producer gating
  + prev-warmth cured the collision cost. Switches −6%, dispatch 219→123.
  Gap = miss path (~25% of wakes fall to the full ladder). Levers: chain
  §G53 walk as mailbox-miss fallback (pair in flight); multi-park (2-3
  entries per idle CPU — consumed entries orphan an idle CPU until its next
  transition); warmth-first reorder if the combined arm shows G53 tails.
  update_idle 9→34 ns producer cost (+5.5 ms/s) — net total still −38%.
- **G54.1 (warmth-first + core entries + per-core slots):** sel 80/81 ns =
  11,748 us/s, tails arm-comparable (quality restored), switches −5%,
  dispatch −41%. §G55 insert probe: the insert is ~10 ns of the 80 and
  skipping it explodes enqueue+dispatch (+60 ms/s) — cheap AND load-bearing.
  Architecture floor ≈ 65-70 ns avg (trampoline ~15-20 + serial block +
  reads + insert): the 8,000 us/s goal is ~2-3k short of reachable in this
  accounting without K2 (fused place kfunc, patch-gated) plus hit-rate work.
  Achieved: 27,400 → 11,748 us/s (2.3x), quality held.
- **HD2 menu frame screen (mirrored ABBA, n=2/arm, ~12k frames/slot): PASS**
  — severe (>2x med) 0.037 vs 0.062%, 0.1% low 286 vs 171 fps, p99.9-median
  tie (1.142 vs 1.132 ms); cost: p99 mid-band thicker (2.22 vs 1.92 ms).
  First fast path to win benchmarks AND frames. Longer rotation before
  default-on; K2 fused kfunc is the remaining path to the 8k line.

---

### §R — Design rationale (from source comments)

#### §R.29 — push vs pull (census-claim autopsy, 2026-08-23)
Identity claims only work from PUSHED events (the §G43 hint: published at
going-idle, single candidate, one test-and-clear); pulled aggregates are
fresh enough for counts ("someone is idle" — gates, zero-skips) but never
for identity ("take this one") under concurrent wakers. Census-as-gate ✓,
census-as-identity ✗ — sel 179→264 ns bought this law.

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

#### §S.8 — per-LLC wake pools (fix branch `fix/cake-1.2.1-llc-overflow`, `f27950e9d`, 2026-09-01)
Field report: 9950X3D, DOOM TDA, game lassoed to the V-cache CCD — shipped
1.2.1 last (152.6 avg / 90.0 1% low) vs crate 1.1.3 first (172.3 / 115.9),
EEVDF 167.5 / 109.0. Nine schedulers sit within 3% avg / 6% low, 1.1.3 a
single run: "1.1.3 first" is not established, "1.2.1 last by 9% / 17%" is.
The 97th-percentile bars are equal (205 vs 207-210): the loss is all slow
tail = intermittent holds, which favours the strand over CCD-blindness.
Root cause: the saturated-mask wake strand (a wake into one busy CPU's
private DSQ, no other server, every rescue gated). Fix, cut from the
shipped tag: one wake pool DSQ per LLC (`LLC_WAKE_DSQ_BASE + idx`, loader
maps cpu→LLC from RUNTIME topology, 1 pool on failure), continuation-arm
wakes behind ANY live occupant pool, plain vtime own-vs-pool arbitration,
per-LLC starve stamps, 24 ms cross-LLC wall kept. Synthetic strand rig only;
no game, no dual-CCD host has run it. Review 2026-09-01 (this file's
author): stage wakes still strand when the pool is backlogged (the herd
depth gate demotes them to the private queue — and the fix makes the pool
non-empty more often); service bound is next dispatch, not a preempt; the
removed `!starved(hc)` guard pools futex handoffs. Isolation, 3 reps each,
interleaved: loosening the herd gate (yield test, or depth ≥ span) costs
messaging t16 0.65-0.69 s → 0.88-0.96 s in every run; the continuation-arm
yield test is a no-op on pipe and messaging. NEITHER PUSHED. The right
discriminator is remaining burst as time, not yield-within-1.5 us — built
on nightly as §G57. Strand rig noise that evening: same binary, same mode,
over-1ms 15/99/216/466 (spinner) and 249/382/522/1604 (peer): no
between-arm verdict survives it. Lestat's verdict pending.

---

### Open review findings — REVIEW_INDEPENDENT_2026-08-17.md

Verified against source, not yet fixed. Each becomes an experiment when picked up:

- **Finding 2** — `cake_system_serial()` denominates in POSSIBLE CPUs, not online.
- **Finding 4** — multi-CCD ring-steal guard returns the wrong sentinel.
- **Finding 5** — `reexec_self()` doc block is attached to the wrong item.
