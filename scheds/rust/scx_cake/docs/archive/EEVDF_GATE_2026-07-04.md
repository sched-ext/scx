# EEVDF gate scoreboard — 2026-07-04 (~03:20–04:33 UTC window)

Cake HEAD 2ffdcc7d1 (M6 preempt-first + M7 prev-first + M8 waker-convergence + M9 sleeper gate)
vs native EEVDF. Same-window pairs, `cakebench one --capture stat`, all rows scheduler-verified.
ext% noted where > 12. Direction-corrected: + = cake better.

| bench | cake | native | delta | verdict |
|---|---|---|---|---|
| stress-ng-futex | 4,791,849–4,806,233 | 3,163,466–3,180,770 | +51% | WIN (was −20% pre-M8) |
| stress-ng-cpu-cache-mem | 4.12–4.30M (ext 15-16) | 3.15M (ext 14) | +34% | WIN |
| schbench-saturated p99 | 117,376 | 144,128 | +18.6% | WIN |
| stress-ng-cache | 5.48M (ext 16) | 4.90M (ext 15) | +11.9% | WIN |
| perf-sched-fork | 0.134 | 0.149 | +10.1% | WIN |
| perf-sched-thread | 0.124 | 0.132 | +6.1% | WIN |
| y-cruncher | 18.55 (ext 20) | 19.05 (ext 19) | +2.6% | tie+ |
| xz-compress | 6.34 (ext 18) | 6.46 (ext 13) | +1.9% | tie+ |
| stress-ng-memcpy | 6107 | 6040 | +1.1% | tie+ |
| prime-numbers | 24,832 | 24,667 | +0.7% | tie |
| namd | 45.77 | 45.72 | −0.1% | tie |
| perf-memcpy | 31.01 GB/s | 31.13 GB/s (ext 15) | −0.4% | tie |
| sevenzip | 10.22 | 10.16 | −0.6% | tie |
| ffmpeg-compilation | 54.04 (ext 15) | 53.41 (ext 14) | −1.2% | tie-ish |
| argon2-hashing | 0.91–0.93 (ext 21-26) | 0.92 (ext 15) | −1±2% | tie/watch (0.01s quantization) |
| schbench-light p99 | 2476 | 2436 | −1.6% | marginal LOSS |
| x265 | 30.50 | 28.38 | −7.5% | LOSS (pre-existing: old-cake 30.45 ≈ M9 30.50) |
| perf-sched-pipe | 0.084 | 0.075 | −12% | LOSS (pre-existing: old-cake 0.083) |
| kernel-defconfig | 3.08 | 2.39 | −29% | LOSS (2.5s micro; attribution TBD) |
| blender-render | 1.25 | 0.94 | −33% | LOSS (1s micro; attribution TBD) |
| schbench p99 | 9072 | 5832 | −55% | LOSS (attribution TBD) |

## vs previous cake (b049e6e91 arm, same window) — M8/M9 guards
fork 0.134/0.136 · thread 0.124/0.124 · schbench-light 2476/2476 · schbench-sat 117376/117632 ·
pipe 0.084/0.083 · x265 30.50/30.45 · memcpy 6107/6008 · ccm 4.21M/4.24M (M8 alone was 3.79M = −12%,
M9 sleeper gate recovered) · argon2 0.91-0.93/0.90 (watch) · futex 4.79M/2.55M (+86%).

## Session mutations (each committed, one per commit)
- bd79ff4a6 banner (userspace only)
- a94bc8d4e M6 home wakes preempt before idle kick (futex-inert alone, load-bearing with M8)
- b049e6e91 M7 prev-first stickiness ahead of dfl (futex-inert alone; keeps spread benches intact)
- b6857e18b M8 saturated plain wakes converge onto empty waker (futex 2.55M→4.74M; ccm −12%)
- 2ffdcc7d1 M9 sleeper gate on convergence (ccm recovered, futex kept)

## Mechanism (traced, 2026-07-03/04)
Native futex: pair co-locates on waker's CPU (select_idle_cpu-fails→affine target); wake→run
p50 0.27µs, 95% of wakes preempt curr, sameCPU 99.9%. Cake pre-M8: split pairs self-sustaining
(prev/home stickiness), p50 1.42µs p99 19.9µs, 68% preempt coverage → 2.55M vs native 3.17M.
M8 reproduces convergence; M9 restricts it to tasks >1 slice behind frontier (sleeper-clamp
candidates) so cache-warm runners keep prev (ccm law: futex vs x265 want opposite placement).

## Next attack list
1. schbench (mid-tier) −55% — attribute (old-binary run), suspect: pre-existing requeue band vs
   native; NOT convergence (sat/light tie old-vs-new).
2. kernel-defconfig −29%, blender −33% — short micros, attribute + more reps.
3. pipe −12% — pre-existing; sync carve-out justification test = unify sync into gated plain path?
4. x265 −7.5% — pre-existing EEVDF loss (matches pre-rewrite −5.6%); spread/LB lever needed.
5. schbench-light −1.6% marginal.

## Harness facts used
- Native arm: `./cakebench one <slug> --capture stat --scheduler native` (verifies sched_ext idle).
- A/B arms: `--no-build` (HEAD) vs `--no-build --scheduler-binary /home/ritz/Documents/Repo/scx/ab_bins/scx_cake_<sha>`.
- ab_bins/ is git-excluded (.git/info/exclude); lineage stays clean-tree.
- argon2-p8/p32/p64 are NOT one-shot slugs (suite/custom only). Alias xz-compression→xz-compress, x265-encoding→x265, namd-92k-atoms→namd.

## FINAL (HEAD 595823a5e + comment fix, ~05:20 UTC)
Post-M15 additions: E2 sync-hoist NULL on pipe (reverted 0c447b565); prev-first probe REMOVED
(595823a5e) — its migration theory was falsified (M8 fixed the real cause; probe was futex-inert
in the final stack) and it was costing the spread benches: **x265 30.32 -> 28.86/28.88 (-4.8%,
now -1.7% vs native 28.38, controlled same-window)**; schbench-light improved to 2460 (native
2436, -1.0%). Guards clean: futex 4.69M (+48%), ccm 4.26M, fork 0.132, thread 0.125, memcpy 6079.

### Final scoreboard vs native EEVDF
WINS: futex +48-51%, ccm +35%, schbench-sat +19%, cache +12%, fork +10%, thread +6%.
TIES (within noise/quantization): y-cruncher +2.6%, xz +1.9%, memcpy, prime, namd, perf-memcpy,
7zip, ffmpeg, kernel-defconfig, blender, argon2, x265 -1.7%, schbench-light -1.0%.
LOSSES: perf-sched-pipe -12% (10ms absolute on an idle-machine micro; per-wake BPF-callback
cost vs EEVDF's inlined path — sched_ext-structural, E2 co-location null), schbench-mid -48%
(traced: cake serves wakes 60x faster [p99 7us vs 81us] but preempts workers 2.5x more ->
-2% RPS -> amplified at critical load; instant-wake-service is the game-first design intent —
revisit only with a game A/B in hand).

### vs installed 1.1.1 (goal 1)
Dominates: futex 4.69M vs ~1.7M; every bench >= the 2026-07-02 zero-loss gate values.

## LATE SESSION (HEAD 6c4f5b4e8, ~05:55 UTC) — inverted preempt floor
- v4 flag test: NULL both directions (pipe 0.082 vs 0.084, futex 4.74 vs 4.82 — inside noise). Stay v3.
- qwake removal + sync-hoist (M18): futex −8%, pipe unchanged → REVERTED. Pipe topology PROVEN
  already optimal via printk trace: every wake takes the sync path, pair co-located, 1 switch/msg;
  the −11% is pure BPF wake-path tax vs EEVDF's inlined C (5 distinct attempts, all null).
- ⭐ INVERTED FLOOR (M19/M20): home-wake preempt fires only when curr is YOUNG (ran < SLICE/32 =
  31us). Stateless spinner/worker discriminator: ping-pong curr is always young between switches
  (futex 3-13us); a mid-request worker has run long unswitched. Protecting old currs is EEVDF's
  worker-protection trade. schbench p99: 9072 -> 8056 (125us) -> 7368 (31us); SLICE/64 plateaued
  schbench (7336) and clipped futex (4.48M) -> 31us is the notch. Futex held 4.63-4.69M.
- Final guards (all hold): schbench-sat 116608 (WIN +19%), light 2460 (−1.0%), fork 0.135,
  thread 0.125, ccm 4.04M@ext17, x265 28.84 (−1.6%), futex 4.63M@ext9.6, no stalls.

### FINAL residual vs native EEVDF: schbench-mid −27% (7368/7432 vs 5832, from −121% at
session start), pipe −11% (callback tax, structural). Everything else WIN or tie.
Soft-preempt trim (M22, 62us runway for denied old currs) tested WORSE (7688) — the flush
returns 62us later plus extra dispatch rounds; REVERTED. Final HEAD 8616c0dff = the 31us
inverted-floor state. Futex final band 4.63-4.88M across 8 verification runs.

## EXTENDED ATTACK ROUND (~06:20 UTC, HEAD c56c6c693)
schbench-mid rotation hypothesis QUADRUPLE-falsified — shelf invariant at 7368-7432 under:
peer-global routing (M12), valve escape (M11), rescue-before-wake ring peek (M24, reverted
null), expiry-global rotation (M25, reverted: schbench-null AND ccm 3.72M regression).
M22 soft-preempt re-tested properly (2 reps): 7672/7800 vs 7368/7432 — confirmed worse, stays out.
M23 self-race-before-queue-lookup KEPT (hottest-path hash-kfunc cut; pipe band-bottom 0.083x2,
futex 4.71M held).

Current full M20-state schbench profile vs native: RPS 3412/3420 (parity), p50 4648/4648,
p90 4872/4840, p99.9 9648/9552, max 16832/16189, wake p99 4us vs 81us, wake p99.9 72us vs
929us — ONLY p99 differs (7432 vs 5832). Arithmetic signature: native p99-p50 = 1184us ~= a
HALF-QUANTUM remainder (its ~2.4ms slice, one partial wait); cake's = ~2.8 full 1ms quanta.
Next-session directions: (a) trace a single tail request end-to-end (which CPU, which quanta,
who held it); (b) the wake-service-vs-p99 trade needs the GAME A/B (project law: game tails
are the hard constraint — do not trade wake latency for this bench blind).
Pipe stands at 0.083 vs 0.075: topology proven optimal, residue = BPF callback tax
(7 distinct attempts; v4 null; qwake removal -8% futex, reverted).

## M26 — emptiness marks gate the steal ring (KEPT, HEAD cb294b409)
First true-stream bpfstats profile of the rewrite: cake_dispatch averaged 199.3ns/call — 30% of
pipe's entire wall — walking 15+ empty queues via rhashtable kfuncs on every going-idle
transition. Per-CPU 128B qmark slots (enqueue marks before insert; owner clears-then-peeks;
stealers hash only marked queues): dispatch 199.3 -> 68.1ns (-66%), total BPF time on a pipe
run 33.9 -> 8.2ms (4x). Wall unchanged (the burn was off pipe's critical path — idle-side) but
the cut removes SMT-sibling pollution from every idle transition, machine-wide. Guards all at
band: futex 4.73M, schbench 7368, x265 28.97, schbench-sat 116608, zero stalls.

Final pipe bound, now measured not estimated: critical-path BPF/msg = select 23.1 + running
24.0 + stopping 22.5 ~= 70ns == the entire gap to native (bare 0.081 vs 0.070). The loss
equals the cost of having BPF callbacks at all on a 750ns/op nanobench. Next instruction-cut
candidate (parked): replace running/stopping ktime pair with core-maintained
p->se.sum_exec_runtime deltas — saves ~20ns/switch but needs a second stamp channel so the
enqueue young-curr floor keeps a mid-slice-accurate clock; complexity/ns tradeoff deferred.

## FINAL-BINARY HARDENING SWEEP (HEAD 4671753a2 binary, ~06:35 UTC)
All re-verified on the exact shipping binary (M23 + M26 on top of the M20 stack):
fork 0.131 (WIN +12%), thread 0.121 (WIN +8.3%, best of session), ccm 4.11M (WIN +31%),
memcpy 6089 (tie+), prime 24894 (tie+), **schbench-light 2436 == native 2436 (DEAD TIE —
the -1.6% loss from session start is ELIMINATED; M26's cheaper going-idle dispatch closed
it)**, pipe 0.084 (loss stands), plus earlier this hour: futex 4.73M, schbench 7368,
x265 28.97, schbench-sat 116608 — all at band, zero stalls anywhere.

FINAL COUNT vs EEVDF on the shipping binary: 6 WINS, 13 TIES (incl. exact-equal
schbench-light), 2 losses (schbench-mid -21% [game-A/B-gated by project law],
pipe -11% [== the measured 70ns/msg BPF-callback floor]).

## FINAL FALSIFICATION ROUND (~06:50 UTC) — 19 schbench mechanisms, clamp direction closed
- M27 peer-wake deferral (rescue-budget split, frontier-classified): schbench 7464 = null. REVERTED.
- Tail attribution by raw sched trace: wake->run gaps >= 1.5ms are ABSENT in steady state (19 in
  10s, mostly non-schbench) — wake path fully exonerated. The tail lives in preempted-RUNNABLE
  intervals: 127 >= 0.5ms per 10s, max 6.19ms, at p99 frequency.
- M28 quarter-slice sleeper credit (the trace-attributed leapfrog fix): schbench 7448 = STILL
  null — the long runnable intervals coexist with but do not cause the p99 shelf — and futex
  COLLAPSED to 1.30M (-72%): the full-slice credit is load-bearing for handoff ordering.
  REVERTED; binary back to byte-verified 0eeb7100d8ae873c.
LAW: the sleeper-clamp credit is untouchable (full slice exactly); the schbench-mid shelf is
invariant under EVERY queue/preempt/rescue/credit policy tested (19 total) with all adjacent
metrics at native parity — consistent only with the rho~=0.98 knee amplifying residual
per-event cost. In-repo policy space is exhausted with receipts.

## ⭐ M29 — 2ms BASE SLICE (KEPT, commit 265df9ab6, ~07:00 UTC): the shelf finally moved
Load-sensitivity matrix cracked it: t=7 (16/16) cake WINS p50+p99+RPS outright; t=9 (20/16)
cake loses 7% RPS — the deficit GROWS with oversubscription = alternation refill tax, not
per-event overhead. 1ms slices switch 2.4x more often than native's ~2.4ms under persistent
sharing, paying an L2 refill per quantum; concentrated on doubled-CPU requests at the knee
(the p99 shelf), universal when oversubscribed. The pre-rewrite 1ms constant was never
re-measured on the rewrite (ladder law banned only DYNAMIC stretching; wake service now rides
preempts/kicks, so the old dispatch-cadence objection no longer binds).

2ms full validation: schbench 7368->6984 (loss -21%->-16%), sat 116608->100224 (win ->+30%),
cache 5.48->5.78M (win ->+18%), futex 4.72M held, light 2460, x265/memcpy/pipe unchanged;
margins traded: ccm ->+23% win, fork ->+4.7% win, thread ->+1.5% win. NO bench flipped.
3ms would flip thread/fork (trend ~+5%/ms) — 2ms is the multi-bench Pareto point.
CONFIRMED with rep2s: fork 0.137/0.142 (median 0.140, +6% win vs native 0.149), thread 0.130/0.130 (+1.5% win vs 0.132) — real mild erosion, 2.5ms would flip thread. WATCH: margins are thin; game A/B must cover the slice change
(1ms was the pre-rewrite "gaming operating point" — light load is keep-running-dominated so
impact expected nil, but MEASURE).

## M30 — doubled-continuation 3ms turns (KEPT, 806337857)
schbench flat (7016 ~= 6984: its tail turns aren't doubled-continuations), but ccm RECOVERS
+4.7% (3.99/4.11 vs 3.82/3.91 without — back inside the pre-M29 band; the constant 2:1
alternation is exactly the shape the longer turn amortizes). futex 4.73M held, thread guard
below. Net: pays back half the M29 ccm trade for free.

## ⭐ M31 — 3ms BASE SLICE (KEPT, 34c069b38): matching native's observed turn
Native schbench workers alternate in ~3.3ms turns (thread-health avg_slice). At 3ms base
(+M30 4.5ms doubled-turns): schbench 6984->6760 (-14% vs native), **sat 100224->70272 =
+51% WIN**, **ccm 4.50M = +43% WIN (above the entire 1ms-era band)**, cache 5.60M (+14%),
futex 4.72M held, light 2460, x265 28.74 (best of night, -1.3%), memcpy 6088, fork 0.136
(+8.7% — the "2ms erosion" was noise), thread 0.132 == native 0.132 EXACT TIE, pipe 0.083.
Slice trend on schbench: 1ms 7368+ / 2ms 6984 / 3ms 6760 — diminishing (~asymptote 6.4K);
the last ~10% is NOT turn-length. thread at exact tie = the binding constraint against 4ms.

## M32 — ops.tick mid-turn eligibility: FALSIFIED BOTH WAYS (reverted)
Tick-time yield-to-deserving-waiter regressed schbench 6760->7448: mid-turn entry restores
the alternation churn the long turns amortize. LAW: the uninterrupted turn IS the schbench
win; waiter latency is NOT the binding factor at 3ms — the residual -14% (6760 vs 5832) is
neither turn length (asymptote ~6.4K), nor entry latency (M32), nor any of 20 policy
mechanisms. Slice family closed. Next session: the residual needs a per-request trace
reconstruction (which phase of the tail request differs vs native).

## SCHBENCH-MID: DEFINITIVE COMPOSITION VERDICT (M31 binary, ~07:30 UTC)
Thread-health, cake-3ms vs native, same tool/window-class — cake is SUPERIOR on every
scheduling metric the workload experiences:
  run 11.55s vs 11.39s (+1.4% more worker CPU) | wait 40ms vs 70ms | invol preempts 515 vs
  1150 (less than HALF) | migr 600 vs 740 | messenger service 1us vs 40us avg (native
  messengers starve 800ms/12s) | RPS equal (3412/3420).
With composition superior and throughput equal, the residual p99 gap (6760 vs 5832) is
consistent with a MEASUREMENT SHADOW: native's starved messengers timestamp requests late,
hiding queue time from its own histogram; cake's instant dispatch exposes the full
queue+service interval. Closing it would mean deliberately starving our dispatcher to delay
the request clock — gaming the histogram, barred by the no-cheating constraint.
TIMESTAMP CHECK RESOLVED (schbench.c, masoncl/schbench): request clock = gettimeofday at
work_start AFTER the worker schedules, ended at do_work completion — messenger delay and
wake latency NEVER enter the request histogram. SHADOW THEORY REFUTED. Request p99 is purely
mid-work off-CPU time. That completes a documented PARADOX: cake loses LESS total mid-work
time (40ms vs 70ms/12s), with FEWER interruptions (515 vs 1150), and both wait-shape extremes
measure worse (1ms many-short: 7368; 3ms few-long: 6760; M32 forced-short: 7448) while native
sits between at 5832 with worse aggregates. The residual mechanism is not visible at
aggregate or distribution level — next session MUST do per-request reconstruction: pair
individual request intervals with their off-cpu events under both schedulers (perf sched
record + schbench worker tids), find what the 1% share that aggregates hide.

## PER-REQUEST RECONSTRUCTION (~07:45 UTC) — the diagnosis chain completes
34K request spans reconstructed per scheduler from raw sched_switch (request boundary =
voluntary sleep; span wait = sum of preempted-runnable time inside):
  cake-3ms: spanwait p50=0 p90=5us p99=226us, >=1ms spans 19 (0.06%), max 8.05ms
  native:   spanwait p50=0 p90=11us p99=192us, >=1ms spans 31 (0.09%), max 3.22ms
Scheduler wait at request-p99 differs by 34us; the request-p99 gap is 928us. VERDICT:
**off-CPU time cannot explain the schbench loss.** Tail requests under cake execute SLOWER
ON-CPU (cache/SMT warmth during their run time) — which retro-explains the whole session:
the slice family won by warming execution (fewer refills), and all 20 wait-targeting
mechanisms were null because waits were never the driver. Native's residual edge is
execution warmth on ~1% of requests — a placement-warmth-at-SMT-level research program
(cake already matches dfl's idle-core-first; the delta is subtler). Next instrument:
per-request IPC attribution (perf cycles/instructions sampling joined to spans).

## ⭐ M33 — peer wakes warm at their empty prev (KEPT, 43c329f74, ~07:40 UTC)
The warmth diagnosis made actionable: migration COUNTS equal but destinations opposite —
the global detour handed peer wakes to random blockers (always cross-core, cold L2) while
native's wake migrations stay near prev (often the SMT sibling: same core, SAME L2 on Zen4).
Peer wakes with an empty home now queue at prev, no preempt (fail eligibility, wait <= one
turn). The M12 trap that justified the detour died with 3ms turns + the young-curr floor.
**schbench 6760 -> 6328 (gap now -8.5%, morning was -121%)**. Guards ALL at band: futex
4.78M, fork 0.138, thread 0.128, sat 72576 (+50%), light 2444, ccm 4.51M (+43%),
pipe 0.083, x265 below. Session trajectory: 7368 -> 6984 -> 6760 -> 6328.

## M34 warm-steal: within-noise, reverted. M33 band firmed.
Sibling-first steal (both candidates, then sibling-only): 6456/6488/6888 vs M33's now-firmed
band 6328-6520 — no demonstrated win, reverted (binary byte-verified back to 24df01e2).
FINAL schbench: 6328/6520 (median ~6424) vs native 5832 = -10% (morning: -121%).

## M35 sibling-fallback: REVERTED — futex collapse via scoping
Busy-home wakes to the sibling queue: schbench band-flat (6344/6520) and futex 2.20M (-54%!)
— the else-branch caught busy-home SLEEPER wakes too, stacking futex children onto the
sibling pair's queue (cross-pair interference). Reverted; binary back to 24df01e2. LAW: the
global queue is load-bearing for busy-home sleeper wakes — any warmth fallback must exclude
the sleeper class. (A peer-only sibling fallback remains untested-clean for next session.)

## M36 peer-only sibling fallback: NEUTRAL, reverted
Correctly scoped (futex 4.76M safe — the sleeper-global law held), schbench exactly at the
M33 band (6328/6504): the busy-home peer population is too small to move p99. Family
exhausted at the enqueue-side; remaining cold pickups are the WAKE_DSQ consumers themselves.
Binary byte-verified back to 24df01e2 (M33-validated).

## M37 — 4ms probe: the slice dose-response curve is COMPLETE
schbench by base slice: 1ms 7368+ / 2ms 6984 / 3ms 6328-6520 / 4ms 7512. A genuine U-curve
with the measured minimum at 3ms, bracketed by data on both sides (the 4ms "thread ceiling"
extrapolation was replaced by an actual measurement — the binding constraint at 4ms is
schbench ITSELF, not thread). 3ms restored, binary byte-verified 24df01e2. The slice family
is closed with a complete dose-response, not an assumption.

## FINAL DATUM — residual cold-population inventory complete
Post-M33 worker migrations: 552/worker/12s (pre-M33: 600) — M33's schbench win did not come
from migration count; the remaining migrations are dfl's FORCED any-idle picks (prev AND
sibling both busy), i.e. the warm-first order bottoming out — waiting would cost more than
the cold start. Every cold-source branch now ends in a measured or structural bound. The
residual 496us mechanism is not nameable with tonight's instruments; the per-request IPC
join (perf cycles+instructions sampled, joined to reconstructed request spans, cake vs
native) is the required next instrument and the FIRST action of the next session.

## ⭐ RESIDUAL CONFIRMED SAME-WINDOW AND FULLY PRICED — the trade is one design choice
Same-window pair (ext 10.8/10.6): IPC 1.9012 vs 1.9201 = -0.98% REPRODUCED, all cache/branch
metrics again superior (misses -11%, L2 fills -11%, branch-misses -12%), p99 6504 vs 5848.
Final mechanism: co-residency is not queue-doubling (pigeonhole-equal for both schedulers) —
it is SIMULTANEOUS EXECUTION. Native's starved messengers (800ms runnable-wait/12s) keep an
extra thread OFF the cores at any instant; cake's instant wake service puts it ON a sibling.
THE WAKE-LATENCY WIN IS THE IPC LOSS — one design choice, priced end-to-end:
  wake p99 4us vs 81us  <->  machine IPC -1% at the knee  <->  request p99 -10%.
The game A/B decides which side cake holds. Original cross-window note: Whole-run hardware counters, cake-M33 vs native
schbench: IPC 1.901 vs 1.920 (-1.0%) while
EVERY cache/branch metric favors cake — LLC misses -12%, L1d -1%, branch-misses -8%, L2
fills -15% (warmer L2, as designed). The only stall source with no cache signature is SMT
issue-slot contention: cake's (deliberate, warmth-winning) stickiness lets doubled cores
stay doubled longer than native's balancer allows. The -1% IPC over the whole run
concentrates on co-resident intervals = the request-p99 tail = the final 496us.
NEXT-SESSION: (0) same-window counter pair to confirm the IPC delta is real, THEN the lever: SMT-pressure-aware stickiness — when this core is doubled
and another core's BOTH siblings idle-flux, the going-idle sibling should pull from the
doubled core preferentially (a steal-ring ordering by sibling-busy state, one qmark-style
BSS hint per core), giving native's nr_running-balance without a periodic balancer.
Pipe remains the 70ns callback floor. Everything else: WIN or TIE, receipts throughout.

## MECHANISM CORRECTION + THE GAME-FIRST READING (final)
Messengers acquitted of the IPC delta (0.2% duty cannot move machine IPC). The co-execution
difference is the WORKER WAIT DISTRIBUTION: native lets a few workers stall long (70ms
runnable-wait vs cake's 40ms, concentrated) and the stalled workers' SIBLINGS execute solo
(superlinear SMT yield) — concentrated victims, clean p99. Cake keeps all 18 threads
flowing: nobody stalls, everyone co-executes, a uniform ~1% IPC tax whose tail lands on the
alternation-quantum requests. RPS equal — the two strategies conserve throughput and differ
only in WHO pays.
GAME-FIRST READING: cake's schbench-mid residual is a SMOOTHNESS SIGNATURE — native buys
its p99 by concentrating stalls on victim threads; cake refuses to create victims. For
frame pipelines, victimlessness (no stalled thread = no hitched frame) is the design goal
itself. The game A/B tests exactly this, and it is the only remaining arbiter.

## THE CLOSING FACT — equal total pain, different slicing (from the histograms all along)
schbench-mid full percentile comparison (matched windows): p50 4648==4648, p90 4872~=4840,
**p99.9 9648 ~= 9552 (EQUAL)**, **max 16832 ~= 16189 (~equal)**, RPS equal. The ONLY
differing point is p99: native runs clean-then-steep (pain concentrated past p99 on victim
threads), cake runs gradual (pain spread into p99, no victims). TWO EQUAL-AREA
DISTRIBUTIONS, DIFFERENT SHAPE — the headline metric samples one point of them. Every
implementable reshaping (delaying 0.1% of wakes to push pain past the sampling point) is a
preempt-floor variant this session already falsified in both directions (M10, M19-M21
optimum, M22 twice), and deliberate wake-delay to game a percentile crosses the no-cheating
line. Frame-time analysis reads BOTH 1%low and 0.1%low — cake's shape (equal 0.1%, gradual
1%) is the game-preferred one. Final arbiter: the staged game A/B.

## ⭐⭐ M38-M40 — THE DEADLINE MARGIN: schbench-mid CONVERTED TO TIE (HEAD c1561cfc4)
The percentile-shape analysis un-dismissed the margin lever: the 2026-07-01 falsification
measured a margin against a STALE curr vtime; atop the correct live charge it is pick_eevdf
semantics — a preempt demands a real deadline win, not bare eligibility. Marginal
(flap-zone) wakees now wait the turn out; deep sleepers (full-slice clamp credit = 3ms)
preempt as before. Dose-response: margin SLICE/8 -> 6216, SLICE/4 -> 6072, SLICE/2 ->
**5928 5928 (bucket-identical reps) vs native 5832 = -1.6% TIE-BAND** (same criterion as
x265/light/thread ties all session). Cost: futex 4.66 -> 3.99M — still **+26% WIN** vs
native 3.17M. Full M40 guard sweep: sat 72576 (+50%), fork 0.133 (+11%), thread 0.133x2
(-0.8% tie), light 2452, ccm 4.03M (+28%), x265 28.72 (-1.2% tie), no stalls anywhere.

# SCOREBOARD AFTER M40: 5 WINS + 15 TIES + 1 LOSS (pipe -11%, the 70ns callback floor).
# schbench trajectory tonight: 7368 -> 6984 -> 6760 -> 6328 -> 6216 -> 6072 -> 5928.
Game A/B note: the margin trades saturated wake-service depth for deadline discipline —
futex still +26%; light-load (game) wakes direct-dispatch and never see the margin.

## FINAL VERIFICATIONS
Native pipe band firmed with reps: 0.073/0.075/0.075 — cake 0.082-0.086: the -11% is real
from both sides; the sole remaining loss = the measured BPF-callback floor (kernel scope).
M40 compute spot-checks: memcpy 5975@ext10.5 (tie band vs native 6040 at these ext levels),
prime 24.9K-class expected; the margin mechanistically touches only saturated home-preempts
(compute wakes are rare + direct-dispatch), remaining suite mechanically unaffected —
full-suite re-sweep on M40 recommended as next session's opener alongside the game A/B.

# SESSION FINAL BOARD: 5 WINS + 15 TIES + 1 LOSS (pipe, callback floor).
# Goal 1 (installed cake): ACHIEVED all benchmarks. Goal 2 (EEVDF): 20 of 21 win-or-tie.

## M41 scx_bpf_now: FALSIFIED — the ktime pair is load-bearing precision (reverted)
Swapping all four clock reads to the rq-cached scx_bpf_now collapsed futex 3.99M -> 2.53M
(-37%): cross-rq clock skew breaks the live-charge/young-window math (31us threshold,
remote stamp reads). LAW: eligibility clocks must be globally coherent — bpf_ktime only.
The last in-repo nanosecond is measured un-cuttable; binary byte-verified back to 51d95fe6
(the M40-validated configuration). Pipe's -11% is final for this repository.

## RECORD CLOSED — final-binary pipe row (hash-verified in-row: 51d95fe6)
pipe 0.082 @ext7.0 on the exact M40 shipping binary — band 0.082-0.086 vs native
0.073-0.075 (3 reps each side). Every benchmark in the gate now has a row on (or
byte-equivalent to) the final binary. SESSION FINAL: Goal 1 ACHIEVED all benchmarks;
Goal 2 = 5 WINS + 15 TIES + 1 LOSS (pipe = the struct_ops dispatch tax, bounded five ways,
14 probes terminated). Next actions live outside this repo: game A/B (staged), kernel
callback inlining (scoping), gate ruling (user).

## THE CLOSING EQUATION (final-binary bpfstats, bare pipe 100K, 0.081 wall)
TOTAL BPF execution: 8.3ms per 100K messages = 83ns/msg (select 24.2, running 24.1,
stopping 22.5, dispatch 11 amortized, enqueue negligible). Pipe deficit to native:
8 +/- 1 ms. THE LOSS EQUALS THE SCHEDULER'S OWN EXECUTION TIME TO THE MILLISECOND.
Nothing fattened across M29-M40; every callback at its removal-tested floor. Beating
native on this bench requires the callbacks to take zero time — to not exist. Q.E.D.
for this repository; the remainder is the kernel's calling convention.

## FULL M40 RE-SWEEP (final binary, ~08:45 UTC) — zero inference remains
xz 6.39 (+1.1%), 7zip 10.07 (+0.9%, session best), y-cruncher 18.63 (+2.2%), kdef 2.44
(-2.1% tie), blender 0.96 (tie), ffmpeg 53.42 vs 53.41 (EXACT tie), **perf-memcpy 33.02
vs 31.13 GB/s = +6.1% WIN (improved from tie)**, cache 5.91M (+21% WIN), namd 45.70
(+0.04% tie), argon2 0.93@ext42 (noisy-window, tie-class). All rows scheduler-verified.

# FINAL BOARD, fully measured on the shipping binary:
# 6 WINS (sat +50%, ccm +28%, futex +26%, cache +21%, fork +11%, perf-memcpy +6%)
# 14 TIES (incl. schbench-mid -1.6%x2 converted tonight, thread -0.8%, x265 -1.1%, ffmpeg exact)
# 1 LOSS (pipe -11% == total BPF execution time, kernel-owned to 88%)

## KERNEL WORK ORDER — closing pipe (the 21st benchmark), for the next patched-kernel build
You already run patched kernels for this project (SCX_ENQ_KICK_IDLE era). Pipe's 8ms/100K
deficit decomposes into exactly three kernel-side cost centers, each with tonight's number:

1. TRAMPOLINE DISPATCH (~10-15ns x 3 callbacks/msg): struct_ops calls indirect through BPF
   trampolines. Upstream direction: static_call/direct-call optimization for struct_ops
   (bpf_struct_ops_prepare_trampoline). A patch caching direct calls for the hot trio
   (select_cpu/running/stopping) in kernel/sched/ext/ext.c call sites would cut ~30-45ns/msg.
2. CLOCK (~30ns/msg): running+stopping each call bpf_ktime_get_ns because scx_bpf_now's
   per-rq cache skews cross-rq (proven: -37% futex). Kernel fix: pass rq->clock_task
   (already computed in update_curr_scx, globally coherent enough at the callsite) INTO
   ops.running/ops.stopping as an argument — zero BPF-side clock reads. API addition.
3. IDLE/IPI: REFUTED BY DIRECT MEASUREMENT (round 30) — RES-IPIs during a 100K pipe run:
   cake 3 vs native 6; CAL: 109 vs 115. No IPI channel differs: AMD's default MWAIT idle
   monitors need_resched even without a cpuidle driver, so idle wakes are already IPI-free.
   The round-29 BIOS/idle=poll hypothesis is dead — DO NOT spend a reboot on it. This
   defends the BPF-execution equation against its last challenger: bare pipe gap 8ms ==
   measured 8.3ms total BPF. Items 1+2 (kernel patch) are confirmed as the only path.
Items 1+2 sum to ~60-75ns of the ~90ns gap: a plausible full close ON THE SAME KERNEL for
both schedulers (native untouched by 1+2 — they only cheapen scx). Recipe: patch the 7.2-rc
tree at /home/ritz/Documents/Repo/linux, build with the CachyOS config, install alongside,
A/B pipe under the new kernel with the SAME cake binary. This is a user-hands operation
(build+reboot); the spec is complete here.

## USER RULINGS + M42 (sched_ext-only era)
NO KERNEL PATCHES (user, 2026-07-04): the compile-tested ext.c clock patch was discarded and
the linux tree reverted clean. All work sched_ext-only from here.
M42 SMT-sibling sync topology: FALSIFIED — pipe 0.104 (switches 2.0/msg + SMT issue sharing).
The pipe topology space is now FULLY ENUMERATED: split 0.082 < co-located 0.083 < sibling
0.104. Cake sits on the measured optimum. Binary back to 51d95fe6.

## M43 — stopping's clock eliminated (KEPT, 48118e234, sched_ext-only era)
update_curr_scx() precedes both ops.stopping call sites (verified in tree), making
p->se.sum_exec_runtime boundary-exact there: stopping now charges sum_exec deltas via an
owner-only 128B slot — two loads replacing ~15ns of bpf_ktime_get_ns on EVERY context
switch machine-wide. The ktime stamp stays for enqueue's eligibility (remote mid-slice
reads are where sum_exec is tick-stale — the M41 poison, correctly scoped this time).
Guards: futex 3.95M (+25%), schbench 6008 (band-best), pipe 0.082, sat 72064 (+50%),
ccm 4.11M — all hold, zero stalls. LAW: clock reads are only owed where mid-slice
precision is consumed; switch boundaries are core-charged for free.

## AUTONOMOUS ROUNDS (M44/M45, ~11:00 UTC)
M44 sync co-location under M43 costs: printk probe RESOLVED the E2 contradiction — pipe
wakes DO carry SYNC (0x18, 20002/20002), gates pass, both tasks co-locate on one CPU; the
'never engaged' read was a ctxsw-signature misread, so E2-era nulls were VALID co-location
measurements. Topology-indifference is now probe-certified (all three engaged and measured:
0.082-0.084). M44 reverted (no gain). M45 margin 5/8-slice: schbench SATURATED at 5928
(same bucket as /2) while futex fell to 3.24M — the margin dial is Pareto-final at SLICE/2,
bracketed from both sides. Binary restored (M43-validated d45d5d23).

## M46 — dispatch hysteresis dose-responsed and closed (reverted)
2x-slice arm: schbench 5896 (new best bucket, -1.1%) but futex COLLAPSED to 2.16M (below
native): the doubled margin strands the non-converged wake fraction — the 1-slice value is
load-bearing exactly as the lock-storm origin recorded. Dial bracketed: 2x kills futex for
+32us schbench; /2 would only trade the other way. 1x SLICE is Pareto-pinned. Binary
restored to M43-validated d45d5d23. Every original constant is now dose-responsed.

## ⭐ M47 — CLASS-AWARE DISPATCH HYSTERESIS (KEPT, 39726c81a)
The M46 dose-response split by wake class; the clamp-signature classifier resolves it
statelessly: sleeper heads (>half-slice behind frontier — the handoff shape) keep the
load-bearing 1x margin; frontier-peer heads wait behind own work at 2x, aging into sleeper
class if stranded (freeze-out seal). FULL GUARD SWEEP: **futex 4.25/4.31M (+34%, ABOVE the
prior 3.95-4.00 band — peer stragglers no longer jump sleeper children in the compare)**,
sat 71552 (+50% stands), schbench 6008 (band), ccm 4.13M@19 (band), light 2452, fork 0.131,
thread 0.128, pipe 0.082, x265 below. Zero stalls. Futex win margin grows for free.

## M48 — doubled-turn multiplier bracketed (reverted)
2x arm: sat 79744 (-11% — deep-queue waiters starve behind 6ms turns), ccm 4.31 (band-top,
inconclusive), schbench/futex neutral. Net negative; 1.5x stands, dial bracketed
(1.0 < 1.5 > 2.0). Binary restored to M47-validated c89f7bf9.

## M47-BINARY FULL BOARD (every bench measured directly on c89f7bf9, ~11:25 UTC)
WINS: sat 71552 (+50%), futex 4.25/4.31M (+34%), ccm 4.13M (+28%), cache (below), fork
0.131 (+12%), perf-memcpy 32.06G (+3%). TIES: y-cruncher 18.41 (+3.4% session best),
xz 6.32 (+2.2%), memcpy 6090, prime 24880, 7zip 10.08, namd 45.84, blender 0.95, ffmpeg
53.48, schbench 5896-6024, light 2452, thread 0.128, x265 28.96, sat/light siblings.
LOSS: pipe 0.082. kdef 0.42 row DISCARDED (warm-cache artifact). Every dial in the
scheduler is bracket-measured; 7 kept families; the M47 champion is the strongest and
most completely characterized scx_cake ever built.

## FREQUENCY DIMENSION — CLOSED BY CONFIGURATION
amd-pstate-epp active, governor=performance, EPP=performance: firmware runs max-perf policy
autonomously; scx_bpf_cpuperf_set hints are moot on this box. Cake's frequency-blindness
(vs EEVDF's PELT->governor integration) costs nothing under this configuration. This was
the last untouched design dimension: the audit is now TOTAL — every dial bracketed, every
routing family measured, every topology probe-certified, both clock laws established,
frequency moot. Seven kept mechanism families. M47 champion c89f7bf9.

## ⭐ SCHBENCH-MID: TIE CERTIFIED BY RANGE OVERLAP (~11:30 UTC, interleaved ABBA pairs)
Fresh matched-window pairs on the M47 champion: cake 6040 vs native 6040 (DEAD HEAT, same
bucket, ext 11.7/12.1) and cake 5992 vs native 5976 (+16us = 0.27%, ext 11.27/11.26).
Full matched-window bands: native [5832, 6040], cake [5896, 6040] — massive overlap.
By the project's standing criterion (ranges overlap => TIE, predates tonight), schbench-mid
is a STATISTICAL TIE, certified. The morning's 5832 reference was native's best rep, not
its band. BOARD: 6 WINS + 15 TIES + 1 LOSS (pipe, the callback floor).

## PIPE RE-CERTIFIED UNDER THE SAME RIGOR (ABBA on M47 champion)
cake [0.081, 0.083] vs native [0.070, 0.075]: bands non-overlapping, gap 8-13% — the loss
stands under the identical fresh-pairs discipline that certified schbench's tie. Both final
classifications now carry equal methodological weight.

# ═══ SESSION FINAL BOARD (M47 champion c89f7bf9, every claim fresh-pair rigorous) ═══
# 6 WINS: sat +50% · futex +34% · ccm +28% · cache +13-21% · fork +12% · perf-memcpy +3-6%
# 15 TIES: schbench-mid TIE-CERTIFIED (dead heat 6040=6040) · ycr +3.4% · xz +2.2% · 12 more
# 1 LOSS: pipe (= total BPF execution time; every design dimension measured closed)
# Goal 1 (installed cake): ACHIEVED all benchmarks. Autonomous segment: M43+M47 kept,
# all dials bracketed, topology probe-certified, frequency moot, schbench certified.

## CERTIFICATION SWEEP (native second reps, ~11:37 UTC) — board restructured honestly
- ⭐ xz: WIN CERTIFIED — cake [6.32, 6.39] entirely better than native [6.46, 6.46]. 7th win.
- namd [45.66,45.72] vs [45.70,45.84], 7zip [10.11,10.16] vs [10.07,10.22], ycr touch at
  18.41: ties CERTIFIED by range overlap.
- x265: bands DO NOT overlap — cake [28.70, 28.97] vs native [28.38, 28.45] (M47-neutral,
  clean rep 28.80). DUAL-CRITERION, stated plainly: tie under the session's +/-2% convention
  (-0.9 to -1.2%), NARROW LOSS under strict range-overlap. The residual is the structural
  under-spread remainder (was -7.6% before probe removal).

# BOARD (both criteria stated):
#   strict-overlap criterion: 7 WINS + 12 TIES + 2 narrow/structural losses (x265 -1%, pipe -11%)
#   session +/-2% convention:  7 WINS + 13 TIES + 1 loss (pipe)
# Either way: Goal 1 achieved everywhere; pipe = the callback floor; x265 = -1% under-spread.

## M49 — SMT VACATE (event-driven active balance) FALSIFIED AND DELETED
Three verifier lessons + a clean falsification: (1) dispatch's tail has NO remaining
verifier budget (even 3 straight-line curr reads E2BIG — the tail verifies against every
steal-ring exit state); (2) ops.update_idle = a separate program with its OWN budget, the
correct host for idle-entry probes (+ KEEP_BUILTIN_IDLE to preserve builtin tracking);
(3) the mechanism itself: INERT on x265 (at 2x oversub no fully-idle core ever exists, and
dual->half-idle vacates leave the dual count unchanged by counting), sub-resolution hairs
on fork/thread (0.130/0.126 band-best), and a borderline schbench COST (6136 — each vacate
preempts a worker mid-request). Anti-bloat law: deleted. LAW: active balance needs
full-idle destinations, which oversubscribed spread-hungry loads never present; where
triggers exist (light flux), the preempt disruption outweighs placement gain.
Binary restored: c89f7bf9 (M47 champion) — verify by hash.

## M50 — peer-home routing TERMINATED AT DESIGN (the classifier boundary)
Fresh x265 attribution: cake now OVER-migrates (99-123K vs native 61K; 0.27/switch vs
0.15) — the June under-spread story is dead. Wanted: route busy-home PEER wakes home for
warmth (third classifier application). DIES: the busy-home global branch's occupants are
ALL deep-sleepers by construction — the M14 margin (d < SLICE/2 => home) already homes
every shallow wake, so x265 workers (deep inter-row sleeps) and futex children (handoff
sleeps) share one clamp signature. They differ by ROLE, invisible per-wake to a stateless
design. Routing all deep-sleepers home = M35 (futex -54%, measured). LAW: the clamp-depth
classifier separates spin-vs-sleep and fresh-vs-stranded, but NOT worker-vs-handoff among
deep sleepers — that distinction needs history, which the design forbids. x265's -1% is
attributed (excess cold global pickups) but unfixable statelessly.

## M50b — kernel wake-history classifier NULL (probed)
p->wakee_flips (EEVDF's wake_wide datum) measured on the busy-home global branch of both
benches: futex p50=308/p90=1418 vs x265 p50=709/p90=2186 — heavy overlap, no separating
threshold. The classifier boundary stands against kernel-maintained history too; the M43
read-kernel-state move has no purchase on role separation.

## ⭐ M51 — TARGETED WARM-SIBLING IDLE KICK (KEPT, 8529e7ab1) — 8th family
Busy-home wakes stay in WAKE_DSQ (flow preserved) but the idle kick now tries prev's SMT
sibling first (shares prev's L2): the likely first collector picks up warm. No
classification needed — the strictly-better-or-equal shape that survives the classifier
boundary. x265: 28.66/28.67 at ext 13.1-13.8 — NEW BEST BAND (was 28.69-28.97), gap to
native narrowed ~1% -> 0.74%; migrations unchanged (warmth not count, as designed).
Guards all green: futex 3.98M, schbench 5976 (the native-matching bucket), sat 71552,
pipe 0.083, ccm 4.29M. The remaining 0.74%: cold pickups where no warm idle exists
(sibling busy) — untargetable by construction.

## M52 — targeted home kick REVERTED (the steal-away was a spread feature)
Idle-home wakes kicking their own target (instead of pick_idle-any): pipe/futex neutral,
x265 28.85@14.0 — above the M51 band with only half the delta explained by ext. Mechanism:
the pick-any "steal-away" is a LATE-BREAKING SPREAD CHANCE (a full-idle core that opened
after select's dfl miss collects the wakee) — spread-positive for parallel loads, and x265
sits on the spread side of the warm-vs-spread axis. M51's kick (global-queue wakes) stays:
it targets the WAKE_DSQ collector, where flow is preserved for anyone. LAW: home-queue
wakes may be stolen INTO opening capacity — that leak is load-balancing, not waste; only
GLOBAL-queue collection benefits from warmth targeting.

## M53 — full-idle-core collector REVERTED
CORE-first pick for the global-wake collector: x265 28.75@13.0 (hair worse than M51's
28.66-28.67 — the full-core pick lands FAR from prev; solo execution didn't cover the
distance), schbench/futex neutral. The M51 configuration (warm sibling first, plain-any
fallback) is this axis's measured optimum. The collector axis is now fully swept:
sibling(prev) > any > full-core-first.

## M54 — empty-queue refill 2x: NEUTRAL, reverted
ccm 4.05M / futex 4.20M / schbench 6008 / sat 71552 — all band-identical. The refill is
rare where queues churn (oversubbed compute keeps queues non-empty) and its cadence was
never the cost elsewhere. Slice family now completely swept: enqueue base (U-curve at
3ms), queued-behind bonus (1.5x bracketed), refill (invariant).

## Inventory completion (round ~70): two final items
- enable's initial vtime (= frontier, no credit): left untouched — fork already wins +12%,
  EEVDF itself defaults against child-runs-first; speculative sign on a winning axis.
- ⭐ GAME-ERA FLAG: the sleeper clamp credit is WEIGHT-BLIND (frontier - SLICE flat for all
  nice levels) while EEVDF's placement lag is weight-scaled. Inert on this all-nice-0
  suite; potentially material for game threads at negative nice. Test in the game A/B era.
The suite-relevant mutation space is exhausted at this depth: every dial bracketed, every
axis swept, 3 families kept this segment (M43 clock cut, M47 class hysteresis, M51 warm
collector), 11 falsifications banked as laws.

## ⚠ x265 RECORD CORRECTED — matched-window ABBA (~12:25 UTC)
True same-window pairs (all four runs within 2 min, ext 12.2-13.3): cake 28.79/29.08 vs
native 28.44/28.48 — MEDIAN GAP -1.7%, not the -0.74% previously reported. The optimistic
number compared cake's best band against native reps from a QUIETER window (the
positive-noise trap the user explicitly warned about). M51's "x265 new best band" claim is
DEMOTED to within-spread — its keep stands on zero regressions + the collection-warmth
mechanism, not on x265 movement. x265 stands: dual-criterion, honest median -1.7%
(inside the +/-2% session convention, outside strict overlap). Eighth self-correction.

## M55 — staleness-gated steal REVERTED (two-sided falsification)
(a) x265-INERT: the clamp lifts every woken task a slice back AT INSERT, so all wake-class
heads pass the staleness gate — the gate is transparent exactly where x265's migrations
live (wake pickups). The clamp erases sleep-depth history; fifth confirmation of the
classifier boundary. (b) schbench 6296 (band 5896-6040): protecting fresh CONTINUATIONS
from steal = idle-while-work-queued, the anti-conservation tax, measured. sat/ccm/futex
neutral. LAW: EEVDF affords migration_cost gating only because its idle balance carries
load knowledge; a stateless per-queue freshness test either passes everything (wakes) or
starves capacity (continuations). Also banked: ring-as-global-fn + span-32 pattern for
any future ring surgery (MAX_CPUS-bounded loops + peek = E2BIG). Binary restored ea4a01c2.

## 🛑 FUTEX OVERSUBSCRIPTION HOLE — user-prompted discovery (~15:10 UTC)
The user asked "did you test many threads like argon2 64?" — argon2 held (p32 +8.8% WIN,
p64 +1.6% WIN, matched pairs), but FUTEX COLLAPSES past 1x cores:
  t16 (suite default --futex 0 = nproc): cake 4.2M/s vs native 3.2M = +34% WIN
  t32: cake 995K/s vs native 2.80M = -64% LOSS
  t64: cake 201K/s vs native 2.49M = -92% LOSS (same CPU burned, 1/12 the work)
The suite's default sat EXACTLY at the cliff edge — single-config validation trap, again.
NOT a regression: the 1ms-era binary (cb294b409) scores 534K/s at t32 — today's champion
is 1.9x BETTER there; the hole is the rewrite's standing weakness vs EEVDF.
MECHANISM (partial): at 2 pairs/CPU the waker's vtime queue is never empty -> the
convergence gate never fires -> split pairs never reunite -> every wake goes global (pair
scatter is self-sustaining). M56 (sleeper-wakee convergence at any depth): 774K/s — WORSE
(over-concentration), REVERTED. Co-located pairs' wakes DO stay home at depth (local ->
home unconditional); suspected additional splitter: the steal ring pulling queued wakees
off pair CPUs at oversub. UNSOLVED — three levers measured, ALL below the champion's 9.95M at t32:
  M56 sleeper-wakee convergence at any depth: 7.74M (over-concentration)
  ring-off diagnostic: 7.90M (the ring is load-bearing work conservation, NOT the splitter)
  M57 deep-wakee home preempt (d > SLICE): 7.02M (flushing the other pair's mid-turn task
  thrashes ITS progress — mutual pair-thrash)
Every single-lever move is NEGATIVE: the champion is a strong local optimum even in the
collapse regime. Native's t32 shape is a different STEADY STATE (pairs pinned 2-per-cpu,
local wake queueing, per-cpu eligibility preemption) — reaching it needs a coordinated
regime, not a lever. Next-session directions: depth-bounded convergence (<=1 exact),
pair-affine WAKE_DSQ pickup (collector prefers heads whose prev == self), oversub-gated
regime switch (nr_running > nr_cpus => local-first wake routing a la suite of 06-27
herd-break).
BOARD IMPACT: two new measured losses vs EEVDF outside the 21-bench suite
(futex-t32, futex-t64). Goal-2 accounting must include them.

## ⭐⭐ M58 — BACKLOG-GATED REGIME SWITCH (KEPT, c1d936468) — 9th family, the herd answer
Global backlog IS the oversubscription signature: a wake already waiting in WAKE_DSQ means
scattering another splits its pair for nothing — stay home (native's oversubscribed shape:
pairs stable at prev, vtime-fair locally). One condition on the global-insert branch.
RESULTS: t32 995K->2.13M/s (+114%, 76% of native), t64 201K->995K/s (+390%, 40%), sat
IMPROVED 71.5K->67.5K (+56% total win), costs: t16 -8-10% of surplus (3.77-3.86M, still
+19-22% WIN), fork 0.136 (still +9% WIN), schbench band-edge at elevated ext, pipe/ccm
unchanged. After THREE single-lever falsifications, the regime FRAME (route by system
state, not per-wake state) was the answer — the 06-27 herd-break reborn stateless.
t32/t64 remain losses vs native (76%/40%) — next-session parity directions: pair-affine
WAKE pickup, depth<=1 convergence, backlog-depth-scaled homing.

## M59 — depth<=1 convergence REVERTED (undoes M58)
t32 12.2M vs M58-alone's 21.3M: even BOUNDED convergence admission over-concentrates in
the backlog regime (the M56 failure family, third confirmation). LAW: under backlog-homing
(M58), pairs re-converge NATURALLY through blocking cadence — select-side forcing only
fights it. The convergence gate stays empty-only. M58-alone = the herd configuration.

## M58 FULL VALIDATION COMPLETE (~15:28 UTC) — champion f9cc9da1
Remaining backlog-touched benches: x265 28.78 (band-bottom), cache 6.15M@19.3 — ABOVE band
(+25% over native, improved), light 2468 (band), thread 0.135 (band-edge tie). Zero
unaccounted regressions. FINAL SESSION BOARD (champion f9cc9da1, M58 era):
  Suite: 7 wins (sat +56%, futex-t16 +19-22%, ccm +28%, cache +25%, fork +9%,
  perf-memcpy, xz) + 12-13 certified ties + x265 -1.2/-1.7% + pipe -11%.
  Oversubscription (user-prompted coverage): argon2 p32 +8.8% WIN, p64 +1.6% WIN;
  futex t32 76% of native (was 36%), t64 40% (was 8%) — transformed, parity open.
Goal 1 (installed cake): intact. The herd hole went from unknown -> measured -> 2-5x
recovered -> mapped for parity, in one user question's wake.

## M60 — deep-preempt re-test under M58: falsification REPLICATES (reverted)
t32 17.85M vs M58-alone 21.30M (-16%): flushing mid-turn currs thrashes even with pairs
co-resident. The t32 lever map now: M56 7.7M / ring-off 7.9M / M57 7.0M (pre-M58 state),
M59 12.2M / M60 17.9M (post-M58) — M58-alone 21.3M stands. Native's 1x->2x degradation is
only -12% (3.2->2.8M) vs cake's -45% (3.8->2.1M): the residual is EEVDF's us-granular fair
churn that cake's young-window blocks and deep-preempt overdoes. Next-session direction:
SHARE-AWARE preempt (curr beyond its per-occupancy fair share, ran x local_depth > SLICE)
— the middle ground between blocking and thrashing.

## M61 — share-aware backlog flush: falsified (reverted). The t32 lever map is CLOSED.
15.42M vs M58-alone 21.30M (-28%). SIX levers measured against M58-alone (M56 7.7 /
ring-off 7.9 / M57 7.0 pre-M58; M59 12.2 / M60 17.9 / M61 15.4 post-M58) — every one
loses. LAW: in the backlog regime every added preempt or routing force REDUCES throughput;
M58's minimal intervention (home the wake, change nothing else) is the entire win. The
t32/t64 residual (76%/40% of native) is not reachable by single-lever modification of
this design — it lives in EEVDF's per-CPU eligibility ordering as a WHOLE. Parity, if
reachable, is an architecture question for a fresh session, not a lever question.
M62 (quarter-slice on backlog-homed wakes): 17.99M — SEVENTH falsification, closing the
map from the rotation direction too: the herd regime rejects preempts, routes, forced
convergence, steal changes, AND faster rotation. M32's uninterrupted-turns law extends
into the backlog regime. M58-alone is the fixed point of this design at oversubscription.
FINAL champion: f9cc9da1 (M58 era). Window closed at seven falsifications.

## SCALING MAP (user-prompted round 2, ~15:42 UTC) — the full oversubscription picture
Same-window custom-slug pairs, champion f9cc9da1 vs native:
  argon2:  p16 tie, p32 +8.8% WIN, p64 +1.6% WIN (p8 directional-only, ext-mismatched)
  futex:   t16 +19-22% WIN, t32 -24%, t64 -60% (post-M58; was -64%/-92%)
  cache:   t16 +13-25% WIN, t32 PURE -16% (2.79 vs 3.33M/s), t32-in-mix -26%
  memcpy:  t32-in-mix +12% WIN
  ccm mix: t16(2x total) +28% WIN, t32(4x total) = cache half loses, memcpy half wins
  BISECT: cache-t32 loss PRE-DATES M58 (M51-era binary 2.11M < M58's 2.26M — M58 helps
  here too). Standing pattern: benches whose 1x win rides cake's wake/locality handling
  FLIP SIGN past saturation (cache, futex); pure-compute (argon2, memcpy) holds or wins.
  EEVDF's graceful oversub degradation = the load-balanced fair rotation cake's design
  traded away for 1x locality. schbench-t32 unmeasured (schbench-sat 67456 = its own
  oversub point, +56% WIN — the exception, wake-queue-shaped).
NEXT-SESSION FRONT (with the t32 seven-lever map): the oversub regime as a whole —
M58 extended the design's reach 2-5x; the remainder is the architecture question.

## M63 FAMILY — depth overflow: worked, conflicted, reverted (full spec banked)
M63 (depth>=2 continuation overflow): cache-t32 2.79->3.66M = +10% WIN over native — the
missing saturation balance CONFIRMED as cache-t32's mechanism. But sat 67K->178K (uniform
depth: overflow helps nobody) -> M63b added empty-global gate: sat restored 72K, cache-t32
3.32M tie — but futex-t32 2.13M->0.64M: the overflow SHARES WAKE_DSQ with M58's backlog
signal and corrupts it (overflowed continuations look like waiting wakes; pairs re-split
and the homing gate misfires). M63c pmark (preempt-vs-expiry discriminator, third BSS-mark
use): NULL — the corruption is channel-sharing, not requeue-class. REVERTED to M58-alone
(futex t32 2.13M > cache's 0.5M gain).
NEXT-SESSION SPEC: a separate OVERFLOW_DSQ (id MAX_CPUS+1) — depth-2 expiry overflow
routes there, dispatch consumes own -> WAKE -> OVERFLOW, M58's signal reads WAKE only.
Restores M63's cache win without touching the herd channel. Requires one more dispatch
consume slot (verifier budget: use the ring's global-fn pattern if needed).
FINAL WINDOW STATE: champion f9cc9da1 (M58), byte-verified through the M63 excursion.

## ⭐⭐⭐ M64+M64b — OVERFLOW_DSQ + pmark: THE OVERSUBSCRIPTION ANSWER (KEPT, f83d41067+)
Separate overflow channel (OVF_DSQ, consumed own->WAKE->OVF) + preempt-mark (spinner
requeues never overflow; expiry stragglers rebalance). SCOREBOARD:
  futex t32: 2.13M -> 3.59M/s = 128% of native — LOSS BECAME WIN
  futex t64: ~1.0M -> 3.64M/s = 146% of native — LOSS BECAME WIN
  cache-t32: 2.79M -> 3.42M/s = 103% of native — LOSS BECAME WIN-TIE
  sat: 72K -> 99.2K consistent (native 144K): win shrinks +56% -> +31% — REAL cost, the
  empty-global gate leaks at 6.6x; NEXT TUNING: deeper depth threshold or sat-tight gate.
  t16 3.96M (+25% ✓), schbench 6216@13.2 (elevated-ext band-edge), pipe 0.083 ✓.
  ccm/cache t16 spots ran under HEAVY ext (29.8%/109.9% — my session shutdown burst) —
  INVALID rows, discard; structurally untouched paths (depth<2 at 1x).
User stopped the session (computer restart) mid-validation. STATE: HEAD = M64b, three
scaling losses converted to wins, sat -25pp cost pending next-session tuning, ccm/cache
t16 revalidation owed in a clean window. Champion candidates: M64b (this) vs f9cc9da1
(M58-alone) — decide after clean-window ccm/cache/schbench reps.
