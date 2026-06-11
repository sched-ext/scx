# Mutation campaign charter — beat EEVDF + all scx schedulers on Kovaaks MangoHud metrics

Started 2026-06-10. User approved all change sizes including rewrites, all cake systems.
Targets: avg FPS, 1%low, 0.1%low, p99/p99.9/max frametime, FT stddev, jitter — vs
native EEVDF (7.1-rc7 w/ HRTICK+POC) and vs cosmos/lavd/bpfland.

## Operating rules (hard, from user)
1. Every mutation's verdict = focused-Kovaaks frame A/B (ABBA order rotation, focus-gated,
   game_capture_doctor precheck per cycle). Profiles/bpf_stats = diagnosis only.
2. NO agents/workflows/builds during captures — quiet system; sequence research <-> bench.
3. Never touch game/MangoHud processes; kill only capture PIDs. kdotool windowactivate
   restores focus if lost while user is away.

## State of knowledge (measured today)
- EEVDF 7.1-rc7 gained: HRTICK-at-deadline (default-on), preempt-short buddy-clear,
  delayed-dequeue lag clamp, NI_RANDOM newidle. Gap vs cake widened to -2.1% avg.
- CachyOS EEVDF also runs POC Selector (cake-inspired O(1) idle bitmaps), auto-off under scx.
- Frame threads eat ~680/s RT-sandwich preemptions (frame_preempt_by_self=99.7% diag):
  KWin FIFO-1 (~11k wakes/s), PipeWire FIFO-20 on top cores, nvidia irq/115 on cpu13.
- Mutation #1 `--irq-avoid auto` (RT/IRQ-noisy core demotion in routing): cycles 1-2 show
  avg gap halved (-2.1% -> ~-1.0%), first-ever 1%low win vs native (943.2 vs 921.1 from
  slot 2), p99 win. Cycles 3-4 pending (game crash interrupted; raw CSVs recoverable).

## Mutation queue (priority order, one at a time, each Kovaaks-A/B'd)
1. [IN FLIGHT] RT/IRQ noise-avoid routing (static load-time demotion).
2. Dynamic noise tracking: userspace governor rescans RT residency every ~2s, publishes
   rt_noisy_cpu_mask via trust lane; BPF placement penalizes masked CPUs live. Fixes the
   static snapshot going stale (KWin migrated 14->15 between scans today).
3. Slice-deadline precision (cake's HRTICK answer): BPF timer or shorter adaptive slice
   for frame-class owners when local DSQ non-empty; EEVDF got avg+pacing from exact
   deadline preemption — cake's 1ms quantum rounds preemption up to tick.
4. Frame-class wake placement v2: prefer the SMT-clean, RT-quiet core with warmest cache
   (blend smtstrict + noise mask + prev-core affinity in one score).
5. Per-hop running/stopping publish cost cut (27% of callback ns unattributed; DCE/lean
   like DISPATCH_SKIP_RESCUE did for dispatch -35.5%).
6. llc-vtime re-test under current champion stack (1%low head-of-line fix; +28.9% 1%low
   in Splitgate measurement, never re-tested post-smtstrict).
7. Wake-chain/futex handoff family (the only lever family with ~44% keep rate).

## Research backlog (run between benches, agents OK when not capturing)
- Read sashiko (~/Documents/Repo/sashiko) for kernel-patch ideas applicable to cake.
- Frontier-code methodology (cognition.ai/blog/frontier-code) — pattern-search loop for
  finding performative code shapes; apply to cake hot paths.
- EEVDF source mining: what exactly HRTICK-at-vdeadline does (kernel/sched/fair.c
  hrtick_start_fair) — replicate semantics in scx terms.
- Beat-the-scx-field baseline: cosmos/lavd A/B once cake-vs-EEVDF stack settles
  (smtstrict already beat cosmos 6/6 on 2026-06-08).

## Decision log
- 2026-06-10: enq-kick-idle fold = keep (mechanism -72% enqueue ns, frame null).
- 2026-06-10: irq-avoid v1 (IRQ-only) insufficient alone (nvCtx 425->373/s) — superseded
  by RT+IRQ noise-avoid same day.
- 2026-06-10 r2 clean set (4-cycle ABBA, fresh instance ~1330fps): noise-avoid = KEEP
  (maxFT -6.5%, jitMax -14%, spreads 3-4x tighter, no regressions) but avg -1.5%
  zero-overlap / 1%low -4.9% / p99 +5.1% still native. Static demotion may trade
  196-bin clock for cleanliness. Queue reordered: slice-deadline precision next
  (targets the lost departments: avg/1%low/p99), THEN dynamic noise mask.
- 2026-06-10 frame-reserve (--frame-reserve, static AND dynamic-governor v2) = PARK,
  mechanism falsified at profile gate both times: pinning works (mig 0, wait
  3.18->1.86us) but GameThread nvCtx exploded 411/s -> ~5,700/s == DP-2's wake rate.
  ROOT CAUSE (new lever-map law): an exclusively-reserved core is the system's
  most-idle CPU -> cpupri ranks CPUPRI_IDLE as the best RT wake/push target ->
  KWin FIFO threads get STEERED onto the anchor's core. Under scx, concentrated
  idleness is an RT magnet; isolation backfires. Counter-designs if revisited:
  keep one light companion task on the reserve core so it never reports
  CPUPRI_IDLE, or abandon isolation and copy EEVDF's mobility instead.
  Code kept behind knob (default off): select/insert/dispatch guards +
  FrameReserveGovernor in main.rs run loop. Kovaaks frames never measured
  (profile gate failed; user rule says frames are the verdict for WINS —
  a 14x mechanism regression doesn't earn the bench time).
- 2026-06-10 ⭐ llc-vtime (baked build, target_llcvtime/) vs native, 4-cycle ABBA,
  same instance as r2: **avg +0.3% slot-consistent, cake wins 3/4 cycles incl.
  both slot-2 runs — THE EEVDF AVG CEILING IS FALSIFIED.** The lever was queue
  policy; champion's baked LOCAL cost ~1.8% avg on 7.1-rc7. Trade vs LOCAL:
  LOCAL wins tail extremes (maxFT/jitter, r2), LLC-VTIME wins avg but cedes
  1%low −5.0% / p99 +5.5% / .1%low −5.7%(mixed).
- 2026-06-10 ⭐⭐ HYBRID (llc-vtime + SCX_CAKE_HYBRID_QUEUE=1: GameThread/RenderThread
  fallback LOCAL, rest vtime arbiter; target_hybrid/, registry cake_hybrid) vs
  native, 4-cycle ABBA: **cake WINS 1%low +5.8% (σ 10.5 vs 43.6!), p99 −5.7%,
  FTstd −4.0% — all slot-consistent — EEVDF's two strongholds taken.** Ties:
  .1%low/maxFT/jitMax. Native keeps only avg −0.4% (small, slot-consistent).
  Day's arc: morning −2.1% avg zero-overlap + all departments lost → evening
  3 departments WON, 3 tied, avg −0.4%. HYBRID = champion candidate.
- NEXT: (a) narrower hybrid gate — GameThread-only LOCAL (RenderThread to the
  arbiter) to recover the ~0.7% avg the frame-LOCAL inserts cost (llcvtime-pure
  proved +0.3% avg reachable) without losing the 1%low/p99 capture; (b) then
  cosmos/lavd field A/B with the hybrid candidate; (c) .1%low/maxFT/jitMax tie
  -breakers after avg closes.
- 2026-06-10 hybrid2 (GT-only LOCAL, HYBRID_QUEUE=2) = FALSIFIED at n=3: avg
  recovered as predicted (+0.4% s1) but 1%low went UNSTABLE (843.9/831.2/1013.6,
  sigma ~104 = EEVDF-like) and p99 regressed +17% in 2/3. RenderThread's LOCAL
  fallback is BOTH the tails ingredient AND the consistency ingredient.
  Gate macros now support HYBRID_QUEUE=3 (RT-only) — testing whether GT-LOCAL
  is pure avg cost.
- 2026-06-10 ⭐⭐⭐ HYBRID4 (HYBRID_QUEUE=4: RT-LOCAL always + GT owner-conditional
  LOCAL/arbiter) = CHAMPION. 4-cycle ABBA vs native: ZERO pooled losses —
  1%low +3.9% / .1%low +3.4% / p99 -3.8% slot-consistent, avg +0.1% parity,
  maxFT/FTstd/jitMax pooled-cake ties at 2.9-4.4x tighter sigma. The
  owner-conditional gate delivered the 2x2's prediction: pair coherence on
  frame-owned targets + bulk-pileup escape. NEXT: n-extension (4 more cycles)
  to convert ties to slot-consistent wins; cosmos/lavd field A/B; bake
  HYBRID_QUEUE=4 + llc-vtime as champion defaults.
- 2026-06-10 (late) hybrid4m main-thread anchor gate (GT gate += pid==tgid) =
  KEEP, promoted into the default gate-4 build. AR: avg +1.6% held 4/4 both
  slots; EVERY tail metric improved vs h4 (.1%low -8.9->-4.1%, jit +30->+8%,
  maxFT flipped to -4.6%) though AR tails remain net-native. MEASURED LAW:
  AR's frame pipeline is a 7-thread complex (GT 41.8% + 4x Foreground Work
  33-41% each + RenderThread 31.4% + RHIThread 32.8%); the GT<->RT pair model
  covers 2/7 — frame-complex behavioral coverage is the next mutation.
  PENDING: Kovaaks no-harm regression of the refined gate.
