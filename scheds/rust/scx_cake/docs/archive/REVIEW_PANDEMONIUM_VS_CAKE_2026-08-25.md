# Code review — scx_pandemonium v5.19.0 vs scx_cake (nightly @ 4a2ab1fce)

Date: 2026-08-25. Basis: source on `RitzDaCat/scx_cake-nightly`.
Pandamonium anchors cite `scheds/rust/scx_pandemonium/src/`; cake cites
`scheds/rust/scx_cake/src/` + `DESIGN.md` §-references resolve to STATE.md.

## Verdict

Two structural designs of similar size that share the sched_ext idiom
(all decisions in-kernel, no ops.preempt) and diverge almost everywhere else.
Cake optimizes a single fixed algorithm around **measured interrupts and frame
geometry**; pandemonium builds an **adaptive control system** — graph-theoretic
placement plus a CoDel oscillator — whose every knob is a live function of
measured load. Cake's surface is 1 wake queue + per-CPU DSQs; pandemonium's is
a 6-step dispatch waterfall over up to 66 queues. Pandamonium's own README
concedes IPC pipe/socket p99 ~1.4 ms (vs EEVDF 15–26 µs) — precisely cake's
sealed strong suit (+22.7% perf-sched-pipe) — while claiming large deadline-miss
wins. Neither has been measured against the other.

## Side by side

| axis | scx_cake | scx_pandemonium |
|---|---|---|
| size | BPF 2161 ln; loader main.rs 1002 | BPF 3396 ln; adaptive.rs 1346 + topology.rs 1616 + scheduler/tuning/watchdog |
| decision locus | all in-BPF; loader writes rodata once + 1→16 s sink shares | in-BPF at runtime, but knobs re-derived by 1 Hz userspace loop into `tuning_knobs_map` (13 read sites) |
| task state | none (`DESIGN.md`: "no per-task storage") | per-task ctx: 20 fields incl. EWMAs, waker bitmap, home_cpu, standing_runs |
| classification | starved = mean wait > mean run; burst = sum_exec/nvcsw | 3 latency tiers from wakeup_freq·csw_rate/avg_runtime score |
| placement input | IRQ-sink avoidance (live), tick look-ahead, cache warmth, SYNC/handoff shape | R_eff resistance affinity (Laplacian pseudoinverse at detect), emergent domain cuts, Φ migration pricing |
| queues | 1 custom vtime DSQ/CPU + global WAKE_DSQ | per-CPU DSQs + up to 64 domain overflow DSQs (interactive/batch), tier-gated routing |
| dispatch | peek two heads → ring steal (qmask-gated, CCD-aware) | 6-step waterfall: bound sweep → own → R_eff steal → starve net → older-overflow → cross-domain scan |
| slice | 2×burst, floor 1464 ns, cap = half frame | regime `slice_ns`; standing tasks get weight-scaled batch slice capped 4×codel_target |
| adaptivity core | frame clock voted in-kernel (sleep-majority, faster-cadence hysteresis); geometry shifts from it | damped harmonic oscillator integrates rescue counts toward R_eff-derived equilibrium target; envelope-parked when quiet |
| preemption | gated table (home claim / global wake / probe / pinned), vtime tests, no ops.preempt | no ops.preempt; enqueue kick-by-seat, tick band preempt, rotating 4-CPU scan, sweep_bound_preempt at dispatch |
| RT handling | SCHED_FIFO untouchable (data-loop law) | FIFO/RR forced LAT_CRITICAL but answer to lag_cap instead of codel_target |
| starvation wall | vtime order + WAKE_DSQ 24 ms unserved takeover | codel_starve_ns net (~167 ms@12C) + lag_cap backstop + watchdog 10 s |
| polling | none — event completeness as a design law | rotating scans per tick, 1 Hz userspace monitor, hotplug poll each tick |

## Sharpest differences

1. **Where adaptation lives.** Cake freezes hardware facts in rodata at load,
   adapts only via in-kernel votes (frame clock, sink gen). Pandamonium keeps a
   live control loop: userspace retunes knobs every second from histograms;
   the BPF side applies them blind. Cake's "derive in the loader, compare in
   the BPF" is the static version of the same idea — pandemonium generalizes it
   to workload-adaptive quantities, at the cost of a permanent userspace
   dependency and a 2-tick-hold regime latch.

2. **Interrupts.** Cake treats IRQ sinks and the timer as first-class placement
   inputs (§G30/G33/G35/G36) — no pandemonium counterpart exists anywhere in
   its BPF. This is the single biggest capability gap in both directions.

3. **Placement math.** Pandemonium's R_eff/Φ machinery is elegant and entirely
   pre-folded into tables (BPF does one indexed lookup per candidate — good).
   But its inputs are topology-only: two identical hosts get identical
   affinity. Cake's ranked pick consumes runtime truth (sinks, tick schedule,
   qmask claims) the graph cannot see.

4. **Queue count vs queue discipline.** Cake's one-wake-queue design bets that
   ordering beats routing; pandemonium's interactive/batch overflow domains bet
   the reverse. Note cake's open gap #3 (schbench-light peer wakes going global)
   is the case where pandemonium's extra queues might genuinely help.

5. **IPC.** Both designs pay handoff shapes, differently: cake sealed
   pipe +22.7%, mutex +10.3%, futex-lock-pi −71.8% (semantic gap);
   pandemonium self-reports pipe/socket p99 ~1.4 ms under saturation — worse
   than EEVDF by ~50×. Its eventfd/sem ADAPTIVE rows (p99 32 µs) show the
   oscillator can recover some primitives, but the ping-pong tail stands.

6. **Gaming evidence.** Cake's ledger is FRAME/WAKE-tier with game rotations;
   pandemonium's README reports synthetic probes (deadline miss vs 16.6 ms
   target, app launch) on a 12C Zen2 box at n=3 iterations — no game frames,
   no MangoHud-tier data. Its numbers are honest about variance but not
   comparable to cake's evidence classes.

## What each would envy in the other

- Cake → pandemonium: nothing mechanical; possibly the standing-runs ledger
  (slice growth for confirmed CPU-bound runs) as a cheaper alternative to
  cake's burst arithmetic — but cake's slice is already burst-derived.
- Pandemonium → cake: sink-awareness (its "interactive probe under saturation"
  rows are exactly mouse-IRQ contention), the 24 ms wake-starve takeover
  (tighter than its 167 ms net), zero userspace dependency, and cake's
  measurement discipline (sealed exact pairs, noise_class).

## Measurement plan if pursued

GAME-FIRST order: (1) build v5.19.0 receipt, verify identity/hash;
(2) HD2 + KovaaKs ABCCBA rotation native/cake/pandemonium, severe-frame ratio +
0.1% low; (3) only then appsim/wallclock sealed pairs (pipe + mutex-handoff
guard expected to be pandemonium's kill-shots). Do not score from its README.

— end —
