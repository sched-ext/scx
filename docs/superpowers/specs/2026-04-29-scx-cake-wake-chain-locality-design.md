# scx_cake Wake-Chain Locality Design

## Purpose

Build a universal `wake_chain_locality` policy for `scx_cake`.

The policy should improve game, compositor, input, audio, browser media, Wine,
and other latency-sensitive pipelines without detecting applications. It must
not score TGIDs, promote process families, use command names, or maintain a game
allowlist. The scheduler should respond only to behavior it can observe from
task execution, wake timing, placement, migration, SMT state, and pressure.

The first implementation should be observational. Debug builds should compute
and dump the new score before the score is allowed to affect placement or
preemption. Policy changes should land only after baseline dumps prove that the
score identifies the intended scheduler shape.

## Current Evidence

The Kovaak / Proton debug dump shows the problem shape clearly, but the design
must not be Kovaak-specific.

Useful scheduler facts from the dump:

- Shared queues are not the visible problem: `queue.shared` is zero.
- Wake target selection is not the visible problem: post-wake target misses are
  zero for direct and busy wakeups.
- Scheduler callbacks are cheap enough that policy shape matters more than raw
  callback overhead.
- The foreground frame path has high migration and high SMT exposure.
- Most work blocks before consuming a full quantum, so wake-to-run and placement
  tails matter more than long slice fairness.
- Debug-derived `gaming.qos` currently fails to identify render/frame candidates
  for this workload because the current shape rules expect longer average run
  bursts than many real frame-chain tasks have.

The conclusion is not "detect Kovaak" or "detect games." The conclusion is that
short, wake-dense, blocking pipelines need locality and SMT protection when the
current placement pattern is creating tail latency.

## Universal Invariant

The scheduler should classify a task as chain-like only from scheduler-native
signals:

- short average runtime
- frequent runs or wakeups
- mostly blocks before full quantum consumption
- repeated wake-to-run samples
- sync wake hints
- wake-to-run tail buckets
- migration rate or broad placement spread
- SMT contention during wake or run
- pressure on the target CPU or core

The scheduler must not use:

- TGID identity as a score input
- process or thread command names
- executable suffixes
- Wine, DXVK, Kovaak, Steam, browser, compositor, or game allowlists
- parent process identity
- per-application profile rules

Wake relationships are allowed only as anonymous scheduler facts. For example,
"a short-running wakee was woken by a short-running waker" is allowed. "this
wake stayed inside the same TGID" must not increase the score or select policy.

## Score Model

Add a small per-task score named `chain_score`.

The score should live in the task context so it naturally follows the task and
does not require a separate identity table. The score is a saturating integer
with a small range, for example `0..15`.

Positive evidence:

- `SHORT_RUN`: enough samples and average runtime below a short-burst threshold.
- `WAKE_DENSE`: enough run or wake samples to show a repeated pipeline.
- `BLOCKS_EARLY`: frequent blocked stops compared with full quantum stops.
- `SYNC_WAKE`: recent wake had `SCX_WAKE_SYNC`.
- `WAIT_TAIL`: wake-to-run wait crossed a tail threshold.
- `MIGRATION_PAIN`: placement changed often enough to indicate instability.
- `SMT_PAIN`: wake or runtime latency is worse when the sibling is active.
- `PRESSURE_WAKE`: wake target was busy or pressure was high.

Negative evidence:

- `FULL_QUANTUM`: task often consumes the full slice.
- `LONG_RUN`: average runtime is no longer short.
- `LOW_ACTIVITY`: insufficient recent samples.
- `STALE`: no recent wake or run activity.

The score should rise quickly enough to catch active latency pipelines and decay
quickly enough to avoid stale protection. Decay should happen on long sleeps,
full-slice behavior, and low recent activity.

## Policy Gates

The score should control policy through bounded gates, not absolute priority.

### Gate 1: Observation

Debug builds calculate `chain_score` and reason bits. This phase does not change
CPU selection, enqueue behavior, kick flags, slice handling, or vtime.

The dump should show:

- score bucket
- reason bits
- positive and negative evidence
- whether the task was score-eligible
- last placement result
- last busy-wake preempt decision in shadow mode

### Gate 2: Locality Placement

When `chain_score` is high enough, `cake_select_cpu` should prefer clean locality
before broad idle spreading:

- learned home CPU if idle
- previous physical primary if idle
- learned home core if a clean lane is available
- lower-pressure physical core before SMT sibling placement
- guarded broad primary scan with periodic credit

The gate should loosen under high pressure. A chain-like task should not wait
behind a busy local lane when the machine has useful idle capacity.

### Gate 3: SMT Avoidance

When a task is chain-like and the SMT sibling is active, prefer another
reasonable physical core if one is available. This should be a preference, not a
hard affinity rule.

The policy should avoid two failure modes:

- moving chain-like tasks across the whole system on every wake
- pinning chain-like tasks so tightly that they queue behind avoidable local
  work

### Gate 4: Busy-Wake Preemption

Busy-wake preempt should become conditional when enough confidence exists.

Allow preempt when:

- wakee has high `chain_score` and the owner does not
- wakee has high `chain_score` and the owner is runtime-heavy
- target pressure is high
- recent wake-to-run tail is above threshold

Skip or downgrade preempt when:

- wakee has low score
- owner also has high `chain_score`
- owner average runtime is short and likely part of a competing latency chain
- pressure is low and the predicted wait is acceptable

This avoids making every busy wake a preempt while still protecting real
latency chains.

## Data Structures

Prefer small fields in `struct cake_task_ctx`:

- `u8 chain_score`
- `u8 chain_reason_mask`
- `u8 chain_decay_credit` or equivalent aging state
- optional debug-only counters in the telemetry block

If release stack or struct-size pressure appears, keep the release fields tiny
and move explanatory counters to debug-only padding or existing telemetry slots.

The release path should not allocate or search external identity state.

## Telemetry

Add debug-only counters and dump lines:

- `chain.score`: count by score bucket
- `chain.reason`: counts by reason bit
- `chain.decay`: counts by negative evidence
- `chain.place`: placement result for chain-scored wakeups
- `chain.scan_guard`: guarded, credit-used, and skipped broad scans
- `chain.smt`: avoid, used, unavailable, pressure-override
- `chain.busy_preempt_shadow`: allow, skip, wakee score, owner score
- `chain.wakewait`: wait buckets for chain-scored wakeups

Per-task dump rows should expose:

- `chain=<score>`
- `chain_reasons=<labels>`
- `chain_policy=<observe|place|smt|preempt>`
- `risk=<migration|smt|tail|ok>`

The existing `task.anatomy` and `gaming.qos` labels should be adjusted so they
describe frame-chain candidates without relying on game names or TGIDs.

## Validation Plan

Use dump-to-dump comparison, not FPS alone.

Baseline comparisons:

1. Kovaak / Proton foreground with background load minimized.
2. A normal desktop latency workload: compositor, browser, audio, terminal.
3. A browser media workload.
4. A light pressure workload while interacting with foreground apps.
5. Optional stress companion once the ordinary cases are clean.

Compare these metrics:

- `mig/s`
- placement spread
- SMT runtime contention
- SMT wake average and max
- `wakewait.all`
- `wakewait<=5ms`
- `kickrun` average and max
- post-wake target hit/miss
- direct and busy wake bucket distribution
- top wakegraph tail edges
- chain score distribution
- chain placement and preempt decisions

Success criteria:

- chain score is explainable from reason bits
- no identity-specific behavior is present
- target misses do not regress
- wake tails improve or stay neutral
- migration and SMT exposure drop for high-score chains
- CPU-bound tasks do not get accidental chain protection
- broad desktop/background workloads do not all become high-score chains

## Rollout Order

1. Add debug-only score derivation and dump output.
2. Capture baseline dumps and review score quality.
3. Add shadow placement and shadow busy-preempt decisions.
4. Compare projected decisions against baseline dumps.
5. Enable locality placement behind an explicit experimental flag.
6. Capture candidate dumps and compare.
7. Enable SMT avoidance behind the same experimental flag.
8. Capture candidate dumps and compare.
9. Enable conditional busy-wake preempt last.
10. Consider default enablement only after multiple workloads improve or stay
    neutral.

## Non-Goals

- Do not detect Kovaak, games, Wine, DXVK, Steam, browsers, compositors, or any
  application family.
- Do not use TGID as a promotion signal.
- Do not introduce app profiles.
- Do not reintroduce shared DSQ fallback.
- Do not make a score that permanently protects stale tasks.
- Do not optimize only for FPS while ignoring wake tails, input feel, and audio
  responsiveness.

## Open Implementation Notes

The existing `home_score`, primary-scan credit, wake wait accounting, SMT debug
accounting, and busy-wake shadow telemetry are good integration points. The
score should reuse these signals rather than creating a parallel scheduler.

The first patch should stay debug-observational so the dump can prove whether
the score is universal before it becomes policy.
