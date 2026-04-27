# scx_cake Latency Shielding Design

## Purpose

Build latency shielding, background wake containment, and selective busy-wake
preempt as a data-driven wake policy layer for `scx_cake`.

The first implementation must be observational. It should classify, count, and
compare behavior before any classifier is allowed to change placement or preempt
policy. This keeps the scheduler tunable from real dumps instead of guesses.

## Evidence From Current Dump

The initial theorycraft dump was captured during browser, music, and desktop
activity, not a game workload. It is still useful because it exposes the wake
shape of normal desktop pressure.

Key signals:

- `shared=0` and `dsq_total=0` show the local-first direction is already intact.
- `wake:busy=3181716` and `kick:wake[i/p]=0/3181717` show every busy wake is
  currently converted into a preempt kick.
- `blocked=98.2%`, `full=1.2%`, and `preempt=0.6%` show most work sleeps before
  consuming a full quantum, so wake-to-run and interference matter more than
  long-run slice fairness for this workload.
- `runtime_contended=27.4%` and `runs_contended=21.4%` show SMT overlap is large
  enough that protected work should prefer cleaner lanes when available.
- Discord and Brave dominate runtime and wake graph pressure while audio,
  compositor, and the observed AppRun/game task have much shorter run bursts.

The design conclusion is not "preempt less everywhere." The conclusion is that
busy wake preempt should become conditional and measured.

## Answer: Do We Need New Classifiers And Dry Run?

Yes. We should add new classifiers, but they should start as debug-visible
shadow classifiers. They should not affect scheduling until their decisions have
been compared against baseline dumps.

The classifiers should be behavioral, not a return to the old hot-path
`GAME / NORMAL / HOG / BG` release policy. Role hints can be used as evidence in
debug builds, but the policy should be driven by runtime behavior:

- short average run duration
- high wake or run frequency
- low full-quantum rate
- wake-to-run tail risk
- SMT exposure
- repeated busy-wake pressure
- broad spread or migration pressure
- task group relationship between waker, wakee, and owner

## Proposed Wake Classes

`SHIELD`
: Work that should receive lower wake latency and cleaner CPU placement. Examples
  from the dump shape are audio, compositor, and game-like short-burst work.

`NORMAL`
: Work with no special handling.

`CONTAIN`
: Work that is active and useful but should not constantly disturb protected
  lanes. Examples from the dump shape are chatty browser or Electron worker
  groups when they are broad, wake-heavy, and not latency critical.

These names describe wake policy, not user intent. A process can move between
classes as behavior changes.

## Architecture

The feature should be implemented as one wake policy layer with three gates.

### Gate 1: Shadow Classification

Compute a candidate wake class and record it in debug telemetry. In the first
phase, this must not change CPU selection, queueing, kick flags, slice handling,
or vtime.

The shadow classifier should report:

- wakee class
- current owner class when known
- reason bits that contributed to the class
- confidence or score bucket
- whether the wake was direct, busy, or queued
- whether the target was local or remote

### Gate 2: Placement Policy

Once dry-run data looks good, `SHIELD` work can bias `cake_select_cpu` toward:

- home CPU when idle
- home core when a sibling lane is clean enough
- lower-pressure physical core before broad scan
- avoiding SMT siblings that are already contended when another good target
  exists

`CONTAIN` work should be biased toward:

- previous CPU or learned home when viable
- fewer broad scans
- less eagerness to disturb shielded lanes

### Gate 3: Busy-Wake Preempt Policy

After dry-run validation, replace unconditional busy-wake preempt with a
conditional decision:

- preempt if the wakee is `SHIELD`
- preempt if the current owner is `CONTAIN`
- preempt if pressure, wait debt, or tail risk is above threshold
- otherwise enqueue locally and skip immediate preempt

The existing `busy_wakeup_pending` per-CPU field should be used or repurposed to
coalesce repeated busy-wake preempt requests. One pending busy wake should be
enough until the CPU runs, dispatches, or clears the handoff state.

## Telemetry Requirements

Every policy-facing change needs counters before and after the behavior changes.

Required shadow counters:

- `class.sample[shield|normal|contain]`
- `class.reason[...]`
- `class.transition[old][new]`
- `busy.preempt_shadow.allow`
- `busy.preempt_shadow.skip`
- `busy.preempt_shadow.owner_class[...]`
- `busy.preempt_shadow.wakee_class[...]`
- `busy.preempt_shadow.local`
- `busy.preempt_shadow.remote`

Required policy counters once enabled:

- `busy.preempt.allow`
- `busy.preempt.skip`
- `busy.preempt.coalesced`
- `busy.preempt.skip_wait_ns`
- `busy.preempt.skip_wait_count`
- `busy.preempt.skip_wait_max_ns`
- `shield.place.home`
- `shield.place.core`
- `shield.place.pressure`
- `shield.place.idle`
- `contain.place.prev`
- `contain.place.home`
- `contain.place.idle`
- `contain.preempt_denied`

The dump should show both lifetime and recent-window values where possible. A
policy that only looks good over lifetime counters but regresses the last 60
seconds should be considered suspect.

## Compare Workflow

The repo should support a simple before/after comparison workflow for dumps.

Minimum comparison output:

- busy wake count
- busy preempt allowed, skipped, and coalesced
- direct, busy, and queued wake-to-run average and max
- wake bucket distribution under `<50us`, `<200us`, `<1ms`, `<5ms`, and `>=5ms`
- SMT runtime and run contention
- path share
- shield and contain class counts
- top app health deltas by runtime share, wake count, wait max, and migrations
- top wakegraph edge deltas by wait max and `>=5ms` bucket count

The comparison should make regressions visible even if averages improve. The
important failure mode is hiding a few frame-breaking or audio-breaking tail
latencies under better aggregate numbers.

## Validation Plan

Use three dump pairs before enabling policy by default:

1. Desktop baseline: browsing, music, chat, terminal.
2. Game foreground: real game or AppRun-style workload with normal desktop
   background activity.
3. Stress companion: light CPU pressure while preserving interactive foreground
   use.

Dry-run promotion criteria:

- classifier decisions are explainable from reason counters
- `SHIELD` does not swallow broad browser or Electron groups wholesale
- `CONTAIN` does not capture audio, compositor, or foreground game threads
- projected preempt skips do not create large wake-to-run tail growth
- comparison output clearly shows which metrics improved or regressed

## Rollout Order

1. Add shadow classifier telemetry and dump presentation.
2. Add dump-to-dump comparison support.
3. Capture baseline and game dumps.
4. Review classifier correctness.
5. Enable selective busy-wake preempt behind an explicit experimental flag.
6. Compare baseline versus selective-preempt dumps.
7. Add latency shielding placement policy behind the same experimental family.
8. Add background containment only after shield behavior is stable.

## Non-Goals

- Do not reintroduce shared DSQ fallback.
- Do not rebuild the old release hot-path `GAME / NORMAL / HOG / BG`
  classifier.
- Do not use process-name allowlists as the main policy mechanism.
- Do not enable policy changes before dry-run data is reviewed.
- Do not optimize for power savings as a primary goal.

## Implementation Decision

The first implementation should split classifier work across BPF and userspace:

- BPF debug counters record the low-level wake, target, owner, and preempt
  decision facts closest to the actual hot path.
- The TUI and dump layer derive richer app-level interpretation from those
  counters and present the classifier reasons.
- Release policy remains unchanged until the debug classifier has been reviewed
  against before/after dump comparisons.

This keeps the first pass verifier-friendly while still producing the app-level
explanation needed for tuning.
