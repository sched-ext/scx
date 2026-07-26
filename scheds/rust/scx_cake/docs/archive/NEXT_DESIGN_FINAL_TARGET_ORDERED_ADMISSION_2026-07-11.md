# Next Cake design: Final-Target Ordered Admission

Date: 2026-07-11

Status: research-phase conclusion and experiment contract. No release behavior
is changed by this document.

## Corpus used

The full canonical refresh completed after the reason-coded intervention
campaign:

- 28,576 accepted normalized metric records;
- 10,683 run IDs;
- 14 benchmark/game families;
- 4,688 grouped attempts;
- 159,940 directed pairwise effects;
- 2,365 trusted and 3,980 provisional rows;
- 762 full-source and 4,275 partial-source snapshots;
- 332 controlled environment-effect rows, of which 147 are eligible for the
  environment model;
- all eight currently wired intervention schedulers represented: Cake,
  Cosmos, Rusty, Mitosis, Flash, bpfland, LAVD, and P2DQ, plus native EEVDF.

The corpus is large enough to prioritize a mechanism, not to claim a universal
winner. Only 8.3% of normalized rows are trusted, historical source
reconstructability is 15%, the controlled environment surface spans one boot,
and no concurrent blend has yet been captured. The environment interaction
model is not decision-grade: its combined held-out-noise R2 is strongly
negative. The pairwise model is useful for ordering tests, but its held-out
MAE is still roughly 26.6 percentage points.

## What the evidence rejects

1. **A new fixed slice.** Slice interventions move along the cache/streaming
   frontier and do not dominate every field.
2. **Broad learned preemption.** Unrestricted M-DBLS preemption caused a kick
   explosion; restricting it to Golden windows still did not repay its cost.
3. **Pressure-shortened adaptive slices.** The tested adaptive slice lost
   cache while buying memcpy and therefore reproduced the measured
   anti-objective.
4. **Direct-dispatch-all synchronous wakes.** Flash's broad synchronous
   direct path was catastrophically bad, and Cosmos/bpfland changed direction
   with wake pressure.
5. **Process or benchmark classification.** The useful interaction is queue
   state, not executable identity.
6. **Using the current direct-debt shadow as final-target truth.** Its counters
   run before Cake's existing WAKE_SYNC redirect, so raw same-CPU selections
   are not necessarily Cake's final placement.

## Strongest surviving pattern

Across independent scheduler implementations, direct dispatch helps only when
it avoids a real handoff and does not bypass pending ordered work. Under wake
pressure, restricting busy/queued-target direct dispatch improved Cosmos and
bpfland substantially. Under ambient or cache pressure, the same broad rule
was neutral or harmful. Cake's existing `select_cpu` already redirects the
known WAKE_SYNC busy-waker return when another idle CPU is found, but it has
two remaining one-way-door cases:

1. the alternate idle search loses a race and Cake still direct-dispatches to
   the original busy callback CPU; and
2. the final CPU is idle but its custom vtime DSQ already contains compatible
   ordered work, so direct insertion bypasses that order.

This is a state predicate, not a workload mode.

## Proposed law

Call the next mechanism **Final-Target Ordered Admission (FTOA)**:

```text
cpu, kernel_idle = select_cpu_dfl(task, prev, wake_flags)

if kernel_idle and sync and cpu == callback_cpu:
    alternate = pick_idle_cpu(allowed)
    if alternate exists:
        cpu = alternate
    else:
        kernel_idle = false

ordered_debt = custom_vtime_dsq_depth(cpu)

admit_direct = kernel_idle and ordered_debt == 0

if admit_direct:
    insert final CPU local DSQ
else:
    return final CPU and let enqueue perform ordinary vtime insertion
```

The kernel contract explicitly describes `is_idle` as a good candidate for
direct dispatch. FTOA does not second-guess that idle decision generally; it
only repairs the known synchronous fallback and refuses to jump Cake's own
pending vtime order.

## Why this is the next active candidate

- It changes one decision surface: direct versus ordered enqueue.
- It uses workload-neutral final CPU and queue state.
- It adds no task storage, clock, scan, kick, new callback, or priority class.
- It preserves the exact CPU returned by Cake and therefore does not add a
  migration policy.
- It preserves weighted vtime, overflow rescue, work conservation, and all
  existing wake/home routing.
- It is almost dormant in uncontended operation, while the cross-scheduler
  evidence predicts increased firing under wake pressure.
- It attacks ordering debt without globally shortening turns, the specific
  gap left by the failed M-DBLS slice/preemption experiments.

The one expected cost is a user-DSQ depth lookup on the would-direct path.
That helper must earn its cost. An owner-local qmark may be used only as a
cheap positive prefilter; because qmark races are deliberately benign for
stealing, it cannot be treated as exact proof that the ordered DSQ is empty.

## Required staged experiment

### F0: corrected post-redirect shadow

Move proposal evaluation after the sync redirect and record:

- final evaluations;
- Golden direct decisions;
- proposed direct decisions;
- rejection because no alternate idle CPU survived;
- rejection because final custom DSQ depth was nonzero;
- overlap between those reasons;
- a small depth histogram.

Golden actions remain unchanged. This replaces, rather than silently reuses,
the pre-redirect same-CPU interpretation.

### F1: active ordered-admission flip

Compile telemetry out and enable exactly the two FTOA clauses. Preserve a
hash-locked baseline and candidate with linked BPF objects and source snapshots.

The first falsifying matrix is:

1. `perf-sched-pipe`, `perf-sched-thread`, `stress-ng-futex`, and
   `schbench-light` under ambient and wake pressure;
2. native A/B, Cake A/A, and semantic-neutral controls;
3. `stress-ng-cpu-cache-mem` as the opposite-risk field pair;
4. BPF/JIT audit for `cake_select_cpu` instruction/helper growth;
5. native restoration and watchdog/stall proof after every arm.

### F0/F1 predicate audit correction

The first post-redirect F0 implementation summed the final CPU's custom-vtime
DSQ depth and kernel-local DSQ depth into one `target_q` value, while the F1
active ordered-admission gate consulted only the custom-vtime DSQ. Those are
different predicates. The original aggregate F0 count therefore cannot prove
how often F1's ordered-debt condition fired, and must not be used to select a
depth threshold.

The corrected observer recipe separates custom ordered depth from kernel-local
backlog, records their overlap, and emits ordered-depth bands
`0, 1, 2, 3-4, 5-8, 9-16, 17-32, >32`. Its counterfactual slow decision now
matches F1 exactly: reject direct dispatch only when custom-vtime depth is
nonzero. The active F1 results remain valid measurements of their code, but
their mechanism attribution stays provisional until this corrected observer
is captured.

### F2: promotion ladder

Only if the mechanism fires and F1 clears every field:

- three trusted alternating repeats on the official latency and coverage
  profiles;
- concurrent cache+memcpy and latency+cache blends;
- full official equal-weight suite with no accepted regression;
- native-versus-candidate game ABBA on WoW, then the other available games,
  scoring average FPS, 1%/0.1% lows, p95/p99/p99.9/max frametime, variance,
  jitter, wake latency, and stability together.

Rollback is exact Golden behavior: keep `is_idle` unchanged after a failed
alternate search and direct-dispatch without consulting the final custom DSQ.

## Secondary research lane

The one-eighth burst predictor reduced shadow error compared with the faster
predictor, while conservative banded confidence stopped treating nearly every
task as certain. Keep that combination in shadow. Do not let it affect rank,
slice, routing, or preemption until FTOA is resolved and the combined predictor
is calibrated across boots and workload shapes.

## Decision

The next Cake attempt is FTOA, not another full adaptive rewrite. It is the
smallest mechanism that aligns the cross-scheduler pressure evidence with
Cake's actual final placement and preserves the parts of Golden that already
win games, futex, and service tails. A universal win is still unproven; FTOA is
the next high-information attempt to move the worst field rather than the
average.
