# Corpus-derived master algorithm for scx_cake

Date: 2026-07-11

Status: design and experiment contract. No scheduling behavior in the release
binary is changed by this document.

Full-coverage re-derivation: `FULL_COVERAGE_MASTER_FORMULA_2026-07-11.md`.
That analysis confirms DBLS and refines it into M-DBLS with an explicit
waiter-risk versus current-completion balance.

This is the post-processing successor to
`UNIFIED_MASTER_ALGORITHM_2026-07-09.md`. It incorporates the corrected
26,689-record research corpus, the fully attributed Golden200 campaign, the
source-history review, and the research-platform audit. It deliberately does
not treat record count, sequential deltas, or untrusted game captures as causal
evidence.

## Decision

The corpus does not support one globally tuned slice, mailbox representation,
preemption threshold, or continuation multiplier. It supports one adaptive
law:

> Preserve fair vtime, predict only the next bounded service window, spend a
> bounded amount of fairness slack when delay is more expensive than finishing
> the current work, and continuously remove that slack as service debt or
> oversubscription rises.

The proposed policy is **Debt-Bounded Learned Slack (DBLS)**. DBLS is not a
workload classifier and has no gaming/benchmark modes. It uses task behavior,
queue service debt, current run progress, and loader-provided topology. The
same rank governs wake preemption, continuation duration, queue choice, and
eventually CPU preference.

DBLS evolves the earlier Learned-Slack Virtual Deadline proposal in two
important ways:

1. urgency is explicitly paid back through bounded service debt; and
2. the continuation slice is a bounded reconsideration budget, not a static
   throughput class.

## Evidence authority

The platform audit found four distinct evidence tiers. They must never be
flattened into one training set.

1. Exact campaign/control evidence: exact candidate, source, build flags,
   benchmark configuration, and baseline relation.
2. Repeated attributed history: useful when source/config identity and the
   repeated comparison are recoverable.
3. Attributed observations: suitable for proposing mechanisms and estimating
   cost surfaces, not promotion.
4. Unknown/noisy history: useful for coverage and anomaly discovery only.

The corrected corpus has 26,689 metric records and 91,692 directed pairwise
rows, but only 241 Golden200 metric rows have exact campaign-mutation joins.
Only 3,049 records resolve to exact content-addressed source. Historical game
rows are not yet joined to focus/order/trust evidence, so they do not authorize
game-mechanism correlations in this design.

## Measured global patterns

### 1. Fixed constants reach a shallow local optimum

Golden200 slice sweeps from 1 through 10 ms were close on perf-thread
(approximately 1.58% coefficient of variation), while wake/preemption sweeps
were often tied or quantized. A different fixed constant may move a Pareto
point, but it does not solve the cross-workload conflict.

### 2. Continuation warmth and service latency are the central conflict

Long continuation turns can raise cache throughput substantially, but the same
turns lose streaming/memcpy throughput. Golden200 found the cache specialist
near 7.5x continuation and the mixed-memcpy specialist near short turns; even
2x was a compromise, not a universal winner. Therefore continuation credit
must depend on whether productive completion is cheaper than delaying an
eligible waiter.

### 3. Broad-tail stability and extreme-tail protection are different jobs

Existing Cake captures can reduce the population of moderately slow frames
while losing the worst one or two events. Average slice tuning cannot protect
the maximum. The policy needs a predicted service-miss test plus structural
aged-work rescue.

### 4. Structural rescue is stronger than a periodic watchdog

The retained aged-overflow rule completed all 200 Golden mutations without a
watchdog failure. Forward progress should follow from queue order and bounded
debt, while the watchdog remains a safety detector rather than a service
policy.

### 5. Queue hints are worth their space; shared RMW compression is not

Blind scans reduced apparent code/state complexity but regressed perf pipe to
0.093 s from its normal 0.067--0.070 s band. The packed atomic bitset also lost
despite its smaller footprint because compactness created shared cache-line
ownership and RMW traffic. Owner-local hints with benign races are the better
hot-path representation.

### 6. Hot-path simplicity is workload dependent but broadly valuable

Many compilation, messaging, and bulk winners used fewer BPF instructions than
their corresponding losers. Cache specialists sometimes benefited from richer
policy. The durable rule is to precompute topology and immutable decisions in
the loader, keep cold compatibility code noinline, and make every new hot-path
state access earn its cost independently.

### 7. Locality is a cost, never an eligibility rule

Multi-CCD experiments validated a loader-built order of same CCD, equivalent
cache-capacity tier, and then unrestricted escape. Single-CCD builds compile
the topology machinery out. Hard affinity would violate work conservation and
is rejected.

### 8. The mixed cache/memcpy loss is the diagnostic target

The Golden final Cake beat native on standalone cache and standalone memcpy,
but lost the memcpy half of the concurrent cache+memcpy benchmark by 14.74%
while winning its cache half by 43.85%. This means static memory-workload
classification is insufficient. DBLS must respond to changing contention and
service debt inside one run.

## Governing invariants

1. Fair weighted vtime remains the base order and starvation proof.
2. Cake stays work-conserving for every compatible runnable task.
3. No executable, PID/TGID, cgroup, foreground, Steam, benchmark, or game
   identity enters policy.
4. Learned credit is capped at one fairness horizon and cannot accumulate
   across activations.
5. Old runnable work and positive queue debt monotonically erase speculative
   credit.
6. Locality changes the cost of a CPU/task pairing, never task eligibility.
7. Cold or low-confidence estimates fall back to the preserved Golden final
   behavior.
8. All arithmetic has bounded fixed-point or shift-based implementations.
9. Queue hints remain owner-local; no shared atomic mailbox is introduced.
10. Every behavioral stage can be disabled independently and must preserve an
    exact checkpoint.

## Minimal learned state

Cake is currently intentionally stateless per task. Task storage is therefore
an experiment, not an assumed free feature. Begin with one 24-byte logical
record, naturally aligned by the map implementation:

```c
struct cake_task_state {
        u64 last_wake_ns;
        u32 burst_q;       /* dyadic estimate of CPU burst C */
        u32 period_q;      /* dyadic estimate of activation period P */
        u32 last_run_q;    /* last completed service sample */
        u16 samples;
        u8  confidence;
        u8  continuation_streak;
};
```

This state contains no relationship identity. `burst_q` and `period_q` use a
coarse representation because scheduler decisions do not need nanosecond
precision. Saturating dyadic updates avoid division and make phase changes
decay:

```text
estimate <- estimate + ((sample - estimate) >> k)
```

`k` is selected from estimator-error experiments, not benchmark score. A phase
change or large signed prediction error reduces confidence quickly; confidence
recovers slowly after consistent samples.

Conceptual signals for task `p` and CPU `c`:

```text
C(p) = predicted CPU burst
P(p) = predicted activation period
A(c) = attained service of the current task from existing run state
R(p) = max(C(p) - A, 0)                 predicted remaining service
D(p) = clamp(P(p) - C(p), 0, H)        learned wake slack
Q(c) = normalized runnable/backlog pressure
W(c) = oldest eligible service debt
M(p,c) = bounded migration/topology cost
K(p,c) = bounded switch/cache disruption cost
H = one fairness horizon, derived from the base slice
```

No PMU classification is required in the first version. The cache-versus-stream
decision is inferred indirectly from productive completion, activation cadence,
contention, and debt. If those runtime signals cannot distinguish the mixed
case, the hypothesis is falsified rather than repaired with process identity.

## The DBLS control law

### Bounded wake urgency

For a wakee `p` targeting CPU `c`:

```text
projected_wait(p,c) = R(curr(c)) + M(p,c) + K(p,c)
miss(p,c) = max(projected_wait(p,c) - D(p), 0)

confidence_gain = confidence(p) / confidence_max
pressure_fade = 1 - clamp(Q(c), 0, 1)
debt_fade = 1 - clamp(W(c) / H, 0, 1)

urgency_credit(p,c) = min(H, miss(p,c))
                      * confidence_gain
                      * pressure_fade
                      * debt_fade
```

The conceptual effective rank is:

```text
rank(p,c) = fair_vtime(p) - urgency_credit(p,c) + M(p,c)
```

Lower rank wins. The first implementation must not rewrite all DSQ ranks. It
uses the same comparison only at the existing home-preemption decision, where
the behavior and rollback are easy to isolate.

### Preemption rule

```text
preempt current iff:
    wakee is fair-vtime eligible
    and urgency_credit(wakee, c) > K(wakee, c)
    and current has not already incurred protected preemption debt
```

The existing proven futex convergence path remains the cold-estimate fallback.
The rule suppresses pointless preemption when a productive current task is near
completion, pressure is high, or older work already has debt. It accelerates a
reliably periodic/blocking wakee when finishing current would consume its
bounded slack.

### Adaptive continuation budget

A slice is a reconsideration budget, not a task priority. Every dispatch starts
from the base horizon and may grant a bounded finish extension:

```text
finish_need = min(R(p), H)
finish_confidence = confidence(p) * prediction_stability(p)
waiter_pressure = max(wake_urgency, normalized_oldest_debt, Q)

finish_credit = finish_need
                * finish_confidence
                * (1 - waiter_pressure)

slice(p) = clamp(S_min, 2 * H, H + finish_credit)
```

Important bounds:

- the maximum is initially `2 * H`, because Golden200 found 2x the best
  available compromise and longer turns were cache specialists that harmed
  memcpy;
- any eligible wake head or aged overflow head drives finish credit toward
  zero;
- a preempted task receives no immediate extension;
- a continuously runnable task cannot build unbounded continuation credit;
- slice changes do not alter vtime charging.

This makes the timer fast during active service competition and longer only
when a confident near-completion prediction says another reconsideration would
be pure overhead.

### Queue and topology selection

DBLS preserves the existing three structural channels:

- local vtime queues for warm continuations;
- global `WAKE_DSQ` for discoverable wake service;
- `OVF_DSQ` for saturation escape with aged rescue.

The same rank comparison may later decide local-versus-wake service, but only
after preemption and slice stages validate the estimates. Steal order remains
loader-precomputed:

```text
same CCD -> equivalent cache-capacity tier -> remaining compatible CPUs
```

The unrestricted tail is mandatory. On single-CCD builds the topology order
and its branches remain compiled out.

## Expected behavior without workload labels

| Observed behavior | DBLS response |
|---|---|
| continuously runnable compute | no periodic slack; fair vtime and base slice dominate |
| tight futex/pipe handoff | low slack and eligible wake produce prompt convergence |
| periodic game/audio pipeline | learned service window creates bounded early service before a predicted bubble |
| cache-hot worker near completion | confident small remaining burst earns at most one extra horizon if no waiter debt exists |
| streaming worker under mixed pressure | repeated debt and weak completion benefit erase finish credit, forcing frequent reconsideration |
| saturated request workers | queue pressure fades urgency and prevents preemption storms |
| old overflow work | structural debt overrides speculative locality/finish credit |
| idle compatible CPU | direct dispatch; DBLS never idles it to protect locality |

## Implementation ladder

### E0 — freeze the exact control

Use the Golden200 `final_default` candidate, its binary/BPF hashes, source
snapshot, kernel identity, and native gate as the control. Never reconstruct it
from dirty `HEAD` alone.

### E1 — behavior-neutral state cost

Add task-storage lifecycle and update timestamps/estimates, but do not affect a
single scheduling decision. Measure callback/JIT cost, BPF instructions, map
memory, futex, pipe, mixed cache+memcpy, schbench, fork/thread, compilation,
and runnable-stall behavior. Reject or redesign storage if the neutral record
causes a repeatable regression outside control noise.

### E2 — shadow prediction

Compute burst, period, remaining service, slack, pressure, debt, would-preempt,
and proposed slice without acting. Export sampled reason histograms and
prediction errors, never per-event logs. Required proof:

- prediction error is bounded across phase changes;
- confidence decays rather than oscillating after a phase change;
- futex handoffs separate from saturated worker wakes;
- proposed long slices disappear in the mixed streaming/debt phase;
- all counters are cheap enough to remove or compile out in release.

### E3 — replace only the young-current home-preemption gate

Leave DSQs, routing, slice, steal order, and overflow unchanged. Use DBLS at the
existing home-preemption branch with the old gate as cold fallback. This is the
smallest causal test of learned slack.

### E4 — adaptive continuation capped at 2H

Enable only the slice equation. Preserve vtime charge and all queue order.
First gate is the concurrent cache+memcpy pair: both halves must improve over
the exact control before broader testing.

### E5 — unify local/wake/overflow comparison

Only if E3 and E4 survive: reuse bounded rank and debt in dispatch choice.
Do not create new game or throughput queues. Preserve aged overflow rescue as
an independent structural safety rule.

### E6 — real topology validation

Keep single-CCD compile-out proof, forced multi-CCD verifier/runtime proof, and
then measure on an actual multi-CCD/X3D system. A synthetic topology build does
not establish performance.

## Promotion matrix

Each stage must beat both the exact Golden control and same-window native EEVDF
with effects beyond repeated-control noise. The first mandatory synthetic gate
is:

- concurrent cache and memcpy, both metrics;
- standalone cache and memcpy;
- futex and perf pipe;
- schbench light, standard, and saturated including throughput and p95/p99;
- perf fork/thread/memcpy;
- kernel defconfig and representative xz/x265/compute;
- fairness, stalls, migrations, context switches, IPC, and BPF cost.

Game evidence is a separate repeated ABBA gate. It requires stable scenario and
focus proof, scheduler/source identity, balanced order, sufficient frames for
the 0.1% tail, same-label variance, average/1%/0.1% FPS, p95/p99/p99.9/max frame
time, spike counts and severities, jitter, CPU/GPU load, and confidence bounds.
No untrusted historical game row promotes a stage.

The platform must finish its canonical game-comparison evidence join before
corpus-wide game correlations are considered authoritative.

## Falsification and stop rules

Reject or redesign DBLS if any of these persists under clean repeats:

1. Behavior-neutral task state materially reduces futex or pipe performance.
2. Prediction confidence remains high through a workload phase change.
3. Mixed cache improves only by recreating the known memcpy loss.
4. Saturation produces repeated preemption or continuation oscillation.
5. A compatible idle CPU is left unused for locality.
6. Old eligible work can be postponed by renewed urgency credit.
7. The win requires executable identity, PMU-heavy hot-path sampling, shared
   atomics, or a benchmark-specific threshold.
8. Improvements disappear under held-out campaign/time validation.

## Platform work still required for full-pool learning

The data processing completed for this design makes campaign mutations and
source/config states queryable, but the following work is required before the
platform can claim full causal ingestion:

1. Build a canonical game-comparison table from every `report.json` and
   `comparison.json`, including focus, scenario, arm/order, variance, trust,
   source identity, and paired effects.
2. Join comparison trust to raw game rows without overwriting capture facts.
3. Add adapters for older campaign ledger formats and report matched/unmatched
   counts.
4. Build a controlled-effect target matrix keyed by exact baseline/candidate,
   configuration, hardware, kernel, and time window; keep sequential deltas in
   a discovery-only table.
5. Validate by held-out campaign, time block, and benchmark—not only source
   pair—and balance benchmarks so Kovaak's row volume cannot dominate.
6. Backfill recoverable source snapshots and permanently tier unrecoverable
   history.

Until those are complete, DBLS is a corpus-informed hypothesis with a rigorous
experiment contract, not a learned universal optimum. “Beat all schedulers on
all fields” remains the promotion objective, never an inference from a
geometric mean or a large historical pool.
