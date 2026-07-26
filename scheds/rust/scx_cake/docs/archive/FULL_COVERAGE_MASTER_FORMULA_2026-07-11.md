# Full-coverage master-formula derivation

Date: 2026-07-11

Status: corpus-derived design hypothesis; scheduling behavior is not yet
implemented by this document.

## Result

The expanded evidence independently converges on the same family as
Debt-Bounded Learned Slack (DBLS). It does not support replacing DBLS with a
fixed slice, fixed wake threshold, workload classifier, or benchmark-selected
mode.

The new derivation sharpens DBLS into **Minimax Debt-Bounded Learned Slack
(M-DBLS)**. The important refinement is an explicit comparison between:

- the predicted cost of delaying the best waiter; and
- the predicted value of letting the current hot task finish.

The original DBLS urgency equation remains the waiter side of this comparison.
M-DBLS adds the symmetric current-completion value and makes worst-field regret,
not average gain, the design objective.

## Evidence surface used

The re-derivation used the final classified research surface:

- 27,567 unique normalized metric records;
- 4,649 attributed attempts;
- 92,066 directed pairwise effects;
- 1,480 controlled-effect summaries;
- 373 campaign designs, including all 200 Golden mutations;
- 54,898 canonical or preserved-raw game evidence rows;
- 25,955 classified metric, diagnostic, and raw source files;
- 206 preserved excluded metric observations;
- 27 DuckDB/Parquet tables;
- 574 of 574 visible research artifacts classified;
- zero Golden binary/BPF identity conflicts.

One root-owned historical `logs/` directory remains unreadable without changing
the repository's sudoless policy. Its parent capture table is available and
classified, but arbitrary hidden ancillary files cannot be claimed as read.

## Direct empirical constraints

### No historical broad candidate won every field

Among 93 goal-score candidates with at least seven controlled metric effects,
zero had a positive worst metric. The best observed seven-metric minimax point
still had a `-0.266%` worst field. Single-row wins are not universal evidence.

Therefore the objective cannot be historical average score:

```text
maximize mean(metric gains)       rejected
maximize minimum accepted gain    governing promotion objective
```

### Cache and streaming are a measured anti-objective

Across 116 controlled designs containing both mixed cache and mixed memcpy,
the Pearson association between their good-direction effects was `-0.739`.
This is the strongest repeated opposition in the controlled matrix.

A static continuation policy moves along this frontier. It does not remove the
frontier. The scheduler must decide whether finishing current or servicing a
waiter is cheaper at the current event.

### Fixed timing remains weak

Golden slice sweeps from 1 through 10 ms were close on the target messaging
screen, while fixed wake and preemption sweeps were commonly tied or quantized.
Long continuation specialists improved cache but harmed mixed memcpy. The 2x
continuation point was the best measured compromise, not a universal optimum.

### Structural facts survive the larger ingestion

- fair vtime is the durable starvation and proportional-fairness basis;
- aged overflow rescue is required for forward progress;
- global wake discoverability is required for handoff chains;
- owner-local queue hints beat blind scans and shared atomic bitsets;
- topology is a bounded preference with unrestricted escape;
- hot-path state and helpers have to win behavior-neutral cost tests first.

## M-DBLS signals

Let `H` be one fairness horizon derived from Cake's compiled base slice.
All time-valued learned terms are saturated to `H`.

For task `p` and CPU `c`:

```text
C(p)       predicted CPU burst
P(p)       predicted activation period
A(p)       attained service in the current activation
R(p)       max(C(p) - A(p), 0)                         remaining service
S(p)       clamp(P(p) - C(p), 0, H)                   learned slack
k(p)       estimator confidence in [0, 1]
Q(c)       normalized runnable/oversubscription pressure in [0, 1]
D(p)       normalized fair service debt in [0, 1]
M(p,c)     bounded topology/migration cost
K(c,p)     bounded switch/cache-disruption cost
```

`D(p)` comes from fair-vtime lag and queue age already needed for structural
service. It is not a second unbounded priority account.

## Master formula

### 1. Waiter delay risk

For runnable waiter `w` on CPU `c`, with current task `r`:

```text
projected_delay(w,c) = min(H, R(r) + M(w,c))
slack_miss(w,c)      = max(projected_delay(w,c) - S(w), 0)

wait_risk(w,c) = min(H,
                     H * D(w)
                     + k(w) * slack_miss(w,c) * (1 - Q(c)))
```

The two components have different semantics:

- fair debt never disappears under load; it guarantees service;
- speculative learned urgency fades under oversubscription, preventing a
  saturated preemption storm.

### 2. Current completion value

```text
third_party_pressure(c) = max(Q(c), max_waiter_debt(c))

finish_value(r,c) = k(r) * min(R(r), H)
                    * (1 - third_party_pressure(c))
```

This is not cache classification. It is a bounded estimate that another switch
would interrupt a confidently near-complete service burst while no other task
has accumulated stronger need.

### 3. Preemption balance

```text
balance(w,r,c) = wait_risk(w,c)
                 - finish_value(r,c)
                 - K(c,w)

preempt iff:
    w is fair-vtime eligible
    and balance(w,r,c) > 0
    and no older compatible task is bypassed
```

Cold estimates use the preserved Golden control gate. Every learned term is
bounded; fair vtime remains authoritative.

### 4. Unified runnable rank

After the preemption-only experiment succeeds, the same quantities can rank
compatible runnable choices:

```text
learned_credit(p,c) = min(H,
                          k(p) * max(projected_wait(p,c) - S(p), 0)
                          * (1 - Q(c)))

rank(p,c) = fair_vtime(p)
            - learned_credit(p,c)
            + M(p,c)
```

Lower rank wins. Learned credit never exceeds one horizon and cannot make an
ineligible task permanently outrank accumulated fair debt.

### 5. Adaptive reconsideration budget

The slice is how long Cake may wait before reconsidering; it is not a priority
class. For a confident current task:

```text
pressure(c) = max(Q(c), max_wait_risk(c) / H)

slice(r,c) = clamp(H / 2,
                   2 * H,
                   H
                   + finish_value(r,c)
                   - (H / 2) * pressure(c))
```

Interpretation:

- near-complete, stable work with no waiter pressure can approach `2H`;
- uncertain or ordinarily loaded work stays near `H`;
- severe eligible-waiter pressure can pull reconsideration toward `H/2`;
- preemption still handles a known urgent wake immediately;
- vtime charging is unchanged.

`H/2` and `2H` are initial falsifiable bounds derived from the existing
fairness horizon and the measured 2x compromise. They are not game constants.
The lower bound must be cost-tested; if shorter reconsideration only adds
overhead, the safe version clamps at `H` and relies on wake preemption.

## Relationship to the earlier DBLS formula

| Element | Earlier DBLS | Full-coverage derivation |
|---|---|---|
| foundation | fair vtime | unchanged |
| learned signal | burst and activation slack | unchanged |
| urgency bound | one horizon | unchanged |
| saturation behavior | fade learned urgency | unchanged |
| starvation | structural debt/overflow rescue | unchanged |
| locality | bounded cost, unrestricted escape | unchanged |
| continuation | bounded finish extension | retained |
| new emphasis | implicit cost of finishing current | explicit `finish_value` |
| objective | universal adaptive service law | explicit minimax worst-field regret |
| slice floor | implementation-open | falsifiable `H/2` pressure floor, with `H` fallback |

Thus the broader ingestion confirms DBLS rather than replacing it. M-DBLS is a
more symmetric and testable expression of the same law.

## Why this formula fits the observed workload shapes

```text
tight handoff:
    S(w) small, wait_risk high, current completion weak -> preempt

periodic game/audio pipeline:
    stable C/P, confidence high, predicted miss crosses slack -> service early

hot cache worker near completion:
    R(current) small and confident, no debt -> finish rather than churn

mixed cache + streaming pressure:
    waiter debt and Q rise -> finish extensions collapse, service rotates

saturated request workers:
    speculative urgency fades with Q, fair debt still advances -> no storm

old overflow work:
    D dominates learned terms -> structural rescue

idle compatible CPU:
    projected delay and topology cost collapse -> dispatch immediately
```

## Implementation order

1. E1: behavior-neutral 24-byte task state and estimator updates.
2. E2: shadow `wait_risk`, `finish_value`, balance, prediction error, and
   proposed slice; sampled reason histograms only.
3. E3: replace only the existing young-current home-preemption comparison.
4. E4a: continuation extension in `[H, 2H]`.
5. E4b: test the pressure-driven lower range `[H/2, H]` independently.
6. E5: reuse the validated rank for local-versus-wake service.
7. E6: validate loader-precomputed locality on real multi-CCD/X3D hardware.

The first behavioral gate remains concurrent cache+memcpy: both fields must
improve over the exact Golden control. Futex, pipe, saturated p99, standalone
cache/memcpy, compilation, compute, and repeated game ABBA remain mandatory
guardrails.

## Falsification

M-DBLS is rejected or redesigned if:

- neutral task state loses hot-path performance beyond repeat noise;
- prediction confidence survives phase changes incorrectly;
- the mixed cache/memcpy opposition remains unchanged;
- the lower slice range only adds scheduler overhead;
- learned urgency bypasses accumulated fair debt;
- locality leaves a compatible CPU idle;
- a win requires process identity or benchmark-specific thresholds;
- repeated clean games or the complete accepted suite expose any field loss.
