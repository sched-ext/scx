# M-DBLS staged implementation experiment and results

Date: 2026-07-11

Status: implemented behind compile-time gates; no behavioral layer promoted.

## Question

Can the corpus-derived M-DBLS model improve Cake's cache/streaming balance and
wakeup latency while preserving Golden's messaging cost, structural fairness,
and runnable-stall safety?

The exact Golden control is preserved at:

`target/release/cake_candidates/golden200_20260711/final_default`

Golden binary SHA-256: `24942a4bee81d14bbd061800ad5a48998feaadc9d25c5f18402aa27739df0bc2`

Golden BPF SHA-256: `541266274e63d81dd0723a4b19bc127ac11b2045b52a0551dafbf2b89cb11f30`

## Implementation

The experiment adds a compile-time `SCX_CAKE_MDBLS_STAGE` surface:

- `0`: Golden behavior, learned code compiled out;
- `1`: 32-byte task-local activation model only;
- `2`: current-task remainder plus learned wake-preemption balance;
- `3`: adaptive continuation slice in `[H/2, 2H]`.

`SCX_CAKE_MDBLS_PREEMPT=0` independently shadows the current-task model and
adaptive slice while preserving Golden wake-preemption decisions.

The first state implementation updated task storage on every `running` and
`stopping` callback. It failed its neutral-cost gate. The folded version learns
period and CPU burst only at `runnable`/`quiescent` activation boundaries; the
state-only stage therefore avoids task-storage lookups on every context switch.

All candidates verifier-loaded, activated as `cake_1.2.0_x86_64_unknown_linux_gnu`,
completed without a runnable-stall watchdog, detached cleanly, and left
`/sys/kernel/sched_ext/state` as `disabled`.

## Thread-messaging cost screen

Metric: `perf-sched-thread` runtime, lower is better. Three accepted runs per
row; Golden control values were `0.133, 0.135, 0.135 s` (median `0.135 s`).

| Candidate | Values (s) | Median | Delta vs Golden | Decision |
|---|---:|---:|---:|---|
| first per-switch state model | 0.141, 0.142, 0.137 | 0.141 | +4.4% | reject implementation |
| folded boundary-only state | 0.134, 0.140, 0.132 | 0.134 | -0.7% | neutral-cost pass |
| current-model shadow, Golden preemption | 0.139, 0.136, 0.136 | 0.136 | +0.7% | cost parity |
| unrestricted learned preemption | 0.456, 0.265, 0.370 | 0.370 | +174.1% | reject; kick-domain explosion |
| learned preemption inside Golden windows | 0.142, 0.137, 0.141 | 0.141 | +4.4% | reject |
| adaptive slice, Golden preemption | 0.136, 0.142, 0.139 | 0.139 | +3.0% | reject for promotion |

The shadow result isolates the catastrophic unrestricted-preemption result from
task-storage lookup cost. Golden's home-young and global-protection windows are
load-bearing hysteresis; learned fair debt must not create kick opportunities
outside them. Even when bounded to those windows, the learned decision did not
repay its complexity.

## Mixed cache and memcpy screen

Metric: two paired 30-second `stress-ng-cpu-cache-mem` runs, higher is better.

| Field | Adaptive mean | Golden mean | Delta |
|---|---:|---:|---:|
| cache ops/s | 3,815,273.60 | 4,038,706.01 | -5.532% |
| memcpy ops/s | 4,467.70 | 4,270.65 | +4.614% |
| equal-weight mean of percentage deltas | | | -0.459% |

The two individual adaptive/Golden pairs were:

- pair 1: cache `3,711,088.20 / 3,999,242.11`, memcpy `4,481.67 / 4,286.05`;
- pair 2: cache `3,919,459.01 / 4,078,169.91`, memcpy `4,453.73 / 4,255.24`.

The result reproduces the corpus's cache-versus-streaming anti-objective. The
adaptive budget moves along the frontier; it does not dominate it. Because the
project objective requires winning every field, the slice layer is rejected.

## Decision

Do not replace Golden with this M-DBLS implementation. Keep stage `0` as the
default, retain the compile-time experiment for reproducibility, and treat the
folded boundary-only estimator as infrastructure rather than a scheduling win.

The useful falsification is narrower than “learning cannot work”:

1. task-storage accounting must stay off context-switch boundaries;
2. fair-vtime debt cannot be directly converted into new preemption domains;
3. pressure-driven shorter slices repeat the cache/memcpy trade instead of
   solving it;
4. a future learned policy needs a mechanism that changes *which compatible
   task* receives service without adding kicks or globally shortening turns.

## Artifacts

Candidate binaries and BPF objects:

- `target/release/cake_candidates/m_dbls_20260711/e1b_boundary_state`
- `target/release/cake_candidates/m_dbls_20260711/e2_shadow_model`
- `target/release/cake_candidates/m_dbls_20260711/e2c_bounded_preempt`
- `target/release/cake_candidates/m_dbls_20260711/e3b_adaptive_slice_only`

Canonical captures:

`/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/experiments/mdbls_20260711`
