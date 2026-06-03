# scx_flow

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-driven `sched_ext` scheduler with zero heuristic classification. Every scheduling signal is kernel-verified and consumed within one quantum.

Tasks accumulate budget while sleeping (`budget += sleep_time ÷ 100`) and spend it while running. Vtime is derived from remaining budget (`vtime = BUDGET_MAX − max(0, budget)`), bounded to `[0, 2000μs]`. Tasks that sleep longer earn higher budget, lower vtime, and earlier dispatch. Budget is clamped to `[−500μs, 2000μs]`, so vtime never grows unbounded.

Wakeup tasks are inserted to the target CPU's local DSQ via `SCX_DSQ_LOCAL_ON`. Tasks with budget ≥ 50μs set `SCX_ENQ_PREEMPT` and send an IPI. Below-threshold wakeups queue at the head of the local DSQ without forcing a context switch.

Non-wakeup re-enqueues are vtime-ordered in a single global DSQ. All non-wakeup tasks run with a fixed 50μs slice — no tunable "shared slice" for bulk workers.

Non-migratable tasks (`nr_cpus_allowed == 1`) are routed to a per-CPU FIFO DSQ checked first in dispatch, giving pinned latency-sensitive tasks absolute priority over tasks from the global DSQ.

There are no temporal urgency buckets, no containment lanes, no score signals, no wake profile bits, no adaptive tuning. The scheduler produces the same dispatch order for the same inputs — any non-determinism is from the kernel and hardware, not the policy.

## Typical Use Case

Systems where scheduling decisions must be deterministic and explainable: embedded control, robotics, avionics, automotive, and other mission-critical workloads. The fixed 50μs slice bounds worst-case wakeup latency, and the bounded-vtime design eliminates priority inversion from accumulated runtime.

General-purpose desktop and workstation use is also supported; the scheduler separates interactive tasks (longer sleep → higher budget → lower vtime) from bulk workers, which keeps foreground responsiveness reasonable under background load.

## Production Ready?

Yes, for the use cases described above. The scheduler has been exercised across combined cyclictest + hackbench + stress-ng workloads. The BPF code is approximately 600 lines, the Rust loader is approximately 260 lines.

## Benchmark Results

Benchmark results (cyclictest, hackbench, stress-ng, schbench) for the current v3.0.2 release are available in the comparison archive:

https://github.com/galpt/testing-scx_flow/tree/benchmark-archives/20260601_scx_flow_v3.0.0/mini/v3.0.0/0_max_latency_spikes

## Validation

Benchmark scripts and archived result bundles are available at:
https://github.com/galpt/testing-scx_flow
