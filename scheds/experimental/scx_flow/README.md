# scx_flow

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-driven `sched_ext` scheduler with zero heuristic classification. Tasks accumulate budget while sleeping and spend it while running; vtime is derived from remaining budget (`BUDGET_MAX − max(0, budget)`) so tasks that sleep longer dispatch earlier. Wakeups are dispatched immediately to the target CPU via `SCX_DSQ_LOCAL_ON`. Non-wakeup re-enqueues are vtime-ordered in a single global DSQ, and non-migratable tasks receive absolute priority over bulk workers via per-CPU FIFO dispatch queues. There are no tunables, no scoring signals, and no adaptive tuning — every scheduling decision is derived from kernel-verified inputs.

## Typical Use Case

Systems where scheduling decisions must be deterministic and explainable: embedded control, robotics, avionics, automotive, and other mission-critical workloads. The bounded-vtime design prevents priority inversion from accumulated runtime, and the fixed minimum slice bounds worst-case wakeup latency.

General-purpose desktop and workstation use is also supported; interactive tasks (longer sleep → higher budget → lower vtime) are naturally separated from bulk workers without requiring configuration or heuristics.

## Production Ready?

Yes, for the use cases described above. The scheduler has been exercised across combined cyclictest + hackbench + stress-ng workloads.

## Validation

Benchmark scripts and archived result bundles are available at:
https://github.com/galpt/testing-scx_flow
