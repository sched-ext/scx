# scx_flow

This is a single user-defined scheduler used within
[`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux
kernel feature which enables implementing kernel thread schedulers in BPF and
dynamically loading them. [Read more about
`sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-based `sched_ext` scheduler built around a small number
of bounded service lanes. It aims to keep interactive wakeups responsive
without abandoning general-purpose throughput or turning the policy into a
large collection of special cases.

Tasks accumulate wakeup budget while sleeping and spend that budget while
running. Positive-budget work is favored ahead of the shared fallback path,
while bounded adaptive tuning lets the scheduler move between balanced,
latency-oriented, and throughput-oriented behavior without requiring constant
manual retuning. The implementation combines reserved, latency, shared, and
contained paths with bounded urgency, fairness, and locality mechanisms so the
scheduler stays explainable and measurable instead of depending on large,
open-ended heuristics.

## Typical Use Case

General-purpose workloads where interactive sleepers and background CPU work
need to coexist reasonably well without per-machine hand tuning.

## Production Ready?

Yes, for everyday general-purpose use.

`scx_flow` has been exercised across broad workload, lifecycle, and adversarial
stress validation, and its core paths are intended to be robust rather than
experimental scaffolding. It should still be described conservatively for hard
latency guarantees under extreme interference, but it is suitable for daily use
as a general-purpose `sched_ext` scheduler.

## Validation

Benchmark scripts, validation helpers, and archived result bundles used during
development are available at:
https://github.com/galpt/testing-scx_flow

These artifacts are provided as supplementary validation material and are not
required to use `scx_flow` itself.
