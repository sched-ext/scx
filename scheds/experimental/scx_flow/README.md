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
contained paths with bounded urgency, fairness, locality, and confidence
signals so the scheduler stays explainable and measurable instead of depending
on large, open-ended heuristics.

## Typical Use Case

General-purpose desktop and workstation use where foreground responsiveness and
background CPU work both matter.

In plain terms, `scx_flow` is aimed at machines that do several things at once:

- gaming while browsers, chat apps, or launchers stay open
- coding or office work while builds, downloads, or background jobs keep running
- everyday multitasking where short interactive work should feel quick instead
  of getting buried behind heavier CPU activity

What users should usually notice is not "maximum benchmark throughput at all
costs", but a machine that feels more consistently responsive, with fewer
obvious hiccups when interactive tasks and background load need to coexist.

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

Direct `v2.2.0` benchmark snapshot:
https://github.com/galpt/testing-scx_flow/tree/benchmark-archives/20260409_scx_flow_v2.2.0_release

In practice, the stronger results there usually translate to better foreground
responsiveness, steadier behavior under background load, and fewer obvious
hiccups when interactive and CPU-heavy work happen at the same time.

These artifacts are provided as supplementary validation material and are not
required to use `scx_flow` itself.
