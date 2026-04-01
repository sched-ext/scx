# scx_flow

This is a single user-defined scheduler used within
[`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux
kernel feature which enables implementing kernel thread schedulers in BPF and
dynamically loading them. [Read more about
`sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-based `sched_ext` scheduler focused on balancing
interactive wakeup responsiveness with general-purpose throughput.

Tasks earn wakeup budget while sleeping and spend that budget while running.
Positive-budget tasks are favored through a reserved path ahead of the shared
fallback queue. The scheduler also includes a bounded adaptive controller so it
can move between balanced, latency-guarded, and throughput-oriented settings
without relying on manual tuning.

Current implementation includes:

- a reserved vs shared queue split
- wakeup-budget accounting in `runnable()`
- a soft last-CPU stability bias in `select_cpu()`
- lifecycle cleanup through `enable()` and `exit_task()`
- `cpu_release()` rescue handling
- a narrow RT-sensitive wakeup lane for pinned positive-budget wakeups

## Typical Use Case

General-purpose workloads where interactive sleepers and background CPU work
need to coexist reasonably well without per-machine hand tuning.

## Production Ready?

Yes, for practical general-purpose use, with caveats.

`scx_flow` is stable enough to run as an everyday `sched_ext` scheduler and has
been exercised across normal workload, lifecycle, and stress scenarios. Its
core behavior, adaptive tuning loop, and task lifecycle paths are all intended
to be production-capable rather than experimental scaffolding.

That said, `scx_flow` should still be described conservatively. It does not yet
justify hard wakeup-latency guarantees, and its implementation surface is still
smaller and less feature-rich than the most mature schedulers in the tree.

## Validation

Benchmark scripts, validation helpers, and archived result bundles used during
development are available at:
https://github.com/galpt/testing-scx_flow

These artifacts are provided as supplementary validation material and are not
required to use `scx_flow` itself.
