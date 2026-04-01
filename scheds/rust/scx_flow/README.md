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
- a dedicated latency lane ahead of the normal reserved queue
- bounded per-task latency debt so recently harmed interactive tasks can carry urgency across wakeups
- a tiny urgent latency sub-lane so debt-bearing wakeups can cut ahead of ordinary latency-credit traffic
- a bounded urgent-latency burst so that sub-lane can actually win a couple of dispatches before normal ordering resumes
- a bounded high-priority dispatch quota so shared and contained lanes can occasionally force service before higher lanes monopolize dispatch forever
- a bounded reserved-lane dispatch cap so the reserved global DSQ must rotate lower lanes before it can dominate dispatch indefinitely
- explicit reserved-lane miss counters so we can tell whether that cap is firing too early or whether lower lanes are simply empty when rotation is attempted
- bounded enqueue-side head-start promotion for real arriving shared/contained work when those lanes are already meaningfully starved
- a bounded local-reserved burst cap so ordinary idle/stable fast-path routing backs off under pressure before it monopolizes wakeup placement
- runtime-tunable urgent-debt and urgent-burst controls so the controller can steer that path without hard-coded threshold churn
- explicit urgent-burst continuation counters so we can tell the difference between isolated urgent hits and a real multi-dispatch burst
- a dedicated contained throughput lane for hog-like tasks after latency and reserved work
- a bounded fairness floor that periodically rescues contained and shared work under sustained higher-lane pressure
- lane-aware runtime tuning for latency credit, fairness-floor thresholds, and local-fast pressure caps
- wakeup-budget accounting in `runnable()`
- a soft last-CPU stability bias in `select_cpu()`
- a bounded stable-local fast path for non-RT positive-budget wakeups that can safely stay on their last CPU
- stable-local diagnostics so last-CPU reuse, misses, and rejections can be observed directly
- bounded hog containment that strips latency privileges from persistent budget exhausters until they recover
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
