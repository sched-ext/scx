# scx_cosmos

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

General-purpose deadline-based scheduler, designed to improve throughput for
server and CPU-intensive workloads while still guaranteeing latency and
responsiveness for interactive tasks.

The scheduler tracks each task's virtual runtime against a global virtual
clock to compute scheduling deadlines, ensuring CPU-intensive tasks do not
crowd out latency-sensitive ones.

When a task voluntarily sleeps, the scheduler records its virtual lag: the
distance between the global clock and the task's virtual runtime at the moment
of sleep. A positive lag (credit) means the task slept behind the virtual clock,
as typical sleepers do; a negative lag (debt) means it slept ahead, as CPU-bound
tasks that briefly block tend to do. On wakeup, debt is re-applied so a
CPU-bound task cannot shed its accumulated penalty with a short sleep. Credit is
bounded so long sleepers do not claim an unbounded head start. The bound is
scaled by wakeup frequency, so tasks that sleep often earn a wider credit/debt
window than tasks with infrequent, long sleeps.

The scheduler uses a per-node deadline-ordered dispatch queue (DSQ), which
enables fast task migration within the same NUMA node; cross-node migrations are
allowed on task wake-up events.

On multi-GPU NVIDIA systems with multiple NUMA nodes, the scheduler can
automatically place GPU-bound tasks on CPUs topologically close to the GPU
they are using, reducing cross-node memory traffic and improving throughput.

The scheduler also supports perf-event-driven task placement. A configurable
hardware performance counter (e.g., cache misses, branch mispredictions, etc.)
can be used to influence migrations: tasks that exceed a threshold for the
monitored event are migrated to spread pressure across CPUs, while a separate
sticky event can keep a task pinned to its current CPU when its counter rate is
high (useful for workloads that benefit from warm caches or tight data
locality).

## Typical Use Case

General-purpose scheduler: the scheduler should adapt itself both for
server workloads or desktop workloads.

## Production Ready?

Yes.
