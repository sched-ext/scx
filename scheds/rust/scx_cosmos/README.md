# scx_cosmos

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

Lightweight scheduler optimized for preserving task-to-CPU locality.

When the system is not saturated, the scheduler prioritizes keeping tasks
on the same CPU using local DSQs. This not only maintains locality but also
reduces locking contention compared to shared DSQs, enabling good
scalability across many CPUs.

Under saturation, tasks are queued on a per-CPU DSQ ordered by an EEVDF
virtual deadline computed against a single system-wide vruntime reference,
so that the queues of different CPUs remain comparable. A CPU that runs out
of work pulls from the other queues of its node, which keeps the CPUs busy
without putting a shared lock in the path of every wakeup.

On systems with CPUs of different capacity (e.g. P-cores and E-cores),
idle CPUs are handed out in capacity order and idle faster CPUs pull work
from the slower ones, so that tasks gravitate toward the fastest cores and
the slower ones are used only while the faster ones are busy.

To further improve responsiveness, the scheduler batches and defers CPU
wakeups using a timer. This reduces the task enqueue overhead and allows
the use of very short time slices (10 us by default).

The scheduler tries to keep tasks running on the same CPU as much as
possible when the system is not saturated.

## Typical Use Case

General-purpose scheduler: the scheduler should adapt itself both for
server workloads or desktop workloads.

## Production Ready?

Yes.
