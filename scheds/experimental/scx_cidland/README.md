# scx_cidland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

Lightweight scheduler optimized for preserving task-to-CPU locality.

A task that wakes up goes straight to an idle CPU, chosen by a scan of an
idle bitmap kept in BPF that prefers, in order, a fully idle core, a faster
CPU, and the CPU or cache the task last ran on, the way EEVDF places a
task. When no CPU is idle, tasks are queued on a per-CPU DSQ ordered by an
EEVDF virtual deadline, with the lag of a task preserved across sleeps and
migrations, so that the queues of different CPUs remain comparable. A CPU
that runs out of work pulls from the other queues of its node, which keeps
the CPUs busy without putting a shared lock in the path of every wakeup.

On systems with CPUs of different capacity (e.g. P-cores and E-cores),
idle CPUs are handed out in capacity order and idle faster CPUs pull work
from the slower ones, so that tasks gravitate toward the fastest cores and
the slower ones are used only while the faster ones are busy.

Time slices are fixed (1 ms by default) and a task that runs out of its
slice with nothing waiting on its CPU keeps running there.

The scheduler is a cid-form scheduler: CPUs are addressed by their cid, a
dense id space ordered by topology in which the CPUs of a core, of an LLC
and of a NUMA node occupy contiguous ranges, so every topology question
the idle scan and the work pulling ask is a range of a bitmap. All the
state sized by the machine lives in a BPF arena allocated at start, so no
limit on the number of CPUs, cores, LLCs, nodes or capacity tiers is
built in.

## Requirements

A kernel with cid-form `sched_ext` support, that is one exporting
`struct sched_ext_ops_cid`:

```shell
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep sched_ext_ops_cid
```

## Typical Use Case

General-purpose scheduler: the scheduler should adapt itself both for
server workloads or desktop workloads.

## Production Ready?

Yes.
