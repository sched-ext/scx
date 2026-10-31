# scx_lavd

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_lavd` is a BPF scheduler that implements an `LAVD` (Latency-criticality Aware
Virtual Deadline) scheduling algorithm. While `LAVD` is new and still evolving,
its core ideas are 1) measuring how much a task is latency critical and 2)
leveraging the task's latency-criticality information in making various
scheduling decisions (e.g., task's deadline, time slice, etc.). As the name
implies, `LAVD` is based on the foundation of deadline scheduling. This scheduler
consists of the BPF part and the `Rust` part. The BPF part makes all the
scheduling decisions; the `Rust` part provides high-level information (e.g., CPU
topology) to the BPF code, loads the BPF code and conducts other chores (e.g.,
printing sampled scheduling decisions).

## Typical Use Case

`scx_lavd` is initially motivated by gaming workloads. It aims to improve
interactivity and reduce stuttering while playing games on Linux. Hence, this
scheduler's typical use case involves highly interactive applications, such as
gaming, which requires high throughput and low tail latencies.

## Queued Wakeups (--queued-wakeup)

By default, `scx_lavd` does not allow queued wakeups, so a wakeup runs the
scheduler's callbacks synchronously in the waker's context. With
`--queued-wakeup`, the scheduler sets `SCX_OPS_ALLOW_QUEUED_WAKEUP` so the
kernel may activate woken tasks asynchronously. In this mode, `@current` in
`ops.runnable()` no longer identifies the original waker.

With `--queued-wakeup`, wake frequency is estimated from eligible wakeups
observed in select_cpu. Wakeups that bypass select_cpu are not counted.
Waker-wakee criticality propagation is disabled.

The option requires kernel `SCX_OPS_ALLOW_QUEUED_WAKEUP` support; the
scheduler refuses to start when it is missing. This is an experimental
feature.

## Production Ready?

Yes, `scx_lavd` should be performant across various CPU architectures. It creates
a separate scheduling domain per-LLC, per-core type (e.g., P or E core on
Intel, big or LITTLE on ARM), and per-NUMA domain, so the default balanced
profile or autopilot mode should be performant. It mainly targets single CCX
/ single-socket systems.
