# scx_mavd

Experimental fork of scx_lavd for an arena-native cid conversion. The
upstream policy and source organization are retained for future ports. It
needs a kernel with the cid form of sched_ext ops and clang 22 or newer.
[CONVERSION.md](CONVERSION.md) states the fork's goals, the representation
choices, the verifier constraints and the procedure for porting lavd
changes.

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_mavd` is a BPF scheduler that implements an `LAVD` (Latency-criticality Aware
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

`scx_mavd` is initially motivated by gaming workloads. It aims to improve
interactivity and reduce stuttering while playing games on Linux. Hence, this
scheduler's typical use case involves highly interactive applications, such as
gaming, which requires high throughput and low tail latencies.

## Production Ready?

The upstream lavd scheduler is production-ready. This experimental fork is
under validation. Like lavd, `scx_mavd` should be performant across various
CPU architectures. It creates a separate scheduling domain per-LLC, per-core
type (e.g., P or E core on Intel, big or LITTLE on ARM), and per-NUMA
domain, so the default balanced profile or autopilot mode should be
performant. It mainly targets single CCX / single-socket systems.
