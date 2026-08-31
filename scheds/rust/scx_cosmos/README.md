# scx_cosmos

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

Lightweight scheduler optimized for preserving task-to-CPU locality.

When the system is not saturated, the scheduler prioritizes keeping tasks
on the same CPU using local DSQs. This not only maintains locality but also
reduces locking contention compared to shared DSQs, enabling good
scalability across many CPUs.

Under saturation, the scheduler switches to a deadline-based policy and
uses a shared DSQ (or per-node DSQs if NUMA optimizations are enabled).
This increases task migration across CPUs and boosts the chances for
interactive tasks to run promptly over the CPU-intensive ones.

To further improve responsiveness, the scheduler batches and defers CPU
wakeups using a timer. This reduces the task enqueue overhead and allows
the use of very short time slices (10 us by default).

The scheduler tries to keep tasks running on the same CPU as much as
possible when the system is not saturated.

## NVIDIA GPU Workloads

With `--gpu`, scx_cosmos uses NVML to identify NVIDIA GPU processes and
prefers CPUs on the GPU-local NUMA node. It also discovers other processes in
the same exact cgroup so multi-process services receive a consistent locality
hint without requiring users to provide process IDs or cgroup paths.

The cgroup is treated as the workload boundary. GPU services should run in a
dedicated cgroup, as every process in the group inherits the GPU locality hint.
Systemd services and container runtimes normally provide such a boundary;
processes launched directly from a login shell may instead share a broader
session cgroup.

scx_cosmos must run in the host PID and cgroup namespaces so userspace TGIDs
match the TGIDs used by BPF. Workloads may still run in containers.

Discovery never expands the root cgroup, child cgroups, or threaded cgroups.
If cgroup membership cannot be determined safely, scx_cosmos retains the
NVML process-only behavior.

Cgroup discovery is used only with `--gpu-util-threshold=0` (the default).
When utilization filtering is enabled, scx_cosmos retains the existing
process-only behavior so filtered NVML processes are not reintroduced as
cgroup peers.

## Typical Use Case

General-purpose scheduler: the scheduler should adapt itself both for
server workloads or desktop workloads.

## Production Ready?

Yes.
