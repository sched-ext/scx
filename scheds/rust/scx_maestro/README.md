# scx_maestro

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_maestro` is a workload orchestrator scheduler with sub-scheduler
support, designed to manage different workloads with distinct performance,
power-saving and latency requirements.

It uses per-LLC (Last Level Cache) dispatch queues to preserve cache
locality, ensuring that tasks are scheduled on CPUs that share the same
cache domain whenever possible.

Key features:

- **Sub-scheduler support**: multiple scheduler instances can coexist, each
  targeting a specific cgroup, allowing fine-grained scheduling policies
  for different workload classes.
- **Per-LLC queues**: tasks are dispatched through per-LLC queues to
  maximize cache reuse and minimize cross-cache migrations.
- **Primary CPU domain**: flexible CPU prioritization via
  `--primary-domain`, supporting explicit CPU lists, automatic detection of
  fast/slow cores, or full-system scheduling.
- **Low-latency mode**: `--lowlatency` enables low-latency scheduling,
  prioritizing performance predictability over throughput.
- **Core compaction**: `--compaction` consolidates tasks onto fewer cores,
  freeing up idle cores for power savings or burst capacity.

## Typical Use Case

Systems running mixed workloads or mixed containers that want to use
separate scheduling profiles per-cgroup / per-container, such as
latency-sensitive services alongside batch jobs, or heterogeneous platforms
(big.LITTLE) where different task classes need different
performance/efficiency trade-offs.

## Example

Run multiple instances of `scx_maestro` with different scheduling profiles,
each targeting a specific cgroup:

```
# Root cgroup scheduler: use default profile
$ sudo scx_maestro --cgroup /sys/fs/cgroup

# User foreground apps: use performance + lowlatency profile
$ sudo scx_maestro -m performance --lowlatency \
  --cgroup /sys/fs/cgroup/user.slice/user-1000.slice/foreground/

# User background apps: use powersave + core compaction + CPU throttling
$ sudo scx_maestro -m powersave --compaction --throttle-us 1000 \
  --cgroup /sys/fs/cgroup/user.slice/user-1000.slice/background/
```

## Production Ready?

Yes.
