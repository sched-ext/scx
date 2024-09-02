# scx_lavd

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_lavd is a BPF scheduler that implements an LAVD (Latency-criticality Aware
Virtual Deadline) scheduling algorithm. While LAVD is new and still evolving,
its core ideas are 1) measuring how much a task is latency critical and 2)
leveraging the task's latency-criticality information in making various
scheduling decisions (e.g., task's deadline, time slice, etc.). As the name
implies, LAVD is based on the foundation of deadline scheduling. This scheduler
consists of the BPF part and the rust part. The BPF part makes all the
scheduling decisions; the rust part provides high-level information (e.g., CPU
topology) to the BPF code, loads the BPF code and conducts other chores (e.g.,
printing sampled scheduling decisions).

## Typical Use Case

scx_lavd is initially motivated by gaming workloads. It aims to improve
interactivity and reduce stuttering while playing games on Linux. Hence, this
scheduler's typical use case involves highly interactive applications, such as
gaming, which requires high throughput and low tail latencies. 

## Production Ready?

Yes, scx_lavd should be performant across various CPU architectures. It creates
a separate scheduling domain per-LLC, per-core type (e.g., P or E core on
Intel, big or LITTLE on ARM), and per-NUMA domain, so the default balanced
profile or autopilot mode should be performant. It mainly targets single CCX
/ single-socket systems.

