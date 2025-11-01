# scx_beerland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_beerland (BPF-Enhanced Execution Runtime Locality-Aware Non-blocking
Dispatcher) is a scheduler designed to prioritize locality and scalability.

The scheduler uses separate DSQ (deadline ordered) for each CPU. Tasks get
a chance to migrate only on wakeup, when the system is not saturated. If
the system becomes saturated, CPUs also start pulling tasks from the remote
DSQs, always selecting the task with the smallest deadline.

## Typical Use Case

Cache-intensive workloads, systems with a large amount of CPUs.

## Production Ready?

Yes.
