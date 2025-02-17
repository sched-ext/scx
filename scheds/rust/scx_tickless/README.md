# scx_tickless

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_tickless is a server-oriented scheduler designed for cloud computing,
virtualization, and high-performance computing workloads.

The scheduler operates by routing all scheduling events through a pool of
primary CPUs dedicated to process scheduling events. This allows to
minimize OS noise on the remaining CPUs.

Tasks are added to a global queue, and the primary CPUs distribute them
across the other CPUs, sending preemption events via IPC, when necessary,
to preserve system responsiveness.

In situations where the system is not overcommitted, tasks can run
uninterrupted on their assigned CPUs, leading to better performance
isolation and lower OS noise.

## Typical Use Case

Typical use cases include cloud computing, virtualization and
high performance computing workloads.

## Production Ready?

This scheduler is still experimental.
