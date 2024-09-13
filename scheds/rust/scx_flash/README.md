# scx_flash

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

A scheduler that focuses on ensuring fairness among tasks and performance
predictability.

It operates using an earliest deadline first (EDF) policy, where each task is
assigned a "latency" weight. This weight is dynamically adjusted based on how
often a task release the CPU before its full time slice is used. Tasks that
release the CPU early are given a higher latency weight, prioritizing them over
tasks that fully consume their time slice.

## Typical Use Case

The combination of dynamic latency weights and EDF scheduling ensures
responsive and consistent performance, even in overcommitted systems.

This makes the scheduler particularly well-suited for latency-sensitive
workloads, such as multimedia or real-time audio processing.

## Production Ready?

Yes.
