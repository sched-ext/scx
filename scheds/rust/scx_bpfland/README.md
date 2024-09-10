# scx_bpfland

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_bpfland: a vruntime-based sched_ext scheduler that prioritizes interactive
workloads.

This scheduler is derived from scx_rustland, but it is fully implemented in BPF.
It has a minimal user-space Rust part to process command line options, collect
metrics and log out scheduling statistics. The BPF part makes all the
scheduling decisions.

Tasks are categorized as either interactive or regular based on their average
rate of voluntary context switches per second. Tasks that exceed a specific
voluntary context switch threshold are classified as interactive. Interactive
tasks are prioritized in a higher-priority queue, while regular tasks are
placed in a lower-priority queue. Within each queue, tasks are sorted based on
their weighted runtime: tasks that have higher weight (priority) or use the CPU
for less time (smaller runtime) are scheduled sooner, due to their a higher
position in the queue.

Moreover, each task gets a time slice budget. When a task is dispatched, it
receives a time slice equivalent to the remaining unused portion of its
previously allocated time slice (with a minimum threshold applied). This gives
latency-sensitive workloads more chances to exceed their time slice when needed
to perform short bursts of CPU activity without being interrupted (i.e.,
real-time audio encoding / decoding workloads).

## Typical Use Case

Interactive workloads, such as gaming, live streaming, multimedia, real-time
audio encoding/decoding, especially when these workloads are running alongside
CPU-intensive background tasks.

In this scenario scx_bpfland ensures that interactive workloads maintain a high
level of responsiveness.

## Production Ready?

The scheduler is based on scx_rustland, implementing nearly the same scheduling
algorithm with minor changes and optimizations to be fully implemented in BPF.

Given that the scx_rustland scheduling algorithm has been extensively tested,
this scheduler can be considered ready for production use.
