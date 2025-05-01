# scx_rustland

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_rustland is based on scx_rustland_core, a BPF component that abstracts
the low-level sched_ext functionalities. The actual scheduling policy is
entirely implemented in user space and it is written in Rust.

## How To Install

Available as a [Rust crate](https://crates.io/crates/scx_rustland): `cargo add scx_rustland`

## Typical Use Case

scx_rustland is designed to prioritize interactive workloads over background
CPU-intensive workloads. For this reason the typical use case of this scheduler
involves low-latency interactive applications, such as gaming, video
conferencing and live streaming.

scx_rustland is also designed to be an "easy to read" template that can be used
by any developer to quickly experiment more complex scheduling policies fully
implemented in Rust.

## Production Ready?

For performance-critical production scenarios, other schedulers are likely
to exhibit better performance, as offloading all scheduling decisions to
user-space comes with a certain cost (even if it's minimal).

However, a scheduler entirely implemented in user-space holds the potential for
seamless integration with sophisticated libraries, tracing tools, external
services (e.g., AI), etc.

Hence, there might be situations where the benefits outweigh the overhead,
justifying the use of this scheduler in a production environment.

## Demo

[scx_rustland-terraria](https://github.com/sched-ext/scx/assets/1051723/42ec3bf2-9f1f-4403-80ab-bf5d66b7c2d5)

The key takeaway of this demo is to demonstrate that , despite the overhead of
running a scheduler in user-space, we can still obtain interesting results and,
in this particular case, even outperform the default Linux scheduler (EEVDF) in
terms of application responsiveness (fps), while a CPU intensive workload
(parallel kernel build) is running in the background.
