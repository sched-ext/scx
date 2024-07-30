# scx_asdf

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_asdf: Adaptive Shortest Deadline First scheduler.

This is a deadline-based scheduler with a user-space classifier that identifies
and prioritizes interactive tasks.

## Typical Use Case

The scheduler is designed to prioritize interactive tasks in single-user
environments. As a result, it is particularly suited for use cases such as
desktop applications, gaming, and multimedia activities.

## Production Ready?

This scheduler is designed to work in single user scenarios. In this particular
context the scheduler can be considered production ready.
