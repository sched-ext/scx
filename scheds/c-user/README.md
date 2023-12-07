EXAMPLE SCHEDULERS
==================

# Introduction

This directory contains sched_ext schedulers with C user-space components.

This document will give some background on each such scheduler, including
describing the types of workloads or scenarios they're designed to accommodate.
For more details on any of these schedulers, please see the header comment in
their .bpf.c file.

# Schedulers

This section lists, in alphabetical order, all of the current example
schedulers.

--------------------------------------------------------------------------------

## scx_nest

### Overview

A scheduler based on the following Inria-Paris paper: [OS Scheduling with Nest:
Keeping Tasks Close Together on Warm
Cores](https://hal.inria.fr/hal-03612592/file/paper.pdf). The core idea of the
scheduler is to make scheduling decisions which encourage work to run on cores
that are expected to have high frequency. This scheduler currently will only
perform well on single CCX / single-socket hosts.

### Typical Use Case

scx_nest is designed to optimize workloads that CPU utilization somewhat low,
and which can benefit from running on a subset of cores on the host so as to
keep the frequencies high on those cores. Some workloads may perform better by
spreading work across many cores to avoid thrashing the cache, etc. Determining
whether a workload is well-suited to scx_nest will likely require
expermentation.

### Production Ready?

This scheduler could be used in a production environment, assuming the hardware
constraints enumerated above.
