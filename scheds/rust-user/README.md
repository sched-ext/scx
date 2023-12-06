RUST SCHEDULERS
===============

# Introduction

This directory contains schedulers with user space rust components.

This document will give some background on each scheduler, including describing
the types of workloads or scenarios they're designed to accommodate.  For more
details on any of these schedulers, please see the header comment in their
main.rs or \*.bpf.c files.


# Schedulers

This section lists, in alphabetical order, all of the current rust user-space
schedulers.

--------------------------------------------------------------------------------

## scx_layered

### Overview

A highly configurable multi-layer BPF / user space hybrid scheduler.

scx_layered allows the user to classify tasks into multiple layers, and apply
different scheduling policies to those layers. For example, a layer could be
created of all tasks that are part of the `user.slice` cgroup slice, and a
policy could be specified that ensures that the layer is given at least 80% CPU
utilization for some subset of CPUs on the system.

### Typical Use Case

scx_layered is designed to be highly customizable, and can be targeted for
specific applications. For example, if you had a high-priority service that
required priority access to all but 1 physical core to ensure acceptable p99
latencies, you could specify that the service would get priority access to all
but 1 core on the system. If that service ends up not utilizing all of those
cores, they could be used by other layers until they're needed.

### Production Ready?

Yes. If tuned correctly, scx_layered should be performant across various CPU
architectures and workloads.

That said, you may run into an issue with infeasible weights, where a task with
a very high weight may cause the scheduler to incorrectly leave cores idle
because it thinks they're necessary to accommodate the compute for a single
task. This can also happen in CFS, and should soon be addressed for
scx_layered.

--------------------------------------------------------------------------------

## scx_rusty

### Overview

A multi-domain, BPF / user space hybrid scheduler. The BPF portion of the
scheduler does a simple round robin in each domain, and the user space portion
(written in Rust) calculates the load factor of each domain, and informs BPF of
how tasks should be load balanced accordingly.

### Typical Use Case

Rusty is designed to be flexible, and accommodate different architectures and
workloads. Various load balancing thresholds (e.g. greediness, frequenty, etc),
as well as how Rusty should partition the system into scheduling domains, can
be tuned to achieve the optimal configuration for any given system or workload.

### Production Ready?

Yes. If tuned correctly, rusty should be performant across various CPU
architectures and workloads. Rusty by default creates a separate scheduling
domain per-LLC, so its default configuration may be performant as well. Note
however that scx_rusty does not yet disambiguate between LLCs in different NUMA
nodes, so it may perform better on multi-CCX machines where all the LLCs share
the same socket, as opposed to multi-socket machines.

Note as well that you may run into an issue with infeasible weights, where a
task with a very high weight may cause the scheduler to incorrectly leave cores
idle because it thinks they're necessary to accommodate the compute for a
single task. This can also happen in CFS, and should soon be addressed for
scx_rusty.
