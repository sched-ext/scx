EXAMPLE SCHEDULERS
==================

# Introduction

This directory contains example schedulers that are shipped with the sched_ext
Linux kernel tree.

While these schedulers can be loaded and used to schedule on your system, their
primary purpose is to illustrate how various features of sched_ext can be used.

This document will give some background on each example scheduler, including
describing the types of workloads or scenarios they're designed to accommodate.
For more details on any of these schedulers, please see the header comment in
their .bpf.c file.

# Schedulers

This section lists, in alphabetical order, all of the current example
schedulers.

--------------------------------------------------------------------------------

## scx_central

### Overview

A "central" scheduler where scheduling decisions are made from a single CPU.
This scheduler illustrates how scheduling decisions can be dispatched from a
single CPU, allowing other cores to run with infinite slices, without timer
ticks, and without having to incur the overhead of making scheduling decisions.

### Typical Use Case

This scheduler could theoretically be useful for any workload that benefits
from minimizing scheduling overhead and timer ticks. An example of where this
could be particularly useful is running VMs, where running with infinite slices
and no timer ticks allows the VM to avoid unnecessary expensive vmexits.

### Production Ready?

Not yet. While tasks are run with an infinite slice (`SCX_SLICE_INF`), they're
preempted every 20ms in a timer callback. The scheduler also puts the core
scheduling logic inside of the central / scheduling CPU's `ops.dispatch()` path,
and does not yet have any kind of priority mechanism.

--------------------------------------------------------------------------------

## scx_flatcg

### Overview

A flattened cgroup hierarchy scheduler. This scheduler implements hierarchical
weight-based cgroup CPU control by flattening the cgroup hierarchy into a
single layer, by compounding the active weight share at each level. The effect
of this is a much more performant CPU controller, which does not need to
descend down cgroup trees in order to properly compute a cgroup's share.

### Typical Use Case

This scheduler could be useful for any typical workload requiring a CPU
controller, but which cannot tolerate the higher overheads of the fair CPU
controller.

### Production Ready?

Yes, though the scheduler (currently) does not adequately accommodate
thundering herds of cgroups. If, for example, many cgroups which are nested
behind a low-priority cgroup were to wake up around the same time, they may be
able to consume more CPU cycles than they are entitled to.

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

`scx_nest` is designed to optimize workloads that CPU utilization somewhat low,
and which can benefit from running on a subset of cores on the host so as to
keep the frequencies high on those cores. Some workloads may perform better by
spreading work across many cores to avoid thrashing the cache, etc. Determining
whether a workload is well-suited to `scx_nest` will likely require
experimentation.

### Production Ready?

This scheduler could be used in a production environment, assuming the hardware
constraints enumerated above.

--------------------------------------------------------------------------------

## scx_pair

### Overview

A sibling scheduler which ensures that tasks will only ever be co-located on a
physical core if they're in the same cgroup. It illustrates how a scheduling
policy could be implemented to mitigate CPU bugs, such as L1TF, and also shows
how some useful kfuncs such as `scx_bpf_kick_cpu()` can be utilized.

### Typical Use Case

While this scheduler is only meant to be used to illustrate certain sched_ext
features, with a bit more work (e.g. by adding some form of priority handling
inside and across cgroups), it could have been used as a way to quickly
mitigate L1TF before core scheduling was implemented and rolled out.

### Production Ready?

No

--------------------------------------------------------------------------------

## scx_qmap

### Overview

Another simple, yet slightly more complex scheduler that provides an example of
a basic weighted FIFO queuing policy. It also provides examples of some common
useful BPF features, such as sleepable per-task storage allocation in the
`ops.prep_enable()` callback, and using the `BPF_MAP_TYPE_QUEUE` map type to
enqueue tasks. It also illustrates how core-sched support could be implemented.

### Typical Use Case

Purely used to illustrate sched_ext features.

### Production Ready?

No

--------------------------------------------------------------------------------


## scx_simple

### Overview

A simple scheduler that provides an example of a minimal sched_ext
scheduler. `scx_simple` can be run in either global weighted vtime mode, or
FIFO mode.

### Typical Use Case

Though very simple, this scheduler should perform reasonably well on
single-socket CPUs with a uniform L3 cache topology. Note that while running in
global FIFO mode may work well for some workloads, saturating threads can
easily starve inactive ones.

### Production Ready?

This scheduler could be used in a production environment, assuming the hardware
constraints enumerated above, and assuming the workload tolerates the simplicity
of the scheduling policy.

--------------------------------------------------------------------------------

## scx_prev

### Overview

A variation on `scx_simple` with CPU selection that prioritizes an idle previous
CPU over finding a fully idle core (as is done in `scx_simple` and `scx_rusty`).

### Typical Use Case

This scheduler outperforms the in-kernel fair class, `scx_simple`, and `scx_rusty`
on OLTP workloads run on systems with simple topology (i.e. non-NUMA, single
LLC).

### Production Ready?

`scx_prev` has not been tested in a production environment, but given its
similarity to `scx_simple`, it might be production ready for specific workloads
on hardware with simple topology.

--------------------------------------------------------------------------------

## scx_userland

### Overview

A simple weighted vtime scheduler where all scheduling decisions take place in
user space. This is in contrast to Rusty, where load balancing lives in user
space, but scheduling decisions are still made in the kernel.

### Typical Use Case

There are many advantages to writing schedulers in user space. For example, you
can use a debugger, you can write the scheduler in Rust, and you can use data
structures bundled with your favorite library.

On the other hand, user space scheduling can be hard to get right. You can
potentially deadlock due to not scheduling a task that's required for the
scheduler itself to make forward progress (though the sched_ext watchdog will
protect the system by unloading your scheduler after a timeout if that
happens). You also have to bootstrap some communication protocol between the
kernel and user space.

A more robust solution to this would be building a user space scheduling
framework that abstracts much of this complexity away from you.

### Production Ready?

No. This scheduler uses an ordered list for vtime scheduling, and is strictly
less performant than just using something like `scx_simple`. It is purely
meant to illustrate that it's possible to build a user space scheduler on
top of sched_ext.
