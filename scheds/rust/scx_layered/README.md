# scx_layered

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

A highly configurable multi-layer BPF / user space hybrid scheduler.

`scx_layered` allows the user to classify tasks into multiple layers, and apply
different scheduling policies to those layers. For example, a layer could be
created of all tasks that are part of the `user.slice` cgroup slice, and a
policy could be specified that ensures that the layer is given at least 80% CPU
utilization for some subset of CPUs on the system.

## How To Install

Available as a [Rust crate](https://crates.io/crates/scx_layered): `cargo add scx_layered`

## Typical Use Case

`scx_layered` is designed to be highly customizable, and can be targeted for
specific applications. For example, if you had a high-priority service that
required priority access to all but 1 physical core to ensure acceptable p99
latencies, you could specify that the service would get priority access to all
but 1 core on the system. If that service ends up not utilizing all of those
cores, they could be used by other layers until they're needed.

## Production Ready?

Yes. If tuned correctly, `scx_layered` should be performant across various CPU
architectures and workloads.

That said, you may run into an issue with infeasible weights, where a task with
a very high weight may cause the scheduler to incorrectly leave cores idle
because it thinks they're necessary to accommodate the compute for a single
task. This can also happen in CFS, and should soon be addressed for
scx_layered.

## Tuning scx_layered

`scx_layered` is designed with specific use cases in mind and may not perform
as well as a general purpose scheduler for all workloads. It does have topology
awareness, which can be disabled with the `-t` flag. This may impact
performance on NUMA machines, as layers will be able to span NUMA nodes by
default. For configuring `scx_layered` to span across multiple NUMA nodes simply
setting all nodes in the `nodes` field of the config.

For controlling the performance level of different levels (i.e. CPU frequency)
the `perf` field can be set. This must be used in combination with the
`schedutil` frequency governor. The value should be from 0-1024 with 1024 being
maximum performance. Depending on the system hardware it will translate to
frequency, which can also trigger turbo boosting if the value is high enough
and turbo is enabled.

Layer affinities can be defined using the `nodes` or `llcs` layer configs. This
allows for restricting a layer to a NUMA node or LLC. Layers will by default
attempt to grow within the same NUMA node, however this may change to support
different layer growth strategies in the future. When tuning the `util_range`
for a layer there should be some consideration for how the layer should grow.
For example, if the `util_range` lower bound is too high, it may lead to the
layer shrinking excessively. This could be ideal for core compaction strategies
for a layer, but may poorly utilize hardware, especially in low system
utilization. The upper bound of the `util_range` controls how the layer grows,
if set too aggressively the layer could grow fast and prevent other layers from
utilizing CPUs. Lastly, the `slice_us` can be used to tune the timeslice
per layer. This is useful if a layer has more latency sensitive tasks, where
timeslices should be shorter. Conversely if a layer is largely CPU bound with
less concerns of latency it may be useful to increase the `slice_us` parameter.

### Utilization Compensation

On systems where external system work (e.g. softirq from network processing)
concentrates on specific CPUs, layers on those CPUs see reduced effective
capacity, but their own utilization metrics don't reflect the loss — because
softirq/irq time isn't attributed to any layer. This causes layers to
under-request CPUs.

The `util_compensation` option addresses this by proportionally scaling a
layer's utilization to account for unattributed CPU work. For each CPU, it
compares `/proc/stat` busy time (which includes irq/softirq) against the
total layer-attributed utilization on that CPU. The ratio gives a per-CPU
scale factor that captures how much unattributed work is consuming capacity.
Each CPU's layer usage delta is then multiplied by that CPU's scale factor
before being summed into the layer total. This means the compensation is
weighted by where the layer's actual work runs — a layer doing most of its
work on hot CPUs gets more compensation than one on cold CPUs, even if both
have the same total utilization.

`util_compensation` is a float from 0.0 to 1.0:
- **0.0** (default): no compensation, existing behavior
- **1.0**: full proportional scaling — each CPU's layer usage is individually
  scaled by that CPU's busy/attributed ratio before aggregation
- **0.5**: half the gap is applied

For example, if a layer runs 900ms on CPU 0 and 100ms on CPU 1 per second,
and CPU 0 has a scale factor of 2.0x (50% unattributed work) while CPU 1 has
1.0x, the compensated utilization is `900ms*2.0 + 100ms*1.0 = 1900ms = 1.9`
vs unscaled `1.0`. With `util_compensation: 0.5`, the blended value is
`1.0*0.5 + 1.9*0.5 = 1.45`, and the layer requests more CPUs via the normal
`util_range` mechanism.

See `examples/util_compensation.json` for a sample configuration.

`scx_layered` can provide performance wins, for certain workloads when
sufficient tuning on the layer config.
