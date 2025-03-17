# scx_p2dq

## Overview
A simple pick 2 load balancing scheduler with (dumb) multi-layer queueing.

The p2dq scheduler is a simple load balancing scheduler that uses a pick two
algorithm for load balancing. A fixed number of DSQs are created per LLC with
incremental slice intervals. If a task is able to consume the majority of the
assigned slice is it dispatched to a DSQ with a longer slice. Tasks that do not
consume more than half the slice are moved to shorter slice DSQs. The DSQs with
the shortest slice lengths are then determined to be "interactive". All DSQs on
the same LLC share the same vtime and there is special handling for
(non)interactive tasks for load balancing purposes.

The scheduler handles all scheduling decisions in BPF and the userspace
component is only for metric reporting.

## Use Cases
p2dq can perform well in a variety of workloads including interactive workloads
such as gaming, batch processing and server applications. Tuning of of p2dq for
each use case is required.

### Configuration
The main idea behind p2dq is being able to classify which tasks are interactive
and using a separate dispatch queue (DSQ) for them. Non interactive tasks
can have special properties such as being able to be load balanced across
LLCs/NUMA nodes. The `--autoslice` option will attempt to scale DSQ time slices
based on the `--interactive-ratio`. DSQ time slices can also be set manually
if the duration/distribution of tasks that are considered to be interactive is
known in advance. `scxtop` can be used to get an understanding of time slice
utilization so that DSQs can be properly configured. For desktop systems keeping
the interactive ratio small (ex: <5) and using a small number of queues (2) will
give a general performance with autoslice enabled.
