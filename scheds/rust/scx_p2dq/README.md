# scx_p2dq

## Overview
A simple pick 2 load balanacing scheduler with dumb queueing.

The p2dq scheduler is a simple load balancing scheduler that uses a pick two
algorithm for load balancing. A fixed number of DSQs are created per LLC with
incremental slice intervals. If a task is able to consume the majority of the
assigned slice is it dispatched to a DSQ with a longer slice. Tasks that do not
consume more than half the slice are moved to shorter slice DSQs. The DSQs with
the shortest slice lengths are then determined to be "interactive". All DSQs on
the same LLC share the same vtime and there is special handling for
(non)interactive tasks.

The scheduler handles all scheduling decisions in BPF and the userspace
component is only for metric reporting.
