# scx_flow

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-driven `sched_ext` scheduler with zero heuristic classification. Tasks accumulate budget while sleeping and spend it while running. Non-wakeup re-enqueues enter the **Waiting Room** — per-CPU vtime-ordered DSQs where each task receives an equal share of its target CPU's bandwidth: `FLOW_CARRIAGE_NS / tasks_on_cpu`, clamped to [50µs, 2ms]. Slices adjust dynamically as tasks arrive on the same core. Wakeups are dispatched immediately to the target CPU via `SCX_DSQ_LOCAL_ON`.

## Typical Use Case

Systems where scheduling decisions must be deterministic and explainable: embedded control, robotics, avionics, automotive, and other mission-critical workloads. The fair-share slice model ensures each task receives an equal portion of its target core's bandwidth, preventing both starvation and priority inversion.

General-purpose desktop and workstation use is also supported; interactive tasks (longer sleep → higher budget → longer slice) are naturally separated from bulk workers without requiring configuration or heuristics.

## Web UI

When scx_flow starts, it serves a live dashboard at `http://[::1]:50005/` or via Unix socket at `/tmp/scx_flow.sock`. The dashboard shows per-core cards (CPU ID, max frequency, LLC, SMT status), the Waiting Room carriage pool (producer slot index, filling count, 64-slot grid), and system statistics (on-CPU count, wake/pinned dispatches, budget exhaustions, CPU migrations). Values update every second. Disable with `--no-webui`.

## Production Ready?

Yes, for the use cases described above.
