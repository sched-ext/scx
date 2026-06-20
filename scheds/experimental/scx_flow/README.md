# scx_flow

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-driven `sched_ext` scheduler with zero heuristic classification. Tasks accumulate budget while sleeping and spend it while running. Non-wakeup re-enqueues enter the **Waiting Room** — per-CPU DSQs where each task receives an ideal CPU time slice computed from the bandwidth model: `(budget / BUDGET_MAX) × (thread_bw / system_total_khz) × window_ns`, adjusted for SMT bandwidth halving, migration cost penalties, and load awareness. Wakeups are dispatched immediately to the target CPU via `SCX_DSQ_LOCAL_ON`.

## Typical Use Case

Systems where scheduling decisions must be deterministic and explainable: embedded control, robotics, avionics, automotive, and other mission-critical workloads. The bandwidth model ensures tasks get slices proportional to their budget and target core frequency, preventing both starvation and priority inversion.

General-purpose desktop and workstation use is also supported; interactive tasks (longer sleep → higher budget → longer slice) are naturally separated from bulk workers without requiring configuration or heuristics.

## Web UI

When scx_flow starts, it serves a live dashboard at `http://[::1]:50005/` or via Unix socket at `/tmp/scx_flow.sock`. The dashboard shows per-core cards (CPU ID, max frequency, LLC, SMT status), the Waiting Room carriage pool (producer slot index, filling count, 64-slot grid), and system statistics (on-CPU count, wake/pinned dispatches, budget exhaustions, CPU migrations). Values update every second. Disable with `--no-webui`.

## Production Ready?

Yes, for the use cases described above.
