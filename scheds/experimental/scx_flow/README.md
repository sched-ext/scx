# scx_flow

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-driven `sched_ext` scheduler with zero heuristic classification. Tasks accumulate budget while sleeping and spend it while running; non-wakeup re-enqueues are classified into four O(1) FIFO tiers by budget level — PRIORITY (≥ 1.5ms budget), NORMAL (≥ 1ms), LOW (≥ 0.5ms), and DEFICIT (< 0.5ms, bulk workers). The dispatch function rotates the starting tier on every call (gen & 3 selects the phase), so no tier waits longer than 3 dispatch cycles before being serviced first — this prevents both starvation and priority inversion without heuristic tuning. Wakeups are dispatched immediately to the target CPU via `SCX_DSQ_LOCAL_ON`, bypassing the tier system entirely. Non-migratable tasks receive absolute priority over bulk workers via per-CPU FIFO dispatch queues. There are no tunables, no scoring signals, and no adaptive tuning — every scheduling decision is derived from kernel-verified inputs.

## Typical Use Case

Systems where scheduling decisions must be deterministic and explainable: embedded control, robotics, avionics, automotive, and other mission-critical workloads. The rotating tier dispatch (cycling start position across all 4 tiers) prevents both starvation and priority inversion without sacrificing O(1) performance. The fixed minimum slice bounds worst-case wakeup latency.

General-purpose desktop and workstation use is also supported; interactive tasks (longer sleep → higher budget → higher tier) are naturally separated from bulk workers without requiring configuration or heuristics.

## Web UI

When scx_flow starts, it automatically serves a live metrics dashboard at [http://localhost:50005](http://localhost:50005). No extra flags needed — open it in any browser.

The dashboard shows:
- How many dispatches have gone through each tier (Priority / Normal / Low / Exhausted)
- System information: running tasks, runtime, dispatch counts
- All values update every second via polling — no page refresh needed
- If the page doesn't load, the scheduler may have stopped running (the kernel falls back to the built-in EEVDF scheduler)

Disable with `--no-webui` if you don't need it.

## Production Ready?

Yes, for the use cases described above. The scheduler has been exercised across combined cyclictest + hackbench + stress-ng workloads.

## Validation

Benchmark scripts and archived result bundles are available at:
https://github.com/galpt/testing-scx_flow
