# scx_flow

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-driven `sched_ext` scheduler with zero heuristic classification. Tasks accumulate budget while sleeping and spend it while running; non-wakeup re-enqueues are classified into four O(1) FIFO tiers by budget level — PRIORITY (≥ 1.5ms budget), NORMAL (≥ 1ms), LOW (≥ 0.5ms), and DEFICIT (< 0.5ms, bulk workers). Higher tiers always dispatch before lower tiers, guaranteeing freedom from priority inversion within the tier hierarchy. Wakeups are dispatched immediately to the target CPU via `SCX_DSQ_LOCAL_ON`, bypassing the tier system entirely. Non-migratable tasks receive absolute priority over bulk workers via per-CPU FIFO dispatch queues. There are no tunables, no scoring signals, and no adaptive tuning — every scheduling decision is derived from kernel-verified inputs.

## Typical Use Case

Systems where scheduling decisions must be deterministic and explainable: embedded control, robotics, avionics, automotive, and other mission-critical workloads. The tier-based dispatch (PRIORITY → NORMAL → LOW → DEFICIT) prevents priority inversion because a lower-tier task can never block a higher-tier task. The fixed minimum slice bounds worst-case wakeup latency.

General-purpose desktop and workstation use is also supported; interactive tasks (longer sleep → higher budget → higher tier) are naturally separated from bulk workers without requiring configuration or heuristics.

## Web UI

When scx_flow starts, it automatically serves a live metrics dashboard at [http://127.0.0.1:50005](http://127.0.0.1:50005). No extra flags needed — open it in any browser.

The dashboard shows:
- How many tasks are in each dispatch tier (Priority / Normal / Low / Exhausted)
- System information: running tasks, runtime, dispatch counts
- All values update every 200ms via Server-Sent Events — no page refresh needed
- If the page doesn't load, the scheduler may have stopped running (the kernel falls back to the built-in EEVDF scheduler)

Disable with `--no-webui` if you don't need it.

## Production Ready?

Yes, for the use cases described above. The scheduler has been exercised across combined cyclictest + hackbench + stress-ng workloads.

## Validation

Benchmark scripts and archived result bundles are available at:
https://github.com/galpt/testing-scx_flow
