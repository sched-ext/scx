# scx_priority

A dual-queue priority CPU scheduler for Linux built with `sched_ext` and `scx_rustland_core`.

## Overview

`scx_priority` classifies tasks into two distinct priority tiers:

1. **Interactive / High-Priority Tier (`weight > 100` / `nice < 0`)**:
   - UI applications, games, audio servers, and latency-sensitive threads.
   - Assigned boosted execution slices (10 ms).
   - Dispatched immediately to idle CPU cores.

2. **Standard / Batch Tier (`weight <= 100`)**:
   - Background tasks, compilation jobs, indexing, and batch workloads.
   - Assigned standard execution slices (5 ms).

On each scheduling pass, the high-priority queue is drained first before standard tasks, ensuring responsive user experience even under heavy background load.

## Usage

```bash
cargo run --release --package scx_priority
```
