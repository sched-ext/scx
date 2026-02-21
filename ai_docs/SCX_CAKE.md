# scx_cake

Generated: 2026-02-21, git-depth 7778

## Overview

scx_cake is a BPF-based CPU scheduler for Linux's sched_ext framework. It adapts the network [CAKE](https://www.bufferbloat.net/projects/codel/wiki/Cake/) (Common Applications Kept Enhanced) algorithm — specifically its DRR++ (Deficit Round Robin++) fairness mechanism — from packet scheduling to CPU task scheduling. It's designed for gaming workloads on modern AMD/Intel hardware.

The core insight mirrors network CAKE: just as short network flows (DNS, game packets) shouldn't be delayed by bulk downloads, short CPU bursts (input handling, audio) shouldn't be delayed by long-running tasks (compilation).

## 4-Tier Classification System

Every task is automatically classified into one of four tiers based on its EWMA (Exponential Weighted Moving Average) runtime — not user-assigned priority:

| Tier | Name | avg_runtime | Examples | Quantum |
|------|-------------|-------------|-----------------------------------|---------|
| T0 | Critical | < 100us | IRQ handlers, input, audio | 0.5ms |
| T1 | Interactive | < 2ms | Compositors, game physics/AI | 2ms |
| T2 | Frame | < 8ms | Game render threads, video encode | 4ms |
| T3 | Bulk | >= 8ms | Compilation, background work | 8ms |

Initial placement uses nice value as a hint, but runtime behavior becomes authoritative after ~3 scheduling stops. Hysteresis (10% deadband) prevents oscillation at tier boundaries.

## Scheduling Hot Path

The scheduling flow has three stages:

1. **`cake_select_cpu`** — First tries SYNC direct dispatch (waker's CPU). Otherwise calls `scx_bpf_select_cpu_dfl()` for kernel-native idle CPU selection. If an idle CPU is found, the task is dispatched directly (`SCX_DSQ_LOCAL_ON`). If all CPUs are busy, it tunnels the LLC ID and timestamp into per-CPU scratch for enqueue to reuse.

2. **`cake_enqueue`** — Inserts the task into a per-LLC DSQ (dispatch queue) with a vtime key of `(tier << 56) | timestamp`. Lower tiers drain first. New tasks (DRR++ new-flow) get a vtime bonus for instant responsiveness.

3. **`cake_dispatch`** — Pulls from the local LLC's DSQ first. If empty, steals from other LLCs (skipped entirely on single-CCD systems via RODATA gate).

## Key Mechanisms

- **DRR++ Deficit Tracking**: Each task starts with ~10ms of "credit" (quantum + new-flow bonus). Each execution bout consumes deficit. When exhausted, the new-flow bonus is removed and the task competes normally.

- **Starvation Prevention (`cake_tick`, 1ms)**: Uses graduated confidence — checks for runqueue contention with decreasing frequency as scheduling remains stable. If a task exceeds its per-tier starvation threshold, it forces preemption via `scx_bpf_kick_cpu`.

- **DVFS**: Per-tier CPU frequency steering — T0-T2 get 100% frequency, T3 gets 75%. On Intel hybrid CPUs, targets scale by each core's `cpuperf_cap`.

- **Reclassification (`cake_stopping` -> `reclassify_task_cold`)**: Updates the EWMA runtime, deducts deficit, and recalculates the tier with hysteresis. Uses graduated backoff — once a tier is stable for 3+ stops, reclassification drops to per-tier intervals (T0: every 1024th stop, T3: every 16th).

## Performance Design

The scheduler is engineered for minimal overhead:

- **Zero global atomics** — all state is per-CPU or per-task
- **Kfunc tunneling** — caches `scx_bpf_now()` and LLC ID in per-CPU scratch to avoid redundant kernel calls
- **MESI guards** — read-before-write pattern skips stores when values haven't changed
- **Per-LLC DSQ sharding** — eliminates cross-CCD lock contention on multi-chiplet CPUs (e.g., Ryzen 9950X)
- **Register pinning** — explicit `asm("r6")` etc. to avoid BPF stack spills

## Userspace Side

The Rust userspace (`main.rs`) handles CLI parsing, topology detection (CCD count, hybrid P/E cores), ETD latency matrix calibration, loading RODATA config into the BPF program, and an optional TUI for live stats. Four profiles are available: gaming (default, 2ms quantum), esports (1ms), legacy (4ms), and default (alias for gaming).
