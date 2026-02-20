# LAVD Real-vs-Simulated Trace Comparison Analysis

Author: Claude (AI-generated analysis)
Date: 2026-02-19

## Overview

This document analyzes the realism gaps between the scx_simulator's execution of LAVD
and real kernel execution, based on trace analysis of the `two_runners.json` workload.

## Test Setup

- **Workload**: `two_runners.json` (heavy at nice -5, light at nice 0)
- **Scheduler**: scx_lavd
- **CPUs**: 2
- **Duration**: 100ms (simulated)

## Quantitative Trace Summary

From a 100ms simulation run:

| Event Type | Count |
|------------|-------|
| STARTED | 23 |
| PREEMPTED | 8 |
| SLEEPING | 5 |
| IDLE | 5 |
| YIELDED | 6 |
| tick | 11 |
| yield re-enqueue | 6 |
| dispatch | 21 |
| select_cpu | 8 |

## Identified Realism Gaps

### Gap 1: Spurious Yield/Re-enqueue Cycles (FIXED)

**Status**: FIXED in commit 7400bd4b (sim-70d93)

**Previous Observation**: The simulator produced 6 "yield re-enqueue" events over 100ms,
representing ~26% of all scheduling cycles (39.5% yield ratio).

**Root Cause**: When a task woke from Sleep, `advance_to_run_phase()` did not
advance past the Sleep phase. The task ran with `run_remaining_ns=0`, causing
immediate TaskPhaseComplete, which advanced to the next Run phase and triggered
the "yield re-enqueue" path.

**Fix**: In `advance_to_run_phase()`, advance past Sleep phases (the sleep has
completed when the wake event fires) and reinitialize `run_remaining_ns` for
Run phases when it's 0.

**Results after fix**:
- Yield ratio: 0.0% (was 39.5%)
- Global DSQ ratio: 1.2% (was 42.5%)
- Total trace events: ~50% fewer (no spurious yield events)

### Gap 2: Tick Frequency Mismatch

**Observation**: 11 ticks in 100ms = ~9ms tick interval (with jitter).
Simulator uses `TICK_INTERVAL_NS = 4_000_000` (4ms) but with jitter.

**Real Kernel**: HZ=1000 systems have 1ms ticks. The trace shows ~4ms base interval
which doesn't match modern kernel configurations.

**Impact**: LAVD's time-slice decisions and preemption timing are affected.
A task that should see 10 ticks in 10ms sees only ~2-3.

### Gap 3: No System Noise

**Observation**: Only 2 PIDs (1 and 2) appear in the simulation trace.

**Real System**: Traces typically show 50-100+ PIDs including:
- kworkers (maintenance tasks)
- V8Workers (JavaScript runtime)
- IO workers
- Timer callbacks
- Interrupt handlers

**Impact**: Run durations are exactly as specified (5ms slice = 5ms run).
Real systems have variance from:
- IRQ handling
- Kernel preemption for higher-priority work
- Cache contention from other tasks

### Gap 4: Direct Dispatch vs Global DSQ

**Observation**: Most scheduling goes through `SCX_DSQ_LOCAL` (direct dispatch)
from `select_cpu`. The global DSQ (id=4096) is only used after re-enqueue.

**Analysis**: This is actually REALISTIC for LAVD's design:
- Fresh wakes go through `select_cpu` -> direct local dispatch
- Only re-enqueued tasks (after preemption) go to global DSQ

The 100ms trace shows 8 `select_cpu` calls (wakes) and many more dispatches
from global DSQ, but this ratio depends on workload pattern.

### Gap 5: Missing kfunc Trace Events

**Traced kfuncs**:
- `dsq_insert` / `dsq_insert_vtime`
- `dsq_move_to_local`
- `dsq_nr_queued`
- `kick_cpu`
- `create_dsq`

**Missing from simulator trace** (but called by real LAVD):
- `pick_idle_cpu` (idle CPU selection)
- `task_cpu` (current CPU query)
- `scx_bpf_consume` (global DSQ consumption)
- `scx_bpf_now` (clock reads)

These are called but not logged at DEBUG level, making comparison difficult.

## Trace Format Comparison

### Simulator Trace (sample)
```
[     20_113_489:L1] DEBUG stopping pid=2 still_runnable=true
[     20_125_289:L1] DEBUG enqueue (yield re-enqueue) pid=2
[     20_125_289:L1] DEBUG kfunc dsq_insert pid=2 dsq_id=... slice=500K
[     20_125_289:L1] DEBUG kick_cpu cpu=1 flags=1
[     20_125_289:L1] INFO  YIELDED task=light pid=2
[     20_137_599:L1] DEBUG running pid=2
```

### Expected Real Trace (from bpftrace)
```
12345678901 cpu=1 >> select_task_rq
12345678902 cpu=1 .. dispatch pid=123 dsq=... slice=...
12345678903 cpu=1 >> enqueue_task
12345678904 cpu=1 >> set_next_task
12345678905 cpu=1 == sched_switch prev_pid=0 next_pid=123
```

### Key Differences

1. **Timestamp format**: Simulator uses formatted ns with underscore separators;
   real trace uses raw ns.

2. **Event names**: Simulator uses ops names (`stopping`, `running`);
   real trace uses sched_class names (`put_prev_task_scx`, `set_next_task_scx`).

3. **PID availability**: Simulator always has PIDs; real kprobe entries lack PIDs
   (BPF complexity limits).

4. **Lifecycle tracepoints**: Real trace has `sched_switch`/`sched_wakeup`;
   simulator uses internal `STARTED`/`SLEEPING` events.

## Recommendations for Improving Realism

### 1. Fix Phase Model Yields

Instead of treating `Phase::Run` -> `Phase::Run` as a yield, model it as:
- Continuous execution when total run time < slice
- Only preempt at slice expiration or explicit yield

This requires changes to `handle_task_phase_complete()` in engine.rs.

### 2. Add Tick Frequency Configuration

Make `TICK_INTERVAL_NS` configurable via `Scenario`:
```rust
pub tick_interval_ns: TimeNs, // Default 4_000_000, allow 1_000_000 for HZ=1000
```

### 3. Add System Noise Tasks

Create a `SystemNoise` scenario option that injects synthetic kworkers,
IO workers, and other system tasks that occasionally preempt workloads.

### 4. Enhance kfunc Tracing

Add `TraceKind` variants for:
- `PickIdleCpu { flags, result }`
- `TaskCpu { pid, cpu }`
- `BpfNow { value }`

### 5. Unified Trace Parser

Create a module that can parse both simulator traces and bpftrace output
into a common `UnifiedEvent` type for automated comparison.

## Conclusion

The simulator provides good coverage of LAVD's core scheduling logic but has
significant gaps in modeling realistic workload patterns. The spurious yield
cycles (Gap 1) are the most critical issue, as they exercise code paths that
real CPU-bound tasks never use.

For validation purposes, the current simulator is useful for:
- DSQ management correctness
- Weight/vtime calculations
- Direct dispatch paths
- Idle CPU selection logic

It is less reliable for:
- End-to-end scheduling fairness measurements
- Timing-sensitive preemption behavior
- Realistic throughput estimates
