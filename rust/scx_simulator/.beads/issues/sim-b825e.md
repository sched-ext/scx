---
title: 'Error detection: stalls, scx_bpf_error, and dispatch loop exhaustion'
status: open
priority: 1
issue_type: task
created_at: 2026-02-19T09:44:12.205695596+00:00
updated_at: 2026-02-19T09:44:12.205695596+00:00
---

## Problem Statement

The simulator currently has no mechanism for detecting scheduler errors. This
makes testing toothless: a scheduler can have corrupt state, starve tasks, or
call `scx_bpf_error()`, but the simulation completes "successfully" and no test
fails.

The three categories of errors to detect:

1. **Stalls** (most common in production): A runnable task is never scheduled for
   an extended period. In the real kernel, if a task goes unscheduled for ~30s,
   the watchdog kills the scheduler with `SCX_EXIT_ERROR_STALL`.

2. **Explicit scheduler errors**: The BPF scheduler calls `scx_bpf_error()`. In
   the real kernel this immediately triggers scheduler shutdown with
   `SCX_EXIT_ERROR_BPF`. Currently the simulator just prints to stderr and
   continues (`kfuncs.rs:845-853`).

3. **Runtime violations**: Invalid CPU from `select_cpu()`, dispatch loop
   exhaustion, DSQ errors, etc. Some of these already panic, but they should be
   reported via a proper error type rather than crashing the process.

## Current State

| Aspect | Status |
|--------|--------|
| `scx_bpf_error()` | Prints to stderr, simulation continues (WRONG) |
| Task stall detection | None |
| Dispatch loop limits | None |
| `run()` return type | `Trace` (infallible, panics on error) |
| Error types | No simulation error type exists |

## Kernel Background

The kernel uses a two-layer watchdog:

1. **Periodic check (`scx_watchdog_workfn`)**: Runs every `timeout/2` jiffies,
   iterates every online CPU's `runnable_list`, compares each task's
   `p->scx.runnable_at` against `jiffies`. If exceeded, exits with
   `SCX_EXIT_ERROR_STALL`. (See `kernel/sched/ext.c:2660-2705`.)

2. **Tick liveness (`scx_tick`)**: Called from scheduler tick, checks whether the
   watchdog workfn itself has stalled. (See `kernel/sched/ext.c:2707-2730`.)

Key detail: `runnable_at` is only reset when a task actually runs
(`set_next_task_scx` → `clr_task_runnable(p, true)`). If a task is dequeued and
re-enqueued without running, the original timestamp is preserved, so the watchdog
correctly measures the full stall duration.

Default timeout: `SCX_WATCHDOG_MAX_TIMEOUT = 30 * HZ` (30 seconds). Schedulers
can set a shorter timeout via `ops.timeout_ms`.

Other kernel error conditions:
- Dispatch loop limit: `SCX_DSP_MAX_LOOPS` (32 iterations)
- `scx_bpf_error()` → `SCX_EXIT_ERROR_BPF`
- Various `scx_error()` calls for invalid ops returns, bad CPU IDs, etc.
- Lockup detector hooks (RCU stall, soft/hard lockup)

## Design

### 1. Add `ExitKind` enum

**File:** `src/engine.rs`

```rust
/// How the simulation terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitKind {
    /// Simulation ran to completion (duration exhausted).
    Normal,
    /// BPF scheduler called scx_bpf_error().
    ErrorBpf(String),
    /// Watchdog detected a stalled runnable task.
    ErrorStall {
        pid: Pid,
        runnable_for_ns: TimeNs,
    },
    /// Dispatch loop exceeded iteration limit without making progress.
    ErrorDispatchLoopExhausted { cpu: CpuId },
}
```

### 2. Add `exit_kind` to `Trace` and `SimulationResult`

Add an `exit_kind: ExitKind` field to `Trace`. The `run()` method continues
returning `Trace` (not `Result`) to keep the simple API, but the `Trace` now
carries its `ExitKind`. Tests that care can check it; tests that don't still work
unchanged.

Add convenience methods: `Trace::has_error() -> bool`,
`Trace::exit_kind() -> &ExitKind`.

### 3. Handle `scx_bpf_error()` properly

**File:** `src/kfuncs.rs`

`scx_bpf_error_bstr` currently prints to stderr and returns. Change it to set a
flag in `SimulatorState` (via `with_sim()`):

```rust
pub extern "C" fn scx_bpf_error_bstr(...) {
    with_sim(|state| {
        if state.bpf_error.is_none() {
            state.bpf_error = Some(msg);
        }
    });
}
```

In the engine's main event loop, after each ops callback returns, check
`state.bpf_error`. If set, stop the simulation and set
`exit_kind = ExitKind::ErrorBpf(msg)`.

### 4. Implement stall detection (watchdog)

**File:** `src/engine.rs`

The kernel's approach: track `runnable_at` per task, check periodically.

- Add `runnable_at_ns: Option<TimeNs>` to `SimTask`. Set it when the task
  becomes `Runnable` (enqueue path). Clear it (set to `None`) when the task
  starts `Running` or goes to `Sleeping`.

- On every `Tick` event (already fires every 4ms simulated), check all tasks:
  if any task has `runnable_at_ns` set and `clock - runnable_at_ns >
  watchdog_timeout`, trigger `ExitKind::ErrorStall`.

**Configurable timeout**: `Scenario::watchdog_timeout_ns: Option<TimeNs>`:
  - `Some(ns)` — watchdog fires after `ns` simulated nanoseconds of stall.
  - `None` — watchdog disabled.
  - Default: `Some(30_000_000_000)` (30s, matching kernel default).

For controlled test scenarios, tests can set a much shorter timeout (e.g. 100ms)
to detect stalls without needing to simulate 30s of wall time.

Key detail (matching kernel): `runnable_at_ns` is only reset when the task
actually runs (transition to `Running`), NOT when it's dequeued and re-enqueued.

### 5. Dispatch loop limit

**File:** `src/engine.rs`

The kernel limits `ops.dispatch()` invocations to `SCX_DSP_MAX_LOOPS` (32) in a
single balance cycle. Add a similar counter in the dispatch path. If exceeded,
record `ExitKind::ErrorDispatchLoopExhausted` or log a warning trace event.

(Note: the kernel doesn't hard-error on this — it kicks and retries. We may want
to just emit a trace event rather than terminating, depending on how strict we
want to be. Start with termination to catch bugs aggressively.)

### 6. Update tests

**File:** `tests/common/mod.rs` + individual test files

- Add a standard assertion `assert_eq!(trace.exit_kind(), &ExitKind::Normal)` in
  the shared validation functions, so all existing tests automatically fail if
  the scheduler errors out.
- Add dedicated tests that intentionally trigger each error condition and verify
  the correct `ExitKind`.

## Files to Modify

| File | Changes |
|------|---------|
| `src/engine.rs` | `ExitKind` enum, stall watchdog in tick handler, `bpf_error` check in event loop, dispatch loop limit |
| `src/kfuncs.rs` | `scx_bpf_error_bstr` → set flag in state instead of just printing |
| `src/task.rs` | Add `runnable_at_ns: Option<TimeNs>` to `SimTask` |
| `src/trace.rs` | Add `exit_kind: ExitKind` to `Trace`, add `has_error()` method |
| `src/scenario.rs` | Add `watchdog_timeout_ns: Option<TimeNs>` to `Scenario` |
| `src/lib.rs` | Export `ExitKind` |
| `tests/common/mod.rs` | Add `exit_kind == Normal` assertion to shared validation |
| `tests/errors.rs` (new) | Tests for each error condition |

## Verification

1. `./validate.sh` passes (all existing tests still pass with the new assertion)
2. New tests in `tests/errors.rs`:
   - Test that `scx_bpf_error()` produces `ErrorBpf`
   - Test that a scheduler which never dispatches a task produces `ErrorStall`
     after the (short, configurable) watchdog timeout
3. No change in behavior for well-behaved schedulers
