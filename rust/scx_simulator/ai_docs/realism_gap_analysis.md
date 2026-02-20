# Realism Gap Analysis: Real vs Simulated Scheduler Traces

This document analyzes the 6 realism gaps identified in issue sim-6b003, based on
comparing bpftrace captures of real kernel scheduling behavior against simulator
traces for the `two_runners.json` workload (mitosis scheduler, 2 CPUs).

## Gap 1: Spurious Yield/Re-enqueue Cycle (MOST IMPORTANT)

### Symptom
The simulator runs 98 cycles of:
```
stopping(still_runnable=true) -> enqueue(yield re-enqueue) -> dsq_insert_vtime(DSQ 0)
    -> dsq_move_to_local -> running
```

This pattern NEVER happens in the real trace for CPU-bound tasks.

### Root Cause
The simulator's workload model uses `Phase::Run(duration)` to represent task work.
When a task completes its Run phase and transitions to another Run phase (e.g.,
`Run(10ms) -> Run(10ms)` in a repeating workload), the engine treats this as a
**yield** event.

In contrast, the real kernel behavior is:
1. CPU-bound tasks run until their slice is exhausted (via tick preemption)
2. On slice exhaustion, `stopping(still_runnable=true)` is called
3. The task is re-enqueued via `enqueue()`
4. On next dispatch, `select_cpu` finds an idle CPU and does **direct dispatch**
   via `scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, ...)`, skipping the enqueue callback

The key difference is that real mitosis uses **direct dispatch in select_cpu** for
waking tasks. The simulator's Phase model creates artificial "wake" points at
phase boundaries that don't correspond to real kernel wake events.

### Evidence from TraceStats
```
Task PID=1:
    Yield ratio: 49.5% (49 yields / 99 schedules)
    Direct dispatch ratio: 0.0%
```

In reality, yield ratio should be near 0% for CPU-bound tasks, and direct dispatch
should be the dominant path.

### Fix Approach
1. **Workload model improvement**: Don't treat Phase::Run -> Phase::Run transitions
   as yields. A true yield in the kernel requires an explicit `sched_yield()` syscall.
   CPU-bound tasks that just run continuously should NOT trigger the yield path.

2. **Model CPU work time vs phases separately**: The current Phase model conflates
   "how much work the task wants to do" with "how long until the next sleep/wake".
   Real CPU-bound tasks want to run forever but get preempted by ticks.

3. **Alternative**: When a task exhausts its Run phase but has another Run phase
   waiting, treat it the same as slice exhaustion (involuntary preempt) rather than
   a voluntary yield.

## Gap 2: Tick Frequency Mismatch

### Symptom
Real kernel: 1ms ticks (HZ=1000), ~10 ticks per 10ms heavy run.
Simulator: ~4ms ticks (configured), but actual intervals vary wildly.

### Evidence from TraceStats
```
CPU 0: Tick interval: 9.939ms mean (expected ~4ms for HZ=250)
CPU 1: Tick interval: 20.000ms mean (expected ~4ms for HZ=250)
```

### Root Cause
The simulator generates tick events at `TICK_INTERVAL_NS = 4_000_000` (4ms), but:
1. Ticks are per-CPU and only fire when the CPU processes events
2. When a CPU is idle, ticks still fire but may not be observable
3. The two_runners workload has CPUs alternating between busy and idle, which
   affects when ticks are processed

### Fix Approach
1. Verify tick event generation is correct regardless of CPU idle state
2. Consider making tick interval configurable to match HZ=1000 setups
3. Add tick jitter modeling to match real kernel timer variance

## Gap 3: No System Noise / Competing Tasks

### Symptom
Real trace has 85 distinct PIDs on CPUs 0-1 (V8Worker, dogpile-ticker, kworkers,
ThriftIO, etc.). System tasks occasionally preempt workload tasks, causing run
duration variance.

### Root Cause
The simulator only models the tasks explicitly defined in the scenario. There's
no background noise from:
- Kernel threads (kworkers)
- System services
- Hardware interrupts
- Timer interrupts (other than scheduler ticks)

### Fix Approach
This is a fundamental limitation. Options:
1. Add a "system noise" workload pattern that injects short-running tasks randomly
2. Add interrupt/IRQ jitter to task run durations via the NoiseConfig
3. Accept this as an intentional simplification (pure workload isolation)

## Gap 4: Missing kfunc Trace Events

### Symptom
Real mitosis calls `pick_idle_cpu` (48x), `kick_cpu` (31x), `task_cpu` (30x), and
`scx_bpf_consume` (28x). These kfuncs either aren't modeled or aren't traced.

### Evidence from TraceStats
```
Kick CPU calls: 0
```

### Root Cause
Several kfuncs are implemented but:
1. Some aren't traced (no TraceKind emitted)
2. `scx_bpf_consume` is not in the trace output
3. `pick_idle_cpu` is an internal mitosis function, not a BPF kfunc

### Fix Approach
1. Add trace events for additional kfuncs: `scx_bpf_consume`, `scx_bpf_kick_cpu`
2. Note: `pick_idle_cpu` is scheduler code, not a kfunc we can observe

## Gap 5: Per-tick Coordinator Dispatch

### Symptom
Every task_tick in the real trace triggers `select_task_rq` + `dispatch` for a
monitoring/coordinator PID. Mitosis appears to proactively re-dispatch a
coordinator task on every tick.

### Root Cause
The simulator doesn't model mitosis's internal coordinator/watcher mechanism.
This is scheduler-specific behavior that would require understanding mitosis's
internal architecture.

### Fix Approach
This may not be fixable without scheduler-specific modeling. The coordinator
appears to be a mitosis implementation detail for load balancing.

## Gap 6: Run Duration Variance

### Symptom
Real: 10.47-10.72ms variance from kernel overhead, interrupts.
Simulator: exactly 10.000ms, no variance.

### Evidence from TraceStats
```
Task PID=1:
    Run duration: 5.053ms mean, 4.999ms stddev, CV=98.9%
```

The high CV% is actually from the alternating 10ms/0ms pattern (run phase + sleep
phase), not from realistic jitter. Individual run durations are deterministic.

### Root Cause
The simulator advances time deterministically. Real systems have:
- Interrupt latency
- Cache effects
- Memory contention
- System call overhead

### Fix Approach
1. The `NoiseConfig.csw_overhead_ns` feature adds context-switch jitter
2. Could add a per-run jitter parameter (gaussian noise on run duration)
3. Consider modeling timer interrupt latency

## Summary Table

| Gap | Severity | Root Cause | Fix Feasibility |
|-----|----------|------------|-----------------|
| 1: Spurious yield | HIGH | Phase model | Medium - requires workload model changes |
| 2: Tick frequency | MEDIUM | Config/modeling | Easy - adjust TICK_INTERVAL_NS |
| 3: System noise | LOW | Fundamental | Accept limitation or add noise injection |
| 4: Missing kfuncs | MEDIUM | Missing traces | Easy - add TraceKind variants |
| 5: Coordinator | LOW | Scheduler-specific | Not feasible without scheduler internals |
| 6: Run variance | LOW | Determinism | Easy - add jitter config |

## Recommendations

1. **Priority 1**: Fix Gap 1 by changing how Phase::Run boundaries are handled
2. **Priority 2**: Improve tick frequency accuracy (Gap 2)
3. **Priority 3**: Add missing kfunc trace events (Gap 4)
4. Accept Gaps 3, 5, 6 as intentional simplifications or add optional noise

## New TraceStats Module

A new `stats.rs` module has been added to quantify these gaps automatically:
- Computes per-task run duration distributions (mean, stddev, CV%)
- Computes per-CPU tick intervals
- Tracks yield/enqueue/preemption counts
- Calculates a realism score (0-100)

Usage:
```rust
let trace = Simulator::new(scheduler).run(scenario);
let stats = TraceStats::from_trace(&trace);
stats.print_summary();
eprintln!("Realism score: {}/100", stats.realism_score());
```
