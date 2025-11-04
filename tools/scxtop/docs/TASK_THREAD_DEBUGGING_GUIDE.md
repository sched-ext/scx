# Task/Thread Scheduling Debugging Guide

## Overview

scxtop perfetto analysis provides comprehensive task and thread-level debugging
capabilities. This guide shows how to diagnose common scheduling problems for
individual tasks and threads.

## Available Task/Thread Debugging Analyses

### 1. Task State Analysis (Where is my task spending time?)

**Question:** "Why isn't my task running?"

```javascript
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "task_states",
  pid: 1234  // Specific task
})
```

**Output shows:**
- **Running time:** Actually executing on CPU
- **Runnable time:** Waiting for CPU (scheduler latency!)
- **Sleeping time:** Voluntarily waiting (I/O, locks, etc.)
- **Blocked time:** Uninterruptible wait (disk I/O)

**Interpretation:**
- High **runnable %**: Task is CPU-starved (system overloaded)
- High **sleeping %**: Task is I/O-bound or waiting on events
- High **blocked %**: Disk I/O issues
- High **scheduler latency p99**: Long wait times when ready to run

**Example Real Result:**
```json
{
  "pid": 2952187,
  "comm": "worker_thread",
  "running_percent": 0.12,    // Only 0.12% actually running
  "runnable_percent": 82.01,  // 82% waiting for CPU! ← PROBLEM
  "sleeping_percent": 17.87,
  "avg_scheduler_latency_ns": 19795337,  // 19.8ms avg wait
  "p99_scheduler_latency_ns": 111439078  // 111ms p99 wait! ← BAD
}
```

**Diagnosis:** Task is CPU-starved, spending 82% of time waiting for CPU.

---

### 2. Process Timeline (What happened to my task?)

**Question:** "Show me the complete lifecycle of my task"

```javascript
get_process_timeline({
  trace_id: "trace",
  pid: 1234,
  start_time_ns: 0,  // Optional: focus on specific time range
  end_time_ns: 1000000000
})
```

**Output shows chronological events:**
- **Scheduled**: Task got CPU (which CPU, when)
- **Preempted**: Task lost CPU (state, when)
- **Woken**: Task woken by another task (by whom, when)
- **Migrated**: Moved between CPUs (from→to)
- **Forked**: Created child process
- **Exited**: Task terminated

**Use cases:**
- Trace execution flow of a specific task
- Find unexpected preemptions
- Identify migration patterns
- Debug task lifecycle issues

---

### 3. Preemption Analysis (Who keeps interrupting my task?)

**Question:** "Why does my task keep getting preempted?"

```javascript
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "preemptions",
  pid: 1234
})
```

**Output shows:**
- Total preemption count
- **Top preemptors:** Which tasks preempted you and how often

**Example Real Result:**
```json
{
  "pid": 2952187,
  "comm": "my_task",
  "preempted_count": 48,
  "preempted_by": [
    {"pid": 2199, "comm": "kipmi0", "count": 5},
    {"pid": 1085780, "comm": "bpfj_log_buffer", "count": 4},
    {"pid": 2952192, "comm": "other_task", "count": 3}
  ]
}
```

**Diagnosis:** Kernel threads and other tasks preempting frequently.
**Action:** Consider task priorities or CPU isolation.

---

### 4. Wakeup→Schedule Correlation (What's my wakeup latency?)

**Question:** "How long after being woken does my task actually run?"

```javascript
correlate_wakeup_to_schedule({
  trace_id: "trace",
  pid: 1234,  // Your task
  limit: 100   // Show top 100 wakeups by latency
})
```

**Output shows:**
- Each wakeup event with waker PID
- Precise wakeup→schedule latency
- Full percentiles (p50/p95/p99/p999)

**Example Result:**
```json
{
  "pid": 1234,
  "waker_pid": 5678,
  "wakeup_latency_ns": 111171276,  // 111ms!
  "cpu": 5
}
```

**With percentiles:**
```
p50: 63ms   ← Median wakeup latency
p99: 738ms  ← 99% wake within 738ms
p999: 1001ms ← Extreme outliers
```

---

### 5. Wakeup Chain Detection (What's blocking my critical path?)

**Question:** "What dependency chain is causing my latency?"

```javascript
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "wakeup_chains",
  limit: 20
})
```

**Output shows:**
- Wakeup chains: Task A wakes B, B wakes C, C wakes D...
- Total cumulative latency
- Critical paths ranked by severity

**Example Chain:**
```
Producer(PID 100) wakes
→ Processor(PID 200, 5ms latency) wakes
→ Aggregator(PID 300, 50ms latency) wakes
→ Consumer(PID 400, 20ms latency)

Total chain latency: 75ms
```

**Diagnosis:** Identifies bottleneck tasks in multi-threaded pipelines.

---

### 6. Scheduling Latency Breakdown (Where exactly is the latency?)

**Question:** "Is my latency from wakeup path or runqueue wait?"

```javascript
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "latency_breakdown"
})
```

**Output shows two stages:**
- **Waking→Wakeup:** Kernel wakeup path (typically microseconds)
- **Wakeup→Schedule:** Runqueue wait (can be milliseconds)

**Example Result:**
```json
{
  "waking_to_wakeup": {
    "avg_ns": 5477,        // 5.5µs - wakeup path fast!
    "percent_of_total": 0.01
  },
  "wakeup_to_schedule": {
    "avg_ns": 83501227,    // 83.5ms - runqueue slow!
    "p99_ns": 940913662,   // 940ms p99
    "percent_of_total": 99.99
  }
}
```

**Diagnosis:** 99.99% of latency is runqueue wait, NOT wakeup path.
**Action:** System is overloaded, need more CPUs or reduce load.

---

### 7. Migration Analysis (Is my task bouncing around?)

**Question:** "How often does my task migrate between CPUs?"

```javascript
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "migration_patterns"
})
```

**Output shows:**
- Total migrations
- Per-process migration counts
- Cross-NUMA/LLC migrations

**Plus use Process Timeline:**
```javascript
get_process_timeline({ trace_id: "trace", pid: 1234 })
```

Look for **Migrated** events showing from_cpu → to_cpu.

---

### 8. CPU Timeline (What's happening on my task's CPU?)

**Question:** "What else is running on the CPU where my task runs?"

```javascript
get_cpu_timeline({
  trace_id: "trace",
  cpu: 0,  // CPU where your task runs
  start_time_ns: task_start,
  end_time_ns: task_end
})
```

**Output shows:**
- All context switches on that CPU
- Which tasks are competing
- Softirq processing interrupting your task

---

## Debugging Workflows

### Workflow 1: "My Task is Slow"

```javascript
// Step 1: Check what state the task is in
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "task_states",
  pid: YOUR_PID
})

// If runnable_percent is high (>50%):
// → Task is waiting for CPU

// Step 2: Check scheduler latency breakdown
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "latency_breakdown"
})

// If wakeup_to_schedule is 99%+:
// → Runqueue contention (system overloaded)

// Step 3: Find who's competing
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "preemptions",
  pid: YOUR_PID
})

// Shows which tasks are preempting you

// Step 4: Check CPU utilization
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "cpu_utilization"
})

// Shows if system is overloaded (>95% util)
```

### Workflow 2: "My Multi-Threaded App Has Latency"

```javascript
// Step 1: Find dependency chains
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "wakeup_chains",
  limit: 20
})

// Identifies producer→consumer chains
// Shows cumulative latency through pipeline

// Step 2: Check individual thread states
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "task_states",
  limit: 50  // Get all your threads
})

// Filter results to your PIDs
// Shows which threads are bottlenecks

// Step 3: Get timeline for bottleneck thread
get_process_timeline({
  trace_id: "trace",
  pid: BOTTLENECK_PID
})

// Shows exactly what happened to that thread
```

### Workflow 3: "My Task Has Latency Spikes"

```javascript
// Step 1: Check wakeup→schedule correlation
correlate_wakeup_to_schedule({
  trace_id: "trace",
  pid: YOUR_PID,
  limit: 100  // Top 100 worst wakeups
})

// Shows highest latency wakeup events
// p999 percentile shows extreme outliers

// Step 2: Get timeline during spike
get_process_timeline({
  trace_id: "trace",
  pid: YOUR_PID,
  start_time_ns: SPIKE_START,
  end_time_ns: SPIKE_END
})

// Step 3: Check CPU timeline during spike
get_cpu_timeline({
  trace_id: "trace",
  cpu: YOUR_CPU,
  start_time_ns: SPIKE_START,
  end_time_ns: SPIKE_END
})

// Shows what else was running during spike
```

### Workflow 4: "Find All Bottlenecks Automatically"

```javascript
// Quick overview
find_scheduling_bottlenecks({
  trace_id: "trace",
  limit: 10
})

// Detects:
// - High context switch rates (thrashing)
// - Long wakeup latencies (overload)
// - Excessive migrations (poor affinity)
```

---

## Thread-Specific Debugging

### Get All Threads in a Process

The `task_states` and `preemptions` analyses work at the **thread level** (PID
level), not process level. Each thread gets its own PID in Linux.

**To analyze all threads in a multi-threaded application:**

1. **Find all threads** - Look at process tree in trace
2. **Analyze each thread individually:**

```javascript
// Thread 1
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "task_states",
  pid: 1001  // Thread 1 PID
})

// Thread 2
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "task_states",
  pid: 1002  // Thread 2 PID
})
```

3. **Or analyze all threads** (set limit high):

```javascript
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "task_states",
  limit: 1000  // Get all threads
})

// Then filter to your TGID (thread group) in results
```

---

## Thread Interaction Patterns

### Producer-Consumer Pattern

```javascript
// Find wakeup relationships
correlate_wakeup_to_schedule({
  trace_id: "trace",
  limit: 1000
})

// Look for patterns like:
// Producer (PID 100) always wakes Consumer (PID 200)
```

### Thread Synchronization

```javascript
// Check wakeup chains between threads
analyze_trace_scheduling({
  trace_id: "trace",
  analysis_type: "wakeup_chains"
})

// Chains like: Thread1 → Thread2 → Thread3
// Indicate lock/condvar/semaphore dependencies
```

---

## CPU Affinity Debugging

### Which CPUs does my task run on?

```javascript
get_process_timeline({
  trace_id: "trace",
  pid: YOUR_PID
})
```

Count **Scheduled** and **Migrated** events:
- Events show which CPUs task ran on
- **Migrated** events show CPU changes
- High migration count = poor affinity

**Example:**
```json
{
  "events": [
    {"Scheduled": {"cpu": 0, "timestamp": ...}},
    {"Migrated": {"from_cpu": 0, "to_cpu": 5, "timestamp": ...}},
    {"Scheduled": {"cpu": 5, "timestamp": ...}},
    {"Migrated": {"from_cpu": 5, "to_cpu": 12, "timestamp": ...}}
  ]
}
```

Count unique CPUs used → **High count = poor affinity**

---

## Real-World Debugging Examples

### Example 1: Latency-Sensitive Task

**Problem:** Task has p99 latency of 200ms

**Debugging:**
```javascript
// 1. Check task state
analyze_trace_scheduling({analysis_type: "task_states", pid: 1234})
```

**Result:**
```json
{
  "runnable_percent": 85,
  "p99_scheduler_latency_ns": 180000000  // 180ms
}
```

**Diagnosis:** Task spends 85% time waiting for CPU. Scheduler latency p99 is 180ms.

**Root Cause:** System overload

**Actions:**
- Reduce system load
- Increase task priority
- Pin task to dedicated CPUs
- Add more CPU cores

---

### Example 2: Multi-Threaded Application Slow

**Problem:** 10-thread application has poor throughput

**Debugging:**
```javascript
// 1. Check all threads
analyze_trace_scheduling({analysis_type: "task_states", limit: 100})
// Filter to your 10 thread PIDs

// 2. Check wakeup chains
analyze_trace_scheduling({analysis_type: "wakeup_chains", limit: 20})
```

**Result:**
```json
{
  "chain": [
    {"wakee_pid": 1001, "waker_pid": 1000, "latency": 50000000},
    {"wakee_pid": 1002, "waker_pid": 1001, "latency": 60000000},
    {"wakee_pid": 1003, "waker_pid": 1002, "latency": 55000000}
  ],
  "total_latency_ns": 165000000  // 165ms for 3-hop chain
}
```

**Diagnosis:** Serial dependency chain causing cumulative 165ms latency.

**Actions:**
- Reduce dependencies (parallelize)
- Batch work to reduce wakeup frequency
- Check lock contention

---

### Example 3: Unexpected Thread Behavior

**Problem:** Thread sometimes runs fast, sometimes slow

**Debugging:**
```javascript
// 1. Get complete timeline
get_process_timeline({trace_id: "trace", pid: 1234})

// 2. Check preemptions
analyze_trace_scheduling({analysis_type: "preemptions", pid: 1234})

// 3. Check wakeup latency distribution
correlate_wakeup_to_schedule({trace_id: "trace", pid: 1234})
```

**Look for:**
- Migration events during slow periods (CPU changes)
- Different preemptors during slow periods
- High p99 vs p50 (bimodal distribution)

---

## Thread-Level Metrics Summary

| Metric | Analysis Type | What It Shows |
|--------|---------------|---------------|
| Time in each state | `task_states` | RUNNING/RUNNABLE/SLEEPING/BLOCKED |
| Scheduler latency | `task_states` | Time waiting when ready to run |
| Voluntary switches | `task_states` | Task voluntarily yielded |
| Involuntary switches | `task_states` | Task was preempted |
| Preemption sources | `preemptions` | Which tasks preempt you |
| Wakeup latency | `correlate_wakeup_to_schedule` | Wakeup→schedule time |
| Dependency chains | `wakeup_chains` | Multi-hop wakeup paths |
| Latency attribution | `latency_breakdown` | Wakeup path vs runqueue |
| CPU migrations | Timeline + `migration_patterns` | CPU affinity behavior |
| Complete lifecycle | `get_process_timeline` | All events chronologically |

---

## Common Patterns and Diagnoses

### Pattern 1: High runnable_percent (>50%)
**Symptom:** Task spending most time in RUNNABLE state
**Root Cause:** CPU starvation (system overloaded)
**Verification:** Check `p99_scheduler_latency_ns` (>10ms is high)
**Action:** Reduce load, add CPUs, or increase task priority

### Pattern 2: High sleeping_percent (>80%)
**Symptom:** Task spending most time SLEEPING
**Root Cause:** I/O-bound or event-driven (normal for many apps)
**Verification:** Check if voluntary or involuntary
**Action:** If unexpected, check what task is waiting for

### Pattern 3: Many involuntary switches
**Symptom:** Task preempted frequently (>100 times)
**Root Cause:** Low priority or CPU contention
**Verification:** Check `preempted_by` to see preemptors
**Action:** Increase priority or isolate task

### Pattern 4: Long wakeup chains (>5 hops)
**Symptom:** Task at end of long dependency chain
**Root Cause:** Serial pipeline architecture
**Verification:** Check cumulative latency
**Action:** Parallelize or batch work

### Pattern 5: Bimodal latency (low p50, high p99)
**Symptom:** Usually fast, occasionally very slow
**Root Cause:** Occasional contention or preemption
**Verification:** Use timeline to find slow periods
**Action:** Identify interfering tasks from timeline

### Pattern 6: High migration count
**Symptom:** Task moving between CPUs frequently
**Root Cause:** Poor CPU affinity or aggressive load balancing
**Verification:** Count migrations in timeline
**Action:** Pin to CPU or numa node

---

## Thread-Specific vs Process-Specific

**Important:** In Linux, threads are tasks with their own PIDs (TIDs).

**All analyses work at the thread level:**
- `task_states` - per-thread states
- `preemptions` - per-thread preemptions
- `timeline` - per-thread events
- `wakeup correlation` - per-thread wakeups

**To analyze a multi-threaded process:**
1. Get all thread PIDs (TIDs) in the thread group (TGID)
2. Run analysis for each thread PID
3. Aggregate results as needed

**Example:**
```javascript
// Process with threads: 1000 (main), 1001, 1002, 1003

// Analyze each thread
analyze_trace_scheduling({analysis_type: "task_states", pid: 1000})
analyze_trace_scheduling({analysis_type: "task_states", pid: 1001})
analyze_trace_scheduling({analysis_type: "task_states", pid: 1002})
analyze_trace_scheduling({analysis_type: "task_states", pid: 1003})

// Or get all and filter
analyze_trace_scheduling({analysis_type: "task_states", limit: 1000})
// Filter JSON results to your thread PIDs
```

---

## Advanced Thread Debugging

### Find Thread Interaction Patterns

1. **Get all threads in process:**
```javascript
analyze_trace_scheduling({analysis_type: "task_states", limit: 1000})
// Identify your thread PIDs
```

2. **Check wakeup relationships:**
```javascript
correlate_wakeup_to_schedule({trace_id: "trace", limit: 10000})
// Filter to your thread PIDs
// Find who wakes whom
```

3. **Visualize communication:**
- Thread A wakes Thread B frequently → likely producer-consumer
- Thread A and B wake each other → mutex/lock pattern
- No wakeup relationship → independent threads

### Find Bottleneck Thread

1. **Run task state analysis on all threads**
2. **Look for:**
   - Thread with highest `runnable_percent` → CPU-starved
   - Thread with most `voluntary_switches` → I/O-bound
   - Thread with most `involuntary_switches` → Being preempted
3. **Check wakeup chains** - is this thread in critical path?

---

## Tips

1. **Always start with `task_states`** - tells you WHERE time is spent
2. **Use `latency_breakdown`** - tells you WHY latency occurs
3. **Use `preemptions`** - identifies interfering tasks
4. **Use `wakeup_chains`** - finds dependency bottlenecks
5. **Use `timeline`** - gets complete picture for specific task
6. **Export everything** - then analyze offline with jq/python

---

## Example: Complete Thread Debugging Session

```javascript
// 1. Load trace
load_perfetto_trace({file_path: "/path/to/trace.proto"})

// 2. Find bottlenecks automatically
find_scheduling_bottlenecks({trace_id: "trace", limit: 5})
// Returns: "High wakeup latency: p99=909ms"

// 3. Check latency source
analyze_trace_scheduling({analysis_type: "latency_breakdown"})
// Returns: 99.99% is runqueue wait → System overloaded

// 4. Find which tasks are affected
analyze_trace_scheduling({analysis_type: "task_states", limit: 50})
// Shows all tasks with high runnable_percent

// 5. Deep dive on worst task
get_process_timeline({trace_id: "trace", pid: WORST_PID})
// Shows complete lifecycle

// 6. Check who's preempting
analyze_trace_scheduling({analysis_type: "preemptions", pid: WORST_PID})
// Shows competing tasks

// 7. Export everything for further analysis
export_trace_analysis({
  trace_id: "trace",
  output_path: "/tmp/debug.json",
  analysis_types: ["task_states", "preemptions", "wakeup_chains", "latency_breakdown"]
})
```

**Result:** Complete understanding of:
- Which tasks are slow
- Why they're slow (CPU starvation, I/O wait, etc.)
- Who's causing the problem (preemptors)
- Where the latency comes from (runqueue vs wakeup path)
- What the critical paths are (dependency chains)

---

## Summary

scxtop has extensive task/thread scheduling debugging:

✅ **Task state tracking** - Where time is spent
✅ **Scheduler latency** - How long tasks wait for CPU
✅ **Preemption analysis** - Who interrupts whom
✅ **Wakeup correlation** - Wakeup→schedule latency per task
✅ **Wakeup chains** - Dependency bottlenecks
✅ **Latency breakdown** - Wakeup path vs runqueue wait
✅ **Process timeline** - Complete task lifecycle
✅ **CPU timeline** - What's competing on same CPU
✅ **Migration tracking** - CPU affinity behavior

All with **full percentile statistics** (p50/p95/p99/p999) for latency metrics!

**For thread-level debugging:** All analyses work on Linux TIDs (thread PIDs), just specify the thread PID instead of process PID.
