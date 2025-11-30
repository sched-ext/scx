# Perfetto Trace Analysis in scxtop MCP

## Overview

The scxtop MCP server provides comprehensive analysis of perfetto trace files,
enabling detailed investigation of scheduler behavior, performance bottlenecks,
and task interactions. Traces contain scheduling events like context switches,
wakeups, migrations, and sched_ext dispatch queue metrics.

## Quick Start

### 1. Generate a Trace

```bash
# Capture 5 seconds of scheduling activity with system stats
sudo scxtop trace -d 5000 -o my_trace.proto -s

# The trace file will be saved as my_trace.proto (binary protobuf format)
```

### 2. Start MCP Server

```bash
# Daemon mode is required for trace loading and analysis
sudo scxtop mcp --daemon
```

### 3. Analyze via MCP Client

Connect your MCP client (like Claude Desktop) to the scxtop MCP server and use the available tools:

```javascript
// Load the trace
load_perfetto_trace({ file_path: "/path/to/my_trace.proto" })

// Analyze CPU utilization
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "cpu_utilization",
  use_parallel: true
})

// Find bottlenecks
find_scheduling_bottlenecks({ trace_id: "my_trace", limit: 10 })
```

## Available Analysis Types

### Core Analyses

### 1. CPU Utilization

Analyzes per-CPU utilization including active/idle time and context switch statistics.

**Returns:**
- Utilization percentage per CPU
- Total context switches
- Timeslice percentiles (min, avg, p50, p95, p99, max)

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "cpu_utilization",
  use_parallel: true  // Use multi-threading for faster analysis
})
```

**Output includes:**
```json
{
  "cpu_id": 0,
  "active_time_ns": 1200000000,
  "idle_time_ns": 50000000,
  "utilization_percent": 96.0,
  "total_switches": 1045,
  "min_timeslice_ns": 3285,
  "avg_timeslice_ns": 1234567,
  "p50_timeslice_ns": 18958,
  "p95_timeslice_ns": 12128758,
  "p99_timeslice_ns": 13497222,
  "max_timeslice_ns": 20551374
}
```

### 2. Process Runtime

Analyzes total runtime, CPU time percentage, and timeslice distributions for all processes.

**Returns:**
- Total runtime per process
- CPU time percentage
- Number of context switches
- Timeslice percentiles

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "process_runtime",
  use_parallel: true,
  limit: 20,  // Return top 20 processes
  pid: 1234   // Optional: analyze specific PID only
})
```

**Output includes:**
```json
{
  "pid": 2199,
  "comm": "kipmi0",
  "total_runtime_ns": 12090065364,
  "cpu_time_percent": 967.24,
  "num_switches": 890,
  "min_timeslice_ns": 4136,
  "p50_timeslice_ns": 12719,
  "p95_timeslice_ns": 61584507,
  "p99_timeslice_ns": 481636252
}
```

### 3. Wakeup Latency

Analyzes latency between wakeup and actual scheduling for all tasks.

**Returns:**
- Overall wakeup latency percentiles (min, avg, p50, p95, p99, p999, max)
- Per-CPU breakdown
- Total wakeup count

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "wakeup_latency"
})
```

**Output includes:**
```json
{
  "total_wakeups": 53704,
  "min_latency_ns": 0,
  "avg_latency_ns": 71740403,
  "p50_latency_ns": 4117,
  "p95_latency_ns": 494678908,
  "p99_latency_ns": 909215934,
  "p999_latency_ns": 1099815864,
  "max_latency_ns": 1226374903,
  "per_cpu_stats": {
    "0": {
      "cpu_id": 0,
      "count": 168,
      "avg_latency_ns": 78362977,
      "p99_latency_ns": 896776207
    }
  }
}
```

### 4. Migration Patterns

Detects process migration across CPUs, including cross-NUMA and cross-LLC migrations.

**Returns:**
- Total migrations
- Per-process migration counts
- Cross-NUMA and cross-LLC migration counts
- Migration latency percentiles

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "migration_patterns"
})
```

### 5. DSQ Summary (sched_ext only)

For traces captured with sched_ext schedulers, analyzes dispatch queue usage.

**Returns:**
- Scheduler name
- All DSQ IDs in the trace
- Per-DSQ descriptors with time ranges

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "dsq_summary"
})
```

**Output includes:**
```json
{
  "scheduler_name": "scx_rusty",
  "total_dsqs": 200,
  "dsq_ids": [0, 64, 65, 66, ...]
}
```

### Extended Scheduler Analyses

### 6. Task State Analysis

Analyzes time spent in different task states (RUNNING, RUNNABLE, SLEEPING, BLOCKED) and scheduler latency.

**Returns:**
- Time in each state with percentages
- Voluntary vs involuntary context switches
- Scheduler latency (time waiting when runnable) with percentiles

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "task_states",
  limit: 20,
  pid: 1234  // Optional
})
```

**Output includes:**
```json
{
  "pid": 2952187,
  "comm": "schbench",
  "running_time_ns": 249632722,
  "runnable_time_ns": 167319071303,
  "sleeping_time_ns": 36450899711,
  "blocked_time_ns": 0,
  "running_percent": 0.12,
  "runnable_percent": 82.01,
  "sleeping_percent": 17.87,
  "blocked_percent": 0.0,
  "voluntary_switches": 5816,
  "involuntary_switches": 24,
  "avg_scheduler_latency_ns": 19795337,
  "p50_scheduler_latency_ns": 11980805,
  "p95_scheduler_latency_ns": 70463572,
  "p99_scheduler_latency_ns": 111439078
}
```

**Key Insight:** High `runnable_percent` indicates tasks waiting for CPU (scheduler latency).

### 7. Preemption Analysis

Identifies which tasks are being preempted and by whom.

**Returns:**
- Preemption count per process
- Top preemptors (who preempted this task)

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "preemptions",
  limit: 20
})
```

**Output includes:**
```json
{
  "pid": 2952187,
  "comm": "schbench",
  "preempted_count": 48,
  "preempted_by": [
    {"pid": 2199, "comm": "kipmi0", "count": 5},
    {"pid": 1085780, "comm": "bpfj_log_buffer", "count": 4}
  ]
}
```

### 8. Wakeup Chain Detection

Identifies cascading wakeup chains (A wakes B, B wakes C...) to find critical paths.

**Returns:**
- Wakeup chains with criticality scores
- Chain length and total latency
- Individual wakeup events in chain

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "wakeup_chains",
  limit: 10
})
```

**Output includes:**
```json
{
  "chain_length": 11,
  "total_latency_ns": 13691850000,
  "criticality_score": 150610.37,
  "chain": [
    {"wakee_pid": 2952306, "waker_pid": 2952305, "wakeup_ts": ..., "schedule_ts": ...}
  ]
}
```

### 9. Scheduling Latency Breakdown

Breaks down wakeup latency into stages: waking→wakeup (wakeup path) and wakeup→schedule (runqueue wait).

**Returns:**
- Waking→wakeup latency percentiles
- Wakeup→schedule latency percentiles
- Percentage attribution

**Example:**
```javascript
analyze_trace_scheduling({
  trace_id: "my_trace",
  analysis_type: "latency_breakdown"
})
```

**Output includes:**
```json
{
  "waking_to_wakeup": {
    "count": 106794,
    "avg_ns": 5477,
    "p50_ns": 4146,
    "p95_ns": 11077,
    "p99_ns": 42764,
    "percent_of_total": 0.01
  },
  "wakeup_to_schedule": {
    "count": 46140,
    "avg_ns": 83501227,
    "p50_ns": 7852,
    "p95_ns": 537974054,
    "p99_ns": 940913662,
    "percent_of_total": 99.99
  }
}
```

**Key Insight:** High `wakeup_to_schedule` percentage indicates runqueue contention, not wakeup path issues.

## Advanced Features

### Process Timeline

Get chronological timeline of all events for a specific process.

```javascript
get_process_timeline({
  trace_id: "my_trace",
  pid: 1234,
  start_time_ns: 0,      // Optional
  end_time_ns: 1000000000 // Optional
})
```

**Returns:**
- Scheduled events (when task runs)
- Preempted events (when task is descheduled)
- Woken events (when task is woken by another task)
- Migrated events (when task moves between CPUs)
- Forked/Exited events

### CPU Timeline

Get chronological timeline of all events for a specific CPU.

```javascript
get_cpu_timeline({
  trace_id: "my_trace",
  cpu: 0,
  start_time_ns: 0,
  end_time_ns: 1000000000
})
```

**Returns:**
- All context switches with prev/next PIDs and comm names
- Softirq entry/exit events

### Wakeup→Schedule Correlation

Find precise wakeup-to-schedule latencies showing which tasks woke which other tasks.

```javascript
correlate_wakeup_to_schedule({
  trace_id: "my_trace",
  pid: 1234,  // Optional: filter to specific process
  limit: 100   // Return top 100 by latency
})
```

**Returns:**
- Waker PID and wakee PID
- Wakeup timestamp and schedule timestamp
- Precise wakeup latency
- CPU where scheduling occurred
- Full percentile statistics (min/p50/p95/p99/p999/max)

**Output shows:**
```json
{
  "pid": 2952187,
  "waker_pid": 2952260,
  "wakeup_timestamp": 174607123456789,
  "schedule_timestamp": 174607234567890,
  "wakeup_latency_ns": 111111101,
  "cpu": 5
}
```

### Bottleneck Detection

Automatically identifies scheduling bottlenecks in the trace.

```javascript
find_scheduling_bottlenecks({
  trace_id: "my_trace",
  limit: 10
})
```

**Detects:**
1. **High context switch rates** (>1000 Hz per CPU)
2. **Long wakeup latencies** (p99 > 100ms)
3. **Excessive migrations** (>100 migrations/sec)

**Returns:** Bottlenecks sorted by severity with descriptions and affected time ranges.

**Example output:**
```json
{
  "description": "High migration rate: 30547 migrations/sec",
  "severity": 10.0,
  "bottleneck_type": "ExcessiveMigration",
  "time_range": [174606978728139, 174608228685859]
}
```

### Export Comprehensive Analysis

Export all analyses to a JSON file for offline processing or archival.

```javascript
export_trace_analysis({
  trace_id: "my_trace",
  output_path: "/tmp/analysis_output.json",
  analysis_types: ["cpu_utilization", "process_runtime", "wakeup_latency", "bottlenecks"]
})
```

**Exports:**
- CPU utilization for all CPUs
- Top 20 processes by runtime
- Wakeup latency distribution
- Migration patterns
- DSQ summary (if sched_ext trace)
- Top bottlenecks

## Query Tools

### Load Trace

```javascript
load_perfetto_trace({
  file_path: "/absolute/path/to/trace.proto",
  trace_id: "my_trace"  // Optional, defaults to filename
})
```

### Query Events

Query specific events with filtering:

```javascript
query_trace_events({
  trace_id: "my_trace",
  event_type: "sched_switch",  // or "sched_wakeup", "sched_migrate", "softirq", "all"
  start_time_ns: 174606978728139,  // Optional
  end_time_ns: 174608228685859,    // Optional
  cpu: 0,      // Optional: filter by CPU
  limit: 1000  // Max events to return
})
```

## MCP Resources

Access trace information via resources:

- `topology://info` - Hardware topology (CPUs, cores, LLCs, NUMA nodes)
- `scheduler://current` - Currently active scheduler

## Performance

Typical analysis performance on 40MB trace with 722K events:

| Analysis Type | Time (Single) | Time (Parallel) | Speedup |
|---------------|---------------|-----------------|---------|
| Trace Loading | 30s | 30s | N/A |
| CPU Utilization (176 CPUs) | ~20ms | ~12ms | 1.7x |
| Process Runtime (2294 processes) | ~58ms | ~30ms | 1.9x |
| Wakeup Latency (53K wakeups) | 150ms | 150ms | N/A |
| Migration Analysis (38K migrations) | 39ms | 39ms | N/A |
| Bottleneck Detection | 265ms | 265ms | N/A |
| Wakeup→Schedule Correlation (111K) | 2.3s | 2.3s | N/A |

**Total comprehensive analysis:** ~500ms (excluding trace loading)

## Understanding Percentiles

All latency and timeslice measurements include full percentile breakdowns:

- **min**: Minimum observed value
- **avg**: Arithmetic mean
- **p50 (median)**: 50% of values are below this
- **p95**: 95% of values are below this (captures most "normal" behavior)
- **p99**: 99% of values are below this (identifies outliers)
- **p999**: 99.9% of values are below this (captures extreme outliers)
- **max**: Maximum observed value

High p95/p99/p999 values compared to median indicate latency spikes or bottlenecks.

## Interpreting Results

### High CPU Utilization (>95%)
- System is heavily loaded
- May indicate CPU-bound workload
- Check process runtime to identify top consumers

### Long Wakeup Latencies (p99 > 10ms)
- Tasks waiting too long after being woken
- May indicate scheduler inefficiency or overloaded system
- Use correlation analysis to identify which tasks are affected

### Excessive Migrations (>100/sec system-wide)
- Tasks bouncing between CPUs frequently
- Can hurt cache performance
- Check if load balancing is too aggressive

### High Context Switch Rate (>1000 Hz per CPU)
- CPU is thrashing between tasks
- May indicate too many runnable tasks
- Could be voluntary yields or preemption

## Tips and Best Practices

1. **Use parallel analysis** (`use_parallel: true`) for large traces
2. **Filter by PID** when investigating specific process behavior
3. **Check DSQ summary first** for sched_ext traces to understand queue structure
4. **Export comprehensive analysis** for offline investigation or comparison
5. **Use timeline queries** to understand task lifecycle and CPU activity patterns
6. **Run bottleneck detection** first to quickly identify issues

## Example Workflow

```javascript
// 1. Load trace
const result = load_perfetto_trace({
  file_path: "/home/user/traces/workload.proto"
})
// Returns: trace_id = "workload"

// 2. Check if it's a sched_ext trace
analyze_trace_scheduling({
  trace_id: "workload",
  analysis_type: "dsq_summary"
})

// 3. Find bottlenecks automatically
find_scheduling_bottlenecks({
  trace_id: "workload",
  limit: 5
})

// 4. Investigate high-latency wakeups
analyze_trace_scheduling({
  trace_id: "workload",
  analysis_type: "wakeup_latency"
})

// 5. Correlate wakeup→schedule for specific process
correlate_wakeup_to_schedule({
  trace_id: "workload",
  pid: 1234,
  limit: 50
})

// 6. Get detailed timeline
get_process_timeline({
  trace_id: "workload",
  pid: 1234
})

// 7. Export everything
export_trace_analysis({
  trace_id: "workload",
  output_path: "/tmp/analysis.json"
})
```

## Available MCP Tools

| Tool | Description | Key Features |
|------|-------------|--------------|
| `load_perfetto_trace` | Load trace file | Returns metadata, DSQ info |
| `query_trace_events` | Query specific events | Filter by type/time/CPU |
| `analyze_trace_scheduling` | Run scheduling analysis | 5 analysis types, parallel |
| `get_process_timeline` | Process event timeline | Chronological lifecycle |
| `get_cpu_timeline` | CPU event timeline | All switches and softirqs |
| `find_scheduling_bottlenecks` | Auto-detect issues | Ranked by severity |
| `correlate_wakeup_to_schedule` | Wakeup→schedule latencies | Shows waker relationships |
| `export_trace_analysis` | Export to JSON | Comprehensive dump |

## Troubleshooting

### "Trace not found" Error
Make sure you've loaded the trace with `load_perfetto_trace` first.

### "Not a sched_ext trace" for DSQ Analysis
DSQ analysis requires traces captured while a sched_ext scheduler is running. Check with `analyze_trace_scheduling` using `dsq_summary`.

### Slow Trace Loading (>60s)
This is normal for large traces (40MB+). Loading is single-threaded. Once loaded, analysis is fast.

### Out of Memory
Large traces (>100MB) may consume significant memory. Close other applications or use a machine with more RAM.

## Technical Details

### Trace Format
- Binary protobuf format (`.proto` extension)
- Based on perfetto trace packet specification
- Contains ftrace events, process/thread descriptors, system stats
- Timestamps in nanoseconds (CLOCK_BOOTTIME)

### Event Types Parsed
- `sched_switch` - Context switches
- `sched_wakeup` / `sched_waking` - Task wakeups
- `sched_migrate_task` - Process migration
- `sched_process_fork/exec/exit` - Process lifecycle
- `softirq_entry/exit` - Software interrupt handling
- **sched_ext specific**: DSQ latency and depth as TrackEvent counters

### Multi-Threading
Analysis functions with `use_parallel: true` use the `rayon` crate to process CPUs in parallel. This provides 1.5-2x speedup on multi-core systems.

### Memory Usage
A 40MB trace file expands to approximately 200MB in memory after parsing and indexing. Traces are cached, so loading the same trace multiple times reuses the cached version.

## See Also

- Perfetto UI for visualization: https://ui.perfetto.dev
- MCP protocol specification: https://modelcontextprotocol.io
