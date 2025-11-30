# Perfetto Trace Analyzer System

## Overview

The scxtop MCP server provides comprehensive perfetto trace analysis
capabilities through a modular, extensible analyzer framework. This system
enables deep analysis of Linux kernel tracing data from various sources
including ftrace, Android systrace, and Chrome tracing.

**Key Features:**
- built-in analyzers across 5 categories (Scheduling, Interrupt, I/O, Power, Extended)
- Automatic analyzer discovery based on trace capabilities
- Generic SQL-like query framework for custom analysis
- Multi-threaded analysis for improved performance
- Cross-tool compatibility with standard perfetto formats

**Performance:** The system can analyze 900K+ events in under 50 seconds, with individual analyzers running in 1-150ms and queries in 1-15ms.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [MCP Tools Reference](#mcp-tools-reference)
3. [Built-in Analyzers](#built-in-analyzers)
4. [Query Framework](#query-framework)
5. [Developer Guide](#developer-guide)
6. [Performance Tuning](#performance-tuning)
7. [Examples](#examples)

---

## Quick Start

### Loading a Trace

```json
{
  "tool": "load_perfetto_trace",
  "arguments": {
    "file_path": "/path/to/trace.proto",
    "trace_id": "my_trace"
  }
}
```

### Getting Trace Summary

```json
{
  "tool": "get_trace_summary",
  "arguments": {
    "trace_id": "my_trace"
  }
}
```

Returns comprehensive trace information including:
- Duration, CPU count, process count, event count
- Trace capabilities (available events, has process tree, etc.)
- Applicable analyzers by category

### Running All Analyzers

```json
{
  "tool": "run_all_analyzers",
  "arguments": {
    "trace_id": "my_trace"
  }
}
```

Automatically discovers and runs all applicable analyzers in parallel.

---

## MCP Tools Reference

### Core Tools

#### `load_perfetto_trace`
Loads a perfetto trace file from disk.

**Parameters:**
- `file_path` (required): Absolute path to .proto file
- `trace_id` (optional): ID to reference this trace (defaults to filename)

**Returns:** Trace metadata (duration, CPUs, processes, events)

---

#### `discover_analyzers`
Discovers which analyzers can run on a trace based on available events.

**Parameters:**
- `trace_id` (required): Trace ID from load_perfetto_trace
- `category` (optional): Filter by category (scheduling|interrupt|io|power|extended)

**Returns:** List of applicable analyzers with metadata

---

#### `get_trace_summary`
Gets comprehensive trace summary including capabilities and applicable analyzers.

**Parameters:**
- `trace_id` (required): Trace ID

**Returns:**
- Trace duration, CPU/process/event counts
- Trace capabilities (available events, process tree, sched_ext)
- Applicable analyzers grouped by category

---

#### `run_all_analyzers`
Runs all applicable analyzers on a trace.

**Parameters:**
- `trace_id` (required): Trace ID
- `category` (optional): Run only analyzers from specific category

**Returns:** Batch analysis results with success/failure counts and timing

---

### Analysis Tools

#### `analyze_trace_scheduling`
Performs specific scheduling analysis.

**Parameters:**
- `trace_id` (required): Trace ID
- `analysis_type` (required): One of:
  - `cpu_utilization` - Per-CPU utilization stats
  - `process_runtime` - Per-process runtime analysis
  - `wakeup_latency` - Wakeup-to-schedule latencies
  - `migration_patterns` - CPU migration analysis
  - `dsq_summary` - sched_ext DSQ behavior (requires scx trace)
  - `task_states` - Task state transitions
  - `preemptions` - Preemption patterns
  - `wakeup_chains` - Wakeup chain detection
  - `latency_breakdown` - Scheduling latency stages
  - `irq_analysis` - Hardware interrupt handlers
  - `ipi_analysis` - Inter-processor interrupts
  - `block_io` - Block device I/O
  - `network_io` - Network transmit/receive
  - `memory_pressure` - Memory allocation/reclaim
  - `file_io` - File sync operations
  - `cpu_frequency` - CPU frequency scaling
  - `cpu_idle` - CPU idle states
  - `power_state` - System suspend/resume
- `use_parallel` (optional): Use multi-threaded analysis (default: true)
- `limit` (optional): Limit results for ranked analyses (default: 20)
- `pid` (optional): Filter for specific process

**Returns:** Analysis results with full percentile statistics

---

#### `find_scheduling_bottlenecks`
Automatically detects scheduling bottlenecks.

**Parameters:**
- `trace_id` (required): Trace ID
- `limit` (optional): Max bottlenecks to return (default: 10)

**Returns:** List of detected bottlenecks (high switch rates, long latencies, excessive migration)

---

#### `correlate_wakeup_to_schedule`
Correlates wakeup events to schedule events, showing waker→wakee latencies.

**Parameters:**
- `trace_id` (required): Trace ID
- `pid` (optional): Filter for specific process
- `limit` (optional): Max correlations (default: 100)

**Returns:** Sorted list of correlations with latency percentiles

---

### Query Tools

#### `query_trace`
Executes generic SQL-like query on trace with filtering and aggregation.

**Parameters:**
- `trace_id` (required): Trace ID
- `event_type` (optional): Filter by event type (e.g., "sched_switch")
- `cpu` (optional): Filter by CPU
- `pid` (optional): Filter by PID
- `start_time_ns` (optional): Start of time range
- `end_time_ns` (optional): End of time range
- `field_filters` (optional): Array of field-level filters:
  ```json
  {
    "field": "prev_state",
    "operator": "equal",  // equal|not_equal|greater_than|less_than|greater_or_equal|less_or_equal|contains
    "value": 1
  }
  ```
- `limit` (optional): Max events to return (default: 1000)
- `offset` (optional): Number of events to skip (default: 0)
- `aggregation` (optional): Aggregation function:
  ```json
  {
    "function": "count_by",  // count|count_by|avg|min|max|group_by
    "field": "comm"
  }
  ```

**Returns:** Query results with timing, matched count, and events or aggregation results

**Example - Find all sched_switch events for CPU 0 with prev_state=1:**
```json
{
  "tool": "query_trace",
  "arguments": {
    "trace_id": "my_trace",
    "event_type": "sched_switch",
    "cpu": 0,
    "field_filters": [
      {
        "field": "prev_state",
        "operator": "equal",
        "value": 1
      }
    ],
    "limit": 100
  }
}
```

---

#### `query_trace_events`
Simple event query by type and filters.

**Parameters:**
- `trace_id` (required): Trace ID
- `event_type` (optional): Event type filter (default: "all")
- `start_time_ns` (optional): Start time
- `end_time_ns` (optional): End time
- `cpu` (optional): CPU filter
- `limit` (optional): Max events (default: 1000)

**Returns:** Event summaries with timestamps and PIDs

---

### Timeline Tools

#### `get_process_timeline`
Gets chronological timeline of all events for a specific process.

**Parameters:**
- `trace_id` (required): Trace ID
- `pid` (required): Process ID
- `start_time_ns` (optional): Start time (defaults to trace start)
- `end_time_ns` (optional): End time (defaults to trace end)

**Returns:** Process timeline with all events

---

#### `get_cpu_timeline`
Gets chronological timeline of all events for a specific CPU.

**Parameters:**
- `trace_id` (required): Trace ID
- `cpu` (required): CPU ID
- `start_time_ns` (optional): Start time
- `end_time_ns` (optional): End time

**Returns:** CPU timeline (first 100 events for readability)

---

### Export Tools

#### `export_trace_analysis`
Exports comprehensive trace analysis to JSON file.

**Parameters:**
- `trace_id` (required): Trace ID
- `output_path` (required): Output file path
- `analysis_types` (optional): Types to include (default: all)
  - Options: cpu_utilization, process_runtime, wakeup_latency, migration, dsq, bottlenecks, task_states, preemptions, wakeup_chains, latency_breakdown

**Returns:** Export summary with analysis time and file size

---

## Built-in Analyzers

### Scheduling Category (4 analyzers)

#### cpu_utilization
Analyzes per-CPU utilization and per-process runtime with parallel processing.

**Required events:** sched_switch
**Performance cost:** 3/5
**Output:** Per-CPU stats (total_time, active_time, idle_time, context_switches)

---

#### wakeup_latency
Analyzes wakeup-to-schedule latencies with full percentile statistics.

**Required events:** sched_waking, sched_switch
**Performance cost:** 4/5
**Output:** Latency percentiles (min, p50, p95, p99, p999, max)

---

#### migration_patterns
Analyzes CPU migration patterns and hotspots.

**Required events:** sched_migrate_task
**Performance cost:** 2/5
**Output:** Migration counts, cross-socket migrations, per-process migration stats

---

#### dsq_summary
Analyzes sched_ext dispatch queue behavior (requires scx trace).

**Required events:** None (uses scx metadata)
**Requires scx:** Yes
**Performance cost:** 3/5
**Output:** Per-DSQ statistics (enqueues, dispatches, latencies)

---

### Interrupt Category (2 analyzers)

#### irq_analysis
Analyzes hardware interrupt handler latencies.

**Required events:** irq_handler_entry, irq_handler_exit
**Performance cost:** 2/5
**Output:** Per-IRQ total time, count, avg/max duration

---

#### ipi_analysis
Analyzes inter-processor interrupts.

**Required events:** ipi_entry, ipi_exit
**Performance cost:** 2/5
**Output:** IPI counts by reason, per-CPU breakdown

---

### I/O Category (4 analyzers)

#### block_io
Analyzes block device I/O patterns and latencies.

**Required events:** block_rq_insert, block_rq_issue
**Performance cost:** 3/5
**Output:** Read/write counts, latency breakdown (queue, device)

---

#### network_io
Analyzes network transmit/receive and bandwidth.

**Required events:** net_dev_xmit, netif_receive_skb
**Performance cost:** 2/5
**Output:** TX/RX packets, bytes, bandwidth (Mbps)

---

#### memory_pressure
Analyzes memory allocation and reclaim.

**Required events:** mm_page_alloc, mm_page_free
**Performance cost:** 3/5
**Output:** Page alloc/free counts, net allocation, reclaim stats

---

#### file_io
Analyzes file sync operations.

**Required events:** ext4_sync_file_enter, ext4_sync_file_exit
**Performance cost:** 2/5
**Output:** Sync count, latency percentiles

---

### Power Category (3 analyzers)

#### cpu_frequency
Analyzes CPU frequency scaling behavior.

**Required events:** cpu_frequency
**Performance cost:** 2/5
**Output:** Per-CPU frequency transitions, min/max/avg frequency

---

#### cpu_idle
Analyzes CPU idle state transitions.

**Required events:** cpu_idle
**Performance cost:** 2/5
**Output:** Per-CPU idle transitions, active/idle time percentages

---

#### power_state
Analyzes system suspend/resume transitions.

**Required events:** suspend_resume
**Performance cost:** 1/5
**Output:** Suspend/resume event count and timestamps

---

### Extended Category (4 analyzers)

#### task_states
Analyzes task state transitions and distributions.

**Required events:** sched_switch
**Performance cost:** 3/5
**Output:** Per-process state time (running, runnable, blocked, sleep)

---

#### preemptions
Analyzes task preemption patterns.

**Required events:** sched_switch
**Performance cost:** 3/5
**Output:** Preemption counts, preemptors, preemption latency

---

#### wakeup_chains
Detects wakeup chains and cascades.

**Required events:** sched_waking, sched_switch
**Performance cost:** 4/5
**Output:** Detected chains with depth and total latency

---

#### latency_breakdown
Breaks down scheduling latency into stages.

**Required events:** sched_waking, sched_switch
**Performance cost:** 4/5
**Output:** Latency breakdown by stage (wakeup→runnable→scheduled)

---

## Query Framework

The query framework provides SQL-like capabilities for custom trace analysis.

### QueryBuilder API

```rust
use scxtop::mcp::{QueryBuilder, Aggregator};

// Build query
let query = QueryBuilder::new()
    .event_type("sched_switch")
    .cpu(0)
    .time_range(start_ns, end_ns)
    .limit(1000);

// Execute
let result = query.execute(&trace);

// Aggregate
let count_by_comm = Aggregator::count_by(&result, "comm");
let avg_prio = Aggregator::avg(&result, "prio");
```

### Filtering Operators

- `equal` - Field equals value
- `not_equal` - Field not equals value
- `greater_than` - Field > value
- `less_than` - Field < value
- `greater_or_equal` - Field >= value
- `less_or_equal` - Field <= value
- `contains` - String field contains substring

### Aggregation Functions

- `count` - Total event count
- `count_by(field)` - Count by unique field values
- `group_by(field)` - Group events by field value
- `avg(field)` - Average of numeric field
- `min(field)` - Minimum value
- `max(field)` - Maximum value

---

## Developer Guide

### Adding a New Analyzer

1. **Create the Analyzer**

```rust
pub struct MyAnalyzer {
    trace: Arc<PerfettoTrace>,
}

impl MyAnalyzer {
    pub fn new(trace: Arc<PerfettoTrace>) -> Self {
        Self { trace }
    }

    pub fn analyze() -> MyResult {
        // Implement analysis logic
        // Use self.trace to access events
    }
}
```

2. **Define the Wrapper**

```rust
struct MyAnalyzerWrapper;

impl TraceAnalyzer for MyAnalyzerWrapper {
    fn metadata(&self) -> &AnalyzerMetadata {
        static METADATA: std::sync::OnceLock<AnalyzerMetadata> =
            std::sync::OnceLock::new();

        METADATA.get_or_init(|| AnalyzerMetadata {
            id: "my_analyzer".to_string(),
            name: "My Analyzer".to_string(),
            description: "What it does".to_string(),
            category: AnalyzerCategory::Scheduling,
            required_events: vec!["sched_switch".to_string()],
            optional_events: vec![],
            requires_scx: false,
            performance_cost: 3,
        })
    }

    fn can_analyze(&self, trace: &PerfettoTrace) -> bool {
        !trace.get_events_by_type("sched_switch").is_empty()
    }

    fn analyze(&self, trace: Arc<PerfettoTrace>) -> AnalyzerResult {
        let start = std::time::Instant::now();
        let analyzer = MyAnalyzer::new(trace);
        let result = analyzer.analyze();

        AnalyzerResult {
            analyzer_id: self.metadata().id.clone(),
            success: true,
            data: serde_json::to_value(&result).unwrap(),
            duration_ms: start.elapsed().as_millis() as u64,
            error: None,
        }
    }
}
```

3. **Register in Registry**

```rust
// In perfetto_analyzer_registry.rs
impl AnalyzerRegistry {
    pub fn register_builtins(&mut self) {
        // ... existing registrations
        self.register(Box::new(MyAnalyzerWrapper));
    }
}
```

4. **Add MCP Tool (Optional)**

```rust
// In tools.rs
McpTool {
    name: "my_analysis".to_string(),
    description: "Performs my custom analysis".to_string(),
    input_schema: json!({
        "type": "object",
        "properties": {
            "trace_id": {
                "type": "string",
                "description": "Trace ID"
            }
        },
        "required": ["trace_id"]
    }),
}
```

### Analyzer Categories

Choose the appropriate category:
- **Scheduling** - Context switches, wakeups, migrations
- **Interrupt** - IRQs, IPIs, softirqs
- **IO** - Block I/O, network, memory, filesystems
- **Power** - Frequency scaling, idle states, suspend/resume
- **Extended** - Advanced scheduling metrics, chains, breakdowns
- **Query** - Generic query capabilities

### Performance Cost Guidelines

- **1** - Very fast, minimal overhead (< 10ms)
- **2** - Fast, low overhead (10-50ms)
- **3** - Moderate, acceptable overhead (50-200ms)
- **4** - Expensive, higher overhead (200ms-1s)
- **5** - Very expensive, significant overhead (> 1s)

---

## Performance Tuning

### Multi-threaded Analysis

Enable parallel processing for better performance:

```json
{
  "analysis_type": "cpu_utilization",
  "use_parallel": true
}
```

**Speedup:** 2-4x on multi-core systems

### Query Optimization

1. **Use specific event type filters** instead of querying all events
2. **Apply time range filters** to narrow the search window
3. **Use limit** to cap result size for exploratory queries
4. **Use aggregation** instead of retrieving all events when only counts are needed

**Example - Fast aggregation:**
```json
{
  "trace_id": "my_trace",
  "event_type": "sched_switch",
  "aggregation": {
    "function": "count_by",
    "field": "comm"
  }
}
```

### Batch Analysis

Run all analyzers in one call instead of individual calls:

```json
{
  "tool": "run_all_analyzers",
  "arguments": {
    "trace_id": "my_trace"
  }
}
```

Analyzers run sequentially but with minimal overhead.

### Memory Management

- Traces are loaded into memory as Arc-wrapped structures
- Multiple analyzers share the same trace data
- Large traces (> 1M events) may require 500MB+ RAM
- Use specific analyzers instead of `run_all_analyzers` for memory-constrained systems

---

## Examples

### Example 1: Basic Trace Analysis

```json
// 1. Load trace
{
  "tool": "load_perfetto_trace",
  "arguments": {
    "file_path": "/traces/my_app.proto",
    "trace_id": "app_trace"
  }
}

// 2. Get summary
{
  "tool": "get_trace_summary",
  "arguments": {
    "trace_id": "app_trace"
  }
}

// 3. Run CPU utilization analysis
{
  "tool": "analyze_trace_scheduling",
  "arguments": {
    "trace_id": "app_trace",
    "analysis_type": "cpu_utilization",
    "use_parallel": true
  }
}
```

### Example 2: Finding Performance Bottlenecks

```json
// 1. Find scheduling bottlenecks
{
  "tool": "find_scheduling_bottlenecks",
  "arguments": {
    "trace_id": "app_trace",
    "limit": 10
  }
}

// 2. Analyze wakeup latency for problematic process
{
  "tool": "analyze_trace_scheduling",
  "arguments": {
    "trace_id": "app_trace",
    "analysis_type": "wakeup_latency"
  }
}

// 3. Get detailed process timeline
{
  "tool": "get_process_timeline",
  "arguments": {
    "trace_id": "app_trace",
    "pid": 1234
  }
}
```

### Example 3: Custom Query Analysis

```json
// Find all blocking events for a specific process
{
  "tool": "query_trace",
  "arguments": {
    "trace_id": "app_trace",
    "event_type": "sched_switch",
    "field_filters": [
      {
        "field": "prev_pid",
        "operator": "equal",
        "value": 1234
      },
      {
        "field": "prev_state",
        "operator": "greater_than",
        "value": 0
      }
    ],
    "aggregation": {
      "function": "count_by",
      "field": "prev_state"
    }
  }
}
```

### Example 4: Comprehensive Analysis Export

```json
// Export all analyses to JSON
{
  "tool": "export_trace_analysis",
  "arguments": {
    "trace_id": "app_trace",
    "output_path": "/tmp/analysis_report.json",
    "analysis_types": [
      "cpu_utilization",
      "process_runtime",
      "wakeup_latency",
      "migration",
      "bottlenecks",
      "task_states"
    ]
  }
}
```

---

## Testing

### Unit Tests

Run analyzer-specific tests:
```bash
cargo test --lib perfetto_analyzers
cargo test --lib perfetto_query
cargo test --lib perfetto_analyzer_registry
```

### Integration Tests

Run end-to-end integration tests:
```bash
# Requires real trace file at /home/hodgesd/scx/scxtop_trace_0.proto
cargo test --test perfetto_integration_tests -- --ignored
```

**Test Coverage:**
- Complete pipeline (load → discover → analyze → query)
- Cross-analyzer consistency
- Performance benchmarks
- Error handling
- Trace summary accuracy
- Category filtering
- Concurrent execution
- Memory cleanup

---

## Troubleshooting

### Analyzer Not Discovered

**Symptom:** `discover_analyzers` doesn't find expected analyzer

**Solution:** Check if trace has required events:
```json
{
  "tool": "get_trace_summary",
  "arguments": {
    "trace_id": "my_trace"
  }
}
```

Look at `capabilities.available_events` to see what events are in the trace.

---

### High Memory Usage

**Symptom:** Memory usage grows during analysis

**Solution:**
1. Use specific analyzers instead of `run_all_analyzers`
2. Analyze smaller time windows using query time ranges
3. Use aggregation instead of retrieving full event data

---

### Slow Query Performance

**Symptom:** Queries take > 100ms

**Solution:**
1. Add event type filter
2. Use time range to narrow search window
3. Reduce limit if returning many events
4. Use aggregation for counts instead of retrieving all events

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    MCP Server                       │
├─────────────────────────────────────────────────────┤
│                  MCP Tools Layer                    │
│  load_perfetto_trace, discover_analyzers, etc.     │
├─────────────────────────────────────────────────────┤
│              Analyzer Registry                      │
│  • Auto-discovery based on capabilities            │
│  • Category-based organization                      │
│  • Batch execution                                  │
├─────────────────────────────────────────────────────┤
│              Built-in Analyzers (17)                │
│  ┌─────────┬──────────┬──────┬───────┬──────────┐  │
│  │Scheduling│Interrupt │ I/O  │ Power │ Extended │  │
│  └─────────┴──────────┴──────┴───────┴──────────┘  │
├─────────────────────────────────────────────────────┤
│              Query Framework                        │
│  • QueryBuilder (fluent API)                        │
│  • Field filters & operators                        │
│  • Aggregation functions                            │
├─────────────────────────────────────────────────────┤
│              Perfetto Parser                        │
│  • Protobuf parsing                                 │
│  • Event indexing                                   │
│  • Capability detection                             │
└─────────────────────────────────────────────────────┘
```

---

## References

- [Perfetto Documentation](https://perfetto.dev/docs/)
- [perfetto_protos v0.51.1](https://docs.rs/perfetto_protos)
- [Linux ftrace Events](https://www.kernel.org/doc/html/latest/trace/events.html)
- [sched_ext Documentation](https://github.com/sched-ext/scx)

---

## Contributing

When adding new analyzers:
1. Follow the developer guide above
2. Add comprehensive tests (unit + integration)
3. Document in this guide
4. Update MCP tool schema if needed
5. Ensure performance cost is accurate
