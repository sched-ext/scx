# Perfetto Trace Analyzer - Phase 8 Complete (with Outlier Detection) ✓

## Overview

The scxtop MCP server now includes a comprehensive perfetto trace analysis
system with built-in analyzers, automatic discovery, and a powerful query
framework.

**📚 Full Documentation:** See [PERFETTO_ANALYZER_GUIDE.md](./PERFETTO_ANALYZER_GUIDE.md)

## Quick Stats

- **17 Analyzers** across 5 categories
- **42 MCP Tools** for trace analysis (24 generic + 18 dedicated analyzer tools)
- **76+ Tests** (all passing)
- **Query Framework** with SQL-like capabilities
- **Auto-Discovery** based on trace capabilities
- **Outlier Detection** with 4 statistical methods
- **Performance:** 900K+ events analyzed in < 50s

## Categories

| Category | Analyzers | Purpose |
|----------|-----------|---------|
| **Scheduling** | 4 | CPU utilization, wakeup latency, migrations, DSQ behavior |
| **Interrupt** | 2 | Hardware IRQs, inter-processor interrupts |
| **I/O** | 4 | Block I/O, network, memory pressure, file sync |
| **Power** | 3 | CPU frequency, idle states, suspend/resume |
| **Extended** | 4 | Task states, preemptions, wakeup chains, latency breakdown |

## Key Features

### 1. Auto-Discovery
```json
{
  "tool": "discover_analyzers",
  "arguments": { "trace_id": "my_trace" }
}
```
Automatically finds applicable analyzers based on available events in the trace.

### 2. Batch Analysis
```json
{
  "tool": "run_all_analyzers",
  "arguments": { "trace_id": "my_trace" }
}
```
Runs all applicable analyzers in one operation.

### 3. Generic Query Framework
```json
{
  "tool": "query_trace",
  "arguments": {
    "trace_id": "my_trace",
    "event_type": "sched_switch",
    "field_filters": [
      { "field": "prev_state", "operator": "equal", "value": 1 }
    ],
    "aggregation": {
      "function": "count_by",
      "field": "comm"
    }
  }
}
```
SQL-like queries with filtering and aggregation.

### 4. Outlier Detection
```json
{
  "tool": "detect_outliers",
  "arguments": {
    "trace_id": "my_trace",
    "method": "IQR",
    "category": "all"
  }
}
```
Statistical outlier detection across latency, runtime, and CPU metrics using 4 methods:
- **IQR** (Interquartile Range) - Most robust, default method
- **MAD** (Median Absolute Deviation) - Robust to extreme values
- **StdDev** (Standard Deviation) - Traditional statistical approach
- **Percentile** - Threshold-based (p99/p999)

Returns outliers by category:
- **Latency**: Wakeup latency, schedule latency, blocked time
- **Runtime**: Excessive runtime, minimal runtime, high context switches
- **CPU**: Overutilized, underutilized, high contention

## Performance

| Operation | Performance |
|-----------|-------------|
| Load trace (900K events) | ~10s |
| Discover analyzers | < 1ms |
| Individual analyzer | 1-150ms |
| Batch analysis (7 analyzers) | ~33s |
| Outlier detection | ~1.3s |
| Query (100K events) | 1-15ms |
| Aggregation | < 1ms |

## Usage Example

```json
// 1. Load trace
{ "tool": "load_perfetto_trace", "arguments": { "file_path": "/path/to/trace.proto" } }

// 2. Get summary
{ "tool": "get_trace_summary", "arguments": { "trace_id": "trace" } }

// 3. Run all applicable analyzers
{ "tool": "run_all_analyzers", "arguments": { "trace_id": "trace" } }

// 4. Detect outliers
{ "tool": "detect_outliers", "arguments": { "trace_id": "trace", "method": "IQR", "category": "all" } }

// 5. Find bottlenecks
{ "tool": "find_scheduling_bottlenecks", "arguments": { "trace_id": "trace" } }

// 6. Custom query
{
  "tool": "query_trace",
  "arguments": {
    "trace_id": "trace",
    "event_type": "sched_switch",
    "aggregation": { "function": "count_by", "field": "comm" }
  }
}
```

## Adding a New Analyzer

See the [Developer Guide](./PERFETTO_ANALYZER_GUIDE.md#developer-guide) in the full documentation.

Quick steps:
1. Create analyzer struct with `analyze()` method
2. Implement `TraceAnalyzer` trait wrapper
3. Register in `AnalyzerRegistry::register_builtins()`
4. Add tests
5. Update documentation

## Compatibility

The analyzer system works with perfetto traces from:
- Linux ftrace
- Android systrace
- Chrome tracing
- Any perfetto-compatible trace format

## Next Steps

The perfetto analyzer system with outlier detection is complete and ready for use. Future enhancements could include:
- Additional analyzers for specific subsystems
- Real-time streaming analysis
- Trace comparison tools
- Advanced visualization support
- Custom analyzer plugins
- Additional outlier detection metrics (e.g., memory usage, I/O patterns)
