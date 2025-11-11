# Perfetto Trace Analyzer - Phase 8 Complete (with Outlier Detection) ✓

## Overview

The scxtop MCP server now includes a comprehensive perfetto trace analysis system with 17 built-in analyzers, automatic discovery, and a powerful query framework.

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

## Implementation Phases

### Phase 1: Enhanced Parser Infrastructure ✅
- Event type indexing
- Capability detection
- Clock type handling

### Phase 2: IRQ and IPI Analyzers ✅
- Hardware interrupt analysis
- Inter-processor interrupt patterns

### Phase 3: I/O and Resource Analyzers ✅
- Block I/O latencies
- Network bandwidth
- Memory pressure
- File sync operations

### Phase 4: Power and Performance Analyzers ✅
- CPU frequency scaling
- Idle state analysis
- Suspend/resume tracking

### Phase 5: Generic Query Framework ✅
- QueryBuilder with fluent API
- Field-level filtering (7 operators)
- Aggregation functions (count, count_by, avg, min, max, group_by)
- Pagination support

### Phase 6: Analyzer Registry and Auto-Discovery ✅
- Dynamic analyzer registration
- Event-based capability matching
- Category organization
- Batch execution
- Performance cost tracking

### Phase 7: Integration, Testing, and Documentation ✅
- 10 comprehensive integration tests
- Complete pipeline validation
- Performance benchmarks
- Concurrent execution tests
- Comprehensive documentation

### Phase 8: Outlier Detection ✅
- 4 statistical detection methods (IQR, MAD, StdDev, Percentile)
- Multi-category analysis (latency, runtime, CPU)
- Severity scoring and percentile calculation
- MCP tool integration
- Comprehensive test coverage (~1.3s analysis time)

## Test Results

```
✓ 76+ tests passing
✓ All integration tests passed
✓ Performance benchmarks:
  - Individual analyzers: 1-150ms
  - Batch analysis: ~33s for 7 analyzers
  - Outlier detection: ~1.3s
  - Queries: 1-15ms
✓ 900K+ events processed
✓ Concurrent execution validated
✓ Memory cleanup verified
```

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

## Architecture

```
MCP Server
├── MCP Tools Layer (24 tools)
├── Analyzer Registry
│   ├── Auto-discovery
│   ├── Category organization
│   └── Batch execution
├── Built-in Analyzers (17)
│   ├── Scheduling (4)
│   ├── Interrupt (2)
│   ├── I/O (4)
│   ├── Power (3)
│   └── Extended (4)
├── Outlier Detection
│   ├── Statistical methods (IQR, MAD, StdDev, Percentile)
│   ├── Latency analysis
│   ├── Runtime analysis
│   └── CPU analysis
├── Query Framework
│   ├── QueryBuilder
│   ├── Field filters
│   └── Aggregation
└── Perfetto Parser
    ├── Protobuf parsing
    ├── Event indexing
    └── Capability detection
```

## Files

### Core Implementation
- `src/mcp/perfetto_parser.rs` - Core trace parsing
- `src/mcp/perfetto_parser_enhanced.rs` - Event indexing and capabilities
- `src/mcp/perfetto_event_types.rs` - Event type definitions
- `src/mcp/perfetto_query.rs` - Query framework
- `src/mcp/perfetto_analyzer_registry.rs` - Analyzer registry
- `src/mcp/outlier_detection.rs` - Statistical outlier detection (NEW)
- `src/mcp/perfetto_outlier_analyzer.rs` - Perfetto-specific outlier analysis (NEW)

### Analyzers
- `src/mcp/perfetto_analyzers.rs` - Core scheduling analyzers
- `src/mcp/perfetto_analyzers_extended.rs` - Extended scheduling metrics
- `src/mcp/perfetto_analyzers_irq.rs` - Interrupt analyzers
- `src/mcp/perfetto_analyzers_io.rs` - I/O analyzers
- `src/mcp/perfetto_analyzers_power.rs` - Power analyzers

### Tests
- `tests/perfetto_parser_tests.rs` - Parser tests
- `tests/perfetto_query_tests.rs` - Query framework tests
- `tests/perfetto_analyzer_registry_tests.rs` - Registry tests
- `tests/perfetto_integration_tests.rs` - Integration tests (includes outlier detection tests)
- Plus 10+ other test files for individual analyzers

### Documentation
- `PERFETTO_ANALYZER_GUIDE.md` - Comprehensive guide (NEW)
- `PERFETTO_ANALYZER_README.md` - This file (NEW)

## Running Tests

```bash
# All tests
cargo test

# Unit tests only
cargo test --lib

# Integration tests (requires trace file)
cargo test --test perfetto_integration_tests -- --ignored

# Specific test
cargo test --test perfetto_integration_tests test_complete_pipeline -- --ignored --nocapture
```

## Adding a New Analyzer

See the [Developer Guide](./PERFETTO_ANALYZER_GUIDE.md#developer-guide) in the full documentation.

Quick steps:
1. Create analyzer struct with `analyze()` method
2. Implement `TraceAnalyzer` trait wrapper
3. Register in `AnalyzerRegistry::register_builtins()`
4. Add tests
5. Update documentation

## Dependencies

- `perfetto_protos = "0.51.1"` - Perfetto protobuf definitions
- `prost = "0.13.4"` - Protocol buffer implementation
- `serde = "1.0"` - Serialization framework
- `serde_json = "1.0"` - JSON support

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

## License

Copyright (c) Meta Platforms, Inc. and affiliates.

This software may be used and distributed according to the terms of the GNU General Public License version 2.

---

**Status:** Phase 8 Complete (with Outlier Detection) ✅
**Tests:** 76+ passing ✅
**Documentation:** Complete ✅
**Ready for use:** Yes ✅
