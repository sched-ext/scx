# scxtop Documentation Index

## Quick Links

### User Documentation
- **[PERFETTO_TRACE_ANALYSIS.md](PERFETTO_TRACE_ANALYSIS.md)** - Complete guide to perfetto trace analysis
- **[TASK_THREAD_DEBUGGING_GUIDE.md](TASK_THREAD_DEBUGGING_GUIDE.md)** - Task/thread debugging workflows
- **[PROTOBUF_LOADING_VERIFIED.md](PROTOBUF_LOADING_VERIFIED.md)** - Protobuf file loading verification

### Main README
- **[../README.md](../README.md)** - scxtop main documentation with MCP integration

### Implementation Documentation
Located in `tools/scxtop/` root:
- **[PERFETTO_MCP_IMPLEMENTATION.md](../PERFETTO_MCP_IMPLEMENTATION.md)**
- **[EXTENDED_ANALYSIS_COMPLETE.md](../EXTENDED_ANALYSIS_COMPLETE.md)**
- **[COMPLETE_IMPLEMENTATION_SUMMARY.md](../COMPLETE_IMPLEMENTATION_SUMMARY.md)**

### MCP Integration
- **[CLAUDE_INTEGRATION.md](../CLAUDE_INTEGRATION.md)** - Setting up Claude with scxtop MCP
- **[MCP_INTEGRATIONS.md](../MCP_INTEGRATIONS.md)** - MCP protocol details

## Documentation Structure

```
tools/scxtop/
├── README.md                           # Main README
├── docs/                               # User documentation
│   ├── README.md                       # This index
│   ├── PERFETTO_TRACE_ANALYSIS.md     # Perfetto analysis guide
│   ├── TASK_THREAD_DEBUGGING_GUIDE.md # Debugging workflows
│   └── PROTOBUF_LOADING_VERIFIED.md   # Protobuf verification
├── examples/
│   └── perfetto_trace_analysis_examples.json
└── CLAUDE_INTEGRATION.md              # Claude setup

```

## Quick Start

1. **New to perfetto analysis?** → Read [PERFETTO_TRACE_ANALYSIS.md](PERFETTO_TRACE_ANALYSIS.md)
2. **Need to debug a task?** → Read [TASK_THREAD_DEBUGGING_GUIDE.md](TASK_THREAD_DEBUGGING_GUIDE.md)
3. **Verify protobuf loading?** → Read [PROTOBUF_LOADING_VERIFIED.md](PROTOBUF_LOADING_VERIFIED.md)

## Features Summary

### Analysis Types
1. CPU Utilization
2. Process Runtime
3. Wakeup Latency
4. Migration Patterns
5. DSQ Summary (sched_ext)
6. Task States
7. Preemptions
8. Wakeup Chains
9. Latency Breakdown
10. Process Timeline
11. CPU Timeline
12. Bottleneck Detection
13. Wakeup→Schedule Correlation

### MCP Tools
1. load_perfetto_trace - **Load protobuf files**
2. query_trace_events
3. analyze_trace_scheduling
4. get_process_timeline
5. get_cpu_timeline
6. find_scheduling_bottlenecks
7. correlate_wakeup_to_schedule
8. export_trace_analysis
