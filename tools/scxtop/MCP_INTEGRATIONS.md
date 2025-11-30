# scxtop MCP Server - Complete Integration Reference

This document provides a comprehensive overview of all MCP (Model Context Protocol) integrations available in the scxtop MCP server.

## Overview

The scxtop MCP server provides AI assistants with programmatic access to Linux scheduler metrics, BPF events, hardware topology, and performance profiling capabilities. It implements the MCP specification (protocol version 2024-11-05) and supports both one-shot queries and daemon mode with real-time event streaming.

## Server Information

- **Server Name**: `scxtop-mcp`
- **Version**: (from Cargo.toml)
- **Protocol Version**: `2024-11-05`
- **Modes**:
  - One-shot mode (stdio)
  - Daemon mode (continuous with event streaming)

## Capabilities

### 1. Resources (17 URIs)

Resources are read-only data endpoints that provide access to system metrics and configuration.

#### Scheduler Resources

| URI | Description | Data Type |
|-----|-------------|-----------|
| `scheduler://current` | Currently active scheduler name, class (sched_ext or other), and state | JSON |
| `stats://scheduler/raw` | Raw JSON statistics from the scheduler's scx_stats framework | JSON |
| `stats://scheduler/scx` | Kernel-level sched_ext statistics and counters | JSON |

#### Topology Resources

| URI | Description | Data Type |
|-----|-------------|-----------|
| `topology://info` | Hardware topology including CPUs, cores, LLCs, NUMA nodes with IDs and mappings | JSON |

#### Aggregated Statistics

| URI | Description | Data Type |
|-----|-------------|-----------|
| `stats://aggregated/cpu` | Per-CPU statistics including utilization, frequency, scheduling metrics | JSON |
| `stats://aggregated/llc` | Statistics aggregated by last-level cache domain | JSON |
| `stats://aggregated/node` | Statistics aggregated by NUMA node | JSON |
| `stats://aggregated/dsq` | Dispatch queue statistics for sched_ext schedulers (latencies, depths, vtime) | JSON |
| `stats://aggregated/process` | Per-process scheduler statistics including runtime, vtime, layer info | JSON |

#### System-Wide Statistics

| URI | Description | Data Type |
|-----|-------------|-----------|
| `stats://system/cpu` | System-wide CPU utilization statistics and context switch rates | JSON |
| `stats://system/memory` | System memory statistics (total, free, cached, etc.) | JSON |
| `stats://system/network` | Network interface statistics | JSON |

#### Profiling and Events

| URI | Description | Data Type |
|-----|-------------|-----------|
| `events://perf` | List of all available perf tracepoint events organized by subsystem | JSON |
| `events://kprobe` | List of all available kernel functions for kprobe profiling | JSON |
| `bpf://programs` | Currently loaded BPF programs with runtime statistics | JSON |
| `profiling://perf/status` | Current perf profiling status (running/stopped, sample count, duration) | JSON |
| `profiling://perf/results` | Symbolized stack traces from perf profiling (kernel and userspace, top 50 symbols) | JSON |

#### Event Streaming (Daemon Mode Only)

| URI | Description | Data Type |
|-----|-------------|-----------|
| `events://stream` | Real-time stream of BPF scheduler events (requires daemon mode and subscription) | NDJSON |

**Supported Event Types** (when subscribed to `events://stream`):
- Scheduling: `sched_switch`, `sched_wakeup`, `sched_waking`, `sched_wakeup_new`, `sched_migrate_task`
- Process lifecycle: `fork`, `exec`, `exit`, `wait`
- System events: `softirq`, `ipi`, `cpuhp_enter`, `cpuhp_exit`, `hw_pressure`
- Profiling: `kprobe`, `perf_sample`
- Scheduler-specific: `sched_hang`, `sched_cpu_perf_set`
- Special: `mango_app`, `trace_started`, `trace_stopped`, `system_stat`, `sched_stats`

### 2. Tools (6 Interactive Functions)

Tools are callable functions that perform queries or actions.

#### `query_stats`

Discover available statistics resources and how to query them.

**Parameters**:
- `stat_type` (optional): Filter by type: `cpu`, `llc`, `node`, `dsq`, `process`, `scheduler`, `system`

**Returns**: List of available resource URIs with descriptions and usage examples.

#### `get_topology`

Get detailed hardware topology with core/LLC/node mappings.

**Parameters**:
- `detail_level` (optional, default: `summary`): `summary` or `full`
  - `summary`: High-level counts and SMT status
  - `full`: Complete per-CPU, per-core, per-LLC, per-node details with frequencies and capacities
- `include_offline` (optional, default: `false`): Include offline CPUs

**Returns**: JSON object with topology information based on detail level.

#### `list_events`

List available profiling events filtered by subsystem.

**Parameters**:
- `subsystem` (**required**): Filter perf events by subsystem (e.g., `sched`, `irq`, `power`, `block`, `net`)
- `event_type` (optional, default: `perf`): `kprobe`, `perf`, or `all`

**Returns**: JSON object with filtered events, count, and subsystem information. On error, lists available subsystems.

**Example**:
```json
{
  "subsystem": "sched",
  "event_type": "perf"
}
```

#### `start_perf_profiling`

Start perf profiling with stack trace collection and symbolization.

**Parameters**:
- `event` (optional, default: `hw:cpu-clock`): Event to profile
  - Hardware events: `hw:cpu-clock`
  - Software events: `sw:task-clock`
  - Tracepoints: `tracepoint:subsystem:event` (e.g., `tracepoint:sched:sched_switch`)
- `freq` (optional, default: `99`): Sampling frequency in Hz
- `cpu` (optional, default: `-1`): CPU to profile (-1 for all CPUs, specific CPU ID otherwise)
- `pid` (optional, default: `-1`): Process ID to profile (-1 for system-wide)
- `max_samples` (optional, default: `10000`): Maximum samples to collect (0 for unlimited)
- `duration_secs` (optional, default: `0`): Duration in seconds (0 for manual stop)

**Returns**: Confirmation with profiling configuration.

**Example**:
```json
{
  "event": "hw:cpu-clock",
  "freq": 99,
  "duration_secs": 10,
  "max_samples": 0
}
```

#### `stop_perf_profiling`

Stop perf profiling and prepare results for retrieval.

**Parameters**: None

**Returns**: Status object with sample count, duration, and profiling state.

#### `get_perf_results`

Retrieve symbolized stack traces and top functions from perf profiling.

**Parameters**:
- `limit` (optional, default: `50`): Number of top symbols to return
- `include_stacks` (optional, default: `true`): Include full symbolized stack traces

**Returns**: JSON object with:
- Top symbols ranked by sample count with percentages
- Symbolized stack traces (if `include_stacks` is true)
- Kernel and userspace function names
- Sample statistics

**Example**:
```json
{
  "limit": 20,
  "include_stacks": true
}
```

### 3. Prompts (5 Guided Workflows)

Prompts are pre-defined analysis workflows that guide the AI through complex investigations.

#### `analyze_scheduler_performance`

Comprehensive scheduler performance analysis workflow.

**Arguments**:
- `focus_area` (optional): `latency`, `throughput`, `balance`, or `general`
  - `latency`: Focus on dispatch queue latencies, wakeup delays
  - `throughput`: Focus on context switch rates, CPU utilization, migration patterns
  - `balance`: Focus on load distribution across CPUs, LLCs, NUMA nodes
  - `general`: Comprehensive overview of all aspects

**Returns**: Detailed workflow instructions for analyzing scheduler performance based on focus area.

#### `debug_high_latency`

Debug high scheduling latency issues with step-by-step investigation.

**Arguments**:
- `pid` (optional): Process ID to investigate (if not specified, system-wide analysis)

**Returns**: Workflow for identifying latency bottlenecks, analyzing wakeup patterns, checking hardware factors, and suggesting remediation.

#### `analyze_cpu_imbalance`

Analyze CPU load imbalance and migration patterns.

**Arguments**: None

**Returns**: Workflow for measuring imbalance severity, understanding topology, identifying migration patterns, analyzing task characteristics, and determining root causes.

#### `investigate_scheduler_behavior`

Deep dive into scheduler behavior and policies.

**Arguments**:
- `scheduler_name` (optional): Specific scheduler to analyze (e.g., `scx_rusty`, `scx_lavd`)

**Returns**: Workflow for examining dispatch queue behavior, monitoring scheduling decisions, analyzing task placement patterns, and comparing against expected behavior.

#### `summarize_system`

Comprehensive system and scheduler summary.

**Arguments**: None

**Returns**: Workflow for gathering complete system overview including hardware topology, active scheduler, system-wide statistics, resource distribution, top processes, and available monitoring capabilities.

## Usage Examples

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scxtop": {
      "command": "/path/to/scxtop",
      "args": ["--mcp"]
    }
  }
}
```

### Query Examples

**Basic resource read**:
```
"What scheduler is currently running?"
→ Claude reads: scheduler://current
```

**Using tools**:
```
"Show me the hardware topology"
→ Claude calls: get_topology with detail_level="full"
```

**Using prompts**:
```
"Analyze scheduler latency issues"
→ Claude invokes: analyze_scheduler_performance prompt with focus_area="latency"
```

**Profiling workflow**:
```
"Profile the system and show me the hottest kernel functions"
→ Claude calls: start_perf_profiling with event="hw:cpu-clock", freq=99
→ (waits or sets duration)
→ Claude calls: stop_perf_profiling
→ Claude calls: get_perf_results with limit=20, include_stacks=true
→ Claude analyzes and presents results
```

**Event monitoring (daemon mode)**:
```
"Monitor scheduling events and alert me if you see high latency"
→ Claude subscribes to: events://stream
→ Claude filters sched_switch events for dsq_lat_us > 1000
→ Claude reports anomalies in real-time
```

## Implementation Details

### File Organization

- `src/mcp/server.rs` - Main MCP server implementation and request handling
- `src/mcp/resources.rs` - Resource registration and data retrieval
- `src/mcp/tools.rs` - Tool implementations
- `src/mcp/prompts.rs` - Workflow prompt definitions
- `src/mcp/protocol.rs` - MCP protocol types and structures
- `src/mcp/events.rs` - BPF event to MCP event conversion
- `src/mcp/bpf_stats.rs` - BPF program statistics collector
- `src/mcp/perf_profiling.rs` - Perf profiling engine with symbolization

### Resource Handler Registration

Resources are registered with closures that capture necessary state (e.g., topology, BPF stats collector):

```rust
self.resources.register_handler("topology://info".to_string(), move || {
    Ok(serde_json::json!({
        "nr_cpus": topo.all_cpus.len(),
        // ... topology data
    }))
});
```

### Event Streaming Architecture

1. MCP server creates an unbounded channel
2. Resources module holds the sender
3. Main scxtop BPF event loop pushes events via `push_event()`
4. Events are converted to JSON and streamed to the client
5. Client subscribes to `events://stream` resource

## Daemon Mode vs One-Shot Mode

### One-Shot Mode
```bash
scxtop --mcp
```
- Processes one MCP request cycle
- No event streaming
- Exits after initialize + first request
- Suitable for CLI usage with Claude Code

### Daemon Mode
```bash
scxtop --mcp-daemon
```
- Runs continuously
- Enables `events://stream` resource
- Real-time BPF event streaming
- Suitable for Claude Desktop long-running sessions
- Allows monitoring and proactive analysis

## Statistics Collection

The MCP server integrates with scxtop's existing statistics infrastructure:

- **scx_stats framework**: Reads raw scheduler statistics from sched_ext schedulers
- **BPF programs**: Collects per-CPU, per-process, per-DSQ metrics
- **System stats**: Reads `/proc` and `/sys` for system-wide metrics
- **BPF program stats**: Monitors loaded BPF programs via bpffs
- **Perf profiling**: Uses perf_event_open() for stack trace collection
- **Symbolization**: Resolves kernel and userspace addresses to function names

## Security Considerations

- Requires root or CAP_BPF/CAP_PERFMON capabilities
- Accesses /sys/kernel/debug/tracing (tracefs)
- Reads /proc filesystem
- Attaches BPF programs to tracepoints
- Can profile system-wide or specific processes
- No authentication mechanism (local stdio only)

## Performance Impact

- **Resource reads**: Minimal impact, reads from in-memory stats
- **Event streaming**: Low overhead, BPF programs filter in kernel
- **Perf profiling**: Configurable sampling rate (default 99 Hz)
- **Symbolization**: Performed in userspace, cached for efficiency

## Future Enhancements

Potential areas for expansion:
- Additional resource types (disk I/O, interrupts)
- More granular event filtering
- Historical data retention and querying
- Flamegraph generation
- Scheduler parameter tuning via tools
- Integration with additional profiling tools (eBPF-based)

## References

- MCP Specification: https://spec.modelcontextprotocol.io/
- scxtop documentation: README.md, CLAUDE_INTEGRATION.md
- sched_ext documentation: https://github.com/sched-ext/scx
