# scxtop

`scxtop` is a top-like utility and observability tool for `sched_ext` schedulers.
It collects and aggregates system performance metrics and scheduler events via BPF.

**Three modes of operation:**
- **TUI Mode** (default): Interactive terminal UI with live metrics across CPUs, LLCs, and NUMA nodes
- **Trace Mode**: Generate Perfetto-compatible traces for detailed offline analysis
- **MCP Mode**: Model Context Protocol server for AI-assisted scheduler analysis

## Quick Start

### Interactive TUI
```bash
sudo scxtop
```

### Generate Perfetto Trace
```bash
sudo scxtop trace --duration 30
```

### MCP Server for AI Integration
```bash
sudo scxtop mcp --daemon
```

See [CLAUDE_INTEGRATION.md](CLAUDE_INTEGRATION.md) for AI assistant setup.

## TUI Mode

### Using `scxtop`

`scxtop` must be run as root or with capabilities as it uses `perf_event_open`
as well as BPF programs for data collection. Use the help menu (`h` key is the
default to see keybindings) to view the current keybindings:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/38d11e5d-edb7-4567-b62f-da223a47efd9" />

`scxtop` has multiple views for presenting aggregated data. The bar chart view
displays live value bar charts:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/8b3a806c-64d4-4f9e-a07d-9321c94cfbb9" />

The sparkline view is useful for seeing a historical view of the metrics:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/83238b44-5580-4587-a370-b2f9a68d925a" />

### Configuration

`scxtop` can use a configuration file, which can be generated using the `S` key
in the default keymap configuration. The config file follows the
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/).

An example configuration shows customization of default tick rates, theme and keymaps:

```
theme = "IAmBlue"
tick_rate_ms = 250
debug = false
exclude_bpf = false
worker_threads = 4

[keymap]
d = "AppStateDefault"
"?" = "AppStateHelp"
"[" = "DecBpfSampleRate"
q = "Quit"
"+" = "IncTickRate"
u = "ToggleUncoreFreq"
"Page Down" = "PageDown"
S = "SaveConfig"
Up = "Up"
P = "RecordTrace"
- = "DecTickRate"
L = "ToggleLocalization"
t = "ChangeTheme"
"]" = "IncBpfSampleRate"
Down = "Down"
l = "AppStateLlc"
k = "NextEvent"
a = "RecordTrace"
j = "PrevEvent"
v = "NextViewState"
h = "AppStateHelp"
n = "AppStateNode"
s = "AppStateScheduler"
e = "AppStateEvent"
w = "RecordTrace"
f = "ToggleCpuFreq"
Enter = "Enter"
"Page Up" = "PageUp"
x = "ClearEvent"
```

### Shell completions

`scxtop` is able to generate shell completions for various shells using the
`scxtop generate-completions` subcommand:

```
scxtop generate-completions -h
Usage: scxtop generate-completions [OPTIONS]

Options:
  -s, --shell <SHELL>    The shell type [default: bash] [possible values: bash, elvish, fish, powershell, zsh]
      --output <OUTPUT>  Output file, stdout if not present
  -h, --help             Print help
```

## Trace Mode - Perfetto Trace Generation and Analysis

`scxtop` can generate [Perfetto](https://perfetto.dev/) compatible traces for detailed
offline analysis. The trace data includes:
- Scheduler events (sched_switch, wakeups, migrations)
- DSQ (dispatch queue) data for active `sched_ext` schedulers
- Soft IRQ events
- CPU frequency transitions
- Task lifecycle events

Traces can be collected via the `scxtop trace` subcommand or triggered from keybindings
within the TUI (default: `P`, `a`, or `w` keys).

**Command line usage:**
```bash
# Trace for 30 seconds
sudo scxtop trace --duration 30

# Trace with custom output path
sudo scxtop trace --duration 60 --output scheduler-trace.proto
```

**View traces at:** https://ui.perfetto.dev/

![scxtop](https://github.com/user-attachments/assets/1be4ace4-e153-48ad-b63e-16f2b4e4c756)

### Analyzing Perfetto Traces (MCP Mode)

`scxtop` can also **analyze** perfetto trace files through its MCP server interface, providing detailed scheduling analysis and bottleneck detection with comprehensive percentile statistics.

**Key Features:**
- Query scheduling events with flexible filtering (time range, CPU, PID, event type)
- Analyze CPU utilization and process runtime with percentile breakdowns
- Measure wakeup latency distributions (p50/p95/p99/p999)
- Detect migration patterns and cross-NUMA/LLC migrations
- Identify scheduling bottlenecks automatically
- Extract sched_ext DSQ metadata from traces
- Correlate wakeup→schedule events to find critical paths
- Export comprehensive analysis to JSON

**Quick Example:**
```bash
# 1. Generate trace
sudo scxtop trace -d 5000 -o trace.proto -s

# 2. Start MCP server
sudo scxtop mcp --daemon

# 3. Via MCP client (e.g., Claude):
#    - load_perfetto_trace(file_path="trace.proto")
#    - analyze_trace_scheduling(analysis_type="cpu_utilization")
#    - find_scheduling_bottlenecks(limit=10)
```

**Performance:** Analyzes 40MB traces with 700K+ events in ~500ms (multi-threaded).

See **[docs/PERFETTO_TRACE_ANALYSIS.md](docs/PERFETTO_TRACE_ANALYSIS.md)** for complete documentation and examples.

For task/thread-level debugging, see **[docs/TASK_THREAD_DEBUGGING_GUIDE.md](docs/TASK_THREAD_DEBUGGING_GUIDE.md)**.

### Aggregating Across Hardware Boundaries

`scxtop` can be used to observe scheduling decisions across hardware boundaries
by using the LLC aggregated view:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/f7b867d8-7afa-4f69-a64a-584859919795" />
For systems with multiple NUMA nodes aggregations can also be done at the NUMA
level:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/32b6b27d-d7fa-4893-890d-84070caf3497" />

### Scheduler Stats

The scheduler view displays scheduler related stats. For schedulers that use
[`scx_stats`](https://github.com/sched-ext/scx/tree/main/rust/scx_stats) the stats
will be collected and aggregated. The scheduler view displays stats such as DSQ latency,
DSQ slice consumed (how much of the given timeslice was used), and vtime delta. Vtime
delta is useful in understanding the progression of scheduler vtime. For most schedulers
vtime delta should remain rather stable as DSQs are consumed. If a scheduler is using FIFO
scheduling this field may be blank.
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/34b645d0-afd9-4b8c-a2e3-db2118d87dfd" />

## MCP Mode - AI-Assisted Scheduler Analysis

`scxtop` includes a Model Context Protocol (MCP) server that exposes scheduler observability
data to AI assistants like Claude. This enables natural language queries, automated analysis,
and intelligent debugging of scheduler behavior.

### What is MCP?

The Model Context Protocol is a standardized way for AI assistants to access local tools and
data sources. The scxtop MCP server implements [Anthropic's MCP specification](https://modelcontextprotocol.io/)
using JSON-RPC 2.0 over stdio.

### Running the MCP Server

**One-shot mode** (single query, then exit):
```bash
sudo scxtop mcp
```

**Daemon mode** (continuous monitoring with event streaming):
```bash
sudo scxtop mcp --daemon
```

### Integration with Claude

**Claude Desktop:**

Add to your Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "scxtop": {
      "command": "/usr/local/bin/scxtop",
      "args": ["mcp", "--daemon"]
    }
  }
}
```

Restart Claude Desktop after updating the configuration.

**Claude Code (CLI):**

Add to your Claude Code settings:
- **macOS/Linux**: `~/.config/claude/config.json`

```json
{
  "mcpServers": {
    "scxtop": {
      "command": "sudo",
      "args": ["/usr/local/bin/scxtop", "mcp", "--daemon"]
    }
  }
}
```

Or configure via Claude Code CLI:
```bash
# Add the MCP server
claude mcp add scxtop --command "sudo /usr/local/bin/scxtop mcp --daemon"

# List configured servers
claude mcp list

# Test the connection
claude --mcp scxtop "Summarize my system's scheduler"
```

### Features

**Resource URIs** - Read-only data endpoints:
- `scheduler://current` - Active scheduler identification
- `topology://info` - Hardware topology (CPUs, cores, LLCs, NUMA)
- `stats://aggregated/{cpu,llc,node,dsq,process}` - Aggregated metrics
- `stats://scheduler/{raw,scx}` - Scheduler-specific statistics
- `stats://system/{cpu,memory,network}` - System-wide metrics
- `events://perf` - Available perf events for profiling
- `events://kprobe` - Available kernel functions for kprobe profiling
- `bpf://programs` - Currently loaded BPF programs with runtime statistics
- `profiling://perf/status` - Perf profiling status (running/stopped, samples)
- `profiling://perf/results` - Symbolized stack traces (kernel and userspace)
- `events://stream` - Real-time BPF event stream (daemon mode only)

**Tools** - Interactive query, profiling, and analysis:

*Live Monitoring Tools:*
- `query_stats` - Discover available statistics by category
- `get_topology` - Get hardware topology with configurable detail level
- `list_event_subsystems` - List available tracing event subsystems
- `list_events` - List specific kprobe or perf events with pagination
- `start_perf_profiling` - Start CPU profiling with stack traces
- `stop_perf_profiling` - Stop profiling and prepare results
- `get_perf_results` - Get symbolized flamegraph data
- `control_event_tracking` - Enable/disable BPF event collection
- `control_stats_collection` - Control BPF statistics sampling
- `control_analyzers` - Start/stop event analyzers
- `analyze_waker_wakee` - Analyze task wakeup relationships
- `analyze_softirq` - Analyze software interrupt processing

*Perfetto Trace Analysis Tools:*
- `load_perfetto_trace` - Load trace file for analysis
- `query_trace_events` - Query events with filtering (type, time, CPU, PID)
- `analyze_trace_scheduling` - Run scheduling analysis (5 types: CPU util, process runtime, wakeup latency, migration, DSQ)
- `get_process_timeline` - Get chronological event timeline for process
- `get_cpu_timeline` - Get chronological event timeline for CPU
- `find_scheduling_bottlenecks` - Auto-detect performance issues
- `correlate_wakeup_to_schedule` - Analyze wakeup→schedule latencies
- `export_trace_analysis` - Export comprehensive analysis to JSON
- `list_events` - List available kprobes and perf events (requires subsystem parameter)
- `start_perf_profiling` - Start perf sampling with stack trace collection
- `stop_perf_profiling` - Stop profiling and finalize results
- `get_perf_results` - Retrieve symbolized stack traces and top functions

**5 Workflow Prompts** - Guided analysis templates:
- `analyze_scheduler_performance` - Comprehensive performance analysis
- `debug_high_latency` - Step-by-step latency debugging
- `analyze_cpu_imbalance` - Load balancing investigation
- `investigate_scheduler_behavior` - Deep scheduler policy analysis
- `summarize_system` - Complete system and scheduler overview

### Example Queries

**Claude Desktop** - Ask questions in natural language:

```
"Summarize my system's scheduler configuration"
→ Claude uses the summarize_system prompt to gather comprehensive info

"Process 1234 has high scheduling latency, can you investigate?"
→ Claude follows the debug_high_latency workflow with filtering

"Monitor scheduler events and alert me if you see any anomalies"
→ Claude subscribes to events://stream in daemon mode

"Compare CPU utilization across NUMA nodes"
→ Claude reads stats://aggregated/node and correlates with topology

"Profile the system for 10 seconds and show me the hottest functions"
→ Claude uses start_perf_profiling, waits, then retrieves symbolized stacks

"What kernel functions are consuming the most CPU?"
→ Claude starts profiling, collects samples, and analyzes results
```

**Claude Code CLI** - Direct command line usage:

```bash
# Quick query
claude --mcp scxtop "What scheduler is running and how's performance?"

# Interactive session
claude --mcp scxtop
> Show me CPU utilization across NUMA nodes
> Which processes have high scheduling latency?
> What perf events are available for profiling?
> Profile the system at 99 Hz for 5 seconds and show the top 20 functions
> Start profiling and collect 10000 samples, then show me kernel stack traces

# Use a specific workflow prompt
claude --mcp scxtop --prompt analyze_scheduler_performance --arg focus_area=latency

# Generate a performance report
claude --mcp scxtop "Create a scheduler performance report" > report.md

# Profile and analyze
claude --mcp scxtop "Profile the system and identify performance bottlenecks"
```

### Real-time Event Streaming

In daemon mode, the MCP server converts BPF events to JSON and streams them to the client:

- Scheduling events: `sched_switch`, `sched_wakeup`, `sched_waking`
- Task lifecycle: `fork`, `exec`, `exit`
- Migrations: `sched_migrate_task`
- DSQ operations: enqueue, dispatch, consume
- System events: softirq, IPI, CPU hotplug, hardware pressure

This enables AI assistants to perform continuous monitoring and proactive analysis.

### Benefits

1. **Natural Language Interface**: Ask questions about scheduler behavior in plain English
2. **Intelligent Correlation**: AI automatically combines multiple metrics and data sources
3. **Guided Workflows**: Structured analysis patterns for common debugging scenarios
4. **Proactive Monitoring**: In daemon mode, AI can spot issues you didn't explicitly ask about
5. **Actionable Recommendations**: Get specific tuning suggestions based on observed patterns

### Documentation

See [CLAUDE_INTEGRATION.md](CLAUDE_INTEGRATION.md) for detailed examples and usage patterns.

## Documentation

### User Guides
- **[docs/PERFETTO_TRACE_ANALYSIS.md](docs/PERFETTO_TRACE_ANALYSIS.md)** - Complete perfetto trace analysis guide
- **[docs/TASK_THREAD_DEBUGGING_GUIDE.md](docs/TASK_THREAD_DEBUGGING_GUIDE.md)** - Task/thread debugging workflows  
- **[docs/PROTOBUF_LOADING_VERIFIED.md](docs/PROTOBUF_LOADING_VERIFIED.md)** - Protobuf loading verification
- **[docs/README.md](docs/README.md)** - Documentation index

### Implementation Documentation
- **[COMPLETE_IMPLEMENTATION_SUMMARY.md](COMPLETE_IMPLEMENTATION_SUMMARY.md)** - Full implementation overview
- **[PERFETTO_MCP_IMPLEMENTATION.md](PERFETTO_MCP_IMPLEMENTATION.md)** - Core implementation (Phases 1-5)
- **[EXTENDED_ANALYSIS_COMPLETE.md](EXTENDED_ANALYSIS_COMPLETE.md)** - Extended analyses (Phase 6)
- **[PERFETTO_ANALYSIS_ROADMAP.md](PERFETTO_ANALYSIS_ROADMAP.md)** - Future enhancements roadmap
- **[CLAUDE_INTEGRATION.md](CLAUDE_INTEGRATION.md)** - Claude Desktop/Code setup guide
