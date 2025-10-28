# Using scxtop MCP Server with Claude

## Configuration

### Claude Desktop

Add the scxtop MCP server to your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "scxtop": {
      "command": "/path/to/scxtop",
      "args": ["mcp", "--daemon"],
      "env": {}
    }
  }
}
```

After adding this configuration, restart Claude Desktop.

### Claude Code (CLI)

Configure the MCP server for Claude Code:

**Configuration file:** `~/.config/claude/config.json`

```json
{
  "mcpServers": {
    "scxtop": {
      "command": "sudo",
      "args": ["/path/to/scxtop", "mcp", "--daemon"],
      "env": {}
    }
  }
}
```

**Or use the CLI command:**

```bash
# Add the MCP server
claude mcp add scxtop --command "sudo /path/to/scxtop mcp --daemon"

# Verify it's configured
claude mcp list

# Test the connection
claude --mcp scxtop "Show me the current scheduler"
```

**Note:** Claude Code requires `sudo` since scxtop needs root privileges for BPF operations.

## Example Usage

### 1. System Overview

**You:** "Can you give me a summary of my system's scheduler?"

**Claude:** I'll use the `summarize_system` prompt to get a comprehensive overview.

*Claude invokes the prompt and follows the workflow, reading resources:*
- `topology://info` - Gets hardware layout
- `scheduler://current` - Identifies active scheduler
- `stats://aggregated/cpu` - CPU utilization
- `stats://aggregated/process` - Top processes

**Response:**
```
System Summary:
- Hardware: 16 CPUs (8 cores), 2 LLCs, 1 NUMA node, SMT enabled
- Active Scheduler: scx_rusty (sched_ext)
- CPU Utilization: Average 45%, range 32-67%
- Top Process: chrome (PID 1234) using 18% CPU time
- Context Switch Rate: 12,450/sec
- Load: Well balanced across CPUs (variance: 8%)
```

### 2. Latency Investigation

**You:** "Process 5678 is experiencing high scheduling latency. Can you investigate?"

**Claude:** I'll use the `debug_high_latency` prompt for PID 5678.

*Claude follows the debugging workflow:*
1. Reads `scheduler://current` to confirm sched_ext is active
2. Queries `stats://aggregated/process` filtered for PID 5678
3. Checks `stats://aggregated/cpu` for bottleneck CPUs
4. Uses `get_topology` tool to understand CPU layout

**Response:**
```
Latency Analysis for PID 5678:

Problem Found:
- Average scheduling latency: 2.3ms (high!)
- Process primarily runs on CPUs 4-7 (LLC 0)
- LLC 0 is heavily loaded (85% utilization vs 45% on LLC 1)
- Migration count: 47 migrations in last minute (excessive)

Root Cause:
The process is experiencing contention on LLC 0. Other CPU-intensive
processes on the same cache domain are causing:
- Long runqueue wait times
- Frequent migrations when seeking idle CPUs
- Cache thrashing from cross-LLC migrations

Recommendations:
1. Consider pinning task to specific CPUs in less loaded LLC 1
2. Adjust scheduler layer weights if using scx_layered
3. Check if workload can be split across cache domains
```

### 3. Real-time Monitoring

**You:** "Monitor scheduler events in real-time and alert me if you see any issues"

**Claude:** I'll subscribe to the event stream to watch for anomalies.

*Claude subscribes to `events://stream` resource in daemon mode*

**Claude observes and reports:**
```
Real-time Monitoring Active...

[10:30:42] Normal: ~450 sched_switch events/sec, latencies < 100μs

[10:31:15] ⚠️ ALERT: Latency spike detected!
- CPU 5: DSQ latency jumped to 3.2ms
- Process: mysqld (PID 2345)
- 15 consecutive high-latency sched_switch events
- Appears to be blocking on lock contention

[10:31:22] Pattern identified:
- MySQL is migrating rapidly (8 migrations in 7 seconds)
- Moving between CPUs 4-7 on same LLC
- Suggest checking MySQL connection pool settings

[10:31:45] Latencies returning to normal (< 150μs)
```

### 4. Performance Tuning

**You:** "My workload is throughput-focused. How should I optimize?"

**Claude:** I'll use the `analyze_scheduler_performance` prompt with focus on throughput.

*Claude uses the tools to gather data:*
- `query_stats` to discover available metrics
- Reads `stats://aggregated/llc` for cache efficiency
- Reads `stats://scheduler/raw` for scheduler-specific config
- Uses `get_topology` with full detail for NUMA layout

**Response:**
```
Throughput Optimization Analysis:

Current State:
- Context switch rate: 8,200/sec (moderate)
- CPU utilization: 78% average, but uneven (60-95% range)
- LLC hit rate: Good on LLC 0 (92%), poor on LLC 1 (76%)
- Migration rate: 120/sec (high for throughput workload)

Optimizations Recommended:

1. Reduce Migration Rate:
   - Current scheduler (scx_rusty) is optimizing for latency
   - Consider tuning migration threshold parameters
   - Increase task_load_weight to make tasks "stickier"

2. Improve Cache Locality:
   - LLC 1 shows poor cache efficiency
   - Use topology to identify which processes run there
   - Consider CPU pinning for cache-intensive workloads

3. Balance CPU Load:
   - CPUs 8-11 are underutilized (60% vs 95% on CPUs 0-3)
   - May indicate poor load balancing or affinity constraints
   - Check for IRQ affinity issues with `list_events` tool

Expected Gains:
- Reducing migrations should improve throughput by 5-10%
- Better cache locality could improve by another 8-12%
- Balancing load prevents hotspot bottlenecks
```

### 5. Comparative Analysis

**You:** "Compare CPU usage across NUMA nodes"

**Claude:** Let me analyze the NUMA distribution.

*Claude queries:*
- `stats://aggregated/node` for per-node metrics
- `get_topology` for NUMA topology details
- `stats://aggregated/process` to see process placement

**Response:**
```
NUMA Node Analysis:

Node 0:
- CPUs: 0-7 (8 CPUs)
- Utilization: 82% average
- Process count: 47 processes
- Memory locality: 94% local accesses
- Top consumers: postgres (28%), nginx (15%)

Node 1:
- CPUs: 8-15 (8 CPUs)
- Utilization: 38% average
- Process count: 23 processes
- Memory locality: 87% local accesses
- Top consumers: backup-daemon (12%), monitoring (8%)

Imbalance Detected:
- Node 0 is heavily loaded while Node 1 is underutilized
- 2.2x difference in utilization
- No apparent affinity constraints preventing better balance

Recommendations:
- Check if scheduler is NUMA-aware (should prefer local memory)
- Consider manually distributing some Node 0 workloads
- Investigate why backup-daemon isn't utilizing available capacity
```

### 6. Stack Trace Profiling

**You:** "Profile the system for 10 seconds and show me the hottest functions"

**Claude:** I'll start perf profiling to collect stack traces.

*Claude uses the tools:*
- `start_perf_profiling` with freq=99, duration_secs=10
- Waits for collection to complete
- Uses `get_perf_results` to retrieve symbolized stack traces

**Response:**
```
Perf Profiling Results (99 Hz for 10 seconds):

Top Functions by CPU Time:
1. schedule (18.3%, kernel)
   - Core scheduler function
   - Stack trace shows calls from do_nanosleep, futex_wait
   - Normal overhead for workload with many blocking syscalls

2. copy_user_enhanced_fast_string (12.1%, kernel)
   - Memory copy operations
   - Heavy userspace ↔ kernel data transfers
   - Top callers: sys_read (45%), sys_write (38%)

3. mysql_execute_command (8.7%, mysqld)
   - User: /usr/bin/mysqld
   - File: sql/sql_parse.cc:4523
   - Most time in query parsing and execution

4. __GI___poll (5.2%, libc)
   - Blocking I/O operations
   - Stack: nginx worker → epoll_wait → poll
   - Shows nginx is I/O bound, not CPU bound

5. scx_bpf_dispatch (3.8%, [scx_rusty])
   - Scheduler BPF program overhead
   - P50: 245ns, P99: 1.2μs per call
   - Call rate: 8,200 calls/sec

Analysis:
- System is I/O and synchronization bound (schedule + poll = 23.5%)
- High memory copy overhead suggests optimization opportunity
- MySQL query parsing is consuming significant CPU
- Scheduler overhead is reasonable (3.8%)

Recommendations:
1. Investigate copy_user patterns - may benefit from batching
2. MySQL: Consider prepared statements to reduce parsing
3. No abnormal kernel spinlock or contention detected
4. Scheduler overhead is healthy for this workload
```

**You:** "Show me the kernel stack trace for the schedule function"

**Claude:** Here's the detailed stack trace:
```
schedule (kernel)
├─ do_nanosleep (42% of samples)
│  ├─ hrtimer_nanosleep
│  ├─ common_nsleep
│  └─ __x64_sys_nanosleep
│     └─ do_syscall_64
│        └─ entry_SYSCALL_64_after_hwframe
│
├─ futex_wait_queue (31% of samples)
│  ├─ futex_wait
│  ├─ do_futex
│  └─ __x64_sys_futex
│     └─ do_syscall_64
│        └─ entry_SYSCALL_64_after_hwframe
│
└─ io_schedule (27% of samples)
   ├─ wait_on_page_bit
   ├─ filemap_fault
   └─ __do_fault
      └─ do_fault
         └─ handle_pf_instruction
            └─ exc_page_fault

Most common paths show normal blocking patterns - no issues detected.
```

## Available Prompts

You can ask Claude to:
- **"Analyze my scheduler's performance"** → General performance analysis
- **"Debug high latency for process X"** → Latency investigation
- **"Analyze CPU load imbalance"** → Load balancing analysis
- **"Investigate scheduler behavior"** → Deep dive into scheduling decisions
- **"Summarize my system"** → Quick system overview
- **"Profile the system and identify bottlenecks"** → Stack trace profiling

## Profiling Events

The MCP server exposes available perf events and kprobe functions:

**Query available profiling events:**
```
"What perf events are available on this system?"
→ Claude reads: events://perf

"Show me available kprobe functions for profiling"
→ Claude reads: events://kprobe

"What profiling events would you recommend for analyzing scheduler overhead?"
→ Claude combines events://perf and events://kprobe data with recommendations

"Show me all loaded BPF programs and their overhead"
→ Claude reads: bpf://programs
→ Returns program IDs, names, types, runtime, and execution counts
```

## Advanced Queries

**Query specific statistics:**
```
"Show me per-CPU dispatch queue latencies"
→ Claude reads: stats://aggregated/dsq

"What's the current scheduler and its configuration?"
→ Claude reads: scheduler://current and stats://scheduler/raw

"List all scheduler-related perf events"
→ Claude calls: list_events tool with subsystem="sched"
```

**Combine multiple data sources:**
```
"Find processes with high scheduling latency and correlate with CPU placement"
→ Claude reads: stats://aggregated/process, stats://aggregated/cpu
→ Claude calls: get_topology to understand CPU relationships
```

**Time-based analysis (daemon mode):**
```
"Monitor for the next 60 seconds and tell me if you see any anomalies"
→ Claude subscribes: events://stream
→ Processes real-time sched_switch, wakeup, migration events
→ Reports patterns and outliers
```

## Benefits

1. **Natural Language Interface**: Ask questions in plain English
2. **Guided Workflows**: Claude follows structured analysis patterns
3. **Contextual Understanding**: Claude correlates multiple data sources
4. **Proactive Analysis**: In daemon mode, Claude can spot issues you didn't ask about
5. **Actionable Recommendations**: Get specific tuning suggestions based on your workload

## Claude Code Command Line Examples

Claude Code provides a CLI for direct interaction with the MCP server:

**Quick queries:**
```bash
# System overview
claude --mcp scxtop "Summarize my system's scheduler and hardware"

# Check specific process
claude --mcp scxtop "Analyze scheduling behavior for process 1234"

# Performance analysis
claude --mcp scxtop "Are there any CPU load imbalances?"

# Latency investigation
claude --mcp scxtop "Debug high scheduling latency issues"
```

**Interactive session:**
```bash
# Start an interactive session with scxtop MCP available
claude --mcp scxtop

# Now you can ask questions naturally:
> What scheduler is currently running?
> Show me per-CPU utilization
> Which processes have the highest scheduling latency?
> Compare load across NUMA nodes
```

**Using prompts directly:**
```bash
# Invoke a specific workflow prompt
claude --mcp scxtop --prompt summarize_system

# Prompt with arguments
claude --mcp scxtop --prompt debug_high_latency --arg pid=5678
claude --mcp scxtop --prompt analyze_scheduler_performance --arg focus_area=latency
```

**Combining with code tasks:**
```bash
# Analyze scheduler and suggest kernel config changes
claude --mcp scxtop "Analyze my scheduler performance and suggest \
  appropriate kernel configuration parameters for my workload"

# Generate a report
claude --mcp scxtop "Create a markdown report of my system's scheduler \
  performance including hardware topology, current utilization, and \
  recommendations" > scheduler-report.md
```

## Requirements

- scxtop built with MCP support
- Claude Desktop or Claude Code CLI
- Scheduler running (ideally sched_ext for full features)
- Root/sudo access for scxtop BPF operations
