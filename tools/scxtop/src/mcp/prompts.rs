// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::protocol::{McpPrompt, McpPromptArgument};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub struct McpPrompts {}

impl Default for McpPrompts {
    fn default() -> Self {
        Self::new()
    }
}

impl McpPrompts {
    pub fn new() -> Self {
        Self {}
    }

    pub fn list(&self) -> Value {
        let prompts = vec![
            McpPrompt {
                name: "analyze_scheduler_performance".to_string(),
                description: Some(
                    "Comprehensive scheduler performance analysis workflow".to_string(),
                ),
                arguments: Some(vec![McpPromptArgument {
                    name: "focus_area".to_string(),
                    description: Some(
                        "Area to focus on: latency, throughput, or balance".to_string(),
                    ),
                    required: false,
                }]),
            },
            McpPrompt {
                name: "debug_high_latency".to_string(),
                description: Some("Debug high scheduling latency issues".to_string()),
                arguments: Some(vec![McpPromptArgument {
                    name: "pid".to_string(),
                    description: Some("Process ID to investigate (optional)".to_string()),
                    required: false,
                }]),
            },
            McpPrompt {
                name: "analyze_cpu_imbalance".to_string(),
                description: Some("Analyze CPU load imbalance and migration patterns".to_string()),
                arguments: None,
            },
            McpPrompt {
                name: "investigate_scheduler_behavior".to_string(),
                description: Some("Deep dive into scheduler behavior and policies".to_string()),
                arguments: Some(vec![McpPromptArgument {
                    name: "scheduler_name".to_string(),
                    description: Some("Specific scheduler to analyze (optional)".to_string()),
                    required: false,
                }]),
            },
            McpPrompt {
                name: "summarize_system".to_string(),
                description: Some("Comprehensive system and scheduler summary".to_string()),
                arguments: None,
            },
        ];

        json!({ "prompts": prompts })
    }

    pub fn get(&self, name: &str, params: &Value) -> Result<Value> {
        let arguments = params.get("arguments").and_then(|v| v.as_object());

        match name {
            "analyze_scheduler_performance" => self.prompt_analyze_scheduler_performance(arguments),
            "debug_high_latency" => self.prompt_debug_high_latency(arguments),
            "analyze_cpu_imbalance" => self.prompt_analyze_cpu_imbalance(),
            "investigate_scheduler_behavior" => {
                self.prompt_investigate_scheduler_behavior(arguments)
            }
            "summarize_system" => self.prompt_summarize_system(),
            _ => Err(anyhow!("Unknown prompt: {}", name)),
        }
    }

    fn prompt_analyze_scheduler_performance(
        &self,
        arguments: Option<&serde_json::Map<String, Value>>,
    ) -> Result<Value> {
        let focus_area = arguments
            .and_then(|a| a.get("focus_area"))
            .and_then(|v| v.as_str())
            .unwrap_or("general");

        let workflow = match focus_area {
            "latency" => {
                r#"# Scheduler Latency Analysis Workflow

## 1. Check Current Scheduler
First, identify which scheduler is running:
- Read resource: `scheduler://current`
- Check if it's a sched_ext scheduler or the default CFS

## 2. Examine Dispatch Queue Latencies
For sched_ext schedulers, check DSQ latencies:
- Read resource: `stats://aggregated/dsq`
- Look for high `dsq_lat_us` values
- Identify queues with long wait times

## 3. Analyze Per-CPU Scheduling Delays
- Read resource: `stats://aggregated/cpu`
- Compare scheduling latency across CPUs
- Identify CPUs with unusually high latency

## 4. Check Process-Level Metrics
- Read resource: `stats://aggregated/process`
- Sort by scheduling latency or wait time
- Identify processes experiencing high latency

## 5. Monitor Real-Time Events (Daemon Mode)
If running in daemon mode:
- Subscribe to: `events://stream`
- Watch for `sched_wakeup` → `sched_switch` delays
- Track `dsq_lat_us` in sched_switch events

## 6. Check Hardware Topology
- Use tool: `get_topology` with `detail_level: "full"`
- Verify NUMA node distances
- Check LLC sharing patterns

## Key Metrics to Monitor:
- DSQ latency: < 100µs is good, > 1ms needs investigation
- Wakeup-to-run delay: Should be minimal for RT tasks
- Per-CPU scheduling rate: Balanced across cores
"#
            }
            "throughput" => {
                r#"# Scheduler Throughput Analysis Workflow

## 1. Measure Context Switch Rate
- Read resource: `stats://system/cpu`
- Check context switch rate (ctxt/sec)
- Compare against baseline expectations

## 2. Analyze CPU Utilization
- Read resource: `stats://aggregated/cpu`
- Check per-CPU utilization
- Identify idle or overloaded CPUs

## 3. Review Scheduler Statistics
- Read resource: `stats://scheduler/scx`
- Check dispatch counts
- Monitor stall indicators

## 4. Check Process Distribution
- Read resource: `stats://aggregated/process`
- Count active processes per CPU
- Look for concentration on few CPUs

## 5. Examine LLC Domain Efficiency
- Read resource: `stats://aggregated/llc`
- Compare throughput across cache domains
- Identify LLC contention

## 6. Monitor Migration Patterns
In daemon mode:
- Subscribe to: `events://stream`
- Track `sched_migrate_task` events
- High migration rate may hurt throughput

## Performance Indicators:
- High context switch rate: Could indicate overhead
- Idle CPUs with runnable tasks: Load balancing issue
- Uneven LLC utilization: Potential optimization opportunity
"#
            }
            "balance" => {
                r#"# Load Balance Analysis Workflow

## 1. Check Per-CPU Load
- Read resource: `stats://aggregated/cpu`
- Compare utilization across all CPUs
- Calculate standard deviation

## 2. Analyze NUMA Balance
- Read resource: `stats://aggregated/node`
- Check distribution across NUMA nodes
- Verify memory locality

## 3. Review LLC Domain Balance
- Read resource: `stats://aggregated/llc`
- Compare load across cache domains
- Identify hot LLCs

## 4. Monitor Migration Activity
In daemon mode:
- Subscribe to: `events://stream`
- Count `sched_migrate_task` events
- Track migration sources and destinations

## 5. Check Topology
- Use tool: `get_topology`
- Understand core/LLC/NUMA layout
- Verify SMT configuration

## 6. Analyze Task Affinity
- Read resource: `stats://aggregated/process`
- Check if tasks are pinned
- Review per-process CPU usage

## Balance Metrics:
- CPU utilization variance: < 10% is well-balanced
- Migration rate: Should be stable, not oscillating
- NUMA remote accesses: Minimize for memory-bound workloads
"#
            }
            _ => {
                r#"# General Scheduler Performance Analysis

## 1. System Overview
- Read resource: `scheduler://current` - Check active scheduler
- Use tool: `get_topology` - Understand hardware layout
- Read resource: `stats://system/cpu` - System-wide metrics

## 2. Scheduler-Specific Analysis
For sched_ext schedulers:
- Read resource: `stats://scheduler/raw` - Raw scheduler stats
- Read resource: `stats://scheduler/scx` - Kernel-level stats
- Read resource: `stats://aggregated/dsq` - Dispatch queue metrics

## 3. Resource Distribution
- Read resource: `stats://aggregated/cpu` - Per-CPU breakdown
- Read resource: `stats://aggregated/llc` - Cache domain view
- Read resource: `stats://aggregated/node` - NUMA perspective

## 4. Process-Level Insights
- Read resource: `stats://aggregated/process` - Per-process stats
- Identify top CPU consumers
- Check for scheduling outliers

## 5. Real-Time Monitoring (Daemon Mode)
- Subscribe to: `events://stream`
- Monitor scheduling decisions in real-time
- Track latency-critical events

## Quick Start:
Use `query_stats` tool with different stat_types to discover
available metrics, then read the appropriate resources.
"#
            }
        };

        Ok(json!({
            "description": format!("Scheduler performance analysis focused on: {}", focus_area),
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": workflow
                }
            }]
        }))
    }

    fn prompt_debug_high_latency(
        &self,
        arguments: Option<&serde_json::Map<String, Value>>,
    ) -> Result<Value> {
        let pid = arguments
            .and_then(|a| a.get("pid"))
            .and_then(|v| v.as_i64())
            .map(|p| p.to_string())
            .unwrap_or_else(|| "any process".to_string());

        let workflow = format!(
            r#"# Debug High Scheduling Latency

Target: {}

## Investigation Steps

### 1. Identify the Problem Scope
- Read resource: `scheduler://current`
- Check which scheduler is active
- Note: sched_ext provides more detailed metrics

### 2. Measure Current Latency
For specific process (if PID provided):
- Read resource: `stats://aggregated/process`
- Filter for PID: {}
- Check scheduling latency and vtime metrics

For system-wide view:
- Read resource: `stats://aggregated/dsq`
- Look for high `dsq_lat_us` values
- Identify problematic dispatch queues

### 3. Find the Bottleneck CPU
- Read resource: `stats://aggregated/cpu`
- Sort by scheduling latency
- Identify CPUs with high latency
- Check runqueue depths

### 4. Check Hardware Factors
- Use tool: `get_topology` with `detail_level: "full"`
- Verify CPU frequencies (min_freq, max_freq)
- Check for CPU capacity issues
- Review NUMA topology

### 5. Monitor Real-Time Behavior (Daemon Mode)
Subscribe to event stream and watch for:
- Long `dsq_lat_us` in sched_switch events
- Delays between sched_waking and sched_switch
- Frequent migrations (sched_migrate_task)

Filter events for target process:
```
events where pid == {}
```

### 6. Analyze Wakeup Patterns
Look for:
- Frequent wakeups from same waker
- Cross-LLC or cross-NUMA wakeups
- Interrupt-driven wakeups (check SoftIRQ events)

### 7. Check for Resource Contention
- Read resource: `stats://aggregated/llc`
- Check cache domain contention
- Read resource: `stats://aggregated/node`
- Verify memory locality

## Common Causes:
1. **High CPU load**: Check overall system utilization
2. **Poor cache locality**: Look at LLC statistics
3. **NUMA imbalance**: Verify node distribution
4. **Scheduler configuration**: Review sched_ext params
5. **Hardware throttling**: Check CPU frequencies

## Remediation Ideas:
- Adjust task placement (CPU affinity)
- Tune scheduler parameters (if sched_ext)
- Address system-wide contention
- Consider CPU frequency scaling
"#,
            pid, pid, pid
        );

        Ok(json!({
            "description": format!("Debug high scheduling latency for: {}", pid),
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": workflow
                }
            }]
        }))
    }

    fn prompt_analyze_cpu_imbalance(&self) -> Result<Value> {
        let workflow = r#"# Analyze CPU Load Imbalance

## 1. Measure Imbalance Severity
- Read resource: `stats://aggregated/cpu`
- Calculate utilization variance across CPUs
- Identify overloaded and idle CPUs
- Check runqueue depths

## 2. Understand Topology
- Use tool: `get_topology`
- Note core/LLC/NUMA organization
- Check SMT configuration
- Verify online CPU count

## 3. Review Load Distribution
By cache domain:
- Read resource: `stats://aggregated/llc`
- Compare utilization across LLCs
- Check for hot LLCs

By NUMA node:
- Read resource: `stats://aggregated/node`
- Verify NUMA balance
- Check memory locality

## 4. Identify Migration Patterns
In daemon mode:
- Subscribe to: `events://stream`
- Count `sched_migrate_task` events per minute
- Track common migration paths (source CPU → dest CPU)
- Look for oscillation (tasks bouncing between CPUs)

## 5. Analyze Task Characteristics
- Read resource: `stats://aggregated/process`
- Group by CPU assignment
- Check for pinned tasks (affinity masks)
- Identify CPU-intensive vs I/O-bound tasks

## 6. Check Scheduler Behavior
For sched_ext:
- Read resource: `stats://scheduler/raw`
- Review load balancing settings
- Check layer or partition configuration

For CFS:
- Read resource: `stats://scheduler/scx` (limited)
- Note: Use standard Linux tools for CFS analysis

## 7. Root Cause Analysis

### Common Imbalance Causes:
1. **Task Affinity**: Processes pinned to specific CPUs
2. **NUMA Locality**: Scheduler keeping tasks near memory
3. **Cache Affinity**: Avoiding LLC misses
4. **Interrupt Affinity**: IRQs pinned to specific CPUs
5. **Scheduler Policy**: Intentional imbalance for latency

### Investigation Checklist:
- [ ] Are there pinned tasks? (Check /proc/PID/status)
- [ ] Is this intentional for performance?
- [ ] Are IRQs balanced? (Check /proc/interrupts)
- [ ] Is NUMA topology well-understood by scheduler?
- [ ] Are some CPUs in power-saving states?

## 8. Remediation Options

### For sched_ext schedulers:
- Adjust layer weights
- Tune load balancing aggressiveness
- Modify migration thresholds

### System-level:
- Use `taskset` to redistribute pinned tasks
- Balance IRQ affinity with `irqbalance`
- Adjust CPU frequency governor
- Consider CPU isolation for real-time tasks

## Expected Balance:
- Utilization variance: < 10% for CPU-bound workloads
- Migration rate: Stable, not oscillating
- Per-LLC balance: More important than per-CPU for throughput
"#;

        Ok(json!({
            "description": "Analyze and debug CPU load imbalance issues",
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": workflow
                }
            }]
        }))
    }

    fn prompt_investigate_scheduler_behavior(
        &self,
        arguments: Option<&serde_json::Map<String, Value>>,
    ) -> Result<Value> {
        let scheduler_filter = arguments
            .and_then(|a| a.get("scheduler_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let workflow = if !scheduler_filter.is_empty() {
            format!(
                r#"# Investigate Scheduler Behavior: {}

## 1. Verify Scheduler
- Read resource: `scheduler://current`
- Confirm {} is active
- Check scheduler class and state

## 2. Scheduler-Specific Metrics
- Read resource: `stats://scheduler/raw`
- Review {}-specific statistics
- Check configuration parameters

## 3. Kernel-Level Stats
- Read resource: `stats://scheduler/scx`
- Monitor kernel scheduler counters
- Check for error conditions

## 4. Dispatch Queue Analysis
- Read resource: `stats://aggregated/dsq`
- Review all dispatch queues
- Check latencies and depths
- Identify queue characteristics

## 5. Decision Pattern Analysis
In daemon mode, monitor scheduling decisions:
- Subscribe to: `events://stream`
- Watch `sched_switch` events for:
  - DSQ ID assignments
  - Slice allocations (slice_ns)
  - Vtime progression
  - Layer assignments (if layered)

## 6. Task Placement Patterns
- Read resource: `stats://aggregated/process`
- Group by layer_id (if applicable)
- Analyze vtime distribution
- Check task_util values

## 7. Performance Characteristics
- Read resource: `stats://aggregated/cpu`
- Compare performance across CPUs
- Check for scheduling hot spots
- Verify load distribution aligns with policy

## {}-Specific Considerations:
- Review scheduler documentation
- Check for known tuning parameters
- Look for scheduler-specific event types
- Monitor custom metrics in raw stats

## Questions to Answer:
1. Is the scheduler making expected decisions?
2. Are tasks placed according to policy?
3. Is preemption behavior correct?
4. Are latency targets being met?
5. Is load balancing working as designed?
"#,
                scheduler_filter, scheduler_filter, scheduler_filter, scheduler_filter
            )
        } else {
            r#"# Investigate General Scheduler Behavior

## 1. Identify Active Scheduler
- Read resource: `scheduler://current`
- Note scheduler name and class
- Check if sched_ext or traditional (CFS/RT)

## 2. Gather Scheduler Statistics
For sched_ext schedulers:
- Read resource: `stats://scheduler/raw`
- Read resource: `stats://scheduler/scx`
- Read resource: `stats://aggregated/dsq`

For traditional schedulers:
- Use standard Linux tools (schedtool, chrt)
- Check /proc/sched_debug

## 3. Understand Scheduling Decisions
Monitor in real-time (daemon mode):
- Subscribe to: `events://stream`
- Observe sched_switch patterns
- Track task migrations
- Note preemption behavior

## 4. Analyze Resource Distribution
- Read resource: `stats://aggregated/cpu`
- Read resource: `stats://aggregated/llc`
- Read resource: `stats://aggregated/node`
- Read resource: `stats://aggregated/process`

## 5. Check Hardware Topology
- Use tool: `get_topology` with `detail_level: "full"`
- Understand CPU/LLC/NUMA layout
- Verify scheduler awareness of topology

## 6. Evaluate Performance
Key metrics to check:
- Scheduling latency
- Context switch rate
- Migration frequency
- Load balance quality
- Throughput

## 7. Compare Against Expectations
Questions to answer:
- Does behavior match scheduler documentation?
- Are latency/throughput goals met?
- Is load balancing effective?
- Are there unexpected patterns?

## Common Investigation Patterns:

### For Latency-Sensitive Workloads:
- Check DSQ latencies
- Monitor wakeup-to-run delays
- Verify preemption behavior

### For Throughput Workloads:
- Check CPU utilization
- Monitor cache efficiency
- Verify load distribution

### For Mixed Workloads:
- Check layer separation (if layered scheduler)
- Verify priority handling
- Monitor resource isolation
"#
            .to_string()
        };

        Ok(json!({
            "description": "Deep investigation of scheduler behavior and policies",
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": workflow
                }
            }]
        }))
    }

    fn prompt_summarize_system(&self) -> Result<Value> {
        let workflow = r#"# Comprehensive System and Scheduler Summary

## 1. Hardware Overview
- Use tool: `get_topology`
- Get summary of CPUs, cores, LLCs, NUMA nodes
- Note SMT configuration
- Check CPU frequency ranges

## 2. Active Scheduler
- Read resource: `scheduler://current`
- Identify scheduler name and class
- Check if sched_ext is active

## 3. System-Wide Statistics
- Read resource: `stats://system/cpu`
- Read resource: `stats://system/memory`
- Read resource: `stats://system/network`
- Get overall resource utilization

## 4. Scheduler Performance
For sched_ext:
- Read resource: `stats://scheduler/raw`
- Read resource: `stats://scheduler/scx`
- Get key performance indicators

## 5. Resource Distribution
- Read resource: `stats://aggregated/cpu`
- Read resource: `stats://aggregated/llc`
- Read resource: `stats://aggregated/node`
- Understand load distribution

## 6. Process Overview
- Read resource: `stats://aggregated/process`
- Identify top CPU consumers
- Check process count and distribution

## 7. Available Events (for Tracing)
- Use tool: `list_events` with required `subsystem` parameter (e.g., "sched", "irq", "power")
- See available kprobes and perf events for the specified subsystem
- Note: Useful for detailed profiling

## 8. Available Statistics Resources
- Use tool: `query_stats`
- Get complete list of queryable resources
- Understand what data is available

## Summary Checklist:
- [ ] Hardware topology understood
- [ ] Scheduler identified and characterized
- [ ] System resource utilization checked
- [ ] Load distribution analyzed
- [ ] Top processes identified
- [ ] Monitoring capabilities noted

## Next Steps:
Based on the summary, you can:
1. Dive deeper with specific analysis prompts
2. Monitor real-time events in daemon mode
3. Investigate specific performance issues
4. Tune scheduler parameters if needed

Use the other prompts for focused analysis:
- `analyze_scheduler_performance` - Detailed performance analysis
- `debug_high_latency` - Latency issue investigation
- `analyze_cpu_imbalance` - Load balancing analysis
- `investigate_scheduler_behavior` - Scheduler policy deep-dive
"#;

        Ok(json!({
            "description": "Get a comprehensive overview of the system and scheduler state",
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": workflow
                }
            }]
        }))
    }
}
