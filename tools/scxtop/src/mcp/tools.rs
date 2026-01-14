// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::memory_aware_limits::MemoryAwareLimits;
use super::perf_profiling::{PerfProfilingConfig, SharedPerfProfiler};
use super::protocol::McpTool;
use super::SharedAnalyzerControl;
use anyhow::{anyhow, Result};
use perfetto_protos::ftrace_event::ftrace_event;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

type TraceCache =
    Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<super::PerfettoTrace>>>>;

pub struct McpTools {
    topo: Option<Arc<scx_utils::Topology>>,
    perf_profiler: Option<SharedPerfProfiler>,
    event_control: Option<super::SharedEventControl>,
    analyzer_control: Option<SharedAnalyzerControl>,
    trace_cache: Option<TraceCache>,
    mem_limits: MemoryAwareLimits,
}

impl Default for McpTools {
    fn default() -> Self {
        Self::new()
    }
}

impl McpTools {
    pub fn new() -> Self {
        Self {
            topo: None,
            perf_profiler: None,
            event_control: None,
            analyzer_control: None,
            trace_cache: None,
            mem_limits: MemoryAwareLimits::new(),
        }
    }

    pub fn set_trace_cache(
        &mut self,
        cache: Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<super::PerfettoTrace>>>>,
    ) {
        self.trace_cache = Some(cache);
    }

    pub fn set_topology(&mut self, topo: Arc<scx_utils::Topology>) {
        self.topo = Some(topo);
    }

    pub fn set_perf_profiler(&mut self, profiler: SharedPerfProfiler) {
        self.perf_profiler = Some(profiler);
    }

    pub fn set_event_control(&mut self, control: super::SharedEventControl) {
        self.event_control = Some(control);
    }

    pub fn set_analyzer_control(&mut self, control: SharedAnalyzerControl) {
        self.analyzer_control = Some(control);
    }

    pub fn list(&self) -> Value {
        let tools = vec![
            McpTool {
                name: "query_stats".to_string(),
                description:
                    "Get information about available statistics resources and how to query them"
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "stat_type": {
                            "type": "string",
                            "enum": ["cpu", "llc", "node", "dsq", "process", "scheduler", "system"],
                            "description": "Type of statistics to get information about (optional)"
                        }
                    }
                }),
            },
            McpTool {
                name: "get_topology".to_string(),
                description: "Get detailed hardware topology with core/LLC/node mappings"
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "include_offline": {
                            "type": "boolean",
                            "description": "Include offline CPUs",
                            "default": false
                        },
                        "detail_level": {
                            "type": "string",
                            "enum": ["summary", "full"],
                            "description": "Level of detail to return",
                            "default": "summary"
                        }
                    }
                }),
            },
            McpTool {
                name: "list_event_subsystems".to_string(),
                description:
                    "List available event subsystems and types without returning all events"
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "event_type": {
                            "type": "string",
                            "enum": ["kprobe", "perf", "all"],
                            "description": "Type of events to get subsystems for (default: all)",
                            "default": "all"
                        }
                    }
                }),
            },
            McpTool {
                name: "list_events".to_string(),
                description:
                    "List available profiling events (kprobes and perf events) that can be traced with pagination and filtering"
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "event_type": {
                            "type": "string",
                            "enum": ["kprobe", "perf"],
                            "description": "Type of events to list (required)"
                        },
                        "subsystem": {
                            "type": "string",
                            "description": "Filter perf events by subsystem (e.g., 'sched', 'irq', 'power'). Required when event_type is 'perf'."
                        },
                        "filter": {
                            "type": "string",
                            "description": "Regex pattern to filter event names (case-insensitive)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of events to return (default: 100, max: 1000)",
                            "default": 100,
                            "minimum": 1,
                            "maximum": 1000
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Number of events to skip for pagination (default: 0)",
                            "default": 0,
                            "minimum": 0
                        }
                    },
                    "required": ["event_type"]
                }),
            },
            McpTool {
                name: "start_perf_profiling".to_string(),
                description: "Start perf profiling with stack trace collection and symbolization"
                    .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "event": {
                            "type": "string",
                            "description": "Event to profile: 'hw:cpu-clock', 'sw:task-clock', or 'tracepoint:subsystem:event'",
                            "default": "hw:cpu-clock"
                        },
                        "freq": {
                            "type": "integer",
                            "description": "Sampling frequency in Hz (e.g., 99)",
                            "default": 99
                        },
                        "cpu": {
                            "type": "integer",
                            "description": "CPU to profile (-1 for all CPUs)",
                            "default": -1
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Process ID to profile (-1 for system-wide)",
                            "default": -1
                        },
                        "max_samples": {
                            "type": "integer",
                            "description": "Maximum samples to collect (0 for unlimited)",
                            "default": 10000
                        },
                        "duration_secs": {
                            "type": "integer",
                            "description": "Duration in seconds (0 for manual stop)",
                            "default": 0
                        }
                    }
                }),
            },
            McpTool {
                name: "stop_perf_profiling".to_string(),
                description: "Stop perf profiling and prepare results for retrieval".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            McpTool {
                name: "get_perf_results".to_string(),
                description:
                    "Get perf profiling results with symbolized stack traces and top functions"
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Number of top symbols to return",
                            "default": 50
                        },
                        "include_stacks": {
                            "type": "boolean",
                            "description": "Include full symbolized stack traces",
                            "default": true
                        }
                    }
                }),
            },
            McpTool {
                name: "control_event_tracking".to_string(),
                description:
                    "Enable or disable BPF event tracking to control system overhead in daemon mode"
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["enable", "disable", "status"],
                            "description": "Action to perform: enable, disable, or get status"
                        }
                    },
                    "required": ["action"]
                }),
            },
            McpTool {
                name: "control_stats_collection".to_string(),
                description:
                    "Start or stop BPF program statistics collection with configurable interval"
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["start", "stop", "status"],
                            "description": "Action to perform: start, stop, or get status"
                        },
                        "interval_ms": {
                            "type": "integer",
                            "description": "Collection interval in milliseconds (default: 100ms, only used with 'start')",
                            "default": 100,
                            "minimum": 10,
                            "maximum": 10000
                        }
                    },
                    "required": ["action"]
                }),
            },
            McpTool {
                name: "control_analyzers".to_string(),
                description:
                    "Control event analyzers (start, stop, reset, or get status). Analyzers include: waker_wakee_analyzer, latency_tracker, cpu_hotspot_analyzer, migration_analyzer, process_history, dsq_monitor, rate_monitor, wakeup_tracker, event_buffer, softirq_analyzer."
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["start", "stop", "reset", "status"],
                            "description": "Action to perform on the analyzer(s)"
                        },
                        "analyzer": {
                            "type": "string",
                            "enum": ["waker_wakee_analyzer", "latency_tracker", "cpu_hotspot_analyzer", "migration_analyzer", "process_history", "dsq_monitor", "rate_monitor", "wakeup_tracker", "event_buffer", "softirq_analyzer", "all"],
                            "description": "Which analyzer to control (use 'all' to control all analyzers)",
                            "default": "all"
                        }
                    },
                    "required": ["action"]
                }),
            },
            McpTool {
                name: "analyze_waker_wakee".to_string(),
                description:
                    "Analyze waker/wakee relationships to find critical task dependencies, latencies, and scheduler behavior. Returns tasks with most impactful wakeup relationships."
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "enum": ["critical", "frequency", "latency", "bidirectional", "for_pid", "summary"],
                            "description": "Analysis mode: 'critical' (by criticality score), 'frequency' (most frequent), 'latency' (highest latency), 'bidirectional' (mutex/semaphore patterns), 'for_pid' (relationships for specific PID), 'summary' (overview)",
                            "default": "critical"
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Specific PID to analyze (required for 'for_pid' mode)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of relationships to return",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        }
                    },
                    "required": []
                }),
            },
            McpTool {
                name: "analyze_softirq".to_string(),
                description:
                    "Analyze software interrupt (softirq) processing to identify performance bottlenecks, high-latency handlers, and CPU hotspots. Returns statistics on softirq types, durations, and system impact."
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "enum": ["summary", "by_type", "by_cpu", "by_process"],
                            "description": "Analysis mode: 'summary' (overall stats), 'by_type' (per softirq type), 'by_cpu' (per-CPU breakdown), 'by_process' (which processes handle softirqs)",
                            "default": "summary"
                        },
                        "softirq_nr": {
                            "type": "integer",
                            "description": "Specific softirq number to analyze (0=HI, 1=TIMER, 2=NET_TX, 3=NET_RX, 4=BLOCK, 5=IRQ_POLL, 6=TASKLET, 7=SCHED, 8=HRTIMER, 9=RCU). Optional, applies to by_cpu and by_process modes."
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of results to return (for by_cpu and by_process modes)",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 100
                        }
                    },
                    "required": []
                }),
            },
            McpTool {
                name: "load_perfetto_trace".to_string(),
                description: "Load a perfetto trace file for analysis".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to perfetto trace file (.proto)"
                        },
                        "trace_id": {
                            "type": "string",
                            "description": "Optional ID to reference this trace (defaults to filename)"
                        }
                    },
                    "required": ["file_path"]
                }),
            },
            McpTool {
                name: "query_trace_events".to_string(),
                description: "Query events from a loaded perfetto trace".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "event_type": {
                            "type": "string",
                            "enum": ["sched_switch", "sched_wakeup", "sched_waking", "sched_migrate", "softirq", "all"],
                            "description": "Type of events to query",
                            "default": "all"
                        },
                        "start_time_ns": {
                            "type": "integer",
                            "description": "Start of time range (nanoseconds, optional)"
                        },
                        "end_time_ns": {
                            "type": "integer",
                            "description": "End of time range (nanoseconds, optional)"
                        },
                        "cpu": {
                            "type": "integer",
                            "description": "Filter by CPU (optional)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of events to return",
                            "default": 1000,
                            "minimum": 1,
                            "maximum": 10000
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_trace_scheduling".to_string(),
                description: "Analyze scheduling patterns in a perfetto trace with full percentile statistics".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "analysis_type": {
                            "type": "string",
                            "enum": ["cpu_utilization", "process_runtime", "wakeup_latency", "migration_patterns", "dsq_summary", "task_states", "preemptions", "wakeup_chains", "latency_breakdown", "irq_analysis", "ipi_analysis", "block_io", "network_io", "memory_pressure", "file_io", "cpu_frequency", "cpu_idle", "power_state"],
                            "description": "Type of analysis to perform"
                        },
                        "use_parallel": {
                            "type": "boolean",
                            "description": "Use multi-threaded analysis for better performance",
                            "default": true
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Limit results (for ranked analyses). Note: task_states is capped at 10 by default due to verbose output.",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Optional PID filter for process-specific analysis"
                        }
                    },
                    "required": ["trace_id", "analysis_type"]
                }),
            },
            McpTool {
                name: "get_process_timeline".to_string(),
                description: "Get chronological timeline of all events for a specific process".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Process ID to get timeline for"
                        },
                        "start_time_ns": {
                            "type": "integer",
                            "description": "Start of time range (optional, defaults to trace start)"
                        },
                        "end_time_ns": {
                            "type": "integer",
                            "description": "End of time range (optional, defaults to trace end)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of events to return (optional, defaults to memory-aware limit)"
                        }
                    },
                    "required": ["trace_id", "pid"]
                }),
            },
            McpTool {
                name: "get_cpu_timeline".to_string(),
                description: "Get chronological timeline of all events for a specific CPU".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "cpu": {
                            "type": "integer",
                            "description": "CPU ID to get timeline for"
                        },
                        "start_time_ns": {
                            "type": "integer",
                            "description": "Start of time range (optional, defaults to trace start)"
                        },
                        "end_time_ns": {
                            "type": "integer",
                            "description": "End of time range (optional, defaults to trace end)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of events to return (optional, defaults to memory-aware limit)"
                        }
                    },
                    "required": ["trace_id", "cpu"]
                }),
            },
            McpTool {
                name: "find_scheduling_bottlenecks".to_string(),
                description: "Automatically detect scheduling bottlenecks including high switch rates, long latencies, and excessive migration".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of bottlenecks to return",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "correlate_wakeup_to_schedule".to_string(),
                description: "Correlate wakeup events to schedule events, showing waker→wakee latencies".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Optional PID filter (shows correlations for specific process)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of correlations to return (sorted by latency)",
                            "default": 100,
                            "minimum": 1,
                            "maximum": 10000
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "export_trace_analysis".to_string(),
                description: "Export comprehensive trace analysis to JSON file".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID to export"
                        },
                        "output_path": {
                            "type": "string",
                            "description": "Output file path for JSON export"
                        },
                        "analysis_types": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["cpu_utilization", "process_runtime", "wakeup_latency", "migration", "dsq", "bottlenecks"]
                            },
                            "description": "Types of analysis to include in export (defaults to all)"
                        }
                    },
                    "required": ["trace_id", "output_path"]
                }),
            },
            McpTool {
                name: "query_trace".to_string(),
                description: "Execute generic SQL-like query on perfetto trace with filtering and aggregation".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID to query"
                        },
                        "event_type": {
                            "type": "string",
                            "description": "Filter by event type (e.g., 'sched_switch', 'sched_wakeup', 'irq_handler_entry')"
                        },
                        "cpu": {
                            "type": "integer",
                            "description": "Filter by CPU"
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Filter by PID"
                        },
                        "start_time_ns": {
                            "type": "integer",
                            "description": "Start of time range (nanoseconds)"
                        },
                        "end_time_ns": {
                            "type": "integer",
                            "description": "End of time range (nanoseconds)"
                        },
                        "field_filters": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "field": {
                                        "type": "string",
                                        "description": "Field name to filter on"
                                    },
                                    "operator": {
                                        "type": "string",
                                        "enum": ["equal", "not_equal", "greater_than", "less_than", "greater_or_equal", "less_or_equal", "contains"],
                                        "description": "Comparison operator"
                                    },
                                    "value": {
                                        "description": "Value to compare against (int or string)"
                                    }
                                },
                                "required": ["field", "operator", "value"]
                            },
                            "description": "Field-level filters (e.g., prev_state == 1, prev_comm contains 'kworker')"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of events to return",
                            "default": 1000,
                            "minimum": 1,
                            "maximum": 10000
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Number of events to skip",
                            "default": 0
                        },
                        "aggregation": {
                            "type": "object",
                            "properties": {
                                "function": {
                                    "type": "string",
                                    "enum": ["count", "count_by", "avg", "min", "max", "group_by"],
                                    "description": "Aggregation function to apply"
                                },
                                "field": {
                                    "type": "string",
                                    "description": "Field to aggregate on (required for count_by, avg, min, max, group_by)"
                                }
                            },
                            "required": ["function"]
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "discover_analyzers".to_string(),
                description: "Discover which analyzers can run on a loaded perfetto trace based on available events".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID to analyze"
                        },
                        "category": {
                            "type": "string",
                            "enum": ["scheduling", "interrupt", "io", "power", "extended", "query"],
                            "description": "Optional: Filter by analyzer category"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "get_trace_summary".to_string(),
                description: "Get comprehensive trace summary including capabilities and applicable analyzers".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID to summarize"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "run_all_analyzers".to_string(),
                description: "Run all applicable analyzers on a trace and return comprehensive results".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID to analyze"
                        },
                        "category": {
                            "type": "string",
                            "enum": ["scheduling", "interrupt", "io", "power", "extended"],
                            "description": "Optional: Run only analyzers from specific category"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "detect_outliers".to_string(),
                description: "Detect outliers in trace data across latency, runtime, and CPU metrics using statistical methods".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID to analyze"
                        },
                        "method": {
                            "type": "string",
                            "enum": ["IQR", "MAD", "StdDev", "Percentile"],
                            "description": "Outlier detection method (default: IQR)",
                            "default": "IQR"
                        },
                        "category": {
                            "type": "string",
                            "enum": ["latency", "runtime", "cpu", "all"],
                            "description": "Category of outliers to detect (default: all)",
                            "default": "all"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of outliers to return per sub-category (e.g., wakeup_latency, excessive_runtime, etc.). Default: 20",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            // Dedicated analyzer tools (one per analysis type)
            McpTool {
                name: "analyze_cpu_utilization".to_string(),
                description: "Analyze per-CPU utilization, active/idle time, and context switches".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "use_parallel": {
                            "type": "boolean",
                            "description": "Use multi-threaded analysis",
                            "default": true
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_process_runtime".to_string(),
                description: "Analyze per-process runtime, CPU time, and context switches".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "use_parallel": {
                            "type": "boolean",
                            "description": "Use multi-threaded analysis",
                            "default": true
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of top processes to return",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Optional PID filter for specific process"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_wakeup_latency".to_string(),
                description: "Analyze wakeup-to-schedule latency for tasks".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_migration_patterns".to_string(),
                description: "Analyze task migration patterns across CPUs".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_dsq".to_string(),
                description: "Analyze sched_ext dispatch queue behavior (requires sched_ext trace)".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_task_states".to_string(),
                description: "Analyze task state transitions (running, runnable, blocked, etc.). Returns verbose per-thread or per-process data.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of top processes/threads to return (capped at 10 by default due to verbose output, max 20 recommended)",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 100
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Optional PID filter"
                        },
                        "aggregation_mode": {
                            "type": "string",
                            "description": "Aggregation level: 'per_thread' (default, shows individual TIDs) or 'per_process' (aggregates by TGID, combines all threads)",
                            "enum": ["per_thread", "per_process"],
                            "default": "per_thread"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_preemptions".to_string(),
                description: "Analyze preemption patterns and involuntary context switches".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of top processes to return",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        },
                        "pid": {
                            "type": "integer",
                            "description": "Optional PID filter"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_wakeup_chains".to_string(),
                description: "Detect wakeup chains and cascading task activations".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of chains to return",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_latency_breakdown".to_string(),
                description: "Break down scheduling latency into stages (wakeup, runnable, running)".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_irq".to_string(),
                description: "Analyze hardware interrupt (IRQ) handlers and latencies".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of top IRQs to return",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_ipi".to_string(),
                description: "Analyze inter-processor interrupts (IPIs)".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of top IPI reasons to return",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_block_io".to_string(),
                description: "Analyze block device I/O operations and latencies".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_network_io".to_string(),
                description: "Analyze network I/O bandwidth and packet statistics".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_memory_pressure".to_string(),
                description: "Analyze memory allocation, freeing, and direct reclaim events".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_file_io".to_string(),
                description: "Analyze file system sync operations and latencies".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_cpu_frequency".to_string(),
                description: "Analyze CPU frequency scaling (DVFS) behavior".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of CPUs to return",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_cpu_idle".to_string(),
                description: "Analyze CPU idle state transitions and residency".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of CPUs to return",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 1000
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
            McpTool {
                name: "analyze_power_state".to_string(),
                description: "Analyze system power state transitions (suspend/resume)".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "trace_id": {
                            "type": "string",
                            "description": "Trace ID returned from load_perfetto_trace"
                        }
                    },
                    "required": ["trace_id"]
                }),
            },
        ];

        json!({ "tools": tools })
    }

    pub fn call(&mut self, params: &Value) -> Result<Value> {
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing tool name"))?;

        let empty_args = json!({});
        let arguments = params.get("arguments").unwrap_or(&empty_args);

        match name {
            "query_stats" => self.tool_query_stats(arguments),
            "get_topology" => self.tool_get_topology(arguments),
            "list_event_subsystems" => self.tool_list_event_subsystems(arguments),
            "list_events" => self.tool_list_events(arguments),
            "start_perf_profiling" => self.tool_start_perf_profiling(arguments),
            "stop_perf_profiling" => self.tool_stop_perf_profiling(arguments),
            "get_perf_results" => self.tool_get_perf_results(arguments),
            "control_event_tracking" => self.tool_control_event_tracking(arguments),
            "control_stats_collection" => self.tool_control_stats_collection(arguments),
            "control_analyzers" => self.tool_control_analyzers(arguments),
            "analyze_waker_wakee" => self.tool_analyze_waker_wakee(arguments),
            "analyze_softirq" => self.tool_analyze_softirq(arguments),
            "load_perfetto_trace" => self.tool_load_perfetto_trace(arguments),
            "query_trace_events" => self.tool_query_trace_events(arguments),
            "analyze_trace_scheduling" => self.tool_analyze_trace_scheduling(arguments),
            "get_process_timeline" => self.tool_get_process_timeline(arguments),
            "get_cpu_timeline" => self.tool_get_cpu_timeline(arguments),
            "find_scheduling_bottlenecks" => self.tool_find_scheduling_bottlenecks(arguments),
            "correlate_wakeup_to_schedule" => self.tool_correlate_wakeup_to_schedule(arguments),
            "export_trace_analysis" => self.tool_export_trace_analysis(arguments),
            "query_trace" => self.tool_query_trace(arguments),
            "discover_analyzers" => self.tool_discover_analyzers(arguments),
            "get_trace_summary" => self.tool_get_trace_summary(arguments),
            "run_all_analyzers" => self.tool_run_all_analyzers(arguments),
            "detect_outliers" => self.tool_detect_outliers(arguments),
            // Dedicated analyzer tools
            "analyze_cpu_utilization" => self.tool_analyze_cpu_utilization(arguments),
            "analyze_process_runtime" => self.tool_analyze_process_runtime(arguments),
            "analyze_wakeup_latency" => self.tool_analyze_wakeup_latency(arguments),
            "analyze_migration_patterns" => self.tool_analyze_migration_patterns(arguments),
            "analyze_dsq" => self.tool_analyze_dsq(arguments),
            "analyze_task_states" => self.tool_analyze_task_states(arguments),
            "analyze_preemptions" => self.tool_analyze_preemptions(arguments),
            "analyze_wakeup_chains" => self.tool_analyze_wakeup_chains(arguments),
            "analyze_latency_breakdown" => self.tool_analyze_latency_breakdown(arguments),
            "analyze_irq" => self.tool_analyze_irq(arguments),
            "analyze_ipi" => self.tool_analyze_ipi(arguments),
            "analyze_block_io" => self.tool_analyze_block_io(arguments),
            "analyze_network_io" => self.tool_analyze_network_io(arguments),
            "analyze_memory_pressure" => self.tool_analyze_memory_pressure(arguments),
            "analyze_file_io" => self.tool_analyze_file_io(arguments),
            "analyze_cpu_frequency" => self.tool_analyze_cpu_frequency(arguments),
            "analyze_cpu_idle" => self.tool_analyze_cpu_idle(arguments),
            "analyze_power_state" => self.tool_analyze_power_state(arguments),
            _ => Err(anyhow!("Unknown tool: {}", name)),
        }
    }

    fn tool_query_stats(&self, args: &Value) -> Result<Value> {
        let stat_type = args.get("stat_type").and_then(|v| v.as_str());

        let resources = match stat_type {
            Some("cpu") => vec![
                (
                    "stats://aggregated/cpu",
                    "Per-CPU statistics including utilization, frequency, and scheduling metrics",
                ),
                (
                    "stats://system/cpu",
                    "System-wide CPU utilization statistics",
                ),
            ],
            Some("llc") => vec![(
                "stats://aggregated/llc",
                "Statistics aggregated by last-level cache domain",
            )],
            Some("node") => vec![(
                "stats://aggregated/node",
                "Statistics aggregated by NUMA node",
            )],
            Some("dsq") => vec![(
                "stats://aggregated/dsq",
                "Dispatch queue statistics for sched_ext schedulers",
            )],
            Some("process") => vec![(
                "stats://aggregated/process",
                "Per-process scheduler statistics including runtime, vtime, and layer info",
            )],
            Some("scheduler") => vec![
                (
                    "stats://scheduler/raw",
                    "Raw JSON statistics from the scheduler's scx_stats framework",
                ),
                ("stats://scheduler/scx", "Kernel-level sched_ext statistics"),
            ],
            Some("system") => vec![
                ("stats://system/cpu", "System-wide CPU statistics"),
                ("stats://system/memory", "System memory statistics"),
                ("stats://system/network", "Network interface statistics"),
            ],
            None => vec![
                ("stats://aggregated/cpu", "Per-CPU statistics"),
                ("stats://aggregated/llc", "Per-LLC statistics"),
                ("stats://aggregated/node", "Per-NUMA-node statistics"),
                ("stats://aggregated/dsq", "Dispatch queue statistics"),
                ("stats://aggregated/process", "Per-process statistics"),
                ("stats://scheduler/raw", "Raw scheduler stats"),
                ("stats://scheduler/scx", "sched_ext kernel stats"),
                ("stats://system/cpu", "System CPU stats"),
                ("stats://system/memory", "System memory stats"),
                ("stats://system/network", "Network stats"),
            ],
            Some(t) => return Err(anyhow!("Unknown stat_type: {}", t)),
        };

        let help_text = if stat_type.is_some() {
            format!("Statistics resources for {}:\n\n", stat_type.unwrap())
        } else {
            "Available statistics resources:\n\n".to_string()
        };

        let resources_text = resources
            .iter()
            .map(|(uri, desc)| format!("• {}\n  {}", uri, desc))
            .collect::<Vec<_>>()
            .join("\n\n");

        let usage_text = "\n\nUsage:\n\
            To query statistics, use the MCP resources/read method with the desired URI.\n\
            In daemon mode, you can also subscribe to events://stream for real-time event updates.\n\n\
            Example: Read resources/read with uri=\"stats://aggregated/cpu\"";

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("{}{}{}", help_text, resources_text, usage_text)
            }]
        }))
    }

    fn tool_get_topology(&self, args: &Value) -> Result<Value> {
        let topo = self
            .topo
            .as_ref()
            .ok_or_else(|| anyhow!("Topology not available"))?;

        let _include_offline = args
            .get("include_offline")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let detail_level = args
            .get("detail_level")
            .and_then(|v| v.as_str())
            .unwrap_or("summary");

        if detail_level == "summary" {
            // Return summary information
            let topology_summary = json!({
                "summary": {
                    "total_cpus": topo.all_cpus.len(),
                    "cores": topo.all_cores.len(),
                    "llcs": topo.all_llcs.len(),
                    "numa_nodes": topo.nodes.len(),
                    "smt_enabled": topo.smt_enabled,
                },
                "hint": "Use detail_level='full' for complete topology information"
            });

            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&topology_summary)
                        .unwrap_or_else(|_| "Failed to serialize topology".to_string())
                }]
            }));
        }

        // Full detail - collect all data first to avoid borrow issues
        type CpuDataTuple = (usize, usize, usize, usize, usize, usize, usize, usize);
        let cpu_data: Vec<CpuDataTuple> = topo
            .all_cpus
            .values()
            .map(|c| {
                (
                    c.id,
                    c.core_id,
                    c.llc_id,
                    c.node_id,
                    c.min_freq,
                    c.max_freq,
                    c.base_freq,
                    c.cpu_capacity,
                )
            })
            .collect();

        let core_data: Vec<(usize, Vec<usize>)> = topo
            .all_cores
            .values()
            .map(|c| (c.id, c.span.iter().collect()))
            .collect();

        let llc_data: Vec<(usize, usize, Vec<usize>)> = topo
            .all_llcs
            .values()
            .map(|llc| (llc.id, llc.kernel_id, llc.span.iter().collect()))
            .collect();

        let node_data: Vec<(usize, Vec<usize>, Vec<usize>)> = topo
            .nodes
            .values()
            .map(|node| (node.id, node.span.iter().collect(), node.distance.clone()))
            .collect();

        // Now build JSON from collected data
        let cpus: Vec<_> = cpu_data
            .iter()
            .map(
                |(id, core_id, llc_id, node_id, min_freq, max_freq, base_freq, cpu_capacity)| {
                    json!({
                        "id": id,
                        "core_id": core_id,
                        "llc_id": llc_id,
                        "node_id": node_id,
                        "min_freq": min_freq,
                        "max_freq": max_freq,
                        "base_freq": base_freq,
                        "cpu_capacity": cpu_capacity,
                    })
                },
            )
            .collect();

        let cores: Vec<_> = core_data
            .iter()
            .map(|(id, span)| {
                json!({
                    "id": id,
                    "span": span,
                })
            })
            .collect();

        let llcs: Vec<_> = llc_data
            .iter()
            .map(|(id, kernel_id, span)| {
                json!({
                    "id": id,
                    "kernel_id": kernel_id,
                    "span": span,
                })
            })
            .collect();

        let nodes: Vec<_> = node_data
            .iter()
            .map(|(id, span, distance)| {
                json!({
                    "id": id,
                    "span": span,
                    "distance": distance,
                })
            })
            .collect();

        let topology_data = json!({
            "summary": {
                "nr_cpus": topo.all_cpus.len(),
                "nr_cores": topo.all_cores.len(),
                "nr_llcs": topo.all_llcs.len(),
                "nr_nodes": topo.nodes.len(),
                "smt_enabled": topo.smt_enabled,
            },
            "cpus": cpus,
            "cores": cores,
            "llcs": llcs,
            "nodes": nodes,
        });

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&topology_data)
                    .unwrap_or_else(|_| "Failed to serialize topology".to_string())
            }]
        }))
    }

    fn tool_list_event_subsystems(&self, args: &Value) -> Result<Value> {
        let event_type = args
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let mut result = json!({});

        if event_type == "perf" || event_type == "all" {
            let perf_events = crate::available_perf_events().unwrap_or_default();
            let subsystems: Vec<String> = perf_events.keys().cloned().collect();
            let subsystem_counts: std::collections::HashMap<String, usize> = perf_events
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect();

            result["perf_subsystems"] = json!({
                "count": subsystems.len(),
                "subsystems": subsystems,
                "event_counts": subsystem_counts,
            });
        }

        if event_type == "kprobe" || event_type == "all" {
            let kprobe_events = crate::available_kprobe_events().unwrap_or_default();
            result["kprobe_info"] = json!({
                "total_functions": kprobe_events.len(),
                "note": "Use list_events with event_type='kprobe' and a filter to search for specific functions"
            });
        }

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Failed to serialize subsystems".to_string())
            }]
        }))
    }

    fn tool_list_events(&self, args: &Value) -> Result<Value> {
        let event_type = args
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("event_type parameter is required"))?;

        let filter = args.get("filter").and_then(|v| v.as_str());
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(100)
            .min(1000) as usize;
        let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        // Compile regex if filter is provided
        let regex_filter = if let Some(pattern) = filter {
            Some(
                regex::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .map_err(|e| anyhow!("Invalid regex pattern: {}", e))?,
            )
        } else {
            None
        };

        let result = match event_type {
            "kprobe" => {
                let mut kprobe_events = crate::available_kprobe_events().unwrap_or_default();

                // Apply regex filter if provided
                if let Some(ref re) = regex_filter {
                    kprobe_events.retain(|event| re.is_match(event));
                }

                let total_count = kprobe_events.len();
                let paginated_events: Vec<String> =
                    kprobe_events.into_iter().skip(offset).take(limit).collect();

                json!({
                    "event_type": "kprobe",
                    "total_count": total_count,
                    "returned_count": paginated_events.len(),
                    "offset": offset,
                    "limit": limit,
                    "has_more": offset + paginated_events.len() < total_count,
                    "events": paginated_events,
                    "filter_applied": filter,
                })
            }
            "perf" => {
                let subsystem = args
                    .get("subsystem")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("subsystem parameter is required for perf events"))?;

                let perf_events = crate::available_perf_events().unwrap_or_default();

                if !perf_events.contains_key(subsystem) {
                    let available_subsystems: Vec<String> = perf_events.keys().cloned().collect();
                    return Err(anyhow!(
                        "Subsystem '{}' not found. Use list_event_subsystems to see available subsystems. Available: {}",
                        subsystem,
                        available_subsystems.join(", ")
                    ));
                }

                let mut events: Vec<String> = perf_events
                    .get(subsystem)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default();

                // Apply regex filter if provided
                if let Some(ref re) = regex_filter {
                    events.retain(|event| re.is_match(event));
                }

                // Sort for consistent pagination
                events.sort();

                let total_count = events.len();
                let paginated_events: Vec<String> =
                    events.into_iter().skip(offset).take(limit).collect();

                json!({
                    "event_type": "perf",
                    "subsystem": subsystem,
                    "total_count": total_count,
                    "returned_count": paginated_events.len(),
                    "offset": offset,
                    "limit": limit,
                    "has_more": offset + paginated_events.len() < total_count,
                    "events": paginated_events,
                    "filter_applied": filter,
                })
            }
            _ => return Err(anyhow!("Invalid event_type: {}", event_type)),
        };

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Failed to serialize events".to_string())
            }]
        }))
    }

    fn tool_start_perf_profiling(&self, args: &Value) -> Result<Value> {
        let profiler = self
            .perf_profiler
            .as_ref()
            .ok_or_else(|| anyhow!("Perf profiler not available"))?;

        let config = PerfProfilingConfig {
            event: args
                .get("event")
                .and_then(|v| v.as_str())
                .unwrap_or("hw:cpu-clock")
                .to_string(),
            freq: args.get("freq").and_then(|v| v.as_u64()).unwrap_or(99) as u32,
            cpu: args.get("cpu").and_then(|v| v.as_i64()).unwrap_or(-1) as i32,
            pid: args.get("pid").and_then(|v| v.as_i64()).unwrap_or(-1) as i32,
            max_samples: args
                .get("max_samples")
                .and_then(|v| v.as_u64())
                .unwrap_or(10000) as usize,
            duration_secs: args
                .get("duration_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        };

        profiler.start(config.clone())?;

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Perf profiling started:\n\
                     - Event: {}\n\
                     - Frequency: {} Hz\n\
                     - CPU: {}\n\
                     - PID: {}\n\
                     - Max samples: {}\n\
                     - Duration: {} seconds\n\n\
                     Collecting stack traces for both kernel and userspace...\n\
                     Use stop_perf_profiling to stop and get_perf_results to retrieve results.",
                    config.event,
                    config.freq,
                    if config.cpu == -1 {
                        "all".to_string()
                    } else {
                        config.cpu.to_string()
                    },
                    if config.pid == -1 {
                        "all".to_string()
                    } else {
                        config.pid.to_string()
                    },
                    if config.max_samples == 0 {
                        "unlimited".to_string()
                    } else {
                        config.max_samples.to_string()
                    },
                    if config.duration_secs == 0 {
                        "manual".to_string()
                    } else {
                        config.duration_secs.to_string()
                    }
                )
            }]
        }))
    }

    fn tool_stop_perf_profiling(&self, _args: &Value) -> Result<Value> {
        let profiler = self
            .perf_profiler
            .as_ref()
            .ok_or_else(|| anyhow!("Perf profiler not available"))?;

        profiler.stop()?;

        let status = profiler.get_status();
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Perf profiling stopped:\n\n{}",
                    serde_json::to_string_pretty(&status)
                        .unwrap_or_else(|_| "Status unavailable".to_string())
                )
            }]
        }))
    }

    fn tool_get_perf_results(&self, args: &Value) -> Result<Value> {
        let profiler = self
            .perf_profiler
            .as_ref()
            .ok_or_else(|| anyhow!("Perf profiler not available"))?;

        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        let include_stacks = args
            .get("include_stacks")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let results = profiler.get_results(limit, include_stacks);

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&results)
                    .unwrap_or_else(|_| "Failed to serialize results".to_string())
            }]
        }))
    }

    fn tool_control_event_tracking(&self, args: &Value) -> Result<Value> {
        let control = self
            .event_control
            .as_ref()
            .ok_or_else(|| anyhow!("Event control not available (daemon mode required)"))?;

        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing action parameter"))?;

        match action {
            "enable" => {
                // Note: Program selection is managed automatically by AnalyzerControl based on
                // which analyzers are enabled. Passing empty slice attaches all programs.
                control.enable_event_tracking(&[])?;
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": "BPF event tracking enabled. Scheduler events will now be collected.\n\nNote: This introduces system overhead from tracepoint handlers. Use control://events/status to check status."
                    }]
                }))
            }
            "disable" => {
                control.disable_event_tracking()?;
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": "BPF event tracking disabled. System overhead minimized.\n\nEvent handlers will return early. Use control://events/status to check status."
                    }]
                }))
            }
            "status" => {
                let enabled = control.is_event_tracking_enabled();
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "BPF Event Tracking: {}\n\nUse control_event_tracking with action='enable' or 'disable' to change.",
                            if enabled { "ENABLED (collecting events)" } else { "DISABLED (minimal overhead)" }
                        )
                    }]
                }))
            }
            _ => Err(anyhow!("Invalid action: {}", action)),
        }
    }

    fn tool_control_stats_collection(&self, args: &Value) -> Result<Value> {
        let control = self
            .event_control
            .as_ref()
            .ok_or_else(|| anyhow!("Event control not available (daemon mode required)"))?;

        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing action parameter"))?;

        match action {
            "start" => {
                let interval_ms = args
                    .get("interval_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100);

                control.start_stats_collection(interval_ms)?;
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "BPF program statistics collection started with {}ms interval.\n\nStats will be polled every {}ms. Use control://events/status to check status.",
                            interval_ms, interval_ms
                        )
                    }]
                }))
            }
            "stop" => {
                control.stop_stats_collection()?;
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": "BPF program statistics collection stopped.\n\nThe polling task has been stopped, zero overhead. Use control://events/status to check status."
                    }]
                }))
            }
            "status" => {
                let running = control.is_stats_collection_running();
                let interval_ms = control.get_stats_collection_interval_ms();
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "BPF Stats Collection: {}\n\nUse control_stats_collection with action='start' or 'stop' to change.",
                            if running {
                                format!("RUNNING (polling every {}ms)", interval_ms)
                            } else {
                                "STOPPED".to_string()
                            }
                        )
                    }]
                }))
            }
            _ => Err(anyhow!("Invalid action: {}", action)),
        }
    }

    fn tool_control_analyzers(&self, args: &Value) -> Result<Value> {
        let control = self
            .analyzer_control
            .as_ref()
            .ok_or_else(|| anyhow!("Analyzer control not available (daemon mode required)"))?;

        let action = args
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing action parameter"))?;

        let analyzer = args
            .get("analyzer")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let control_lock = control.lock().unwrap();

        match action {
            "start" => {
                control_lock
                    .start_analyzer(analyzer)
                    .map_err(|e| anyhow!(e))?;
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "Analyzer '{}' started.\n\nEvent tracking will begin collecting data. Use control_analyzers with action='status' to check analyzer states.",
                            analyzer
                        )
                    }]
                }))
            }
            "stop" => {
                control_lock
                    .stop_analyzer(analyzer)
                    .map_err(|e| anyhow!(e))?;
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "Analyzer '{}' stopped.\n\nData collection paused. Existing data is retained. Use control_analyzers with action='status' to check analyzer states.",
                            analyzer
                        )
                    }]
                }))
            }
            "reset" => {
                control_lock
                    .reset_analyzer(analyzer)
                    .map_err(|e| anyhow!(e))?;
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "Analyzer '{}' reset.\n\nAll collected data has been cleared. Use control_analyzers with action='status' to check analyzer states.",
                            analyzer
                        )
                    }]
                }))
            }
            "status" => {
                let status = control_lock.get_status();
                let status_json = serde_json::to_value(&status)
                    .unwrap_or_else(|_| json!({"error": "Failed to serialize status"}));

                let enabled_list = status.enabled_analyzers();
                let summary = if enabled_list.is_empty() {
                    "All analyzers are currently STOPPED (zero overhead)".to_string()
                } else {
                    format!("Currently enabled: {}", enabled_list.join(", "))
                };

                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "Analyzer Status:\n\n{}\n\nDetails:\n{}",
                            summary,
                            serde_json::to_string_pretty(&status_json)
                                .unwrap_or_else(|_| "Failed to format status".to_string())
                        )
                    }]
                }))
            }
            _ => Err(anyhow!("Invalid action: {}", action)),
        }
    }

    fn tool_analyze_waker_wakee(&self, args: &Value) -> Result<Value> {
        let control = self
            .analyzer_control
            .as_ref()
            .ok_or_else(|| anyhow!("Analyzer control not available (daemon mode required)"))?;

        let control_lock = control.lock().unwrap();

        // Check if waker_wakee_analyzer is registered and enabled
        let status = control_lock.get_status();
        if status.waker_wakee_analyzer != Some(true) {
            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": "Waker/wakee analyzer is not enabled.\n\nTo enable it, use:\n  control_analyzers action=start analyzer=waker_wakee_analyzer\n\nNote: You must also enable BPF event tracking:\n  control_event_tracking action=enable"
                }]
            }));
        }

        // Get the waker_wakee_analyzer reference
        let analyzer_arc = control_lock
            .get_waker_wakee_analyzer()
            .ok_or_else(|| anyhow!("Waker/wakee analyzer not registered"))?;

        drop(control_lock); // Release control lock before accessing analyzer

        let analyzer = analyzer_arc.lock().unwrap();

        let mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("critical");

        // Use memory-aware default for analysis results
        let default_limit = self.mem_limits.analysis_result_limit();
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default_limit);

        let result = match mode {
            "critical" => {
                let relationships = analyzer.get_critical_relationships(limit);
                json!({
                    "mode": "critical",
                    "description": "Tasks with most critical waker/wakee relationships (frequency × latency)",
                    "count": relationships.len(),
                    "relationships": relationships,
                })
            }
            "frequency" => {
                let relationships = analyzer.get_top_by_frequency(limit);
                json!({
                    "mode": "frequency",
                    "description": "Most frequent waker/wakee relationships",
                    "count": relationships.len(),
                    "relationships": relationships,
                })
            }
            "latency" => {
                let relationships = analyzer.get_top_by_latency(limit);
                json!({
                    "mode": "latency",
                    "description": "Waker/wakee relationships with highest average latency",
                    "count": relationships.len(),
                    "relationships": relationships,
                })
            }
            "bidirectional" => {
                let relationships = analyzer.get_bidirectional_relationships();
                json!({
                    "mode": "bidirectional",
                    "description": "Bidirectional wakeup patterns (mutex/semaphore/condvar)",
                    "count": relationships.len(),
                    "relationships": relationships,
                })
            }
            "for_pid" => {
                let pid = args
                    .get("pid")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("Missing 'pid' parameter for 'for_pid' mode"))?
                    as u32;

                let relationships = analyzer.get_relationships_for_pid(pid);
                json!({
                    "mode": "for_pid",
                    "description": format!("All waker/wakee relationships for PID {}", pid),
                    "pid": pid,
                    "as_waker_count": relationships.as_waker.len(),
                    "as_wakee_count": relationships.as_wakee.len(),
                    "relationships": relationships,
                })
            }
            "summary" => {
                let summary = analyzer.get_summary();
                json!({
                    "mode": "summary",
                    "description": "Overview of waker/wakee relationship tracking",
                    "summary": summary,
                })
            }
            _ => return Err(anyhow!("Invalid mode: {}", mode)),
        };

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Failed to serialize results".to_string())
            }]
        }))
    }

    fn tool_analyze_softirq(&self, args: &Value) -> Result<Value> {
        let control = self
            .analyzer_control
            .as_ref()
            .ok_or_else(|| anyhow!("Analyzer control not available (daemon mode required)"))?;

        let control_lock = control.lock().unwrap();

        // Check if softirq_analyzer is registered and enabled
        let status = control_lock.get_status();
        if status.softirq_analyzer != Some(true) {
            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": "Softirq analyzer is not enabled.\n\nTo enable it, use:\n  control_analyzers action=start analyzer=softirq_analyzer\n\nNote: You must also enable BPF event tracking:\n  control_event_tracking action=enable"
                }]
            }));
        }

        // Get the softirq_analyzer reference
        let analyzer_arc = control_lock
            .get_softirq_analyzer()
            .ok_or_else(|| anyhow!("Softirq analyzer not registered"))?;

        drop(control_lock); // Release control lock before accessing analyzer

        let analyzer = analyzer_arc.lock().unwrap();

        let mode = args
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("summary");

        let softirq_nr = args
            .get("softirq_nr")
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        // Use memory-aware default for analysis results
        let default_limit = self.mem_limits.analysis_result_limit();
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default_limit);

        let result = match mode {
            "summary" => {
                let summary = analyzer.get_summary();
                json!({
                    "mode": "summary",
                    "description": "Overall softirq processing statistics",
                    "summary": summary,
                    "note": "Softirq types: 0=HI, 1=TIMER, 2=NET_TX, 3=NET_RX, 4=BLOCK, 5=IRQ_POLL, 6=TASKLET, 7=SCHED, 8=HRTIMER, 9=RCU"
                })
            }
            "by_type" => {
                let stats = analyzer.get_overall_stats();
                json!({
                    "mode": "by_type",
                    "description": "Softirq statistics by type (sorted by frequency)",
                    "count": stats.len(),
                    "stats": stats,
                })
            }
            "by_cpu" => {
                let stats = analyzer.get_cpu_breakdown(softirq_nr, limit);
                let desc = if let Some(nr) = softirq_nr {
                    format!("CPU breakdown for softirq type {} (top {})", nr, limit)
                } else {
                    format!("CPU breakdown for all softirq types (top {})", limit)
                };
                json!({
                    "mode": "by_cpu",
                    "description": desc,
                    "softirq_nr": softirq_nr,
                    "count": stats.len(),
                    "stats": stats,
                })
            }
            "by_process" => {
                let stats = analyzer.get_process_breakdown(softirq_nr, limit);
                let desc = if let Some(nr) = softirq_nr {
                    format!("Process breakdown for softirq type {} (top {})", nr, limit)
                } else {
                    format!("Process breakdown for all softirq types (top {})", limit)
                };
                json!({
                    "mode": "by_process",
                    "description": desc,
                    "softirq_nr": softirq_nr,
                    "count": stats.len(),
                    "stats": stats,
                })
            }
            _ => return Err(anyhow!("Invalid mode: {}", mode)),
        };

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|_| "Failed to serialize results".to_string())
            }]
        }))
    }

    fn tool_load_perfetto_trace(&mut self, args: &Value) -> Result<Value> {
        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let file_path = args
            .get("file_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing file_path parameter"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                std::path::Path::new(file_path)
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            });

        // Parse trace file
        let trace = Arc::new(super::PerfettoTrace::from_file(std::path::Path::new(
            file_path,
        ))?);

        // Store in cache
        let mut cache_lock = cache.lock().unwrap();
        cache_lock.insert(trace_id.clone(), trace.clone());

        // Get metadata
        let (start_ts, end_ts) = trace.time_range();
        let duration_ms = (end_ts - start_ts) / 1_000_000;

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Loaded perfetto trace: {}\n\
                     Trace ID: {}\n\
                     Time range: {} - {} ns ({} ms)\n\
                     Processes: {}\n\
                     CPUs: {}\n\
                     Total packets: {}\n\
                     Track events: {} (categories: {:?})\n\
                     sched_ext trace: {}\n\
                     {}",
                    file_path,
                    trace_id,
                    start_ts,
                    end_ts,
                    duration_ms,
                    trace.get_processes().len(),
                    trace.num_cpus(),
                    trace.total_events(),
                    trace.total_track_events(),
                    trace.get_track_event_categories(),
                    if trace.is_scx_trace() { "yes" } else { "no" },
                    if let Some(scx_meta) = trace.get_scx_metadata() {
                        format!("DSQs: {} ({:?})", scx_meta.dsq_ids.len(), &scx_meta.dsq_ids[..scx_meta.dsq_ids.len().min(10)])
                    } else {
                        "".to_string()
                    }
                )
            }]
        }))
    }

    fn tool_query_trace_events(&self, args: &Value) -> Result<Value> {
        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        // Get trace from cache
        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| {
                anyhow!(
                    "Trace '{}' not found. Use load_perfetto_trace first.",
                    trace_id
                )
            })?
            .clone();
        drop(cache_lock);

        let event_type = args
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        // Use memory-aware default if no limit specified
        let default_limit = self.mem_limits.event_query_limit();
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .or(default_limit)
            .unwrap_or(usize::MAX); // If mem_limits returns None, query all events

        // Apply filters
        let events = if let Some(cpu) = args.get("cpu").and_then(|v| v.as_u64()) {
            // CPU-specific query
            trace
                .get_events_by_cpu(cpu as u32)
                .iter()
                .map(|e| &e.event)
                .collect()
        } else if let (Some(start), Some(end)) = (
            args.get("start_time_ns").and_then(|v| v.as_u64()),
            args.get("end_time_ns").and_then(|v| v.as_u64()),
        ) {
            // Time range query
            trace.get_events_by_time_range(start, end)
        } else if event_type != "all" {
            // Type-specific query
            trace.get_events_by_type(event_type)
        } else {
            // All events
            trace.get_events_by_time_range(0, u64::MAX)
        };

        let limited_events: Vec<_> = events.into_iter().take(limit).collect();

        // Format events for display - use memory-aware display limit
        let display_limit = self.mem_limits.display_limit();
        let event_summaries: Vec<_> = limited_events
            .iter()
            .take(display_limit)
            .map(|event| {
                let event_type_str = match &event.event {
                    Some(ftrace_event::Event::SchedSwitch(_)) => "sched_switch",
                    Some(ftrace_event::Event::SchedWakeup(_)) => "sched_wakeup",
                    Some(ftrace_event::Event::SchedWaking(_)) => "sched_waking",
                    Some(ftrace_event::Event::SchedMigrateTask(_)) => "sched_migrate",
                    Some(ftrace_event::Event::SoftirqEntry(_)) => "softirq_entry",
                    Some(ftrace_event::Event::SoftirqExit(_)) => "softirq_exit",
                    _ => "other",
                };

                json!({
                    "type": event_type_str,
                    "timestamp": event.timestamp,
                    "pid": event.pid,
                })
            })
            .collect();

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Trace Query Results:\n\
                     Trace ID: {}\n\
                     Event type filter: {}\n\
                     Total matching events: {}\n\
                     Returned: {} (limit: {})\n\n\
                     Sample events (first 100):\n{}",
                    trace_id,
                    event_type,
                    limited_events.len(),
                    limited_events.len().min(limit),
                    limit,
                    serde_json::to_string_pretty(&event_summaries)
                        .unwrap_or_else(|_| "Failed to serialize events".to_string())
                )
            }]
        }))
    }

    fn tool_analyze_trace_scheduling(&self, args: &Value) -> Result<Value> {
        use super::perfetto_analyzers::{
            ContextSwitchAnalyzer, DsqAnalyzer, PerfettoMigrationAnalyzer, WakeupChainAnalyzer,
        };

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        let analysis_type = args
            .get("analysis_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing analysis_type parameter"))?;

        let use_parallel = args
            .get("use_parallel")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Use memory-aware default for analysis results
        let default_limit = self.mem_limits.analysis_result_limit();
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default_limit);

        let pid = args.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);

        // Extract aggregation_mode parameter for task state analysis
        let aggregation_mode = args
            .get("aggregation_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("per_thread"); // Default to per-thread

        // Get trace from cache
        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| {
                anyhow!(
                    "Trace '{}' not found. Use load_perfetto_trace first.",
                    trace_id
                )
            })?
            .clone();
        drop(cache_lock);

        let start_time = std::time::Instant::now();

        let result = match analysis_type {
            "cpu_utilization" => {
                let analyzer = ContextSwitchAnalyzer::new(trace);
                let stats = if use_parallel {
                    analyzer.analyze_cpu_utilization_parallel()
                } else {
                    analyzer.analyze_cpu_utilization()
                };

                json!({
                    "analysis_type": "cpu_utilization",
                    "cpus_analyzed": stats.len(),
                    "multi_threaded": use_parallel,
                    "cpus": stats,
                })
            }
            "process_runtime" => {
                let analyzer = ContextSwitchAnalyzer::new(trace);
                let stats = if use_parallel {
                    analyzer.analyze_process_runtime_parallel(pid)
                } else {
                    analyzer.analyze_process_runtime(pid)
                };

                let limited_stats: Vec<_> = stats.into_iter().take(limit).collect();

                json!({
                    "analysis_type": "process_runtime",
                    "processes_analyzed": limited_stats.len(),
                    "multi_threaded": use_parallel,
                    "pid_filter": pid,
                    "processes": limited_stats,
                })
            }
            "wakeup_latency" => {
                let analyzer = WakeupChainAnalyzer::new(trace);
                let stats = analyzer.analyze_wakeup_latency();

                json!({
                    "analysis_type": "wakeup_latency",
                    "stats": stats,
                })
            }
            "migration_patterns" => {
                let analyzer = PerfettoMigrationAnalyzer::new(trace);
                let stats = analyzer.analyze_migration_patterns();

                json!({
                    "analysis_type": "migration_patterns",
                    "stats": stats,
                })
            }
            "dsq_summary" => {
                let analyzer = DsqAnalyzer::new(trace);

                if !analyzer.has_scx_data() {
                    return Ok(json!({
                        "content": [{
                            "type": "text",
                            "text": "This trace does not contain sched_ext (DSQ) data.\n\nDSQ analysis is only available for traces generated while a sched_ext scheduler is active."
                        }]
                    }));
                }

                let summary = analyzer.get_summary().unwrap();

                json!({
                    "analysis_type": "dsq_summary",
                    "summary": summary,
                })
            }
            "task_states" => {
                use super::perfetto_analyzers_extended::{AggregationMode, TaskStateAnalyzer};

                // Parse aggregation mode
                let agg_mode = match aggregation_mode {
                    "per_process" => AggregationMode::PerProcess,
                    _ => AggregationMode::PerThread, // Default to per_thread
                };

                let analyzer = TaskStateAnalyzer::new(trace);
                let stats = analyzer.analyze_task_states(pid, agg_mode);
                // Task states are very verbose - use smaller limit to prevent token overflow
                let task_state_limit = limit.min(10);
                let limited_stats: Vec<_> = stats.into_iter().take(task_state_limit).collect();

                json!({
                    "analysis_type": "task_states",
                    "aggregation_mode": aggregation_mode,
                    "processes_analyzed": limited_stats.len(),
                    "pid_filter": pid,
                    "processes": limited_stats,
                    "note": format!("Showing top {} {} (use limit parameter to adjust, max recommended: 20)",
                                   task_state_limit,
                                   if matches!(agg_mode, AggregationMode::PerProcess) { "processes" } else { "threads" })
                })
            }
            "preemptions" => {
                use super::perfetto_analyzers_extended::PreemptionAnalyzer;
                let analyzer = PreemptionAnalyzer::new(trace);
                let stats = analyzer.analyze_preemptions(pid);
                let limited_stats: Vec<_> = stats.into_iter().take(limit).collect();

                json!({
                    "analysis_type": "preemptions",
                    "processes_analyzed": limited_stats.len(),
                    "pid_filter": pid,
                    "processes": limited_stats,
                })
            }
            "wakeup_chains" => {
                use super::perfetto_analyzers_extended::WakeupChainDetector;
                let analyzer = WakeupChainDetector::new(trace);
                let chains = analyzer.find_wakeup_chains(limit);

                json!({
                    "analysis_type": "wakeup_chains",
                    "chains_found": chains.len(),
                    "chains": chains,
                })
            }
            "latency_breakdown" => {
                use super::perfetto_analyzers_extended::SchedulingLatencyBreakdown;
                let analyzer = SchedulingLatencyBreakdown::new(trace);
                let stats = analyzer.analyze_latency_stages();

                json!({
                    "analysis_type": "latency_breakdown",
                    "stats": stats,
                })
            }
            "irq_analysis" => {
                use super::perfetto_analyzers_irq::IrqHandlerAnalyzer;
                let result = IrqHandlerAnalyzer::analyze(&trace);

                let limited_summary: Vec<_> = result.irq_summary.iter().take(limit).collect();

                json!({
                    "analysis_type": "irq_analysis",
                    "description": "Hardware IRQ handler analysis",
                    "irq_count": result.irq_summary.len(),
                    "top_irqs": limited_summary,
                    "note": "IRQ handlers sorted by total time spent. Lower duration is better."
                })
            }
            "ipi_analysis" => {
                use super::perfetto_analyzers_irq::IpiAnalyzer;
                let result = IpiAnalyzer::analyze(&trace);

                let limited_reasons: Vec<_> = result.reason_summary.iter().take(limit).collect();

                json!({
                    "analysis_type": "ipi_analysis",
                    "description": "Inter-Processor Interrupt (IPI) analysis",
                    "total_ipis": result.ipi_events.len(),
                    "reason_count": result.reason_summary.len(),
                    "top_reasons": limited_reasons,
                    "note": "IPIs are interrupts sent between CPUs for synchronization and cache coherence."
                })
            }
            "block_io" => {
                use super::perfetto_analyzers_io::BlockIoAnalyzer;
                let result = BlockIoAnalyzer::analyze(&trace);

                json!({
                    "analysis_type": "block_io",
                    "description": "Block device I/O analysis",
                    "total_ios": result.total_ios,
                    "read_count": result.read_count,
                    "write_count": result.write_count,
                    "read_latency": result.read_latency,
                    "write_latency": result.write_latency,
                    "queue_latency": result.queue_latency,
                    "device_latency": result.device_latency,
                    "note": "Analyzes block I/O request lifecycle from insert to completion."
                })
            }
            "network_io" => {
                use super::perfetto_analyzers_io::NetworkIoAnalyzer;
                let result = NetworkIoAnalyzer::analyze(&trace);

                json!({
                    "analysis_type": "network_io",
                    "description": "Network I/O analysis",
                    "tx_packets": result.tx_packets,
                    "rx_packets": result.rx_packets,
                    "tx_bytes": result.tx_bytes,
                    "rx_bytes": result.rx_bytes,
                    "tx_bandwidth_mbps": result.tx_bandwidth_mbps,
                    "rx_bandwidth_mbps": result.rx_bandwidth_mbps,
                    "duration_secs": result.duration_secs,
                    "note": "Network transmit/receive statistics and bandwidth calculation."
                })
            }
            "memory_pressure" => {
                use super::perfetto_analyzers_io::MemoryPressureAnalyzer;
                let result = MemoryPressureAnalyzer::analyze(&trace);

                json!({
                    "analysis_type": "memory_pressure",
                    "description": "Memory pressure and reclaim analysis",
                    "page_alloc_count": result.page_alloc_count,
                    "page_free_count": result.page_free_count,
                    "net_allocation": result.net_allocation,
                    "reclaim_count": result.reclaim_count,
                    "reclaim_latency": result.reclaim_latency,
                    "note": "Analyzes memory allocation, freeing, and direct reclaim events."
                })
            }
            "file_io" => {
                use super::perfetto_analyzers_io::FileIoAnalyzer;
                let result = FileIoAnalyzer::analyze(&trace);

                json!({
                    "analysis_type": "file_io",
                    "description": "File I/O sync operation analysis",
                    "sync_count": result.sync_count,
                    "sync_latency": result.sync_latency,
                    "note": "Analyzes ext4 file sync operations (more FS types can be added)."
                })
            }
            "cpu_frequency" => {
                use super::perfetto_analyzers_power::CpuFrequencyAnalyzer;
                let result = CpuFrequencyAnalyzer::analyze(&trace);

                let limited_cpus: Vec<_> = result.cpu_stats.iter().take(limit).collect();

                json!({
                    "analysis_type": "cpu_frequency",
                    "description": "CPU frequency scaling analysis",
                    "total_transitions": result.total_transitions,
                    "cpu_count": result.cpu_stats.len(),
                    "cpu_stats": limited_cpus,
                    "note": "Analyzes CPU frequency scaling behavior and DVFS (Dynamic Voltage and Frequency Scaling)."
                })
            }
            "cpu_idle" => {
                use super::perfetto_analyzers_power::CpuIdleStateAnalyzer;
                let result = CpuIdleStateAnalyzer::analyze(&trace);

                let limited_cpus: Vec<_> = result.cpu_stats.iter().take(limit).collect();

                json!({
                    "analysis_type": "cpu_idle",
                    "description": "CPU idle state analysis",
                    "total_transitions": result.total_transitions,
                    "cpu_count": result.cpu_stats.len(),
                    "cpu_stats": limited_cpus,
                    "note": "Analyzes CPU idle state transitions and time spent in active vs idle states."
                })
            }
            "power_state" => {
                use super::perfetto_analyzers_power::PowerStateAnalyzer;
                let result = PowerStateAnalyzer::analyze(&trace);

                json!({
                    "analysis_type": "power_state",
                    "description": "System power state analysis",
                    "suspend_resume_count": result.suspend_resume_count,
                    "suspend_resume_events": result.suspend_resume_events,
                    "note": "Analyzes system suspend/resume transitions."
                })
            }
            _ => return Err(anyhow!("Unknown analysis_type: {}", analysis_type)),
        };

        let analysis_time = start_time.elapsed();

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Analysis completed in {:?}\n\n{}",
                    analysis_time,
                    serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| "Failed to serialize results".to_string())
                )
            }]
        }))
    }

    fn tool_get_process_timeline(&self, args: &Value) -> Result<Value> {
        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        let pid = args
            .get("pid")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow!("Missing pid parameter"))? as i32;

        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        let (default_start, default_end) = trace.time_range();
        let start_ns = args
            .get("start_time_ns")
            .and_then(|v| v.as_u64())
            .unwrap_or(default_start);
        let end_ns = args
            .get("end_time_ns")
            .and_then(|v| v.as_u64())
            .unwrap_or(default_end);

        let timeline = trace.get_timeline_for_process(pid, start_ns, end_ns);

        // Limit output for readability using memory-aware limit or user-provided limit
        let default_limit = self.mem_limits.timeline_limit();
        let timeline_limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default_limit);
        let limited_events: Vec<_> = timeline.events.iter().take(timeline_limit).collect();

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Process Timeline for PID {} ({})\n\
                     Time range: {} - {} ns\n\
                     Total events: {}\n\n\
                     Timeline (first {} events):\n{}",
                    timeline.pid,
                    timeline.comm,
                    start_ns,
                    end_ns,
                    timeline.events.len(),
                    timeline_limit.min(timeline.events.len()),
                    serde_json::to_string_pretty(&limited_events)
                        .unwrap_or_else(|_| "Failed to serialize timeline".to_string())
                )
            }]
        }))
    }

    fn tool_get_cpu_timeline(&self, args: &Value) -> Result<Value> {
        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        let cpu = args
            .get("cpu")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow!("Missing cpu parameter"))? as u32;

        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        let (default_start, default_end) = trace.time_range();
        let start_ns = args
            .get("start_time_ns")
            .and_then(|v| v.as_u64())
            .unwrap_or(default_start);
        let end_ns = args
            .get("end_time_ns")
            .and_then(|v| v.as_u64())
            .unwrap_or(default_end);

        let timeline = trace.get_cpu_timeline(cpu, start_ns, end_ns);

        // Limit output for readability using memory-aware limit or user-provided limit
        let default_limit = self.mem_limits.timeline_limit();
        let timeline_limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default_limit);
        let limited_events: Vec<_> = timeline.events.iter().take(timeline_limit).collect();

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "CPU Timeline for CPU {}\n\
                     Time range: {} - {} ns\n\
                     Total events: {}\n\n\
                     Timeline (first {} events):\n{}",
                    timeline.cpu,
                    start_ns,
                    end_ns,
                    timeline.events.len(),
                    timeline_limit.min(timeline.events.len()),
                    serde_json::to_string_pretty(&limited_events)
                        .unwrap_or_else(|_| "Failed to serialize timeline".to_string())
                )
            }]
        }))
    }

    fn tool_find_scheduling_bottlenecks(&self, args: &Value) -> Result<Value> {
        use super::perfetto_analyzers::CorrelationAnalyzer;

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        // Use memory-aware default for analysis results
        let default_limit = self.mem_limits.analysis_result_limit().min(10);
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default_limit);

        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        let start_time = std::time::Instant::now();
        let analyzer = CorrelationAnalyzer::new(trace);
        let bottlenecks = analyzer.find_scheduling_bottlenecks(limit);
        let analysis_time = start_time.elapsed();

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Scheduling Bottlenecks (analyzed in {:?})\n\n\
                     Found {} bottleneck(s):\n\n{}",
                    analysis_time,
                    bottlenecks.len(),
                    serde_json::to_string_pretty(&bottlenecks)
                        .unwrap_or_else(|_| "Failed to serialize bottlenecks".to_string())
                )
            }]
        }))
    }

    fn tool_correlate_wakeup_to_schedule(&self, args: &Value) -> Result<Value> {
        use super::perfetto_analyzers::CorrelationAnalyzer;

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        let pid = args.get("pid").and_then(|v| v.as_i64()).map(|v| v as i32);

        // Use memory-aware default for analysis results
        let default_limit = self.mem_limits.analysis_result_limit().min(100);
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(default_limit);

        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        let start_time = std::time::Instant::now();
        let analyzer = CorrelationAnalyzer::new(trace);
        let correlations = analyzer.correlate_wakeup_to_schedule(pid);
        let analysis_time = start_time.elapsed();

        let limited_correlations: Vec<_> = correlations.into_iter().take(limit).collect();

        // Calculate latency percentiles
        let latencies: Vec<u64> = limited_correlations
            .iter()
            .map(|c| c.wakeup_latency_ns)
            .collect();
        let percentiles = super::PerfettoTrace::calculate_percentiles(&latencies);

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Wakeup→Schedule Correlations (analyzed in {:?})\n\n\
                     Total correlations: {}\n\
                     Showing top {} by latency\n\n\
                     Latency percentiles:\n\
                       min:  {} ns\n\
                       p50:  {} ns\n\
                       p95:  {} ns\n\
                       p99:  {} ns\n\
                       p999: {} ns\n\
                       max:  {} ns\n\n\
                     Correlations:\n{}",
                    analysis_time,
                    limited_correlations.len(),
                    limit,
                    percentiles.min,
                    percentiles.median,
                    percentiles.p95,
                    percentiles.p99,
                    percentiles.p999,
                    percentiles.max,
                    serde_json::to_string_pretty(&limited_correlations)
                        .unwrap_or_else(|_| "Failed to serialize correlations".to_string())
                )
            }]
        }))
    }

    fn tool_export_trace_analysis(&self, args: &Value) -> Result<Value> {
        use super::perfetto_analyzers::{
            ContextSwitchAnalyzer, CorrelationAnalyzer, DsqAnalyzer, PerfettoMigrationAnalyzer,
            WakeupChainAnalyzer,
        };

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        let output_path = args
            .get("output_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing output_path parameter"))?;

        let analysis_types = args
            .get("analysis_types")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                vec![
                    "cpu_utilization".to_string(),
                    "process_runtime".to_string(),
                    "wakeup_latency".to_string(),
                    "migration".to_string(),
                    "dsq".to_string(),
                    "bottlenecks".to_string(),
                    "task_states".to_string(),
                    "preemptions".to_string(),
                    "wakeup_chains".to_string(),
                    "latency_breakdown".to_string(),
                ]
            });

        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        let mut export_data = json!({
            "trace_id": trace_id,
            "time_range": trace.time_range(),
            "num_cpus": trace.num_cpus(),
            "num_processes": trace.get_processes().len(),
            "total_events": trace.total_events(),
            "is_scx_trace": trace.is_scx_trace(),
            "export_timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        let start_time = std::time::Instant::now();

        // Run requested analyses
        for analysis_type in &analysis_types {
            match analysis_type.as_str() {
                "cpu_utilization" => {
                    let analyzer = ContextSwitchAnalyzer::new(trace.clone());
                    let stats = analyzer.analyze_cpu_utilization_parallel();
                    export_data["cpu_utilization"] = json!(stats);
                }
                "process_runtime" => {
                    let analyzer = ContextSwitchAnalyzer::new(trace.clone());
                    let stats = analyzer.analyze_process_runtime_parallel(None);
                    let top_20: Vec<_> = stats.into_iter().take(20).collect();
                    export_data["process_runtime"] = json!(top_20);
                }
                "wakeup_latency" => {
                    let analyzer = WakeupChainAnalyzer::new(trace.clone());
                    let stats = analyzer.analyze_wakeup_latency();
                    export_data["wakeup_latency"] = json!(stats);
                }
                "migration" => {
                    let analyzer = PerfettoMigrationAnalyzer::new(trace.clone());
                    let stats = analyzer.analyze_migration_patterns();
                    export_data["migration"] = json!(stats);
                }
                "dsq" => {
                    let analyzer = DsqAnalyzer::new(trace.clone());
                    if analyzer.has_scx_data() {
                        export_data["dsq"] = json!(analyzer.get_summary());
                    }
                }
                "bottlenecks" => {
                    let analyzer = CorrelationAnalyzer::new(trace.clone());
                    let bottlenecks = analyzer.find_scheduling_bottlenecks(10);
                    export_data["bottlenecks"] = json!(bottlenecks);
                }
                "task_states" => {
                    use super::perfetto_analyzers_extended::{AggregationMode, TaskStateAnalyzer};
                    let analyzer = TaskStateAnalyzer::new(trace.clone());
                    let stats = analyzer.analyze_task_states(None, AggregationMode::PerThread);
                    let top_20: Vec<_> = stats.into_iter().take(20).collect();
                    export_data["task_states"] = json!(top_20);
                }
                "preemptions" => {
                    use super::perfetto_analyzers_extended::PreemptionAnalyzer;
                    let analyzer = PreemptionAnalyzer::new(trace.clone());
                    let stats = analyzer.analyze_preemptions(None);
                    let top_20: Vec<_> = stats.into_iter().take(20).collect();
                    export_data["preemptions"] = json!(top_20);
                }
                "wakeup_chains" => {
                    use super::perfetto_analyzers_extended::WakeupChainDetector;
                    let analyzer = WakeupChainDetector::new(trace.clone());
                    let chains = analyzer.find_wakeup_chains(10);
                    export_data["wakeup_chains"] = json!(chains);
                }
                "latency_breakdown" => {
                    use super::perfetto_analyzers_extended::SchedulingLatencyBreakdown;
                    let analyzer = SchedulingLatencyBreakdown::new(trace.clone());
                    let stats = analyzer.analyze_latency_stages();
                    export_data["latency_breakdown"] = json!(stats);
                }
                _ => {}
            }
        }

        let analysis_time = start_time.elapsed();

        // Write to file
        let json_str = serde_json::to_string_pretty(&export_data)?;
        std::fs::write(output_path, json_str)?;

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Trace analysis exported successfully\n\n\
                     Output file: {}\n\
                     Analysis types: {}\n\
                     Analysis time: {:?}\n\
                     File size: {} bytes",
                    output_path,
                    analysis_types.join(", "),
                    analysis_time,
                    std::fs::metadata(output_path)?.len()
                )
            }]
        }))
    }

    fn tool_query_trace(&self, args: &Value) -> Result<Value> {
        use super::perfetto_query::{
            Aggregator, FieldFilter, FilterOperator, FilterValue, QueryBuilder,
        };

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        // Get trace from cache
        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| {
                anyhow!(
                    "Trace '{}' not found. Use load_perfetto_trace first.",
                    trace_id
                )
            })?
            .clone();
        drop(cache_lock);

        // Build query
        let mut query = QueryBuilder::new();

        if let Some(event_type) = args.get("event_type").and_then(|v| v.as_str()) {
            query = query.event_type(event_type);
        }

        if let Some(cpu) = args.get("cpu").and_then(|v| v.as_u64()) {
            query = query.cpu(cpu as u32);
        }

        if let Some(pid) = args.get("pid").and_then(|v| v.as_i64()) {
            query = query.pid(pid as i32);
        }

        if let (Some(start), Some(end)) = (
            args.get("start_time_ns").and_then(|v| v.as_u64()),
            args.get("end_time_ns").and_then(|v| v.as_u64()),
        ) {
            query = query.time_range(start, end);
        }

        // Add field filters
        if let Some(field_filters) = args.get("field_filters").and_then(|v| v.as_array()) {
            for filter in field_filters {
                let field = filter
                    .get("field")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing field in filter"))?;

                let operator_str = filter
                    .get("operator")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow!("Missing operator in filter"))?;

                let operator = match operator_str {
                    "equal" => FilterOperator::Equal,
                    "not_equal" => FilterOperator::NotEqual,
                    "greater_than" => FilterOperator::GreaterThan,
                    "less_than" => FilterOperator::LessThan,
                    "greater_or_equal" => FilterOperator::GreaterOrEqual,
                    "less_or_equal" => FilterOperator::LessOrEqual,
                    "contains" => FilterOperator::Contains,
                    _ => return Err(anyhow!("Invalid operator: {}", operator_str)),
                };

                let value = filter
                    .get("value")
                    .ok_or_else(|| anyhow!("Missing value in filter"))?;

                let filter_value = if let Some(i) = value.as_i64() {
                    FilterValue::Int(i)
                } else if let Some(s) = value.as_str() {
                    FilterValue::String(s.to_string())
                } else {
                    return Err(anyhow!("Invalid filter value type"));
                };

                query = query.where_field(FieldFilter::new(field, operator, filter_value));
            }
        }

        // Use memory-aware default if no limit specified
        let default_limit = self.mem_limits.event_query_limit();
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .or(default_limit)
            .unwrap_or(usize::MAX);
        let offset = args.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

        query = query.limit(limit).offset(offset);

        // Execute query
        let result = query.execute(&trace);

        // Apply aggregation if requested
        let output = if let Some(aggregation) = args.get("aggregation") {
            let function = aggregation
                .get("function")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Missing aggregation function"))?;

            let aggregation_result = match function {
                "count" => json!({
                    "function": "count",
                    "result": Aggregator::count(&result),
                }),
                "count_by" => {
                    let field = aggregation
                        .get("field")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("Missing field for count_by"))?;
                    let counts = Aggregator::count_by(&result, field);
                    json!({
                        "function": "count_by",
                        "field": field,
                        "result": counts,
                    })
                }
                "avg" => {
                    let field = aggregation
                        .get("field")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("Missing field for avg"))?;
                    let avg = Aggregator::avg(&result, field);
                    json!({
                        "function": "avg",
                        "field": field,
                        "result": avg,
                    })
                }
                "min" => {
                    let field = aggregation
                        .get("field")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("Missing field for min"))?;
                    let min = Aggregator::min(&result, field);
                    json!({
                        "function": "min",
                        "field": field,
                        "result": min,
                    })
                }
                "max" => {
                    let field = aggregation
                        .get("field")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("Missing field for max"))?;
                    let max = Aggregator::max(&result, field);
                    json!({
                        "function": "max",
                        "field": field,
                        "result": max,
                    })
                }
                "group_by" => {
                    let field = aggregation
                        .get("field")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow!("Missing field for group_by"))?;
                    let groups = Aggregator::group_by(&result, field);
                    let group_counts: HashMap<String, usize> =
                        groups.iter().map(|(k, v)| (k.clone(), v.len())).collect();
                    json!({
                        "function": "group_by",
                        "field": field,
                        "group_counts": group_counts,
                        "groups": groups.keys().collect::<Vec<_>>(),
                    })
                }
                _ => return Err(anyhow!("Invalid aggregation function: {}", function)),
            };

            json!({
                "query_time_ms": result.query_time_ms,
                "total_matched": result.total_matched,
                "aggregation": aggregation_result,
            })
        } else {
            // No aggregation - return events (use memory-aware display limit)
            let display_limit = self.mem_limits.display_limit();
            let limited_events: Vec<_> = result.events.iter().take(display_limit).collect();

            json!({
                "query_time_ms": result.query_time_ms,
                "total_matched": result.total_matched,
                "returned_count": result.events.len(),
                "events": limited_events,
            })
        };

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&output)
                    .unwrap_or_else(|_| "Failed to serialize query results".to_string())
            }]
        }))
    }

    fn tool_discover_analyzers(&self, args: &Value) -> Result<Value> {
        use super::perfetto_analyzer_registry::AnalyzerRegistry;

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        // Get trace from cache
        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        // Create registry and discover
        let registry = AnalyzerRegistry::with_builtins();
        let analyzers = registry.discover_analyzers(&trace);

        // Filter by category if requested
        let filtered_analyzers: Vec<_> =
            if let Some(category_str) = args.get("category").and_then(|v| v.as_str()) {
                use super::perfetto_analyzer_registry::AnalyzerCategory;
                let category = match category_str {
                    "scheduling" => AnalyzerCategory::Scheduling,
                    "interrupt" => AnalyzerCategory::Interrupt,
                    "io" => AnalyzerCategory::IO,
                    "power" => AnalyzerCategory::Power,
                    "extended" => AnalyzerCategory::Extended,
                    "query" => AnalyzerCategory::Query,
                    _ => return Err(anyhow!("Invalid category: {}", category_str)),
                };
                analyzers
                    .into_iter()
                    .filter(|a| a.category == category)
                    .collect()
            } else {
                analyzers
            };

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Discovered {} applicable analyzer(s):\\n\\n{}",
                    filtered_analyzers.len(),
                    serde_json::to_string_pretty(&filtered_analyzers)
                        .unwrap_or_else(|_| "Failed to serialize analyzers".to_string())
                )
            }]
        }))
    }

    fn tool_get_trace_summary(&self, args: &Value) -> Result<Value> {
        use super::perfetto_analyzer_registry::AnalyzerRegistry;

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        // Get trace from cache
        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        // Create registry and get summary
        let registry = AnalyzerRegistry::with_builtins();
        let summary = registry.get_trace_summary(&trace);

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Trace Summary:\\n\\n{}",
                    serde_json::to_string_pretty(&summary)
                        .unwrap_or_else(|_| "Failed to serialize summary".to_string())
                )
            }]
        }))
    }

    fn tool_run_all_analyzers(&self, args: &Value) -> Result<Value> {
        use super::perfetto_analyzer_registry::{AnalyzerCategory, AnalyzerRegistry};

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        // Option to return only summary (default: true for compact output)
        let summary_only = args
            .get("summary_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Get trace from cache
        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        let start_time = std::time::Instant::now();

        // Create registry
        let registry = AnalyzerRegistry::with_builtins();

        // Filter by category if requested
        let results = if let Some(category_str) = args.get("category").and_then(|v| v.as_str()) {
            let category = match category_str {
                "scheduling" => AnalyzerCategory::Scheduling,
                "interrupt" => AnalyzerCategory::Interrupt,
                "io" => AnalyzerCategory::IO,
                "power" => AnalyzerCategory::Power,
                "extended" => AnalyzerCategory::Extended,
                _ => return Err(anyhow!("Invalid category: {}", category_str)),
            };

            // Run only analyzers from specific category
            registry
                .discover_analyzers(&trace)
                .into_iter()
                .filter(|a| a.category == category)
                .filter_map(|metadata| registry.analyze_by_id(&metadata.id, trace.clone()))
                .collect()
        } else {
            // Run all applicable analyzers
            registry.analyze_all(trace)
        };

        let total_time = start_time.elapsed();

        // Build metadata lookup map
        let metadata_map: HashMap<String, _> = registry
            .list_analyzers()
            .into_iter()
            .map(|m| (m.id.clone(), m))
            .collect();

        // Summarize results
        let successful = results.iter().filter(|r| r.success).count();
        let failed = results.iter().filter(|r| !r.success).count();
        let total_analysis_time: u64 = results.iter().map(|r| r.duration_ms).sum();

        // Create compact summary
        let analyzer_summaries: Vec<_> = results
            .iter()
            .map(|r| {
                let metadata = metadata_map.get(&r.analyzer_id);
                json!({
                    "analyzer": metadata.map(|m| m.name.as_str()).unwrap_or(&r.analyzer_id),
                    "category": metadata.map(|m| m.category.as_str()).unwrap_or("unknown"),
                    "success": r.success,
                    "duration_ms": r.duration_ms,
                    "data_size": r.data.to_string().len(), // Size of JSON data
                    "error": r.error.as_ref().map(|e| e.to_string()),
                })
            })
            .collect();

        let response_data = if summary_only {
            // Compact response - just summaries
            json!({
                "total_analyzers": results.len(),
                "successful": successful,
                "failed": failed,
                "total_time_ms": total_time.as_millis(),
                "analysis_time_ms": total_analysis_time,
                "analyzers": analyzer_summaries,
            })
        } else {
            // Full response - includes all detailed data
            json!({
                "total_analyzers": results.len(),
                "successful": successful,
                "failed": failed,
                "total_time_ms": total_time.as_millis(),
                "analysis_time_ms": total_analysis_time,
                "analyzers": analyzer_summaries,
                "full_results": results,
            })
        };

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Batch Analysis Complete:\n\
                     Total analyzers: {}\n\
                     Successful: {}\n\
                     Failed: {}\n\
                     Total time: {}ms\n\n\
                     {}\n\n\
                     Note: Use summary_only=false to get full detailed results",
                    results.len(),
                    successful,
                    failed,
                    total_time.as_millis(),
                    serde_json::to_string_pretty(&response_data)
                        .unwrap_or_else(|_| "Failed to serialize results".to_string())
                )
            }]
        }))
    }

    fn tool_detect_outliers(&self, args: &Value) -> Result<Value> {
        use super::outlier_detection::OutlierMethod;
        use super::perfetto_outlier_analyzer::PerfettoOutlierAnalyzer;

        let cache = self
            .trace_cache
            .as_ref()
            .ok_or_else(|| anyhow!("Trace cache not available"))?;

        let trace_id = args
            .get("trace_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing trace_id parameter"))?;

        // Get trace from cache
        let cache_lock = cache.lock().unwrap();
        let trace = cache_lock
            .get(trace_id)
            .ok_or_else(|| anyhow!("Trace '{}' not found", trace_id))?
            .clone();
        drop(cache_lock);

        // Parse detection method
        let method_str = args.get("method").and_then(|v| v.as_str()).unwrap_or("IQR");

        let method = match method_str {
            "IQR" => OutlierMethod::IQR,
            "MAD" => OutlierMethod::MAD,
            "StdDev" => OutlierMethod::StdDev,
            "Percentile" => OutlierMethod::Percentile,
            _ => return Err(anyhow!("Invalid outlier detection method: {}", method_str)),
        };

        let category = args
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        // Get limit parameter (default: 20)
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

        let start_time = std::time::Instant::now();
        let analyzer = PerfettoOutlierAnalyzer::with_method(trace, method);
        let analysis = analyzer.analyze();
        let analysis_time = start_time.elapsed();

        // Filter by category if specified and apply limits
        let output = match category {
            "latency" => json!({
                "trace_id": trace_id,
                "detection_method": method_str,
                "category": "latency",
                "analysis_time_ms": analysis_time.as_millis(),
                "limit_per_subcategory": limit,
                "summary": {
                    "total_outliers": analysis.latency_outliers.outlier_count,
                    "wakeup_latency": analysis.latency_outliers.wakeup_latency.len(),
                    "schedule_latency": analysis.latency_outliers.schedule_latency.len(),
                    "blocked_time": analysis.latency_outliers.blocked_time.len(),
                },
                "outliers": {
                    "wakeup_latency": analysis.latency_outliers.wakeup_latency.into_iter().take(limit).collect::<Vec<_>>(),
                    "schedule_latency": analysis.latency_outliers.schedule_latency.into_iter().take(limit).collect::<Vec<_>>(),
                    "blocked_time": analysis.latency_outliers.blocked_time.into_iter().take(limit).collect::<Vec<_>>(),
                },
                "detection_result": analysis.latency_outliers.detection_result,
            }),
            "runtime" => json!({
                "trace_id": trace_id,
                "detection_method": method_str,
                "category": "runtime",
                "analysis_time_ms": analysis_time.as_millis(),
                "limit_per_subcategory": limit,
                "summary": {
                    "total_outliers": analysis.runtime_outliers.outlier_count,
                    "excessive_runtime": analysis.runtime_outliers.excessive_runtime.len(),
                    "minimal_runtime": analysis.runtime_outliers.minimal_runtime.len(),
                    "high_context_switches": analysis.runtime_outliers.high_context_switches.len(),
                },
                "outliers": {
                    "excessive_runtime": analysis.runtime_outliers.excessive_runtime.into_iter().take(limit).collect::<Vec<_>>(),
                    "minimal_runtime": analysis.runtime_outliers.minimal_runtime.into_iter().take(limit).collect::<Vec<_>>(),
                    "high_context_switches": analysis.runtime_outliers.high_context_switches.into_iter().take(limit).collect::<Vec<_>>(),
                },
                "detection_result": analysis.runtime_outliers.detection_result,
            }),
            "cpu" => json!({
                "trace_id": trace_id,
                "detection_method": method_str,
                "category": "cpu",
                "analysis_time_ms": analysis_time.as_millis(),
                "limit_per_subcategory": limit,
                "summary": {
                    "total_outliers": analysis.cpu_outliers.outlier_count,
                    "overutilized_cpus": analysis.cpu_outliers.overutilized_cpus.len(),
                    "underutilized_cpus": analysis.cpu_outliers.underutilized_cpus.len(),
                    "high_contention_cpus": analysis.cpu_outliers.high_contention_cpus.len(),
                },
                "outliers": {
                    "overutilized_cpus": analysis.cpu_outliers.overutilized_cpus.into_iter().take(limit).collect::<Vec<_>>(),
                    "underutilized_cpus": analysis.cpu_outliers.underutilized_cpus.into_iter().take(limit).collect::<Vec<_>>(),
                    "high_contention_cpus": analysis.cpu_outliers.high_contention_cpus.into_iter().take(limit).collect::<Vec<_>>(),
                },
                "detection_result": analysis.cpu_outliers.detection_result,
            }),
            _ => {
                // "all" category - apply limits to all sub-categories
                json!({
                    "trace_id": trace_id,
                    "detection_method": method_str,
                    "category": "all",
                    "analysis_time_ms": analysis_time.as_millis(),
                    "limit_per_subcategory": limit,
                    "summary": {
                        "total_outliers": analysis.summary.total_outliers,
                        "latency_outliers_total": analysis.latency_outliers.outlier_count,
                        "runtime_outliers_total": analysis.runtime_outliers.outlier_count,
                        "cpu_outliers_total": analysis.cpu_outliers.outlier_count,
                        "by_metric": analysis.summary.by_metric,
                    },
                    "latency_outliers": {
                        "wakeup_latency": analysis.latency_outliers.wakeup_latency.into_iter().take(limit).collect::<Vec<_>>(),
                        "schedule_latency": analysis.latency_outliers.schedule_latency.into_iter().take(limit).collect::<Vec<_>>(),
                        "blocked_time": analysis.latency_outliers.blocked_time.into_iter().take(limit).collect::<Vec<_>>(),
                        "detection_result": analysis.latency_outliers.detection_result,
                    },
                    "runtime_outliers": {
                        "excessive_runtime": analysis.runtime_outliers.excessive_runtime.into_iter().take(limit).collect::<Vec<_>>(),
                        "minimal_runtime": analysis.runtime_outliers.minimal_runtime.into_iter().take(limit).collect::<Vec<_>>(),
                        "high_context_switches": analysis.runtime_outliers.high_context_switches.into_iter().take(limit).collect::<Vec<_>>(),
                        "detection_result": analysis.runtime_outliers.detection_result,
                    },
                    "cpu_outliers": {
                        "overutilized_cpus": analysis.cpu_outliers.overutilized_cpus.into_iter().take(limit).collect::<Vec<_>>(),
                        "underutilized_cpus": analysis.cpu_outliers.underutilized_cpus.into_iter().take(limit).collect::<Vec<_>>(),
                        "high_contention_cpus": analysis.cpu_outliers.high_contention_cpus.into_iter().take(limit).collect::<Vec<_>>(),
                        "detection_result": analysis.cpu_outliers.detection_result,
                    },
                })
            }
        };

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "Outlier Analysis ({} method)\\n\\n{}",
                    method_str,
                    serde_json::to_string_pretty(&output)
                        .unwrap_or_else(|_| "Failed to serialize outlier analysis".to_string())
                )
            }]
        }))
    }

    // Dedicated analyzer tool implementations (wrappers around analyze_trace_scheduling)

    fn tool_analyze_cpu_utilization(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("cpu_utilization");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_process_runtime(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("process_runtime");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_wakeup_latency(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("wakeup_latency");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_migration_patterns(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("migration_patterns");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_dsq(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("dsq_summary");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_task_states(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("task_states");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_preemptions(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("preemptions");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_wakeup_chains(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("wakeup_chains");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_latency_breakdown(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("latency_breakdown");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_irq(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("irq_analysis");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_ipi(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("ipi_analysis");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_block_io(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("block_io");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_network_io(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("network_io");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_memory_pressure(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("memory_pressure");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_file_io(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("file_io");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_cpu_frequency(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("cpu_frequency");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_cpu_idle(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("cpu_idle");
        self.tool_analyze_trace_scheduling(&modified_args)
    }

    fn tool_analyze_power_state(&self, args: &Value) -> Result<Value> {
        let mut modified_args = args.clone();
        modified_args["analysis_type"] = json!("power_state");
        self.tool_analyze_trace_scheduling(&modified_args)
    }
}
