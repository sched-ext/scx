// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::perf_profiling::{PerfProfilingConfig, SharedPerfProfiler};
use super::protocol::McpTool;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct McpTools {
    topo: Option<Arc<scx_utils::Topology>>,
    perf_profiler: Option<SharedPerfProfiler>,
    event_control: Option<super::SharedEventControl>,
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
        }
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
                name: "list_events".to_string(),
                description:
                    "List available profiling events (kprobes and perf events) that can be traced"
                        .to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "event_type": {
                            "type": "string",
                            "enum": ["kprobe", "perf", "all"],
                            "description": "Type of events to list"
                        },
                        "subsystem": {
                            "type": "string",
                            "description": "Filter perf events by subsystem (e.g., 'sched', 'irq', 'power'). Required when event_type is 'perf' or not specified."
                        }
                    },
                    "required": ["subsystem"]
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
            "list_events" => self.tool_list_events(arguments),
            "start_perf_profiling" => self.tool_start_perf_profiling(arguments),
            "stop_perf_profiling" => self.tool_stop_perf_profiling(arguments),
            "get_perf_results" => self.tool_get_perf_results(arguments),
            "control_event_tracking" => self.tool_control_event_tracking(arguments),
            "control_stats_collection" => self.tool_control_stats_collection(arguments),
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

    fn tool_list_events(&self, args: &Value) -> Result<Value> {
        let subsystem = args
            .get("subsystem")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("subsystem parameter is required"))?;

        let event_type = args
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("perf");

        let mut result = json!({});

        if event_type == "kprobe" || event_type == "all" {
            let kprobe_events = crate::available_kprobe_events().unwrap_or_default();
            result["kprobe_events"] = json!({
                "count": kprobe_events.len(),
                "events": kprobe_events,
            });
        }

        if event_type == "perf" || event_type == "all" {
            let perf_events = crate::available_perf_events().unwrap_or_default();

            // Filter by subsystem
            let filtered_events: std::collections::BTreeMap<
                String,
                std::collections::HashSet<String>,
            > = perf_events
                .into_iter()
                .filter(|(sub, _)| sub == subsystem)
                .collect();

            if filtered_events.is_empty() {
                // List available subsystems if the requested one doesn't exist
                let available_subsystems: Vec<String> = crate::available_perf_events()
                    .unwrap_or_default()
                    .keys()
                    .cloned()
                    .collect();

                return Err(anyhow!(
                    "Subsystem '{}' not found. Available subsystems: {}",
                    subsystem,
                    available_subsystems.join(", ")
                ));
            }

            let events_in_subsystem = filtered_events.get(subsystem).map(|s| s.len()).unwrap_or(0);
            result["perf_events"] = json!({
                "subsystem": subsystem,
                "count": events_in_subsystem,
                "events": filtered_events.get(subsystem),
            });
        }

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
                control.enable_event_tracking()?;
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
}
