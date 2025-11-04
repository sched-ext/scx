// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::bpf_stats::BpfStatsCollector;
use super::perf_profiling::SharedPerfProfiler;
use super::prompts::McpPrompts;
use super::protocol::*;
use super::resources::McpResources;
use super::shared_state::SharedStatsHandle;
use super::stats_client::SharedStatsClient;
use super::tools::McpTools;
use anyhow::Result;
use log::{debug, error, info};
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};

#[derive(Debug, Clone, Default)]
pub struct McpServerConfig {
    pub daemon_mode: bool,
    pub enable_logging: bool,
}

pub struct McpServer {
    config: McpServerConfig,
    initialized: bool,
    resources: McpResources,
    tools: McpTools,
    prompts: McpPrompts,
    bpf_stats: Option<Arc<BpfStatsCollector>>,
    perf_profiler: Option<SharedPerfProfiler>,
    shared_stats: Option<SharedStatsHandle>,
    topology: Option<Arc<scx_utils::Topology>>,
    stats_client: Option<SharedStatsClient>,
    event_control: Option<super::SharedEventControl>,
    analyzer_control: Option<super::SharedAnalyzerControl>,
}

impl McpServer {
    pub fn new(config: McpServerConfig) -> Self {
        Self {
            config,
            initialized: false,
            resources: McpResources::new(),
            tools: McpTools::new(),
            prompts: McpPrompts::new(),
            bpf_stats: None,
            perf_profiler: None,
            shared_stats: None,
            topology: None,
            stats_client: None,
            event_control: None,
            analyzer_control: None,
        }
    }

    pub fn with_topology(mut self, topo: std::sync::Arc<scx_utils::Topology>) -> Self {
        // Register topology://info resource
        let topo_clone = topo.clone();
        self.resources
            .register_handler("topology://info".to_string(), move || {
                Ok(serde_json::json!({
                    "nr_cpus": topo_clone.all_cpus.len(),
                    "nr_cores": topo_clone.all_cores.len(),
                    "nr_llcs": topo_clone.all_llcs.len(),
                    "nr_nodes": topo_clone.nodes.len(),
                    "cpus": topo_clone.all_cpus.values().map(|c| serde_json::json!({
                        "id": c.id,
                        "core_id": c.core_id,
                        "llc_id": c.llc_id,
                        "node_id": c.node_id,
                    })).collect::<Vec<_>>(),
                }))
            });

        // Also pass topology to tools
        self.tools.set_topology(topo.clone());

        // Store topology for LLC and Node aggregation
        self.topology = Some(topo);
        self
    }

    pub fn setup_scheduler_resource(self) -> Self {
        use crate::util::read_file_string;
        use crate::SCHED_NAME_PATH;

        // Register scheduler://current resource
        self.resources
            .register_handler("scheduler://current".to_string(), || {
                let scheduler =
                    read_file_string(SCHED_NAME_PATH).unwrap_or_else(|_| "unknown".to_string());
                Ok(serde_json::json!({
                    "name": scheduler.trim(),
                    "class": if scheduler.starts_with("scx_") { "sched_ext" } else { "other" },
                    "active": !scheduler.trim().is_empty() && scheduler != "unknown",
                }))
            });
        self
    }

    pub fn setup_profiling_resources(mut self) -> Self {
        use crate::profiling_events::{available_kprobe_events, available_perf_events};

        // Create BPF stats collector
        let bpf_stats = Arc::new(BpfStatsCollector::new());

        // Collect initial sample
        let _ = bpf_stats.collect_sample();

        // Register events://perf resource - list all available perf events
        self.resources
            .register_handler("events://perf".to_string(), || {
                let events = available_perf_events().unwrap_or_default();

                // Convert BTreeMap<String, HashSet<String>> to JSON
                let subsystems: Vec<_> = events
                    .iter()
                    .map(|(subsystem, event_set)| {
                        let mut events_vec: Vec<_> = event_set.iter().cloned().collect();
                        events_vec.sort();
                        serde_json::json!({
                            "subsystem": subsystem,
                            "events": events_vec,
                            "count": events_vec.len(),
                        })
                    })
                    .collect();

                Ok(serde_json::json!({
                    "subsystems": subsystems,
                    "total_subsystems": events.len(),
                    "total_events": events.values().map(|s| s.len()).sum::<usize>(),
                }))
            });

        // Register events://kprobe resource - list all available kprobe events
        self.resources
            .register_handler("events://kprobe".to_string(), || {
                let events = available_kprobe_events().unwrap_or_default();

                Ok(serde_json::json!({
                    "functions": events,
                    "count": events.len(),
                }))
            });

        // Register bpf://programs resource - list loaded BPF programs with statistics
        let bpf_stats_clone = Arc::clone(&bpf_stats);
        self.resources
            .register_handler("bpf://programs".to_string(), move || {
                Ok(bpf_stats_clone.get_stats())
            });

        // Create perf profiler for stack trace collection
        let perf_profiler = SharedPerfProfiler::new();

        // Register profiling://perf/status resource
        let profiler_status = perf_profiler.clone();
        self.resources
            .register_handler("profiling://perf/status".to_string(), move || {
                Ok(profiler_status.get_status())
            });

        // Register profiling://perf/results resource
        let profiler_results = perf_profiler.clone();
        self.resources
            .register_handler("profiling://perf/results".to_string(), move || {
                Ok(profiler_results.get_results(50, true))
            });

        // Set perf profiler in tools
        self.tools.set_perf_profiler(perf_profiler.clone());

        // Set topology on perf profiler if available
        if let Some(ref topo) = self.topology {
            perf_profiler.set_topology(topo.clone());
        }

        self.bpf_stats = Some(bpf_stats);
        self.perf_profiler = Some(perf_profiler);
        self
    }

    pub fn with_bpf_perf_attacher(
        self,
        attacher: std::sync::Arc<dyn super::perf_profiling::PerfEventAttacher>,
    ) -> Self {
        if let Some(ref profiler) = self.perf_profiler {
            profiler.set_bpf_attacher(attacher);
        }
        self
    }

    pub fn setup_stats_resources(self) -> Self {
        // Register handlers for aggregated stats resources using shared state

        let shared_stats_cpu = self.shared_stats.clone();
        self.resources
            .register_handler("stats://aggregated/cpu".to_string(), move || {
                if let Some(ref stats) = shared_stats_cpu {
                    // Enable tracking on first access
                    if let Ok(mut stats_write) = stats.write() {
                        stats_write.enable_tracking();
                    }

                    match stats.read() {
                        Ok(stats) => Ok(stats.get_cpu_stats_json()),
                        Err(e) => Ok(serde_json::json!({
                            "error": "lock_failed",
                            "message": format!("Failed to acquire stats lock: {}", e)
                        })),
                    }
                } else {
                    Ok(serde_json::json!({
                        "error": "not_available",
                        "message": "CPU aggregated stats require daemon mode",
                        "note": "Start scxtop MCP with --daemon flag to enable this feature"
                    }))
                }
            });

        // Process-level stats (aggregated across all threads)
        let shared_stats_process = self.shared_stats.clone();
        self.resources
            .register_handler("stats://aggregated/process".to_string(), move || {
                if let Some(ref stats) = shared_stats_process {
                    // Enable tracking on first access
                    if let Ok(mut stats_write) = stats.write() {
                        stats_write.enable_tracking();
                    }

                    match stats.read() {
                        Ok(stats) => Ok(stats.get_aggregated_process_stats_json(Some(100))),
                        Err(e) => Ok(serde_json::json!({
                            "error": "lock_failed",
                            "message": format!("Failed to acquire stats lock: {}", e)
                        })),
                    }
                } else {
                    Ok(serde_json::json!({
                        "error": "not_available",
                        "message": "Per-process aggregated stats require daemon mode",
                        "note": "Start scxtop MCP with --daemon flag to enable this feature"
                    }))
                }
            });

        // Thread-level stats (per-thread details)
        let shared_stats_thread = self.shared_stats.clone();
        self.resources
            .register_handler("stats://aggregated/thread".to_string(), move || {
                if let Some(ref stats) = shared_stats_thread {
                    // Enable tracking on first access
                    if let Ok(mut stats_write) = stats.write() {
                        stats_write.enable_tracking();
                    }

                    match stats.read() {
                        Ok(stats) => Ok(stats.get_process_stats_json(Some(100))),
                        Err(e) => Ok(serde_json::json!({
                            "error": "lock_failed",
                            "message": format!("Failed to acquire stats lock: {}", e)
                        })),
                    }
                } else {
                    Ok(serde_json::json!({
                        "error": "not_available",
                        "message": "Per-thread stats require daemon mode",
                        "note": "Start scxtop MCP with --daemon flag to enable this feature"
                    }))
                }
            });

        let shared_stats_dsq = self.shared_stats.clone();
        self.resources
            .register_handler("stats://aggregated/dsq".to_string(), move || {
                if let Some(ref stats) = shared_stats_dsq {
                    // Enable tracking on first access
                    if let Ok(mut stats_write) = stats.write() {
                        stats_write.enable_tracking();
                    }

                    match stats.read() {
                        Ok(stats) => Ok(stats.get_dsq_stats_json()),
                        Err(e) => Ok(serde_json::json!({
                            "error": "lock_failed",
                            "message": format!("Failed to acquire stats lock: {}", e)
                        })),
                    }
                } else {
                    Ok(serde_json::json!({
                        "error": "not_available",
                        "message": "Dispatch queue stats require daemon mode",
                        "note": "Start scxtop MCP with --daemon flag to enable this feature"
                    }))
                }
            });

        // LLC aggregated stats
        let shared_stats_llc = self.shared_stats.clone();
        let topology_llc = self.topology.clone();
        self.resources
            .register_handler("stats://aggregated/llc".to_string(), move || {
                if let (Some(ref stats), Some(ref topo)) = (&shared_stats_llc, &topology_llc) {
                    // Enable tracking on first access
                    if let Ok(mut stats_write) = stats.write() {
                        stats_write.enable_tracking();
                    }

                    match stats.read() {
                        Ok(stats) => Ok(stats.get_llc_stats_json(topo)),
                        Err(e) => Ok(serde_json::json!({
                            "error": "lock_failed",
                            "message": format!("Failed to acquire stats lock: {}", e)
                        })),
                    }
                } else {
                    Ok(serde_json::json!({
                        "error": "not_available",
                        "message": "LLC aggregated stats require daemon mode and topology information",
                        "note": "Start scxtop MCP with --daemon flag to enable this feature"
                    }))
                }
            });

        // NUMA node aggregated stats
        let shared_stats_node = self.shared_stats.clone();
        let topology_node = self.topology.clone();
        self.resources
            .register_handler("stats://aggregated/node".to_string(), move || {
                if let (Some(ref stats), Some(ref topo)) = (&shared_stats_node, &topology_node) {
                    // Enable tracking on first access
                    if let Ok(mut stats_write) = stats.write() {
                        stats_write.enable_tracking();
                    }

                    match stats.read() {
                        Ok(stats) => Ok(stats.get_node_stats_json(topo)),
                        Err(e) => Ok(serde_json::json!({
                            "error": "lock_failed",
                            "message": format!("Failed to acquire stats lock: {}", e)
                        })),
                    }
                } else {
                    Ok(serde_json::json!({
                        "error": "not_available",
                        "message": "NUMA node aggregated stats require daemon mode and topology information",
                        "note": "Start scxtop MCP with --daemon flag to enable this feature"
                    }))
                }
            });

        // Register handler for scheduler stats from scx_stats framework
        let stats_client = self.stats_client.clone();
        self.resources
            .register_handler("stats://scheduler/raw".to_string(), move || {
                if let Some(ref client) = stats_client {
                    // Request both stats and stats_meta to provide complete information
                    let stats_result = client.request_stats(None)?;
                    let meta_result = client.request_stats_meta()?;

                    Ok(serde_json::json!({
                        "stats": stats_result,
                        "stats_meta": meta_result,
                        "note": "Stats from scheduler's scx_stats server. Use stats_meta to understand the format."
                    }))
                } else {
                    Ok(serde_json::json!({
                        "error": "not_configured",
                        "message": "Stats client not configured",
                        "note": "Set up stats client with socket path to connect to scheduler's stats server"
                    }))
                }
            });

        self.resources
            .register_handler("stats://scheduler/scx".to_string(), || {
                // Read kernel-level sched_ext stats from /sys/kernel/debug/sched/ext
                let stats_path = "/sys/kernel/debug/sched/ext";
                match std::fs::read_to_string(stats_path) {
                    Ok(content) => Ok(serde_json::json!({
                        "path": stats_path,
                        "content": content,
                    })),
                    Err(e) => Ok(serde_json::json!({
                        "error": "cannot_read",
                        "message": format!("Failed to read {}: {}", stats_path, e),
                        "note": "Try running as root or check if debugfs is mounted"
                    })),
                }
            });

        // Register stub handlers for system stats resources
        self.resources
            .register_handler("stats://system/cpu".to_string(), || {
                use crate::cpu_stats::CpuStatTracker;
                use sysinfo::System;

                // Create a temporary stat tracker and system
                let mut tracker = CpuStatTracker::default();
                let mut sys = System::new_all();

                match tracker.update(&mut sys) {
                    Ok(_) => {
                        let active = tracker.system_active_util();
                        let total = tracker.system_total_util();
                        let idle_pct = if total > 0 {
                            100.0 - (active as f64 / total as f64 * 100.0)
                        } else {
                            100.0
                        };

                        Ok(serde_json::json!({
                            "active_util": active,
                            "total_util": total,
                            "idle_pct": idle_pct,
                            "note": "Instantaneous snapshot, not averaged over time"
                        }))
                    }
                    Err(e) => Ok(serde_json::json!({
                        "error": "read_failed",
                        "message": format!("Failed to read CPU stats: {}", e)
                    })),
                }
            });

        self.resources
            .register_handler("stats://system/memory".to_string(), || {
                use crate::mem_stats::MemStatSnapshot;

                let mut stats = MemStatSnapshot::default();
                match stats.update() {
                    Ok(_) => Ok(serde_json::json!({
                        "total_kb": stats.total_kb,
                        "free_kb": stats.free_kb,
                        "available_kb": stats.available_kb,
                        "buffers_kb": stats.buffers_kb,
                        "cached_kb": stats.cached_kb,
                        "swap_total_kb": stats.swap_total_kb,
                        "swap_free_kb": stats.swap_free_kb,
                        "free_ratio": stats.free_ratio(),
                        "swap_ratio": stats.swap_ratio(),
                    })),
                    Err(e) => Ok(serde_json::json!({
                        "error": "read_failed",
                        "message": format!("Failed to read memory stats: {}", e)
                    })),
                }
            });

        self.resources
            .register_handler("stats://system/network".to_string(), || {
                use crate::network_stats::NetworkStatSnapshot;

                let mut snapshot = NetworkStatSnapshot::default();
                match snapshot.update() {
                    Ok(_) => {
                        // Convert NetworkStatSnapshot to JSON
                        let interfaces: Vec<_> = snapshot
                            .interfaces
                            .iter()
                            .map(|(name, iface)| {
                                serde_json::json!({
                                    "name": name,
                                    "recv_bytes": iface.recv_bytes,
                                    "sent_bytes": iface.sent_bytes,
                                    "recv_packets": iface.recv_packets,
                                    "sent_packets": iface.sent_packets,
                                })
                            })
                            .collect();

                        Ok(serde_json::json!({
                            "interfaces": interfaces,
                            "total_recv_bytes": snapshot.get_total_recv_bytes(),
                            "total_sent_bytes": snapshot.get_total_sent_bytes(),
                        }))
                    }
                    Err(e) => Ok(serde_json::json!({
                        "error": "read_failed",
                        "message": format!("Failed to read network stats: {}", e)
                    })),
                }
            });

        self
    }

    pub fn get_bpf_stats_collector(&self) -> Option<Arc<BpfStatsCollector>> {
        self.bpf_stats.as_ref().map(Arc::clone)
    }

    pub fn get_perf_profiler(&self) -> Option<SharedPerfProfiler> {
        self.perf_profiler.clone()
    }

    pub fn with_shared_stats(mut self, shared_stats: SharedStatsHandle) -> Self {
        self.shared_stats = Some(shared_stats);
        self
    }

    pub fn get_shared_stats(&self) -> Option<SharedStatsHandle> {
        self.shared_stats.clone()
    }

    pub fn with_stats_client(mut self, socket_path: Option<String>) -> Self {
        self.stats_client = Some(SharedStatsClient::new(socket_path));
        self
    }

    pub fn get_stats_client(&self) -> Option<SharedStatsClient> {
        self.stats_client.clone()
    }

    pub fn with_event_control(mut self, event_control: super::SharedEventControl) -> Self {
        // Register control://events/status resource
        let control_status = event_control.clone();
        self.resources
            .register_handler("control://events/status".to_string(), move || {
                Ok(control_status.get_status_json())
            });

        // Pass event control to tools
        self.tools.set_event_control(event_control.clone());

        self.event_control = Some(event_control);
        self
    }

    pub fn get_event_control(&self) -> Option<super::SharedEventControl> {
        self.event_control.clone()
    }

    pub fn with_analyzer_control(mut self, analyzer_control: super::SharedAnalyzerControl) -> Self {
        // Pass analyzer control to tools
        self.tools.set_analyzer_control(analyzer_control.clone());

        self.analyzer_control = Some(analyzer_control);
        self
    }

    pub fn get_analyzer_control(&self) -> Option<super::SharedAnalyzerControl> {
        self.analyzer_control.clone()
    }

    pub fn with_trace_cache(
        mut self,
        cache: std::sync::Arc<
            std::sync::Mutex<
                std::collections::HashMap<String, std::sync::Arc<super::PerfettoTrace>>,
            >,
        >,
    ) -> Self {
        // Pass trace cache to tools
        self.tools.set_trace_cache(cache);
        self
    }

    pub fn tools_mut(&mut self) -> &mut McpTools {
        &mut self.tools
    }

    /// Run the MCP server in blocking mode (reads from stdin, writes to stdout)
    pub fn run_blocking(&mut self) -> Result<()> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let reader = BufReader::new(stdin.lock());

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            debug!("Received: {}", line);
            let response = self.handle_request(&line);
            let response_json = serde_json::to_string(&response)? + "\n";
            debug!("Sending: {}", response_json.trim());
            stdout.write_all(response_json.as_bytes())?;
            stdout.flush()?;
        }

        Ok(())
    }

    /// Run the MCP server in async mode (for daemon mode with tokio)
    pub async fn run_async(&mut self) -> Result<()> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = AsyncBufReader::new(stdin).lines();

        while let Some(line) = reader.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            debug!("Received: {}", line);
            let response = self.handle_request(&line);
            let response_json = serde_json::to_string(&response)? + "\n";
            debug!("Sending: {}", response_json.trim());
            stdout.write_all(response_json.as_bytes()).await?;
            stdout.flush().await?;

            // In one-shot mode, exit after first request (after initialize)
            if !self.config.daemon_mode && self.initialized {
                break;
            }
        }

        Ok(())
    }

    fn handle_request(&mut self, line: &str) -> JsonRpcResponse {
        // Parse request
        let request: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to parse request: {}", e);
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError::parse_error()),
                    id: None,
                };
            }
        };

        // Dispatch to method handler
        let result = self.dispatch_method(&request);

        match result {
            Ok(result) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(result),
                error: None,
                id: request.id.clone(),
            },
            Err(error) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(error),
                id: request.id.clone(),
            },
        }
    }

    fn dispatch_method(
        &mut self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, JsonRpcError> {
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "resources/list" => self.handle_resources_list(request),
            "resources/read" => self.handle_resources_read(request),
            "tools/list" => self.handle_tools_list(request),
            "tools/call" => self.handle_tools_call(request),
            "prompts/list" => self.handle_prompts_list(request),
            "prompts/get" => self.handle_prompts_get(request),
            _ => Err(JsonRpcError::method_not_found(&request.method)),
        }
    }

    fn handle_initialize(
        &mut self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, JsonRpcError> {
        let _params: McpInitializeParams = match &request.params {
            Some(p) => serde_json::from_value(p.clone())
                .map_err(|e| JsonRpcError::invalid_params(&e.to_string()))?,
            None => return Err(JsonRpcError::invalid_params("Missing params")),
        };

        self.initialized = true;
        info!("MCP server initialized");

        let result = McpInitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: McpServerCapabilities {
                experimental: None,
                logging: if self.config.enable_logging {
                    Some(serde_json::json!({}))
                } else {
                    None
                },
                prompts: Some(McpPromptsCapability {
                    list_changed: Some(false),
                }),
                resources: Some(McpResourcesCapability {
                    subscribe: Some(false),
                    list_changed: Some(false),
                }),
                tools: Some(McpToolsCapability {
                    list_changed: Some(false),
                }),
            },
            server_info: McpImplementationInfo {
                name: "scxtop-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        Ok(serde_json::to_value(result).unwrap())
    }

    fn handle_resources_list(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, JsonRpcError> {
        if !self.initialized {
            return Err(JsonRpcError::invalid_request());
        }
        Ok(self.resources.list())
    }

    fn handle_resources_read(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, JsonRpcError> {
        if !self.initialized {
            return Err(JsonRpcError::invalid_request());
        }
        let params = request
            .params
            .as_ref()
            .ok_or_else(|| JsonRpcError::invalid_params("Missing params"))?;
        let uri = params
            .get("uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError::invalid_params("Missing uri"))?;

        // Special handling for event stream
        if uri == "events://stream" {
            if !self.config.daemon_mode {
                return Err(JsonRpcError::internal_error(
                    "Event streaming only available in daemon mode",
                ));
            }
            // Return metadata about the stream
            return Ok(serde_json::json!({
                "uri": uri,
                "stream": true,
                "mime_type": "application/x-ndjson",
                "description": "Use resources/subscribe to subscribe to events",
            }));
        }

        self.resources
            .read(uri)
            .map_err(|e| JsonRpcError::internal_error(&e.to_string()))
    }

    fn handle_tools_list(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, JsonRpcError> {
        if !self.initialized {
            return Err(JsonRpcError::invalid_request());
        }
        Ok(self.tools.list())
    }

    fn handle_tools_call(
        &mut self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, JsonRpcError> {
        if !self.initialized {
            return Err(JsonRpcError::invalid_request());
        }
        let params = request
            .params
            .as_ref()
            .ok_or_else(|| JsonRpcError::invalid_params("Missing params"))?;

        self.tools
            .call(params)
            .map_err(|e| JsonRpcError::internal_error(&e.to_string()))
    }

    fn handle_prompts_list(
        &self,
        _request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, JsonRpcError> {
        if !self.initialized {
            return Err(JsonRpcError::invalid_request());
        }
        Ok(self.prompts.list())
    }

    fn handle_prompts_get(
        &self,
        request: &JsonRpcRequest,
    ) -> Result<serde_json::Value, JsonRpcError> {
        if !self.initialized {
            return Err(JsonRpcError::invalid_request());
        }
        let params = request
            .params
            .as_ref()
            .ok_or_else(|| JsonRpcError::invalid_params("Missing params"))?;
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError::invalid_params("Missing name"))?;

        self.prompts
            .get(name, params)
            .map_err(|e| JsonRpcError::internal_error(&e.to_string()))
    }

    /// Enable event streaming and return the receiver
    pub fn enable_event_streaming(
        &mut self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<serde_json::Value> {
        self.resources.enable_event_streaming()
    }

    /// Get a cloneable handle to resources for event pushing
    pub fn get_resources_handle(&self) -> McpResources {
        self.resources.clone()
    }
}
