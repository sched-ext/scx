// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use super::protocol::{McpReadResourceResult, McpResource, McpResourceContent};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

type ResourceHandler = Box<dyn Fn() -> Result<Value> + Send + Sync>;

pub struct McpResources {
    handlers: Arc<Mutex<HashMap<String, ResourceHandler>>>,
    event_stream_tx: Arc<Mutex<Option<UnboundedSender<Value>>>>,
    daemon_mode: Arc<Mutex<bool>>,
}

impl Clone for McpResources {
    fn clone(&self) -> Self {
        Self {
            handlers: Arc::clone(&self.handlers),
            event_stream_tx: Arc::clone(&self.event_stream_tx),
            daemon_mode: Arc::clone(&self.daemon_mode),
        }
    }
}

impl Default for McpResources {
    fn default() -> Self {
        Self::new()
    }
}

impl McpResources {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(Mutex::new(HashMap::new())),
            event_stream_tx: Arc::new(Mutex::new(None)),
            daemon_mode: Arc::new(Mutex::new(false)),
        }
    }

    pub fn register_handler<F>(&self, uri: String, handler: F)
    where
        F: Fn() -> Result<Value> + Send + Sync + 'static,
    {
        self.handlers.lock().unwrap().insert(uri, Box::new(handler));
    }

    pub fn list(&self) -> Value {
        let mut resources = vec![
            McpResource {
                uri: "scheduler://current".to_string(),
                name: "Current Scheduler".to_string(),
                description: Some(
                    "Information about the currently running sched_ext scheduler".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "topology://info".to_string(),
                name: "Hardware Topology".to_string(),
                description: Some(
                    "System topology information (CPUs, cores, LLCs, NUMA nodes)".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://aggregated/cpu".to_string(),
                name: "Per-CPU Statistics".to_string(),
                description: Some("Aggregated statistics for each CPU".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://aggregated/llc".to_string(),
                name: "Per-LLC Statistics".to_string(),
                description: Some(
                    "Aggregated statistics for each last-level cache domain".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://aggregated/node".to_string(),
                name: "Per-Node Statistics".to_string(),
                description: Some("Aggregated statistics for each NUMA node".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://aggregated/dsq".to_string(),
                name: "Dispatch Queue Statistics".to_string(),
                description: Some("Statistics for sched_ext dispatch queues".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://aggregated/process".to_string(),
                name: "Per-Process Statistics".to_string(),
                description: Some(
                    "Aggregated scheduler statistics for each process (all threads combined)"
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://aggregated/thread".to_string(),
                name: "Per-Thread Statistics".to_string(),
                description: Some(
                    "Detailed scheduler statistics for each thread within processes".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://scheduler/raw".to_string(),
                name: "Raw Scheduler Stats".to_string(),
                description: Some("Raw JSON statistics from scx_stats framework".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://scheduler/scx".to_string(),
                name: "sched_ext Kernel Stats".to_string(),
                description: Some("Kernel-level sched_ext statistics".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://system/cpu".to_string(),
                name: "CPU System Stats".to_string(),
                description: Some("System-wide CPU utilization statistics".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://system/memory".to_string(),
                name: "Memory System Stats".to_string(),
                description: Some("System memory statistics".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "stats://system/network".to_string(),
                name: "Network System Stats".to_string(),
                description: Some("Network interface statistics".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "events://perf".to_string(),
                name: "Available Perf Events".to_string(),
                description: Some(
                    "List of all available perf events by subsystem for profiling".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "events://kprobe".to_string(),
                name: "Available Kprobe Events".to_string(),
                description: Some(
                    "List of all available kernel functions for kprobe profiling".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "bpf://programs".to_string(),
                name: "Loaded BPF Programs".to_string(),
                description: Some(
                    "List of currently loaded BPF programs with runtime statistics".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "profiling://perf/status".to_string(),
                name: "Perf Profiling Status".to_string(),
                description: Some(
                    "Current status of perf profiling (running/stopped, sample count, duration)"
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            McpResource {
                uri: "profiling://perf/results".to_string(),
                name: "Perf Profiling Results".to_string(),
                description: Some(
                    "Top symbols and stack traces from perf profiling (kernel and userspace)"
                        .to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
        ];

        // Add event stream resource only in daemon mode
        if *self.daemon_mode.lock().unwrap() {
            resources.push(McpResource {
                uri: "events://stream".to_string(),
                name: "Real-time Event Stream".to_string(),
                description: Some("Live stream of BPF scheduler events".to_string()),
                mime_type: Some("application/x-ndjson".to_string()),
            });
        }

        json!({ "resources": resources })
    }

    pub fn read(&self, uri: &str) -> Result<Value> {
        let handlers = self.handlers.lock().unwrap();
        match handlers.get(uri) {
            Some(handler) => {
                let content_value = handler()?;
                // Wrap the content in MCP resource response format
                let result = McpReadResourceResult {
                    contents: vec![McpResourceContent {
                        uri: uri.to_string(),
                        mime_type: Some("application/json".to_string()),
                        text: Some(serde_json::to_string_pretty(&content_value)?),
                        blob: None,
                    }],
                };
                Ok(serde_json::to_value(result)?)
            }
            None => Err(anyhow!("Resource not found: {}", uri)),
        }
    }

    /// Enable event streaming and return the receiver for events
    pub fn enable_event_streaming(&self) -> UnboundedReceiver<Value> {
        let (tx, rx) = unbounded_channel();
        *self.event_stream_tx.lock().unwrap() = Some(tx);
        *self.daemon_mode.lock().unwrap() = true;
        rx
    }

    /// Push an event to the stream (if enabled)
    pub fn push_event(&self, event: Value) -> Result<()> {
        if let Some(tx) = self.event_stream_tx.lock().unwrap().as_ref() {
            tx.send(event)?;
        }
        Ok(())
    }
}
