// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use libbpf_rs::Link;
use log::{debug, info, warn};
use serde_json::Value as JsonValue;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Command to control stats collection task
#[derive(Debug)]
pub enum StatsControlCommand {
    Start(u64), // Start with interval in milliseconds
    Stop,
}

/// Callback to reattach BPF programs when enabling event tracking
/// Takes a list of program names to attach
pub type AttachCallback = Box<dyn Fn(&[&str]) -> Result<Vec<Link>> + Send + Sync>;

/// Control handle for BPF event tracking and stats collection
/// This allows dynamically starting/stopping collection to minimize overhead
pub struct EventControl {
    /// BPF program links - when Some, programs are attached; when None, detached
    bpf_links: Arc<Mutex<Option<Vec<Link>>>>,
    /// Callback to reattach BPF programs
    attach_callback: Arc<Mutex<Option<AttachCallback>>>,
    /// Current event tracking status
    event_tracking_enabled: Arc<Mutex<bool>>,
    /// Channel to send commands to stats collection task
    stats_control_tx: Option<mpsc::UnboundedSender<StatsControlCommand>>,
    /// Stats collection task status
    stats_collection_running: Arc<Mutex<bool>>,
    /// Current stats collection interval in ms
    stats_collection_interval_ms: Arc<Mutex<u64>>,
}

unsafe impl Send for EventControl {}
unsafe impl Sync for EventControl {}

impl EventControl {
    pub fn new() -> Self {
        Self {
            bpf_links: Arc::new(Mutex::new(None)),
            attach_callback: Arc::new(Mutex::new(None)),
            event_tracking_enabled: Arc::new(Mutex::new(false)),
            stats_control_tx: None,
            stats_collection_running: Arc::new(Mutex::new(false)),
            stats_collection_interval_ms: Arc::new(Mutex::new(100)),
        }
    }

    /// Set BPF links and attach callback
    /// Links will be managed by EventControl - detached on disable, reattached on enable
    pub fn set_bpf_links(&self, links: Vec<Link>, attach_callback: AttachCallback) {
        *self.bpf_links.lock().unwrap() = Some(links);
        *self.attach_callback.lock().unwrap() = Some(attach_callback);
        *self.event_tracking_enabled.lock().unwrap() = true;
        info!(
            "BPF links initialized ({} programs attached)",
            self.bpf_links
                .lock()
                .unwrap()
                .as_ref()
                .map(|l| l.len())
                .unwrap_or(0)
        );
    }

    /// Set the stats control channel for starting/stopping stats collection
    pub fn set_stats_control_channel(&mut self, tx: mpsc::UnboundedSender<StatsControlCommand>) {
        self.stats_control_tx = Some(tx);
    }

    /// Enable BPF event tracking by reattaching specified programs
    ///
    /// # Arguments
    /// * `program_names` - List of BPF program names to attach. If empty, attaches all programs.
    pub fn enable_event_tracking(&self, program_names: &[&str]) -> Result<()> {
        let mut links_guard = self.bpf_links.lock().unwrap();

        // Already enabled
        if links_guard.is_some() {
            info!("BPF event tracking already enabled");
            return Ok(());
        }

        // Reattach programs using callback
        let callback_guard = self.attach_callback.lock().unwrap();
        if let Some(ref callback) = *callback_guard {
            if program_names.is_empty() {
                info!("Reattaching all BPF programs...");
            } else {
                info!(
                    "Reattaching {} BPF programs: {:?}",
                    program_names.len(),
                    program_names
                );
            }
            match callback(program_names) {
                Ok(new_links) => {
                    let count = new_links.len();
                    *links_guard = Some(new_links);
                    *self.event_tracking_enabled.lock().unwrap() = true;
                    info!("BPF event tracking enabled ({} programs attached)", count);
                    Ok(())
                }
                Err(e) => {
                    warn!("Failed to reattach BPF programs: {}", e);
                    Err(anyhow::anyhow!("Failed to reattach BPF programs: {}", e))
                }
            }
        } else {
            Err(anyhow::anyhow!("No attach callback configured"))
        }
    }

    /// Disable BPF event tracking by detaching programs
    /// This drops the links, which detaches the BPF programs
    pub fn disable_event_tracking(&self) -> Result<()> {
        let mut links_guard = self.bpf_links.lock().unwrap();

        if links_guard.is_none() {
            info!("BPF event tracking already disabled");
            return Ok(());
        }

        // Drop links to detach programs
        let count = links_guard.as_ref().map(|l| l.len()).unwrap_or(0);
        *links_guard = None;
        *self.event_tracking_enabled.lock().unwrap() = false;

        info!("BPF event tracking disabled ({} programs detached)", count);
        debug!("BPF programs unloaded, zero overhead from tracepoints");
        Ok(())
    }

    /// Check if event tracking is enabled
    pub fn is_event_tracking_enabled(&self) -> bool {
        self.bpf_links.lock().unwrap().is_some()
    }

    /// Start BPF stats collection with specified interval
    pub fn start_stats_collection(&self, interval_ms: u64) -> Result<()> {
        if let Some(ref tx) = self.stats_control_tx {
            tx.send(StatsControlCommand::Start(interval_ms))
                .map_err(|e| anyhow::anyhow!("Failed to send start command: {}", e))?;
            *self.stats_collection_running.lock().unwrap() = true;
            *self.stats_collection_interval_ms.lock().unwrap() = interval_ms;
            info!(
                "BPF stats collection started with {}ms interval",
                interval_ms
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!("Stats control channel not configured"))
        }
    }

    /// Stop BPF stats collection to reduce overhead
    pub fn stop_stats_collection(&self) -> Result<()> {
        if let Some(ref tx) = self.stats_control_tx {
            tx.send(StatsControlCommand::Stop)
                .map_err(|e| anyhow::anyhow!("Failed to send stop command: {}", e))?;
            *self.stats_collection_running.lock().unwrap() = false;
            info!("BPF stats collection stopped");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Stats control channel not configured"))
        }
    }

    /// Check if BPF stats collection is running
    pub fn is_stats_collection_running(&self) -> bool {
        *self.stats_collection_running.lock().unwrap()
    }

    /// Get current stats collection interval in ms
    pub fn get_stats_collection_interval_ms(&self) -> u64 {
        *self.stats_collection_interval_ms.lock().unwrap()
    }

    /// Get current status as JSON
    pub fn get_status_json(&self) -> JsonValue {
        let links_count = self
            .bpf_links
            .lock()
            .unwrap()
            .as_ref()
            .map(|l| l.len())
            .unwrap_or(0);

        serde_json::json!({
            "event_tracking": {
                "enabled": self.is_event_tracking_enabled(),
                "programs_attached": links_count,
                "description": if self.is_event_tracking_enabled() {
                    format!("BPF programs attached ({} active), collecting scheduler events", links_count)
                } else {
                    "BPF programs detached, zero tracepoint overhead".to_string()
                }
            },
            "stats_collection": {
                "running": self.is_stats_collection_running(),
                "interval_ms": if self.is_stats_collection_running() {
                    Some(self.get_stats_collection_interval_ms())
                } else {
                    None
                },
                "description": if self.is_stats_collection_running() {
                    format!("BPF stats collected every {}ms", self.get_stats_collection_interval_ms())
                } else {
                    "BPF stats collection stopped".to_string()
                }
            },
            "note": "Use control_event_tracking and control_stats_collection tools to manage these settings"
        })
    }
}

impl Default for EventControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared handle for event control
pub type SharedEventControl = Arc<EventControl>;

/// Create a new shared event control
pub fn create_event_control() -> SharedEventControl {
    Arc::new(EventControl::new())
}
