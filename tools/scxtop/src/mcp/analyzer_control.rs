// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Unified control interface for all event analyzers
//!
//! This module provides a centralized way to start, stop, and monitor
//! all event analyzers to prevent continuous overhead.

use super::analyzers::{CpuHotspotAnalyzer, LatencyTracker, MigrationAnalyzer};
use super::event_buffer::EventBuffer;
use super::event_control::SharedEventControl;
use super::extended_analyzers::{
    DsqMonitor, EventRateMonitor, ProcessEventHistory, SoftirqAnalyzer, WakeupChainTracker,
};
use super::waker_wakee_analyzer::WakerWakeeAnalyzer;
use log::{info, warn};
use serde::Serialize;
use std::sync::{Arc, Mutex};

/// Unified control for all analyzers with automatic BPF program management
pub struct AnalyzerControl {
    event_buffer: Option<Arc<Mutex<EventBuffer>>>,
    latency_tracker: Option<Arc<Mutex<LatencyTracker>>>,
    cpu_hotspot_analyzer: Option<Arc<Mutex<CpuHotspotAnalyzer>>>,
    migration_analyzer: Option<Arc<Mutex<MigrationAnalyzer>>>,
    process_history: Option<Arc<Mutex<ProcessEventHistory>>>,
    dsq_monitor: Option<Arc<Mutex<DsqMonitor>>>,
    rate_monitor: Option<Arc<Mutex<EventRateMonitor>>>,
    wakeup_tracker: Option<Arc<Mutex<WakeupChainTracker>>>,
    waker_wakee_analyzer: Option<Arc<Mutex<WakerWakeeAnalyzer>>>,
    softirq_analyzer: Option<Arc<Mutex<SoftirqAnalyzer>>>,
    /// Optional EventControl for automatic BPF program attach/detach
    event_control: Option<SharedEventControl>,
}

impl AnalyzerControl {
    pub fn new() -> Self {
        Self {
            event_buffer: None,
            latency_tracker: None,
            cpu_hotspot_analyzer: None,
            migration_analyzer: None,
            process_history: None,
            dsq_monitor: None,
            rate_monitor: None,
            wakeup_tracker: None,
            waker_wakee_analyzer: None,
            softirq_analyzer: None,
            event_control: None,
        }
    }

    /// Set EventControl for automatic BPF program attach/detach
    ///
    /// When set, AnalyzerControl will automatically:
    /// - Attach BPF programs when first analyzer starts
    /// - Detach BPF programs when last analyzer stops
    ///
    /// This provides true zero overhead when no analyzers are running.
    pub fn set_event_control(&mut self, event_control: SharedEventControl) {
        self.event_control = Some(event_control);
    }

    /// Get list of BPF programs needed by currently enabled analyzers
    fn get_required_bpf_programs(&self) -> Vec<&'static str> {
        let mut programs = std::collections::HashSet::new();

        // event_buffer needs all events - don't specify any to attach all
        if self
            .event_buffer
            .as_ref()
            .is_some_and(|b| b.lock().unwrap().is_enabled())
        {
            return vec![]; // Empty list means attach all
        }

        // latency_tracker needs wakeup + switch
        if self
            .latency_tracker
            .as_ref()
            .is_some_and(|t| t.lock().unwrap().is_enabled())
        {
            programs.insert("on_sched_wakeup");
            programs.insert("on_sched_waking");
            programs.insert("on_sched_switch");
        }

        // cpu_hotspot_analyzer needs switch
        if self
            .cpu_hotspot_analyzer
            .as_ref()
            .is_some_and(|a| a.lock().unwrap().is_enabled())
        {
            programs.insert("on_sched_switch");
        }

        // migration_analyzer needs migrate
        if self
            .migration_analyzer
            .as_ref()
            .is_some_and(|a| a.lock().unwrap().is_enabled())
        {
            programs.insert("on_sched_migrate_task");
        }

        // process_history needs multiple events
        if self
            .process_history
            .as_ref()
            .is_some_and(|h| h.lock().unwrap().is_enabled())
        {
            programs.insert("on_sched_switch");
            programs.insert("on_sched_wakeup");
            programs.insert("on_sched_waking");
            programs.insert("on_sched_migrate_task");
        }

        // dsq_monitor needs dispatch events
        if self
            .dsq_monitor
            .as_ref()
            .is_some_and(|m| m.lock().unwrap().is_enabled())
        {
            // Note: Actual programs depend on kernel version, handled by attach_progs
            programs.insert("scx_insert");
            programs.insert("scx_insert_vtime");
            programs.insert("scx_dispatch");
            programs.insert("scx_dispatch_vtime");
            programs.insert("scx_dispatch_from_dsq");
            programs.insert("scx_dispatch_from_dsq_set_vtime");
            programs.insert("scx_dispatch_from_dsq_set_slice");
            programs.insert("scx_dsq_move");
            programs.insert("scx_dsq_move_set_vtime");
            programs.insert("scx_dsq_move_set_slice");
        }

        // rate_monitor needs common events
        if self
            .rate_monitor
            .as_ref()
            .is_some_and(|m| m.lock().unwrap().is_enabled())
        {
            programs.insert("on_sched_switch");
            programs.insert("on_sched_wakeup");
            programs.insert("on_sched_waking");
            programs.insert("on_sched_migrate_task");
        }

        // wakeup_tracker needs wakeup
        if self
            .wakeup_tracker
            .as_ref()
            .is_some_and(|t| t.lock().unwrap().is_enabled())
        {
            programs.insert("on_sched_wakeup");
        }

        // waker_wakee_analyzer needs wakeup events
        if self
            .waker_wakee_analyzer
            .as_ref()
            .is_some_and(|a| a.lock().unwrap().is_enabled())
        {
            programs.insert("on_sched_wakeup");
            programs.insert("on_sched_waking");
        }

        // softirq_analyzer needs softirq events
        if self
            .softirq_analyzer
            .as_ref()
            .is_some_and(|a| a.lock().unwrap().is_enabled())
        {
            programs.insert("on_softirq_entry");
            programs.insert("on_softirq_exit");
        }

        programs.into_iter().collect()
    }

    /// Check if BPF event tracking should be enabled/disabled
    /// Returns true if state changed
    fn manage_bpf_state(&self, enable: bool) -> bool {
        if let Some(ref ec) = self.event_control {
            let currently_enabled = ec.is_event_tracking_enabled();

            if enable && !currently_enabled {
                // Get required programs based on enabled analyzers
                let required_progs = self.get_required_bpf_programs();
                let prog_refs: Vec<&str> = required_progs.to_vec();

                // Need to enable BPF tracking
                match ec.enable_event_tracking(&prog_refs) {
                    Ok(()) => {
                        info!("BPF event tracking enabled (first analyzer started)");
                        return true;
                    }
                    Err(e) => {
                        warn!("Failed to enable BPF event tracking: {}", e);
                    }
                }
            } else if !enable && currently_enabled {
                // Need to disable BPF tracking
                match ec.disable_event_tracking() {
                    Ok(()) => {
                        info!("BPF event tracking disabled (all analyzers stopped)");
                        return true;
                    }
                    Err(e) => {
                        warn!("Failed to disable BPF event tracking: {}", e);
                    }
                }
            }
        }
        false
    }

    /// Register an event buffer
    pub fn set_event_buffer(&mut self, buffer: Arc<Mutex<EventBuffer>>) {
        self.event_buffer = Some(buffer);
    }

    /// Register a latency tracker
    pub fn set_latency_tracker(&mut self, tracker: Arc<Mutex<LatencyTracker>>) {
        self.latency_tracker = Some(tracker);
    }

    /// Register a CPU hotspot analyzer
    pub fn set_cpu_hotspot_analyzer(&mut self, analyzer: Arc<Mutex<CpuHotspotAnalyzer>>) {
        self.cpu_hotspot_analyzer = Some(analyzer);
    }

    /// Register a migration analyzer
    pub fn set_migration_analyzer(&mut self, analyzer: Arc<Mutex<MigrationAnalyzer>>) {
        self.migration_analyzer = Some(analyzer);
    }

    /// Register a process event history tracker
    pub fn set_process_history(&mut self, history: Arc<Mutex<ProcessEventHistory>>) {
        self.process_history = Some(history);
    }

    /// Register a DSQ monitor
    pub fn set_dsq_monitor(&mut self, monitor: Arc<Mutex<DsqMonitor>>) {
        self.dsq_monitor = Some(monitor);
    }

    /// Register an event rate monitor
    pub fn set_rate_monitor(&mut self, monitor: Arc<Mutex<EventRateMonitor>>) {
        self.rate_monitor = Some(monitor);
    }

    /// Register a wakeup chain tracker
    pub fn set_wakeup_tracker(&mut self, tracker: Arc<Mutex<WakeupChainTracker>>) {
        self.wakeup_tracker = Some(tracker);
    }

    /// Register a waker/wakee relationship analyzer
    pub fn set_waker_wakee_analyzer(&mut self, analyzer: Arc<Mutex<WakerWakeeAnalyzer>>) {
        self.waker_wakee_analyzer = Some(analyzer);
    }

    /// Register a softirq analyzer
    pub fn set_softirq_analyzer(&mut self, analyzer: Arc<Mutex<SoftirqAnalyzer>>) {
        self.softirq_analyzer = Some(analyzer);
    }

    /// Start a specific analyzer with automatic BPF control
    pub fn start_analyzer(&self, name: &str) -> Result<(), String> {
        // Check if any analyzers are currently enabled
        let status_before = self.get_status();
        let was_any_enabled = status_before.any_enabled();

        // Start the requested analyzer
        match name {
            "event_buffer" => {
                if let Some(ref buffer) = self.event_buffer {
                    buffer.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("Event buffer not registered".to_string())
                }
            }
            "latency_tracker" => {
                if let Some(ref tracker) = self.latency_tracker {
                    tracker.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("Latency tracker not registered".to_string())
                }
            }
            "cpu_hotspot_analyzer" => {
                if let Some(ref analyzer) = self.cpu_hotspot_analyzer {
                    analyzer.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("CPU hotspot analyzer not registered".to_string())
                }
            }
            "migration_analyzer" => {
                if let Some(ref analyzer) = self.migration_analyzer {
                    analyzer.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("Migration analyzer not registered".to_string())
                }
            }
            "process_history" => {
                if let Some(ref history) = self.process_history {
                    history.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("Process history not registered".to_string())
                }
            }
            "dsq_monitor" => {
                if let Some(ref monitor) = self.dsq_monitor {
                    monitor.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("DSQ monitor not registered".to_string())
                }
            }
            "rate_monitor" => {
                if let Some(ref monitor) = self.rate_monitor {
                    monitor.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("Rate monitor not registered".to_string())
                }
            }
            "wakeup_tracker" => {
                if let Some(ref tracker) = self.wakeup_tracker {
                    tracker.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("Wakeup tracker not registered".to_string())
                }
            }
            "waker_wakee_analyzer" => {
                if let Some(ref analyzer) = self.waker_wakee_analyzer {
                    analyzer.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("Waker/wakee analyzer not registered".to_string())
                }
            }
            "softirq_analyzer" => {
                if let Some(ref analyzer) = self.softirq_analyzer {
                    analyzer.lock().unwrap().start();
                    Ok(())
                } else {
                    Err("Softirq analyzer not registered".to_string())
                }
            }
            "all" => {
                self.start_all();
                Ok(())
            }
            _ => Err(format!("Unknown analyzer: {}", name)),
        }?;

        // If this was the first analyzer started, enable BPF tracking
        if !was_any_enabled {
            self.manage_bpf_state(true);
        }

        Ok(())
    }

    /// Stop a specific analyzer with automatic BPF control
    pub fn stop_analyzer(&self, name: &str) -> Result<(), String> {
        // Stop the requested analyzer
        match name {
            "event_buffer" => {
                if let Some(ref buffer) = self.event_buffer {
                    buffer.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("Event buffer not registered".to_string())
                }
            }
            "latency_tracker" => {
                if let Some(ref tracker) = self.latency_tracker {
                    tracker.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("Latency tracker not registered".to_string())
                }
            }
            "cpu_hotspot_analyzer" => {
                if let Some(ref analyzer) = self.cpu_hotspot_analyzer {
                    analyzer.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("CPU hotspot analyzer not registered".to_string())
                }
            }
            "migration_analyzer" => {
                if let Some(ref analyzer) = self.migration_analyzer {
                    analyzer.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("Migration analyzer not registered".to_string())
                }
            }
            "process_history" => {
                if let Some(ref history) = self.process_history {
                    history.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("Process history not registered".to_string())
                }
            }
            "dsq_monitor" => {
                if let Some(ref monitor) = self.dsq_monitor {
                    monitor.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("DSQ monitor not registered".to_string())
                }
            }
            "rate_monitor" => {
                if let Some(ref monitor) = self.rate_monitor {
                    monitor.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("Rate monitor not registered".to_string())
                }
            }
            "wakeup_tracker" => {
                if let Some(ref tracker) = self.wakeup_tracker {
                    tracker.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("Wakeup tracker not registered".to_string())
                }
            }
            "waker_wakee_analyzer" => {
                if let Some(ref analyzer) = self.waker_wakee_analyzer {
                    analyzer.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("Waker/wakee analyzer not registered".to_string())
                }
            }
            "softirq_analyzer" => {
                if let Some(ref analyzer) = self.softirq_analyzer {
                    analyzer.lock().unwrap().stop();
                    Ok(())
                } else {
                    Err("Softirq analyzer not registered".to_string())
                }
            }
            "all" => {
                self.stop_all();
                Ok(())
            }
            _ => Err(format!("Unknown analyzer: {}", name)),
        }?;

        // Check if all analyzers are now stopped
        let status_after = self.get_status();
        if !status_after.any_enabled() {
            // All analyzers stopped - disable BPF tracking
            self.manage_bpf_state(false);
        }

        Ok(())
    }

    /// Reset a specific analyzer (clear all data)
    pub fn reset_analyzer(&self, name: &str) -> Result<(), String> {
        match name {
            "event_buffer" => {
                if let Some(ref buffer) = self.event_buffer {
                    buffer.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("Event buffer not registered".to_string())
                }
            }
            "latency_tracker" => {
                if let Some(ref tracker) = self.latency_tracker {
                    tracker.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("Latency tracker not registered".to_string())
                }
            }
            "cpu_hotspot_analyzer" => {
                if let Some(ref analyzer) = self.cpu_hotspot_analyzer {
                    analyzer.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("CPU hotspot analyzer not registered".to_string())
                }
            }
            "migration_analyzer" => {
                if let Some(ref analyzer) = self.migration_analyzer {
                    analyzer.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("Migration analyzer not registered".to_string())
                }
            }
            "process_history" => {
                if let Some(ref history) = self.process_history {
                    history.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("Process history not registered".to_string())
                }
            }
            "dsq_monitor" => {
                if let Some(ref monitor) = self.dsq_monitor {
                    monitor.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("DSQ monitor not registered".to_string())
                }
            }
            "rate_monitor" => {
                if let Some(ref monitor) = self.rate_monitor {
                    monitor.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("Rate monitor not registered".to_string())
                }
            }
            "wakeup_tracker" => {
                if let Some(ref tracker) = self.wakeup_tracker {
                    tracker.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("Wakeup tracker not registered".to_string())
                }
            }
            "waker_wakee_analyzer" => {
                if let Some(ref analyzer) = self.waker_wakee_analyzer {
                    analyzer.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("Waker/wakee analyzer not registered".to_string())
                }
            }
            "softirq_analyzer" => {
                if let Some(ref analyzer) = self.softirq_analyzer {
                    analyzer.lock().unwrap().reset();
                    Ok(())
                } else {
                    Err("Softirq analyzer not registered".to_string())
                }
            }
            "all" => {
                self.reset_all();
                Ok(())
            }
            _ => Err(format!("Unknown analyzer: {}", name)),
        }
    }

    /// Start all registered analyzers with automatic BPF control
    pub fn start_all(&self) {
        // Check if any analyzers are currently enabled
        let status_before = self.get_status();
        let was_any_enabled = status_before.any_enabled();

        // Start all registered analyzers
        if let Some(ref buffer) = self.event_buffer {
            buffer.lock().unwrap().start();
        }
        if let Some(ref tracker) = self.latency_tracker {
            tracker.lock().unwrap().start();
        }
        if let Some(ref analyzer) = self.cpu_hotspot_analyzer {
            analyzer.lock().unwrap().start();
        }
        if let Some(ref analyzer) = self.migration_analyzer {
            analyzer.lock().unwrap().start();
        }
        if let Some(ref history) = self.process_history {
            history.lock().unwrap().start();
        }
        if let Some(ref monitor) = self.dsq_monitor {
            monitor.lock().unwrap().start();
        }
        if let Some(ref monitor) = self.rate_monitor {
            monitor.lock().unwrap().start();
        }
        if let Some(ref tracker) = self.wakeup_tracker {
            tracker.lock().unwrap().start();
        }
        if let Some(ref analyzer) = self.waker_wakee_analyzer {
            analyzer.lock().unwrap().start();
        }
        if let Some(ref analyzer) = self.softirq_analyzer {
            analyzer.lock().unwrap().start();
        }

        // If no analyzers were running before, enable BPF tracking
        if !was_any_enabled {
            self.manage_bpf_state(true);
        }
    }

    /// Stop all registered analyzers with automatic BPF control
    pub fn stop_all(&self) {
        // Stop all registered analyzers
        if let Some(ref buffer) = self.event_buffer {
            buffer.lock().unwrap().stop();
        }
        if let Some(ref tracker) = self.latency_tracker {
            tracker.lock().unwrap().stop();
        }
        if let Some(ref analyzer) = self.cpu_hotspot_analyzer {
            analyzer.lock().unwrap().stop();
        }
        if let Some(ref analyzer) = self.migration_analyzer {
            analyzer.lock().unwrap().stop();
        }
        if let Some(ref history) = self.process_history {
            history.lock().unwrap().stop();
        }
        if let Some(ref monitor) = self.dsq_monitor {
            monitor.lock().unwrap().stop();
        }
        if let Some(ref monitor) = self.rate_monitor {
            monitor.lock().unwrap().stop();
        }
        if let Some(ref tracker) = self.wakeup_tracker {
            tracker.lock().unwrap().stop();
        }
        if let Some(ref analyzer) = self.waker_wakee_analyzer {
            analyzer.lock().unwrap().stop();
        }
        if let Some(ref analyzer) = self.softirq_analyzer {
            analyzer.lock().unwrap().stop();
        }

        // All analyzers are now stopped - disable BPF tracking
        self.manage_bpf_state(false);
    }

    /// Reset all registered analyzers
    pub fn reset_all(&self) {
        if let Some(ref buffer) = self.event_buffer {
            buffer.lock().unwrap().reset();
        }
        if let Some(ref tracker) = self.latency_tracker {
            tracker.lock().unwrap().reset();
        }
        if let Some(ref analyzer) = self.cpu_hotspot_analyzer {
            analyzer.lock().unwrap().reset();
        }
        if let Some(ref analyzer) = self.migration_analyzer {
            analyzer.lock().unwrap().reset();
        }
        if let Some(ref history) = self.process_history {
            history.lock().unwrap().reset();
        }
        if let Some(ref monitor) = self.dsq_monitor {
            monitor.lock().unwrap().reset();
        }
        if let Some(ref monitor) = self.rate_monitor {
            monitor.lock().unwrap().reset();
        }
        if let Some(ref tracker) = self.wakeup_tracker {
            tracker.lock().unwrap().reset();
        }
        if let Some(ref analyzer) = self.waker_wakee_analyzer {
            analyzer.lock().unwrap().reset();
        }
        if let Some(ref analyzer) = self.softirq_analyzer {
            analyzer.lock().unwrap().reset();
        }
    }

    /// Get status of all analyzers
    pub fn get_status(&self) -> AnalyzerStatus {
        AnalyzerStatus {
            event_buffer: self
                .event_buffer
                .as_ref()
                .map(|b| b.lock().unwrap().is_enabled()),
            latency_tracker: self
                .latency_tracker
                .as_ref()
                .map(|t| t.lock().unwrap().is_enabled()),
            cpu_hotspot_analyzer: self
                .cpu_hotspot_analyzer
                .as_ref()
                .map(|a| a.lock().unwrap().is_enabled()),
            migration_analyzer: self
                .migration_analyzer
                .as_ref()
                .map(|a| a.lock().unwrap().is_enabled()),
            process_history: self
                .process_history
                .as_ref()
                .map(|h| h.lock().unwrap().is_enabled()),
            dsq_monitor: self
                .dsq_monitor
                .as_ref()
                .map(|m| m.lock().unwrap().is_enabled()),
            rate_monitor: self
                .rate_monitor
                .as_ref()
                .map(|m| m.lock().unwrap().is_enabled()),
            wakeup_tracker: self
                .wakeup_tracker
                .as_ref()
                .map(|t| t.lock().unwrap().is_enabled()),
            waker_wakee_analyzer: self
                .waker_wakee_analyzer
                .as_ref()
                .map(|a| a.lock().unwrap().is_enabled()),
            softirq_analyzer: self
                .softirq_analyzer
                .as_ref()
                .map(|a| a.lock().unwrap().is_enabled()),
        }
    }

    /// Get waker/wakee analyzer reference for querying data
    pub fn get_waker_wakee_analyzer(&self) -> Option<Arc<Mutex<WakerWakeeAnalyzer>>> {
        self.waker_wakee_analyzer.clone()
    }

    /// Get softirq analyzer reference for querying data
    pub fn get_softirq_analyzer(&self) -> Option<Arc<Mutex<SoftirqAnalyzer>>> {
        self.softirq_analyzer.clone()
    }
}

impl Default for AnalyzerControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Status of all analyzers
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerStatus {
    pub event_buffer: Option<bool>,
    pub latency_tracker: Option<bool>,
    pub cpu_hotspot_analyzer: Option<bool>,
    pub migration_analyzer: Option<bool>,
    pub process_history: Option<bool>,
    pub dsq_monitor: Option<bool>,
    pub rate_monitor: Option<bool>,
    pub wakeup_tracker: Option<bool>,
    pub waker_wakee_analyzer: Option<bool>,
    pub softirq_analyzer: Option<bool>,
}

impl AnalyzerStatus {
    /// Check if any analyzer is enabled
    pub fn any_enabled(&self) -> bool {
        self.event_buffer.unwrap_or(false)
            || self.latency_tracker.unwrap_or(false)
            || self.cpu_hotspot_analyzer.unwrap_or(false)
            || self.migration_analyzer.unwrap_or(false)
            || self.process_history.unwrap_or(false)
            || self.dsq_monitor.unwrap_or(false)
            || self.rate_monitor.unwrap_or(false)
            || self.wakeup_tracker.unwrap_or(false)
            || self.waker_wakee_analyzer.unwrap_or(false)
            || self.softirq_analyzer.unwrap_or(false)
    }

    /// Get list of enabled analyzers
    pub fn enabled_analyzers(&self) -> Vec<String> {
        let mut enabled = Vec::new();
        if self.event_buffer.unwrap_or(false) {
            enabled.push("event_buffer".to_string());
        }
        if self.latency_tracker.unwrap_or(false) {
            enabled.push("latency_tracker".to_string());
        }
        if self.cpu_hotspot_analyzer.unwrap_or(false) {
            enabled.push("cpu_hotspot_analyzer".to_string());
        }
        if self.migration_analyzer.unwrap_or(false) {
            enabled.push("migration_analyzer".to_string());
        }
        if self.process_history.unwrap_or(false) {
            enabled.push("process_history".to_string());
        }
        if self.dsq_monitor.unwrap_or(false) {
            enabled.push("dsq_monitor".to_string());
        }
        if self.rate_monitor.unwrap_or(false) {
            enabled.push("rate_monitor".to_string());
        }
        if self.wakeup_tracker.unwrap_or(false) {
            enabled.push("wakeup_tracker".to_string());
        }
        if self.waker_wakee_analyzer.unwrap_or(false) {
            enabled.push("waker_wakee_analyzer".to_string());
        }
        if self.softirq_analyzer.unwrap_or(false) {
            enabled.push("softirq_analyzer".to_string());
        }
        enabled
    }
}

pub type SharedAnalyzerControl = Arc<Mutex<AnalyzerControl>>;
