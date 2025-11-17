// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::PerfEvent;
use anyhow::Result;
use std::collections::BTreeMap;

/// Stores counter values for a specific scope (system-wide or per-process)
#[derive(Clone, Debug, Default)]
pub struct PerfStatCounters {
    // Raw counter values (latest read)
    pub cycles: u64,
    pub instructions: u64,
    pub branches: u64,
    pub branch_misses: u64,
    pub cache_references: u64,
    pub cache_misses: u64,
    pub stalled_cycles_frontend: u64,
    pub stalled_cycles_backend: u64,
    pub context_switches: u64,
    pub cpu_migrations: u64,
    pub page_faults: u64,

    // Delta values (difference since last read)
    pub cycles_delta: u64,
    pub instructions_delta: u64,
    pub branches_delta: u64,
    pub branch_misses_delta: u64,
    pub cache_references_delta: u64,
    pub cache_misses_delta: u64,
    pub stalled_cycles_frontend_delta: u64,
    pub stalled_cycles_backend_delta: u64,
    pub context_switches_delta: u64,
    pub cpu_migrations_delta: u64,
    pub page_faults_delta: u64,

    // Timestamp of last update
    pub last_update_ms: u128,
}

impl PerfStatCounters {
    /// Update counter values and calculate deltas
    pub fn update(&mut self, new_values: &PerfStatCounters, timestamp_ms: u128) {
        self.cycles_delta = new_values.cycles.saturating_sub(self.cycles);
        self.instructions_delta = new_values.instructions.saturating_sub(self.instructions);
        self.branches_delta = new_values.branches.saturating_sub(self.branches);
        self.branch_misses_delta = new_values.branch_misses.saturating_sub(self.branch_misses);
        self.cache_references_delta = new_values
            .cache_references
            .saturating_sub(self.cache_references);
        self.cache_misses_delta = new_values.cache_misses.saturating_sub(self.cache_misses);
        self.stalled_cycles_frontend_delta = new_values
            .stalled_cycles_frontend
            .saturating_sub(self.stalled_cycles_frontend);
        self.stalled_cycles_backend_delta = new_values
            .stalled_cycles_backend
            .saturating_sub(self.stalled_cycles_backend);
        self.context_switches_delta = new_values
            .context_switches
            .saturating_sub(self.context_switches);
        self.cpu_migrations_delta = new_values
            .cpu_migrations
            .saturating_sub(self.cpu_migrations);
        self.page_faults_delta = new_values.page_faults.saturating_sub(self.page_faults);

        // Update absolute values
        self.cycles = new_values.cycles;
        self.instructions = new_values.instructions;
        self.branches = new_values.branches;
        self.branch_misses = new_values.branch_misses;
        self.cache_references = new_values.cache_references;
        self.cache_misses = new_values.cache_misses;
        self.stalled_cycles_frontend = new_values.stalled_cycles_frontend;
        self.stalled_cycles_backend = new_values.stalled_cycles_backend;
        self.context_switches = new_values.context_switches;
        self.cpu_migrations = new_values.cpu_migrations;
        self.page_faults = new_values.page_faults;

        self.last_update_ms = timestamp_ms;
    }

    /// Calculate derived metrics
    pub fn derived_metrics(&self) -> DerivedMetrics {
        DerivedMetrics::calculate(self)
    }
}

/// Derived performance metrics calculated from raw counters
#[derive(Clone, Debug, Default)]
pub struct DerivedMetrics {
    pub ipc: f64,                  // Instructions per cycle
    pub cache_miss_rate: f64,      // Cache misses / cache references
    pub branch_miss_rate: f64,     // Branch misses / branches
    pub stalled_frontend_pct: f64, // Frontend stalls / cycles
    pub stalled_backend_pct: f64,  // Backend stalls / cycles
}

impl DerivedMetrics {
    pub fn calculate(counters: &PerfStatCounters) -> Self {
        let ipc = if counters.cycles_delta > 0 {
            counters.instructions_delta as f64 / counters.cycles_delta as f64
        } else {
            0.0
        };

        let cache_miss_rate = if counters.cache_references_delta > 0 {
            (counters.cache_misses_delta as f64 / counters.cache_references_delta as f64) * 100.0
        } else {
            0.0
        };

        let branch_miss_rate = if counters.branches_delta > 0 {
            (counters.branch_misses_delta as f64 / counters.branches_delta as f64) * 100.0
        } else {
            0.0
        };

        let stalled_frontend_pct = if counters.cycles_delta > 0 {
            (counters.stalled_cycles_frontend_delta as f64 / counters.cycles_delta as f64) * 100.0
        } else {
            0.0
        };

        let stalled_backend_pct = if counters.cycles_delta > 0 {
            (counters.stalled_cycles_backend_delta as f64 / counters.cycles_delta as f64) * 100.0
        } else {
            0.0
        };

        Self {
            ipc,
            cache_miss_rate,
            branch_miss_rate,
            stalled_frontend_pct,
            stalled_backend_pct,
        }
    }
}

/// Stores historical delta values for chart visualization
#[derive(Clone, Debug)]
pub struct PerfStatHistory {
    max_size: usize,
    pub ipc_history: Vec<f64>,
    pub cache_miss_rate_history: Vec<f64>,
    pub branch_miss_rate_history: Vec<f64>,
    pub stalled_frontend_pct_history: Vec<f64>,
    pub stalled_backend_pct_history: Vec<f64>,
    pub instructions_per_sec: Vec<u64>,
    pub cycles_per_sec: Vec<u64>,
}

impl PerfStatHistory {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            ipc_history: Vec::new(),
            cache_miss_rate_history: Vec::new(),
            branch_miss_rate_history: Vec::new(),
            stalled_frontend_pct_history: Vec::new(),
            stalled_backend_pct_history: Vec::new(),
            instructions_per_sec: Vec::new(),
            cycles_per_sec: Vec::new(),
        }
    }

    pub fn push(
        &mut self,
        metrics: &DerivedMetrics,
        counters: &PerfStatCounters,
        duration_ms: u128,
    ) {
        let duration_secs = duration_ms as f64 / 1000.0;
        let instructions_rate = if duration_secs > 0.0 {
            (counters.instructions_delta as f64 / duration_secs) as u64
        } else {
            0
        };
        let cycles_rate = if duration_secs > 0.0 {
            (counters.cycles_delta as f64 / duration_secs) as u64
        } else {
            0
        };

        self.ipc_history.push(metrics.ipc);
        self.cache_miss_rate_history.push(metrics.cache_miss_rate);
        self.branch_miss_rate_history.push(metrics.branch_miss_rate);
        self.stalled_frontend_pct_history
            .push(metrics.stalled_frontend_pct);
        self.stalled_backend_pct_history
            .push(metrics.stalled_backend_pct);
        self.instructions_per_sec.push(instructions_rate);
        self.cycles_per_sec.push(cycles_rate);

        // Trim to max size
        if self.ipc_history.len() > self.max_size {
            self.ipc_history.remove(0);
            self.cache_miss_rate_history.remove(0);
            self.branch_miss_rate_history.remove(0);
            self.stalled_frontend_pct_history.remove(0);
            self.stalled_backend_pct_history.remove(0);
            self.instructions_per_sec.remove(0);
            self.cycles_per_sec.remove(0);
        }
    }
}

/// Manages perf stat counter collection
pub struct PerfStatCollector {
    // Per-CPU perf events (system-wide mode)
    cpu_events: BTreeMap<usize, Vec<PerfEvent>>,

    // Per-process perf events (filtered mode)
    process_events: Option<Vec<PerfEvent>>,

    // Collected counter data
    pub system_counters: PerfStatCounters,
    pub per_cpu_counters: BTreeMap<usize, PerfStatCounters>,
    pub per_llc_counters: BTreeMap<usize, PerfStatCounters>,
    pub per_node_counters: BTreeMap<usize, PerfStatCounters>,
    pub process_counters: Option<PerfStatCounters>,

    // Historical data for charts (store last N deltas)
    pub system_history: PerfStatHistory,
    pub per_cpu_history: BTreeMap<usize, PerfStatHistory>,
    pub per_llc_history: BTreeMap<usize, PerfStatHistory>,
    pub per_node_history: BTreeMap<usize, PerfStatHistory>,

    // CPU to LLC/Node mapping
    cpu_to_llc: BTreeMap<usize, usize>,
    cpu_to_node: BTreeMap<usize, usize>,

    // Configuration
    filter_pid: Option<i32>,
    is_active: bool,
}

impl PerfStatCollector {
    pub fn new() -> Self {
        Self {
            cpu_events: BTreeMap::new(),
            process_events: None,
            system_counters: PerfStatCounters::default(),
            per_cpu_counters: BTreeMap::new(),
            per_llc_counters: BTreeMap::new(),
            per_node_counters: BTreeMap::new(),
            process_counters: None,
            system_history: PerfStatHistory::new(100),
            per_cpu_history: BTreeMap::new(),
            per_llc_history: BTreeMap::new(),
            per_node_history: BTreeMap::new(),
            cpu_to_llc: BTreeMap::new(),
            cpu_to_node: BTreeMap::new(),
            filter_pid: None,
            is_active: false,
        }
    }

    /// Set CPU to LLC/Node topology mappings
    pub fn set_topology(
        &mut self,
        cpu_to_llc: BTreeMap<usize, usize>,
        cpu_to_node: BTreeMap<usize, usize>,
    ) {
        self.cpu_to_llc = cpu_to_llc;
        self.cpu_to_node = cpu_to_node;
    }

    /// Initialize perf events for system-wide collection with custom history size
    pub fn init_system_wide_with_history_size(
        &mut self,
        num_cpus: usize,
        history_size: usize,
    ) -> Result<()> {
        self.cleanup();

        // Update history sizes
        let history_size = history_size.max(10);
        self.system_history = PerfStatHistory::new(history_size);

        // Initialize LLC and NUMA node histories based on topology
        for &llc_id in self.cpu_to_llc.values() {
            self.per_llc_history
                .entry(llc_id)
                .or_insert_with(|| PerfStatHistory::new(history_size));
            self.per_llc_counters.entry(llc_id).or_default();
        }

        for &node_id in self.cpu_to_node.values() {
            self.per_node_history
                .entry(node_id)
                .or_insert_with(|| PerfStatHistory::new(history_size));
            self.per_node_counters.entry(node_id).or_default();
        }

        for cpu in 0..num_cpus {
            let mut events = Vec::new();

            // Create perf events for all counters
            let event_specs = vec![
                ("hw", "cycles"),
                ("hw", "instructions"),
                ("hw", "branches"),
                ("hw", "branch-misses"),
                ("hw", "cache-references"),
                ("hw", "cache-misses"),
                ("hw", "stalled-cycles-frontend"),
                ("hw", "stalled-cycles-backend"),
                ("sw", "context-switches"),
                ("sw", "cpu-migrations"),
                ("sw", "page-faults"),
            ];

            for (subsystem, event_name) in event_specs {
                let mut event = PerfEvent::new(subsystem.to_string(), event_name.to_string(), cpu as i32);
                // Attach in counting mode (no sampling)
                if let Err(e) = event.attach(-1) {
                    log::warn!("Failed to attach {} for CPU {}: {}", event_name, cpu, e);
                    continue;
                }
                events.push(event);
            }

            if !events.is_empty() {
                self.cpu_events.insert(cpu, events);
                self.per_cpu_counters
                    .insert(cpu, PerfStatCounters::default());
                self.per_cpu_history
                    .insert(cpu, PerfStatHistory::new(history_size));
            }
        }

        self.is_active = true;
        Ok(())
    }

    /// Initialize perf events for system-wide collection (uses default history size)
    pub fn init_system_wide(&mut self, num_cpus: usize) -> Result<()> {
        self.init_system_wide_with_history_size(num_cpus, 100)
    }

    /// Initialize perf events for per-process collection
    pub fn init_process(&mut self, pid: i32) -> Result<()> {
        let mut events = Vec::new();
        let mut failed_events = Vec::new();

        let event_specs = vec![
            ("hw", "cycles"),
            ("hw", "instructions"),
            ("hw", "branches"),
            ("hw", "branch-misses"),
            ("hw", "cache-references"),
            ("hw", "cache-misses"),
            ("hw", "stalled-cycles-frontend"),
            ("hw", "stalled-cycles-backend"),
            ("sw", "context-switches"),
            ("sw", "cpu-migrations"),
            ("sw", "page-faults"),
        ];

        let total_events = event_specs.len();

        for (subsystem, event_name) in &event_specs {
            // CPU -1 means monitor on all CPUs
            let mut event = PerfEvent::new(subsystem.to_string(), event_name.to_string(), -1);
            if let Err(e) = event.attach(pid) {
                log::warn!("Failed to attach {} for PID {}: {}", event_name, pid, e);
                failed_events.push(*event_name);
                continue;
            }
            events.push(event);
        }

        if events.is_empty() {
            return Err(anyhow::anyhow!(
                "Failed to attach any perf events for PID {} (process may have terminated or insufficient permissions)",
                pid
            ));
        }

        if !failed_events.is_empty() {
            log::info!(
                "Successfully attached {} of {} events for PID {} (failed: {})",
                events.len(),
                total_events,
                pid,
                failed_events.join(", ")
            );
        }

        self.process_events = Some(events);
        self.process_counters = Some(PerfStatCounters::default());
        self.filter_pid = Some(pid);
        self.is_active = true;

        Ok(())
    }

    /// Read all counters and update data structures
    pub fn update(&mut self, timestamp_ms: u128, duration_ms: u128) -> Result<()> {
        if !self.is_active {
            return Ok(());
        }

        // Track if any counters succeeded
        let mut any_success = false;

        // Read process counters first if filtering by PID
        if let Some(events) = &mut self.process_events {
            let mut proc_counters = PerfStatCounters::default();
            let mut proc_success = false;

            for event in events {
                if let Ok(value) = event.value(false) {
                    proc_success = true;
                    match event.event_name() {
                        "cycles" | "cpu-cycles" => proc_counters.cycles = value,
                        "instructions" => proc_counters.instructions = value,
                        "branches" => proc_counters.branches = value,
                        "branch-misses" => proc_counters.branch_misses = value,
                        "cache-references" => proc_counters.cache_references = value,
                        "cache-misses" => proc_counters.cache_misses = value,
                        "stalled-cycles-frontend" => proc_counters.stalled_cycles_frontend = value,
                        "stalled-cycles-backend" => proc_counters.stalled_cycles_backend = value,
                        "context-switches" => proc_counters.context_switches = value,
                        "cpu-migrations" => proc_counters.cpu_migrations = value,
                        "page-faults" => proc_counters.page_faults = value,
                        _ => {}
                    }
                }
            }

            if proc_success {
                any_success = true;
                if let Some(prev) = &mut self.process_counters {
                    prev.update(&proc_counters, timestamp_ms);
                }
            }
        }

        // Read system-wide counters
        let mut system_total = PerfStatCounters::default();

        for (cpu, events) in &mut self.cpu_events {
            let mut cpu_counters = PerfStatCounters::default();
            let mut cpu_success = false;

            for event in events {
                match event.value(false) {
                    Ok(value) => {
                        cpu_success = true;
                        match event.event_name() {
                            "cycles" | "cpu-cycles" => cpu_counters.cycles = value,
                            "instructions" => cpu_counters.instructions = value,
                            "branches" => cpu_counters.branches = value,
                            "branch-misses" => cpu_counters.branch_misses = value,
                            "cache-references" => cpu_counters.cache_references = value,
                            "cache-misses" => cpu_counters.cache_misses = value,
                            "stalled-cycles-frontend" => {
                                cpu_counters.stalled_cycles_frontend = value
                            }
                            "stalled-cycles-backend" => cpu_counters.stalled_cycles_backend = value,
                            "context-switches" => cpu_counters.context_switches = value,
                            "cpu-migrations" => cpu_counters.cpu_migrations = value,
                            "page-faults" => cpu_counters.page_faults = value,
                            _ => {}
                        }
                    }
                    Err(e) => {
                        log::debug!(
                            "Failed to read {} for CPU {}: {}",
                            event.event_name(),
                            cpu,
                            e
                        );
                    }
                }
            }

            if cpu_success {
                any_success = true;

                // Update per-CPU data with deltas
                if let Some(prev) = self.per_cpu_counters.get_mut(cpu) {
                    prev.update(&cpu_counters, timestamp_ms);

                    // Update history
                    if let Some(history) = self.per_cpu_history.get_mut(cpu) {
                        let metrics = prev.derived_metrics();
                        history.push(&metrics, prev, duration_ms);
                    }
                }

                // Aggregate to system total
                system_total.cycles += cpu_counters.cycles;
                system_total.instructions += cpu_counters.instructions;
                system_total.branches += cpu_counters.branches;
                system_total.branch_misses += cpu_counters.branch_misses;
                system_total.cache_references += cpu_counters.cache_references;
                system_total.cache_misses += cpu_counters.cache_misses;
                system_total.stalled_cycles_frontend += cpu_counters.stalled_cycles_frontend;
                system_total.stalled_cycles_backend += cpu_counters.stalled_cycles_backend;
                system_total.context_switches += cpu_counters.context_switches;
                system_total.cpu_migrations += cpu_counters.cpu_migrations;
                system_total.page_faults += cpu_counters.page_faults;
            }
        }

        // Aggregate per-CPU counters into LLC and NUMA node totals
        let mut llc_totals: BTreeMap<usize, PerfStatCounters> = BTreeMap::new();
        let mut node_totals: BTreeMap<usize, PerfStatCounters> = BTreeMap::new();

        for (cpu, counters) in &self.per_cpu_counters {
            // Aggregate by LLC
            if let Some(&llc_id) = self.cpu_to_llc.get(cpu) {
                let llc_counter = llc_totals.entry(llc_id).or_default();
                llc_counter.cycles += counters.cycles;
                llc_counter.instructions += counters.instructions;
                llc_counter.branches += counters.branches;
                llc_counter.branch_misses += counters.branch_misses;
                llc_counter.cache_references += counters.cache_references;
                llc_counter.cache_misses += counters.cache_misses;
                llc_counter.stalled_cycles_frontend += counters.stalled_cycles_frontend;
                llc_counter.stalled_cycles_backend += counters.stalled_cycles_backend;
                llc_counter.context_switches += counters.context_switches;
                llc_counter.cpu_migrations += counters.cpu_migrations;
                llc_counter.page_faults += counters.page_faults;
            }

            // Aggregate by NUMA node
            if let Some(&node_id) = self.cpu_to_node.get(cpu) {
                let node_counter = node_totals.entry(node_id).or_default();
                node_counter.cycles += counters.cycles;
                node_counter.instructions += counters.instructions;
                node_counter.branches += counters.branches;
                node_counter.branch_misses += counters.branch_misses;
                node_counter.cache_references += counters.cache_references;
                node_counter.cache_misses += counters.cache_misses;
                node_counter.stalled_cycles_frontend += counters.stalled_cycles_frontend;
                node_counter.stalled_cycles_backend += counters.stalled_cycles_backend;
                node_counter.context_switches += counters.context_switches;
                node_counter.cpu_migrations += counters.cpu_migrations;
                node_counter.page_faults += counters.page_faults;
            }
        }

        // Update LLC counters with deltas and history
        for (llc_id, llc_total) in llc_totals {
            if let Some(prev) = self.per_llc_counters.get_mut(&llc_id) {
                prev.update(&llc_total, timestamp_ms);
                if let Some(history) = self.per_llc_history.get_mut(&llc_id) {
                    let metrics = prev.derived_metrics();
                    history.push(&metrics, prev, duration_ms);
                }
            }
        }

        // Update NUMA node counters with deltas and history
        for (node_id, node_total) in node_totals {
            if let Some(prev) = self.per_node_counters.get_mut(&node_id) {
                prev.update(&node_total, timestamp_ms);
                if let Some(history) = self.per_node_history.get_mut(&node_id) {
                    let metrics = prev.derived_metrics();
                    history.push(&metrics, prev, duration_ms);
                }
            }
        }

        if !any_success {
            log::warn!("Failed to read any perf counters this cycle");
            return Ok(());
        }

        // Update system counters with deltas
        self.system_counters.update(&system_total, timestamp_ms);
        let metrics = self.system_counters.derived_metrics();
        self.system_history
            .push(&metrics, &self.system_counters, duration_ms);

        Ok(())
    }

    /// Cleanup all perf events
    pub fn cleanup(&mut self) {
        self.cpu_events.clear();
        self.process_events = None;
        self.is_active = false;
    }

    pub fn is_active(&self) -> bool {
        self.is_active
    }

    pub fn filter_pid(&self) -> Option<i32> {
        self.filter_pid
    }

    pub fn has_process_counters(&self) -> bool {
        self.process_counters.is_some()
    }
}

impl Default for PerfStatCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for PerfStatCollector
#[derive(Clone)]
pub struct SharedPerfStatCollector {
    inner: Arc<Mutex<PerfStatCollector>>,
}

impl SharedPerfStatCollector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PerfStatCollector::new())),
        }
    }

    pub fn set_topology(
        &self,
        cpu_to_llc: BTreeMap<usize, usize>,
        cpu_to_node: BTreeMap<usize, usize>,
    ) {
        self.inner
            .lock()
            .unwrap()
            .set_topology(cpu_to_llc, cpu_to_node);
    }

    pub fn init_system_wide_with_history_size(
        &self,
        num_cpus: usize,
        history_size: usize,
    ) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .init_system_wide_with_history_size(num_cpus, history_size)
    }

    pub fn init_process(&self, pid: i32) -> Result<()> {
        self.inner.lock().unwrap().init_process(pid)
    }

    pub fn update(&self, timestamp_ms: u128, duration_ms: u128) -> Result<()> {
        self.inner.lock().unwrap().update(timestamp_ms, duration_ms)
    }

    pub fn cleanup(&self) {
        self.inner.lock().unwrap().cleanup();
    }

    pub fn is_active(&self) -> bool {
        self.inner.lock().unwrap().is_active()
    }

    pub fn get_system_counters(&self) -> PerfStatCounters {
        self.inner.lock().unwrap().system_counters.clone()
    }

    pub fn get_per_cpu_counters(&self) -> BTreeMap<usize, PerfStatCounters> {
        self.inner.lock().unwrap().per_cpu_counters.clone()
    }

    pub fn get_per_llc_counters(&self) -> BTreeMap<usize, PerfStatCounters> {
        self.inner.lock().unwrap().per_llc_counters.clone()
    }

    pub fn get_per_node_counters(&self) -> BTreeMap<usize, PerfStatCounters> {
        self.inner.lock().unwrap().per_node_counters.clone()
    }

    pub fn get_process_counters(&self) -> Option<PerfStatCounters> {
        self.inner.lock().unwrap().process_counters.clone()
    }

    pub fn filter_pid(&self) -> Option<i32> {
        self.inner.lock().unwrap().filter_pid()
    }
}

impl Default for SharedPerfStatCollector {
    fn default() -> Self {
        Self::new()
    }
}

use std::sync::{Arc, Mutex};
