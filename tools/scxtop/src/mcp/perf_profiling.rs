// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Trait for attaching BPF programs to perf events
/// This allows the perf profiler to attach without owning the full BPF skeleton
pub trait PerfEventAttacher: Send + Sync {
    /// Attach the BPF program to a perf event file descriptor
    /// Returns an opaque link handle that keeps the attachment alive
    fn attach_to_perf_event(&self, perf_fd: RawFd) -> Result<Box<dyn std::any::Any + Send>>;
}

/// Type alias for the perf event attachment callback function
type AttachFn = Arc<Mutex<Box<dyn Fn(RawFd) -> Result<Box<dyn std::any::Any + Send>> + Send>>>;

/// Thread-safe wrapper for BPF perf_sample_handler program
/// This allows multiple threads to attach perf events to the same BPF program
/// Uses a callback function to avoid lifetime issues with the BPF skeleton
pub struct BpfPerfEventAttacher {
    attach_fn: AttachFn,
}

impl BpfPerfEventAttacher {
    /// Create a new attacher with a callback function that performs the attachment
    pub fn new<F>(attach_fn: F) -> Self
    where
        F: Fn(RawFd) -> Result<Box<dyn std::any::Any + Send>> + Send + 'static,
    {
        Self {
            attach_fn: Arc::new(Mutex::new(Box::new(attach_fn))),
        }
    }
}

impl PerfEventAttacher for BpfPerfEventAttacher {
    fn attach_to_perf_event(&self, perf_fd: RawFd) -> Result<Box<dyn std::any::Any + Send>> {
        let attach_fn = self.attach_fn.lock().unwrap();
        attach_fn(perf_fd)
    }
}

/// Configuration for perf_event_open parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerfProfilingConfig {
    /// Event type: "hw", "sw", or "tracepoint:event:name"
    pub event: String,
    /// Sampling frequency in Hz (e.g., 99 for 99 Hz)
    pub freq: u32,
    /// CPU to profile (-1 for all CPUs)
    pub cpu: i32,
    /// Process ID to profile (-1 for system-wide)
    pub pid: i32,
    /// Maximum number of samples to collect (0 for unlimited)
    pub max_samples: usize,
    /// Duration to collect in seconds (0 for manual stop)
    pub duration_secs: u64,
}

impl Default for PerfProfilingConfig {
    fn default() -> Self {
        Self {
            event: "hw:cpu-clock".to_string(),
            freq: 99,
            cpu: -1,
            pid: -1,
            max_samples: 10000,
            duration_secs: 0,
        }
    }
}

/// Status of the profiler
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ProfilingStatus {
    Idle,
    Running,
    Stopped,
}

/// Raw sample data that can be safely sent between threads
#[derive(Clone, Debug)]
pub struct RawSample {
    pub address: u64,
    pub pid: u32,
    pub cpu_id: u32,
    pub is_kernel: bool,
    pub kernel_stack: Vec<u64>,
    pub user_stack: Vec<u64>,
    pub layer_id: Option<i32>,
}

/// Perf profiling manager that collects raw samples
pub struct PerfProfiler {
    samples: Vec<RawSample>,
    status: ProfilingStatus,
    config: Option<PerfProfilingConfig>,
    start_time: Option<Instant>,
    samples_collected: usize,
    // Perf event attachment state
    perf_fds: Vec<RawFd>,
    perf_links: Vec<Box<dyn std::any::Any + Send>>,
    bpf_attacher: Option<Arc<dyn PerfEventAttacher>>,
    topology: Option<Arc<scx_utils::Topology>>,
}

impl Default for PerfProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl PerfProfiler {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
            status: ProfilingStatus::Idle,
            config: None,
            start_time: None,
            samples_collected: 0,
            perf_fds: Vec::new(),
            perf_links: Vec::new(),
            bpf_attacher: None,
            topology: None,
        }
    }

    pub fn set_bpf_attacher(&mut self, attacher: Arc<dyn PerfEventAttacher>) {
        self.bpf_attacher = Some(attacher);
    }

    pub fn set_topology(&mut self, topology: Arc<scx_utils::Topology>) {
        self.topology = Some(topology);
    }

    /// Start profiling with the given configuration
    pub fn start(&mut self, config: PerfProfilingConfig) -> Result<()> {
        if self.status == ProfilingStatus::Running {
            return Err(anyhow!("Profiling is already running"));
        }

        // Clear previous data
        self.samples.clear();
        self.samples_collected = 0;
        self.start_time = Some(Instant::now());

        // Attach perf events if we have the required components
        if self.bpf_attacher.is_some() && self.topology.is_some() {
            self.attach_perf_events(&config)?;
        }

        self.config = Some(config);
        self.status = ProfilingStatus::Running;

        Ok(())
    }

    /// Attach perf events to all CPUs
    /// Only called when start() is invoked - not automatic
    fn attach_perf_events(&mut self, config: &PerfProfilingConfig) -> Result<()> {
        use scx_utils::perf;

        let topology = self
            .topology
            .as_ref()
            .ok_or_else(|| anyhow!("Topology not set"))?;
        let attacher = self
            .bpf_attacher
            .as_ref()
            .ok_or_else(|| anyhow!("BPF attacher not set"))?;

        log::info!(
            "Attaching perf events for '{}' (freq={}, cpu={}, pid={})",
            config.event,
            config.freq,
            config.cpu,
            config.pid
        );

        let mut attached_count = 0;
        let cpus: Vec<usize> = topology.all_cpus.keys().copied().collect();
        log::debug!("Total CPUs available: {}", cpus.len());

        for cpu_id in cpus {
            // Determine which CPUs to attach to
            if config.cpu >= 0 && cpu_id != config.cpu as usize {
                continue;
            }

            // Create a fresh perf_event_attr for each CPU
            let mut attr: perf::bindings::perf_event_attr = unsafe { std::mem::zeroed() };
            attr.size = std::mem::size_of::<perf::bindings::perf_event_attr>() as u32;

            self.configure_perf_event_attr(&mut attr, &config.event)?;

            // Configure for sampling with instruction pointer
            // Stack traces are collected by BPF program using bpf_get_stack()
            attr.sample_type = perf::bindings::PERF_SAMPLE_IP as u64;
            attr.__bindgen_anon_1.sample_period = config.freq as u64;
            attr.set_freq(0); // Use period mode (sample every N events)
            attr.set_disabled(0);
            attr.set_exclude_kernel(0);
            attr.set_exclude_hv(0);
            attr.set_inherit(1);
            attr.set_pinned(1);

            // Open perf event for this specific CPU
            let perf_fd = unsafe {
                perf::perf_event_open(
                    &mut attr as *mut perf::bindings::perf_event_attr,
                    config.pid,
                    cpu_id as i32,
                    -1, // group_fd
                    0,  // flags
                )
            };

            if perf_fd <= 0 {
                let err = std::io::Error::last_os_error();
                log::warn!(
                    "Failed to open perf event for CPU {}: {} (errno: {})",
                    cpu_id,
                    err,
                    err.raw_os_error().unwrap_or(0)
                );
                continue;
            }

            log::debug!("Opened perf event fd={} for CPU {}", perf_fd, cpu_id);

            // Attach BPF program to the perf event
            match attacher.attach_to_perf_event(perf_fd) {
                Ok(link) => {
                    log::debug!(
                        "Successfully attached BPF program to perf fd={} (CPU {})",
                        perf_fd,
                        cpu_id
                    );

                    // Enable the perf event
                    if unsafe { perf::ioctls::enable(perf_fd, 0) } < 0 {
                        let err = std::io::Error::last_os_error();
                        log::error!(
                            "Failed to enable perf event fd={} for CPU {}: {}",
                            perf_fd,
                            cpu_id,
                            err
                        );
                        unsafe {
                            libc::close(perf_fd);
                        }
                        continue;
                    }

                    log::debug!("Enabled perf event fd={} for CPU {}", perf_fd, cpu_id);

                    self.perf_fds.push(perf_fd);
                    self.perf_links.push(link);
                    attached_count += 1;
                }
                Err(e) => {
                    log::error!(
                        "Failed to attach BPF program to perf fd={} for CPU {}: {}",
                        perf_fd,
                        cpu_id,
                        e
                    );
                    unsafe {
                        libc::close(perf_fd);
                    }
                }
            }
        }

        if attached_count == 0 {
            log::error!("Failed to attach perf events to any CPU - no CPUs attached!");
            return Err(anyhow!("Failed to attach perf events to any CPU"));
        }

        log::info!(
            "Successfully attached perf profiling to {} CPUs for event '{}'",
            attached_count,
            config.event
        );
        log::debug!(
            "Perf config: freq={}, cpu={}, pid={}, max_samples={}, duration_secs={}",
            config.freq,
            config.cpu,
            config.pid,
            config.max_samples,
            config.duration_secs
        );
        Ok(())
    }

    /// Configure perf_event_attr based on event string
    fn configure_perf_event_attr(
        &self,
        attr: &mut scx_utils::perf::bindings::perf_event_attr,
        event_str: &str,
    ) -> Result<()> {
        use scx_utils::perf;

        // Parse event string format:
        // - "cache-misses", "cycles", "instructions" (hardware events)
        // - "cpu-clock", "task-clock" (software events)
        // - "hw:cache-misses", "sw:cpu-clock" (explicit subsystem)

        let (subsystem, event_name) = if event_str.contains(':') {
            let parts: Vec<&str> = event_str.split(':').collect();
            if parts.len() != 2 {
                return Err(anyhow!("Invalid event format: {}", event_str));
            }
            (parts[0], parts[1])
        } else {
            // Try to infer subsystem from event name
            match event_str.to_lowercase().as_str() {
                "cpu-clock" | "task-clock" | "context-switches" | "page-faults"
                | "minor-faults" | "major-faults" | "migrations" => ("sw", event_str),
                _ => ("hw", event_str), // Default to hardware
            }
        };

        match subsystem.to_lowercase().as_str() {
            "hw" | "hardware" => {
                attr.type_ = perf::bindings::PERF_TYPE_HARDWARE;
                match event_name.to_lowercase().as_str() {
                    "cycles" | "cpu-cycles" | "cpu_cycles" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_CPU_CYCLES as u64;
                    }
                    "instructions" | "instr" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_INSTRUCTIONS as u64;
                    }
                    "branches" | "branch-instructions" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_BRANCH_INSTRUCTIONS as u64;
                    }
                    "branch-misses" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_BRANCH_MISSES as u64;
                    }
                    "cache-misses" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_CACHE_MISSES as u64;
                    }
                    "cache-references" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_CACHE_REFERENCES as u64;
                    }
                    "ref-cycles" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_REF_CPU_CYCLES as u64;
                    }
                    "stalled-cycles-backend" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_STALLED_CYCLES_BACKEND as u64;
                    }
                    "stalled-cycles-frontend" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_STALLED_CYCLES_FRONTEND as u64;
                    }
                    "bus-cycles" | "bus_cycles" => {
                        attr.config = perf::bindings::PERF_COUNT_HW_BUS_CYCLES as u64;
                    }
                    _ => {
                        return Err(anyhow!("Unknown hardware event: {}", event_name));
                    }
                }
            }
            "sw" | "software" => {
                attr.type_ = perf::bindings::PERF_TYPE_SOFTWARE;
                match event_name.to_lowercase().as_str() {
                    "cpu-clock" => {
                        attr.config = perf::bindings::PERF_COUNT_SW_CPU_CLOCK as u64;
                    }
                    "task-clock" => {
                        attr.config = perf::bindings::PERF_COUNT_SW_TASK_CLOCK as u64;
                    }
                    "context-switches" | "cs" => {
                        attr.config = perf::bindings::PERF_COUNT_SW_CONTEXT_SWITCHES as u64;
                    }
                    "page-faults" | "faults" => {
                        attr.config = perf::bindings::PERF_COUNT_SW_PAGE_FAULTS as u64;
                    }
                    "minor-faults" => {
                        attr.config = perf::bindings::PERF_COUNT_SW_PAGE_FAULTS_MIN as u64;
                    }
                    "major-faults" => {
                        attr.config = perf::bindings::PERF_COUNT_SW_PAGE_FAULTS_MAJ as u64;
                    }
                    "migrations" | "cpu-migrations" => {
                        attr.config = perf::bindings::PERF_COUNT_SW_CPU_MIGRATIONS as u64;
                    }
                    _ => {
                        return Err(anyhow!("Unknown software event: {}", event_name));
                    }
                }
            }
            _ => {
                return Err(anyhow!("Unknown subsystem: {}", subsystem));
            }
        }

        Ok(())
    }

    /// Stop profiling
    pub fn stop(&mut self) -> Result<()> {
        if self.status != ProfilingStatus::Running {
            return Err(anyhow!("Profiling is not running"));
        }

        // Detach perf events
        self.detach_perf_events();

        self.status = ProfilingStatus::Stopped;
        Ok(())
    }

    /// Detach and cleanup perf events
    fn detach_perf_events(&mut self) {
        // Close all perf event FDs
        for &perf_fd in &self.perf_fds {
            unsafe {
                libc::close(perf_fd);
            }
        }

        // Drop all BPF links (this detaches the programs)
        self.perf_links.clear();
        self.perf_fds.clear();

        log::debug!("Detached all perf events");
    }

    /// Check if profiling should be stopped based on config
    pub fn should_stop(&self) -> bool {
        if self.status != ProfilingStatus::Running {
            return false;
        }

        if let Some(ref config) = self.config {
            // Check max samples
            if config.max_samples > 0 && self.samples_collected >= config.max_samples {
                return true;
            }

            // Check duration
            if config.duration_secs > 0 {
                if let Some(start) = self.start_time {
                    if start.elapsed() >= Duration::from_secs(config.duration_secs) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Add a raw sample
    pub fn add_sample(&mut self, sample: RawSample) {
        if self.status != ProfilingStatus::Running {
            log::trace!(
                "Ignoring sample - profiling not running (status: {:?})",
                self.status
            );
            return;
        }

        self.samples.push(sample);
        self.samples_collected += 1;

        if self.samples_collected.is_multiple_of(100) {
            log::debug!("Collected {} samples so far", self.samples_collected);
        }

        // Auto-stop if conditions met
        if self.should_stop() {
            log::info!(
                "Auto-stopping profiling (collected: {}, max: {})",
                self.samples_collected,
                self.config.as_ref().map(|c| c.max_samples).unwrap_or(0)
            );
            self.status = ProfilingStatus::Stopped;
        }
    }

    /// Get the current status
    pub fn get_status(&self) -> serde_json::Value {
        let duration_ms = self
            .start_time
            .map(|start| start.elapsed().as_millis())
            .unwrap_or(0);

        serde_json::json!({
            "status": format!("{:?}", self.status),
            "samples_collected": self.samples_collected,
            "duration_ms": duration_ms,
            "config": self.config,
        })
    }

    /// Get results with symbolization (done on-demand to avoid Send issues)
    pub fn get_results(&self, limit: usize, include_stacks: bool) -> serde_json::Value {
        use crate::symbol_data::SymbolData;

        // Create SymbolData fresh for symbolization (avoids Send issues)
        let mut symbol_data = SymbolData::new();

        // Add all samples to symbol data for symbolization
        for sample in &self.samples {
            symbol_data.add_sample_with_stacks_and_layer(
                sample.address,
                sample.pid,
                sample.cpu_id,
                sample.is_kernel,
                &sample.kernel_stack,
                &sample.user_stack,
                sample.layer_id,
            );
        }

        // Get top symbols
        let top_samples = symbol_data.get_top_symbols(limit);

        let symbols: Vec<serde_json::Value> = top_samples
            .iter()
            .map(|sample| {
                let mut symbol_json = serde_json::json!({
                    "symbol": sample.symbol_info.symbol_name,
                    "module": sample.symbol_info.module_name,
                    "file": sample.symbol_info.file_name,
                    "line": sample.symbol_info.line_number,
                    "address": format!("0x{:x}", sample.symbol_info.address),
                    "count": sample.count,
                    "percentage": format!("{:.2}%", sample.percentage),
                    "pid": sample.pid,
                    "cpu_id": sample.cpu_id,
                    "is_kernel": sample.is_kernel,
                    "layer_id": sample.layer_id,
                });

                if include_stacks && !sample.stack_traces.is_empty() {
                    let stack_traces: Vec<serde_json::Value> = sample
                        .stack_traces
                        .iter()
                        .map(|raw_trace| {
                            let symbolized = symbol_data.symbolize_stack_trace(raw_trace);
                            format_symbolized_stack_trace(&symbolized)
                        })
                        .collect();
                    symbol_json["stack_traces"] = serde_json::json!(stack_traces);
                }

                symbol_json
            })
            .collect();

        serde_json::json!({
            "symbols": symbols,
            "total_samples": symbol_data.total_samples(),
            "samples_collected": self.samples_collected,
        })
    }

    /// Clear all collected data
    pub fn clear(&mut self) {
        self.samples.clear();
        self.samples_collected = 0;
        self.status = ProfilingStatus::Idle;
        self.config = None;
        self.start_time = None;
    }

    /// Get current status enum
    pub fn status(&self) -> &ProfilingStatus {
        &self.status
    }
}

/// Format a symbolized stack trace as JSON
fn format_symbolized_stack_trace(
    symbolized: &crate::symbol_data::SymbolizedStackTrace,
) -> serde_json::Value {
    let kernel_frames: Vec<serde_json::Value> = symbolized
        .kernel_stack
        .iter()
        .map(|sym| {
            serde_json::json!({
                "symbol": sym.symbol_name,
                "module": sym.module_name,
                "file": sym.file_name,
                "line": sym.line_number,
                "address": format!("0x{:x}", sym.address),
            })
        })
        .collect();

    let user_frames: Vec<serde_json::Value> = symbolized
        .user_stack
        .iter()
        .map(|sym| {
            serde_json::json!({
                "symbol": sym.symbol_name,
                "module": sym.module_name,
                "file": sym.file_name,
                "line": sym.line_number,
                "address": format!("0x{:x}", sym.address),
            })
        })
        .collect();

    serde_json::json!({
        "kernel_stack": kernel_frames,
        "user_stack": user_frames,
        "count": symbolized.count,
    })
}

/// Thread-safe wrapper for PerfProfiler
#[derive(Clone)]
pub struct SharedPerfProfiler {
    inner: Arc<Mutex<PerfProfiler>>,
}

impl SharedPerfProfiler {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PerfProfiler::new())),
        }
    }

    pub fn set_bpf_attacher(&self, attacher: Arc<dyn PerfEventAttacher>) {
        self.inner.lock().unwrap().set_bpf_attacher(attacher);
    }

    pub fn set_topology(&self, topology: Arc<scx_utils::Topology>) {
        self.inner.lock().unwrap().set_topology(topology);
    }

    pub fn start(&self, config: PerfProfilingConfig) -> Result<()> {
        self.inner.lock().unwrap().start(config)
    }

    pub fn stop(&self) -> Result<()> {
        self.inner.lock().unwrap().stop()
    }

    pub fn add_sample(&self, sample: RawSample) {
        self.inner.lock().unwrap().add_sample(sample);
    }

    pub fn get_status(&self) -> serde_json::Value {
        self.inner.lock().unwrap().get_status()
    }

    pub fn get_results(&self, limit: usize, include_stacks: bool) -> serde_json::Value {
        self.inner
            .lock()
            .unwrap()
            .get_results(limit, include_stacks)
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    pub fn status(&self) -> ProfilingStatus {
        self.inner.lock().unwrap().status().clone()
    }
}

impl Default for SharedPerfProfiler {
    fn default() -> Self {
        Self::new()
    }
}
