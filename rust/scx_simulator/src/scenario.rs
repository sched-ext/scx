//! Scenario definition and builder API.

use crate::task::{TaskBehavior, TaskDef};
use crate::types::{MmId, Pid, TimeNs};

/// Configuration for simulation timing noise (tick jitter).
///
/// Models hardware interrupt delivery latency: on commodity non-RT kernels,
/// timer interrupts show 1–10μs of jitter due to interrupt latency, cache
/// misses, and pipeline stalls. Modeled as normally-distributed noise added
/// to each tick interval.
#[derive(Debug, Clone)]
pub struct NoiseConfig {
    /// Master switch: false disables all noise (exact deterministic tick timing).
    pub enabled: bool,
    /// Enable tick jitter (normally-distributed variation in tick intervals).
    pub tick_jitter: bool,
    /// Standard deviation for tick jitter (ns). Default: 2000 (2μs).
    pub tick_jitter_stddev_ns: TimeNs,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        NoiseConfig {
            enabled: true,
            tick_jitter: true,
            tick_jitter_stddev_ns: 2_000,
        }
    }
}

/// Configuration for context switch overhead.
///
/// Models real CPU time consumed during task transitions. A voluntary yield
/// (sleep, exit) costs ~500ns (~1000 cycles at 2GHz). An involuntary
/// preemption costs ~1000ns due to pipeline flush, TLB shootdown, and cache
/// cold effects. Each has optional per-switch jitter.
#[derive(Debug, Clone)]
pub struct OverheadConfig {
    /// Master switch: false disables all overhead (zero-cost transitions).
    pub enabled: bool,
    /// Enable overhead for voluntary context switches (sleep, exit, yield).
    pub voluntary_csw: bool,
    /// Enable overhead for involuntary context switches (preemption).
    pub involuntary_csw: bool,
    /// Time consumed by a voluntary context switch (ns). Default: 500.
    pub voluntary_csw_ns: TimeNs,
    /// Time consumed by an involuntary context switch (ns). Default: 1000.
    pub involuntary_csw_ns: TimeNs,
    /// Enable per-switch jitter on CSW overhead.
    pub csw_jitter: bool,
    /// Standard deviation for CSW overhead jitter (ns). Default: 100.
    pub csw_jitter_stddev_ns: TimeNs,
}

impl Default for OverheadConfig {
    fn default() -> Self {
        OverheadConfig {
            enabled: true,
            voluntary_csw: true,
            involuntary_csw: true,
            voluntary_csw_ns: 500,
            involuntary_csw_ns: 1_000,
            csw_jitter: true,
            csw_jitter_stddev_ns: 100,
        }
    }
}

/// A complete simulation scenario: CPUs, tasks, and duration.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub nr_cpus: u32,
    /// SMT threads per physical core (1 = no SMT, 2 = hyperthreading).
    /// CPUs are grouped sequentially: with 4 CPUs and smt=2, CPUs 0,1
    /// share core 0 and CPUs 2,3 share core 1.
    pub smt_threads_per_core: u32,
    pub tasks: Vec<TaskDef>,
    pub duration_ns: TimeNs,
    pub noise: NoiseConfig,
    pub overhead: OverheadConfig,
}

/// Builder for constructing scenarios.
pub struct ScenarioBuilder {
    nr_cpus: u32,
    smt_threads_per_core: u32,
    tasks: Vec<TaskDef>,
    duration_ns: TimeNs,
    next_pid: Pid,
    noise: NoiseConfig,
    overhead: OverheadConfig,
}

impl Scenario {
    pub fn builder() -> ScenarioBuilder {
        ScenarioBuilder {
            nr_cpus: 1,
            smt_threads_per_core: 1,
            tasks: Vec::new(),
            duration_ns: 100_000_000, // 100ms default
            next_pid: Pid(1),
            noise: NoiseConfig::default(),
            overhead: OverheadConfig::default(),
        }
    }
}

impl ScenarioBuilder {
    /// Set the number of simulated CPUs.
    pub fn cpus(mut self, n: u32) -> Self {
        self.nr_cpus = n;
        self
    }

    /// Set SMT threads per core (default 1 = no SMT).
    ///
    /// `nr_cpus` must be divisible by this value.
    pub fn smt(mut self, threads_per_core: u32) -> Self {
        self.smt_threads_per_core = threads_per_core;
        self
    }

    /// Add a task with a full TaskDef.
    pub fn task(mut self, def: TaskDef) -> Self {
        self.tasks.push(def);
        self
    }

    /// Convenience: add a task with auto-assigned PID.
    pub fn add_task(mut self, name: &str, nice: i8, behavior: TaskBehavior) -> Self {
        let pid = self.next_pid;
        self.next_pid = Pid(pid.0 + 1);
        self.tasks.push(TaskDef {
            name: name.to_string(),
            pid,
            nice,
            behavior,
            start_time_ns: 0,
            mm_id: None,
            allowed_cpus: None,
        });
        self
    }

    /// Convenience: add a task with auto-assigned PID and a shared address space.
    ///
    /// Tasks with the same `MmId` are treated as threads sharing an address
    /// space, enabling wake-affine scheduling in COSMOS.
    pub fn add_task_with_mm(
        mut self,
        name: &str,
        nice: i8,
        behavior: TaskBehavior,
        mm_id: MmId,
    ) -> Self {
        let pid = self.next_pid;
        self.next_pid = Pid(pid.0 + 1);
        self.tasks.push(TaskDef {
            name: name.to_string(),
            pid,
            nice,
            behavior,
            start_time_ns: 0,
            mm_id: Some(mm_id),
            allowed_cpus: None,
        });
        self
    }

    /// Set the simulation duration in nanoseconds.
    pub fn duration_ns(mut self, ns: TimeNs) -> Self {
        self.duration_ns = ns;
        self
    }

    /// Set the simulation duration in milliseconds.
    pub fn duration_ms(mut self, ms: u64) -> Self {
        self.duration_ns = ms * 1_000_000;
        self
    }

    /// Enable or disable all simulation noise (tick jitter).
    pub fn noise(mut self, enabled: bool) -> Self {
        self.noise.enabled = enabled;
        self
    }

    /// Set a custom noise configuration.
    pub fn noise_config(mut self, config: NoiseConfig) -> Self {
        self.noise = config;
        self
    }

    /// Enable or disable all context switch overhead.
    pub fn overhead(mut self, enabled: bool) -> Self {
        self.overhead.enabled = enabled;
        self
    }

    /// Set a custom overhead configuration.
    pub fn overhead_config(mut self, config: OverheadConfig) -> Self {
        self.overhead = config;
        self
    }

    /// Disable all noise and overhead for exact deterministic timing.
    ///
    /// Shorthand for `.noise(false).overhead(false)`.
    pub fn exact_timing(self) -> Self {
        self.noise(false).overhead(false)
    }

    /// Build the scenario.
    pub fn build(self) -> Scenario {
        assert!(
            !self.tasks.is_empty(),
            "scenario must have at least one task"
        );
        assert!(self.nr_cpus > 0, "scenario must have at least one CPU");
        assert!(
            self.smt_threads_per_core > 0,
            "smt_threads_per_core must be at least 1"
        );
        assert!(
            self.nr_cpus.is_multiple_of(self.smt_threads_per_core),
            "nr_cpus ({}) must be divisible by smt_threads_per_core ({})",
            self.nr_cpus,
            self.smt_threads_per_core
        );
        Scenario {
            nr_cpus: self.nr_cpus,
            smt_threads_per_core: self.smt_threads_per_core,
            tasks: self.tasks,
            duration_ns: self.duration_ns,
            noise: self.noise,
            overhead: self.overhead,
        }
    }
}
