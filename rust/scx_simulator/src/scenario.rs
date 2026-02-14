//! Scenario definition and builder API.

use crate::task::{TaskBehavior, TaskDef};
use crate::types::{MmId, Pid, TimeNs};

/// Configuration for simulation timing noise.
///
/// Models two sources of real-world timing imprecision:
/// - **Tick jitter**: Hardware interrupt delivery latency causes 1–10μs of
///   jitter on commodity hardware (normal distribution, σ=2μs default).
/// - **Context switch overhead**: Voluntary yields cost ~500ns; involuntary
///   preemptions cost ~1000ns due to cache/TLB invalidation.
#[derive(Debug, Clone)]
pub struct NoiseConfig {
    /// Master switch: false disables all noise (exact deterministic timing).
    pub enabled: bool,
    /// Standard deviation for tick jitter (ns). Default: 2000 (2μs).
    pub tick_jitter_stddev_ns: TimeNs,
    /// Time consumed by a voluntary context switch (ns). Default: 500.
    pub voluntary_csw_overhead_ns: TimeNs,
    /// Time consumed by an involuntary context switch (ns). Default: 1000.
    pub involuntary_csw_overhead_ns: TimeNs,
    /// Standard deviation for CSW overhead jitter (ns). Default: 100.
    pub csw_jitter_stddev_ns: TimeNs,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        NoiseConfig {
            enabled: true,
            tick_jitter_stddev_ns: 2_000,
            voluntary_csw_overhead_ns: 500,
            involuntary_csw_overhead_ns: 1_000,
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
}

/// Builder for constructing scenarios.
pub struct ScenarioBuilder {
    nr_cpus: u32,
    smt_threads_per_core: u32,
    tasks: Vec<TaskDef>,
    duration_ns: TimeNs,
    next_pid: Pid,
    noise: NoiseConfig,
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

    /// Enable or disable all simulation noise.
    pub fn noise(mut self, enabled: bool) -> Self {
        self.noise.enabled = enabled;
        self
    }

    /// Set a custom noise configuration.
    pub fn noise_config(mut self, config: NoiseConfig) -> Self {
        self.noise = config;
        self
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
        }
    }
}
