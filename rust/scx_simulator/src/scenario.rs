//! Scenario definition and builder API.

use tracing::warn;

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

impl NoiseConfig {
    /// Create a NoiseConfig with defaults influenced by environment variables.
    ///
    /// Precedence: `SCX_SIM_NOISE` > `SCX_SIM_INSTANT_TIMING` > hardcoded default.
    ///
    /// - `SCX_SIM_NOISE=0` disables noise; `SCX_SIM_NOISE=1` enables it.
    /// - `SCX_SIM_INSTANT_TIMING=1` disables noise (lower priority).
    /// - If neither is set, defaults to enabled.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if std::env::var("SCX_SIM_INSTANT_TIMING").ok().as_deref() == Some("1") {
            config.enabled = false;
        }
        match std::env::var("SCX_SIM_NOISE").ok().as_deref() {
            Some("0") => config.enabled = false,
            Some("1") => config.enabled = true,
            _ => {}
        }
        config
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

impl OverheadConfig {
    /// Create an OverheadConfig with defaults influenced by environment variables.
    ///
    /// Precedence: `SCX_SIM_OVERHEAD` > `SCX_SIM_INSTANT_TIMING` > hardcoded default.
    ///
    /// - `SCX_SIM_OVERHEAD=0` disables overhead; `SCX_SIM_OVERHEAD=1` enables it.
    /// - `SCX_SIM_INSTANT_TIMING=1` disables overhead (lower priority).
    /// - If neither is set, defaults to enabled.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if std::env::var("SCX_SIM_INSTANT_TIMING").ok().as_deref() == Some("1") {
            config.enabled = false;
        }
        match std::env::var("SCX_SIM_OVERHEAD").ok().as_deref() {
            Some("0") => config.enabled = false,
            Some("1") => config.enabled = true,
            _ => {}
        }
        config
    }
}

/// Default PRNG seed used when `SCX_SIM_SEED` is not set.
const DEFAULT_SEED: u32 = 42;

/// Resolve the PRNG seed from the `SCX_SIM_SEED` environment variable.
///
/// - Unset or empty: returns `DEFAULT_SEED` (42).
/// - `"entropy"` (case-insensitive): seeds from OS randomness and logs the
///   chosen value so the run can be reproduced later.
/// - Any decimal integer: parsed as a `u32` seed.
pub fn seed_from_env() -> u32 {
    match std::env::var("SCX_SIM_SEED").ok().as_deref() {
        None | Some("") => DEFAULT_SEED,
        Some(s) if s.eq_ignore_ascii_case("entropy") => {
            // Use OS randomness: read 4 bytes from /dev/urandom.
            let seed = {
                use std::io::Read;
                let mut buf = [0u8; 4];
                std::fs::File::open("/dev/urandom")
                    .and_then(|mut f| f.read_exact(&mut buf).map(|_| u32::from_le_bytes(buf)))
                    .unwrap_or_else(|_| {
                        // Fallback: use process ID + rough timestamp.
                        let pid = std::process::id();
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos() as u32)
                            .unwrap_or(0);
                        pid ^ ts
                    })
            };
            // Avoid seed 0 which is a fixed point for xorshift.
            let seed = if seed == 0 { 1 } else { seed };
            warn!(
                seed,
                "SCX_SIM_SEED=entropy: seeding PRNG with OS randomness \
                 (set SCX_SIM_SEED={seed} to reproduce this run)"
            );
            seed
        }
        Some(s) => s.parse::<u32>().unwrap_or_else(|_| {
            panic!("SCX_SIM_SEED={s:?}: expected a u32 integer or \"entropy\"");
        }),
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
    /// PRNG seed for deterministic simulation. Default: 42.
    pub seed: u32,
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
    seed: u32,
}

impl Scenario {
    pub fn builder() -> ScenarioBuilder {
        ScenarioBuilder {
            nr_cpus: 1,
            smt_threads_per_core: 1,
            tasks: Vec::new(),
            duration_ns: 100_000_000, // 100ms default
            next_pid: Pid(1),
            noise: NoiseConfig::from_env(),
            overhead: OverheadConfig::from_env(),
            seed: seed_from_env(),
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

    /// Disable all noise and overhead for instant timing.
    ///
    /// Context switches and tick interrupts happen instantaneously with zero
    /// cost. Shorthand for `.noise(false).overhead(false)`.
    pub fn instant_timing(self) -> Self {
        self.noise(false).overhead(false)
    }

    /// Set the PRNG seed for deterministic simulation.
    pub fn seed(mut self, seed: u32) -> Self {
        self.seed = seed;
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
            overhead: self.overhead,
            seed: self.seed,
        }
    }
}
