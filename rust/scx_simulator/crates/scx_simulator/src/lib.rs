//! scx_simulator - Deterministic event-driven simulator for sched_ext schedulers.
//!
//! This crate compiles sched_ext BPF scheduler code as regular userspace C and
//! runs it in a deterministic simulation with scripted task behaviors.
//!
//! # Architecture
//!
//! - **Engine**: Event-driven simulation loop that drives scheduling decisions
//! - **Tasks**: Scripted behaviors (run/sleep/wake phases)
//! - **DSQs**: Simulated dispatch queues (FIFO and vtime-ordered)
//! - **Kfuncs**: Rust implementations of BPF helper functions the scheduler calls
//! - **FFI**: Scheduler ops trait and C interop
//!
//! # Usage
//!
//! ```rust,no_run
//! use scx_simulator::*;
//!
//! let scenario = Scenario::builder()
//!     .cpus(2)
//!     .add_task("worker", 0, TaskBehavior {
//!         phases: vec![Phase::Run(10_000_000)],
//!         repeat: RepeatMode::Forever,
//!     })
//!     .duration_ms(100)
//!     .build();
//!
//! let trace = Simulator::new(DynamicScheduler::simple()).run(scenario);
//! trace.dump();
//! ```

pub mod cgroup;
pub mod cpu;
pub mod dsq;
pub mod engine;
pub mod ffi;
pub mod fmt;
pub mod kfuncs;
pub mod monitor;
pub mod perf;
mod perfetto;
pub mod probes;
pub mod rtapp;
pub mod scenario;
pub mod task;
pub mod trace;
pub mod types;
pub mod workloads;

// Re-export the main public types for convenience.
pub use cgroup::{
    clear_cgroup_registry, install_cgroup_registry, CgroupId, CgroupInfo, CgroupRegistry,
};
pub use engine::{ExitKind, SimulationResult, Simulator};
pub use ffi::{discover_schedulers, DynamicScheduler, LavdPowerMode, Scheduler, SchedulerInfo};
pub use fmt::{FmtN, FmtTs, SimFormat};
pub use kfuncs::sim_clock;
pub use monitor::{Monitor, ProbeContext, ProbePoint};
pub use perf::RbcCounter;
pub use rtapp::load_rtapp;
pub use scenario::{
    CgroupBandwidth, CgroupDef, CgroupMigrateEvent, CpuPreemptEvent, HotplugEvent, NoiseConfig,
    OverheadConfig, Scenario,
};
pub use task::{nice_to_weight, sched_weight_to_cgroup, Phase, RepeatMode, TaskBehavior, TaskDef};
pub use trace::{Trace, TraceEvent, TraceKind};
pub use types::{CpuId, DsqId, KickFlags, MmId, Pid, TimeNs, Vtime};

use std::sync::Mutex;

/// Global lock for serializing simulator tests.
///
/// The compiled C scheduler has global mutable state, so only one
/// simulation can run at a time within a process. Tests that use
/// `cargo test` (threads in a single process) must hold this lock.
/// `cargo nextest` (separate processes) works without it, but holding
/// the lock is harmless.
pub static SIM_LOCK: Mutex<()> = Mutex::new(());
