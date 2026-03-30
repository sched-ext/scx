// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use log::info;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_flow";

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Debug mode
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Disable adaptive runtime tuning and keep fixed default policy values.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_autotune: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AutoTuneMode {
    Balanced,
    Latency,
    Throughput,
}

impl AutoTuneMode {
    fn as_u64(self) -> u64 {
        match self {
            Self::Balanced => 0,
            Self::Latency => 1,
            Self::Throughput => 2,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::Latency => "latency",
            Self::Throughput => "throughput",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeTunables {
    reserved_max_ns: u64,
    shared_slice_ns: u64,
    interactive_floor_ns: u64,
    preempt_budget_min_ns: u64,
    preempt_refill_min_ns: u64,
}

impl Default for RuntimeTunables {
    fn default() -> Self {
        Self {
            reserved_max_ns: u64::from(consts_FLOW_SLICE_RESERVED_MAX_NS),
            shared_slice_ns: u64::from(consts_FLOW_SLICE_SHARED_NS),
            interactive_floor_ns: u64::from(consts_FLOW_INTERACTIVE_FLOOR_NS),
            preempt_budget_min_ns: u64::from(consts_FLOW_PREEMPT_BUDGET_MIN_NS),
            preempt_refill_min_ns: u64::from(consts_FLOW_PREEMPT_REFILL_MIN_NS),
        }
    }
}

impl RuntimeTunables {
    fn clamp(self) -> Self {
        Self {
            reserved_max_ns: self.reserved_max_ns.clamp(
                u64::from(consts_FLOW_SLICE_MIN_NS),
                u64::from(consts_FLOW_SLICE_RESERVED_TUNE_MAX_NS),
            ),
            shared_slice_ns: self.shared_slice_ns.clamp(
                u64::from(consts_FLOW_SLICE_SHARED_MIN_NS),
                u64::from(consts_FLOW_SLICE_SHARED_MAX_NS),
            ),
            interactive_floor_ns: self.interactive_floor_ns.clamp(
                u64::from(consts_FLOW_INTERACTIVE_FLOOR_MIN_NS),
                u64::from(consts_FLOW_INTERACTIVE_FLOOR_MAX_NS),
            ),
            preempt_budget_min_ns: self.preempt_budget_min_ns.clamp(
                u64::from(consts_FLOW_PREEMPT_BUDGET_MIN_NS),
                u64::from(consts_FLOW_PREEMPT_BUDGET_MAX_NS),
            ),
            preempt_refill_min_ns: self.preempt_refill_min_ns.clamp(
                u64::from(consts_FLOW_PREEMPT_REFILL_MIN_NS),
                u64::from(consts_FLOW_PREEMPT_REFILL_MAX_NS),
            ),
        }
    }

    fn target_for(mode: AutoTuneMode) -> Self {
        match mode {
            AutoTuneMode::Balanced => Self::default(),
            AutoTuneMode::Latency => Self {
                reserved_max_ns: 300 * 1000,
                shared_slice_ns: 900 * 1000,
                interactive_floor_ns: 140 * 1000,
                preempt_budget_min_ns: 225 * 1000,
                preempt_refill_min_ns: 250 * 1000,
            }
            .clamp(),
            AutoTuneMode::Throughput => Self {
                reserved_max_ns: 200 * 1000,
                shared_slice_ns: 1200 * 1000,
                interactive_floor_ns: 80 * 1000,
                preempt_budget_min_ns: 300 * 1000,
                preempt_refill_min_ns: 325 * 1000,
            }
            .clamp(),
        }
    }

    fn step_towards(&mut self, target: Self) -> bool {
        let mut changed = false;

        changed |= step_u64(&mut self.reserved_max_ns, target.reserved_max_ns, 25 * 1000);
        changed |= step_u64(
            &mut self.shared_slice_ns,
            target.shared_slice_ns,
            100 * 1000,
        );
        changed |= step_u64(
            &mut self.interactive_floor_ns,
            target.interactive_floor_ns,
            20 * 1000,
        );
        changed |= step_u64(
            &mut self.preempt_budget_min_ns,
            target.preempt_budget_min_ns,
            25 * 1000,
        );
        changed |= step_u64(
            &mut self.preempt_refill_min_ns,
            target.preempt_refill_min_ns,
            25 * 1000,
        );

        *self = self.clamp();
        changed
    }
}

fn step_u64(value: &mut u64, target: u64, step: u64) -> bool {
    if *value == target {
        return false;
    }

    if *value < target {
        *value = (*value + step).min(target);
    } else {
        *value = value.saturating_sub(step).max(target);
    }

    true
}

#[derive(Debug)]
struct AutoTuner {
    tunables: RuntimeTunables,
    mode: AutoTuneMode,
    pending_mode: AutoTuneMode,
    pending_steps: u8,
    latency_cooldown: u8,
    generation: u64,
    prev_metrics: Metrics,
}

impl AutoTuner {
    fn new(initial_metrics: Metrics) -> Self {
        Self {
            tunables: RuntimeTunables::default(),
            mode: AutoTuneMode::Balanced,
            pending_mode: AutoTuneMode::Balanced,
            pending_steps: 0,
            latency_cooldown: 0,
            generation: 0,
            prev_metrics: initial_metrics,
        }
    }

    fn evaluate_mode(&self, current: &Metrics, delta: &Metrics) -> AutoTuneMode {
        let positive = delta.positive_budget_wakeups;
        let shared_wake = delta.shared_wakeup_enqueues;
        let reserved_local = delta.reserved_local_enqueues;
        let reserved_global = delta.reserved_global_enqueues;
        let reserved_dispatches = delta.reserved_dispatches;
        let wake_preempt = delta.wake_preempt_dispatches;
        let exhaustions = delta.budget_exhaustions;
        let runnable = delta.runnable_wakeups;
        let reserved_total = reserved_local + reserved_global;

        if positive + shared_wake < 3 && reserved_total < 2 {
            return self.mode;
        }

        let shared_ratio = shared_wake as f64 / (positive + shared_wake).max(1) as f64;
        let global_ratio = reserved_global as f64 / reserved_total.max(1) as f64;
        let preempt_ratio = wake_preempt as f64 / reserved_local.max(1) as f64;
        let exhaustion_ratio = exhaustions as f64 / positive.max(1) as f64;
        let keep_latency_mode = self.mode == AutoTuneMode::Latency
            && current.nr_running >= 1
            && (wake_preempt > 0
                || reserved_dispatches > 0
                || reserved_global > 0
                || runnable > 64);
        let should_enter_latency_mode =
            shared_ratio > 0.45 || global_ratio > 0.35 || exhaustion_ratio > 0.30;

        if keep_latency_mode || should_enter_latency_mode {
            AutoTuneMode::Latency
        } else if current.nr_running >= 3
            && reserved_local >= 2
            && preempt_ratio > 0.65
            && shared_ratio < 0.35
            && global_ratio < 0.20
        {
            AutoTuneMode::Throughput
        } else {
            AutoTuneMode::Balanced
        }
    }

    fn update(&mut self, current: &Metrics) -> Option<(AutoTuneMode, RuntimeTunables, u64)> {
        let delta = current.delta(&self.prev_metrics);
        self.prev_metrics = current.clone();

        let desired_mode = self.evaluate_mode(current, &delta);
        let mut next_mode = self.mode;
        let leave_latency =
            self.mode == AutoTuneMode::Latency && desired_mode != AutoTuneMode::Latency;

        if desired_mode == AutoTuneMode::Latency {
            self.latency_cooldown = 3;
        } else if self.latency_cooldown > 0 {
            self.latency_cooldown -= 1;
        }

        if desired_mode == self.mode {
            self.pending_mode = self.mode;
            self.pending_steps = 0;
        } else {
            if desired_mode == self.pending_mode {
                self.pending_steps = self.pending_steps.saturating_add(1);
            } else {
                self.pending_mode = desired_mode;
                self.pending_steps = 1;
            }

            let required_steps = if leave_latency || self.latency_cooldown > 0 {
                4
            } else {
                2
            };

            if self.pending_steps >= required_steps {
                next_mode = desired_mode;
                self.pending_mode = desired_mode;
                self.pending_steps = 0;
            }
        }

        let target = RuntimeTunables::target_for(next_mode);
        let mode_changed = next_mode != self.mode;
        let tunables_changed = self.tunables.step_towards(target);

        if !mode_changed && !tunables_changed {
            return None;
        }

        self.mode = next_mode;
        self.generation += 1;
        Some((self.mode, self.tunables, self.generation))
    }
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.debug);

        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, flow_ops, open_opts)?;

        skel.struct_ops.flow_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;

        // Load BPF program
        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        Self::write_runtime_tunables(
            &mut skel,
            RuntimeTunables::default(),
            AutoTuneMode::Balanced,
            0,
        );

        // Attach scheduler
        let struct_ops = scx_ops_attach!(skel, flow_ops)?;

        // Launch stats server for scx_top
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        let data = self.skel.maps.data_data.as_ref().unwrap();
        Metrics {
            nr_running: bss_data.nr_running,
            total_runtime: bss_data.total_runtime,
            reserved_dispatches: bss_data.reserved_dispatches,
            shared_dispatches: bss_data.shared_dispatches,
            local_fast_dispatches: bss_data.local_fast_dispatches,
            wake_preempt_dispatches: bss_data.wake_preempt_dispatches,
            budget_refill_events: bss_data.budget_refill_events,
            budget_exhaustions: bss_data.budget_exhaustions,
            positive_budget_wakeups: bss_data.positive_budget_wakeups,
            reserved_local_enqueues: bss_data.reserved_local_enqueues,
            reserved_global_enqueues: bss_data.reserved_global_enqueues,
            shared_wakeup_enqueues: bss_data.shared_wakeup_enqueues,
            runnable_wakeups: bss_data.runnable_wakeups,
            cpu_release_reenqueues: bss_data.cpu_release_reenqueues,
            init_task_events: bss_data.init_task_events,
            enable_events: bss_data.enable_events,
            exit_task_events: bss_data.exit_task_events,
            rt_sensitive_wakeups: bss_data.rt_sensitive_wakeups,
            rt_sensitive_local_enqueues: bss_data.rt_sensitive_local_enqueues,
            rt_sensitive_preempts: bss_data.rt_sensitive_preempts,
            autotune_generation: bss_data.autotune_generation,
            autotune_mode: bss_data.autotune_mode,
            tune_reserved_max_ns: data.tune_reserved_max_ns,
            tune_shared_slice_ns: data.tune_shared_slice_ns,
            tune_interactive_floor_ns: data.tune_interactive_floor_ns,
            tune_preempt_budget_min_ns: data.tune_preempt_budget_min_ns,
            tune_preempt_refill_min_ns: data.tune_preempt_refill_min_ns,
        }
    }

    fn write_runtime_tunables(
        skel: &mut BpfSkel<'a>,
        tunables: RuntimeTunables,
        mode: AutoTuneMode,
        generation: u64,
    ) {
        let data = skel.maps.data_data.as_mut().unwrap();
        data.tune_reserved_max_ns = tunables.reserved_max_ns;
        data.tune_shared_slice_ns = tunables.shared_slice_ns;
        data.tune_interactive_floor_ns = tunables.interactive_floor_ns;
        data.tune_preempt_budget_min_ns = tunables.preempt_budget_min_ns;
        data.tune_preempt_refill_min_ns = tunables.preempt_refill_min_ns;

        let bss_data = skel.maps.bss_data.as_mut().unwrap();
        bss_data.autotune_mode = mode.as_u64();
        bss_data.autotune_generation = generation;
    }

    fn apply_runtime_tunables(
        &mut self,
        tunables: RuntimeTunables,
        mode: AutoTuneMode,
        generation: u64,
    ) {
        Self::write_runtime_tunables(&mut self.skel, tunables, mode, generation);
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>, autotune_enabled: bool) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let mut autotuner = autotune_enabled.then(|| AutoTuner::new(self.get_metrics()));
        let mut next_tune_at = Instant::now() + Duration::from_secs(1);

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_millis(250)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }

            if let Some(autotuner) = autotuner.as_mut() {
                if Instant::now() >= next_tune_at {
                    let current = self.get_metrics();
                    if let Some((mode, tunables, generation)) = autotuner.update(&current) {
                        self.apply_runtime_tunables(tunables, mode, generation);
                        info!(
                            "autotune={} gen={} reserve_cap={}us shared_slice={}us refill_floor={}us preempt_budget={}us preempt_refill={}us",
                            mode.as_str(),
                            generation,
                            tunables.reserved_max_ns / 1000,
                            tunables.shared_slice_ns / 1000,
                            tunables.interactive_floor_ns / 1000,
                            tunables.preempt_budget_min_ns / 1000,
                            tunables.preempt_refill_min_ns / 1000,
                        );
                    }
                    next_tune_at = Instant::now() + Duration::from_secs(1);
                }
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let monitor_only = opts.monitor.is_some();

    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }

    if !monitor_only {
        simplelog::SimpleLogger::init(
            if opts.debug {
                simplelog::LevelFilter::Debug
            } else {
                simplelog::LevelFilter::Info
            },
            simplelog::Config::default(),
        )?;

        info!("{} {}", SCHEDULER_NAME, full_version());
        info!("Starting {} scheduler", SCHEDULER_NAME);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Handle Ctrl+C
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(err) = stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                log::warn!("stats monitor thread finished with error: {err}");
            }
        });

        if monitor_only {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object)?;
    let uei = sched.run(shutdown, !opts.no_autotune)?;

    info!("Scheduler exited: {:?}", uei);

    Ok(())
}
