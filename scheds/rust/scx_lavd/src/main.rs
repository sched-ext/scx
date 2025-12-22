// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod cpu_order;
use scx_utils::init_libbpf_logging;
mod stats;
use std::ffi::c_int;
use std::ffi::CStr;
use std::mem;
use std::mem::MaybeUninit;
use std::str;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use clap_num::number_range;
use cpu_order::CpuOrder;
use cpu_order::PerfCpuOrder;
use crossbeam::channel;
use crossbeam::channel::Receiver;
use crossbeam::channel::RecvTimeoutError;
use crossbeam::channel::Sender;
use crossbeam::channel::TrySendError;
use libbpf_rs::skel::Skel;
use libbpf_rs::OpenObject;
use libbpf_rs::PrintLevel;
use libbpf_rs::ProgramInput;
use libc::c_char;
use plain::Plain;
use scx_arena::ArenaLib;
use scx_stats::prelude::*;
use scx_utils::autopower::{fetch_power_profile, PowerProfile};
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::ksym_exists;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::EnergyModel;
use scx_utils::TopologyArgs;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::SchedSample;
use stats::SchedSamples;
use stats::StatsReq;
use stats::StatsRes;
use stats::SysStats;
use tracing::{debug, info, warn};
use tracing_subscriber::filter::EnvFilter;

const SCHEDULER_NAME: &str = "scx_lavd";
/// scx_lavd: Latency-criticality Aware Virtual Deadline (LAVD) scheduler
///
/// The rust part is minimal. It processes command line options and logs out
/// scheduling statistics. The BPF part makes all the scheduling decisions.
/// See the more detailed overview of the LAVD design at main.bpf.c.
#[derive(Debug, Parser)]
struct Opts {
    /// Deprecated, noop, use RUST_LOG or --log-level instead.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Automatically decide the scheduler's power mode (performance vs.
    /// powersave vs. balanced), CPU preference order, etc, based on system
    /// load. The options affecting the power mode and the use of core compaction
    /// (--autopower, --performance, --powersave, --balanced,
    /// --no-core-compaction) cannot be used with this option. When no option
    /// is specified, this is a default mode.
    #[clap(long = "autopilot", action = clap::ArgAction::SetTrue)]
    autopilot: bool,

    /// Automatically decide the scheduler's power mode (performance vs.
    /// powersave vs. balanced) based on the system's active power profile.
    /// The scheduler's power mode decides the CPU preference order and the use
    /// of core compaction, so the options affecting these (--autopilot,
    /// --performance, --powersave, --balanced, --no-core-compaction) cannot
    /// be used with this option.
    #[clap(long = "autopower", action = clap::ArgAction::SetTrue)]
    autopower: bool,

    /// Run the scheduler in performance mode to get maximum performance.
    /// This option cannot be used with other conflicting options (--autopilot,
    /// --autopower, --balanced, --powersave, --no-core-compaction)
    /// affecting the use of core compaction.
    #[clap(long = "performance", action = clap::ArgAction::SetTrue)]
    performance: bool,

    /// Run the scheduler in powersave mode to minimize powr consumption.
    /// This option cannot be used with other conflicting options (--autopilot,
    /// --autopower, --performance, --balanced, --no-core-compaction)
    /// affecting the use of core compaction.
    #[clap(long = "powersave", action = clap::ArgAction::SetTrue)]
    powersave: bool,

    /// Run the scheduler in balanced mode aiming for sweetspot between power
    /// and performance. This option cannot be used with other conflicting
    /// options (--autopilot, --autopower, --performance, --powersave,
    /// --no-core-compaction) affecting the use of core compaction.
    #[clap(long = "balanced", action = clap::ArgAction::SetTrue)]
    balanced: bool,

    /// Maximum scheduling slice duration in microseconds.
    #[clap(long = "slice-max-us", default_value = "5000")]
    slice_max_us: u64,

    /// Minimum scheduling slice duration in microseconds.
    #[clap(long = "slice-min-us", default_value = "500")]
    slice_min_us: u64,

    /// Migration delta threshold percentage (0-100). When set to a non-zero value,
    /// uses average utilization for threshold calculation instead of current
    /// utilization, and the threshold is calculated as: avg_load * (mig-delta-pct / 100).
    /// Additionally, disables force task stealing in the consume path, relying only
    /// on the is_stealer/is_stealee thresholds for more predictable load balancing.
    /// Default is 0 (disabled, uses dynamic threshold based on load with both
    /// probabilistic and force task stealing enabled). This is an experimental feature.
    #[clap(long = "mig-delta-pct", default_value = "0", value_parser=Opts::mig_delta_pct_range)]
    mig_delta_pct: u8,

    /// Slice duration in microseconds to use for all tasks when pinned tasks
    /// are running on a CPU. Must be between slice-min-us and slice-max-us.
    /// When this option is enabled, pinned tasks are always enqueued to per-CPU DSQs
    /// and the dispatch logic compares vtimes across all DSQs to select the lowest
    /// vtime task. This helps improve responsiveness for pinned tasks. By default,
    /// this option is on with a default value of 5000 (5 msec). To turn off the option,
    /// explicitly set the value to 0.
    #[clap(long = "pinned-slice-us", default_value = "5000")]
    pinned_slice_us: Option<u64>,

    /// Limit the ratio of preemption to the roughly top P% of latency-critical
    /// tasks. When N is given as an argument, P is 0.5^N * 100. The default
    /// value is 6, which limits the preemption for the top 1.56% of
    /// latency-critical tasks.
    #[clap(long = "preempt-shift", default_value = "6", value_parser=Opts::preempt_shift_range)]
    preempt_shift: u8,

    /// List of CPUs in preferred order (e.g., "0-3,7,6,5,4"). The scheduler
    /// uses the CPU preference mode only when the core compaction is enabled
    /// (i.e., balanced or powersave mode is specified as an option or chosen
    /// in the autopilot or autopower mode). When "--cpu-pref-order" is given,
    /// it implies "--no-use-em".
    #[clap(long = "cpu-pref-order", default_value = "")]
    cpu_pref_order: String,

    /// Do not use the energy model in making CPU preference order decisions.
    #[clap(long = "no-use-em", action = clap::ArgAction::SetTrue)]
    no_use_em: bool,

    /// Do not boost futex holders.
    #[clap(long = "no-futex-boost", action = clap::ArgAction::SetTrue)]
    no_futex_boost: bool,

    /// Disable preemption.
    #[clap(long = "no-preemption", action = clap::ArgAction::SetTrue)]
    no_preemption: bool,

    /// Disable an optimization for synchronous wake-up.
    #[clap(long = "no-wake-sync", action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Disable dynamic slice boost for long-running tasks.
    #[clap(long = "no-slice-boost", action = clap::ArgAction::SetTrue)]
    no_slice_boost: bool,

    /// Enables DSQs per CPU, this enables task queuing and dispatching
    /// from CPU specific DSQs. This generally increases L1/L2 cache
    /// locality for tasks and lowers lock contention compared to shared DSQs,
    /// but at the cost of higher load balancing complexity. This is a
    /// highly experimental feature.
    #[clap(long = "per-cpu-dsq", action = clap::ArgAction::SetTrue)]
    per_cpu_dsq: bool,

    /// Enable CPU bandwidth control using cpu.max in cgroup v2.
    /// This is a highly experimental feature.
    #[clap(long = "enable-cpu-bw", action = clap::ArgAction::SetTrue)]
    enable_cpu_bw: bool,

    ///
    /// Disable core compaction so the scheduler uses all the online CPUs.
    /// The core compaction attempts to minimize the number of actively used
    /// CPUs for unaffinitized tasks, respecting the CPU preference order.
    /// Normally, the core compaction is enabled by the power mode (i.e.,
    /// balanced or powersave mode is specified as an option or chosen in
    /// the autopilot or autopower mode). This option cannot be used with the
    /// other options that control the core compaction (--autopilot,
    /// --autopower, --performance, --balanced, --powersave).
    #[clap(long = "no-core-compaction", action = clap::ArgAction::SetTrue)]
    no_core_compaction: bool,

    /// Disable controlling the CPU frequency.
    #[clap(long = "no-freq-scaling", action = clap::ArgAction::SetTrue)]
    no_freq_scaling: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Run in monitoring mode. Show the specified number of scheduling
    /// samples every second.
    #[clap(long)]
    monitor_sched_samples: Option<u64>,

    /// Specify the logging level. Accepts rust's envfilter syntax for modular
    /// logging: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax. Examples: ["info", "warn,tokio=info"]
    #[clap(long, default_value = "info")]
    log_level: String,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Optional run ID for tracking scheduler instances.
    #[clap(long)]
    run_id: Option<u64>,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,

    /// Topology configuration options
    #[clap(flatten)]
    topology: Option<TopologyArgs>,
}

impl Opts {
    fn can_autopilot(&self) -> bool {
        self.autopower == false
            && self.performance == false
            && self.powersave == false
            && self.balanced == false
            && self.no_core_compaction == false
    }

    fn can_autopower(&self) -> bool {
        self.autopilot == false
            && self.performance == false
            && self.powersave == false
            && self.balanced == false
            && self.no_core_compaction == false
    }

    fn can_performance(&self) -> bool {
        self.autopilot == false
            && self.autopower == false
            && self.powersave == false
            && self.balanced == false
    }

    fn can_balanced(&self) -> bool {
        self.autopilot == false
            && self.autopower == false
            && self.performance == false
            && self.powersave == false
            && self.no_core_compaction == false
    }

    fn can_powersave(&self) -> bool {
        self.autopilot == false
            && self.autopower == false
            && self.performance == false
            && self.balanced == false
            && self.no_core_compaction == false
    }

    fn proc(&mut self) -> Option<&mut Self> {
        if !self.autopilot {
            self.autopilot = self.can_autopilot();
        }

        if self.autopilot {
            if !self.can_autopilot() {
                info!("Autopilot mode cannot be used with conflicting options.");
                return None;
            }
            info!("Autopilot mode is enabled.");
        }

        if self.autopower {
            if !self.can_autopower() {
                info!("Autopower mode cannot be used with conflicting options.");
                return None;
            }
            info!("Autopower mode is enabled.");
        }

        if self.performance {
            if !self.can_performance() {
                info!("Performance mode cannot be used with conflicting options.");
                return None;
            }
            info!("Performance mode is enabled.");
            self.no_core_compaction = true;
        }

        if self.powersave {
            if !self.can_powersave() {
                info!("Powersave mode cannot be used with conflicting options.");
                return None;
            }
            info!("Powersave mode is enabled.");
            self.no_core_compaction = false;
        }

        if self.balanced {
            if !self.can_balanced() {
                info!("Balanced mode cannot be used with conflicting options.");
                return None;
            }
            info!("Balanced mode is enabled.");
            self.no_core_compaction = false;
        }

        if !EnergyModel::has_energy_model() || !self.cpu_pref_order.is_empty() {
            self.no_use_em = true;
            info!("Energy model won't be used for CPU preference order.");
        }

        if let Some(pinned_slice) = self.pinned_slice_us {
            if pinned_slice == 0 {
                info!("Pinned task slice mode is disabled. Pinned tasks will use per-domain DSQs.");
            } else if pinned_slice < self.slice_min_us || pinned_slice > self.slice_max_us {
                info!(
                    "pinned-slice-us ({}) must be between slice-min-us ({}) and slice-max-us ({})",
                    pinned_slice, self.slice_min_us, self.slice_max_us
                );
                return None;
            } else {
                info!(
                "Pinned task slice mode is enabled ({} us). Pinned tasks will use per-CPU DSQs.",
                pinned_slice
            );
            }
        }

        Some(self)
    }

    fn preempt_shift_range(s: &str) -> Result<u8, String> {
        number_range(s, 0, 10)
    }

    fn mig_delta_pct_range(s: &str) -> Result<u8, String> {
        number_range(s, 0, 100)
    }
}

unsafe impl Plain for msg_task_ctx {}

impl msg_task_ctx {
    fn from_bytes(buf: &[u8]) -> &msg_task_ctx {
        plain::from_bytes(buf).expect("The buffer is either too short or not aligned!")
    }
}

impl introspec {
    fn new() -> Self {
        let intrspc = unsafe { mem::MaybeUninit::<introspec>::zeroed().assume_init() };
        intrspc
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    rb_mgr: libbpf_rs::RingBuffer<'static>,
    intrspc: introspec,
    intrspc_rx: Receiver<SchedSample>,
    monitor_tid: Option<ThreadId>,
    stats_server: StatsServer<StatsReq, StatsRes>,
    mseq_id: u64,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        if *NR_CPU_IDS > LAVD_CPU_ID_MAX as usize {
            panic!(
                "Num possible CPU IDs ({}) exceeds maximum of ({})",
                *NR_CPU_IDS, LAVD_CPU_ID_MAX
            );
        }

        try_set_rlimit_infinity();

        // Open the BPF prog first for verification.
        let debug_level = if opts.log_level.contains("trace") {
            2
        } else if opts.log_level.contains("debug") {
            1
        } else {
            0
        };
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(debug_level > 1);
        init_libbpf_logging(Some(PrintLevel::Debug));

        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, lavd_ops, open_opts)?;

        // Enable futex tracing using ftrace if available. If the ftrace is not
        // available, use tracepoint, which is known to be slower than ftrace.
        if !opts.no_futex_boost {
            if Self::attach_futex_ftraces(&mut skel)? == false {
                info!("Fail to attach futex ftraces. Try with tracepoints.");
                if Self::attach_futex_tracepoints(&mut skel)? == false {
                    info!("Fail to attach futex tracepoints.");
                }
            }
        }

        // Initialize CPU topology with CLI arguments
        let order = CpuOrder::new(opts.topology.as_ref()).unwrap();
        Self::init_cpus(&mut skel, &order);
        Self::init_cpdoms(&mut skel, &order);

        // Initialize skel according to @opts.
        Self::init_globals(&mut skel, &opts, &order, debug_level);

        // Initialize arena
        let mut skel = scx_ops_load!(skel, lavd_ops, uei)?;
        let task_size = std::mem::size_of::<types::task_ctx>();
        let arenalib = ArenaLib::init(skel.object_mut(), task_size, *NR_CPU_IDS)?;
        arenalib.setup()?;

        // Attach.
        let struct_ops = Some(scx_ops_attach!(skel, lavd_ops)?);
        let stats_server = StatsServer::new(stats::server_data(*NR_CPU_IDS as u64)).launch()?;

        // Build a ring buffer for instrumentation
        let (intrspc_tx, intrspc_rx) = channel::bounded(65536);
        let rb_map = &mut skel.maps.introspec_msg;
        let mut builder = libbpf_rs::RingBufferBuilder::new();
        builder
            .add(rb_map, move |data| {
                Scheduler::relay_introspec(data, &intrspc_tx)
            })
            .unwrap();
        let rb_mgr = builder.build().unwrap();

        Ok(Self {
            skel,
            struct_ops,
            rb_mgr,
            intrspc: introspec::new(),
            intrspc_rx,
            monitor_tid: None,
            stats_server,
            mseq_id: 0,
        })
    }

    fn attach_futex_ftraces(skel: &mut OpenBpfSkel) -> Result<bool> {
        let ftraces = vec![
            ("__futex_wait", &skel.progs.fexit___futex_wait),
            ("futex_wait_multiple", &skel.progs.fexit_futex_wait_multiple),
            (
                "futex_wait_requeue_pi",
                &skel.progs.fexit_futex_wait_requeue_pi,
            ),
            ("futex_wake", &skel.progs.fexit_futex_wake),
            ("futex_wake_op", &skel.progs.fexit_futex_wake_op),
            ("futex_lock_pi", &skel.progs.fexit_futex_lock_pi),
            ("futex_unlock_pi", &skel.progs.fexit_futex_unlock_pi),
        ];

        if compat::tracer_available("function")? == false {
            info!("Ftrace is not enabled in the kernel.");
            return Ok(false);
        }

        compat::cond_kprobes_enable(ftraces)
    }

    fn attach_futex_tracepoints(skel: &mut OpenBpfSkel) -> Result<bool> {
        let tracepoints = vec![
            ("syscalls:sys_enter_futex", &skel.progs.rtp_sys_enter_futex),
            ("syscalls:sys_exit_futex", &skel.progs.rtp_sys_exit_futex),
            (
                "syscalls:sys_exit_futex_wait",
                &skel.progs.rtp_sys_exit_futex_wait,
            ),
            (
                "syscalls:sys_exit_futex_waitv",
                &skel.progs.rtp_sys_exit_futex_waitv,
            ),
            (
                "syscalls:sys_exit_futex_wake",
                &skel.progs.rtp_sys_exit_futex_wake,
            ),
        ];

        compat::cond_tracepoints_enable(tracepoints)
    }

    fn init_cpus(skel: &mut OpenBpfSkel, order: &CpuOrder) {
        debug!("{:#?}", order);

        // Initialize CPU capacity and sibling
        for cpu in order.cpuids.iter() {
            skel.maps.rodata_data.as_mut().unwrap().cpu_capacity[cpu.cpu_adx] = cpu.cpu_cap as u16;
            skel.maps.rodata_data.as_mut().unwrap().cpu_big[cpu.cpu_adx] = cpu.big_core as u8;
            skel.maps.rodata_data.as_mut().unwrap().cpu_turbo[cpu.cpu_adx] = cpu.turbo_core as u8;
            skel.maps.rodata_data.as_mut().unwrap().cpu_sibling[cpu.cpu_adx] =
                cpu.cpu_sibling as u32;
        }

        // Initialize performance vs. CPU order table.
        let nr_pco_states: u8 = order.perf_cpu_order.len() as u8;
        if nr_pco_states > LAVD_PCO_STATE_MAX as u8 {
            panic!("Generated performance vs. CPU order stats are too complex ({nr_pco_states}) to handle");
        }

        skel.maps.rodata_data.as_mut().unwrap().nr_pco_states = nr_pco_states;
        for (i, (_, pco)) in order.perf_cpu_order.iter().enumerate() {
            Self::init_pco_tuple(skel, i, &pco);
            info!("{:#}", pco);
        }

        let (_, last_pco) = order.perf_cpu_order.last_key_value().unwrap();
        for i in nr_pco_states..LAVD_PCO_STATE_MAX as u8 {
            Self::init_pco_tuple(skel, i as usize, &last_pco);
        }
    }

    fn init_pco_tuple(skel: &mut OpenBpfSkel, i: usize, pco: &PerfCpuOrder) {
        let cpus_perf = pco.cpus_perf.borrow();
        let cpus_ovflw = pco.cpus_ovflw.borrow();
        let pco_nr_primary = cpus_perf.len();

        skel.maps.rodata_data.as_mut().unwrap().pco_bounds[i] = pco.perf_cap as u32;
        skel.maps.rodata_data.as_mut().unwrap().pco_nr_primary[i] = pco_nr_primary as u16;

        for (j, &cpu_adx) in cpus_perf.iter().enumerate() {
            skel.maps.rodata_data.as_mut().unwrap().pco_table[i][j] = cpu_adx as u16;
        }

        for (j, &cpu_adx) in cpus_ovflw.iter().enumerate() {
            let k = j + pco_nr_primary;
            skel.maps.rodata_data.as_mut().unwrap().pco_table[i][k] = cpu_adx as u16;
        }
    }

    fn init_cpdoms(skel: &mut OpenBpfSkel, order: &CpuOrder) {
        // Initialize compute domain contexts
        for (k, v) in order.cpdom_map.iter() {
            skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].id = v.cpdom_id as u64;
            skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].alt_id =
                v.cpdom_alt_id.get() as u64;
            skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].numa_id = k.numa_adx as u8;
            skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].llc_id = k.llc_adx as u8;
            skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].is_big = k.is_big as u8;
            skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].is_valid = 1;
            for cpu_id in v.cpu_ids.iter() {
                let i = cpu_id / 64;
                let j = cpu_id % 64;
                skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].__cpumask[i] |=
                    0x01 << j;
            }

            if v.neighbor_map.borrow().iter().len() > LAVD_CPDOM_MAX_DIST as usize {
                panic!("The processor topology is too complex to handle in BPF.");
            }

            for (k, (_d, neighbors)) in v.neighbor_map.borrow().iter().enumerate() {
                let nr_neighbors = neighbors.borrow().len() as u8;
                if nr_neighbors > LAVD_CPDOM_MAX_NR as u8 {
                    panic!("The processor topology is too complex to handle in BPF.");
                }
                skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].nr_neighbors[k] =
                    nr_neighbors;
                for (i, &id) in neighbors.borrow().iter().enumerate() {
                    let idx = (k * LAVD_CPDOM_MAX_NR as usize) + i;
                    skel.maps.bss_data.as_mut().unwrap().cpdom_ctxs[v.cpdom_id].neighbor_ids[idx] =
                        id as u8;
                }
            }
        }
    }

    fn init_globals(skel: &mut OpenBpfSkel, opts: &Opts, order: &CpuOrder, debug_level: u8) {
        let bss_data = skel.maps.bss_data.as_mut().unwrap();
        bss_data.no_preemption = opts.no_preemption;
        bss_data.no_core_compaction = opts.no_core_compaction;
        bss_data.no_freq_scaling = opts.no_freq_scaling;
        bss_data.is_powersave_mode = opts.powersave;
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.nr_llcs = order.nr_llcs as u64;
        rodata.nr_cpu_ids = *NR_CPU_IDS as u32;
        rodata.is_smt_active = order.smt_enabled;
        rodata.is_autopilot_on = opts.autopilot;
        rodata.verbose = debug_level;
        rodata.slice_max_ns = opts.slice_max_us * 1000;
        rodata.slice_min_ns = opts.slice_min_us * 1000;
        rodata.pinned_slice_ns = opts.pinned_slice_us.map(|v| v * 1000).unwrap_or(0);
        rodata.preempt_shift = opts.preempt_shift;
        rodata.mig_delta_pct = opts.mig_delta_pct;
        rodata.no_use_em = opts.no_use_em as u8;
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.no_slice_boost = opts.no_slice_boost;
        rodata.per_cpu_dsq = opts.per_cpu_dsq;
        rodata.enable_cpu_bw = opts.enable_cpu_bw;

        if !ksym_exists("scx_group_set_bandwidth").unwrap() {
            skel.struct_ops.lavd_ops_mut().cgroup_set_bandwidth = std::ptr::null_mut();
            warn!("Kernel does not support ops.cgroup_set_bandwidth(), so disable it.");
        }

        skel.struct_ops.lavd_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_KEEP_BUILTIN_IDLE;
    }

    fn get_msg_seq_id() -> u64 {
        static mut MSEQ: u64 = 0;
        unsafe {
            MSEQ += 1;
            MSEQ
        }
    }

    fn relay_introspec(data: &[u8], intrspc_tx: &Sender<SchedSample>) -> i32 {
        let mt = msg_task_ctx::from_bytes(data);
        let tx = mt.taskc_x;

        // No idea how to print other types than LAVD_MSG_TASKC
        if mt.hdr.kind != LAVD_MSG_TASKC {
            return 0;
        }

        let mseq = Scheduler::get_msg_seq_id();

        let c_tx_cm: *const c_char = (&tx.comm as *const [c_char; 17]) as *const c_char;
        let c_tx_cm_str: &CStr = unsafe { CStr::from_ptr(c_tx_cm) };
        let tx_comm: &str = c_tx_cm_str.to_str().unwrap();

        let c_waker_cm: *const c_char = (&tx.waker_comm as *const [c_char; 17]) as *const c_char;
        let c_waker_cm_str: &CStr = unsafe { CStr::from_ptr(c_waker_cm) };
        let waker_comm: &str = c_waker_cm_str.to_str().unwrap();

        let c_tx_st: *const c_char = (&tx.stat as *const [c_char; 5]) as *const c_char;
        let c_tx_st_str: &CStr = unsafe { CStr::from_ptr(c_tx_st) };
        let tx_stat: &str = c_tx_st_str.to_str().unwrap();

        match intrspc_tx.try_send(SchedSample {
            mseq,
            pid: tx.pid,
            comm: tx_comm.into(),
            stat: tx_stat.into(),
            cpu_id: tx.cpu_id,
            prev_cpu_id: tx.prev_cpu_id,
            suggested_cpu_id: tx.suggested_cpu_id,
            waker_pid: tx.waker_pid,
            waker_comm: waker_comm.into(),
            slice: tx.slice,
            lat_cri: tx.lat_cri,
            avg_lat_cri: tx.avg_lat_cri,
            static_prio: tx.static_prio,
            rerunnable_interval: tx.rerunnable_interval,
            resched_interval: tx.resched_interval,
            run_freq: tx.run_freq,
            avg_runtime: tx.avg_runtime,
            wait_freq: tx.wait_freq,
            wake_freq: tx.wake_freq,
            perf_cri: tx.perf_cri,
            thr_perf_cri: tx.thr_perf_cri,
            cpuperf_cur: tx.cpuperf_cur,
            cpu_util: tx.cpu_util,
            cpu_sutil: tx.cpu_sutil,
            nr_active: tx.nr_active,
            dsq_id: tx.dsq_id,
            dsq_consume_lat: tx.dsq_consume_lat,
            slice_used: tx.last_slice_used,
        }) {
            Ok(()) | Err(TrySendError::Full(_)) => 0,
            Err(e) => panic!("failed to send on intrspc_tx ({})", e),
        }
    }

    fn prep_introspec(&mut self) {
        if !self.skel.maps.bss_data.as_ref().unwrap().is_monitored {
            self.skel.maps.bss_data.as_mut().unwrap().is_monitored = true;
        }
        self.skel.maps.bss_data.as_mut().unwrap().intrspc.cmd = self.intrspc.cmd;
        self.skel.maps.bss_data.as_mut().unwrap().intrspc.arg = self.intrspc.arg;
    }

    fn cleanup_introspec(&mut self) {
        self.skel.maps.bss_data.as_mut().unwrap().intrspc.cmd = LAVD_CMD_NOP;
    }

    fn get_pc(x: u64, y: u64) -> f64 {
        return 100. * x as f64 / y as f64;
    }

    fn get_power_mode(power_mode: i32) -> &'static str {
        match power_mode as u32 {
            LAVD_PM_PERFORMANCE => "performance",
            LAVD_PM_BALANCED => "balanced",
            LAVD_PM_POWERSAVE => "powersave",
            _ => "unknown",
        }
    }

    fn stats_req_to_res(&mut self, req: &StatsReq) -> Result<StatsRes> {
        Ok(match req {
            StatsReq::NewSampler(tid) => {
                self.rb_mgr.consume().unwrap();
                self.monitor_tid = Some(*tid);
                StatsRes::Ack
            }
            StatsReq::SysStatsReq { tid } => {
                if Some(*tid) != self.monitor_tid {
                    return Ok(StatsRes::Bye);
                }
                self.mseq_id += 1;

                let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
                let st = bss_data.sys_stat;

                let mseq = self.mseq_id;
                let nr_queued_task = st.nr_queued_task;
                let nr_active = st.nr_active;
                let nr_sched = st.nr_sched;
                let nr_preempt = st.nr_preempt;
                let pc_pc = Self::get_pc(st.nr_perf_cri, nr_sched);
                let pc_lc = Self::get_pc(st.nr_lat_cri, nr_sched);
                let pc_x_migration = Self::get_pc(st.nr_x_migration, nr_sched);
                let nr_stealee = st.nr_stealee;
                let nr_big = st.nr_big;
                let pc_big = Self::get_pc(nr_big, nr_sched);
                let pc_pc_on_big = Self::get_pc(st.nr_pc_on_big, nr_big);
                let pc_lc_on_big = Self::get_pc(st.nr_lc_on_big, nr_big);
                let power_mode = Self::get_power_mode(bss_data.power_mode);
                let total_time = bss_data.performance_mode_ns
                    + bss_data.balanced_mode_ns
                    + bss_data.powersave_mode_ns;
                let pc_performance = Self::get_pc(bss_data.performance_mode_ns, total_time);
                let pc_balanced = Self::get_pc(bss_data.balanced_mode_ns, total_time);
                let pc_powersave = Self::get_pc(bss_data.powersave_mode_ns, total_time);

                StatsRes::SysStats(SysStats {
                    mseq,
                    nr_queued_task,
                    nr_active,
                    nr_sched,
                    nr_preempt,
                    pc_pc,
                    pc_lc,
                    pc_x_migration,
                    nr_stealee,
                    pc_big,
                    pc_pc_on_big,
                    pc_lc_on_big,
                    power_mode: power_mode.to_string(),
                    pc_performance,
                    pc_balanced,
                    pc_powersave,
                })
            }
            StatsReq::SchedSamplesNr {
                tid,
                nr_samples,
                interval_ms,
            } => {
                if Some(*tid) != self.monitor_tid {
                    return Ok(StatsRes::Bye);
                }

                self.intrspc.cmd = LAVD_CMD_SCHED_N;
                self.intrspc.arg = *nr_samples;
                self.prep_introspec();
                std::thread::sleep(Duration::from_millis(*interval_ms));
                self.rb_mgr.poll(Duration::from_millis(100)).unwrap();

                let mut samples = vec![];
                while let Ok(ts) = self.intrspc_rx.try_recv() {
                    samples.push(ts);
                }

                self.cleanup_introspec();

                StatsRes::SchedSamples(SchedSamples { samples })
            }
        })
    }

    fn stop_monitoring(&mut self) {
        if self.skel.maps.bss_data.as_ref().unwrap().is_monitored {
            self.skel.maps.bss_data.as_mut().unwrap().is_monitored = false;
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn set_power_profile(&mut self, mode: u32) -> Result<(), u32> {
        let prog = &mut self.skel.progs.set_power_profile;
        let mut args = power_arg {
            power_mode: mode as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn update_power_profile(&mut self, prev_profile: PowerProfile) -> (bool, PowerProfile) {
        let profile = fetch_power_profile(false);
        if profile == prev_profile {
            // If the profile is the same, skip updaring the profile for BPF.
            return (true, profile);
        }

        let _ = match profile {
            PowerProfile::Performance => self.set_power_profile(LAVD_PM_PERFORMANCE),
            PowerProfile::Balanced { .. } => self.set_power_profile(LAVD_PM_BALANCED),
            PowerProfile::Powersave => self.set_power_profile(LAVD_PM_POWERSAVE),
            PowerProfile::Unknown => {
                // We don't know how to handle an unknown energy profile,
                // so we just give up updating the profile from now on.
                return (false, profile);
            }
        };

        info!("Set the scheduler's power profile to {profile} mode.");
        (true, profile)
    }

    fn run(&mut self, opts: &Opts, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let mut autopower = opts.autopower;
        let mut profile = PowerProfile::Unknown;

        if opts.performance {
            let _ = self.set_power_profile(LAVD_PM_PERFORMANCE);
        } else if opts.powersave {
            let _ = self.set_power_profile(LAVD_PM_POWERSAVE);
        } else {
            let _ = self.set_power_profile(LAVD_PM_BALANCED);
        }

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if autopower {
                (autopower, profile) = self.update_power_profile(profile);
            }

            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(req) => {
                    let res = self.stats_req_to_res(&req)?;
                    res_ch.send(res)?;
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.stop_monitoring();
                }
                Err(e) => {
                    self.stop_monitoring();
                    Err(e)?
                }
            }
            self.cleanup_introspec();
        }
        self.rb_mgr.consume().unwrap();

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");

        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn init_log(opts: &Opts) {
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| match EnvFilter::try_new(&opts.log_level) {
            Ok(filter) => Ok(filter),
            Err(e) => {
                eprintln!(
                    "invalid log envvar: {}, using info, err is: {}",
                    opts.log_level, e
                );
                EnvFilter::try_new("info")
            }
        })
        .unwrap_or_else(|_| EnvFilter::new("info"));

    match tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .try_init()
    {
        Ok(()) => {}
        Err(e) => eprintln!("failed to init logger: {}", e),
    }
}

#[clap_main::clap_main]
fn main(mut opts: Opts) -> Result<()> {
    if opts.version {
        println!(
            "scx_lavd {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        let sys_stats_meta_name = SysStats::meta().name;
        let sched_sample_meta_name = SchedSample::meta().name;
        let stats_meta_names: &[&str] = &[
            sys_stats_meta_name.as_str(),
            sched_sample_meta_name.as_str(),
        ];
        stats::server_data(0).describe_meta(&mut std::io::stdout(), Some(&stats_meta_names))?;
        return Ok(());
    }

    init_log(&opts);

    if opts.verbose > 0 {
        warn!("Setting verbose via -v is deprecated and will be an error in future releases.");
    }

    if let Some(run_id) = opts.run_id {
        info!("scx_lavd run_id: {}", run_id);
    }

    if opts.monitor.is_none() && opts.monitor_sched_samples.is_none() {
        opts.proc().unwrap();
        info!("{:#?}", opts);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(nr_samples) = opts.monitor_sched_samples {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            stats::monitor_sched_samples(nr_samples, shutdown_copy).unwrap()
        });
        let _ = jh.join();
        return Ok(());
    }

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            stats::monitor(Duration::from_secs_f64(intv), shutdown_copy).unwrap()
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        info!(
            "scx_lavd scheduler is initialized (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        info!("scx_lavd scheduler starts running.");
        if !sched.run(&opts, shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
