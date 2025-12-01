// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
pub mod bpf_intf;
pub mod bpf_skel;
pub mod energy;
pub use bpf_skel::types;

use scx_utils::cli::TopologyArgs;
pub use scx_utils::CoreType;
use scx_utils::Topology;
pub use scx_utils::NR_CPU_IDS;
use tracing::info;

use clap::Parser;
use clap::ValueEnum;

lazy_static::lazy_static! {
        pub static ref TOPO: Topology = Topology::new().unwrap();
}

fn get_default_greedy_disable() -> bool {
    TOPO.all_llcs.len() > 1
}

fn get_default_llc_runs() -> u64 {
    let n_llcs = TOPO.all_llcs.len() as f64;
    let llc_runs = n_llcs.log2();
    llc_runs as u64
}

fn get_default_llc_shards() -> u32 {
    let max_cpus_per_llc = TOPO
        .all_llcs
        .values()
        .map(|l| l.all_cpus.len() as u32)
        .max()
        .unwrap_or(1);
    if max_cpus_per_llc <= 4 {
        return 0;
    }
    max_cpus_per_llc / 4
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LbMode {
    /// load of the LLC
    Load,
    /// number of tasks queued
    NrQueued,
}

impl LbMode {
    pub fn as_i32(&self) -> i32 {
        match self {
            LbMode::Load => bpf_intf::p2dq_lb_mode_PICK2_LOAD as i32,
            LbMode::NrQueued => bpf_intf::p2dq_lb_mode_PICK2_NR_QUEUED as i32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum SchedMode {
    /// Default mode for most workloads.
    Default,
    /// Performance mode prioritizes scheduling on Big cores.
    Performance,
    /// Efficiency mode prioritizes scheduling on little cores.
    Efficiency,
}

impl SchedMode {
    pub fn as_i32(&self) -> i32 {
        match self {
            SchedMode::Default => bpf_intf::scheduler_mode_MODE_DEFAULT as i32,
            SchedMode::Performance => bpf_intf::scheduler_mode_MODE_PERF as i32,
            SchedMode::Efficiency => bpf_intf::scheduler_mode_MODE_EFFICIENCY as i32,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HardwareProfile {
    pub single_llc: bool,
    pub core_count: usize,
    pub is_arm64: bool,
    pub is_neoverse_v2: bool,
}

impl HardwareProfile {
    pub fn detect() -> Self {
        let single_llc = TOPO.all_llcs.len() == 1;
        let core_count = TOPO.all_cpus.len();

        let is_arm64 = cfg!(target_arch = "aarch64");
        let is_neoverse_v2 = is_arm64 && Self::detect_neoverse_v2();

        Self {
            single_llc,
            core_count,
            is_arm64,
            is_neoverse_v2,
        }
    }

    fn detect_neoverse_v2() -> bool {
        // Read /proc/cpuinfo to detect Neoverse-V2
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            cpuinfo.contains("Neoverse-V2")
        } else {
            false
        }
    }

    pub fn optimize_scheduler_opts(&self, opts: &mut SchedulerOpts) {
        if self.single_llc {
            // Disable pick2 dispatch since there's only one LLC
            opts.dispatch_pick2_disable = true;
            // Disable wakeup LLC migrations
            opts.wakeup_llc_migrations = false;
            // For single LLC, set min_llc_runs_pick2 to 0 (effectively disable)
            opts.min_llc_runs_pick2 = 0;
            info!("Single LLC detected - disabling multi-LLC optimizations");
        }

        if self.is_neoverse_v2 && self.single_llc && self.core_count >= 64 {
            // Optimize shard count for large single-LLC systems
            let optimal_shards = (self.core_count / 8).min(16) as u32;
            if opts.llc_shards == get_default_llc_shards() {
                opts.llc_shards = optimal_shards;
                info!(
                    "Large single-LLC system ({} cores) - using {} shards",
                    self.core_count, opts.llc_shards
                );
            }
        }

        if self.is_neoverse_v2 {
            info!("ARM64 Neoverse-V2 detected - ARM-specific optimizations available");
        }
    }
}

#[derive(Debug, Clone, Parser)]
pub struct SchedulerOpts {
    /// Disables per-cpu kthreads directly dispatched into local dsqs.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    pub disable_kthreads_local: bool,

    /// Enables autoslice tuning
    #[clap(short = 'a', long, action = clap::ArgAction::SetTrue)]
    pub autoslice: bool,

    /// Ratio of interactive tasks for autoslice tuning, percent value from 1-99.
    #[clap(short = 'r', long, default_value = "10")]
    pub interactive_ratio: usize,

    /// Enables deadline scheduling
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub deadline: bool,

    /// ***DEPRECATED*** Disables eager pick2 load balancing.
    #[clap(short = 'e', long, help="DEPRECATED", action = clap::ArgAction::SetTrue)]
    pub eager_load_balance: bool,

    /// Enables CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    pub freq_control: bool,

    /// ***DEPRECATED*** Disables greedy idle CPU selection, may cause better load balancing on
    /// multi-LLC systems.
    #[clap(short = 'g', long, default_value_t = get_default_greedy_disable(), action = clap::ArgAction::Set)]
    pub greedy_idle_disable: bool,

    /// Interactive tasks stay sticky to their CPU if no idle CPU is found.
    #[clap(short = 'y', long, action = clap::ArgAction::SetTrue)]
    pub interactive_sticky: bool,

    /// ***DEPRECATED*** Interactive tasks are FIFO scheduled
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub interactive_fifo: bool,

    /// Disables pick2 load balancing on the dispatch path.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    pub dispatch_pick2_disable: bool,

    /// Enables pick2 load balancing on the dispatch path when LLC utilization is under the
    /// specified utilization.
    #[clap(long, default_value = "75", value_parser = clap::value_parser!(u64).range(0..100))]
    pub dispatch_lb_busy: u64,

    /// Enables pick2 load balancing on the dispatch path for interactive tasks.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub dispatch_lb_interactive: bool,

    /// Enable tasks to run beyond their timeslice if the CPU is idle.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub keep_running: bool,

    /// Use a arena based queues (ATQ) for task queueing.
    #[clap(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub atq_enabled: bool,

    /// Use a double helix queue (DHQ) for LLC migration. DHQ provides two-strand
    /// queue structure for cache-aware task migration between LLCs.
    #[clap(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub dhq_enabled: bool,

    /// Maximum imbalance allowed between DHQ strands. Controls how far one strand
    /// can dequeue ahead of the other. Lower values maintain tighter balance,
    /// higher values allow more asymmetric cross-LLC migration (0 = unlimited).
    #[clap(long, default_value = "3", value_parser = clap::value_parser!(u64).range(0..=100))]
    pub dhq_max_imbalance: u64,

    /// Schedule based on preferred core values available on some x86 systems with the appropriate
    /// CPU frequency governor (ex: amd-pstate).
    #[clap(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub cpu_priority: bool,

    /// ***DEPRECATED*** Use a separate DSQ for interactive tasks
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub interactive_dsq: bool,

    /// *DEPRECATED* Minimum load for load balancing on the wakeup path, 0 to disable.
    #[clap(long, default_value = "0", help="DEPRECATED", value_parser = clap::value_parser!(u64).range(0..99))]
    pub wakeup_lb_busy: u64,

    /// Allow LLC migrations on the wakeup path.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub wakeup_llc_migrations: bool,

    /// Enable fork-time load balancing across LLCs. New child processes are
    /// placed on less loaded LLCs when the parent's LLC is overloaded.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub fork_balance: bool,

    /// Enable exec-time load balancing across LLCs. Tasks transitioning from
    /// fork to exec are migrated to less loaded LLCs if beneficial.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub exec_balance: bool,

    /// **DEPRECATED*** Allow selecting idle in enqueue path.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub select_idle_in_enqueue: bool,

    /// Allow queued wakeup.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub queued_wakeup: bool,

    /// Set idle QoS resume latency based in microseconds.
    #[clap(long)]
    pub idle_resume_us: Option<u32>,

    /// Only pick2 load balance from the max DSQ.
    #[clap(long, default_value="false", action = clap::ArgAction::Set)]
    pub max_dsq_pick2: bool,

    /// Task slice tracking, slices are automatically scaled based on utilization rather than the
    /// predetermined slice index.
    #[clap(long, default_value="false", action = clap::ArgAction::Set)]
    pub task_slice: bool,

    /// Scheduling min slice duration in microseconds.
    #[clap(short = 's', long, default_value = "100")]
    pub min_slice_us: u64,

    /// ***DEPRECATED*** Load balance mode
    #[arg(value_enum, long, default_value_t = LbMode::Load)]
    pub lb_mode: LbMode,

    /// Scheduler mode
    #[arg(value_enum, long, default_value_t = SchedMode::Default)]
    pub sched_mode: SchedMode,

    /// Slack factor for load balancing, load balancing is not performed if load is within slack
    /// factor percent.
    #[clap(long, default_value = "5", value_parser = clap::value_parser!(u64).range(0..99))]
    pub lb_slack_factor: u64,

    /// Number of runs on the LLC before a task becomes eligbile for pick2 migration on the wakeup
    /// path.
    #[clap(short = 'l', long, default_value_t = get_default_llc_runs())]
    pub min_llc_runs_pick2: u64,

    /// Saturated percent is the percent at which the system is considered saturated in terms of
    /// free CPUs.
    #[clap(long, default_value_t = 5)]
    pub saturated_percent: u32,

    /// Manual definition of slice intervals in microseconds for DSQs, must be equal to number of
    /// dumb_queues.
    #[clap(short = 't', long, value_parser = clap::value_parser!(u64), default_values_t = [500, 2500, 5000])]
    pub dsq_time_slices: Vec<u64>,

    /// DSQ scaling shift, each queue min timeslice is shifted by the scaling shift.
    #[clap(short = 'x', long, default_value = "4")]
    pub dsq_shift: u64,

    /// Number of shards for LLC DSQ sharding. Default 0 means use single DSQ per LLC.
    #[clap(long, default_value_t = get_default_llc_shards())]
    pub llc_shards: u32,

    /// Minimum number of queued tasks to use pick2 balancing, 0 to always enabled.
    #[clap(short = 'm', long, default_value = "0")]
    pub min_nr_queued_pick2: u64,

    /// Number of dumb DSQs.
    #[clap(short = 'q', long, default_value = "3")]
    pub dumb_queues: usize,

    /// Initial DSQ for tasks.
    #[clap(short = 'i', long, default_value = "0")]
    pub init_dsq_index: usize,

    /// Use a arena based queues (ATQ) for task queueing.
    #[clap(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub virt_llc_enabled: bool,

    /// Enable hardware-specific optimizations automatically
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub hw_auto_optimize: bool,

    /// Force single-LLC fast path optimizations
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub single_llc_fast_path: bool,

    /// Enable PELT (Per-Entity Load Tracking) for improved load balancing.
    /// PELT uses exponential decay to provide more accurate CPU utilization
    /// tracking than simple counters. This may improve load balancing decisions
    /// but adds computational overhead.
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub enable_pelt: bool,

    /// Enable latency priority system (uses task nice value)
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub latency_priority: bool,

    /// Enable wakeup preemption for latency-critical tasks
    #[clap(long, action = clap::ArgAction::SetTrue)]
    pub wakeup_preemption: bool,

    /// Enable Energy-Aware Scheduling (EAS) for big.LITTLE CPUs.
    /// Places low-utilization tasks on efficient cores and high-utilization
    /// tasks on performance cores. Requires PELT to be enabled. Improves
    /// battery life on heterogeneous systems.
    #[clap(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub enable_eas: bool,

    #[clap(flatten, next_help_heading = "Topology Options")]
    pub topo: TopologyArgs,
}

pub fn dsq_slice_ns(dsq_index: u64, min_slice_us: u64, dsq_shift: u64) -> u64 {
    if dsq_index == 0 {
        1000 * min_slice_us
    } else {
        1000 * (min_slice_us << (dsq_index as u32) << dsq_shift)
    }
}

#[macro_export]
macro_rules! init_open_skel {
    ($skel: expr, $topo: expr, $opts: expr, $verbose: expr, $hw_profile: expr) => {
        'block: {
            let skel = &mut *$skel;
            let opts: &$crate::SchedulerOpts = $opts;
            let verbose: u8 = $verbose;
            let hw_profile: &$crate::HardwareProfile = $hw_profile;

            if opts.init_dsq_index > opts.dumb_queues - 1 {
                break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                    "Invalid init_dsq_index {}",
                    opts.init_dsq_index
                ));
            }
            if opts.dsq_time_slices.len() > 0 {
                if opts.dsq_time_slices.len() != opts.dumb_queues {
                    break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                        "Invalid number of dsq_time_slices, got {} need {}",
                        opts.dsq_time_slices.len(),
                        opts.dumb_queues,
                    ));
                }
                for vals in opts.dsq_time_slices.windows(2) {
                    if vals[0] >= vals[1] {
                        break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                            "DSQ time slices must be in increasing order"
                        ));
                    }
                }
                for (i, slice) in opts.dsq_time_slices.iter().enumerate() {
                    info!("DSQ[{}] slice_ns {}", i, slice * 1000);
                    skel.maps.bss_data.as_mut().unwrap().dsq_time_slices[i] = slice * 1000;
                }
            } else {
                for i in 0..=opts.dumb_queues - 1 {
                    let slice_ns =
                        $crate::dsq_slice_ns(i as u64, opts.min_slice_us, opts.dsq_shift);
                    info!("DSQ[{}] slice_ns {}", i, slice_ns);
                    skel.maps.bss_data.as_mut().unwrap().dsq_time_slices[i] = slice_ns;
                }
            }
            if opts.autoslice {
                if opts.interactive_ratio == 0 || opts.interactive_ratio > 99 {
                    break 'block ::anyhow::Result::Err(::anyhow::anyhow!(
                        "Invalid interactive_ratio {}, must be between 1-99",
                        opts.interactive_ratio
                    ));
                }
            }

            // topo config
            let rodata = skel.maps.rodata_data.as_mut().unwrap();
            rodata.topo_config.nr_cpus = *$crate::NR_CPU_IDS as u32;
            rodata.topo_config.nr_llcs = $topo.all_llcs.clone().keys().len() as u32;
            rodata.topo_config.nr_nodes = $topo.nodes.clone().keys().len() as u32;
            rodata.topo_config.smt_enabled = MaybeUninit::new($topo.smt_enabled);
            rodata.topo_config.has_little_cores = MaybeUninit::new($topo.has_little_cores());

            // timeline config
            rodata.timeline_config.min_slice_us = opts.min_slice_us;
            rodata.timeline_config.max_exec_ns =
                2 * skel.maps.bss_data.as_ref().unwrap().dsq_time_slices[opts.dumb_queues - 1];
            rodata.timeline_config.autoslice = MaybeUninit::new(opts.autoslice);
            rodata.timeline_config.deadline = MaybeUninit::new(opts.deadline);

            // load balance config
            rodata.lb_config.slack_factor = opts.lb_slack_factor;
            rodata.lb_config.min_nr_queued_pick2 = opts.min_nr_queued_pick2;
            rodata.lb_config.min_llc_runs_pick2 = opts.min_llc_runs_pick2;
            rodata.lb_config.max_dsq_pick2 = MaybeUninit::new(opts.max_dsq_pick2);
            rodata.lb_config.eager_load_balance = MaybeUninit::new(!opts.eager_load_balance);
            rodata.lb_config.dispatch_pick2_disable = MaybeUninit::new(opts.dispatch_pick2_disable);
            rodata.lb_config.dispatch_lb_busy = opts.dispatch_lb_busy;
            rodata.lb_config.dispatch_lb_interactive =
                MaybeUninit::new(opts.dispatch_lb_interactive);
            rodata.lb_config.wakeup_lb_busy = opts.wakeup_lb_busy;
            rodata.lb_config.wakeup_llc_migrations = MaybeUninit::new(opts.wakeup_llc_migrations);
            rodata.lb_config.single_llc_mode = MaybeUninit::new(
                opts.single_llc_fast_path || (opts.hw_auto_optimize && hw_profile.single_llc),
            );

            // p2dq config
            rodata.p2dq_config.interactive_ratio = opts.interactive_ratio as u32;
            rodata.p2dq_config.dsq_shift = opts.dsq_shift as u64;
            rodata.p2dq_config.task_slice = MaybeUninit::new(opts.task_slice);
            rodata.p2dq_config.kthreads_local = MaybeUninit::new(!opts.disable_kthreads_local);
            rodata.p2dq_config.nr_dsqs_per_llc = opts.dumb_queues as u32;
            rodata.p2dq_config.init_dsq_index = opts.init_dsq_index as i32;
            rodata.p2dq_config.saturated_percent = opts.saturated_percent;
            rodata.p2dq_config.sched_mode = opts.sched_mode.clone() as u32;
            rodata.p2dq_config.llc_shards = opts.llc_shards.max(1);

            rodata.p2dq_config.atq_enabled = MaybeUninit::new(
                opts.atq_enabled && compat::ksym_exists("bpf_spin_unlock").unwrap_or(false),
            );

            rodata.p2dq_config.dhq_enabled = MaybeUninit::new(
                opts.dhq_enabled && compat::ksym_exists("bpf_spin_unlock").unwrap_or(false),
            );

            rodata.p2dq_config.dhq_max_imbalance = opts.dhq_max_imbalance;

            // Check if cpu_priority is supported by the kernel
            let cpu_priority_supported = compat::ksym_exists("sched_core_priority").unwrap_or(false);
            if opts.cpu_priority && !cpu_priority_supported {
                warn!("CPU priority scheduling requested but kernel doesn't support sched_core_priority");
                warn!("Feature disabled - requires kernel with hybrid CPU support and appropriate CPU governor (e.g., amd-pstate)");
                warn!("See README for kernel requirements");
            }
            rodata.p2dq_config.cpu_priority = MaybeUninit::new(opts.cpu_priority && cpu_priority_supported);
            rodata.p2dq_config.freq_control = MaybeUninit::new(opts.freq_control);
            rodata.p2dq_config.interactive_sticky = MaybeUninit::new(opts.interactive_sticky);
            rodata.p2dq_config.keep_running_enabled = MaybeUninit::new(opts.keep_running);
            rodata.p2dq_config.pelt_enabled = MaybeUninit::new(opts.enable_pelt);
            rodata.p2dq_config.fork_balance = MaybeUninit::new(opts.fork_balance);
            rodata.p2dq_config.exec_balance = MaybeUninit::new(opts.exec_balance);
            rodata.p2dq_config.enable_eas = MaybeUninit::new(opts.enable_eas);
            rodata.p2dq_config.small_task_threshold = 256;  // 25% utilization
            rodata.p2dq_config.large_task_threshold = 768;  // 75% utilization

            // Latency priority config
            rodata.latency_config.latency_priority_enabled = MaybeUninit::new(opts.latency_priority);
            rodata.latency_config.wakeup_preemption_enabled = MaybeUninit::new(opts.wakeup_preemption);

            rodata.debug = verbose as u32;
            rodata.nr_cpu_ids = *NR_CPU_IDS as u32;

            Ok(())
        }
    };
}

#[macro_export]
macro_rules! init_skel {
    ($skel: expr, $topo: expr) => {{
        use $crate::energy::EnergyModel;

        // Initialize energy model for EAS
        let energy_model = EnergyModel::new(&$topo).unwrap_or_else(|e| {
            eprintln!("Warning: Failed to create energy model: {}", e);
            eprintln!("Energy-aware scheduling will use fallback values");
            EnergyModel::new(&$topo).unwrap() // This should not fail
        });

        for cpu in $topo.all_cpus.values() {
            $skel.maps.bss_data.as_mut().unwrap().big_core_ids[cpu.id] =
                if cpu.core_type == ($crate::CoreType::Big { turbo: true }) {
                    1
                } else {
                    0
                };
            $skel.maps.bss_data.as_mut().unwrap().cpu_core_ids[cpu.id] = cpu.core_id as u32;
            $skel.maps.bss_data.as_mut().unwrap().cpu_llc_ids[cpu.id] = cpu.llc_id as u64;
            $skel.maps.bss_data.as_mut().unwrap().cpu_node_ids[cpu.id] = cpu.node_id as u64;

            // Populate energy model data
            $skel.maps.bss_data.as_mut().unwrap().cpu_capacity[cpu.id] =
                energy_model.cpu_capacity(cpu.id) as u16;
            $skel.maps.bss_data.as_mut().unwrap().cpu_energy_cost[cpu.id] =
                energy_model.cpu_energy_cost(cpu.id) as u16;
        }
        for llc in $topo.all_llcs.values() {
            $skel.maps.bss_data.as_mut().unwrap().llc_ids[llc.id] = llc.id as u64;
        }
    }};
}
