// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod cell_manager;
mod mitosis_topology_utils;
mod stats;

use cell_manager::{CellManager, CpuAssignment};

use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Display;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::eventfd::EventFd;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPUS_POSSIBLE;
use tracing::{debug, info, trace, warn};
use tracing_subscriber::filter::EnvFilter;

use stats::CellMetrics;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_mitosis";
const MAX_CELLS: usize = bpf_intf::consts_MAX_CELLS as usize;
const NR_CSTATS: usize = bpf_intf::cell_stat_idx_NR_CSTATS as usize;

/// Epoll token for inotify events (cgroup creation/destruction)
const INOTIFY_TOKEN: u64 = 1;
/// Epoll token for stats request wakeups
const STATS_TOKEN: u64 = 2;

fn parse_ewma_factor(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|e| format!("{e}"))?;
    if !(0.0..=1.0).contains(&v) {
        return Err(format!("value {v} not in range 0.0..=1.0"));
    }
    Ok(v)
}

/// scx_mitosis: A dynamic affinity scheduler
///
/// Cgroups are assigned to a dynamic number of Cells which are assigned to a
/// dynamic set of CPUs. The BPF part does simple vtime scheduling for each cell.
///
/// Userspace makes the dynamic decisions of which Cells should be merged or
/// split and which CPUs they should be assigned to.
#[derive(Debug, Parser)]
struct Opts {
    /// Deprecated, noop, use RUST_LOG or --log-level instead.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Specify the logging level. Accepts rust's envfilter syntax for modular
    /// logging: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax. Examples: ["info", "warn,tokio=info"]
    #[clap(long, default_value = "info")]
    log_level: String,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Interval to consider reconfiguring the Cells (e.g. merge or split)
    #[clap(long, default_value = "10")]
    reconfiguration_interval_s: u64,

    /// Interval to consider rebalancing CPUs to Cells
    #[clap(long, default_value = "5")]
    rebalance_cpus_interval_s: u64,

    /// Interval to report monitoring information
    #[clap(long, default_value = "1")]
    monitor_interval_s: u64,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Optional run ID for tracking scheduler instances.
    #[clap(long)]
    run_id: Option<u64>,

    /// Enable debug event tracking for cgroup_init, init_task, and cgroup_exit.
    /// Events are recorded in a ring buffer and output in dump().
    #[clap(long, action = clap::ArgAction::SetTrue)]
    debug_events: bool,

    /// Enable workaround for exiting tasks with offline cgroups during scheduler load.
    /// This works around a kernel bug where tasks can be initialized with cgroups that
    /// were never initialized. Disable this once the kernel bug is fixed.
    #[clap(long, default_value = "true", action = clap::ArgAction::Set)]
    exiting_task_workaround: bool,

    /// Disable SCX cgroup callbacks (for when CPU cgroup controller is disabled).
    /// Uses tracepoints and cgroup iteration instead.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    cpu_controller_disabled: bool,

    /// Reject tasks with multi-CPU pinning that doesn't cover the entire cell.
    /// By default, these tasks are allowed but may have degraded performance.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    reject_multicpu_pinning: bool,

    /// Enable LLC-awareness. This will populate the scheduler's LLC maps and cause it
    /// to use LLC-aware scheduling.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_llc_awareness: bool,

    /// Enable work stealing. This is only relevant when LLC-awareness is enabled.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_work_stealing: bool,

    /// Parent cgroup path whose direct children become cells.
    /// When specified, cells are created for each direct child cgroup of this parent,
    /// with CPUs divided equally among cells. Example: --cell-parent-cgroup /workloads
    #[clap(long)]
    cell_parent_cgroup: Option<String>,

    /// Exact directory name of a direct child cgroup to exclude from cell creation
    /// (excluded cgroups remain in cell 0). Matched against the directory basename,
    /// not the full path. Can be specified multiple times. Requires --cell-parent-cgroup.
    /// Example: --cell-exclude systemd-workaround.service
    #[clap(long)]
    cell_exclude: Vec<String>,

    /// Enable CPU borrowing: cells can use idle CPUs from other cells.
    /// Only meaningful with --cell-parent-cgroup and multiple cells.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_borrowing: bool,

    /// Enable demand-based CPU rebalancing between cells.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    enable_rebalancing: bool,

    /// Utilization spread (max - min) that triggers rebalancing (default: 20%)
    #[clap(long, default_value = "20.0")]
    rebalance_threshold: f64,

    /// Minimum seconds between rebalancing events (default: 5)
    #[clap(long, default_value = "5")]
    rebalance_cooldown_s: u64,

    /// EWMA smoothing factor for demand tracking. Higher = more responsive (default: 0.3)
    #[clap(long, default_value = "0.3", value_parser = parse_ewma_factor)]
    demand_smoothing: f64,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

// The subset of cstats we care about.
// Local + Default + Hi + Lo = Total Decisions
// Affinity violations are not queue decisions, but
// will be calculated separately and reported as a percent of the total
const QUEUE_STATS_IDX: [bpf_intf::cell_stat_idx; 4] = [
    bpf_intf::cell_stat_idx_CSTAT_LOCAL,
    bpf_intf::cell_stat_idx_CSTAT_CPU_DSQ,
    bpf_intf::cell_stat_idx_CSTAT_CELL_DSQ,
    bpf_intf::cell_stat_idx_CSTAT_BORROWED,
];

// Per cell book-keeping
#[derive(Debug)]
struct Cell {
    cpus: Cpumask,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    monitor_interval: Duration,
    cells: HashMap<u32, Cell>,
    // These are the per-cell cstats.
    // Note these are accumulated across all CPUs.
    prev_cell_stats: [[u64; NR_CSTATS]; MAX_CELLS],
    // Per-cell running_ns tracking for demand metrics
    prev_cell_running_ns: [u64; MAX_CELLS],
    prev_cell_own_ns: [u64; MAX_CELLS],
    prev_cell_lent_ns: [u64; MAX_CELLS],
    metrics: Metrics,
    stats_server: Option<StatsServer<(), Metrics>>,
    last_configuration_seq: Option<u32>,
    /// Last observed cpuset_seq for cpuset change detection
    last_cpuset_seq: u32,
    /// Optional cell manager for --cell-parent-cgroup mode
    cell_manager: Option<CellManager>,
    /// Whether CPU borrowing is enabled
    enable_borrowing: bool,
    /// Whether demand-based rebalancing is enabled
    enable_rebalancing: bool,
    /// Utilization spread threshold for triggering rebalancing
    rebalance_threshold: f64,
    /// Minimum duration between rebalancing events
    rebalance_cooldown: Duration,
    /// EWMA smoothing factor for demand tracking
    demand_smoothing: f64,
    /// EWMA-smoothed utilization per cell
    smoothed_util: [f64; MAX_CELLS],
    /// Last time rebalancing was performed
    last_rebalance: Instant,
    /// Number of rebalancing events
    rebalance_count: u64,
    /// Epoll instance for waiting on multiple fds (inotify, stats wakeup)
    epoll: Epoll,
    /// EventFd to wake up main loop when stats are requested
    stats_waker: EventFd,
}

struct DistributionStats {
    total_decisions: u64,
    share_of_decisions_pct: f64,
    local_q_pct: f64,
    cpu_q_pct: f64,
    cell_q_pct: f64,
    borrowed_pct: f64,
    affn_viol_pct: f64,
    steal_pct: f64,

    // for formatting
    global_queue_decisions: u64,
}

impl Display for DistributionStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This makes the output easier to read by improving column alignment. First, it guarantees that within a
        // given logging interval, the global and cell queueing decision counts print at the same width.
        // Second, it reduces variance in column width between logging intervals. 5 is simply a heuristic.
        const MIN_DECISIONS_WIDTH: usize = 5;
        let descisions_width = if self.global_queue_decisions > 0 {
            max(
                MIN_DECISIONS_WIDTH,
                (self.global_queue_decisions as f64).log10().ceil() as usize,
            )
        } else {
            MIN_DECISIONS_WIDTH
        };
        write!(
            f,
            "{:width$} {:5.1}% | Local:{:4.1}% From: CPU:{:4.1}% Cell:{:4.1}% Borrow:{:4.1}% | V:{:4.1}% S:{:4.1}%",
            self.total_decisions,
            self.share_of_decisions_pct,
            self.local_q_pct,
            self.cpu_q_pct,
            self.cell_q_pct,
            self.borrowed_pct,
            self.affn_viol_pct,
            self.steal_pct,
            width = descisions_width,
        )
    }
}

impl<'a> Scheduler<'a> {
    fn validate_args(opts: &Opts) -> Result<()> {
        if opts.enable_work_stealing && !opts.enable_llc_awareness {
            bail!("Work stealing requires LLC-aware mode (--enable-llc-awareness)");
        }

        Ok(())
    }

    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        Self::validate_args(opts)?;

        let topology = Topology::new()?;

        let nr_llc = topology.all_llcs.len().max(1);

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder
            .obj_builder
            .debug(opts.log_level.contains("trace"));
        init_libbpf_logging(None);
        info!(
            "Running scx_mitosis (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );

        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, mitosis, open_opts)?;

        skel.struct_ops.mitosis_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();

        rodata.slice_ns = scx_enums.SCX_SLICE_DFL;
        rodata.debug_events_enabled = opts.debug_events;
        rodata.exiting_task_workaround_enabled = opts.exiting_task_workaround;
        rodata.cpu_controller_disabled = opts.cpu_controller_disabled;

        rodata.nr_possible_cpus = *NR_CPUS_POSSIBLE as u32;
        for cpu in topology.all_cpus.keys() {
            rodata.all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }

        rodata.reject_multicpu_pinning = opts.reject_multicpu_pinning;

        // Set nr_llc in rodata
        rodata.nr_llc = nr_llc as u32;
        rodata.enable_llc_awareness = opts.enable_llc_awareness;
        rodata.enable_work_stealing = opts.enable_work_stealing;

        rodata.userspace_managed_cell_mode = opts.cell_parent_cgroup.is_some();

        rodata.enable_borrowing = opts.enable_borrowing;

        match *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP {
            0 => info!("Kernel does not support queued wakeup optimization."),
            v => skel.struct_ops.mitosis_mut().flags |= v,
        }

        // Populate LLC topology arrays before load (data section is only writable before load)
        mitosis_topology_utils::populate_topology_maps(
            &mut skel,
            mitosis_topology_utils::MapKind::CpuToLLC,
            None,
        )?;
        mitosis_topology_utils::populate_topology_maps(
            &mut skel,
            mitosis_topology_utils::MapKind::LLCToCpus,
            None,
        )?;

        let skel = scx_ops_load!(skel, mitosis, uei)?;

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        // Initialize CellManager if --cell-parent-cgroup is specified
        if !opts.cell_exclude.is_empty() && opts.cell_parent_cgroup.is_none() {
            bail!("--cell-exclude requires --cell-parent-cgroup");
        }
        let cell_manager = if let Some(ref parent_cgroup) = opts.cell_parent_cgroup {
            let exclude: HashSet<String> = opts.cell_exclude.iter().cloned().collect();
            Some(CellManager::new(
                parent_cgroup,
                MAX_CELLS as u32,
                topology.span.clone(),
                exclude,
            )?)
        } else {
            None
        };

        // Create epoll instance for event-driven main loop
        let epoll = Epoll::new(EpollCreateFlags::empty())?;

        // Create eventfd for stats wakeup (non-blocking, semaphore mode)
        let stats_waker = EventFd::from_value_and_flags(
            0,
            nix::sys::eventfd::EfdFlags::EFD_NONBLOCK | nix::sys::eventfd::EfdFlags::EFD_SEMAPHORE,
        )?;

        // Register stats_waker with epoll
        epoll.add(
            &stats_waker,
            EpollEvent::new(EpollFlags::EPOLLIN, STATS_TOKEN),
        )?;

        // Register inotify fd if cell_manager exists
        if let Some(ref cell_manager) = cell_manager {
            epoll.add(
                cell_manager,
                EpollEvent::new(EpollFlags::EPOLLIN, INOTIFY_TOKEN),
            )?;
        }

        Ok(Self {
            skel,
            monitor_interval: Duration::from_secs(opts.monitor_interval_s),
            cells: HashMap::new(),
            prev_cell_stats: [[0; NR_CSTATS]; MAX_CELLS],
            prev_cell_running_ns: [0; MAX_CELLS],
            prev_cell_own_ns: [0; MAX_CELLS],
            prev_cell_lent_ns: [0; MAX_CELLS],
            metrics: Metrics::default(),
            stats_server: Some(stats_server),
            last_configuration_seq: None,
            last_cpuset_seq: 0,
            cell_manager,
            enable_borrowing: opts.enable_borrowing,
            enable_rebalancing: opts.enable_rebalancing,
            rebalance_threshold: opts.rebalance_threshold,
            rebalance_cooldown: Duration::from_secs(opts.rebalance_cooldown_s),
            demand_smoothing: opts.demand_smoothing,
            smoothed_util: [0.0; MAX_CELLS],
            last_rebalance: Instant::now(),
            rebalance_count: 0,
            epoll,
            stats_waker,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let struct_ops = scx_ops_attach!(self.skel, mitosis)?;

        info!("Mitosis Scheduler Attached. Run `scx_mitosis --monitor` for metrics.");

        // Apply initial cell configuration if CellManager is active
        self.apply_initial_cells()?;

        let (res_ch, req_ch) = self.stats_server.as_ref().unwrap().channels();

        // Spawn thread to bridge stats requests to eventfd.
        // The thread exits when the channel closes (stats_server dropped).
        // Clone the eventfd so the thread owns its own handle to the same kernel object.
        let stats_waker_fd = self.stats_waker.as_fd().try_clone_to_owned()?;
        let stats_waker = unsafe { EventFd::from_owned_fd(stats_waker_fd) };
        let stats_bridge = std::thread::spawn(move || {
            while req_ch.recv().is_ok() {
                // Wake up main loop via eventfd
                let _ = stats_waker.write(1);
            }
        });

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            let mut events = [EpollEvent::empty(); 1];
            let timeout = EpollTimeout::try_from(self.monitor_interval).with_context(|| {
                format!(
                    "monitor_interval {:?} exceeds maximum epoll timeout",
                    self.monitor_interval,
                )
            })?;

            match self.epoll.wait(&mut events, timeout) {
                Ok(n) => {
                    for event in &events[..n] {
                        match event.data() {
                            INOTIFY_TOKEN => {
                                // Cgroup event - process immediately
                                self.process_cell_events()?;
                            }
                            STATS_TOKEN => {
                                // Stats request - drain eventfd and send metrics
                                let _ = self.stats_waker.read();
                                res_ch.send(self.get_metrics())?;
                            }
                            _ => {}
                        }
                    }
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }

            // Periodic work on every iteration
            self.refresh_bpf_cells()?;
            self.check_cpuset_changes()?;
            self.collect_metrics()?;

            if self.enable_rebalancing && self.cell_manager.is_some() {
                self.maybe_rebalance()?;
            }
        }

        drop(struct_ops);
        // Drop stats_server to close the channel, allowing stats_bridge to exit
        drop(self.stats_server.take());
        let _ = stats_bridge.join();
        info!("Unregister {SCHEDULER_NAME} scheduler");
        uei_report!(&self.skel, uei)
    }

    /// Apply initial cell assignments discovered at startup
    fn apply_initial_cells(&mut self) -> Result<()> {
        if self.cell_manager.is_none() {
            return Ok(());
        }

        let cpu_assignments = self.compute_and_apply_cell_config(&[])?;

        let cell_manager = self.cell_manager.as_ref().unwrap();
        info!(
            "Applied initial cell configuration: {}",
            cell_manager.format_cell_config(&cpu_assignments)
        );

        Ok(())
    }

    /// Process cell manager events (new/destroyed cgroups)
    fn process_cell_events(&mut self) -> Result<()> {
        let (num_new, num_destroyed, new_cell_ids, destroyed_cell_ids) = {
            let Some(ref mut cell_manager) = self.cell_manager else {
                return Ok(());
            };

            let (new_cells, destroyed_cells) = cell_manager.process_events()?;

            if new_cells.is_empty() && destroyed_cells.is_empty() {
                return Ok(());
            }

            let new_ids: Vec<u32> = new_cells.iter().map(|(_, cell_id)| *cell_id).collect();
            (
                new_cells.len(),
                destroyed_cells.len(),
                new_ids,
                destroyed_cells,
            )
        };

        // Clear smoothed_util for destroyed cells so stale data doesn't
        // leak if the cell ID is reused later.
        for &cell_id in &destroyed_cell_ids {
            self.smoothed_util[cell_id as usize] = 0.0;
        }

        let cpu_assignments = self.compute_and_apply_cell_config(&new_cell_ids)?;

        let cell_manager = self.cell_manager.as_ref().unwrap();
        info!(
            "Cell config updated ({} new, {} destroyed): {}",
            num_new,
            num_destroyed,
            cell_manager.format_cell_config(&cpu_assignments)
        );

        Ok(())
    }

    /// Compute cell configuration from CellManager and apply it to BPF.
    ///
    /// When rebalancing is enabled and there is existing utilization data,
    /// uses demand-weighted CPU assignment instead of equal-weight. New cells
    /// (listed in `new_cell_ids`) are seeded to the average smoothed_util of
    /// existing cells so they start with a fair share rather than zero.
    ///
    /// Returns the CPU assignments for use with `format_cell_config`.
    fn compute_and_apply_cell_config(
        &mut self,
        new_cell_ids: &[u32],
    ) -> Result<Vec<CpuAssignment>> {
        let (cell_assignments, cpu_assignments) = {
            let cell_manager = self.cell_manager.as_ref().unwrap();
            let active_cell_ids: Vec<u32> = cell_manager
                .get_cell_assignments()
                .iter()
                .map(|(_, cell_id)| *cell_id)
                .collect();
            // Cell 0 is always active
            let all_cell_ids: Vec<u32> = std::iter::once(0)
                .chain(active_cell_ids.iter().copied())
                .collect();

            let cpu_assignments = if self.enable_rebalancing {
                // Check if any existing (non-new) cell has utilization data
                let new_set: HashSet<u32> = new_cell_ids.iter().copied().collect();
                let existing_utils: Vec<f64> = all_cell_ids
                    .iter()
                    .filter(|id| !new_set.contains(id))
                    .map(|&id| self.smoothed_util[id as usize])
                    .collect();

                let has_data = existing_utils.iter().any(|&u| u > 0.0);

                if has_data {
                    // Seed new cells to the average utilization of existing cells
                    let avg_util: f64 =
                        existing_utils.iter().sum::<f64>() / existing_utils.len().max(1) as f64;
                    for &id in new_cell_ids {
                        self.smoothed_util[id as usize] = avg_util;
                        info!(
                            "Seeded new cell {} smoothed_util to average {:.1}%",
                            id, avg_util
                        );
                    }

                    // Build demand map from smoothed_util for all active cells
                    let cell_demands: HashMap<u32, f64> = all_cell_ids
                        .iter()
                        .map(|&id| (id, self.smoothed_util[id as usize]))
                        .collect();

                    cell_manager
                        .compute_demand_cpu_assignments(&cell_demands, self.enable_borrowing)?
                } else {
                    // No utilization data yet (e.g., initial startup) — equal weight
                    cell_manager.compute_cpu_assignments(self.enable_borrowing)?
                }
            } else {
                cell_manager.compute_cpu_assignments(self.enable_borrowing)?
            };

            (cell_manager.get_cell_assignments(), cpu_assignments)
        };

        self.apply_cell_config(&cell_assignments, &cpu_assignments)?;

        Ok(cpu_assignments)
    }

    /// Check if rebalancing should be triggered and apply demand-weighted CPU assignments.
    fn maybe_rebalance(&mut self) -> Result<()> {
        // Check cooldown
        if self.last_rebalance.elapsed() < self.rebalance_cooldown {
            return Ok(());
        }

        // Compute min/max smoothed utilization across active cells
        let active_cells: Vec<u32> = self.cells.keys().copied().collect();
        if active_cells.len() < 2 {
            return Ok(());
        }

        let mut min_util = f64::MAX;
        let mut max_util = f64::MIN;
        for &cell_id in &active_cells {
            let util = self.smoothed_util[cell_id as usize];
            if util < min_util {
                min_util = util;
            }
            if util > max_util {
                max_util = util;
            }
        }

        let spread = max_util - min_util;
        if spread < self.rebalance_threshold {
            return Ok(());
        }

        // Build demand map from smoothed utilization
        let cell_demands: HashMap<u32, f64> = active_cells
            .iter()
            .map(|&cell_id| (cell_id, self.smoothed_util[cell_id as usize]))
            .collect();

        // Compute new assignments and check if they differ from current
        let (cell_assignments, cpu_assignments) = {
            let cell_manager = self.cell_manager.as_ref().unwrap();
            let cpu_assignments = cell_manager
                .compute_demand_cpu_assignments(&cell_demands, self.enable_borrowing)?;

            let changed = cpu_assignments.iter().any(|a| {
                self.cells
                    .get(&a.cell_id)
                    .map_or(true, |cell| cell.cpus != a.primary)
            });

            if !changed {
                return Ok(());
            }

            (cell_manager.get_cell_assignments(), cpu_assignments)
        };

        self.apply_cell_config(&cell_assignments, &cpu_assignments)?;

        self.last_rebalance = Instant::now();
        self.rebalance_count += 1;
        self.metrics.rebalance_count = self.rebalance_count;

        let cell_manager = self.cell_manager.as_ref().unwrap();
        info!(
            "Rebalanced CPUs (spread={:.1}%, count={}): {}",
            spread,
            self.rebalance_count,
            cell_manager.format_cell_config(&cpu_assignments)
        );

        Ok(())
    }

    /// Apply cell configuration to BPF.
    ///
    /// Writes the cell and CPU assignments to the BPF config struct and triggers
    /// the BPF program to apply the configuration.
    fn apply_cell_config(
        &mut self,
        cell_assignments: &[(u64, u32)],
        cpu_assignments: &[CpuAssignment],
    ) -> Result<()> {
        let bss_data = self
            .skel
            .maps
            .bss_data
            .as_mut()
            .expect("bss_data must be available after scheduler load");
        let config = &mut bss_data.cell_config;

        // Zero out the config struct. This is necessary because:
        // 1. Cell IDs can be sparse (e.g., cells 0, 2, 3 if cell 1 was destroyed)
        // 2. We only write cpumasks for active cells, leaving gaps unwritten
        // 3. BPF iterates 0..num_cells and applies each cpumask
        // 4. Without zeroing, a gap (e.g., cell 1) would have a stale cpumask,
        //    causing CPUs to be assigned to an unused cell
        // Safety: cell_config is a plain data struct with no Drop impl
        unsafe {
            std::ptr::write_bytes(
                config as *mut _ as *mut u8,
                0,
                std::mem::size_of_val(config),
            );
        }

        if cell_assignments.len() > bpf_intf::consts_MAX_CELLS as usize {
            bail!(
                "Too many cell assignments: {} > MAX_CELLS ({})",
                cell_assignments.len(),
                bpf_intf::consts_MAX_CELLS
            );
        }
        config.num_cell_assignments = cell_assignments.len() as u32;

        for (i, (cgid, cell_id)) in cell_assignments.iter().enumerate() {
            config.assignments[i].cgid = *cgid;
            config.assignments[i].cell_id = *cell_id;
        }

        // Set cell cpumasks and borrowable cpumasks
        let mut max_cell_id: u32 = 0;
        for a in cpu_assignments {
            if a.cell_id >= bpf_intf::consts_MAX_CELLS {
                bail!(
                    "Cell ID {} exceeds MAX_CELLS ({})",
                    a.cell_id,
                    bpf_intf::consts_MAX_CELLS
                );
            }
            max_cell_id = max_cell_id.max(a.cell_id + 1);

            write_cpumask_to_config(&a.primary, &mut config.cpumasks[a.cell_id as usize].mask);

            if let Some(ref borrowable) = a.borrowable {
                write_cpumask_to_config(
                    borrowable,
                    &mut config.borrowable_cpumasks[a.cell_id as usize].mask,
                );
            }
        }
        config.num_cells = max_cell_id;

        // Trigger the BPF program to apply the configuration
        let prog = &mut self.skel.progs.apply_cell_config;
        let out = prog
            .test_run(ProgramInput::default())
            .context("Failed to run apply_cell_config BPF program")?;
        if out.return_value != 0 {
            bail!(
                "apply_cell_config BPF program returned error {} (num_assignments={}, num_cells={})",
                out.return_value as i32,
                cell_assignments.len(),
                cpu_assignments.len()
            );
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        self.metrics.clone()
    }

    fn calculate_distribution_stats(
        &self,
        queue_counts: &[u64; QUEUE_STATS_IDX.len()],
        global_queue_decisions: u64,
        scope_queue_decisions: u64,
        scope_affn_viols: u64,
        scope_steals: u64,
    ) -> Result<DistributionStats> {
        // First % on the line: share of global work
        // We know global_queue_decisions is non-zero.
        let share_of_global =
            100.0 * (scope_queue_decisions as f64) / (global_queue_decisions as f64);

        // Each queue's % of the scope total
        let queue_pct = if scope_queue_decisions == 0 {
            debug!("No queue decisions in scope, zeroing out queue distribution");
            [0.0; QUEUE_STATS_IDX.len()]
        } else {
            core::array::from_fn(|i| {
                100.0 * (queue_counts[i] as f64) / (scope_queue_decisions as f64)
            })
        };

        // These are summed differently for the global and per-cell totals.
        let affinity_violations_percent = if scope_queue_decisions == 0 {
            debug!("No queue decisions in scope, zeroing out affinity violations");
            0.0
        } else {
            100.0 * (scope_affn_viols as f64) / (scope_queue_decisions as f64)
        };

        let steal_pct = if scope_queue_decisions == 0 {
            0.0
        } else {
            100.0 * (scope_steals as f64) / (scope_queue_decisions as f64)
        };

        const EXPECTED_QUEUES: usize = 4;
        if queue_pct.len() != EXPECTED_QUEUES {
            bail!(
                "Expected {} queues, got {}",
                EXPECTED_QUEUES,
                queue_pct.len()
            );
        }

        return Ok(DistributionStats {
            total_decisions: scope_queue_decisions,
            share_of_decisions_pct: share_of_global,
            local_q_pct: queue_pct[0],
            cpu_q_pct: queue_pct[1],
            cell_q_pct: queue_pct[2],
            borrowed_pct: queue_pct[3],
            affn_viol_pct: affinity_violations_percent,
            steal_pct,
            global_queue_decisions,
        });
    }

    // Queue stats for the whole node
    fn update_and_log_global_queue_stats(
        &mut self,
        global_queue_decisions: u64,
        cell_stats_delta: &[[u64; NR_CSTATS]; MAX_CELLS],
    ) -> Result<()> {
        // Get total of each queue summed over all cells
        let mut queue_counts = [0; QUEUE_STATS_IDX.len()];
        for cells in 0..MAX_CELLS {
            for (i, stat) in QUEUE_STATS_IDX.iter().enumerate() {
                queue_counts[i] += cell_stats_delta[cells][*stat as usize];
            }
        }

        let prefix = "Total Decisions:";

        // Here we want to sum the affinity violations over all cells.
        let scope_affn_viols: u64 = cell_stats_delta
            .iter()
            .map(|&cell| cell[bpf_intf::cell_stat_idx_CSTAT_AFFN_VIOL as usize])
            .sum::<u64>();

        // Sum steals over all cells
        let scope_steals: u64 = cell_stats_delta
            .iter()
            .map(|&cell| cell[bpf_intf::cell_stat_idx_CSTAT_STEAL as usize])
            .sum::<u64>();

        // Special case where the number of scope decisions == number global decisions
        let stats = self.calculate_distribution_stats(
            &queue_counts,
            global_queue_decisions,
            global_queue_decisions,
            scope_affn_viols,
            scope_steals,
        )?;

        self.metrics.update(&stats);

        trace!("{} {}", prefix, stats);

        Ok(())
    }

    // Print out the per-cell stats
    fn update_and_log_cell_queue_stats(
        &mut self,
        global_queue_decisions: u64,
        cell_stats_delta: &[[u64; NR_CSTATS]; MAX_CELLS],
    ) -> Result<()> {
        for cell in 0..MAX_CELLS {
            let cell_queue_decisions = QUEUE_STATS_IDX
                .iter()
                .map(|&stat| cell_stats_delta[cell][stat as usize])
                .sum::<u64>();

            // FIXME: This should really query if the cell is enabled or not.
            if cell_queue_decisions == 0 {
                continue;
            }

            let mut queue_counts = [0; QUEUE_STATS_IDX.len()];
            for (i, &stat) in QUEUE_STATS_IDX.iter().enumerate() {
                queue_counts[i] = cell_stats_delta[cell][stat as usize];
            }

            const MIN_CELL_WIDTH: usize = 2;
            let cell_width: usize = max(MIN_CELL_WIDTH, (MAX_CELLS as f64).log10().ceil() as usize);

            let prefix = format!("        Cell {:width$}:", cell, width = cell_width);

            // Sum affinity violations for this cell
            let scope_affn_viols: u64 =
                cell_stats_delta[cell][bpf_intf::cell_stat_idx_CSTAT_AFFN_VIOL as usize];

            // Steals for this cell
            let scope_steals: u64 =
                cell_stats_delta[cell][bpf_intf::cell_stat_idx_CSTAT_STEAL as usize];

            let stats = self.calculate_distribution_stats(
                &queue_counts,
                global_queue_decisions,
                cell_queue_decisions,
                scope_affn_viols,
                scope_steals,
            )?;

            self.metrics
                .cells
                .entry(cell as u32)
                .or_default()
                .update(&stats);

            trace!("{} {}", prefix, stats);
        }
        Ok(())
    }

    fn log_all_queue_stats(
        &mut self,
        cell_stats_delta: &[[u64; NR_CSTATS]; MAX_CELLS],
    ) -> Result<()> {
        // Get total decisions
        let global_queue_decisions: u64 = cell_stats_delta
            .iter()
            .flat_map(|cell| QUEUE_STATS_IDX.iter().map(|&idx| cell[idx as usize]))
            .sum();

        // We don't want to divide by zero later, but this is never expected.
        if global_queue_decisions == 0 {
            bail!("Error: No queueing decisions made globally");
        }

        self.update_and_log_global_queue_stats(global_queue_decisions, &cell_stats_delta)?;

        self.update_and_log_cell_queue_stats(global_queue_decisions, &cell_stats_delta)?;

        Ok(())
    }

    fn calculate_cell_stat_delta(
        &mut self,
        cpu_ctxs: &[bpf_intf::cpu_ctx],
    ) -> Result<[[u64; NR_CSTATS]; MAX_CELLS]> {
        let mut cell_stats_delta = [[0 as u64; NR_CSTATS]; MAX_CELLS];

        // Loop over cells and stats first, then CPU contexts
        // TODO: We should loop over the in_use cells only.
        for cell in 0..MAX_CELLS {
            for stat in 0..NR_CSTATS {
                let mut cur_cell_stat = 0;

                // Accumulate stats from all CPUs
                for cpu_ctx in cpu_ctxs.iter() {
                    cur_cell_stat += cpu_ctx.cstats[cell][stat];
                }

                // Calculate delta and update previous stat
                cell_stats_delta[cell][stat] = cur_cell_stat - self.prev_cell_stats[cell][stat];
                self.prev_cell_stats[cell][stat] = cur_cell_stat;
            }
        }
        Ok(cell_stats_delta)
    }

    /// Collect metrics and out various debugging data like per cell stats, per-cpu stats, etc.
    fn collect_metrics(&mut self) -> Result<()> {
        let cpu_ctxs = read_cpu_ctxs(&self.skel)?;

        let cell_stats_delta = self.calculate_cell_stat_delta(&cpu_ctxs)?;

        self.log_all_queue_stats(&cell_stats_delta)?;

        if self.cell_manager.is_some() {
            self.collect_demand_metrics(&cpu_ctxs)?;
        }

        for (cell_id, cell) in &self.cells {
            trace!("CELL[{}]: {}", cell_id, cell.cpus);
        }

        for (cell_id, cell) in self.cells.iter() {
            // Assume we have a CellMetrics entry if we have a known cell
            self.metrics
                .cells
                .entry(*cell_id)
                .and_modify(|cell_metrics| cell_metrics.num_cpus = cell.cpus.weight() as u32);
        }
        self.metrics.num_cells = self.cells.len() as u32;

        Ok(())
    }

    /// Compute per-cell demand metrics (utilization, borrowed, lent) from BPF running_ns counters.
    fn collect_demand_metrics(&mut self, cpu_ctxs: &[bpf_intf::cpu_ctx]) -> Result<()> {
        // Per-cell cumulative counters derived from BPF per-CPU running_ns:
        //   total_running_ns[c] = total time tasks in cell c ran (on any CPU)
        //   on_own_ns[c]        = time tasks in cell c ran on CPUs owned by cell c
        //   lent_ns[c]          = time foreign tasks ran on CPUs owned by cell c
        let mut total_running_ns = [0u64; MAX_CELLS];
        let mut on_own_ns = [0u64; MAX_CELLS];
        let mut lent_ns = [0u64; MAX_CELLS];

        for cpu_ctx in cpu_ctxs.iter() {
            let owner = cpu_ctx.cell as usize;
            for cell in 0..MAX_CELLS {
                let ns = cpu_ctx.running_ns[cell];
                total_running_ns[cell] += ns;
                if owner == cell {
                    on_own_ns[cell] += ns;
                }
            }
            if owner >= MAX_CELLS {
                bail!(
                    "CPU has invalid cell assignment {} (MAX_CELLS={})",
                    owner,
                    MAX_CELLS
                );
            }
            // Lent time: non-owner cell tasks running on this CPU
            let total_on_cpu: u64 = cpu_ctx.running_ns.iter().sum();
            let owner_on_cpu = cpu_ctx.running_ns[owner];
            lent_ns[owner] += total_on_cpu - owner_on_cpu;
        }

        // Compute deltas since last collection interval
        let interval_ns = self.monitor_interval.as_nanos() as u64;

        let mut global_running_delta = 0u64;
        let mut global_borrowed_delta = 0u64;
        let mut global_lent_delta = 0u64;
        let mut global_capacity = 0u64;

        for cell in 0..MAX_CELLS {
            let delta_running =
                total_running_ns[cell].wrapping_sub(self.prev_cell_running_ns[cell]);
            let delta_on_own = on_own_ns[cell].wrapping_sub(self.prev_cell_own_ns[cell]);
            let delta_lent = lent_ns[cell].wrapping_sub(self.prev_cell_lent_ns[cell]);

            self.prev_cell_running_ns[cell] = total_running_ns[cell];
            self.prev_cell_own_ns[cell] = on_own_ns[cell];
            self.prev_cell_lent_ns[cell] = lent_ns[cell];

            if delta_running == 0 && delta_lent == 0 {
                continue;
            }

            // Borrowed = ran somewhere other than own CPUs
            let delta_borrowed = delta_running.saturating_sub(delta_on_own);

            // After a cell is destroyed, BPF may still report residual
            // running_ns from the previous interval. Skip stale cells.
            let Some(cell_info) = self.cells.get(&(cell as u32)) else {
                continue;
            };

            let nr_cpus = cell_info.cpus.weight() as u64;
            if nr_cpus == 0 {
                bail!("Cell {} has 0 CPUs assigned", cell);
            }

            // capacity = total available CPU-time this interval
            let capacity = nr_cpus * interval_ns;
            // util: fraction of own capacity consumed by own tasks
            let util_pct = 100.0 * (delta_running as f64) / (capacity as f64);
            // demand_borrow: fraction of running time that was borrowed from other cells
            let demand_borrow_pct = if delta_running > 0 {
                100.0 * (delta_borrowed as f64) / (delta_running as f64)
            } else {
                0.0
            };
            // lent: fraction of own capacity used by foreign tasks
            let lent_pct = 100.0 * (delta_lent as f64) / (capacity as f64);

            // Update EWMA-smoothed utilization
            if self.enable_rebalancing {
                self.smoothed_util[cell] = self.demand_smoothing * util_pct
                    + (1.0 - self.demand_smoothing) * self.smoothed_util[cell];
            }

            self.metrics
                .cells
                .entry(cell as u32)
                .or_default()
                .update_demand(util_pct, demand_borrow_pct, lent_pct);

            // Update smoothed_util_pct in metrics
            if self.enable_rebalancing {
                self.metrics
                    .cells
                    .entry(cell as u32)
                    .or_default()
                    .smoothed_util_pct = self.smoothed_util[cell];
            }

            global_running_delta += delta_running;
            global_borrowed_delta += delta_borrowed;
            global_lent_delta += delta_lent;
            global_capacity += capacity;
        }

        let global_util_pct = if global_capacity > 0 {
            100.0 * (global_running_delta as f64) / (global_capacity as f64)
        } else {
            0.0
        };
        let global_borrow_pct = if global_running_delta > 0 {
            100.0 * (global_borrowed_delta as f64) / (global_running_delta as f64)
        } else {
            0.0
        };
        let global_lent_pct = if global_capacity > 0 {
            100.0 * (global_lent_delta as f64) / (global_capacity as f64)
        } else {
            0.0
        };

        self.metrics
            .update_demand(global_util_pct, global_borrow_pct, global_lent_pct);

        Ok(())
    }

    /// Check if any cell's cpuset was modified and recompute if so.
    fn check_cpuset_changes(&mut self) -> Result<()> {
        let Some(ref mut cm) = self.cell_manager else {
            return Ok(());
        };

        let current_seq = unsafe {
            let ptr = &self.skel.maps.bss_data.as_ref().unwrap().cpuset_seq as *const u32;
            (ptr as *const AtomicU32)
                .as_ref()
                .unwrap()
                .load(Ordering::Acquire)
        };

        if current_seq == self.last_cpuset_seq {
            return Ok(());
        }
        self.last_cpuset_seq = current_seq;

        if !cm.refresh_cpusets()? {
            return Ok(()); // seq changed but no cpusets on our cells changed
        }

        let cpu_assignments = self.compute_and_apply_cell_config(&[])?;
        let cell_manager = self.cell_manager.as_ref().unwrap();
        info!(
            "Cpuset change detected, recomputed config: {}",
            cell_manager.format_cell_config(&cpu_assignments)
        );
        Ok(())
    }

    fn refresh_bpf_cells(&mut self) -> Result<()> {
        let applied_configuration = unsafe {
            let ptr = &self
                .skel
                .maps
                .bss_data
                .as_ref()
                .unwrap()
                .applied_configuration_seq as *const u32;
            (ptr as *const std::sync::atomic::AtomicU32)
                .as_ref()
                .unwrap()
                .load(std::sync::atomic::Ordering::Acquire)
        };
        if self
            .last_configuration_seq
            .is_some_and(|seq| applied_configuration == seq)
        {
            return Ok(());
        }
        // collect all cpus per cell.
        let mut cell_to_cpus: HashMap<u32, Cpumask> = HashMap::new();
        let cpu_ctxs = read_cpu_ctxs(&self.skel)?;
        for (i, cpu_ctx) in cpu_ctxs.iter().enumerate() {
            cell_to_cpus
                .entry(cpu_ctx.cell)
                .or_insert_with(|| Cpumask::new())
                .set_cpu(i)
                .expect("set cpu in existing mask");
        }

        // Create cells we don't have yet, drop cells that are no longer in use.
        // If we continue to drop cell metrics once a cell is removed, we'll need to make sure we
        // flush metrics for a cell before we remove it completely.
        //
        // IMPORTANT: We determine which cells exist based on CPU assignments (which are
        // synchronized by applied_configuration_seq), NOT by reading the in_use field
        // separately. This avoids a TOCTOU race where a cell's in_use is set before
        // CPUs are assigned.

        // Cell 0 (root cell) always exists even if it has no CPUs temporarily
        let cells_with_cpus: HashSet<u32> = cell_to_cpus.keys().copied().collect();
        let mut active_cells = cells_with_cpus.clone();
        active_cells.insert(0);

        for cell_idx in &active_cells {
            let cpus = cell_to_cpus
                .get(cell_idx)
                .cloned()
                .unwrap_or_else(|| Cpumask::new());
            self.cells
                .entry(*cell_idx)
                .or_insert_with(|| Cell {
                    cpus: Cpumask::new(),
                })
                .cpus = cpus;
            self.metrics.cells.insert(*cell_idx, CellMetrics::default());
        }

        // Remove cells that no longer have CPUs assigned
        self.cells.retain(|&k, _| active_cells.contains(&k));
        self.metrics.cells.retain(|&k, _| active_cells.contains(&k));

        self.last_configuration_seq = Some(applied_configuration);

        Ok(())
    }
}

fn write_cpumask_to_config(cpumask: &Cpumask, dest: &mut [u8]) {
    let raw_slice = cpumask.as_raw_slice();
    for (word_idx, word) in raw_slice.iter().enumerate() {
        let byte_start = word_idx * 8;
        let bytes = word.to_le_bytes();
        for (j, byte) in bytes.iter().enumerate() {
            let idx = byte_start + j;
            if idx < dest.len() {
                dest[idx] = *byte;
            }
        }
    }
}

fn read_cpu_ctxs(skel: &BpfSkel) -> Result<Vec<bpf_intf::cpu_ctx>> {
    let mut cpu_ctxs = vec![];
    let cpu_ctxs_vec = skel
        .maps
        .cpu_ctxs
        .lookup_percpu(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
        .context("Failed to lookup cpu_ctx")?
        .unwrap();
    if cpu_ctxs_vec.len() < *NR_CPUS_POSSIBLE {
        bail!(
            "Percpu map returned {} entries but expected {}",
            cpu_ctxs_vec.len(),
            *NR_CPUS_POSSIBLE
        );
    }
    for cpu in 0..*NR_CPUS_POSSIBLE {
        cpu_ctxs.push(*unsafe {
            &*(cpu_ctxs_vec[cpu].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
        });
    }
    Ok(cpu_ctxs)
}

#[clap_main::clap_main]
fn main(opts: Opts) -> Result<()> {
    if opts.version {
        println!(
            "scx_mitosis {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

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

    if opts.verbose > 0 {
        warn!("Setting verbose via -v is deprecated and will be an error in future releases.");
    }

    debug!("opts={:?}", &opts);

    if let Some(run_id) = opts.run_id {
        info!("scx_mitosis run_id: {}", run_id);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor {
        let shutdown_clone = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_clone) {
                Ok(_) => {
                    debug!("stats monitor thread finished successfully")
                }
                Err(error_object) => {
                    warn!(
                        "stats monitor thread finished because of an error {}",
                        error_object
                    )
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
