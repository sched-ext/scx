// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod stats;

use std::cmp::max;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::debug;
use log::info;
use log::trace;
use log::warn;
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

use stats::CellMetrics;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_mitosis";
const MAX_CELLS: usize = bpf_intf::consts_MAX_CELLS as usize;
const NR_CSTATS: usize = bpf_intf::cell_stat_idx_NR_CSTATS as usize;

/// scx_mitosis: A dynamic affinity scheduler
///
/// Cgroups are assigned to a dynamic number of Cells which are assigned to a
/// dynamic set of CPUs. The BPF part does simple vtime scheduling for each cell.
///
/// Userspace makes the dynamic decisions of which Cells should be merged or
/// split and which CPUs they should be assigned to.
#[derive(Debug, Parser)]
struct Opts {
    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

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

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

// The subset of cstats we care about.
// Local + Default + Hi + Lo = Total Decisions
// Affinity violations are not queue decisions, but
// will be calculated separately and reported as a percent of the total
const QUEUE_STATS_IDX: [bpf_intf::cell_stat_idx; 3] = [
    bpf_intf::cell_stat_idx_CSTAT_LOCAL,
    bpf_intf::cell_stat_idx_CSTAT_CPU_DSQ,
    bpf_intf::cell_stat_idx_CSTAT_CELL_DSQ,
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
    metrics: Metrics,
    stats_server: StatsServer<(), Metrics>,
    last_configuration_seq: Option<u32>,
}

struct DistributionStats {
    total_decisions: u64,
    share_of_decisions_pct: f64,
    local_q_pct: f64,
    cpu_q_pct: f64,
    cell_q_pct: f64,
    affn_viol_pct: f64,

    // for formatting
    global_queue_decisions: u64,
}

impl Display for DistributionStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This makes the output easier to read by improving column alignment. First, it guarantees that within a
        // given logging interval, the global and cell queueing decision counts print at the same width.
        // Second, it reduces variance in column width between logging intervals. 5 is simply a heuristic.
        const MIN_DECISIONS_WIDTH: usize = 5;
        let descisions_width = max(
            MIN_DECISIONS_WIDTH,
            (self.global_queue_decisions as f64).log10().ceil() as usize,
        );
        write!(
            f,
            "{:width$} {:5.1}% | Local:{:4.1}% From: CPU:{:4.1}% Cell:{:4.1}% | V:{:4.1}%",
            self.total_decisions,
            self.share_of_decisions_pct,
            self.local_q_pct,
            self.cpu_q_pct,
            self.cell_q_pct,
            self.affn_viol_pct,
            width = descisions_width,
        )
    }
}

impl<'a> Scheduler<'a> {
    fn is_cell_in_use(&self, cell_id: u32) -> bool {
        let cells = &self.skel.maps.bss_data.as_ref().unwrap().cells;
        let bpf_cell = cells[cell_id as usize];
        let in_use = unsafe { std::ptr::read_volatile(&bpf_cell.in_use as *const u32) };
        in_use != 0
    }

    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let topology = Topology::new()?;

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 1);
        init_libbpf_logging(None);
        info!(
            "Running scx_mitosis (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );

        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, mitosis, open_opts)?;

        skel.struct_ops.mitosis_mut().exit_dump_len = opts.exit_dump_len;

        skel.maps.rodata_data.as_mut().unwrap().slice_ns = scx_enums.SCX_SLICE_DFL;

        skel.maps.rodata_data.as_mut().unwrap().nr_possible_cpus = *NR_CPUS_POSSIBLE as u32;
        for cpu in topology.all_cpus.keys() {
            skel.maps.rodata_data.as_mut().unwrap().all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }

        match *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP {
            0 => info!("Kernel does not support queued wakeup optimization."),
            v => skel.struct_ops.mitosis_mut().flags |= v,
        }

        let skel = scx_ops_load!(skel, mitosis, uei)?;

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            monitor_interval: Duration::from_secs(opts.monitor_interval_s),
            cells: HashMap::new(),
            prev_cell_stats: [[0; NR_CSTATS]; MAX_CELLS],
            metrics: Metrics::default(),
            stats_server,
            last_configuration_seq: None,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let struct_ops = scx_ops_attach!(self.skel, mitosis)?;

        info!("Mitosis Scheduler Attached. Run `scx_mitosis --monitor` for metrics.");

        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            self.refresh_bpf_cells()?;
            self.collect_metrics()?;

            match req_ch.recv_timeout(self.monitor_interval) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }
        drop(struct_ops);
        info!("Unregister {SCHEDULER_NAME} scheduler");
        uei_report!(&self.skel, uei)
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

        const EXPECTED_QUEUES: usize = 3;
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
            affn_viol_pct: affinity_violations_percent,
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

        // Special case where the number of scope decisions == number global decisions
        let stats = self.calculate_distribution_stats(
            &queue_counts,
            global_queue_decisions,
            global_queue_decisions,
            scope_affn_viols,
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

            // Only print stats for cells that are in use and have decisions
            if cell_queue_decisions == 0 || !self.is_cell_in_use(cell as u32) {
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

            let stats = self.calculate_distribution_stats(
                &queue_counts,
                global_queue_decisions,
                cell_queue_decisions,
                scope_affn_viols,
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

    fn calculate_cell_stat_delta(&mut self) -> Result<[[u64; NR_CSTATS]; MAX_CELLS]> {
        let mut cell_stats_delta = [[0 as u64; NR_CSTATS]; MAX_CELLS];

        // Read CPU contexts
        let cpu_ctxs = read_cpu_ctxs(&self.skel)?;

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
        let cell_stats_delta = self.calculate_cell_stat_delta()?;

        self.log_all_queue_stats(&cell_stats_delta)?;

        for (cell_id, cell) in &self.cells {
            // Check if cell is actually in use from BPF before printing
            if !self.is_cell_in_use(*cell_id) {
                continue;
            }
            
            trace!("CELL[{}]: {}", cell_id, cell.cpus);
            
            // Read current CPU assignments directly from BPF for comparison
            let mut bpf_cpus = Cpumask::new();
            let cpu_ctxs = read_cpu_ctxs(&self.skel)?;
            for (i, cpu_ctx) in cpu_ctxs.iter().enumerate() {
                if cpu_ctx.cell == *cell_id {
                    bpf_cpus.set_cpu(i).expect("set cpu in bpf mask");
                }
            }

            trace!("CELL[{}]: BPF={}", cell_id, bpf_cpus);
            
            // Flag potential staleness
            if cell.cpus != bpf_cpus {
                warn!("STALENESS DETECTED: CELL[{}] userspace={} != bpf={}", 
                      cell_id, cell.cpus, bpf_cpus);
            }
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

    fn refresh_bpf_cells(&mut self) -> Result<()> {
        let applied_configuration = unsafe {
            std::ptr::read_volatile(
                &self
                    .skel
                    .maps
                    .bss_data
                    .as_ref()
                    .unwrap()
                    .applied_configuration_seq as *const u32,
            )
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
        let cells = &self.skel.maps.bss_data.as_ref().unwrap().cells;
        for i in 0..MAX_CELLS {
            let cell_idx = i as u32;
            let bpf_cell = cells[i];
            let in_use = unsafe { std::ptr::read_volatile(&bpf_cell.in_use as *const u32) };
            if in_use > 0 {
                self.cells
                    .entry(cell_idx)
                    .or_insert_with(|| Cell {
                        cpus: Cpumask::new(),
                    })
                    .cpus = cell_to_cpus
                    .get(&cell_idx)
                    .expect("missing cell in cpu map")
                    .clone();
                self.metrics.cells.insert(cell_idx, CellMetrics::default());
            } else {
                self.cells.remove(&cell_idx);
                self.metrics.cells.remove(&cell_idx);
            }
        }

        self.last_configuration_seq = Some(applied_configuration);

        Ok(())
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
    for cpu in 0..*NR_CPUS_POSSIBLE {
        cpu_ctxs.push(*unsafe {
            &*(cpu_ctxs_vec[cpu].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
        });
    }
    Ok(cpu_ctxs)
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "scx_mitosis {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    debug!("opts={:?}", &opts);

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
