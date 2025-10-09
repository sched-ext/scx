// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
mod stats;
mod mitosis_topology_utils;

use std::cmp::max;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::sync::Mutex;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::{MapCore, OpenObject, MapFlags};
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
use crate::mitosis_topology_utils::{populate_topology_maps, MapKind};

// This is the cell type from intf.h.
// When copied to user, the lock field is omitted.
// We can mmap it, or use calls to the BPF_MAP_LOOKUP_ELEM
// command of the bpf() system call with the BPF_F_LOCK flag
type BpfCell = bpf_intf::cell;

const SCHEDULER_NAME: &str = "scx_mitosis";
const MAX_CELLS: usize = bpf_intf::consts_MAX_CELLS as usize;
const NR_CSTATS: usize = bpf_intf::cell_stat_idx_NR_CSTATS as usize;

// Can we deduplicate this with mitosis.bpf.h?
const CPUMASK_LONG_ENTRIES: usize = 128;

// Global debug flags
// TODO: These will be runtime adjustable via a CLI option.
static DEBUG_FLAGS: std::sync::LazyLock<Mutex<HashMap<String, bool>>> = std::sync::LazyLock::new(|| {
    let mut flags = HashMap::new();
    flags.insert("cpu_to_l3".to_string(),  false);
    flags.insert("l3_to_cpus".to_string(), false);
    flags.insert("cells".to_string(),      true );
    flags.insert("counters".to_string(),   true );
    flags.insert("steals".to_string(),     true );
    flags.insert("metrics".to_string(),    true );
    Mutex::new(flags)
});

/// Debug Printers
const ANSI_RED: &str = "\x1b[31m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RESET: &str = "\x1b[0m";

/// Check if a debug flag is enabled
fn is_debug_flag_enabled(flag: &str) -> bool {
    if let Ok(flags) = DEBUG_FLAGS.lock() {
        flags.get(flag).copied().unwrap_or(false)
    } else {
        false
    }
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
struct CellMask {
    cpus: Cpumask,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    monitor_interval: Duration,
    cells: HashMap<u32, CellMask>,
    // These are the per-cell cstats.
    // Note these are accumulated across all CPUs.
    prev_cell_stats: [[u64; NR_CSTATS]; MAX_CELLS],
    prev_total_steals: u64,
    metrics: Metrics,
    stats_server: StatsServer<(), Metrics>,
    last_configuration_seq: Option<u32>,
    iteration_count: u64,
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
            "{:width$} {:5.1}% | Local:{:5.1}% From: CPU:{:4.1}% Cell:{:5.1}% | V:{:4.1}%",
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
    fn get_bpf_cell(&self, cell_id: u32) -> anyhow::Result<Option<BpfCell>> {
        let key = cell_id.to_ne_bytes();
        let map = &self.skel.maps.cells; // NOTE: map is a field, not a method

        match map.lookup(&key, MapFlags::ANY)? {
            Some(bytes) => {
                let need = core::mem::size_of::<BpfCell>();
                if bytes.len() != need {
                    anyhow::bail!("cells value size {} != BpfCell {}", bytes.len(), need);
                }
                // Copy to an aligned buffer to avoid misaligned reference
                let mut tmp = MaybeUninit::<BpfCell>::uninit();
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        tmp.as_mut_ptr() as *mut u8,
                        need,
                    );
                    Ok(Some(tmp.assume_init()))
                }
            }
            None => Ok(None),
        }
    }

    fn is_cell_in_use(&self, cell_id: u32) -> bool {
        match self.get_bpf_cell(cell_id) {
            Ok(Some(c)) => c.in_use != 0,
            _ => false,
        }
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

        skel.maps.rodata_data.as_mut().unwrap().nr_l3 = topology.all_llcs.len() as u32;

        // print the number of l3s we detected
        info!("Found {} L3s", topology.all_llcs.len());

        match *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP {
            0 => info!("Kernel does not support queued wakeup optimization."),
            v => skel.struct_ops.mitosis_mut().flags |= v,
        }

        let mut skel = scx_ops_load!(skel, mitosis, uei)?;

        // Verify our version of the cell datastructure is the same size
        // as the bpf one.
        let cells_info = skel.maps.cells.info()?;
        let usz = core::mem::size_of::<BpfCell>() as u32;
        if cells_info.info.value_size != usz {
            bail!(
                "cells value_size={} but Rust expects {} (BpfCell)",
                cells_info.info.value_size,
                usz
            );
        }

        // Set up CPU to L3 topology mapping using the common functionality
        populate_topology_maps(&mut skel, MapKind::CpuToL3, None)?;

        // Set up L3 to CPUs mapping using the common functionality
        populate_topology_maps(&mut skel, MapKind::L3ToCpus, None)?;

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            monitor_interval: Duration::from_secs(opts.monitor_interval_s),
            cells: HashMap::new(),
            prev_cell_stats: [[0; NR_CSTATS]; MAX_CELLS],
            prev_total_steals: 0,
            metrics: Metrics::default(),
            stats_server,
            last_configuration_seq: None,
            iteration_count: 0,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let struct_ops = scx_ops_attach!(self.skel, mitosis)?;

        info!("Mitosis Scheduler Attached. Run `scx_mitosis --monitor` for metrics.");

        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            self.iteration_count += 1;
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

        let prefix = "  Total:  ";

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

        if is_debug_flag_enabled("metrics") {
            trace!("{}{}{}", ANSI_GREEN, "metrics:", ANSI_RESET);
            trace!("{} {}", prefix, stats);
        }

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
            if !self.is_cell_in_use(cell as u32) {
                continue;
            }

            let mut queue_counts = [0; QUEUE_STATS_IDX.len()];
            for (i, &stat) in QUEUE_STATS_IDX.iter().enumerate() {
                queue_counts[i] = cell_stats_delta[cell][stat as usize];
            }

            const MIN_CELL_WIDTH: usize = 2;
            let cell_width: usize = max(MIN_CELL_WIDTH, (MAX_CELLS as f64).log10().ceil() as usize);

            let prefix = format!("  Cell {:width$}:", cell, width = cell_width);

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

            if is_debug_flag_enabled("metrics") {
                trace!("{} {}", prefix, stats);
            }
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
    /// Print debug printer status summary
    fn print_debug_status(&self) {
        if let Ok(flags) = DEBUG_FLAGS.lock() {
            let mut disabled: Vec<_> = flags.iter().filter_map(|(flag, &enabled)| (!enabled).then_some(format!("{}~{}{}", ANSI_RED, flag, ANSI_RESET))).collect();
            let enabled: Vec<_> = flags.iter().filter_map(|(flag, &enabled)| enabled.then_some(format!("{}+{}{}", ANSI_GREEN, flag, ANSI_RESET))).collect();
            disabled.extend(enabled);
            trace!("Debug Flags: {}", if disabled.is_empty() { "none".to_string() } else { disabled.join(" ") });
            // trace!("hint: sudo ./scx_mitosis cli debug ~/+<flag_name>");
        }
    }

    /// Collect metrics and out various debugging data like per cell stats, per-cpu stats, etc.
    fn collect_metrics(&mut self) -> Result<()> {
        trace!("");
        trace!("Iteration #{}", self.iteration_count);

        let cell_stats_delta = self.calculate_cell_stat_delta()?;

        self.log_all_queue_stats(&cell_stats_delta)?;

        // TODO: I don't really understand this.
        for (cell_id, cell) in &self.cells {
            // Check if cell is actually in use from BPF before printing
            if !self.is_cell_in_use(*cell_id) {
                continue;
            }
            trace!("CELL[{}]: {}", cell_id, cell.cpus);
        }

        // Read total steals from BPF and update metrics
        self.update_steal_metrics()?;

        // Read and print function counters
        self.print_and_reset_function_counters()?;
        if is_debug_flag_enabled("cells") {
            trace!("{}cells:{}", ANSI_GREEN, ANSI_RESET);
            for i in 0..self.cells.len() {
                if let Some(cell) = self.cells.get(&(i as u32)) {
                    trace!("  CELL[{}]: {} ({:3} CPUs)", i, cell.cpus, cell.cpus.weight());
                }
            }
        }

        if is_debug_flag_enabled("cpu_to_l3") {
            let cpu_to_l3 = read_cpu_to_l3(&self.skel)?;
            let cpu_l3_pairs: Vec<String> = cpu_to_l3.iter().enumerate()
                .map(|(cpu, l3)| format!("{:3}:{:2}", cpu, l3))
                .collect();
            let chunked_output = cpu_l3_pairs
                .chunks(16)
                .map(|chunk| chunk.join(" "))
                .collect::<Vec<_>>()
                .join("\n");
            trace!("{}cpu_to_l3:{}\n{}", ANSI_GREEN, ANSI_RESET, chunked_output);
        }

        if is_debug_flag_enabled("l3_to_cpus") {
            trace!("{}l3_to_cpus:{}", ANSI_GREEN, ANSI_RESET);
            let l3_to_cpus = read_l3_to_cpus(&self.skel)?;
            for (l3_id, mask) in l3_to_cpus.iter() {
                trace!("l3_to_cpus: [{:2}] = {}", l3_id, mask);
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

        // Print debug printer status at the end of each cycle
        self.print_debug_status();

        Ok(())
    }

    fn print_and_reset_function_counters(&mut self) -> Result<()> {
        if !is_debug_flag_enabled("counters") {
            return Ok(());
        }
        trace!("{}counters:{}", ANSI_GREEN, ANSI_RESET);

        let counter_names = ["select", "enqueue", "dispatch"];
        let max_name_len = counter_names.iter().map(|name| name.len()).max().unwrap_or(0);
        let mut all_counters = Vec::new();

        // Read counters for each function
        for counter_idx in 0..bpf_intf::fn_counter_idx_NR_COUNTERS {
            let key = (counter_idx as u32).to_ne_bytes();

            // Read per-CPU values
            let percpu_values = self.skel
                .maps
                .function_counters
                .lookup_percpu(&key, MapFlags::ANY)
                .context("Failed to lookup function counter")?
                .unwrap_or_default();

            let mut cpu_values = Vec::new();
            for cpu in 0..*NR_CPUS_POSSIBLE {
                if cpu < percpu_values.len() {
                    let value = u64::from_ne_bytes(
                        percpu_values[cpu].as_slice().try_into()
                            .context("Failed to convert counter bytes")?
                    );
                    cpu_values.push(value);
                }
            }

            all_counters.push(cpu_values);
        }

        // Calculate and print statistics for each counter
        for (idx, counter_values) in all_counters.iter().enumerate() {
            if idx >= counter_names.len() {
                break;
            }

            let name = counter_names[idx];
            let non_zero_values: Vec<u64> = counter_values.iter().filter(|&&v| v > 0).copied().collect();

            if non_zero_values.is_empty() {
                trace!("  Fn[{:<width$}]: no activity", name, width = max_name_len);
                continue;
            }

            let total: u64 = non_zero_values.iter().sum();
            let min = *non_zero_values.iter().min().unwrap();
            let max = *non_zero_values.iter().max().unwrap();

            // Calculate median
            let mut sorted_values = non_zero_values.clone();
            sorted_values.sort();
            let median = if sorted_values.len() % 2 == 0 {
                let mid = sorted_values.len() / 2;
                (sorted_values[mid - 1] + sorted_values[mid]) / 2
            } else {
                sorted_values[sorted_values.len() / 2]
            };

            trace!(
                "  Fn[{:<width$}]: tot={:>6} min={:>4} med={:>4} max={:>5} ({:3} CPUs)",
                name, total, min, median, max, non_zero_values.len(), width = max_name_len
            );
        }

        // Zero out all counters after printing
        for counter_idx in 0..bpf_intf::fn_counter_idx_NR_COUNTERS {
            let key = (counter_idx as u32).to_ne_bytes();
            let zero_value = 0u64.to_ne_bytes().to_vec();

            // Create per-CPU values array (all zeros)
            let percpu_values: Vec<Vec<u8>> = (0..*NR_CPUS_POSSIBLE)
                .map(|_| zero_value.clone())
                .collect();

            self.skel
                .maps
                .function_counters
                .update_percpu(&key, &percpu_values, MapFlags::ANY)
                .context("Failed to reset function counter")?;
        }

        Ok(())
    }

fn update_steal_metrics(&mut self) -> Result<()> {
    let steals_debug = is_debug_flag_enabled("steals");

    // Early out if stealing is compiled out.
    if bpf_intf::MITOSIS_ENABLE_STEALING == 0 {
        self.metrics.total_steals = 0;
        if steals_debug {
            trace!("{}steals:{}", ANSI_GREEN, ANSI_RESET);
            trace!("  Work stealing disabled at compile time (MITOSIS_ENABLE_STEALING=0)");
        }
        return Ok(());
    }

    let key = 0u32.to_ne_bytes();

    // Read the count; lazily initialize the slot to 0 if it doesn't exist.
    let steal_count = match self.skel.maps.steal_stats.lookup(&key, MapFlags::ANY) {
        Ok(Some(data)) if data.len() >= 8 => {
            u64::from_ne_bytes(data[..8].try_into().unwrap())
        }
        Ok(Some(_)) => {
            if steals_debug {
                debug!("steal_stats map data too small");
            }
            0
        }
        Ok(None) => {
            let zero = 0u64.to_ne_bytes();
            if let Err(e) = self.skel.maps.steal_stats.update(&key, &zero, MapFlags::ANY) {
                if steals_debug {
                    debug!("Failed to initialize steal_stats map: {e}");
                }
            }
            0
        }
        Err(e) => {
            if steals_debug {
                debug!("Failed to read steal_stats map: {e}");
            }
            0
        }
    };

    // Calculate steals since last update (delta)
    let steals_delta = steal_count - self.prev_total_steals;
    self.prev_total_steals = steal_count;
    self.metrics.total_steals = steals_delta;

    // Early out if we aren't logging.
    if !steals_debug {
        return Ok(());
    }

    if steals_delta > 0 {
        trace!("{}steals:{}", ANSI_GREEN, ANSI_RESET);
        trace!("  Work stealing active: steals_since_last={}", steals_delta);
    } else {
        trace!("{}steals:{}", ANSI_GREEN, ANSI_RESET);
        trace!("  Work stealing enabled but no new steals: steals_since_last={}", steals_delta);
    }

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
        for i in 0..MAX_CELLS {
            let cell_idx = i as u32;
            if self.is_cell_in_use(cell_idx) {
                self.cells
                    .entry(cell_idx)
                    .or_insert_with(|| CellMask {
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
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)
        .context("Failed to lookup cpu_ctx")?
        .unwrap();
    for cpu in 0..*NR_CPUS_POSSIBLE {
        cpu_ctxs.push(*unsafe {
            &*(cpu_ctxs_vec[cpu].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
        });
    }
    Ok(cpu_ctxs)
}

fn read_cpu_to_l3(skel: &BpfSkel) -> Result<Vec<u32>> {
    let mut cpu_to_l3 = vec![];
    for cpu in 0..*NR_CPUS_POSSIBLE {
        let key = (cpu as u32).to_ne_bytes();
        let val = skel
            .maps
            .cpu_to_l3
            .lookup(&key, MapFlags::ANY)?
            .map(|v| u32::from_ne_bytes(v.try_into().unwrap()))
            .unwrap_or(0);
        cpu_to_l3.push(val);
    }
    Ok(cpu_to_l3)
}

fn read_l3_to_cpus(skel: &BpfSkel) -> Result<Vec<(u32, Cpumask)>> {
    let mut l3_to_cpus = vec![];

    // Get the number of L3 caches from the BPF rodata
    let nr_l3 = skel.maps.rodata_data.as_ref().unwrap().nr_l3;

    for l3 in 0..nr_l3 {
        let key = (l3 as u32).to_ne_bytes();
        let mask = if let Some(v) = skel
            .maps
            .l3_to_cpus
            .lookup(&key, MapFlags::ANY)?
        {
            let bytes = v.as_slice();
            let mut longs = [0u64; CPUMASK_LONG_ENTRIES];
            let mut i = 0;
            while i < CPUMASK_LONG_ENTRIES && i * 8 + 8 <= bytes.len() {
                longs[i] = u64::from_ne_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
                i += 1;
            }
            Cpumask::from_vec(longs.to_vec())
        } else {
            Cpumask::new()
        };
        l3_to_cpus.push((l3, mask));
    }
    Ok(l3_to_cpus)
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
