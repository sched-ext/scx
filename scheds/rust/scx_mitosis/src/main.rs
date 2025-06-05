// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::collections::HashMap;
use std::cmp::max;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::debug;
use log::info;
use log::trace;
use scx_utils::init_libbpf_logging;
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
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
    }
}

// Per cell book-keeping
#[derive(Debug)]
struct Cell {
    cpus: Cpumask,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    monitor_interval: std::time::Duration,
    cells: HashMap<u32, Cell>,
    // These are the per-cell cstats.
    // Note these are accumulated across all CPUs.
    prev_cell_stats:[[u64; NR_CSTATS]; MAX_CELLS],
    // The difference between the current and previous cstats.
    cell_stats_delta:[[u64; NR_CSTATS]; MAX_CELLS],
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let topology = Topology::new()?;

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 1);
        init_libbpf_logging(None);
        let mut skel = scx_ops_open!(skel_builder, open_object, mitosis)?;

        skel.struct_ops.mitosis_mut().exit_dump_len = opts.exit_dump_len;

        skel.maps.rodata_data.slice_ns = scx_enums.SCX_SLICE_DFL;

        skel.maps.rodata_data.nr_possible_cpus = *NR_CPUS_POSSIBLE as u32;
        for cpu in topology.all_cores.keys() {
            skel.maps.rodata_data.all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }

        let skel = scx_ops_load!(skel, mitosis, uei)?;

        Ok(Self {
            skel,
            monitor_interval: std::time::Duration::from_secs(opts.monitor_interval_s),
            cells: HashMap::new(),
            prev_cell_stats: [[0; NR_CSTATS]; MAX_CELLS],
            cell_stats_delta: [[0; NR_CSTATS]; MAX_CELLS],
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let struct_ops = scx_ops_attach!(self.skel, mitosis)?;
        info!("Mitosis Scheduler Attached");
        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            std::thread::sleep(self.monitor_interval);
            self.refresh_bpf_cells()?;
            self.debug()?;
        }
        drop(struct_ops);
        uei_report!(&self.skel, uei)
    }

    fn load_cpu_contexts(&self) -> Result<Vec<Vec<u8>>> {
        let zero = 0 as libc::__u32;
        let zero_slice = unsafe { any_as_u8_slice(&zero) };

        let v = match self
        .skel
        .maps
        .cpu_ctxs
        .lookup_percpu(zero_slice, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(v)) => v,
            Ok(None) => return Err(anyhow::anyhow!("Found no values for cpu_ctxs map")),
            Err(e) => return Err(anyhow::anyhow!("Error looking up cpu_ctxs map: {:?}", e)),
        };
        Ok(v)
    }

    fn calculate_distribution_and_log<const N: usize>(
        &self,
        queue_counts:           &[u64; N],
        global_queue_decisions:  u64,
        scope_queue_decisions:         u64,
        scope_affn_viols:        u64,
        prefix:                 &str)
        -> Result<()> {

        debug_assert!(global_queue_decisions > 0 && scope_queue_decisions > 0);

        // First % on the line: share of global work
        let share_of_global = 100.0 * (scope_queue_decisions as f64) / (global_queue_decisions as f64);

        // Each queue's % of the scope total
        let mut queue_pct = [0.0; N];
        for (i, total) in queue_counts.iter().enumerate() {
            queue_pct[i] = 100.0 * (*total as f64) / (scope_queue_decisions as f64);
        }

        // These are summed differently for the global and per-cell totals.
        let affinity_violations_percent = 100.0 * (scope_affn_viols as f64) / (scope_queue_decisions as f64);

        // Decisions width. We know global_queue_decisions is non-zero.
        const MIN_DECISIONS_WIDTH: usize = 5;
        let decisions_format_width: usize = max(MIN_DECISIONS_WIDTH, (global_queue_decisions as f64).log10().ceil() as usize);

        debug_assert!(
            N == 4,
            "calculate_distribution_and_log: expected 4 queue counters, got {}",
            N
        );

        trace!(
            "{} {:width$} {:5.1}% | L:{:4.1}% D:{:4.1}% hi:{:4.1}% lo:{:4.1}% | V:{:4.1}%",
            prefix,
            scope_queue_decisions,
            share_of_global,
            queue_pct[0], queue_pct[1], queue_pct[2], queue_pct[3],
            affinity_violations_percent,
            width = decisions_format_width
        );
        Ok(())
    }

    // Queue stats for the whole node
    fn log_global_queue_stats<const N: usize>(
        &self,
        queue_stats_idx: [bpf_intf::cell_stat_idx; N],
        global_queue_decisions: u64)
        -> Result<()> {

        // Get total of each queue summed over all cells
        let mut queue_counts = [0; N];
        for cells in 0..MAX_CELLS {
            for (i, stat) in queue_stats_idx.iter().enumerate() {
                queue_counts[i] += self.cell_stats_delta[cells][*stat as usize];
            }
        }

        let prefix = "Total Decisions:   ";

        // Here we want to sum the affinity violations over all cells.
        let scope_affn_viols: u64 = self.cell_stats_delta.iter()
            .map(|&cell| cell[bpf_intf::cell_stat_idx_CSTAT_AFFN_VIOL as usize])
            .sum::<u64>();

        // Special case where the number of scope decisions == number global decisions
        self.calculate_distribution_and_log(&queue_counts,
                                            global_queue_decisions,
                                            global_queue_decisions,
                                            scope_affn_viols,
                                            &prefix)?;

        Ok(())
    }

    // Print out the per-cell stats
    fn log_cell_queue_stats<const N: usize>(
        &self, queue_stats_idx: [bpf_intf::cell_stat_idx; N],
        global_queue_decisions: u64)
        -> Result<()> {

        for cell in 0..MAX_CELLS {
            let cell_queue_decisions = queue_stats_idx.iter()
                .map(|&stat| self.cell_stats_delta[cell][stat as usize])
                .sum::<u64>();

            // FIXME: This should really query if the cell is enabled or not.
            if cell_queue_decisions == 0 {
                continue;
            }

            let mut queue_counts = [0; N];
            for (i, &stat) in queue_stats_idx.iter().enumerate() {
                queue_counts[i] = self.cell_stats_delta[cell][stat as usize];
            }

            const MIN_CELL_WIDTH: usize = 2;
            let cell_width: usize = max(MIN_CELL_WIDTH, (MAX_CELLS as f64).log10().ceil() as usize);

            let prefix = format!("Cell {:width$} Decisions: ", cell, width = cell_width);

            // Sum affinity violations for this cell
            let scope_affn_viols: u64 = self.cell_stats_delta[cell][bpf_intf::cell_stat_idx_CSTAT_AFFN_VIOL as usize];

            self.calculate_distribution_and_log(&queue_counts,
                                                global_queue_decisions,
                                                cell_queue_decisions,
                                                scope_affn_viols,
                                                &prefix)?;

        }
        Ok(())
    }

    fn log_all_queue_stats(&self) -> Result<()> {
        // The subset of cstats we care about.
        // Local + Default + Hi + Lo = Total Decisions
        // Affinity violations are not queue decisions, but
        // will be calculated separately and reported as a percent of the total
        let queue_stats_idx = [
            bpf_intf::cell_stat_idx_CSTAT_LOCAL,
            bpf_intf::cell_stat_idx_CSTAT_DEFAULT_Q,
            bpf_intf::cell_stat_idx_CSTAT_HI_FALLBACK_Q,
            bpf_intf::cell_stat_idx_CSTAT_LO_FALLBACK_Q,
        ];
        // Get total decisions
        let global_queue_decisions: u64 = self.cell_stats_delta
            .iter()
            .flat_map(|cell| queue_stats_idx.iter().map(|&idx| cell[idx as usize]))
            .sum();

        // We don't want to divide by zero later, but this is never expected.
        if global_queue_decisions == 0 { trace!("No decisions made"); return Ok(()); }

        self.log_global_queue_stats(queue_stats_idx, global_queue_decisions)?;

        self.log_cell_queue_stats(queue_stats_idx, global_queue_decisions)?;

        Ok(())
    }

    fn calculate_cell_stat_delta(&mut self) -> Result<()> {
        self.cell_stats_delta = [[0; NR_CSTATS]; MAX_CELLS];

        // Sum each CPU's stats into the diff array
        let v = self.load_cpu_contexts()?;
        for (cpu, ctx) in v.iter().enumerate() {
            let cpu_ctx = unsafe {
                let ptr = ctx.as_slice().as_ptr() as *const bpf_intf::cpu_ctx;
                &*ptr
            };
            // Each CPU has a u64 cstats[MAX_CELLS][NR_CSTATS];
            for cell in 0..MAX_CELLS {
                for stat in 0..NR_CSTATS {
                    self.cell_stats_delta[cell][stat] += cpu_ctx.cstats[cell][stat];
                }
            }
        }
        // Right now cell_stats_delta holds the total counts
        // So subtracting prev will give us the diff, what we're after.
        // We can also update prev_cell_stats here by adding the diff
        for cell in 0..MAX_CELLS {
            for stat in 0..NR_CSTATS {
                self.cell_stats_delta[cell][stat] -= self.prev_cell_stats[cell][stat];
                self.prev_cell_stats[cell][stat] += self.cell_stats_delta[cell][stat];
            }
        }
        Ok(())
    }

    /// Output various debugging data like per cell stats, per-cpu stats, etc.
    fn debug(&mut self) -> Result<()> {
        self.calculate_cell_stat_delta()?;

        self.log_all_queue_stats()?;

        for (cell_id, cell) in &self.cells {
            trace!("CELL[{}]: {}", cell_id, cell.cpus);
        }
        Ok(())
    }

    fn refresh_bpf_cells(&mut self) -> Result<()> {
        // collect all cpus per cell.
        let mut cell_to_cpus: HashMap<u32, Cpumask> = HashMap::new();
        let cpu_ctxs = read_cpu_ctxs(&self.skel)?;
        for (i, cpu_ctx) in cpu_ctxs.iter().enumerate() {
            cell_to_cpus
                .entry(cpu_ctx.cell)
                .and_modify(|mask| mask.set_cpu(i).expect("set cpu in existing mask"))
                .or_insert_with(|| {
                    let mut mask = Cpumask::new();
                    mask.set_cpu(i).expect("set cpu in new mask");
                    mask
                });
        }

        // create cells we don't have yet, drop cells that are no longer in use.
        let cells = &self.skel.maps.bss_data.cells;
        for i in 0..MAX_CELLS {
            let cell_idx = i as u32;
            let bpf_cell = cells[i];
            if bpf_cell.in_use > 0 {
                self.cells.entry(cell_idx).or_insert(Cell {
                    cpus: cell_to_cpus
                        .get(&cell_idx)
                        .expect("missing cell in cpu map")
                        .clone(),
                });
            } else {
                self.cells.remove(&cell_idx);
            }
        }

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

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
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

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
