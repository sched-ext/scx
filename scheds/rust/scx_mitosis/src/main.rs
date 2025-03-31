// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitvec::prelude::*;
use cgroupfs::CgroupReader;
use clap::Parser;
use itertools::Itertools;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::debug;
use log::info;
use log::trace;
use maplit::btreemap;
use maplit::hashmap;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::ravg::ravg_read;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

const RAVG_FRAC_BITS: u32 = bpf_intf::ravg_consts_RAVG_FRAC_BITS;
const MAX_CPUS: usize = bpf_intf::consts_MAX_CPUS as usize;
const MAX_CELLS: usize = bpf_intf::consts_MAX_CELLS as usize;
const USAGE_HALF_LIFE: u32 = bpf_intf::consts_USAGE_HALF_LIFE;

lazy_static::lazy_static! {
    static ref NR_POSSIBLE_CPUS: usize = libbpf_rs::num_possible_cpus().unwrap();
}

/// scx_mitosis: A dynamic affinity scheduler
///
/// Cgroups are assigned to a dynamic number of Cells which are assigned to a
/// dynamic set of CPUs. The BPF part does simple vtime scheduling for each cell.
///
/// Userspace makes the dynamic decisions of which Cells should be merged or
/// split and which cpus they should be assigned to.
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
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

fn now_monotonic() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) };
    assert!(ret == 0);
    time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64
}

#[derive(Debug)]
struct CpuPool {
    nr_cpus: usize,
    all_cpus: BitVec,
    available_cpus: BitVec,
}

// TODO: The way we alloc/free CPUs to/from cells is totally topology agnostic,
// needs to be much smarter.
impl CpuPool {
    fn new() -> Result<Self> {
        if *NR_POSSIBLE_CPUS > MAX_CPUS {
            bail!(
                "NR_POSSIBLE_CPUS {} > MAX_CPUS {}",
                *NR_POSSIBLE_CPUS,
                MAX_CPUS
            );
        }

        let mut nr_offline = 0;
        let mut all_cpus = bitvec![1; *NR_POSSIBLE_CPUS];

        for cpu in 0..*NR_POSSIBLE_CPUS {
            let path = format!("/sys/devices/system/cpu/cpu{}", cpu,);
            if !std::path::Path::new(&path).exists() {
                nr_offline += 1;
                all_cpus.set(cpu, false);
            }
        }

        let nr_cpus = *NR_POSSIBLE_CPUS - nr_offline;

        info!("CPUs: online/possible={}/{}", nr_cpus, *NR_POSSIBLE_CPUS);

        Ok(Self {
            nr_cpus,
            all_cpus: all_cpus.clone(),
            available_cpus: all_cpus,
        })
    }

    fn alloc(&mut self) -> Option<usize> {
        let cpu = self.available_cpus.first_one()?;
        self.available_cpus.set(cpu, false);
        Some(cpu)
    }

    fn free(&mut self, cands: &mut BitVec) -> Option<usize> {
        let cpu = cands.last_one()?;
        self.available_cpus.set(cpu, true);
        cands.set(cpu, false);
        Some(cpu)
    }
}

#[derive(Clone, Debug)]
struct Cgroup {
    name: String,
    load: f64,
    pinned_load: f64,
}

impl Ord for Cgroup {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for Cgroup {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Cgroup {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Cgroup {}

#[derive(Debug)]
struct Cell {
    cgroups: BTreeMap<String, Cgroup>,
    cpu_assignment: BitVec,
    load: f64,
    pinned_load: f64,
}

#[derive(Debug)]
enum SplitOrMerge {
    Split(Split),
    Merge(Merge),
}

#[derive(Debug)]
struct Split {
    cell: u32,
    g1: Vec<Cgroup>,
    g2: Vec<Cgroup>,
    score: f64,
}

impl std::fmt::Display for Split {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "Split Cell({}), Score({})", self.cell, self.score)?;
        writeln!(f, "g1:")?;
        for cg in self.g1.iter() {
            if cg.load == 0.0 && cg.pinned_load == 0.0 {
                continue;
            }
            writeln!(
                f,
                "/{}: load={} pinned_load={}",
                cg.name, cg.load, cg.pinned_load
            )?;
        }
        writeln!(f, "g2:")?;
        for cg in self.g2.iter() {
            if cg.load == 0.0 && cg.pinned_load == 0.0 {
                continue;
            }
            writeln!(
                f,
                "/{}: load={} pinned_load={}",
                cg.name, cg.load, cg.pinned_load
            )?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Merge {
    cell1: u32,
    cell2: u32,
    score: f64,
}

impl std::fmt::Display for Merge {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Merge Cells {} and {}, Score({})",
            self.cell1, self.cell2, self.score
        )?;
        Ok(())
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    cpu_pool: CpuPool,
    cells: BTreeMap<u32, Cell>,
    cgroup_to_cell: HashMap<String, u32>,
    prev_percpu_cell_cycles: Vec<[u64; MAX_CELLS]>,
    last_reconfiguration: std::time::Instant,
    last_cpu_rebalancing: std::time::Instant,
    reconfiguration_interval: std::time::Duration,
    cpu_rebalancing_interval: std::time::Duration,
    monitor_interval: std::time::Duration,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let mut cpu_pool = CpuPool::new()?;

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 1);
        init_libbpf_logging(None);
        let mut skel = scx_ops_open!(skel_builder, open_object, mitosis)?;

        // scheduler_tick() got renamed to sched_tick() during v6.10-rc.
        let sched_tick_name = match compat::ksym_exists("sched_tick")? {
            true => "sched_tick",
            false => "scheduler_tick",
        };

        skel.progs
            .sched_tick_fentry
            .set_attach_target(0, Some(sched_tick_name.into()))
            .context("Failed to set attach target for sched_tick_fentry()")?;

        skel.struct_ops.mitosis_mut().exit_dump_len = opts.exit_dump_len;

        skel.maps.rodata_data.slice_ns = scx_enums.SCX_SLICE_DFL;

        if opts.verbose >= 1 {
            skel.maps.rodata_data.debug = true;
        }
        skel.maps.rodata_data.nr_possible_cpus = *NR_POSSIBLE_CPUS as u32;
        for cpu in cpu_pool.all_cpus.iter_ones() {
            skel.maps.rodata_data.all_cpus[cpu / 8] |= 1 << (cpu % 8);
            skel.maps.bss_data.cells[0].cpus[cpu / 8] |= 1 << (cpu % 8);
        }
        for _ in 0..cpu_pool.all_cpus.count_ones() {
            cpu_pool.alloc();
        }

        let mut skel = scx_ops_load!(skel, mitosis, uei)?;

        let struct_ops = Some(scx_ops_attach!(skel, mitosis)?);
        info!("Mitosis Scheduler Attached");

        // Initial configuration: Cell 0 with the rootcg assigned to it
        let cells = btreemap! {
            0 => Cell {
                cgroups: btreemap!{
                    "".to_string() => Cgroup {
                        name: "".to_string(),
                        load: 0.0,
                        pinned_load: 0.0,
                    }
                },
                cpu_assignment: cpu_pool.all_cpus.clone(),
                load: 0.0,
                pinned_load: 0.0,
            }
        };
        let cgroup_to_cell = hashmap! {
            "".to_string() => 0
        };
        let now = std::time::Instant::now();
        let nr_cpus = cpu_pool.nr_cpus;
        Ok(Self {
            skel,
            struct_ops,
            cpu_pool,
            cells,
            cgroup_to_cell,
            prev_percpu_cell_cycles: vec![[0; MAX_CELLS]; nr_cpus],
            last_reconfiguration: now,
            last_cpu_rebalancing: now,
            reconfiguration_interval: std::time::Duration::from_secs(
                opts.reconfiguration_interval_s,
            ),
            cpu_rebalancing_interval: std::time::Duration::from_secs(
                opts.rebalance_cpus_interval_s,
            ),
            monitor_interval: std::time::Duration::from_secs(opts.monitor_interval_s),
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            std::thread::sleep(self.monitor_interval);
            let total_load = self.collect_cgroup_load()?;
            self.debug()?;
            let mut reconfigured = false;
            if self.skel.maps.bss_data.user_global_seq != self.skel.maps.bss_data.global_seq {
                trace!("BPF reconfiguration still in progress, skipping further changes");
                continue;
            } else if self.last_reconfiguration.elapsed() >= self.reconfiguration_interval {
                trace!("Reconfiguring");
                reconfigured = true;
                match self.reconfigure()? {
                    Some(SplitOrMerge::Split(s)) => self.split(s)?,
                    Some(SplitOrMerge::Merge(m)) => self.merge(m)?,
                    _ => {
                        trace!("No beneficial reconfiguration found");
                        reconfigured = false;
                    }
                }
                self.last_reconfiguration = std::time::Instant::now();
            }
            if reconfigured || self.last_cpu_rebalancing.elapsed() >= self.cpu_rebalancing_interval
            {
                trace!("CPU rebalancing");
                self.assign_cpus(total_load)?;
                self.last_cpu_rebalancing = std::time::Instant::now();
                if reconfigured {
                    self.update_cgroup_to_cell_assignment()?;
                }
                self.trigger_reconfiguration();
            }
        }
        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }

    fn update_cgroup_to_cell_assignment(&mut self) -> Result<()> {
        for (cgroup, cell_idx) in self.cgroup_to_cell.iter() {
            let mut cg_path = String::from("/sys/fs/cgroup/");
            cg_path.push_str(cgroup);
            let cg_file = File::open(&cg_path)
                .with_context(|| format!("Failed to open path: {}", cg_path))?;
            let cg_fd = cg_file.as_raw_fd();
            let cg_fd_slice = unsafe { any_as_u8_slice(&cg_fd) };
            let cell_idx_u32 = *cell_idx as libc::__u32;
            let cell_idx_slice = unsafe { any_as_u8_slice(&cell_idx_u32) };
            /* XXX: NO_EXIST should be correct here, but it fails */
            self.skel
                .maps
                .cgrp_cell_assignment
                .update(cg_fd_slice, cell_idx_slice, libbpf_rs::MapFlags::ANY)
                .with_context(|| {
                    format!("Failed to update cgroup cell assignment for: {}", cg_path)
                })?;
            trace!("Assigned {} to {}", cgroup, cell_idx);
        }
        self.skel.maps.bss_data.update_cell_assignment = true;
        Ok(())
    }

    fn trigger_reconfiguration(&mut self) {
        trace!("Triggering Reconfiguration");
        self.skel.maps.bss_data.user_global_seq += 1;
    }

    /// Iterate through each cg in the cgroupfs, read its load from BPF and
    /// update the cells map
    fn collect_cgroup_load(&mut self) -> Result<f64> {
        let mut cgroup_to_cell = HashMap::new();

        for (_, cell) in self.cells.iter_mut() {
            cell.cgroups = BTreeMap::new();
            cell.load = 0.0;
            cell.pinned_load = 0.0;
        }
        let now_mono = now_monotonic();
        let mut stack = VecDeque::new();
        let root = CgroupReader::root()?;
        stack.push_back(root);
        let mut total_load = 0.0;
        while let Some(reader) = stack.pop_back() {
            for child in reader.child_cgroup_iter()? {
                stack.push_back(child);
            }
            let mut path = PathBuf::new();
            path.push(cgroupfs::DEFAULT_CG_ROOT);
            path.push(reader.name());
            let cg = File::open(path).with_context(|| {
                format!("Failed to open cgroup dir {}", reader.name().display())
            })?;
            let cg_fd = cg.as_raw_fd();
            let cg_fd_slice = unsafe { any_as_u8_slice(&cg_fd) };
            if let Some(v) = self
                .skel
                .maps
                .cgrp_ctx
                .lookup(cg_fd_slice, libbpf_rs::MapFlags::ANY)
                .with_context(|| {
                    format!(
                        "Failed to lookup cgroup {} in cgrp_ctx map",
                        reader.name().display()
                    )
                })?
            {
                let cgrp_ctx = unsafe {
                    let ptr = v.as_slice().as_ptr() as *const bpf_intf::cgrp_ctx;
                    *ptr
                };
                let rd = &cgrp_ctx.load_rd;
                let load = ravg_read(
                    rd.val,
                    rd.val_at,
                    rd.old,
                    rd.cur,
                    now_mono,
                    USAGE_HALF_LIFE,
                    RAVG_FRAC_BITS,
                );
                total_load += load;
                let pinned_rd = &cgrp_ctx.pinned_load_rd;
                let pinned_load = ravg_read(
                    pinned_rd.val,
                    pinned_rd.val_at,
                    pinned_rd.old,
                    pinned_rd.cur,
                    now_mono,
                    USAGE_HALF_LIFE,
                    RAVG_FRAC_BITS,
                );
                let name = reader.name().to_string_lossy().to_string();

                // We don't trust BPF knows the cgroup's cell (e.g. if a
                // reconfiguration is in flight) so rely on userspace as the
                // source of truth. If we don't know the cell, then walk up the
                // hierarchy.
                let cell_idx = self
                    .cgroup_to_cell
                    .get(&name)
                    .or_else(|| {
                        let mut s = name.as_str();
                        while let Some((parent, _)) = s.rsplit_once('/') {
                            if let Some(cell) = cgroup_to_cell.get(parent) {
                                return Some(cell);
                            }
                            s = parent;
                        }
                        cgroup_to_cell.get("")
                    })
                    .copied()
                    .ok_or_else(|| anyhow!("Failed to identify cell for cgroup {}", name))?;

                cgroup_to_cell.insert(name.clone(), cell_idx);
                let cell = self.cells.get_mut(&cell_idx).ok_or_else(|| {
                    anyhow!(
                        "Cgroup {} maps to cell {} which doesn't exist",
                        name,
                        cell_idx
                    )
                })?;
                cell.cgroups.insert(
                    name.clone(),
                    Cgroup {
                        name,
                        load,
                        pinned_load,
                    },
                );
                cell.load += load;
                cell.pinned_load += pinned_load;
            }
        }
        self.cgroup_to_cell = cgroup_to_cell;
        Ok(total_load)
    }

    /// Output various debugging data like per cell stats, per-cpu stats, etc.
    fn debug(&mut self) -> Result<()> {
        for (cell_idx, cell) in self.cells.iter() {
            trace!(
                "Cell {}, Load: {}, Pinned Load: {}",
                cell_idx,
                cell.load,
                cell.pinned_load
            );
        }
        let zero = 0 as libc::__u32;
        let zero_slice = unsafe { any_as_u8_slice(&zero) };
        if let Some(v) = self
            .skel
            .maps
            .cpu_ctxs
            .lookup_percpu(zero_slice, libbpf_rs::MapFlags::ANY)
            .context("Failed to lookup cpu_ctxs map")?
        {
            for (cpu, ctx) in v.iter().enumerate() {
                let cpu_ctx = unsafe {
                    let ptr = ctx.as_slice().as_ptr() as *const bpf_intf::cpu_ctx;
                    &*ptr
                };
                let diff_cycles: Vec<i64> = self.prev_percpu_cell_cycles[cpu]
                    .iter()
                    .zip(cpu_ctx.cell_cycles.iter())
                    .map(|(a, b)| (b - a) as i64)
                    .collect();
                self.prev_percpu_cell_cycles[cpu] = cpu_ctx.cell_cycles;
                trace!("CPU {}: {:?}", cpu, diff_cycles);
            }
        }
        Ok(())
    }

    /// This determines what action to take (split a cell or merge two)
    fn reconfigure(&mut self) -> Result<Option<SplitOrMerge>> {
        let mut ret = None;
        // This is just a place-holder to validate the mechanisms. Right now it
        // just flip-flops between splitting Cell 0 and merging Cells 0 and 1
        if self.cells.len() < 2 {
            // Find the best scoring split out of all the Cells.
            for (cell_idx, cell) in self.cells.iter() {
                let split = self.find_best_split(cell, *cell_idx)?;
                if let Some(ref sp) = split {
                    match ret {
                        Some(SplitOrMerge::Split(ref bsp)) if bsp.score > sp.score => {}
                        _ => {
                            ret = split.map(|s| SplitOrMerge::Split(s));
                        }
                    };
                }
            }
        } else {
            // For each cell pair, find the best merge
            let mut best_score = 0.0;
            for ((cell_idx1, cell1), (cell_idx2, cell2)) in self.cells.iter().tuple_combinations() {
                let mut score = 0.0;
                for (_, c1) in cell1.cgroups.iter() {
                    for (_, c2) in cell2.cgroups.iter() {
                        score += self.score_cgroup_pair(c1, c2);
                    }
                }
                if score > best_score {
                    best_score = score;
                    ret = Some(SplitOrMerge::Merge(Merge {
                        cell1: *cell_idx1,
                        cell2: *cell_idx2,
                        score: best_score,
                    }));
                }
            }
        }
        Ok(ret)
    }

    fn allocate_cell(&mut self) -> Result<u32> {
        for i in 0u32..MAX_CELLS as u32 {
            if !self.cells.contains_key(&i) {
                return Ok(i);
            }
        }
        bail!("No free cell available");
    }

    /// Assign CPUs based on per-cell load
    fn assign_cpus(&mut self, total_load: f64) -> Result<()> {
        let max_cpus = self.cpu_pool.nr_cpus - self.cells.len() + 1;
        // Figure out how many cpus each cell should have
        let cells_cpus = self
            .cells
            .iter()
            .map(|(cell_idx, cell)| {
                let cell_load_frac = cell.load / total_load;
                let cell_cpus = cell_load_frac * self.cpu_pool.nr_cpus as f64;
                let cell_cpus_usz = if cell_cpus <= 1.0 {
                    1
                } else if cell_cpus >= max_cpus as f64 {
                    max_cpus
                } else {
                    cell_cpus.round() as usize
                };
                trace!("Allocating {} cpus to Cell {}", cell_cpus_usz, cell_idx);
                (*cell_idx, cell_cpus_usz)
            })
            .collect::<BTreeMap<u32, usize>>();
        // Free first
        for (cell_idx, cpus) in cells_cpus.iter() {
            let cell = self
                .cells
                .get_mut(cell_idx)
                .ok_or(anyhow!("non-existent cell"))?;
            trace!(
                "Cell {} has {} cpus assigned",
                cell_idx,
                cell.cpu_assignment.count_ones()
            );
            while cell.cpu_assignment.count_ones() > *cpus {
                let freed_cpu = self
                    .cpu_pool
                    .free(&mut cell.cpu_assignment)
                    .ok_or(anyhow!("No cpus to free"))?;
                trace!("Freeing {} from Cell {}", freed_cpu, cell_idx);
                self.skel.maps.bss_data.cells[*cell_idx as usize].cpus[freed_cpu / 8] &=
                    !(1 << freed_cpu % 8);
            }
        }
        // Allocate after
        for (cell_idx, cpus) in cells_cpus.iter() {
            let cell = self
                .cells
                .get_mut(cell_idx)
                .ok_or(anyhow!("non-existent cell"))?;
            while cell.cpu_assignment.count_ones() < *cpus {
                let new_cpu = self
                    .cpu_pool
                    .alloc()
                    .ok_or(anyhow!("No cpus to allocate"))?;
                trace!("Allocating {} to Cell {}", new_cpu, cell_idx);
                cell.cpu_assignment.set(new_cpu, true);
                self.skel.maps.bss_data.cells[*cell_idx as usize].cpus[new_cpu / 8] |=
                    1 << new_cpu % 8;
            }
        }
        for (cell_idx, cell) in self.skel.maps.bss_data.cells.iter().enumerate() {
            trace!("Cell {} Cpumask {:X?}", cell_idx, cell.cpus);
        }
        Ok(())
    }

    /// Execute a split, allocating a new cell, assigning cgroups
    fn split(&mut self, split: Split) -> Result<()> {
        trace!("Performing split: {}", split);
        let new_cell_idx = self.allocate_cell()?;
        let mut new_cell_load = 0.0;
        let mut new_cell_pinned_load = 0.0;
        for cg in split.g2.iter() {
            new_cell_load += cg.load;
            new_cell_pinned_load += cg.pinned_load;
            let cg_cell = self
                .cgroup_to_cell
                .get_mut(&cg.name)
                .ok_or(anyhow!("Could not change cell of cgroup to be split"))?;
            *cg_cell = new_cell_idx;
        }
        self.cells.insert(
            new_cell_idx,
            Cell {
                cgroups: split
                    .g2
                    .into_iter()
                    .map(|cg| (cg.name.clone(), cg))
                    .collect(),
                cpu_assignment: bitvec!(0; *NR_POSSIBLE_CPUS),
                load: new_cell_load,
                pinned_load: new_cell_pinned_load,
            },
        );
        let old_cell = self
            .cells
            .get_mut(&split.cell)
            .expect("Cell to split should exist");
        old_cell.cgroups = split
            .g1
            .into_iter()
            .map(|cg| (cg.name.clone(), cg))
            .collect();
        old_cell.load -= new_cell_load;
        old_cell.pinned_load -= new_cell_pinned_load;
        info!(
            "Split from Cell {}, Load: {}, Pinned Load: {}",
            split.cell, old_cell.load, old_cell.pinned_load
        );
        info!(
            "Created new Cell {}, Load: {}, Pinned Load: {}",
            new_cell_idx, new_cell_load, new_cell_pinned_load
        );
        Ok(())
    }

    /// Execute a merge, combining two cells into one
    fn merge(&mut self, merge: Merge) -> Result<()> {
        trace!("Performing Merge: {}", merge);
        let mut cell2 = self
            .cells
            .remove(&merge.cell2)
            .ok_or_else(|| anyhow!("Could not find merge cell {}", merge.cell2))?;
        for (cg, _) in cell2.cgroups.iter() {
            let cg_cell = self
                .cgroup_to_cell
                .get_mut(cg)
                .ok_or_else(|| anyhow!("Could not find cgroup {}", cg))?;
            *cg_cell = merge.cell1;
        }

        let cell1 = self
            .cells
            .get_mut(&merge.cell1)
            .ok_or_else(|| anyhow!("could not find merge cell {}", merge.cell1))?;

        cell1.cgroups.append(&mut cell2.cgroups);
        // XXX: I don't love manipulating the CPU mask here and not in assign_cpus
        for cpu in cell2.cpu_assignment.iter_ones() {
            self.skel.maps.bss_data.cells[merge.cell1 as usize].cpus[cpu / 8] |= 1 << cpu % 8;
            self.skel.maps.bss_data.cells[merge.cell2 as usize].cpus[cpu / 8] &= !(1 << cpu % 8);
        }
        cell1.cpu_assignment |= cell2.cpu_assignment;
        cell1.load += cell2.load;
        cell1.pinned_load += cell2.pinned_load;

        Ok(())
    }

    /// This is largely a placeholder, it views the Cell as a fully-connected
    /// graph of cgroups where edges are the score of the pair (see
    /// score_cgroup_pair) and then identifies the max-cut of that graph.
    fn find_best_split(&self, cell: &Cell, cell_idx: u32) -> Result<Option<Split>> {
        let num_cgroups = cell.cgroups.len();
        let mut best_score = 0.0;
        let mut best_split = None;
        for combo_vec in cell.cgroups.iter().combinations(num_cgroups) {
            for i in 1..(num_cgroups - 2) {
                let mut score = 0.0;
                let (g1, g2) = combo_vec.split_at(i);
                for (_, c1) in g1.iter() {
                    for (_, c2) in g2.iter() {
                        score += self.score_cgroup_pair(c1, c2);
                    }
                }
                if score > best_score {
                    best_score = score;
                    let mut g1: Vec<Cgroup> = g1.iter().map(|(_, c)| (*c).clone()).collect();
                    g1.sort_by(|a, b| b.load.partial_cmp(&a.load).expect("Can't compare loads"));
                    let mut g2: Vec<Cgroup> = g2.iter().map(|(_, c)| (*c).clone()).collect();
                    g2.sort_by(|a, b| b.load.partial_cmp(&a.load).expect("Can't compare loads"));
                    best_split = Some(Split {
                        cell: cell_idx,
                        g1,
                        g2,
                        score,
                    });
                }
            }
        }
        Ok(best_split)
    }

    /// This is a straight-up placeholder - can take into account cgroup tree
    /// distance, weights, etc. The idea is that higher scoring pairs should be
    /// in separate cells.
    fn score_cgroup_pair(&self, c1: &Cgroup, c2: &Cgroup) -> f64 {
        c1.load * c2.load
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
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
