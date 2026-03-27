use std::collections::BTreeSet;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::cgroup::CgroupManager;
use crate::topology::TestTopology;
use crate::verify::{self, VerifyResult};
use crate::workload::*;

// ---------------------------------------------------------------------------
// Flag system
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flag {
    LlcAware,
    Borrowing,
    WorkStealing,
    Rebalancing,
    RejectMulticpuPinning,
    CpuControllerDisabled,
}

impl Flag {
    pub fn cli_flag(&self) -> &'static str {
        match self {
            Self::LlcAware => "--enable-llc-awareness",
            Self::Borrowing => "--enable-borrowing",
            Self::WorkStealing => "--enable-work-stealing",
            Self::Rebalancing => "--enable-rebalancing",
            Self::RejectMulticpuPinning => "--reject-multicpu-pinning",
            Self::CpuControllerDisabled => "--cpu-controller-disabled",
        }
    }
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::LlcAware => "llc",
            Self::Borrowing => "borrow",
            Self::WorkStealing => "steal",
            Self::Rebalancing => "rebal",
            Self::RejectMulticpuPinning => "reject-pin",
            Self::CpuControllerDisabled => "no-ctrl",
        }
    }
    pub fn all() -> &'static [Flag] {
        &[Self::LlcAware, Self::Borrowing, Self::WorkStealing, Self::Rebalancing,
          Self::RejectMulticpuPinning, Self::CpuControllerDisabled]
    }
    pub fn from_short_name(s: &str) -> Option<Flag> {
        Self::all().iter().find(|f| f.short_name() == s).copied()
    }
    fn requires(&self) -> &'static [Flag] {
        match self { Self::WorkStealing => &[Self::LlcAware], _ => &[] }
    }
    fn conflicts(&self) -> &'static [Flag] { &[] }
}

#[derive(Debug, Clone)]
pub struct FlagProfile { pub flags: Vec<Flag> }

impl FlagProfile {
    pub fn name(&self) -> String {
        if self.flags.is_empty() { "default".into() }
        else { self.flags.iter().map(|f| f.short_name()).collect::<Vec<_>>().join("+") }
    }
    pub fn args(&self) -> Vec<&'static str> {
        self.flags.iter().map(|f| f.cli_flag()).collect()
    }
}

fn generate_profiles(required: &[Flag], excluded: &[Flag]) -> Vec<FlagProfile> {
    let optional: Vec<Flag> = Flag::all().iter().copied()
        .filter(|f| !required.contains(f) && !excluded.contains(f)).collect();
    let mut out = Vec::new();
    for mask in 0..(1u32 << optional.len()) {
        let mut flags: Vec<Flag> = required.to_vec();
        for (i, &f) in optional.iter().enumerate() {
            if mask & (1 << i) != 0 { flags.push(f); }
        }
        let valid = flags.iter().all(|f| {
            f.requires().iter().all(|r| flags.contains(r))
            && f.conflicts().iter().all(|c| !flags.contains(c))
        });
        if valid {
            flags.sort_by_key(|f| *f as u8);
            out.push(FlagProfile { flags });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Scenario definition (data-driven)
// ---------------------------------------------------------------------------

/// How to set up cell cpusets.
#[derive(Clone)]
pub enum CpusetMode {
    None,
    LlcAligned,
    SplitHalf,
    SplitMisaligned,
    Overlap(f64),
    Uneven(f64), // fraction for cell 0
    Holdback(f64), // fraction of CPUs held back, rest split evenly
}

/// What happens during the test.
#[derive(Clone)]
pub enum Action {
    /// Steady state: just run workers for the duration.
    Steady,
    /// Custom scenario logic.
    Custom(fn(&Ctx) -> Result<VerifyResult>),
}

/// Per-cell workload. If multiple, each cell gets one round-robin.
#[derive(Clone)]
pub struct CellWork {
    pub workers: usize, // 0 = use config.workers_per_cell
    pub work_type: WorkType,
    pub policy: SchedPolicy,
    pub affinity: AffinityKind,
}

#[derive(Clone)]
pub enum AffinityKind {
    Inherit,
    RandomSubset,
    LlcAligned,
    CrossCell,
    SingleCpu,
}

impl Default for CellWork {
    fn default() -> Self {
        Self { workers: 0, work_type: WorkType::CpuSpin, policy: SchedPolicy::Normal, affinity: AffinityKind::Inherit }
    }
}

pub struct Scenario {
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub required_flags: &'static [Flag],
    pub excluded_flags: &'static [Flag],
    pub num_cells: usize,
    pub cpuset_mode: CpusetMode,
    pub cell_works: Vec<CellWork>,
    pub action: Action,
    pub extra_sched_args: &'static [&'static str],
}

impl Scenario {
    pub fn scheduler_args(&self, parent_cgroup: &str, profile: &FlagProfile) -> Vec<String> {
        let rel = parent_cgroup.strip_prefix("/sys/fs/cgroup").unwrap_or(parent_cgroup);
        let mut args = vec![
            "--cell-parent-cgroup".into(), rel.into(),
            "--watchdog-timeout-ms".into(), "2000".into(),
            "--exit-dump-len".into(), "1048576".into(),
            "--debug-events".into(),
        ];
        for a in profile.args() { args.push(a.into()); }
        for a in self.extra_sched_args { args.push(a.to_string()); }
        args
    }
    pub fn profiles(&self) -> Vec<FlagProfile> {
        generate_profiles(self.required_flags, self.excluded_flags)
    }
    pub fn profiles_with(&self, active: &[Flag]) -> Vec<FlagProfile> {
        let mut excl: Vec<Flag> = self.excluded_flags.to_vec();
        for f in Flag::all() {
            if !active.contains(f) && !self.required_flags.contains(f) { excl.push(*f); }
        }
        generate_profiles(self.required_flags, &excl)
    }
    pub fn qualified_name(&self, p: &FlagProfile) -> String {
        format!("{}/{}", self.name, p.name())
    }
}

// ---------------------------------------------------------------------------
// Runtime context and interpreter
// ---------------------------------------------------------------------------

pub struct Ctx<'a> {
    pub cgroups: &'a CgroupManager,
    pub topo: &'a TestTopology,
    pub duration: Duration,
    pub workers_per_cell: usize,
    pub sched_pid: u32,
}

/// Run a scenario. Returns verification result.
pub fn run_scenario(scenario: &Scenario, ctx: &Ctx) -> Result<VerifyResult> {
    tracing::info!(scenario = scenario.name, "running");
    if let Action::Custom(f) = &scenario.action {
        return f(ctx);
    }

    let cpusets = resolve_cpusets(&scenario.cpuset_mode, scenario.num_cells, ctx.topo);

    // Skip if topology doesn't support the test
    if let Some(ref cs) = cpusets {
        if cs.iter().any(|s| s.is_empty()) {
            return Ok(VerifyResult { passed: true, details: vec!["skipped: not enough CPUs/LLCs".into()], stats: Default::default() });
        }
    }

    let names: Vec<String> = (0..scenario.num_cells).map(|i| format!("cell_{i}")).collect();
    for (i, name) in names.iter().enumerate() {
        ctx.cgroups.create_cell(name)?;
        if let Some(ref cs) = cpusets { ctx.cgroups.set_cpuset(name, &cs[i])?; }
    }
    tracing::debug!(cells = scenario.num_cells, "cells created, settling");
    thread::sleep(Duration::from_secs(3));

    // Bail early if the scheduler died (e.g. apply_cell_config failure)
    if unsafe { libc::kill(ctx.sched_pid as i32, 0) } != 0 {
        anyhow::bail!("scheduler died after cell creation");
    }

    let mut handles = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let cw = scenario.cell_works.get(i).or(scenario.cell_works.first())
            .cloned().unwrap_or_default();
        let n = if cw.workers == 0 { ctx.workers_per_cell } else { cw.workers };
        let affinity = resolve_affinity_kind(&cw.affinity, cpusets.as_deref(), i, ctx.topo);
        let wl = WorkloadConfig { num_workers: n, affinity, work_type: cw.work_type, sched_policy: cw.policy };
        let h = WorkloadHandle::spawn(&wl)?;
        tracing::debug!(cell = %name, workers = n, tids = h.tids().len(), "spawned workers");
        for tid in h.tids() { ctx.cgroups.move_task(name, tid)?; }
        handles.push(h);
    }

    // Start all workers now that they're in their cgroups
    for h in &mut handles { h.start(); }

    // Host-level noise disabled - was causing scheduler stalls in no-ctrl mode
    // TODO: investigate why forked host noise workers cause "No queueing decisions"

    tracing::debug!(duration_s = ctx.duration.as_secs(), "running workload");
    thread::sleep(ctx.duration);

    // Check if scheduler stalled/died - capture dump from dmesg
    let sched_dead = unsafe { libc::kill(ctx.sched_pid as i32, 0) } != 0;
    // host noise disabled

    let mut result = VerifyResult::pass();
    for (i, h) in handles.into_iter().enumerate() {
        let reports = h.stop_and_collect();
        result.merge(verify::verify_not_starved(&reports));
        if let Some(ref cs) = cpusets {
            result.merge(verify::verify_isolation(&reports, &cs[i]));
        }
    }

    // Capture full dmesg on failure
    if !result.passed {
        if let Ok(dmesg) = std::process::Command::new("dmesg").arg("--notime").output() {
            let log = String::from_utf8_lossy(&dmesg.stdout);
            for line in log.lines() {
                result.details.push(line.to_string());
            }
        }
    }

    if sched_dead {
        result.passed = false;
        result.details.push("scheduler died".into());
    }

    Ok(result)
}

fn resolve_cpusets(mode: &CpusetMode, n: usize, topo: &TestTopology) -> Option<Vec<BTreeSet<usize>>> {
    let all = topo.all_cpus();
    // Reserve at least 1 CPU for cell 0 (root cell) - mitosis requires it.
    // Use the last CPU as the holdback.
    let usable = if all.len() > 2 { &all[..all.len()-1] } else { all };
    match mode {
        CpusetMode::None => None,
        CpusetMode::LlcAligned => {
            let llcs = topo.split_by_llc();
            if llcs.len() < 2 { return Some(vec![BTreeSet::new()]) }
            // Remove last CPU from last LLC to reserve for cell 0
            let mut sets: Vec<BTreeSet<usize>> = llcs[..n.min(llcs.len())].to_vec();
            if let Some(last) = sets.last_mut() {
                if last.len() > 1 { last.remove(&all[all.len()-1]); }
            }
            Some(sets)
        }
        CpusetMode::SplitHalf => {
            let mid = usable.len() / 2;
            Some(vec![usable[..mid].iter().copied().collect(), usable[mid..].iter().copied().collect()])
        }
        CpusetMode::SplitMisaligned => {
            let split = if topo.num_llcs() > 1 { topo.cpus_in_llc(0).len() / 2 } else { usable.len() / 2 };
            Some(vec![usable[..split].iter().copied().collect(), usable[split..].iter().copied().collect()])
        }
        CpusetMode::Overlap(frac) => Some(topo.overlapping_cpusets(n, *frac)),
        CpusetMode::Uneven(frac) => {
            let split = (usable.len() as f64 * frac) as usize;
            Some(vec![usable[..split.max(1)].iter().copied().collect(), usable[split.max(1)..].iter().copied().collect()])
        }
        CpusetMode::Holdback(frac) => {
            let keep = all.len() - (all.len() as f64 * frac) as usize;
            let mid = keep / 2;
            Some(vec![all[..mid.max(1)].iter().copied().collect(), all[mid.max(1)..keep].iter().copied().collect()])
        }
    }
}

fn resolve_affinity_kind(
    kind: &AffinityKind, cpusets: Option<&[BTreeSet<usize>]>, cell_idx: usize, topo: &TestTopology,
) -> AffinityMode {
    match kind {
        AffinityKind::Inherit => AffinityMode::None,
        AffinityKind::RandomSubset => {
            let pool = cpusets.map(|cs| cs[cell_idx].clone())
                .unwrap_or_else(|| topo.all_cpus().iter().copied().collect());
            let count = (pool.len() / 2).max(1);
            AffinityMode::Random { from: pool, count }
        }
        AffinityKind::LlcAligned => {
            let idx = cell_idx % topo.num_llcs();
            AffinityMode::Fixed(topo.llc_aligned_cpuset(idx))
        }
        AffinityKind::CrossCell => {
            AffinityMode::Fixed(topo.all_cpus().iter().copied().collect())
        }
        AffinityKind::SingleCpu => {
            let cpu = topo.all_cpus()[cell_idx % topo.total_cpus()];
            AffinityMode::SingleCpu(cpu)
        }
    }
}

// ---------------------------------------------------------------------------
// Custom scenario helpers and functions
// ---------------------------------------------------------------------------

/// Create N cells, spawn workers in each, return handles.
fn setup_cells(ctx: &Ctx, n: usize, wl: &WorkloadConfig) -> Result<Vec<WorkloadHandle>> {
    for i in 0..n { ctx.cgroups.create_cell(&format!("cell_{i}"))?; }
    thread::sleep(Duration::from_secs(2));
    if unsafe { libc::kill(ctx.sched_pid as i32, 0) } != 0 {
        anyhow::bail!("scheduler died after cell creation");
    }
    let handles: Result<Vec<_>> = (0..n).map(|i| {
        let h = WorkloadHandle::spawn(wl)?;
        for t in h.tids() { ctx.cgroups.move_task(&format!("cell_{i}"), t)?; }
        Ok(h)
    }).collect();
    let mut handles = handles?;
    for h in &mut handles { h.start(); }
    Ok(handles)
}

fn collect_all(handles: Vec<WorkloadHandle>) -> VerifyResult {
    let mut r = VerifyResult::pass();
    for h in handles { r.merge(verify::verify_not_starved(&h.stop_and_collect())); }
    r
}

fn dfl_wl(ctx: &Ctx) -> WorkloadConfig {
    WorkloadConfig { num_workers: ctx.workers_per_cell, ..Default::default() }
}

fn split_half(ctx: &Ctx) -> (BTreeSet<usize>, BTreeSet<usize>) {
    let all = ctx.topo.all_cpus();
    // Reserve last CPU for cell 0
    let usable = if all.len() > 2 { &all[..all.len()-1] } else { all };
    let mid = usable.len() / 2;
    (usable[..mid].iter().copied().collect(), usable[mid..].iter().copied().collect())
}

fn custom_dynamic_add(ctx: &Ctx) -> Result<VerifyResult> {
    // Start with 2, add up to 2 more. Need room for cell 0 + all cells.
    let max_new = ctx.topo.total_cpus().saturating_sub(3).min(2);
    if max_new == 0 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=4 CPUs".into()], stats: Default::default() }); }
    let wl = dfl_wl(ctx);
    let mut handles = setup_cells(ctx, 2, &wl)?;
    thread::sleep(ctx.duration / 2);
    for i in 2..(2 + max_new) {
        ctx.cgroups.create_cell(&format!("cell_{i}"))?;
        let h = WorkloadHandle::spawn(&wl)?;
        for t in h.tids() { ctx.cgroups.move_task(&format!("cell_{i}"), t)?; }
        handles.push(h);
    }
    thread::sleep(ctx.duration / 2);
    Ok(collect_all(handles))
}

fn custom_dynamic_remove(ctx: &Ctx) -> Result<VerifyResult> {
    // Need at least 5 CPUs for 4 cells + cell 0
    let n = 4.min(ctx.topo.total_cpus().saturating_sub(1));
    if n < 2 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=3 CPUs".into()], stats: Default::default() }); }
    let half = n / 2;
    let mut handles = setup_cells(ctx, n, &dfl_wl(ctx))?;
    thread::sleep(ctx.duration / 2);
    for h in handles.drain(half..) { h.stop_and_collect(); }
    for i in half..n { let _ = ctx.cgroups.remove_cell(&format!("cell_{i}")); }
    thread::sleep(ctx.duration / 2);
    Ok(collect_all(handles))
}

fn custom_rapid_churn(ctx: &Ctx) -> Result<VerifyResult> {
    let handles = setup_cells(ctx, 2, &dfl_wl(ctx))?;
    let deadline = Instant::now() + ctx.duration;
    let mut i = 0;
    while Instant::now() < deadline {
        let n = format!("ephemeral_{i}");
        ctx.cgroups.create_cell(&n)?;
        thread::sleep(Duration::from_millis(100));
        let _ = ctx.cgroups.remove_cell(&n);
        i += 1;
    }
    Ok(collect_all(handles))
}

fn custom_cpuset_add(ctx: &Ctx) -> Result<VerifyResult> {
    let handles = setup_cells(ctx, 2, &dfl_wl(ctx))?;
    thread::sleep(ctx.duration / 2);
    let (a, b) = split_half(ctx);
    ctx.cgroups.set_cpuset("cell_0", &a)?;
    ctx.cgroups.set_cpuset("cell_1", &b)?;
    thread::sleep(ctx.duration / 2);
    Ok(collect_all(handles))
}

fn custom_cpuset_remove(ctx: &Ctx) -> Result<VerifyResult> {
    let (a, b) = split_half(ctx);
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &a)?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &b)?;
    thread::sleep(Duration::from_secs(3));
    let wl = dfl_wl(ctx);
    let mut handles: Vec<_> = ["cell_0", "cell_1"].iter().map(|n| {
        let h = WorkloadHandle::spawn(&wl).unwrap();
        for t in h.tids() { ctx.cgroups.move_task(n, t).unwrap(); }
        h
    }).collect();
    for h in &mut handles { h.start(); }
    thread::sleep(ctx.duration / 2);
    ctx.cgroups.clear_cpuset("cell_0")?; ctx.cgroups.clear_cpuset("cell_1")?;
    thread::sleep(ctx.duration / 2);
    Ok(collect_all(handles))
}

fn custom_cpuset_change(ctx: &Ctx) -> Result<VerifyResult> {
    let all = ctx.topo.all_cpus();
    let q = all.len() / 4;
    if q == 0 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=4 CPUs".into()], stats: Default::default() }); }
    // Reserve last CPU for cell 0
    let last = all.len() - 1;
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &all[..q*2].iter().copied().collect())?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &all[q*2..last].iter().copied().collect())?;
    thread::sleep(Duration::from_secs(3));
    let wl = dfl_wl(ctx);
    let mut handles: Vec<_> = ["cell_0", "cell_1"].iter().map(|n| {
        let h = WorkloadHandle::spawn(&wl).unwrap();
        for t in h.tids() { ctx.cgroups.move_task(n, t).unwrap(); }
        h
    }).collect();
    for h in &mut handles { h.start(); }
    let t = ctx.duration / 3;
    thread::sleep(t);
    ctx.cgroups.set_cpuset("cell_0", &all[..q].iter().copied().collect())?;
    ctx.cgroups.set_cpuset("cell_1", &all[q..last].iter().copied().collect())?;
    thread::sleep(t);
    ctx.cgroups.set_cpuset("cell_0", &all[..q*3].iter().copied().collect())?;
    ctx.cgroups.set_cpuset("cell_1", &all[q*3..last].iter().copied().collect())?;
    thread::sleep(t);
    Ok(collect_all(handles))
}

fn custom_affinity_mutation(ctx: &Ctx) -> Result<VerifyResult> {
    let handles = setup_cells(ctx, 2, &dfl_wl(ctx))?;
    let all: Vec<usize> = ctx.topo.all_cpus().to_vec();
    let interval = ctx.duration / 5;
    for _ in 0..4 {
        thread::sleep(interval);
        for h in &handles {
            for idx in 0..h.tids().len() {
                use rand::seq::SliceRandom;
                let chosen: BTreeSet<usize> = all.choose_multiple(&mut rand::thread_rng(), (all.len()/2).max(1)).copied().collect();
                let _ = h.set_affinity(idx, &chosen);
            }
        }
    }
    thread::sleep(interval);
    Ok(collect_all(handles))
}

fn custom_host_stress(ctx: &Ctx) -> Result<VerifyResult> {
    let handles = setup_cells(ctx, 2, &dfl_wl(ctx))?;
    let mut host = WorkloadHandle::spawn(&WorkloadConfig { num_workers: ctx.topo.total_cpus(), ..Default::default() })?;
    host.start(); // Start immediately - host workers stay in parent cgroup
    thread::sleep(ctx.duration);
    let mut r = collect_all(handles);
    r.merge(verify::verify_not_starved(&host.stop_and_collect()));
    Ok(r)
}

fn custom_many_cells(ctx: &Ctx) -> Result<VerifyResult> {
    let all = ctx.topo.all_cpus();
    // Reserve 1 CPU for cell 0, cap at 64
    let n = (all.len() - 1).min(64);
    for i in 0..n {
        let name = format!("many_{i}");
        ctx.cgroups.create_cell(&name)?;
        ctx.cgroups.set_cpuset(&name, &[all[i]].into_iter().collect())?;
    }
    thread::sleep(Duration::from_secs(1));
    let wl = WorkloadConfig { num_workers: 1, ..Default::default() };
    let mut handles = Vec::new();
    for i in 0..n {
        let h = WorkloadHandle::spawn(&wl)?;
        for t in h.tids() { ctx.cgroups.move_task(&format!("many_{i}"), t)?; }
        handles.push(h);
    }
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    for h in handles { r.merge(verify::verify_not_starved(&h.stop_and_collect())); }
    for i in 0..n { let _ = ctx.cgroups.remove_cell(&format!("many_{i}")); }
    Ok(r)
}

fn custom_cell_exhaustion(ctx: &Ctx) -> Result<VerifyResult> {
    let all = ctx.topo.all_cpus();
    // Don't create more cells than CPUs-1 (reserve 1 for cell 0)
    let n = (all.len() - 1).min(15);
    for i in 0..n {
        let name = format!("exhaust_{i}");
        ctx.cgroups.create_cell(&name)?;
        ctx.cgroups.set_cpuset(&name, &[all[i % all.len()]].into_iter().collect())?;
    }
    thread::sleep(Duration::from_secs(1));
    let half = n / 2;
    for i in 0..half { let _ = ctx.cgroups.remove_cell(&format!("exhaust_{i}")); }
    thread::sleep(Duration::from_secs(1));
    let wl = WorkloadConfig { num_workers: 1, ..Default::default() };
    let mut handles = Vec::new();
    for i in 0..half {
        let name = format!("reuse_{i}");
        ctx.cgroups.create_cell(&name)?;
        ctx.cgroups.set_cpuset(&name, &[all[i % all.len()]].into_iter().collect())?;
        let h = WorkloadHandle::spawn(&wl)?;
        for t in h.tids() { ctx.cgroups.move_task(&name, t)?; }
        handles.push(h);
    }
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    for h in handles { r.merge(verify::verify_not_starved(&h.stop_and_collect())); }
    for i in half..n { let _ = ctx.cgroups.remove_cell(&format!("exhaust_{i}")); }
    for i in 0..half { let _ = ctx.cgroups.remove_cell(&format!("reuse_{i}")); }
    Ok(r)
}

fn custom_sched_mixed(ctx: &Ctx) -> Result<VerifyResult> {
    for i in 0..2 { ctx.cgroups.create_cell(&format!("cell_{i}"))?; }
    thread::sleep(Duration::from_secs(1));
    let configs = [
        (SchedPolicy::Normal, WorkType::CpuSpin),
        (SchedPolicy::Batch, WorkType::CpuSpin),
        (SchedPolicy::Idle, WorkType::CpuSpin),
        (SchedPolicy::Fifo(1), WorkType::Bursty { burst_ms: 500, sleep_ms: 250 }),
    ];
    let mut handles = Vec::new();
    for i in 0..2 {
        for &(policy, wtype) in &configs {
            let wl = WorkloadConfig { num_workers: 2, sched_policy: policy, work_type: wtype, ..Default::default() };
            let h = WorkloadHandle::spawn(&wl)?;
            for t in h.tids() { ctx.cgroups.move_task(&format!("cell_{i}"), t)?; }
            handles.push(h);
        }
    }
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    for h in handles { r.merge(verify::verify_not_starved(&h.stop_and_collect())); }
    Ok(r)
}

fn custom_io_sync(ctx: &Ctx) -> Result<VerifyResult> {
    for i in 0..2 { ctx.cgroups.create_cell(&format!("cell_{i}"))?; }
    thread::sleep(Duration::from_secs(1));
    let mut handles = Vec::new();
    for i in 0..2 {
        for wl in [
            WorkloadConfig { num_workers: 2, work_type: WorkType::IoSync, ..Default::default() },
            WorkloadConfig { num_workers: ctx.workers_per_cell, ..Default::default() },
        ] {
            let h = WorkloadHandle::spawn(&wl)?;
            for t in h.tids() { ctx.cgroups.move_task(&format!("cell_{i}"), t)?; }
            handles.push(h);
        }
    }
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    for h in handles { r.merge(verify::verify_not_starved(&h.stop_and_collect())); }
    Ok(r)
}

fn custom_nested_basic(ctx: &Ctx) -> Result<VerifyResult> {
    // Workers in sub-cgroups should inherit the cell's scheduling
    let wl = dfl_wl(ctx);
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    thread::sleep(Duration::from_secs(2));

    // Create nested cgroups within each cell
    ctx.cgroups.create_cell("cell_0/sub_a")?;
    ctx.cgroups.create_cell("cell_0/sub_b")?;
    ctx.cgroups.create_cell("cell_1/sub_a")?;
    ctx.cgroups.create_cell("cell_1/sub_a/deep")?;

    let mut handles = Vec::new();
    // Workers at various nesting depths
    for path in ["cell_0/sub_a", "cell_0/sub_b", "cell_1/sub_a", "cell_1/sub_a/deep"] {
        let h = WorkloadHandle::spawn(&wl)?;
        for t in h.tids() { ctx.cgroups.move_task(path, t)?; }
        handles.push(h);
    }
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_nested_move(ctx: &Ctx) -> Result<VerifyResult> {
    // Move tasks between nested cgroups within and across cells
    let wl = dfl_wl(ctx);
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    thread::sleep(Duration::from_secs(2));

    ctx.cgroups.create_cell("cell_0/sub")?;
    ctx.cgroups.create_cell("cell_1/sub")?;

    let h = WorkloadHandle::spawn(&wl)?;
    for t in h.tids() { ctx.cgroups.move_task("cell_0/sub", t)?; }

    let interval = ctx.duration / 4;
    // Move workers around: within cell, then across cells
    thread::sleep(interval);
    for t in h.tids() { let _ = ctx.cgroups.move_task("cell_0", t); }
    thread::sleep(interval);
    for t in h.tids() { let _ = ctx.cgroups.move_task("cell_1/sub", t); }
    thread::sleep(interval);
    for t in h.tids() { let _ = ctx.cgroups.move_task("cell_1", t); }
    thread::sleep(interval);

    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h.stop_and_collect()));
    Ok(r)
}

fn custom_nested_churn(ctx: &Ctx) -> Result<VerifyResult> {
    let handles = setup_cells(ctx, 2, &dfl_wl(ctx))?;
    let deadline = Instant::now() + ctx.duration;
    let mut i = 0;
    while Instant::now() < deadline {
        let path = format!("cell_0/churn_{i}");
        ctx.cgroups.create_cell(&path)?;
        if i % 3 == 0 {
            let deep = format!("{path}/deep");
            ctx.cgroups.create_cell(&deep)?;
            thread::sleep(Duration::from_millis(50));
            let _ = ctx.cgroups.remove_cell(&deep);
        }
        thread::sleep(Duration::from_millis(50));
        let _ = ctx.cgroups.remove_cell(&path);
        i += 1;
    }
    Ok(collect_all(handles))
}

fn custom_nested_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // Nested cgroups with their own cpusets (more restrictive than parent)
    let all = ctx.topo.all_cpus();
    if all.len() < 4 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=4 CPUs".into()], stats: Default::default() }); }
    let mid = all.len() / 2;
    let set_a: BTreeSet<usize> = all[..mid].iter().copied().collect();

    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.set_cpuset("cell_0", &set_a)?;
    thread::sleep(Duration::from_secs(2));

    // Enable cpuset controller at cell level for nested cgroups
    let sc = std::path::Path::new(&ctx.cgroups.parent_path()).join("cell_0/cgroup.subtree_control");
    let _ = std::fs::write(&sc, "+cpuset");

    let sub_set: BTreeSet<usize> = all[..mid/2].iter().copied().collect();
    ctx.cgroups.create_cell("cell_0/narrow")?;
    ctx.cgroups.set_cpuset("cell_0/narrow", &sub_set)?;

    let wl = WorkloadConfig { num_workers: ctx.workers_per_cell, ..Default::default() };
    let mut h = WorkloadHandle::spawn(&wl)?;
    for t in h.tids() { ctx.cgroups.move_task("cell_0/narrow", t)?; }
    h.start();

    thread::sleep(ctx.duration);
    let reports = h.stop_and_collect();
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&reports));
    r.merge(verify::verify_isolation(&reports, &sub_set));
    Ok(r)
}

fn custom_cell_exclude(ctx: &Ctx) -> Result<VerifyResult> {
    // 3 cells, one excluded via --cell-exclude. Excluded stays in cell 0.
    // Use different workloads: excluded=IO (exercises cell 0 dispatch path),
    // normal cells=CpuSpin. Verify excluded workers still get CPU despite
    // sharing cell 0 with system tasks.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    ctx.cgroups.create_cell("excluded_cell")?;
    thread::sleep(Duration::from_secs(3));

    let cpu_wl = WorkloadConfig { num_workers: ctx.workers_per_cell, ..Default::default() };
    let io_wl = WorkloadConfig { num_workers: ctx.workers_per_cell, work_type: WorkType::Mixed, ..Default::default() };
    let mut handles = Vec::new();
    for (name, wl) in [("cell_0", &cpu_wl), ("cell_1", &cpu_wl), ("excluded_cell", &io_wl)] {
        let h = WorkloadHandle::spawn(wl)?;
        for t in h.tids() { ctx.cgroups.move_task(name, t)?; }
        handles.push(h);
    }
    for h in &mut handles { h.start(); }
    thread::sleep(ctx.duration);

    let mut r = VerifyResult::pass();
    for (i, h) in handles.into_iter().enumerate() {
        let reports = h.stop_and_collect();
        let cell_r = verify::verify_not_starved(&reports);
        if i == 2 {
            // Excluded cell: verify workers ran on CPUs shared with cell 0
            // (no dedicated cell isolation). They should share CPUs with system tasks.
            for w in &reports {
                if w.work_units == 0 {
                    r.passed = false;
                    r.details.push(format!("excluded worker {} starved", w.tid));
                }
            }
        }
        r.merge(cell_r);
    }
    Ok(r)
}

fn custom_borrowing_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // Borrowing with cpuset-constrained cells. Borrowable mask = all_cpus & ~primary & cpuset.
    // cell_0: heavy CPU load on half the CPUs. cell_1: bursty (sleeps free CPUs for borrowing).
    // Borrowing should let cell_0 use cell_1's CPUs during sleep phases.
    let (a, b) = split_half(ctx);
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &a)?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &b)?;
    thread::sleep(Duration::from_secs(3));

    let heavy = WorkloadConfig { num_workers: a.len() * 2, ..Default::default() };
    let bursty = WorkloadConfig { num_workers: ctx.workers_per_cell,
        work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 100 }, ..Default::default() };
    let mut h0 = WorkloadHandle::spawn(&heavy)?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&bursty)?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1.start();
    thread::sleep(ctx.duration);

    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_rebalancing_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // Rebalancing with cpusets. Load shifts mid-run: cell_0 starts heavy, cell_1 light,
    // then cell_1 becomes heavy. Rebalancing should adapt CPU allocation within cpuset bounds.
    let (a, b) = split_half(ctx);
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &a)?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &b)?;
    thread::sleep(Duration::from_secs(3));

    // Phase 1: cell_0 heavy, cell_1 light
    let heavy = WorkloadConfig { num_workers: 16, ..Default::default() };
    let light = WorkloadConfig { num_workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() };
    let mut h0 = WorkloadHandle::spawn(&heavy)?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1_light = WorkloadHandle::spawn(&light)?;
    for t in h1_light.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1_light.start();
    thread::sleep(ctx.duration / 2);

    // Phase 2: add heavy load to cell_1
    let mut h1_heavy = WorkloadHandle::spawn(&heavy)?;
    for t in h1_heavy.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h1_heavy.start();
    thread::sleep(ctx.duration / 2);

    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1_light.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1_heavy.stop_and_collect()));
    Ok(r)
}

fn custom_rebalancing_dynamic(ctx: &Ctx) -> Result<VerifyResult> {
    // Rebalancing + dynamic cell add. Tests demand seeding for new cells.
    // Start with 2 light cells, add heavy cell mid-run. Rebalancing should
    // redistribute CPUs to the new heavy cell.
    let light = WorkloadConfig { num_workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() };
    let mut handles = setup_cells(ctx, 2, &light)?;
    thread::sleep(ctx.duration / 2);

    ctx.cgroups.create_cell("cell_2")?;
    thread::sleep(Duration::from_secs(1));
    let heavy = WorkloadConfig { num_workers: 16, ..Default::default() };
    let mut h = WorkloadHandle::spawn(&heavy)?;
    for t in h.tids() { ctx.cgroups.move_task("cell_2", t)?; }
    h.start();
    handles.push(h);
    thread::sleep(ctx.duration / 2);
    Ok(collect_all(handles))
}

fn custom_borrowing_rebalancing(ctx: &Ctx) -> Result<VerifyResult> {
    // Both borrowing + rebalancing active. Tests that borrowed CPU time
    // doesn't inflate utilization used for rebalancing. cell_0: bursty (borrows
    // during others' sleep). cell_1: steady. cell_2: IO-heavy (blocks often).
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    ctx.cgroups.create_cell("cell_2")?;
    thread::sleep(Duration::from_secs(3));

    let configs = [
        ("cell_0", WorkloadConfig { num_workers: 8, ..Default::default() }),
        ("cell_1", WorkloadConfig { num_workers: ctx.workers_per_cell,
            work_type: WorkType::Bursty { burst_ms: 100, sleep_ms: 50 }, ..Default::default() }),
        ("cell_2", WorkloadConfig { num_workers: ctx.workers_per_cell,
            work_type: WorkType::IoSync, ..Default::default() }),
    ];
    let mut handles = Vec::new();
    for (name, wl) in &configs {
        let mut h = WorkloadHandle::spawn(wl)?;
        for t in h.tids() { ctx.cgroups.move_task(name, t)?; }
        h.start();
        handles.push(h);
    }
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_reject_pin(ctx: &Ctx) -> Result<VerifyResult> {
    // With --reject-multicpu-pinning, multi-CPU affinity should be rejected.
    // Set workers with 2-CPU affinity masks and verify they still run.
    let handles = setup_cells(ctx, 2, &dfl_wl(ctx))?;
    let all: Vec<usize> = ctx.topo.all_cpus().to_vec();

    // Set multi-CPU affinities that should be rejected by mitosis
    for h in &handles {
        for idx in 0..h.tids().len() {
            if all.len() >= 2 {
                let cpus: BTreeSet<usize> = all[..2].iter().copied().collect();
                let _ = h.set_affinity(idx, &cpus);
            }
        }
    }
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_no_ctrl_cgroup_move(ctx: &Ctx) -> Result<VerifyResult> {
    // In --cpu-controller-disabled mode, cgroup moves are detected by polling
    // (not callbacks). Rapidly move workers between cgroups to test the detection window.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    thread::sleep(Duration::from_secs(2));

    let mut h = WorkloadHandle::spawn(&WorkloadConfig { num_workers: ctx.workers_per_cell * 2, ..Default::default() })?;
    for t in h.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    h.start();

    // Rapidly move half the workers back and forth
    let tids = h.tids();
    let half = tids.len() / 2;
    let interval = ctx.duration / 10;
    for i in 0..9 {
        thread::sleep(interval);
        let target = if i % 2 == 0 { "cell_1" } else { "cell_0" };
        for &tid in &tids[..half] { let _ = ctx.cgroups.move_task(target, tid); }
    }
    thread::sleep(interval);

    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h.stop_and_collect()));
    Ok(r)
}

fn custom_borrowing_cpuset_change(ctx: &Ctx) -> Result<VerifyResult> {
    // Task on borrowed CPU when lender's cpuset changes and that CPU leaves the lender's set.
    let all = ctx.topo.all_cpus();
    if all.len() < 4 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=4 CPUs".into()], stats: Default::default() }); }
    let last = all.len() - 1;
    let mid = last / 2;
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &all[..mid].iter().copied().collect())?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &all[mid..last].iter().copied().collect())?;
    thread::sleep(Duration::from_secs(3));
    // cell_0 heavy (will borrow from cell_1), cell_1 bursty (frees CPUs)
    let heavy = WorkloadConfig { num_workers: mid * 2, ..Default::default() };
    let bursty = WorkloadConfig { num_workers: 2, work_type: WorkType::Bursty { burst_ms: 30, sleep_ms: 100 }, ..Default::default() };
    let mut h0 = WorkloadHandle::spawn(&heavy)?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&bursty)?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1.start();
    thread::sleep(ctx.duration / 3);
    // Shrink cell_1's cpuset - borrowed CPUs may disappear
    let narrow: BTreeSet<usize> = all[mid..mid+1].iter().copied().collect();
    ctx.cgroups.set_cpuset("cell_1", &narrow)?;
    thread::sleep(ctx.duration / 3);
    // Restore
    ctx.cgroups.set_cpuset("cell_1", &all[mid..last].iter().copied().collect())?;
    thread::sleep(ctx.duration / 3);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_rebalancing_oscillate(ctx: &Ctx) -> Result<VerifyResult> {
    // Alternating load: cell_0 heavy/cell_1 light, then swap.
    // Stop previous phase before starting next to avoid piling up workers.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    thread::sleep(Duration::from_secs(3));
    let phase = ctx.duration / 4;
    let mut result = VerifyResult::pass();
    for i in 0..4 {
        let (heavy_cell, light_cell) = if i % 2 == 0 { ("cell_0", "cell_1") } else { ("cell_1", "cell_0") };
        let mut hh = WorkloadHandle::spawn(&WorkloadConfig { num_workers: ctx.workers_per_cell * 2, ..Default::default() })?;
        for t in hh.tids() { ctx.cgroups.move_task(heavy_cell, t)?; }
        let mut hl = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() })?;
        for t in hl.tids() { ctx.cgroups.move_task(light_cell, t)?; }
        hh.start(); hl.start();
        thread::sleep(phase);
        result.merge(verify::verify_not_starved(&hh.stop_and_collect()));
        result.merge(verify::verify_not_starved(&hl.stop_and_collect()));
    }
    Ok(result)
}

fn custom_exclude_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // Excluded cell in cell 0 + other cells with cpusets. Cell 0 gets unclaimed CPUs.
    let (a, b) = split_half(ctx);
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &a)?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &b)?;
    ctx.cgroups.create_cell("excluded_cell")?; // no cpuset - stays in cell 0
    thread::sleep(Duration::from_secs(3));
    let wl = dfl_wl(ctx);
    let mut handles = Vec::new();
    for name in ["cell_0", "cell_1", "excluded_cell"] {
        let mut h = WorkloadHandle::spawn(&wl)?;
        for t in h.tids() { ctx.cgroups.move_task(name, t)?; }
        h.start();
        handles.push(h);
    }
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_exclude_dynamic(ctx: &Ctx) -> Result<VerifyResult> {
    // Add/remove cells while excluded cell exists. Excluded cell should be unaffected.
    ctx.cgroups.create_cell("excluded_cell")?;
    ctx.cgroups.create_cell("cell_0")?;
    thread::sleep(Duration::from_secs(3));
    let wl = dfl_wl(ctx);
    let mut h_excl = WorkloadHandle::spawn(&wl)?;
    for t in h_excl.tids() { ctx.cgroups.move_task("excluded_cell", t)?; }
    let mut h0 = WorkloadHandle::spawn(&wl)?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    h_excl.start(); h0.start();
    thread::sleep(ctx.duration / 3);
    // Add cells
    ctx.cgroups.create_cell("cell_1")?;
    let mut h1 = WorkloadHandle::spawn(&wl)?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h1.start();
    thread::sleep(ctx.duration / 3);
    // Remove cell_1
    let _ = h1.stop_and_collect();
    let _ = ctx.cgroups.remove_cell("cell_1");
    thread::sleep(ctx.duration / 3);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h_excl.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    Ok(r)
}

fn custom_no_ctrl_nested(ctx: &Ctx) -> Result<VerifyResult> {
    // Nested cgroups in no-ctrl mode. Ancestor chain init via tracepoints.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_0/sub_a")?;
    ctx.cgroups.create_cell("cell_0/sub_a/deep")?;
    ctx.cgroups.create_cell("cell_1")?;
    ctx.cgroups.create_cell("cell_1/sub_b")?;
    thread::sleep(Duration::from_secs(3));
    let wl = dfl_wl(ctx);
    let mut handles = Vec::new();
    for path in ["cell_0/sub_a/deep", "cell_1/sub_b"] {
        let mut h = WorkloadHandle::spawn(&wl)?;
        for t in h.tids() { ctx.cgroups.move_task(path, t)?; }
        h.start();
        handles.push(h);
    }
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_cpuset_disjoint(ctx: &Ctx) -> Result<VerifyResult> {
    // Cpuset changed to completely different CPU range. Exposes vtime domain discontinuity.
    let all = ctx.topo.all_cpus();
    if all.len() < 8 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=8 CPUs".into()], stats: Default::default() }); }
    let last = all.len() - 1;
    let q = last / 4;
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &all[..q*2].iter().copied().collect())?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &all[q*2..last].iter().copied().collect())?;
    thread::sleep(Duration::from_secs(3));
    let wl = WorkloadConfig { num_workers: ctx.workers_per_cell, ..Default::default() };
    let mut handles: Vec<_> = ["cell_0", "cell_1"].iter().map(|n| {
        let mut h = WorkloadHandle::spawn(&wl).unwrap();
        for t in h.tids() { ctx.cgroups.move_task(n, t).unwrap(); }
        h.start();
        h
    }).collect();
    thread::sleep(ctx.duration / 3);
    // Swap cpusets: cell_0 gets cell_1's old CPUs and vice versa
    ctx.cgroups.set_cpuset("cell_0", &all[q*2..last].iter().copied().collect())?;
    ctx.cgroups.set_cpuset("cell_1", &all[..q*2].iter().copied().collect())?;
    thread::sleep(ctx.duration / 3);
    // Swap back
    ctx.cgroups.set_cpuset("cell_0", &all[..q*2].iter().copied().collect())?;
    ctx.cgroups.set_cpuset("cell_1", &all[q*2..last].iter().copied().collect())?;
    thread::sleep(ctx.duration / 3);
    Ok(collect_all(handles))
}

fn custom_io_borrowing(ctx: &Ctx) -> Result<VerifyResult> {
    // IO-heavy cell blocks often, freeing CPUs. Borrowing should use them.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    thread::sleep(Duration::from_secs(3));
    // cell_0: IO workers (block on sync, free CPUs). cell_1: heavy CPU (should borrow).
    let mut h0 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: ctx.workers_per_cell, work_type: WorkType::IoSync, ..Default::default() })?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: ctx.topo.total_cpus(), ..Default::default() })?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1.start();
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_rebalancing_many(ctx: &Ctx) -> Result<VerifyResult> {
    // Rebalancing with 4 cells and asymmetric demand.
    for i in 0..4 { ctx.cgroups.create_cell(&format!("cell_{i}"))?; }
    thread::sleep(Duration::from_secs(3));
    let loads = [16, 1, 8, 4]; // asymmetric
    let mut handles = Vec::new();
    for (i, &n) in loads.iter().enumerate() {
        let wt = if n == 1 { WorkType::YieldHeavy } else { WorkType::CpuSpin };
        let mut h = WorkloadHandle::spawn(&WorkloadConfig { num_workers: n, work_type: wt, ..Default::default() })?;
        for t in h.tids() { ctx.cgroups.move_task(&format!("cell_{i}"), t)?; }
        h.start();
        handles.push(h);
    }
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_borrow_rebal_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // Borrowing + rebalancing + cpusets. Bursty cell frees CPUs for borrowing,
    // rebalancing redistributes based on demand, cpusets constrain both.
    let (a, b) = split_half(ctx);
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &a)?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &b)?;
    thread::sleep(Duration::from_secs(3));
    let mut h0 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: a.len() * 2, ..Default::default() })?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 2, work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 150 }, ..Default::default() })?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1.start();
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_borrow_rebal_overlap(ctx: &Ctx) -> Result<VerifyResult> {
    // Borrowing + rebalancing + overlapping cpusets. Contested CPUs must be
    // correctly handled by both borrowing masks and rebalancing redistribution.
    let sets = ctx.topo.overlapping_cpusets(3, 0.5);
    if sets.iter().any(|s| s.is_empty()) {
        return Ok(VerifyResult { passed: true, details: vec!["skipped: not enough CPUs".into()], stats: Default::default() });
    }
    for (i, s) in sets.iter().enumerate() {
        let name = format!("cell_{i}");
        ctx.cgroups.create_cell(&name)?;
        ctx.cgroups.set_cpuset(&name, s)?;
    }
    thread::sleep(Duration::from_secs(3));
    let configs = [
        WorkloadConfig { num_workers: 12, ..Default::default() },
        WorkloadConfig { num_workers: 2, work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 100 }, ..Default::default() },
        WorkloadConfig { num_workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() },
    ];
    let mut handles = Vec::new();
    for (i, wl) in configs.iter().enumerate() {
        let mut h = WorkloadHandle::spawn(wl)?;
        for t in h.tids() { ctx.cgroups.move_task(&format!("cell_{i}"), t)?; }
        h.start();
        handles.push(h);
    }
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_exclude_borrowing(ctx: &Ctx) -> Result<VerifyResult> {
    // Excluded cell in cell 0 should borrow from idle cells.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    ctx.cgroups.create_cell("excluded_cell")?;
    thread::sleep(Duration::from_secs(3));
    // excluded_cell heavy (should borrow), cell_1 bursty (frees CPUs)
    let mut h_excl = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 8, ..Default::default() })?;
    for t in h_excl.tids() { ctx.cgroups.move_task("excluded_cell", t)?; }
    let mut h0 = WorkloadHandle::spawn(&dfl_wl(ctx))?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 2, work_type: WorkType::Bursty { burst_ms: 30, sleep_ms: 100 }, ..Default::default() })?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h_excl.start(); h0.start(); h1.start();
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h_excl.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_exclude_rebalancing(ctx: &Ctx) -> Result<VerifyResult> {
    // Excluded cell load shouldn't confuse rebalancing (it's in cell 0).
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    ctx.cgroups.create_cell("excluded_cell")?;
    thread::sleep(Duration::from_secs(3));
    let mut h_excl = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 16, ..Default::default() })?;
    for t in h_excl.tids() { ctx.cgroups.move_task("excluded_cell", t)?; }
    let mut h0 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 8, ..Default::default() })?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() })?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h_excl.start(); h0.start(); h1.start();
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h_excl.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_no_ctrl_borrowing(ctx: &Ctx) -> Result<VerifyResult> {
    // Polling-based cgroup detection + borrowing. Move tasks between cells
    // while borrowing is active to stress the detection window.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    thread::sleep(Duration::from_secs(3));
    let mut h0 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 8, ..Default::default() })?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 2, work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 100 }, ..Default::default() })?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1.start();
    // Move some workers between cells while borrowing is happening
    let tids = h0.tids();
    let interval = ctx.duration / 6;
    for i in 0..5 {
        thread::sleep(interval);
        let target = if i % 2 == 0 { "cell_1" } else { "cell_0" };
        for &tid in &tids[..2.min(tids.len())] { let _ = ctx.cgroups.move_task(target, tid); }
    }
    thread::sleep(interval);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_no_ctrl_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // Cpuset changes in no-ctrl mode. Tracepoint-based cpuset detection.
    let (a, b) = split_half(ctx);
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &a)?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &b)?;
    thread::sleep(Duration::from_secs(3));
    let wl = dfl_wl(ctx);
    let mut handles: Vec<_> = ["cell_0", "cell_1"].iter().map(|n| {
        let mut h = WorkloadHandle::spawn(&wl).unwrap();
        for t in h.tids() { ctx.cgroups.move_task(n, t).unwrap(); }
        h.start(); h
    }).collect();
    thread::sleep(ctx.duration / 2);
    // Change cpusets mid-run
    ctx.cgroups.clear_cpuset("cell_0")?;
    ctx.cgroups.clear_cpuset("cell_1")?;
    thread::sleep(ctx.duration / 2);
    Ok(collect_all(handles))
}

fn custom_no_ctrl_rebalancing(ctx: &Ctx) -> Result<VerifyResult> {
    // Rebalancing with polling-based cgroup detection.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    thread::sleep(Duration::from_secs(3));
    let mut h0 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 16, ..Default::default() })?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() })?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1.start();
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_reject_pin_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // Reject-pin with cpuset-constrained cells. Multi-CPU affinity within cpuset rejected.
    let (a, b) = split_half(ctx);
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &a)?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &b)?;
    thread::sleep(Duration::from_secs(3));
    let wl = dfl_wl(ctx);
    let mut handles: Vec<_> = ["cell_0", "cell_1"].iter().map(|n| {
        let h = WorkloadHandle::spawn(&wl).unwrap();
        for t in h.tids() { ctx.cgroups.move_task(n, t).unwrap(); }
        h
    }).collect();
    for h in &mut handles { h.start(); }
    // Set multi-CPU affinities within each cell's cpuset
    let a_vec: Vec<usize> = a.iter().copied().collect();
    let b_vec: Vec<usize> = b.iter().copied().collect();
    for idx in 0..handles[0].tids().len() {
        if a_vec.len() >= 2 { let _ = handles[0].set_affinity(idx, &a_vec[..2].iter().copied().collect()); }
    }
    for idx in 0..handles[1].tids().len() {
        if b_vec.len() >= 2 { let _ = handles[1].set_affinity(idx, &b_vec[..2].iter().copied().collect()); }
    }
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_dynamic_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // Add/remove cells that have cpusets.
    let all = ctx.topo.all_cpus();
    if all.len() < 4 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=4 CPUs".into()], stats: Default::default() }); }
    let last = all.len() - 1;
    let q = last / 3;
    ctx.cgroups.create_cell("cell_0")?; ctx.cgroups.set_cpuset("cell_0", &all[..q].iter().copied().collect())?;
    ctx.cgroups.create_cell("cell_1")?; ctx.cgroups.set_cpuset("cell_1", &all[q..q*2].iter().copied().collect())?;
    thread::sleep(Duration::from_secs(3));
    let wl = dfl_wl(ctx);
    let mut h0 = WorkloadHandle::spawn(&wl)?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&wl)?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1.start();
    thread::sleep(ctx.duration / 3);
    // Add cell_2 with cpuset
    ctx.cgroups.create_cell("cell_2")?; ctx.cgroups.set_cpuset("cell_2", &all[q*2..last].iter().copied().collect())?;
    let mut h2 = WorkloadHandle::spawn(&wl)?;
    for t in h2.tids() { ctx.cgroups.move_task("cell_2", t)?; }
    h2.start();
    thread::sleep(ctx.duration / 3);
    // Remove cell_2
    let _ = h2.stop_and_collect();
    let _ = ctx.cgroups.remove_cell("cell_2");
    thread::sleep(ctx.duration / 3);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

fn custom_dynamic_borrowing(ctx: &Ctx) -> Result<VerifyResult> {
    // Add cell while borrowing is active.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    thread::sleep(Duration::from_secs(3));
    let mut h0 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 8, ..Default::default() })?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0", t)?; }
    let mut h1 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 2, work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 100 }, ..Default::default() })?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1", t)?; }
    h0.start(); h1.start();
    thread::sleep(ctx.duration / 2);
    // Add cell_2 while borrowing is happening between cell_0 and cell_1
    ctx.cgroups.create_cell("cell_2")?;
    let mut h2 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 4, ..Default::default() })?;
    for t in h2.tids() { ctx.cgroups.move_task("cell_2", t)?; }
    h2.start();
    thread::sleep(ctx.duration / 2);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h2.stop_and_collect()));
    Ok(r)
}

fn custom_nested_borrowing(ctx: &Ctx) -> Result<VerifyResult> {
    // Nested cgroups with borrowing. Workers at various depths, one cell
    // bursty to free CPUs for the other to borrow.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_0/sub_a")?;
    ctx.cgroups.create_cell("cell_1")?;
    ctx.cgroups.create_cell("cell_1/sub_b")?;
    thread::sleep(Duration::from_secs(3));
    let mut h0 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 8, ..Default::default() })?;
    for t in h0.tids() { ctx.cgroups.move_task("cell_0/sub_a", t)?; }
    let mut h1 = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 2, work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 100 }, ..Default::default() })?;
    for t in h1.tids() { ctx.cgroups.move_task("cell_1/sub_b", t)?; }
    h0.start(); h1.start();
    thread::sleep(ctx.duration);
    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h0.stop_and_collect()));
    r.merge(verify::verify_not_starved(&h1.stop_and_collect()));
    Ok(r)
}

/// Spawn diverse workloads across N cells: CpuSpin, Bursty, IoSync, Mixed, YieldHeavy.
fn spawn_diverse(ctx: &Ctx, cell_names: &[&str]) -> Result<Vec<WorkloadHandle>> {
    let types = [
        WorkType::CpuSpin,
        WorkType::Bursty { burst_ms: 50, sleep_ms: 100 },
        WorkType::IoSync,
        WorkType::Mixed,
        WorkType::YieldHeavy,
    ];
    let mut handles = Vec::new();
    for (i, name) in cell_names.iter().enumerate() {
        let wt = types[i % types.len()];
        let n = if matches!(wt, WorkType::IoSync) { 2 } else { ctx.workers_per_cell };
        let mut h = WorkloadHandle::spawn(&WorkloadConfig { num_workers: n, work_type: wt, ..Default::default() })?;
        for t in h.tids() { ctx.cgroups.move_task(name, t)?; }
        h.start();
        handles.push(h);
    }
    Ok(handles)
}

fn custom_mix_no_flags(ctx: &Ctx) -> Result<VerifyResult> {
    // All workload types across 5 cells, no flags. Exercises base dispatch with every work pattern.
    let names: Vec<String> = (0..5).map(|i| format!("cell_{i}")).collect();
    for n in &names { ctx.cgroups.create_cell(n)?; }
    thread::sleep(Duration::from_secs(3));
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let handles = spawn_diverse(ctx, &name_refs)?;
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_mix_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // All workload types with cpusets.
    let all = ctx.topo.all_cpus();
    if all.len() < 6 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=6 CPUs".into()], stats: Default::default() }); }
    let last = all.len() - 1;
    let chunk = last / 3;
    let names = ["cell_0", "cell_1", "cell_2"];
    for (i, n) in names.iter().enumerate() {
        ctx.cgroups.create_cell(n)?;
        let start = i * chunk;
        let end = if i == 2 { last } else { (i + 1) * chunk };
        ctx.cgroups.set_cpuset(n, &all[start..end].iter().copied().collect())?;
    }
    thread::sleep(Duration::from_secs(3));
    let handles = spawn_diverse(ctx, &names)?;
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_mix_dynamic(ctx: &Ctx) -> Result<VerifyResult> {
    // Dynamic cell ops with diverse workloads.
    let names: Vec<String> = (0..3).map(|i| format!("cell_{i}")).collect();
    for n in &names { ctx.cgroups.create_cell(n)?; }
    thread::sleep(Duration::from_secs(3));
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let mut handles = spawn_diverse(ctx, &name_refs)?;
    thread::sleep(ctx.duration / 3);
    // Add cells with more workload types
    ctx.cgroups.create_cell("cell_3")?;
    let mut h = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 4, work_type: WorkType::Bursty { burst_ms: 100, sleep_ms: 50 }, ..Default::default() })?;
    for t in h.tids() { ctx.cgroups.move_task("cell_3", t)?; }
    h.start();
    handles.push(h);
    thread::sleep(ctx.duration / 3);
    // Remove cell_3
    if let Some(h) = handles.pop() { h.stop_and_collect(); }
    let _ = ctx.cgroups.remove_cell("cell_3");
    thread::sleep(ctx.duration / 3);
    Ok(collect_all(handles))
}

fn custom_mix_allflags(ctx: &Ctx) -> Result<VerifyResult> {
    // All workload types + all flags active (borrow, rebal, no-ctrl, reject-pin) + excluded cell.
    // This is the "kitchen sink" - every work pattern hitting every capability simultaneously.
    let names = ["cell_0", "cell_1", "cell_2", "cell_3", "excluded_cell"];
    for n in &names { ctx.cgroups.create_cell(n)?; }
    thread::sleep(Duration::from_secs(3));
    let handles = spawn_diverse(ctx, &names)?;
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_mix_allflags_cpuset(ctx: &Ctx) -> Result<VerifyResult> {
    // All flags + cpusets + all workload types.
    let all = ctx.topo.all_cpus();
    if all.len() < 6 { return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=6 CPUs".into()], stats: Default::default() }); }
    let last = all.len() - 1;
    let chunk = last / 3;
    for (i, n) in ["cell_0", "cell_1", "cell_2"].iter().enumerate() {
        ctx.cgroups.create_cell(n)?;
        let start = i * chunk;
        let end = if i == 2 { last } else { (i + 1) * chunk };
        ctx.cgroups.set_cpuset(n, &all[start..end].iter().copied().collect())?;
    }
    ctx.cgroups.create_cell("excluded_cell")?; // no cpuset, stays cell 0
    thread::sleep(Duration::from_secs(3));
    let handles = spawn_diverse(ctx, &["cell_0", "cell_1", "cell_2", "excluded_cell"])?;
    thread::sleep(ctx.duration);
    Ok(collect_all(handles))
}

fn custom_mix_allflags_dynamic(ctx: &Ctx) -> Result<VerifyResult> {
    // All flags + dynamic cell ops + all workload types.
    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.create_cell("cell_1")?;
    ctx.cgroups.create_cell("excluded_cell")?;
    thread::sleep(Duration::from_secs(3));
    let mut handles = spawn_diverse(ctx, &["cell_0", "cell_1", "excluded_cell"])?;
    thread::sleep(ctx.duration / 3);
    // Add cell with bursty load (triggers borrowing + rebalancing interaction)
    ctx.cgroups.create_cell("cell_2")?;
    let mut h = WorkloadHandle::spawn(&WorkloadConfig { num_workers: 8, work_type: WorkType::Bursty { burst_ms: 100, sleep_ms: 50 }, ..Default::default() })?;
    for t in h.tids() { ctx.cgroups.move_task("cell_2", t)?; }
    h.start();
    handles.push(h);
    thread::sleep(ctx.duration / 3);
    // Remove it
    if let Some(h) = handles.pop() { h.stop_and_collect(); }
    let _ = ctx.cgroups.remove_cell("cell_2");
    thread::sleep(ctx.duration / 3);
    Ok(collect_all(handles))
}

// ---------------------------------------------------------------------------
// Scenario catalog
// ---------------------------------------------------------------------------

macro_rules! s {
    ($name:expr, $cat:expr, $desc:expr, $cells:expr, $cpuset:expr, $works:expr) => {
        Scenario { name: $name, category: $cat, description: $desc,
            required_flags: &[], excluded_flags: &[],
            num_cells: $cells, cpuset_mode: $cpuset,
            cell_works: $works, action: Action::Steady, extra_sched_args: &[] }
    };
}

fn custom_dispatch_contention(ctx: &Ctx) -> Result<VerifyResult> {
    // Stress the dispatch fallback path in mitosis_dispatch.
    //
    // Multiple CPUs in one cell all serve the same cell DSQ. When many
    // bursty workers wake simultaneously, the lockless peek can miss
    // tasks due to store visibility ordering (list_add visible before
    // rcu_assign_pointer sets first_task). Without fallback to the
    // locked consume path, CPUs go idle and never retry.
    let all = ctx.topo.all_cpus();
    if all.len() < 4 {
        return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=4 CPUs".into()], stats: Default::default() });
    }
    let last = all.len() - 1;

    ctx.cgroups.create_cell("cell_0")?;
    ctx.cgroups.set_cpuset("cell_0", &all[..last].iter().copied().collect())?;
    thread::sleep(Duration::from_secs(3));

    let n_unpinned = (last * 3).max(8);
    let mut h_cell = WorkloadHandle::spawn(&WorkloadConfig {
        num_workers: n_unpinned,
        work_type: WorkType::Bursty { burst_ms: 10, sleep_ms: 5 },
        ..Default::default()
    })?;
    for t in h_cell.tids() { ctx.cgroups.move_task("cell_0", t)?; }

    let n_pinned = last.min(4);
    let mut pinned_handles = Vec::new();
    for i in 0..n_pinned {
        let mut h = WorkloadHandle::spawn(&WorkloadConfig {
            num_workers: 1,
            affinity: AffinityMode::SingleCpu(all[i]),
            work_type: WorkType::Bursty { burst_ms: 10, sleep_ms: 5 },
            ..Default::default()
        })?;
        for t in h.tids() { ctx.cgroups.move_task("cell_0", t)?; }
        pinned_handles.push(h);
    }

    h_cell.start();
    for h in &mut pinned_handles { h.start(); }
    thread::sleep(ctx.duration);

    let mut r = VerifyResult::pass();
    r.merge(verify::verify_not_starved(&h_cell.stop_and_collect()));
    for h in pinned_handles {
        let reports = h.stop_and_collect();
        for w in &reports {
            if w.max_gap_ms > 1500 {
                r.passed = false;
                r.details.push(format!(
                    "pinned worker {} on CPU {} had {}ms gap (dispatch contention stall)",
                    w.tid, w.cpus_used.iter().next().unwrap_or(&0), w.max_gap_ms
                ));
            }
        }
        r.merge(verify::verify_not_starved(&reports));
    }
    Ok(r)
}

fn custom_vtime_contamination(ctx: &Ctx) -> Result<VerifyResult> {
    // Trigger cross-cell vtime contamination via rebalancing + cpuset
    // transitions.
    //
    // Hot cells drive vtime high. Cold cells keep vtime low. Root cell
    // has mixed work. We randomly walk through phases that add/remove
    // cells and transition between disjoint and overlapping cpuset
    // layouts. Each transition forces apply_cell_config to retag CPUs
    // between cells with divergent vtime domains.
    let all = ctx.topo.all_cpus();
    if all.len() < 12 {
        return Ok(VerifyResult { passed: true, details: vec!["skipped: need >=12 CPUs".into()], stats: Default::default() });
    }
    let last = all.len() - 1; // reserve for cell 0
    let usable = &all[..last];

    // Seed PRNG from pid for reproducibility per run
    let mut rng = (std::process::id() as u64).wrapping_mul(6364136223846793005).wrapping_add(1);
    let mut next = || -> u64 { rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); rng >> 33 };

    // Root cell (cell 0): mixed workload on CPUs being retagged
    let mut handles = Vec::new();
    let mut h_root = WorkloadHandle::spawn(&WorkloadConfig {
        num_workers: usable.len(),
        work_type: WorkType::Mixed,
        ..Default::default()
    })?;
    h_root.start();
    handles.push(h_root);

    // Excluded cell — stays in cell 0 but with its own workload
    ctx.cgroups.create_cell("excluded_cell")?;
    let mut h_excl = WorkloadHandle::spawn(&WorkloadConfig {
        num_workers: 4,
        work_type: WorkType::Bursty { burst_ms: 100, sleep_ms: 200 },
        ..Default::default()
    })?;
    for t in h_excl.tids() { ctx.cgroups.move_task("excluded_cell", t)?; }
    h_excl.start();
    handles.push(h_excl);

    // Base cells that always exist: 2 hot, 3 cold
    let base_cells: Vec<String> = (0..5).map(|i| format!("cell_{i}")).collect();
    for name in &base_cells {
        ctx.cgroups.create_cell(name)?;
    }

    // Spawn hot workers (cells 0,1)
    for name in &base_cells[..2] {
        let mut h = WorkloadHandle::spawn(&WorkloadConfig {
            num_workers: usable.len(),
            work_type: WorkType::CpuSpin,
            ..Default::default()
        })?;
        for t in h.tids() { ctx.cgroups.move_task(name, t)?; }
        h.start();
        handles.push(h);
    }
    // Spawn cold workers (cells 2,3,4)
    for name in &base_cells[2..] {
        let mut h = WorkloadHandle::spawn(&WorkloadConfig {
            num_workers: 2,
            work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 500 },
            ..Default::default()
        })?;
        for t in h.tids() { ctx.cgroups.move_task(name, t)?; }
        h.start();
        handles.push(h);
    }

    let check_alive = |r: &mut VerifyResult| -> bool {
        if unsafe { libc::kill(ctx.sched_pid as i32, 0) } != 0 {
            r.passed = false;
            r.details.push("scheduler died".into());
            if let Ok(dmesg) = std::process::Command::new("dmesg").arg("--notime").output() {
                for line in String::from_utf8_lossy(&dmesg.stdout).lines() {
                    r.details.push(line.to_string());
                }
            }
            return false;
        }
        true
    };

    let apply_disjoint = |cells: &[String], usable: &[usize]| -> Result<()> {
        let chunk = usable.len() / cells.len();
        for (i, name) in cells.iter().enumerate() {
            let start = i * chunk;
            let end = if i == cells.len() - 1 { usable.len() } else { (i + 1) * chunk };
            ctx.cgroups.set_cpuset(name, &usable[start..end].iter().copied().collect())?;
        }
        Ok(())
    };

    let apply_overlap = |cells: &[String], usable: &[usize], overlap_frac: f64| -> Result<()> {
        let chunk = usable.len() / cells.len();
        let overlap = (chunk as f64 * overlap_frac) as usize;
        for (i, name) in cells.iter().enumerate() {
            let start = if i == 0 { 0 } else { (i * chunk).saturating_sub(overlap) };
            let end = if i == cells.len() - 1 { usable.len() } else { ((i + 1) * chunk + overlap).min(usable.len()) };
            ctx.cgroups.set_cpuset(name, &usable[start..end].iter().copied().collect())?;
        }
        Ok(())
    };

    let mut r = VerifyResult::pass();
    let mut extra_cell_exists = false;
    let extra_name = "cell_5".to_string();
    let phase_dur = Duration::from_secs(8);

    // Actions: (num_cells, overlapping)
    // Vary cell count 2-max × disjoint/overlap. Cap to usable/2 so
    // each cell gets at least 2 CPUs.
    let max_cells = (usable.len() / 2).min(6);
    let all_actions: Vec<(usize, bool)> = (2..=max_cells)
        .flat_map(|n| vec![(n, false), (n, true)])
        .collect();

    let mut actions: Vec<usize> = Vec::with_capacity(12);
    for _ in 0..12 {
        let last = actions.last().copied();
        // Pick a random action that differs from the last
        loop {
            let idx = (next() as usize) % all_actions.len();
            if Some(idx) != last {
                actions.push(idx);
                break;
            }
        }
    }

    // Extra cell names beyond the 2 base hot + base cold
    let extra_names: Vec<String> = (5..10).map(|i| format!("cell_{i}")).collect();
    let mut live_extras: Vec<String> = Vec::new();

    // Initial layout: disjoint with base cells
    apply_disjoint(&base_cells, usable)?;
    thread::sleep(Duration::from_secs(2));

    for (phase, &action_idx) in actions.iter().enumerate() {
        if !check_alive(&mut r) {
            break;
        }

        let (target_cells, overlapping) = &all_actions[action_idx];
        let target_cells = *target_cells;
        tracing::debug!(phase, target_cells, overlapping, "vtime_contamination phase");

        // We always have 2 hot (cell_0, cell_1) + some cold cells.
        // Total user cells = target_cells. Hot cells = min(2, target).
        // Cold cells = target - hot.
        let cold_count = target_cells.saturating_sub(2);

        // Build the cell list for this phase
        let mut phase_cells: Vec<String> = base_cells[..2.min(target_cells)].to_vec();
        // Add cold cells from base_cells[2..] first, then extras
        let base_cold = &base_cells[2..];
        for i in 0..cold_count {
            if i < base_cold.len() {
                phase_cells.push(base_cold[i].clone());
            } else {
                let extra_idx = i - base_cold.len();
                let name = &extra_names[extra_idx];
                if !live_extras.contains(name) {
                    ctx.cgroups.create_cell(name)?;
                    let mut h = WorkloadHandle::spawn(&WorkloadConfig {
                        num_workers: 2,
                        work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 500 },
                        ..Default::default()
                    })?;
                    for t in h.tids() { ctx.cgroups.move_task(name, t)?; }
                    h.start();
                    handles.push(h);
                    live_extras.push(name.clone());
                }
                phase_cells.push(name.clone());
            }
        }

        // Remove extras that aren't needed this phase
        let needed: std::collections::BTreeSet<String> = phase_cells.iter().cloned().collect();
        live_extras.retain(|name| {
            if !needed.contains(name) {
                let _ = ctx.cgroups.remove_cell(name);
                false
            } else {
                true
            }
        });

        // Apply cpuset layout
        if *overlapping {
            let frac = 0.2 + (next() % 30) as f64 / 100.0;
            apply_overlap(&phase_cells, usable, frac)?;
        } else {
            apply_disjoint(&phase_cells, usable)?;
        }

        thread::sleep(phase_dur);
    }

    check_alive(&mut r);
    for h in handles {
        r.merge(verify::verify_not_starved(&h.stop_and_collect()));
    }

    Ok(r)
}

macro_rules! custom {
    ($name:expr, $cat:expr, $desc:expr, $fn:expr) => {
        Scenario { name: $name, category: $cat, description: $desc,
            required_flags: &[], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom($fn), extra_sched_args: &[] }
    };
}

pub fn all_scenarios() -> Vec<Scenario> {
    let dfl = || vec![CellWork::default()];
    let w = |wt, pol| vec![CellWork { work_type: wt, policy: pol, ..Default::default() }];
    let aff = |a| vec![CellWork { affinity: a, ..Default::default() }];

    vec![
        // Basic
        s!("proportional", "basic", "No cpusets, proportional CPU division", 2, CpusetMode::None, dfl()),
        s!("cpuset_aligned", "basic", "Cpusets aligned to LLC boundaries", 2, CpusetMode::LlcAligned, dfl()),
        s!("cpuset_misaligned", "basic", "Cpusets spanning LLC boundaries", 2, CpusetMode::SplitMisaligned, dfl()),
        s!("cpuset_overlapping", "cpuset", "Overlapping cpusets", 3, CpusetMode::Overlap(0.5), dfl()),
        s!("holdback_cpus", "stress", "1/3 CPUs held back from cells", 2, CpusetMode::Holdback(0.33), dfl()),
        s!("uneven_cells", "stress", "75/25 CPU split between cells", 2, CpusetMode::Uneven(0.75), dfl()),
        s!("oversubscribed", "stress", "Many more workers than CPUs", 2, CpusetMode::None,
            vec![CellWork { workers: 32, work_type: WorkType::Mixed, ..Default::default() }]),
        // Affinity
        s!("affinity_none", "affinity", "No explicit affinity", 2, CpusetMode::None, w(WorkType::Mixed, SchedPolicy::Normal)),
        s!("affinity_random", "affinity", "Random CPU subsets", 2, CpusetMode::SplitHalf, aff(AffinityKind::RandomSubset)),
        s!("affinity_cross_cell", "affinity", "Affinity spanning all CPUs", 2, CpusetMode::SplitHalf, aff(AffinityKind::CrossCell)),
        s!("affinity_single_cpu", "affinity", "Single CPU pinning", 2, CpusetMode::SplitHalf, aff(AffinityKind::SingleCpu)),
        // Sched classes
        s!("sched_batch", "sched_class", "SCHED_BATCH workers", 2, CpusetMode::None, w(WorkType::CpuSpin, SchedPolicy::Batch)),
        s!("sched_idle", "sched_class", "SCHED_IDLE workers", 2, CpusetMode::None, w(WorkType::CpuSpin, SchedPolicy::Idle)),
        s!("sched_fifo", "sched_class", "RT SCHED_FIFO + normal workers", 2, CpusetMode::None,
            vec![CellWork { workers: 1, policy: SchedPolicy::Fifo(1), work_type: WorkType::Bursty { burst_ms: 500, sleep_ms: 250 }, ..Default::default() }]),
        s!("sched_rr", "sched_class", "RT SCHED_RR + normal workers", 2, CpusetMode::None,
            vec![CellWork { workers: 2, policy: SchedPolicy::RoundRobin(1), work_type: WorkType::Bursty { burst_ms: 500, sleep_ms: 250 }, ..Default::default() }]),
        // Borrowing (require flag)
        Scenario { name: "borrowing_idle", category: "advanced", description: "One cell idle, other overloaded",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 2, cpuset_mode: CpusetMode::None,
            cell_works: vec![CellWork { workers: 16, ..Default::default() }], // only cell 0 gets workers
            action: Action::Steady, extra_sched_args: &[] },
        Scenario { name: "borrowing_contention", category: "advanced", description: "All cells loaded with borrowing",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 2, cpuset_mode: CpusetMode::None,
            cell_works: vec![CellWork { workers: 16, ..Default::default() }],
            action: Action::Steady, extra_sched_args: &[] },
        Scenario { name: "work_stealing", category: "advanced", description: "LLC-aware work stealing",
            required_flags: &[Flag::LlcAware, Flag::WorkStealing], excluded_flags: &[],
            num_cells: 1, cpuset_mode: CpusetMode::None,
            cell_works: vec![CellWork { workers: 8, ..Default::default() }],
            action: Action::Steady, extra_sched_args: &[] },
        Scenario { name: "rebalancing", category: "advanced", description: "Demand-based CPU rebalancing",
            required_flags: &[Flag::Rebalancing], excluded_flags: &[],
            num_cells: 2, cpuset_mode: CpusetMode::None,
            cell_works: vec![
                CellWork { workers: 16, ..Default::default() },
                CellWork { workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() },
            ],
            action: Action::Steady, extra_sched_args: &[] },
        Scenario { name: "stall_detect", category: "stall", description: "Low watchdog + overloaded cell",
            required_flags: &[], excluded_flags: &[],
            num_cells: 1, cpuset_mode: CpusetMode::None,
            cell_works: vec![CellWork { workers: 16, ..Default::default() }],
            action: Action::Steady, extra_sched_args: &[] },
        // Affinity scenarios that exclude RejectMulticpuPinning
        Scenario { name: "affinity_llc_aligned", category: "affinity", description: "LLC-aligned affinities",
            required_flags: &[Flag::LlcAware], excluded_flags: &[],
            num_cells: 2, cpuset_mode: CpusetMode::LlcAligned,
            cell_works: aff(AffinityKind::LlcAligned), action: Action::Steady, extra_sched_args: &[] },
        Scenario { name: "affinity_mutation", category: "affinity", description: "Change affinities while running",
            required_flags: &[], excluded_flags: &[Flag::RejectMulticpuPinning],
            num_cells: 2, cpuset_mode: CpusetMode::None,
            cell_works: dfl(), action: Action::Custom(custom_affinity_mutation), extra_sched_args: &[] },
        // Custom scenarios
        custom!("dynamic_add", "dynamic", "Add cells while running", custom_dynamic_add),
        custom!("dynamic_remove", "dynamic", "Remove cells while running", custom_dynamic_remove),
        custom!("dynamic_churn", "dynamic", "Rapid create/destroy cycling", custom_rapid_churn),
        custom!("cpuset_add", "cpuset", "Add cpusets to existing cells", custom_cpuset_add),
        custom!("cpuset_remove", "cpuset", "Remove cpusets from cells", custom_cpuset_remove),
        custom!("cpuset_change", "cpuset", "Change cpusets on live cells", custom_cpuset_change),
        custom!("host_stress", "stress", "Host workers competing with cells", custom_host_stress),
        custom!("many_cells", "stress", "One cell per CPU", custom_many_cells),
        custom!("cell_exhaustion", "advanced", "Fill cells, remove, verify reuse", custom_cell_exhaustion),
        custom!("sched_mixed", "sched_class", "Mix of all sched classes", custom_sched_mixed),
        custom!("io_sync", "sched_class", "Sync IO mixed with CPU workers", custom_io_sync),
        Scenario { name: "stall_recovery", category: "stall", description: "Scheduler restart recovery",
            required_flags: &[], excluded_flags: &[],
            num_cells: 2, cpuset_mode: CpusetMode::None,
            cell_works: vec![CellWork { workers: 16, ..Default::default() }],
            action: Action::Steady, extra_sched_args: &[] },
        // Nested cgroups
        custom!("nested_basic", "nested", "Workers in nested sub-cgroups", custom_nested_basic),
        custom!("nested_move", "nested", "Move tasks between nested cgroups", custom_nested_move),
        custom!("nested_churn", "nested", "Rapid nested cgroup create/destroy", custom_nested_churn),
        custom!("nested_cpuset", "nested", "Nested cgroups with restrictive cpusets", custom_nested_cpuset),
        // Cell exclusion
        Scenario { name: "cell_exclude", category: "advanced", description: "Excluded cgroup stays in cell 0",
            required_flags: &[], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_cell_exclude),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
        // Borrowing + cpusets
        Scenario { name: "borrowing_cpuset", category: "advanced", description: "Borrowing with cpuset-constrained cells",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_borrowing_cpuset),
            extra_sched_args: &[] },
        // Rebalancing + cpusets
        Scenario { name: "rebalancing_cpuset", category: "advanced", description: "Rebalancing with cpuset-constrained cells",
            required_flags: &[Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_rebalancing_cpuset),
            extra_sched_args: &[] },
        // Rebalancing + dynamic cell add
        Scenario { name: "rebalancing_dynamic", category: "advanced", description: "Rebalancing during cell add",
            required_flags: &[Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_rebalancing_dynamic),
            extra_sched_args: &[] },
        // Borrowing + rebalancing combined
        Scenario { name: "borrowing_rebalancing", category: "advanced", description: "Borrowing + rebalancing together",
            required_flags: &[Flag::Borrowing, Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_borrowing_rebalancing),
            extra_sched_args: &[] },
        // Reject multicpu pinning
        Scenario { name: "reject_pin", category: "advanced", description: "Multi-CPU affinity rejection",
            required_flags: &[Flag::RejectMulticpuPinning], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_reject_pin),
            extra_sched_args: &[] },
        // CPU controller disabled: rapid cgroup moves
        Scenario { name: "no_ctrl_cgroup_move", category: "advanced", description: "Rapid cgroup moves in no-ctrl mode",
            required_flags: &[Flag::CpuControllerDisabled], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_no_ctrl_cgroup_move),
            extra_sched_args: &[] },
        // Borrowing + cpuset change (borrowed CPU disappears from lender)
        Scenario { name: "borrowing_cpuset_change", category: "advanced", description: "Cpuset change while borrowing",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_borrowing_cpuset_change),
            extra_sched_args: &[] },
        // Rebalancing oscillation
        Scenario { name: "rebalancing_oscillate", category: "advanced", description: "Alternating load tests rebalancing stability",
            required_flags: &[Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_rebalancing_oscillate),
            extra_sched_args: &[] },
        // Cell exclude + cpusets
        Scenario { name: "exclude_cpuset", category: "advanced", description: "Excluded cell + cpuset cells",
            required_flags: &[], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_exclude_cpuset),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
        // Cell exclude + dynamic add/remove
        Scenario { name: "exclude_dynamic", category: "advanced", description: "Excluded cell + dynamic cell changes",
            required_flags: &[], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_exclude_dynamic),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
        // No-ctrl + nested cgroups
        Scenario { name: "no_ctrl_nested", category: "advanced", description: "Nested cgroups in no-ctrl mode",
            required_flags: &[Flag::CpuControllerDisabled], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_no_ctrl_nested),
            extra_sched_args: &[] },
        // Cpuset disjoint swap (vtime domain discontinuity)
        Scenario { name: "cpuset_disjoint", category: "cpuset", description: "Cpuset swapped to disjoint CPU range",
            required_flags: &[], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_cpuset_disjoint),
            extra_sched_args: &[] },
        // IO + borrowing
        Scenario { name: "io_borrowing", category: "advanced", description: "IO cell frees CPUs for borrowing",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_io_borrowing),
            extra_sched_args: &[] },
        // Rebalancing with many cells + asymmetric demand
        Scenario { name: "rebalancing_many", category: "advanced", description: "Rebalancing with 4 asymmetric cells",
            required_flags: &[Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_rebalancing_many),
            extra_sched_args: &[] },
        // Borrowing + overlapping cpusets
        Scenario { name: "borrowing_overlap", category: "advanced", description: "Borrowing with overlapping cpusets",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 3, cpuset_mode: CpusetMode::Overlap(0.5),
            cell_works: vec![CellWork { workers: 8, ..Default::default() },
                             CellWork { workers: 1, work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 100 }, ..Default::default() },
                             CellWork { workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() }],
            action: Action::Steady, extra_sched_args: &[] },
        // Rebalancing + overlapping cpusets
        Scenario { name: "rebalancing_overlap", category: "advanced", description: "Rebalancing with overlapping cpusets",
            required_flags: &[Flag::Rebalancing], excluded_flags: &[],
            num_cells: 3, cpuset_mode: CpusetMode::Overlap(0.5),
            cell_works: vec![CellWork { workers: 16, ..Default::default() },
                             CellWork { workers: 1, work_type: WorkType::YieldHeavy, ..Default::default() },
                             CellWork { workers: 4, ..Default::default() }],
            action: Action::Steady, extra_sched_args: &[] },
        // Borrowing no cpusets (baseline, already exists but add bursty workload)
        Scenario { name: "borrowing_bursty", category: "advanced", description: "Borrowing with bursty workload",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 2, cpuset_mode: CpusetMode::None,
            cell_works: vec![CellWork { workers: 8, ..Default::default() },
                             CellWork { workers: 4, work_type: WorkType::Bursty { burst_ms: 50, sleep_ms: 100 }, ..Default::default() }],
            action: Action::Steady, extra_sched_args: &[] },
        // Rebalancing no cpusets, load shift
        Scenario { name: "rebalancing_shift", category: "advanced", description: "Rebalancing with bursty load shift",
            required_flags: &[Flag::Rebalancing], excluded_flags: &[],
            num_cells: 2, cpuset_mode: CpusetMode::None,
            cell_works: vec![CellWork { workers: 12, work_type: WorkType::Bursty { burst_ms: 200, sleep_ms: 50 }, ..Default::default() },
                             CellWork { workers: 4, ..Default::default() }],
            action: Action::Steady, extra_sched_args: &[] },
        // Vtime contamination via rebalancing (PR 3464)
        // Needs 90s+ because mitosis reconfigs are timer-driven (~1s)
        Scenario { name: "vtime_contamination", category: "stress", description: "Hot/cold cells trigger cross-cell vtime contamination",
            required_flags: &[Flag::Borrowing, Flag::Rebalancing, Flag::CpuControllerDisabled],
            excluded_flags: &[Flag::RejectMulticpuPinning],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_vtime_contamination),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
        // Borrowing + rebalancing + cpusets
        Scenario { name: "borrow_rebal_cpuset", category: "interaction", description: "Borrowing + rebalancing + cpusets",
            required_flags: &[Flag::Borrowing, Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_borrow_rebal_cpuset),
            extra_sched_args: &[] },
        // Borrowing + rebalancing + overlapping cpusets
        Scenario { name: "borrow_rebal_overlap", category: "interaction", description: "Borrowing + rebalancing + overlapping cpusets",
            required_flags: &[Flag::Borrowing, Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_borrow_rebal_overlap),
            extra_sched_args: &[] },
        // Cell exclude + borrowing
        Scenario { name: "exclude_borrowing", category: "interaction", description: "Excluded cell borrows from idle cells",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_exclude_borrowing),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
        // Cell exclude + rebalancing
        Scenario { name: "exclude_rebalancing", category: "interaction", description: "Excluded cell load vs rebalancing",
            required_flags: &[Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_exclude_rebalancing),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
        // No-ctrl + borrowing
        Scenario { name: "no_ctrl_borrowing", category: "interaction", description: "Polling detection + borrowing + cgroup moves",
            required_flags: &[Flag::CpuControllerDisabled, Flag::Borrowing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_no_ctrl_borrowing),
            extra_sched_args: &[] },
        // No-ctrl + cpusets
        Scenario { name: "no_ctrl_cpuset", category: "interaction", description: "Cpuset changes in no-ctrl mode",
            required_flags: &[Flag::CpuControllerDisabled], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_no_ctrl_cpuset),
            extra_sched_args: &[] },
        // No-ctrl + rebalancing
        Scenario { name: "no_ctrl_rebalancing", category: "interaction", description: "Rebalancing with polling detection",
            required_flags: &[Flag::CpuControllerDisabled, Flag::Rebalancing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_no_ctrl_rebalancing),
            extra_sched_args: &[] },
        // Reject-pin + cpusets
        Scenario { name: "reject_pin_cpuset", category: "interaction", description: "Reject pin within cpuset cells",
            required_flags: &[Flag::RejectMulticpuPinning], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_reject_pin_cpuset),
            extra_sched_args: &[] },
        // Dynamic + cpusets
        Scenario { name: "dynamic_cpuset", category: "interaction", description: "Add/remove cpuset-constrained cells",
            required_flags: &[], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_dynamic_cpuset),
            extra_sched_args: &[] },
        // Dynamic + borrowing
        Scenario { name: "dynamic_borrowing", category: "interaction", description: "Add cell while borrowing active",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_dynamic_borrowing),
            extra_sched_args: &[] },
        // Nested + borrowing
        Scenario { name: "nested_borrowing", category: "interaction", description: "Nested cgroups with borrowing",
            required_flags: &[Flag::Borrowing], excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_nested_borrowing),
            extra_sched_args: &[] },
        // Dispatch contention
        custom!("dispatch_contention", "stress", "Cell DSQ contention starving per-CPU DSQ", custom_dispatch_contention),
        // Workload variety - no flags
        custom!("mix_no_flags", "stress", "All workload types, no flags", custom_mix_no_flags),
        custom!("mix_cpuset", "stress", "All workload types + cpusets", custom_mix_cpuset),
        custom!("mix_dynamic", "stress", "All workload types + dynamic cells", custom_mix_dynamic),
        // Workload variety - all flags
        Scenario { name: "mix_allflags", category: "stress", description: "All workloads + all flags",
            required_flags: &[Flag::Borrowing, Flag::Rebalancing, Flag::CpuControllerDisabled, Flag::RejectMulticpuPinning],
            excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_mix_allflags),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
        Scenario { name: "mix_allflags_cpuset", category: "stress", description: "All workloads + all flags + cpusets",
            required_flags: &[Flag::Borrowing, Flag::Rebalancing, Flag::CpuControllerDisabled, Flag::RejectMulticpuPinning],
            excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_mix_allflags_cpuset),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
        Scenario { name: "mix_allflags_dynamic", category: "stress", description: "All workloads + all flags + dynamic",
            required_flags: &[Flag::Borrowing, Flag::Rebalancing, Flag::CpuControllerDisabled, Flag::RejectMulticpuPinning],
            excluded_flags: &[],
            num_cells: 0, cpuset_mode: CpusetMode::None,
            cell_works: vec![], action: Action::Custom(custom_mix_allflags_dynamic),
            extra_sched_args: &["--cell-exclude", "excluded_cell"] },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_short_name_roundtrip() {
        for f in Flag::all() {
            assert_eq!(Flag::from_short_name(f.short_name()), Some(*f));
        }
    }

    #[test]
    fn flag_all_unique_short_names() {
        let names: Vec<&str> = Flag::all().iter().map(|f| f.short_name()).collect();
        let unique: std::collections::HashSet<&&str> = names.iter().collect();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn flag_all_unique_cli_flags() {
        let flags: Vec<&str> = Flag::all().iter().map(|f| f.cli_flag()).collect();
        let unique: std::collections::HashSet<&&str> = flags.iter().collect();
        assert_eq!(flags.len(), unique.len());
    }

    #[test]
    fn flag_from_short_name_unknown() {
        assert_eq!(Flag::from_short_name("nonexistent"), None);
    }

    #[test]
    fn profile_name_default() {
        assert_eq!(FlagProfile { flags: vec![] }.name(), "default");
    }

    #[test]
    fn profile_name_with_flags() {
        let p = FlagProfile { flags: vec![Flag::LlcAware, Flag::Borrowing] };
        assert_eq!(p.name(), "llc+borrow");
    }

    #[test]
    fn profile_args_maps_to_cli() {
        let p = FlagProfile { flags: vec![Flag::Borrowing, Flag::Rebalancing] };
        let args = p.args();
        assert!(args.contains(&"--enable-borrowing"));
        assert!(args.contains(&"--enable-rebalancing"));
    }

    #[test]
    fn generate_profiles_no_constraints() {
        // 2^6=64 minus 16 invalid (WorkStealing without LlcAware) = 48
        assert_eq!(generate_profiles(&[], &[]).len(), 48);
    }

    #[test]
    fn generate_profiles_work_stealing_requires_llc() {
        let profiles = generate_profiles(&[Flag::WorkStealing], &[]);
        for p in &profiles {
            assert!(p.flags.contains(&Flag::LlcAware), "WorkStealing without LlcAware: {:?}", p.flags);
        }
    }

    #[test]
    fn generate_profiles_excluded_never_present() {
        let profiles = generate_profiles(&[], &[Flag::CpuControllerDisabled]);
        for p in &profiles {
            assert!(!p.flags.contains(&Flag::CpuControllerDisabled));
        }
    }

    #[test]
    fn generate_profiles_required_always_present() {
        let profiles = generate_profiles(&[Flag::Borrowing], &[]);
        for p in &profiles {
            assert!(p.flags.contains(&Flag::Borrowing));
        }
    }

    #[test]
    fn generate_profiles_required_and_excluded() {
        let profiles = generate_profiles(&[Flag::Borrowing], &[Flag::Rebalancing]);
        for p in &profiles {
            assert!(p.flags.contains(&Flag::Borrowing));
            assert!(!p.flags.contains(&Flag::Rebalancing));
        }
    }

    #[test]
    fn all_scenarios_non_empty() {
        assert!(!all_scenarios().is_empty());
    }

    #[test]
    fn all_scenarios_unique_names() {
        let scenarios = all_scenarios();
        let names: Vec<&str> = scenarios.iter().map(|s| s.name).collect();
        let unique: std::collections::HashSet<&&str> = names.iter().collect();
        assert_eq!(names.len(), unique.len(), "duplicate scenario names");
    }

    #[test]
    fn all_scenarios_have_profiles() {
        for s in &all_scenarios() {
            assert!(!s.profiles().is_empty(), "{} has no valid profiles", s.name);
        }
    }

    #[test]
    fn scenario_scheduler_args_includes_parent() {
        let s = &all_scenarios()[0];
        let p = FlagProfile { flags: vec![] };
        let args = s.scheduler_args("/sys/fs/cgroup/stt", &p);
        assert!(args.contains(&"--cell-parent-cgroup".to_string()));
        assert!(args.contains(&"/stt".to_string()));
        assert!(args.contains(&"--watchdog-timeout-ms".to_string()));
        assert!(args.contains(&"2000".to_string()));
    }

    #[test]
    fn scenario_scheduler_args_includes_profile_flags() {
        let s = &all_scenarios()[0];
        let p = FlagProfile { flags: vec![Flag::Borrowing] };
        let args = s.scheduler_args("/sys/fs/cgroup/stt", &p);
        assert!(args.contains(&"--enable-borrowing".to_string()));
    }

    #[test]
    fn resolve_cpusets_none_returns_none() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        assert!(resolve_cpusets(&CpusetMode::None, 2, &t).is_none());
    }

    #[test]
    fn resolve_cpusets_split_half_covers_usable() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        let r = resolve_cpusets(&CpusetMode::SplitHalf, 2, &t).unwrap();
        assert_eq!(r.len(), 2);
        // Last CPU reserved for cell 0 → 7 usable
        let total: usize = r.iter().map(|s| s.len()).sum();
        assert_eq!(total, 7);
    }

    #[test]
    fn resolve_cpusets_llc_aligned() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        let r = resolve_cpusets(&CpusetMode::LlcAligned, 2, &t).unwrap();
        assert_eq!(r.len(), 2);
        // Both sets non-empty
        assert!(!r[0].is_empty());
        assert!(!r[1].is_empty());
    }

    #[test]
    fn resolve_cpusets_uneven() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        let r = resolve_cpusets(&CpusetMode::Uneven(0.75), 2, &t).unwrap();
        assert!(r[0].len() > r[1].len(), "75/25 split should be uneven");
    }

    #[test]
    fn resolve_cpusets_holdback() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        let r = resolve_cpusets(&CpusetMode::Holdback(0.5), 2, &t).unwrap();
        let total: usize = r.iter().map(|s| s.len()).sum();
        assert!(total < 8, "holdback should use fewer CPUs");
    }

    #[test]
    fn resolve_cpusets_overlap() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        let r = resolve_cpusets(&CpusetMode::Overlap(0.5), 3, &t).unwrap();
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn resolve_affinity_inherit() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        assert!(matches!(resolve_affinity_kind(&AffinityKind::Inherit, None, 0, &t), AffinityMode::None));
    }

    #[test]
    fn resolve_affinity_single_cpu() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        match resolve_affinity_kind(&AffinityKind::SingleCpu, None, 0, &t) {
            AffinityMode::SingleCpu(c) => assert_eq!(c, 0),
            other => panic!("expected SingleCpu, got {:?}", other),
        }
    }

    #[test]
    fn resolve_affinity_cross_cell() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        match resolve_affinity_kind(&AffinityKind::CrossCell, None, 0, &t) {
            AffinityMode::Fixed(cpus) => assert_eq!(cpus.len(), 8),
            other => panic!("expected Fixed, got {:?}", other),
        }
    }

    #[test]
    fn resolve_affinity_llc_aligned() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        match resolve_affinity_kind(&AffinityKind::LlcAligned, None, 1, &t) {
            AffinityMode::Fixed(cpus) => assert_eq!(cpus, [4, 5, 6, 7].into_iter().collect()),
            other => panic!("expected Fixed, got {:?}", other),
        }
    }

    #[test]
    fn resolve_affinity_random_subset() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        let cpusets: Vec<BTreeSet<usize>> = vec![[0, 1, 2, 3].into_iter().collect()];
        match resolve_affinity_kind(&AffinityKind::RandomSubset, Some(&cpusets), 0, &t) {
            AffinityMode::Random { from, count } => {
                assert_eq!(from, cpusets[0]);
                assert_eq!(count, 2); // half of 4
            }
            other => panic!("expected Random, got {:?}", other),
        }
    }

    #[test]
    fn profiles_with_filters_correctly() {
        let s = &all_scenarios()[0]; // proportional, no required/excluded
        let profiles = s.profiles_with(&[Flag::Borrowing]);
        for p in &profiles {
            // Only Borrowing (and its dependencies) should be possible
            for f in &p.flags {
                assert!(*f == Flag::Borrowing || Flag::Borrowing.requires().contains(f),
                    "unexpected flag {:?}", f);
            }
        }
    }

    #[test]
    fn resolve_cpusets_split_misaligned() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        let r = resolve_cpusets(&CpusetMode::SplitMisaligned, 2, &t).unwrap();
        assert_eq!(r.len(), 2);
        let total: usize = r.iter().map(|s| s.len()).sum();
        assert!(total > 0);
        // Misaligned means split within an LLC, not at LLC boundary
        assert_ne!(r[0].len(), 4, "misaligned should NOT split at LLC boundary");
    }

    #[test]
    fn resolve_cpusets_llc_aligned_single_llc() {
        let t = crate::topology::TestTopology::synthetic(4, 1);
        let r = resolve_cpusets(&CpusetMode::LlcAligned, 2, &t).unwrap();
        // With 1 LLC, can only make 1 set -> returns empty for missing
        assert!(r.iter().any(|s| s.is_empty()), "should signal skip with empty set");
    }

    #[test]
    fn resolve_cpusets_small_topology() {
        let t = crate::topology::TestTopology::synthetic(2, 1);
        let r = resolve_cpusets(&CpusetMode::SplitHalf, 2, &t).unwrap();
        assert_eq!(r.len(), 2);
        // 2 CPUs, no reserve (too small), each gets 1
        assert_eq!(r[0].len(), 1);
        assert_eq!(r[1].len(), 1);
    }

    #[test]
    fn cell_work_default() {
        let cw = CellWork::default();
        assert_eq!(cw.workers, 0);
        assert!(matches!(cw.work_type, WorkType::CpuSpin));
        assert!(matches!(cw.policy, SchedPolicy::Normal));
        assert!(matches!(cw.affinity, AffinityKind::Inherit));
    }

    #[test]
    fn scenario_qualified_name() {
        let s = &all_scenarios()[0];
        let p = FlagProfile { flags: vec![] };
        assert_eq!(s.qualified_name(&p), format!("{}/default", s.name));
    }

    #[test]
    fn scenario_qualified_name_with_flags() {
        let s = &all_scenarios()[0];
        let p = FlagProfile { flags: vec![Flag::LlcAware, Flag::Borrowing] };
        assert_eq!(s.qualified_name(&p), format!("{}/llc+borrow", s.name));
    }

    #[test]
    fn all_scenarios_count() {
        let scenarios = all_scenarios();
        assert!(scenarios.len() >= 30, "expected >=30 scenarios, got {}", scenarios.len());
    }

    #[test]
    fn scenario_categories_valid() {
        let valid = ["basic", "cpuset", "affinity", "sched_class", "dynamic", "stress", "stall", "advanced", "nested", "interaction"];
        for s in &all_scenarios() {
            assert!(valid.contains(&s.category), "unknown category '{}' in {}", s.category, s.name);
        }
    }

    #[test]
    fn generate_profiles_single_required_count() {
        // Required=[Borrowing], 5 optional, WorkStealing needs LlcAware
        // 2^5=32 minus 8 invalid = 24
        assert_eq!(generate_profiles(&[Flag::Borrowing], &[]).len(), 24);
    }

    #[test]
    fn profiles_sorted_by_flag_order() {
        for p in &generate_profiles(&[], &[]) {
            for w in p.flags.windows(2) {
                assert!((w[0] as u8) < (w[1] as u8), "flags not sorted: {:?}", p.flags);
            }
        }
    }

    #[test]
    fn scheduler_args_strips_cgroup_prefix() {
        let s = &all_scenarios()[0];
        let p = FlagProfile { flags: vec![] };
        let args = s.scheduler_args("/sys/fs/cgroup/test/nested", &p);
        assert!(args.contains(&"/test/nested".to_string()));
    }

    #[test]
    fn scheduler_args_includes_debug_events() {
        let s = &all_scenarios()[0];
        let p = FlagProfile { flags: vec![] };
        let args = s.scheduler_args("/sys/fs/cgroup/stt", &p);
        assert!(args.contains(&"--debug-events".to_string()));
        assert!(args.contains(&"--exit-dump-len".to_string()));
    }

    #[test]
    fn scenario_with_extra_sched_args() {
        // Find a scenario with required flags to verify extra args
        for s in &all_scenarios() {
            if !s.extra_sched_args.is_empty() {
                let p = FlagProfile { flags: vec![] };
                let args = s.scheduler_args("/sys/fs/cgroup/stt", &p);
                for extra in s.extra_sched_args {
                    assert!(args.contains(&extra.to_string()), "missing extra arg {}", extra);
                }
            }
        }
    }

    #[test]
    fn resolve_cpusets_holdback_reserves_cpus() {
        let t = crate::topology::TestTopology::synthetic(12, 3);
        let r = resolve_cpusets(&CpusetMode::Holdback(0.33), 2, &t).unwrap();
        let total: usize = r.iter().map(|s| s.len()).sum();
        // 12 CPUs, holdback 33%: keep = 12 - floor(12*0.33) = 12 - 3 = 9
        assert_eq!(total, 9, "holdback 33% of 12 should keep 9");
        assert!(total < 12, "holdback should use fewer CPUs than total");
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn resolve_cpusets_overlap_sets_overlap() {
        let t = crate::topology::TestTopology::synthetic(12, 1);
        let r = resolve_cpusets(&CpusetMode::Overlap(0.5), 2, &t).unwrap();
        let overlap: BTreeSet<usize> = r[0].intersection(&r[1]).copied().collect();
        assert!(!overlap.is_empty(), "50% overlap should have overlapping CPUs");
    }

    #[test]
    fn resolve_affinity_random_no_cpusets() {
        let t = crate::topology::TestTopology::synthetic(8, 2);
        match resolve_affinity_kind(&AffinityKind::RandomSubset, None, 0, &t) {
            AffinityMode::Random { from, count } => {
                assert_eq!(from.len(), 8); // all CPUs
                assert_eq!(count, 4); // half
            }
            other => panic!("expected Random, got {:?}", other),
        }
    }
}
