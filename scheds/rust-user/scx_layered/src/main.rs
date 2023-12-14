// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::ops::Sub;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use ::fb_procfs as procfs;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitvec::prelude::*;
use clap::Parser;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;
use log::debug;
use log::info;
use log::trace;
use scx_utils::ravg::ravg_read;
use serde::Deserialize;
use serde::Serialize;

const RAVG_FRAC_BITS: u32 = bpf_intf::ravg_consts_RAVG_FRAC_BITS;
const MAX_CPUS: usize = bpf_intf::consts_MAX_CPUS as usize;
const MAX_PATH: usize = bpf_intf::consts_MAX_PATH as usize;
const MAX_COMM: usize = bpf_intf::consts_MAX_COMM as usize;
const MAX_LAYER_MATCH_ORS: usize = bpf_intf::consts_MAX_LAYER_MATCH_ORS as usize;
const MAX_LAYERS: usize = bpf_intf::consts_MAX_LAYERS as usize;
const USAGE_HALF_LIFE: u32 = bpf_intf::consts_USAGE_HALF_LIFE;
const USAGE_HALF_LIFE_F64: f64 = USAGE_HALF_LIFE as f64 / 1_000_000_000.0;
const NR_GSTATS: usize = bpf_intf::global_stat_idx_NR_GSTATS as usize;
const NR_LSTATS: usize = bpf_intf::layer_stat_idx_NR_LSTATS as usize;
const NR_LAYER_MATCH_KINDS: usize = bpf_intf::layer_match_kind_NR_LAYER_MATCH_KINDS as usize;
const CORE_CACHE_LEVEL: u32 = 2;

lazy_static::lazy_static! {
    static ref NR_POSSIBLE_CPUS: usize = libbpf_rs::num_possible_cpus().unwrap();
    static ref USAGE_DECAY: f64 = 0.5f64.powf(1.0 / USAGE_HALF_LIFE_F64);
}

/// scx_layered: A highly configurable multi-layer sched_ext scheduler
///
/// scx_layered allows classifying tasks into multiple layers and applying
/// different scheduling policies to them. The configuration is specified in
/// json and composed of two parts - matches and policies.
///
/// Matches
/// =======
///
/// Whenever a task is forked or its attributes are changed, the task goes
/// through a series of matches to determine the layer it belongs to. A
/// match set is composed of OR groups of AND blocks. An example:
///
///   "matches": [
///     [
///       {
///         "CgroupPrefix": "system.slice/"
///       }
///     ],
///     [
///       {
///         "CommPrefix": "fbagent"
///       },
///       {
///         "NiceAbove": 0
///       }
///     ]
///   ],
///
/// The outer array contains the OR groups and the inner AND blocks, so the
/// above matches:
///
/// * Tasks which are in the cgroup sub-hierarchy under "system.slice".
/// * Or tasks whose comm starts with "fbagent" and have a nice value > 0.
///
/// Currently, the following matches are supported:
///
/// * CgroupPrefix: Matches the prefix of the cgroup that the task belongs
///   to. As this is a string match, whether the pattern has the trailing
///   '/' makes a difference. For example, "TOP/CHILD/" only matches tasks
///   which are under that particular cgroup while "TOP/CHILD" also matches
///   tasks under "TOP/CHILD0/" or "TOP/CHILD1/".
///
/// * CommPrefix: Matches the task's comm prefix.
///
/// * NiceAbove: Matches if the task's nice value is greater than the
///   pattern.
///
/// * NiceBelow: Matches if the task's nice value is smaller than the
///   pattern.
///
/// While there are complexity limitations as the matches are performed in
/// BPF, it is straightforward to add more types of matches.
///
/// Policies
/// ========
///
/// The following is an example policy configuration for a layer.
///
///   "kind": {
///     "Confined": {
///       "cpus_range": [1, 8],
///       "util_range": [0.8, 0.9]
///     }
///   }
///
/// It's of "Confined" kind, which tries to concentrate the layer's tasks
/// into a limited number of CPUs. In the above case, the number of CPUs
/// assigned to the layer is scaled between 1 and 8 so that the per-cpu
/// utilization is kept between 80% and 90%. If the CPUs are loaded higher
/// than 90%, more CPUs are allocated to the layer. If the utilization drops
/// below 80%, the layer loses CPUs.
///
/// Currently, the following policy kinds are supported:
///
/// * Confined: Tasks are restricted to the allocated CPUs. The number of
///   CPUs allocated is modulated to keep the per-CPU utilization in
///   "util_range". The range can optionally be restricted with the
///   "cpus_range" property.
///
/// * Grouped: Similar to Confined but tasks may spill outside if there are
///   idle CPUs outside the allocated ones. If "preempt" is true, tasks in
///   this layer will preempt tasks which belong to other non-preempting
///   layers when no idle CPUs are available.
///
/// * Open: Prefer the CPUs which are not occupied by Confined or Grouped
///   layers. Tasks in this group will spill into occupied CPUs if there are
///   no unoccupied idle CPUs. If "preempt" is true, tasks in this layer
///   will preempt tasks which belong to other non-preempting layers when no
///   idle CPUs are available.
///
/// Similar to matches, adding new policies and extending existing ones
/// should be relatively straightforward.
///
/// Configuration example and running scx_layered
/// =============================================
///
/// A scx_layered config is composed of layer configs and a layer config is
/// composed of a name, a set of matches and a policy block. Running the
/// following will write an example configuration into example.json.
///
///   $ scx_layered -e example.json
///
/// Note that the last layer in the configuration must have an empty match
/// set as it must match all tasks which haven't been matched into previous
/// layers.
///
/// The configuration can be specified in multiple json files and command
/// line arguments. Each must contain valid layer configurations and they're
/// concatenated in the specified order. In most cases, something like the
/// following should do.
///
///   $ scx_layered file:example.json
///
/// Statistics
/// ==========
///
/// scx_layered will print out a set of statistics every monitoring
/// interval.
///
///   tot= 117909 local=86.20 open_idle= 0.21 affn_viol= 1.37 tctx_err=9 proc=6ms
///   busy= 34.2 util= 1733.6 load=  21744.1 fallback_cpu=  1
///     batch    : util/frac=   11.8/  0.7 load/frac=     29.7:  0.1 tasks=  2597
///                tot=   3478 local=67.80 open_idle= 0.00 preempt= 0.00 affn_viol= 0.00
///                cpus=  2 [  2,  2] 04000001 00000000
///     immediate: util/frac= 1218.8/ 70.3 load/frac=  21399.9: 98.4 tasks=  1107
///                tot=  68997 local=90.57 open_idle= 0.26 preempt= 9.36 affn_viol= 0.00
///                cpus= 50 [ 50, 50] fbfffffe 000fffff
///     normal   : util/frac=  502.9/ 29.0 load/frac=    314.5:  1.4 tasks=  3512
///                tot=  45434 local=80.97 open_idle= 0.16 preempt= 0.00 affn_viol= 3.56
///                cpus= 50 [ 50, 50] fbfffffe 000fffff
///
/// Global statistics:
///
/// - tot: Total scheduling events in the period.
///
/// - local: % that got scheduled directly into an idle CPU.
///
/// - open_idle: % of open layer tasks scheduled into occupied idle CPUs.
///
/// - affn_viol: % which violated configured policies due to CPU affinity
///   restrictions.
///
/// - proc: CPU time this binary consumed during the period.
///
/// - busy: CPU busy % (100% means all CPUs were fully occupied)
///
/// - util: CPU utilization % (100% means one CPU was fully occupied)
///
/// - load: Sum of weight * duty_cycle for all tasks
///
/// Per-layer statistics:
///
/// - util/frac: CPU utilization and fraction % (sum of fractions across
///   layers is always 100%).
///
/// - load/frac: Load sum and fraction %.
///
/// - tasks: Number of tasks.
///
/// - tot: Total scheduling events.
///
/// - open_idle: % of tasks scheduled into idle CPUs occupied by other layers.
///
/// - preempt: % of tasks that preempted other tasks.
///
/// - affn_viol: % which violated configured policies due to CPU affinity
///   restrictions.
///
/// - cpus: CUR_NR_CPUS [MIN_NR_CPUS, MAX_NR_CPUS] CUR_CPU_MASK
///
#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    /// Scheduling interval in seconds.
    #[clap(short = 'i', long, default_value = "0.1")]
    interval: f64,

    /// Monitoring interval in seconds.
    #[clap(short = 'm', long, default_value = "2.0")]
    monitor: f64,

    /// Disable load-fraction based max layer CPU limit. ***NOTE***
    /// load-fraction calculation is currently broken due to lack of
    /// infeasible weight adjustments. Setting this option is recommended.
    #[clap(short = 'n', long)]
    no_load_frac_limit: bool,

    /// Enable verbose output including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Write example layer specifications into the file and exit.
    #[clap(short = 'e', long)]
    example: Option<String>,

    /// Layer specification. See --help.
    specs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum LayerMatch {
    CgroupPrefix(String),
    CommPrefix(String),
    NiceAbove(i32),
    NiceBelow(i32),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum LayerKind {
    Confined {
        cpus_range: Option<(usize, usize)>,
        util_range: (f64, f64),
    },
    Grouped {
        cpus_range: Option<(usize, usize)>,
        util_range: (f64, f64),
        preempt: bool,
    },
    Open {
        preempt: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LayerSpec {
    name: String,
    comment: Option<String>,
    matches: Vec<Vec<LayerMatch>>,
    kind: LayerKind,
}

impl LayerSpec {
    fn parse(input: &str) -> Result<Vec<Self>> {
        let config: LayerConfig = if input.starts_with("f:") || input.starts_with("file:") {
            let mut f = fs::OpenOptions::new()
                .read(true)
                .open(input.split_once(':').unwrap().1)?;
            let mut content = String::new();
            f.read_to_string(&mut content)?;
            serde_json::from_str(&content)?
        } else {
            serde_json::from_str(input)?
        };
        Ok(config.specs)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct LayerConfig {
    specs: Vec<LayerSpec>,
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

fn read_total_cpu(reader: &procfs::ProcReader) -> Result<procfs::CpuStat> {
    reader
        .read_stat()
        .context("Failed to read procfs")?
        .total_cpu
        .ok_or_else(|| anyhow!("Could not read total cpu stat in proc"))
}

fn calc_util(curr: &procfs::CpuStat, prev: &procfs::CpuStat) -> Result<f64> {
    match (curr, prev) {
        (
            procfs::CpuStat {
                user_usec: Some(curr_user),
                nice_usec: Some(curr_nice),
                system_usec: Some(curr_system),
                idle_usec: Some(curr_idle),
                iowait_usec: Some(curr_iowait),
                irq_usec: Some(curr_irq),
                softirq_usec: Some(curr_softirq),
                stolen_usec: Some(curr_stolen),
                ..
            },
            procfs::CpuStat {
                user_usec: Some(prev_user),
                nice_usec: Some(prev_nice),
                system_usec: Some(prev_system),
                idle_usec: Some(prev_idle),
                iowait_usec: Some(prev_iowait),
                irq_usec: Some(prev_irq),
                softirq_usec: Some(prev_softirq),
                stolen_usec: Some(prev_stolen),
                ..
            },
        ) => {
            let idle_usec = curr_idle - prev_idle;
            let iowait_usec = curr_iowait - prev_iowait;
            let user_usec = curr_user - prev_user;
            let system_usec = curr_system - prev_system;
            let nice_usec = curr_nice - prev_nice;
            let irq_usec = curr_irq - prev_irq;
            let softirq_usec = curr_softirq - prev_softirq;
            let stolen_usec = curr_stolen - prev_stolen;

            let busy_usec =
                user_usec + system_usec + nice_usec + irq_usec + softirq_usec + stolen_usec;
            let total_usec = idle_usec + busy_usec + iowait_usec;
            if total_usec > 0 {
                Ok(((busy_usec as f64) / (total_usec as f64)).clamp(0.0, 1.0))
            } else {
                Ok(1.0)
            }
        }
        _ => {
            bail!("Missing stats in cpustat");
        }
    }
}

fn copy_into_cstr(dst: &mut [i8], src: &str) {
    let cstr = CString::new(src).unwrap();
    let bytes = unsafe { std::mem::transmute::<&[u8], &[i8]>(cstr.as_bytes_with_nul()) };
    dst[0..bytes.len()].copy_from_slice(bytes);
}

fn format_bitvec(bitvec: &BitVec) -> String {
    let mut vals = Vec::<u32>::new();
    let mut val: u32 = 0;
    for (idx, bit) in bitvec.iter().enumerate() {
        if idx > 0 && idx % 32 == 0 {
            vals.push(val);
            val = 0;
        }
        if *bit {
            val |= 1 << (idx % 32);
        }
    }
    vals.push(val);
    let mut output = vals
        .iter()
        .fold(String::new(), |string, v| format!("{}{:08x} ", string, v));
    output.pop();
    output
}

fn read_cpu_ctxs(skel: &BpfSkel) -> Result<Vec<bpf_intf::cpu_ctx>> {
    let mut cpu_ctxs = vec![];
    let cpu_ctxs_vec = skel
        .maps()
        .cpu_ctxs()
        .lookup_percpu(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
        .context("Failed to lookup cpu_ctx")?
        .unwrap();
    for cpu in 0..*NR_POSSIBLE_CPUS {
        cpu_ctxs.push(*unsafe {
            &*(cpu_ctxs_vec[cpu].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
        });
    }
    Ok(cpu_ctxs)
}

#[derive(Clone, Debug)]
struct BpfStats {
    gstats: Vec<u64>,
    lstats: Vec<Vec<u64>>,
    lstats_sums: Vec<u64>,
}

impl BpfStats {
    fn read(cpu_ctxs: &[bpf_intf::cpu_ctx], nr_layers: usize) -> Self {
        let mut gstats = vec![0u64; NR_GSTATS];
        let mut lstats = vec![vec![0u64; NR_LSTATS]; nr_layers];

        for cpu in 0..*NR_POSSIBLE_CPUS {
            for stat in 0..NR_GSTATS {
                gstats[stat] += cpu_ctxs[cpu].gstats[stat];
            }
            for layer in 0..nr_layers {
                for stat in 0..NR_LSTATS {
                    lstats[layer][stat] += cpu_ctxs[cpu].lstats[layer][stat];
                }
            }
        }

        let mut lstats_sums = vec![0u64; NR_LSTATS];
        for layer in 0..nr_layers {
            for stat in 0..NR_LSTATS {
                lstats_sums[stat] += lstats[layer][stat];
            }
        }

        Self {
            gstats,
            lstats,
            lstats_sums,
        }
    }
}

impl<'a, 'b> Sub<&'b BpfStats> for &'a BpfStats {
    type Output = BpfStats;

    fn sub(self, rhs: &'b BpfStats) -> BpfStats {
        let vec_sub = |l: &[u64], r: &[u64]| l.iter().zip(r.iter()).map(|(l, r)| *l - *r).collect();
        BpfStats {
            gstats: vec_sub(&self.gstats, &rhs.gstats),
            lstats: self
                .lstats
                .iter()
                .zip(rhs.lstats.iter())
                .map(|(l, r)| vec_sub(l, r))
                .collect(),
            lstats_sums: vec_sub(&self.lstats_sums, &rhs.lstats_sums),
        }
    }
}

struct Stats {
    nr_layers: usize,
    at: Instant,

    nr_layer_tasks: Vec<usize>,

    total_load: f64,
    layer_loads: Vec<f64>,

    total_util: f64, // Running AVG of sum of layer_utils
    layer_utils: Vec<f64>,
    prev_layer_cycles: Vec<u64>,

    cpu_busy: f64, // Read from /proc, maybe higher than total_util
    prev_total_cpu: procfs::CpuStat,

    bpf_stats: BpfStats,
    prev_bpf_stats: BpfStats,
}

impl Stats {
    fn read_layer_loads(skel: &mut BpfSkel, nr_layers: usize) -> (f64, Vec<f64>) {
        let now_mono = now_monotonic();
        let layer_loads: Vec<f64> = skel
            .bss()
            .layers
            .iter()
            .take(nr_layers)
            .map(|layer| {
                let rd = &layer.load_rd;
                ravg_read(
                    rd.val,
                    rd.val_at,
                    rd.old,
                    rd.cur,
                    now_mono,
                    USAGE_HALF_LIFE,
                    RAVG_FRAC_BITS,
                )
            })
            .collect();
        (layer_loads.iter().sum(), layer_loads)
    }

    fn read_layer_cycles(cpu_ctxs: &[bpf_intf::cpu_ctx], nr_layers: usize) -> Vec<u64> {
        let mut layer_cycles = vec![0u64; nr_layers];

        for cpu in 0..*NR_POSSIBLE_CPUS {
            for layer in 0..nr_layers {
                layer_cycles[layer] += cpu_ctxs[cpu].layer_cycles[layer];
            }
        }

        layer_cycles
    }

    fn new(skel: &mut BpfSkel, proc_reader: &procfs::ProcReader) -> Result<Self> {
        let nr_layers = skel.rodata().nr_layers as usize;
        let bpf_stats = BpfStats::read(&read_cpu_ctxs(skel)?, nr_layers);

        Ok(Self {
            at: Instant::now(),
            nr_layers,

            nr_layer_tasks: vec![0; nr_layers],

            total_load: 0.0,
            layer_loads: vec![0.0; nr_layers],

            total_util: 0.0,
            layer_utils: vec![0.0; nr_layers],
            prev_layer_cycles: vec![0; nr_layers],

            cpu_busy: 0.0,
            prev_total_cpu: read_total_cpu(&proc_reader)?,

            bpf_stats: bpf_stats.clone(),
            prev_bpf_stats: bpf_stats,
        })
    }

    fn refresh(
        &mut self,
        skel: &mut BpfSkel,
        proc_reader: &procfs::ProcReader,
        now: Instant,
    ) -> Result<()> {
        let elapsed = now.duration_since(self.at).as_secs_f64() as f64;
        let cpu_ctxs = read_cpu_ctxs(skel)?;

        let nr_layer_tasks: Vec<usize> = skel
            .bss()
            .layers
            .iter()
            .take(self.nr_layers)
            .map(|layer| layer.nr_tasks as usize)
            .collect();

        let (total_load, layer_loads) = Self::read_layer_loads(skel, self.nr_layers);

        let cur_layer_cycles = Self::read_layer_cycles(&cpu_ctxs, self.nr_layers);
        let cur_layer_utils: Vec<f64> = cur_layer_cycles
            .iter()
            .zip(self.prev_layer_cycles.iter())
            .map(|(cur, prev)| (cur - prev) as f64 / 1_000_000_000.0 / elapsed)
            .collect();
        let layer_utils: Vec<f64> = cur_layer_utils
            .iter()
            .zip(self.layer_utils.iter())
            .map(|(cur, prev)| {
                let decay = USAGE_DECAY.powf(elapsed);
                prev * decay + cur * (1.0 - decay)
            })
            .collect();

        let cur_total_cpu = read_total_cpu(proc_reader)?;
        let cpu_busy = calc_util(&cur_total_cpu, &self.prev_total_cpu)?;

        let cur_bpf_stats = BpfStats::read(&cpu_ctxs, self.nr_layers);
        let bpf_stats = &cur_bpf_stats - &self.prev_bpf_stats;

        *self = Self {
            at: now,
            nr_layers: self.nr_layers,

            nr_layer_tasks,

            total_load,
            layer_loads,

            total_util: layer_utils.iter().sum(),
            layer_utils: layer_utils.try_into().unwrap(),
            prev_layer_cycles: cur_layer_cycles,

            cpu_busy,
            prev_total_cpu: cur_total_cpu,

            bpf_stats,
            prev_bpf_stats: cur_bpf_stats,
        };
        Ok(())
    }
}

#[derive(Debug, Default)]
struct UserExitInfo {
    kind: i32,
    reason: Option<String>,
    msg: Option<String>,
}

impl UserExitInfo {
    fn read(bpf_uei: &bpf_bss_types::user_exit_info) -> Result<Self> {
        let kind = unsafe { std::ptr::read_volatile(&bpf_uei.kind as *const _) };

        let (reason, msg) = if kind != 0 {
            (
                Some(
                    unsafe { CStr::from_ptr(bpf_uei.reason.as_ptr() as *const _) }
                        .to_str()
                        .context("Failed to convert reason to string")?
                        .to_string(),
                )
                .filter(|s| !s.is_empty()),
                Some(
                    unsafe { CStr::from_ptr(bpf_uei.msg.as_ptr() as *const _) }
                        .to_str()
                        .context("Failed to convert msg to string")?
                        .to_string(),
                )
                .filter(|s| !s.is_empty()),
            )
        } else {
            (None, None)
        };

        Ok(Self { kind, reason, msg })
    }

    fn exited(bpf_uei: &bpf_bss_types::user_exit_info) -> Result<bool> {
        Ok(Self::read(bpf_uei)?.kind != 0)
    }

    fn report(&self) -> Result<()> {
        let why = match (&self.reason, &self.msg) {
            (Some(reason), None) => format!("{}", reason),
            (Some(reason), Some(msg)) => format!("{} ({})", reason, msg),
            _ => "".into(),
        };

        match self.kind {
            0 => Ok(()),
            etype => {
                if etype != 64 {
                    bail!("EXIT: kind={} {}", etype, why);
                } else {
                    info!("EXIT: {}", why);
                    Ok(())
                }
            }
        }
    }
}

#[derive(Debug)]
struct CpuPool {
    nr_cores: usize,
    nr_cpus: usize,
    all_cpus: BitVec,
    core_cpus: Vec<BitVec>,
    cpu_core: Vec<usize>,
    available_cores: BitVec,
    first_cpu: usize,
    fallback_cpu: usize, // next free or the first CPU if none is free
}

impl CpuPool {
    fn new() -> Result<Self> {
        if *NR_POSSIBLE_CPUS > MAX_CPUS {
            bail!(
                "NR_POSSIBLE_CPUS {} > MAX_CPUS {}",
                *NR_POSSIBLE_CPUS,
                MAX_CPUS
            );
        }

        let mut cpu_to_cache = vec![]; // (cpu_id, Option<cache_id>)
        let mut cache_ids = BTreeSet::<usize>::new();
        let mut nr_offline = 0;

        // Build cpu -> cache ID mapping.
        for cpu in 0..*NR_POSSIBLE_CPUS {
            let path = format!(
                "/sys/devices/system/cpu/cpu{}/cache/index{}/id",
                cpu, CORE_CACHE_LEVEL
            );
            let id = match std::fs::read_to_string(&path) {
                Ok(val) => Some(val.trim().parse::<usize>().with_context(|| {
                    format!("Failed to parse {:?}'s content {:?}", &path, &val)
                })?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    nr_offline += 1;
                    None
                }
                Err(e) => return Err(e).with_context(|| format!("Failed to open {:?}", &path)),
            };

            cpu_to_cache.push(id);
            if let Some(id) = id {
                cache_ids.insert(id);
            }
        }

        let nr_cpus = *NR_POSSIBLE_CPUS - nr_offline;

        // Cache IDs may have holes. Assign consecutive core IDs to existing
        // cache IDs.
        let mut cache_to_core = BTreeMap::<usize, usize>::new();
        let mut nr_cores = 0;
        for cache_id in cache_ids.iter() {
            cache_to_core.insert(*cache_id, nr_cores);
            nr_cores += 1;
        }

        // Build core -> cpumask and cpu -> core mappings.
        let mut all_cpus = bitvec![0; *NR_POSSIBLE_CPUS];
        let mut core_cpus = vec![bitvec![0; *NR_POSSIBLE_CPUS]; nr_cores];
        let mut cpu_core = vec![];

        for (cpu, cache) in cpu_to_cache.iter().enumerate().take(*NR_POSSIBLE_CPUS) {
            if let Some(cache_id) = cache {
                let core_id = cache_to_core[cache_id];
                all_cpus.set(cpu, true);
                core_cpus[core_id].set(cpu, true);
                cpu_core.push(core_id);
            }
        }

        info!(
            "CPUs: online/possible={}/{} nr_cores={}",
            nr_cpus, *NR_POSSIBLE_CPUS, nr_cores,
        );

        let first_cpu = core_cpus[0].first_one().unwrap();

        let mut cpu_pool = Self {
            nr_cores,
            nr_cpus,
            all_cpus,
            core_cpus,
            cpu_core,
            available_cores: bitvec![1; nr_cores],
            first_cpu,
            fallback_cpu: first_cpu,
        };
        cpu_pool.update_fallback_cpu();
        Ok(cpu_pool)
    }

    fn update_fallback_cpu(&mut self) {
        match self.available_cores.first_one() {
            Some(next) => self.fallback_cpu = self.core_cpus[next].first_one().unwrap(),
            None => self.fallback_cpu = self.first_cpu,
        }
    }

    fn alloc<'a>(&'a mut self) -> Option<&'a BitVec> {
        let core = self.available_cores.first_one()?;
        self.available_cores.set(core, false);
        self.update_fallback_cpu();
        Some(&self.core_cpus[core])
    }

    fn cpus_to_cores(&self, cpus_to_match: &BitVec) -> Result<BitVec> {
        let mut cpus = cpus_to_match.clone();
        let mut cores = bitvec![0; self.nr_cores];

        while let Some(cpu) = cpus.first_one() {
            let core = self.cpu_core[cpu];

            if (self.core_cpus[core].clone() & !cpus.clone()).count_ones() != 0 {
                bail!(
                    "CPUs {} partially intersect with core {} ({})",
                    cpus_to_match,
                    core,
                    self.core_cpus[core],
                );
            }

            cpus &= !self.core_cpus[core].clone();
            cores.set(core, true);
        }

        Ok(cores)
    }

    fn free<'a>(&'a mut self, cpus_to_free: &BitVec) -> Result<()> {
        let cores = self.cpus_to_cores(cpus_to_free)?;
        if (self.available_cores.clone() & &cores).any() {
            bail!("Some of CPUs {} are already free", cpus_to_free);
        }
        self.available_cores |= cores;
        self.update_fallback_cpu();
        Ok(())
    }

    fn next_to_free<'a>(&'a self, cands: &BitVec) -> Result<Option<&'a BitVec>> {
        let last = match cands.last_one() {
            Some(ret) => ret,
            None => return Ok(None),
        };
        let core = self.cpu_core[last];
        if (self.core_cpus[core].clone() & !cands.clone()).count_ones() != 0 {
            bail!(
                "CPUs{} partially intersect with core {} ({})",
                cands,
                core,
                self.core_cpus[core]
            );
        }

        Ok(Some(&self.core_cpus[core]))
    }

    fn available_cpus(&self) -> BitVec {
        let mut cpus = bitvec![0; self.nr_cpus];
        for core in self.available_cores.iter_ones() {
            cpus |= &self.core_cpus[core];
        }
        cpus
    }
}

#[derive(Debug)]
struct Layer {
    name: String,
    kind: LayerKind,

    nr_cpus: usize,
    cpus: BitVec,
}

impl Layer {
    fn new(cpu_pool: &mut CpuPool, name: &str, kind: LayerKind) -> Result<Self> {
        match &kind {
            LayerKind::Confined {
                cpus_range,
                util_range,
            } => {
                let cpus_range = cpus_range.unwrap_or((0, std::usize::MAX));
                if cpus_range.0 > cpus_range.1 || cpus_range.1 == 0 {
                    bail!("invalid cpus_range {:?}", cpus_range);
                }
                if util_range.0 < 0.0
                    || util_range.0 > 1.0
                    || util_range.1 < 0.0
                    || util_range.1 > 1.0
                    || util_range.0 >= util_range.1
                {
                    bail!("invalid util_range {:?}", util_range);
                }
            }
            _ => {}
        }

        let nr_cpus = cpu_pool.nr_cpus;

        let mut layer = Self {
            name: name.into(),
            kind,

            nr_cpus: 0,
            cpus: bitvec![0; nr_cpus],
        };

        match &layer.kind {
            LayerKind::Confined {
                cpus_range,
                util_range,
            }
            | LayerKind::Grouped {
                cpus_range,
                util_range,
                ..
            } => {
                layer.resize_confined_or_grouped(
                    cpu_pool,
                    *cpus_range,
                    *util_range,
                    (0.0, 0.0),
                    (0.0, 0.0),
                    false,
                )?;
            }
            _ => {}
        }

        Ok(layer)
    }

    fn grow_confined_or_grouped(
        &mut self,
        cpu_pool: &mut CpuPool,
        (cpus_min, cpus_max): (usize, usize),
        (_util_low, util_high): (f64, f64),
        (layer_load, total_load): (f64, f64),
        (layer_util, _total_util): (f64, f64),
        no_load_frac_limit: bool,
    ) -> Result<bool> {
        if self.nr_cpus >= cpus_max {
            return Ok(false);
        }

        // Do we already have enough?
        if self.nr_cpus >= cpus_min
            && (layer_util == 0.0
                || (self.nr_cpus > 0 && layer_util / self.nr_cpus as f64 <= util_high))
        {
            return Ok(false);
        }

        // Can't have more CPUs than our load fraction.
        if !no_load_frac_limit
            && self.nr_cpus >= cpus_min
            && (total_load >= 0.0
                && self.nr_cpus as f64 / cpu_pool.nr_cpus as f64 >= layer_load / total_load)
        {
            trace!(
                "layer-{} needs more CPUs (util={:.3}) but is over the load fraction",
                &self.name,
                layer_util
            );
            return Ok(false);
        }

        let new_cpus = match cpu_pool.alloc().clone() {
            Some(ret) => ret.clone(),
            None => {
                trace!("layer-{} can't grow, no CPUs", &self.name);
                return Ok(false);
            }
        };

        trace!(
            "layer-{} adding {} CPUs to {} CPUs",
            &self.name,
            new_cpus.count_ones(),
            self.nr_cpus
        );

        self.nr_cpus += new_cpus.count_ones();
        self.cpus |= &new_cpus;
        Ok(true)
    }

    fn cpus_to_free(
        &self,
        cpu_pool: &mut CpuPool,
        (cpus_min, _cpus_max): (usize, usize),
        (util_low, util_high): (f64, f64),
        (layer_load, total_load): (f64, f64),
        (layer_util, _total_util): (f64, f64),
        no_load_frac_limit: bool,
    ) -> Result<Option<BitVec>> {
        if self.nr_cpus <= cpus_min {
            return Ok(None);
        }

        let cpus_to_free = match cpu_pool.next_to_free(&self.cpus)? {
            Some(ret) => ret.clone(),
            None => return Ok(None),
        };

        let nr_to_free = cpus_to_free.count_ones();

        // If we'd be over the load fraction even after freeing
        // $cpus_to_free, we have to free.
        if !no_load_frac_limit
            && total_load >= 0.0
            && (self.nr_cpus - nr_to_free) as f64 / cpu_pool.nr_cpus as f64
                >= layer_load / total_load
        {
            return Ok(Some(cpus_to_free));
        }

        if layer_util / self.nr_cpus as f64 >= util_low {
            return Ok(None);
        }

        // Can't shrink if losing the CPUs pushes us over @util_high.
        match self.nr_cpus - nr_to_free {
            0 => {
                if layer_util > 0.0 {
                    return Ok(None);
                }
            }
            nr_left => {
                if layer_util / nr_left as f64 >= util_high {
                    return Ok(None);
                }
            }
        }

        return Ok(Some(cpus_to_free));
    }

    fn shrink_confined_or_grouped(
        &mut self,
        cpu_pool: &mut CpuPool,
        cpus_range: (usize, usize),
        util_range: (f64, f64),
        load: (f64, f64),
        util: (f64, f64),
        no_load_frac_limit: bool,
    ) -> Result<bool> {
        match self.cpus_to_free(
            cpu_pool,
            cpus_range,
            util_range,
            load,
            util,
            no_load_frac_limit,
        )? {
            Some(cpus_to_free) => {
                trace!("freeing CPUs {}", &cpus_to_free);
                self.nr_cpus -= cpus_to_free.count_ones();
                self.cpus &= !cpus_to_free.clone();
                cpu_pool.free(&cpus_to_free)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn resize_confined_or_grouped(
        &mut self,
        cpu_pool: &mut CpuPool,
        cpus_range: Option<(usize, usize)>,
        util_range: (f64, f64),
        load: (f64, f64),
        util: (f64, f64),
        no_load_frac_limit: bool,
    ) -> Result<i64> {
        let cpus_range = cpus_range.unwrap_or((0, std::usize::MAX));
        let mut adjusted = 0;

        while self.grow_confined_or_grouped(
            cpu_pool,
            cpus_range,
            util_range,
            load,
            util,
            no_load_frac_limit,
        )? {
            adjusted += 1;
            trace!("{} grew, adjusted={}", &self.name, adjusted);
        }

        if adjusted == 0 {
            while self.shrink_confined_or_grouped(
                cpu_pool,
                cpus_range,
                util_range,
                load,
                util,
                no_load_frac_limit,
            )? {
                adjusted -= 1;
                trace!("{} shrunk, adjusted={}", &self.name, adjusted);
            }
        }

        if adjusted != 0 {
            trace!("{} done resizing, adjusted={}", &self.name, adjusted);
        }
        Ok(adjusted)
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    layer_specs: Vec<LayerSpec>,

    sched_intv: Duration,
    monitor_intv: Duration,
    no_load_frac_limit: bool,

    cpu_pool: CpuPool,
    layers: Vec<Layer>,

    proc_reader: procfs::ProcReader,
    sched_stats: Stats,
    report_stats: Stats,

    nr_layer_cpus_min_max: Vec<(usize, usize)>,
    processing_dur: Duration,
    prev_processing_dur: Duration,
}

impl<'a> Scheduler<'a> {
    fn init_layers(skel: &mut OpenBpfSkel, specs: &Vec<LayerSpec>) -> Result<()> {
        skel.rodata_mut().nr_layers = specs.len() as u32;

        for (spec_i, spec) in specs.iter().enumerate() {
            let layer = &mut skel.bss_mut().layers[spec_i];

            for (or_i, or) in spec.matches.iter().enumerate() {
                for (and_i, and) in or.iter().enumerate() {
                    let mt = &mut layer.matches[or_i].matches[and_i];
                    match and {
                        LayerMatch::CgroupPrefix(prefix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_CGROUP_PREFIX as i32;
                            copy_into_cstr(&mut mt.cgroup_prefix, prefix.as_str());
                        }
                        LayerMatch::CommPrefix(prefix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_COMM_PREFIX as i32;
                            copy_into_cstr(&mut mt.comm_prefix, prefix.as_str());
                        }
                        LayerMatch::NiceAbove(nice) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_NICE_ABOVE as i32;
                            mt.nice_above_or_below = *nice;
                        }
                        LayerMatch::NiceBelow(nice) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_NICE_BELOW as i32;
                            mt.nice_above_or_below = *nice;
                        }
                    }
                }
                layer.matches[or_i].nr_match_ands = or.len() as i32;
            }

            layer.nr_match_ors = spec.matches.len() as u32;

            match &spec.kind {
                LayerKind::Open { preempt } | LayerKind::Grouped { preempt, .. } => {
                    layer.open = true;
                    layer.preempt = *preempt;
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn init(opts: &Opts, layer_specs: Vec<LayerSpec>) -> Result<Self> {
        let nr_layers = layer_specs.len();
        let mut cpu_pool = CpuPool::new()?;

        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 1);
        let mut skel = skel_builder.open().context("Failed to open BPF program")?;

        // Initialize skel according to @opts.
        skel.rodata_mut().debug = opts.verbose as u32;
        skel.rodata_mut().slice_ns = opts.slice_us * 1000;
        skel.rodata_mut().nr_possible_cpus = *NR_POSSIBLE_CPUS as u32;
        skel.rodata_mut().smt_enabled = cpu_pool.nr_cpus > cpu_pool.nr_cores;
        for cpu in cpu_pool.all_cpus.iter_ones() {
            skel.rodata_mut().all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }
        Self::init_layers(&mut skel, &layer_specs)?;

        // Attach.
        let mut skel = skel.load().context("Failed to load BPF program")?;
        skel.attach().context("Failed to attach BPF program")?;
        let struct_ops = Some(
            skel.maps_mut()
                .layered()
                .attach_struct_ops()
                .context("Failed to attach layered struct ops")?,
        );
        info!("Layered Scheduler Attached");

        let mut layers = vec![];
        for spec in layer_specs.iter() {
            layers.push(Layer::new(&mut cpu_pool, &spec.name, spec.kind.clone())?);
        }

        // Other stuff.
        let proc_reader = procfs::ProcReader::new();

        Ok(Self {
            struct_ops, // should be held to keep it attached
            layer_specs,

            sched_intv: Duration::from_secs_f64(opts.interval),
            monitor_intv: Duration::from_secs_f64(opts.monitor),
            no_load_frac_limit: opts.no_load_frac_limit,

            cpu_pool,
            layers,

            sched_stats: Stats::new(&mut skel, &proc_reader)?,
            report_stats: Stats::new(&mut skel, &proc_reader)?,

            nr_layer_cpus_min_max: vec![(0, 0); nr_layers],
            processing_dur: Duration::from_millis(0),
            prev_processing_dur: Duration::from_millis(0),

            proc_reader,
            skel,
        })
    }

    fn update_bpf_layer_cpumask(layer: &Layer, bpf_layer: &mut bpf_bss_types::layer) {
        for bit in 0..layer.cpus.len() {
            if layer.cpus[bit] {
                bpf_layer.cpus[bit / 8] |= 1 << (bit % 8);
            } else {
                bpf_layer.cpus[bit / 8] &= !(1 << (bit % 8));
            }
        }
        bpf_layer.refresh_cpus = 1;
    }

    fn step(&mut self) -> Result<()> {
        let started_at = Instant::now();
        self.sched_stats
            .refresh(&mut self.skel, &self.proc_reader, started_at)?;
        let mut updated = false;

        for idx in 0..self.layers.len() {
            match self.layers[idx].kind {
                LayerKind::Confined {
                    cpus_range,
                    util_range,
                }
                | LayerKind::Grouped {
                    cpus_range,
                    util_range,
                    ..
                } => {
                    let load = (
                        self.sched_stats.layer_loads[idx],
                        self.sched_stats.total_load,
                    );
                    let util = (
                        self.sched_stats.layer_utils[idx],
                        self.sched_stats.total_util,
                    );
                    if self.layers[idx].resize_confined_or_grouped(
                        &mut self.cpu_pool,
                        cpus_range,
                        util_range,
                        load,
                        util,
                        self.no_load_frac_limit,
                    )? != 0
                    {
                        Self::update_bpf_layer_cpumask(
                            &self.layers[idx],
                            &mut self.skel.bss_mut().layers[idx],
                        );
                        updated = true;
                    }
                }
                _ => {}
            }
        }

        if updated {
            let available_cpus = self.cpu_pool.available_cpus();
            let nr_available_cpus = available_cpus.count_ones();
            for idx in 0..self.layers.len() {
                let layer = &mut self.layers[idx];
                let bpf_layer = &mut self.skel.bss_mut().layers[idx];
                match &layer.kind {
                    LayerKind::Open { .. } => {
                        layer.cpus.copy_from_bitslice(&available_cpus);
                        layer.nr_cpus = nr_available_cpus;
                        Self::update_bpf_layer_cpumask(layer, bpf_layer);
                    }
                    _ => {}
                }
            }

            self.skel.bss_mut().fallback_cpu = self.cpu_pool.fallback_cpu as u32;

            for (lidx, layer) in self.layers.iter().enumerate() {
                self.nr_layer_cpus_min_max[lidx] = (
                    self.nr_layer_cpus_min_max[lidx].0.min(layer.nr_cpus),
                    self.nr_layer_cpus_min_max[lidx].1.max(layer.nr_cpus),
                );
            }
        }

        self.processing_dur += Instant::now().duration_since(started_at);
        Ok(())
    }

    fn report(&mut self) -> Result<()> {
        let started_at = Instant::now();
        self.report_stats
            .refresh(&mut self.skel, &self.proc_reader, started_at)?;
        let stats = &self.report_stats;

        let processing_dur = self.processing_dur - self.prev_processing_dur;
        self.prev_processing_dur = self.processing_dur;

        let lsum = |idx| stats.bpf_stats.lstats_sums[idx as usize];
        let total = lsum(bpf_intf::layer_stat_idx_LSTAT_LOCAL)
            + lsum(bpf_intf::layer_stat_idx_LSTAT_GLOBAL);
        let lsum_pct = |idx| {
            if total != 0 {
                lsum(idx) as f64 / total as f64 * 100.0
            } else {
                0.0
            }
        };

        info!(
            "tot={:7} local={:5.2} open_idle={:5.2} affn_viol={:5.2} tctx_err={} proc={:?}ms",
            total,
            lsum_pct(bpf_intf::layer_stat_idx_LSTAT_LOCAL),
            lsum_pct(bpf_intf::layer_stat_idx_LSTAT_OPEN_IDLE),
            lsum_pct(bpf_intf::layer_stat_idx_LSTAT_AFFN_VIOL),
            stats.prev_bpf_stats.gstats
                [bpf_intf::global_stat_idx_GSTAT_TASK_CTX_FREE_FAILED as usize],
            processing_dur.as_millis(),
        );

        info!(
            "busy={:5.1} util={:7.1} load={:9.1} fallback_cpu={:3}",
            stats.cpu_busy * 100.0,
            stats.total_util * 100.0,
            stats.total_load,
            self.cpu_pool.fallback_cpu,
        );

        let header_width = self
            .layer_specs
            .iter()
            .map(|spec| spec.name.len())
            .max()
            .unwrap()
            .max(4);

        let calc_frac = |a, b| {
            if b != 0.0 { a / b * 100.0 } else { 0.0 }
        };

        for (lidx, (spec, layer)) in self.layer_specs.iter().zip(self.layers.iter()).enumerate() {
            let lstat = |sidx| stats.bpf_stats.lstats[lidx][sidx as usize];
            let ltotal = lstat(bpf_intf::layer_stat_idx_LSTAT_LOCAL)
                + lstat(bpf_intf::layer_stat_idx_LSTAT_GLOBAL);
            let lstat_pct = |sidx| {
                if ltotal != 0 {
                    lstat(sidx) as f64 / ltotal as f64 * 100.0
                } else {
                    0.0
                }
            };

            info!(
                "  {:<width$}: util/frac={:7.1}/{:5.1} load/frac={:9.1}:{:5.1} tasks={:6}",
                spec.name,
                stats.layer_utils[lidx] * 100.0,
                calc_frac(stats.layer_utils[lidx], stats.total_util),
                stats.layer_loads[lidx],
                calc_frac(stats.layer_loads[lidx], stats.total_load),
                stats.nr_layer_tasks[lidx],
                width = header_width,
            );
            info!(
                "  {:<width$}  tot={:7} local={:5.2} open_idle={:5.2} preempt={:5.2} affn_viol={:5.2}",
                "",
                ltotal,
                lstat_pct(bpf_intf::layer_stat_idx_LSTAT_LOCAL),
                lstat_pct(bpf_intf::layer_stat_idx_LSTAT_OPEN_IDLE),
                lstat_pct(bpf_intf::layer_stat_idx_LSTAT_PREEMPT),
                lstat_pct(bpf_intf::layer_stat_idx_LSTAT_AFFN_VIOL),
                width = header_width,
            );
            info!(
                "  {:<width$}  cpus={:3} [{:3},{:3}] {}",
                "",
                layer.nr_cpus,
                self.nr_layer_cpus_min_max[lidx].0,
                self.nr_layer_cpus_min_max[lidx].1,
                format_bitvec(&layer.cpus),
                width = header_width
            );
            self.nr_layer_cpus_min_max[lidx] = (layer.nr_cpus, layer.nr_cpus);
        }

        self.processing_dur += Instant::now().duration_since(started_at);
        Ok(())
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let now = Instant::now();
        let mut next_sched_at = now + self.sched_intv;
        let mut next_monitor_at = now + self.monitor_intv;

        while !shutdown.load(Ordering::Relaxed) && !UserExitInfo::exited(&self.skel.bss().uei)? {
            let now = Instant::now();

            if now >= next_sched_at {
                self.step()?;
                while next_sched_at < now {
                    next_sched_at += self.sched_intv;
                }
            }

            if now >= next_monitor_at {
                self.report()?;
                while next_monitor_at < now {
                    next_monitor_at += self.monitor_intv;
                }
            }

            std::thread::sleep(
                next_sched_at
                    .min(next_monitor_at)
                    .duration_since(Instant::now()),
            );
        }

        self.struct_ops.take();
        UserExitInfo::read(&self.skel.bss().uei)?.report()
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
    }
}

fn write_example_file(path: &str) -> Result<()> {
    let example = LayerConfig {
        specs: vec![
            LayerSpec {
                name: "batch".into(),
                comment: Some("tasks under system.slice or tasks with nice value > 0".into()),
                matches: vec![
                    vec![LayerMatch::CgroupPrefix("system.slice/".into())],
                    vec![LayerMatch::NiceAbove(0)],
                ],
                kind: LayerKind::Confined {
                    cpus_range: Some((0, 16)),
                    util_range: (0.8, 0.9),
                },
            },
            LayerSpec {
                name: "immediate".into(),
                comment: Some("tasks under workload.slice with nice value < 0".into()),
                matches: vec![vec![
                    LayerMatch::CgroupPrefix("workload.slice/".into()),
                    LayerMatch::NiceBelow(0),
                ]],
                kind: LayerKind::Open { preempt: true },
            },
            LayerSpec {
                name: "normal".into(),
                comment: Some("the rest".into()),
                matches: vec![vec![]],
                kind: LayerKind::Grouped {
                    cpus_range: None,
                    util_range: (0.5, 0.6),
                    preempt: false,
                },
            },
        ],
    };

    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    Ok(f.write_all(serde_json::to_string_pretty(&example)?.as_bytes())?)
}

fn verify_layer_specs(specs: &[LayerSpec]) -> Result<()> {
    let nr_specs = specs.len();
    if nr_specs == 0 {
        bail!("No layer spec");
    }
    if nr_specs > MAX_LAYERS {
        bail!("Too many layer specs");
    }

    for (idx, spec) in specs.iter().enumerate() {
        if idx < nr_specs - 1 {
            if spec.matches.len() == 0 {
                bail!("Non-terminal spec {:?} has NULL matches", spec.name);
            }
        } else {
            if spec.matches.len() != 1 || spec.matches[0].len() != 0 {
                bail!("Terminal spec {:?} must have an empty match", spec.name);
            }
        }

        if spec.matches.len() > MAX_LAYER_MATCH_ORS {
            bail!(
                "Spec {:?} has too many ({}) OR match blocks",
                spec.name,
                spec.matches.len()
            );
        }

        for (ands_idx, ands) in spec.matches.iter().enumerate() {
            if ands.len() > NR_LAYER_MATCH_KINDS {
                bail!(
                    "Spec {:?}'s {}th OR block has too many ({}) match conditions",
                    spec.name,
                    ands_idx,
                    ands.len()
                );
            }
            for one in ands.iter() {
                match one {
                    LayerMatch::CgroupPrefix(prefix) => {
                        if prefix.len() > MAX_PATH {
                            bail!("Spec {:?} has too long a cgroup prefix", spec.name);
                        }
                    }
                    LayerMatch::CommPrefix(prefix) => {
                        if prefix.len() > MAX_COMM {
                            bail!("Spec {:?} has too long a comm prefix", spec.name);
                        }
                    }
                    _ => {}
                }
            }
        }

        match spec.kind {
            LayerKind::Confined {
                cpus_range,
                util_range,
            }
            | LayerKind::Grouped {
                cpus_range,
                util_range,
                ..
            } => {
                if let Some((cpus_min, cpus_max)) = cpus_range {
                    if cpus_min > cpus_max {
                        bail!(
                            "Spec {:?} has invalid cpus_range({}, {})",
                            spec.name,
                            cpus_min,
                            cpus_max
                        );
                    }
                }
                if util_range.0 >= util_range.1 {
                    bail!(
                        "Spec {:?} has invalid util_range ({}, {})",
                        spec.name,
                        util_range.0,
                        util_range.1
                    );
                }
            }
            _ => {}
        }
    }

    Ok(())
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

    if let Some(path) = &opts.example {
        write_example_file(path)?;
        return Ok(());
    }

    let mut layer_config = LayerConfig { specs: vec![] };
    for (idx, input) in opts.specs.iter().enumerate() {
        layer_config.specs.append(
            &mut LayerSpec::parse(input)
                .context(format!("Failed to parse specs[{}] ({:?})", idx, input))?,
        );
    }

    debug!("specs={}", serde_json::to_string_pretty(&layer_config)?);
    verify_layer_specs(&layer_config.specs)?;

    let mut sched = Scheduler::init(&opts, layer_config.specs)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    sched.run(shutdown)
}
