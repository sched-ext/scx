// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
mod stats;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::mem::MaybeUninit;
use std::ops::Sub;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::Duration;
use std::time::Instant;

use ::fb_procfs as procfs;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bitvec::prelude::*;
pub use bpf_skel::*;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use lazy_static::lazy_static;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::debug;
use log::info;
use log::trace;
use log::warn;
use scx_layered::*;
use scx_stats::prelude::*;
use scx_utils::compat;
use scx_utils::import_enums;
use scx_utils::init_libbpf_logging;
use scx_utils::ravg::ravg_read;
use scx_utils::read_netdevs;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Llc;
use scx_utils::NetDev;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPUS_POSSIBLE;
use stats::LayerStats;
use stats::StatsReq;
use stats::StatsRes;
use stats::SysStats;

const RAVG_FRAC_BITS: u32 = bpf_intf::ravg_consts_RAVG_FRAC_BITS;
const MAX_PATH: usize = bpf_intf::consts_MAX_PATH as usize;
const MAX_COMM: usize = bpf_intf::consts_MAX_COMM as usize;
const MAX_LAYER_WEIGHT: u32 = bpf_intf::consts_MAX_LAYER_WEIGHT;
const MIN_LAYER_WEIGHT: u32 = bpf_intf::consts_MIN_LAYER_WEIGHT;
const MAX_LAYER_MATCH_ORS: usize = bpf_intf::consts_MAX_LAYER_MATCH_ORS as usize;
const MAX_LAYER_NAME: usize = bpf_intf::consts_MAX_LAYER_NAME as usize;
const MAX_LAYERS: usize = bpf_intf::consts_MAX_LAYERS as usize;
const DEFAULT_LAYER_WEIGHT: u32 = bpf_intf::consts_DEFAULT_LAYER_WEIGHT;
const USAGE_HALF_LIFE: u32 = bpf_intf::consts_USAGE_HALF_LIFE;
const USAGE_HALF_LIFE_F64: f64 = USAGE_HALF_LIFE as f64 / 1_000_000_000.0;

const LAYER_USAGE_OWNED: usize = bpf_intf::layer_usage_LAYER_USAGE_OWNED as usize;
const LAYER_USAGE_OPEN: usize = bpf_intf::layer_usage_LAYER_USAGE_OPEN as usize;
const NR_LAYER_USAGES: usize = bpf_intf::layer_usage_NR_LAYER_USAGES as usize;

const NR_GSTATS: usize = bpf_intf::global_stat_id_NR_GSTATS as usize;
const NR_LSTATS: usize = bpf_intf::layer_stat_id_NR_LSTATS as usize;

const NR_LAYER_MATCH_KINDS: usize = bpf_intf::layer_match_kind_NR_LAYER_MATCH_KINDS as usize;

lazy_static! {
    static ref USAGE_DECAY: f64 = 0.5f64.powf(1.0 / USAGE_HALF_LIFE_F64);
    static ref EXAMPLE_CONFIG: LayerConfig = LayerConfig {
        specs: vec![
            LayerSpec {
                name: "batch".into(),
                comment: Some("tasks under system.slice or tasks with nice value > 0".into()),
                matches: vec![
                    vec![LayerMatch::CgroupPrefix("system.slice/".into())],
                    vec![LayerMatch::NiceAbove(0)],
                ],
                kind: LayerKind::Confined {
                    util_range: (0.8, 0.9),
                    cpus_range: Some((0, 16)),
                    common: LayerCommon {
                        min_exec_us: 1000,
                        yield_ignore: 0.0,
                        preempt: false,
                        preempt_first: false,
                        exclusive: false,
                        idle_smt: false,
                        slice_us: 20000,
                        weight: DEFAULT_LAYER_WEIGHT,
                        growth_algo: LayerGrowthAlgo::Sticky,
                        perf: 1024,
                        nodes: vec![],
                        llcs: vec![],
                    },
                },
            },
            LayerSpec {
                name: "immediate".into(),
                comment: Some("tasks under workload.slice with nice value < 0".into()),
                matches: vec![vec![
                    LayerMatch::CgroupPrefix("workload.slice/".into()),
                    LayerMatch::NiceBelow(0),
                ]],
                kind: LayerKind::Open {
                    common: LayerCommon {
                        min_exec_us: 100,
                        yield_ignore: 0.25,
                        preempt: true,
                        preempt_first: false,
                        exclusive: true,
                        idle_smt: false,
                        slice_us: 20000,
                        weight: DEFAULT_LAYER_WEIGHT,
                        growth_algo: LayerGrowthAlgo::Sticky,
                        perf: 1024,
                        nodes: vec![],
                        llcs: vec![],
                    },
                },
            },
            LayerSpec {
                name: "stress-ng".into(),
                comment: Some("stress-ng test layer".into()),
                matches: vec![
                    vec![LayerMatch::CommPrefix("stress-ng".into()),],
                    vec![LayerMatch::PcommPrefix("stress-ng".into()),]
                ],
                kind: LayerKind::Confined {
                    cpus_range: None,
                    util_range: (0.2, 0.8),
                    common: LayerCommon {
                        min_exec_us: 800,
                        yield_ignore: 0.0,
                        preempt: true,
                        preempt_first: false,
                        exclusive: false,
                        idle_smt: false,
                        slice_us: 800,
                        weight: DEFAULT_LAYER_WEIGHT,
                        growth_algo: LayerGrowthAlgo::Topo,
                        perf: 1024,
                        nodes: vec![],
                        llcs: vec![],
                    },
                },
            },
            LayerSpec {
                name: "normal".into(),
                comment: Some("the rest".into()),
                matches: vec![vec![]],
                kind: LayerKind::Grouped {
                    cpus_range: None,
                    util_range: (0.5, 0.6),
                    common: LayerCommon {
                        min_exec_us: 200,
                        yield_ignore: 0.0,
                        preempt: false,
                        preempt_first: false,
                        exclusive: false,
                        idle_smt: false,
                        slice_us: 20000,
                        weight: DEFAULT_LAYER_WEIGHT,
                        growth_algo: LayerGrowthAlgo::Linear,
                        perf: 1024,
                        nodes: vec![],
                        llcs: vec![],
                    },
                },
            },
        ],
    };
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
/// - Tasks which are in the cgroup sub-hierarchy under "system.slice".
///
/// - Or tasks whose comm starts with "fbagent" and have a nice value > 0.
///
/// Currently, the following matches are supported:
///
/// - CgroupPrefix: Matches the prefix of the cgroup that the task belongs
///   to. As this is a string match, whether the pattern has the trailing
///   '/' makes a difference. For example, "TOP/CHILD/" only matches tasks
///   which are under that particular cgroup while "TOP/CHILD" also matches
///   tasks under "TOP/CHILD0/" or "TOP/CHILD1/".
///
/// - CommPrefix: Matches the task's comm prefix.
///
/// - PcommPrefix: Matches the task's thread group leader's comm prefix.
///
/// - NiceAbove: Matches if the task's nice value is greater than the
///   pattern.
///
/// - NiceBelow: Matches if the task's nice value is smaller than the
///   pattern.
///
/// - NiceEquals: Matches if the task's nice value is exactly equal to
///   the pattern.
///
/// - UIDEquals: Matches if the task's effective user id matches the value
///
/// - GIDEquals: Matches if the task's effective group id matches the value.
///
/// - PIDEquals: Matches if the task's pid matches the value.
///
/// - PPIDEquals: Matches if the task's ppid matches the value.
///
/// - TGIDEquals: Matches if the task's tgid matches the value.
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
/// - Confined: Tasks are restricted to the allocated CPUs. The number of
///   CPUs allocated is modulated to keep the per-CPU utilization in
///   "util_range". The range can optionally be restricted with the
///   "cpus_range" property.
///
/// - Grouped: Similar to Confined but tasks may spill outside if there are
///   idle CPUs outside the allocated ones.
///
/// - Open: Prefer the CPUs which are not occupied by Confined or Grouped
///   layers. Tasks in this group will spill into occupied CPUs if there are
///   no unoccupied idle CPUs.
///
/// All layers take the following options:
///
/// - min_exec_us: Minimum execution time in microseconds. Whenever a task
///   is scheduled in, this is the minimum CPU time that it's charged no
///   matter how short the actual execution time may be.
///
/// - yield_ignore: Yield ignore ratio. If 0.0, yield(2) forfeits a whole
///   execution slice. 0.25 yields three quarters of an execution slice and
///   so on. If 1.0, yield is completely ignored.
///
/// - preempt: If true, tasks in the layer will preempt tasks which belong
///   to other non-preempting layers when no idle CPUs are available.
///
/// - preempt_first: If true, tasks in the layer will try to preempt tasks
///   in their previous CPUs before trying to find idle CPUs.
///
/// - exclusive: If true, tasks in the layer will occupy the whole core. The
///   other logical CPUs sharing the same core will be kept idle. This isn't
///   a hard guarantee, so don't depend on it for security purposes.
///
/// - slice_us: Scheduling slice duration in microseconds.
///
/// - weight: Weight of the layer, which is a range from 1 to 10000 with a
///   default of 100. Layer weights are used during contention to prevent
///   starvation across layers. Weights are used in combination with
///   utilization to determine the infeasible adjusted weight with higher
///   weights having a larger adjustment in adjusted utilization.
///
/// - idle_smt: When selecting an idle CPU for task task migration use
///   only idle SMT CPUs. The default is to select any idle cpu.
///
/// - growth_algo: When a layer is allocated new CPUs different algorithms can
///   be used to determine which CPU should be allocated next. The default
///   algorithm is a "sticky" algorithm that attempts to spread layers evenly
///   across cores.
///
/// - perf: CPU performance target. 0 means no configuration. A value
///   between 1 and 1024 indicates the performance level CPUs running tasks
///   in this layer are configured to using scx_bpf_cpuperf_set().
///
/// - nodes: If set the layer will use the set of NUMA nodes for scheduling
///   decisions. If unset then all available NUMA nodes will be used. If the
///   llcs value is set the cpuset of NUMA nodes will be or'ed with the LLC
///   config.
///
/// - llcs: If set the layer will use the set of LLCs (last level caches)
///   for scheduling decisions. If unset then all LLCs will be used. If
///   the nodes value is set the cpuset of LLCs will be or'ed with the nodes
///   config.
///
///
/// Similar to matches, adding new policies and extending existing ones
/// should be relatively straightforward.
///
/// Configuration example and running scx_layered
/// =============================================
///
/// An scx_layered config is composed of layer configs. A layer config is
/// composed of a name, a set of matches, and a policy block. Running the
/// following will write an example configuration into example.json.
///
///   $ scx_layered -e example.json
///
/// Note that the last layer in the configuration must have an empty match set
/// as a catch-all for tasks which haven't been matched into previous layers.
///
/// The configuration can be specified in multiple json files and
/// command line arguments, which are concatenated in the specified
/// order. Each must contain valid layer configurations.
///
/// By default, an argument to scx_layered is interpreted as a JSON string. If
/// the argument is a pointer to a JSON file, it should be prefixed with file:
/// or f: as follows:
///
///   $ scx_layered file:example.json
///   ...
///   $ scx_layered f:example.json
///
/// Monitoring Statistics
/// =====================
///
/// Run with `--stats INTERVAL` to enable stats monitoring. There is
/// also an scx_stat server listening on /var/run/scx/root/stat that can
/// be monitored by running `scx_layered --monitor INTERVAL` separately.
///
///   ```bash
///   $ scx_layered --monitor 1
///   tot= 117909 local=86.20 open_idle= 0.21 affn_viol= 1.37 proc=6ms
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
///   ```
///
/// Global statistics: see [`SysStats`]
///
/// Per-layer statistics: see [`LayerStats`]
///
#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    /// Maximum consecutive execution time in microseconds. A task may be
    /// allowed to keep executing on a CPU for this long. Note that this is
    /// the upper limit and a task may have to moved off the CPU earlier. 0
    /// indicates default - 20 * slice_us.
    #[clap(short = 'M', long, default_value = "0")]
    max_exec_us: u64,

    /// Scheduling interval in seconds.
    #[clap(short = 'i', long, default_value = "0.1")]
    interval: f64,

    /// ***DEPRECATED*** Disable load-fraction based max layer CPU limit.
    /// recommended.
    #[clap(short = 'n', long, default_value = "false")]
    no_load_frac_limit: bool,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Disable topology awareness. When enabled, the "nodes" and "llcs" settings on
    /// a layer are ignored. Defaults to false on topologies with multiple NUMA nodes
    /// or LLCs, and true otherwise.
    #[arg(short = 't', long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    disable_topology: Option<bool>,

    /// Enable cross NUMA preemption.
    #[clap(long)]
    xnuma_preemption: bool,

    /// Disable monitor
    #[clap(long)]
    monitor_disable: bool,

    /// Write example layer specifications into the file and exit.
    #[clap(short = 'e', long)]
    example: Option<String>,

    /// ***DEPRECATED*** Disables preemption if the weighted load fraction
    /// of a layer (load_frac_adj) exceeds the threshold. The default is
    /// disabled (0.0).
    #[clap(long, default_value = "0.0")]
    layer_preempt_weight_disable: f64,

    /// ***DEPRECATED*** Disables layer growth if the weighted load fraction
    /// of a layer (load_frac_adj) exceeds the threshold. The default is
    /// disabled (0.0).
    #[clap(long, default_value = "0.0")]
    layer_growth_weight_disable: f64,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Run with example layer specifications (useful for e.g. CI pipelines)
    #[clap(long)]
    run_example: bool,

    /// Enables iteration over local LLCs first for dispatch.
    #[clap(long, default_value = "false")]
    local_llc_iteration: bool,

    /// Disable antistall
    #[clap(long, default_value = "false")]
    disable_antistall: bool,

    /// Enable netdev IRQ balancing. This is experimental and should be used with caution.
    #[clap(long, default_value = "false")]
    netdev_irq_balance: bool,

    /// Maximum task runnable_at delay (in seconds) before antistall turns on
    #[clap(long, default_value = "3")]
    antistall_sec: u64,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    /// Layer specification. See --help.
    specs: Vec<String>,
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
            let idle_usec = curr_idle.saturating_sub(*prev_idle);
            let iowait_usec = curr_iowait.saturating_sub(*prev_iowait);
            let user_usec = curr_user.saturating_sub(*prev_user);
            let system_usec = curr_system.saturating_sub(*prev_system);
            let nice_usec = curr_nice.saturating_sub(*prev_nice);
            let irq_usec = curr_irq.saturating_sub(*prev_irq);
            let softirq_usec = curr_softirq.saturating_sub(*prev_softirq);
            let stolen_usec = curr_stolen.saturating_sub(*prev_stolen);

            let busy_usec =
                user_usec + system_usec + nice_usec + irq_usec + softirq_usec + stolen_usec;
            let total_usec = idle_usec + busy_usec + iowait_usec;
            if total_usec > 0 {
                Ok(((busy_usec as f64) / (total_usec as f64)).clamp(0.0, 1.0))
            } else {
                Ok(1.0)
            }
        }
        _ => bail!("Missing stats in cpustat"),
    }
}

fn copy_into_cstr(dst: &mut [i8], src: &str) {
    let cstr = CString::new(src).unwrap();
    let bytes = unsafe { std::mem::transmute::<&[u8], &[i8]>(cstr.as_bytes_with_nul()) };
    dst[0..bytes.len()].copy_from_slice(bytes);
}

fn nodemask_from_nodes(nodes: &Vec<usize>) -> usize {
    let mut mask = 0;
    for node in nodes {
        mask |= 1 << node;
    }
    mask
}

fn llcmask_from_llcs(llcs: &BTreeMap<usize, Arc<Llc>>) -> usize {
    let mut mask = 0;
    for (_, cache) in llcs {
        mask |= 1 << cache.id;
    }
    mask
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

fn init_cpu_prox_map(topo: &Topology, cpu_ctxs: &mut Vec<bpf_intf::cpu_ctx>) {
    for (&cpu_id, cpu) in &topo.all_cpus {
        // Collect the spans.
        let mut core_span = topo.all_cores[&cpu.core_id].span.clone();
        let llc_span = &topo.all_llcs[&cpu.llc_id].span;
        let node_span = &topo.nodes[&cpu.node_id].span;
        let sys_span = &topo.span;

        // Make the spans exclusive and conver.
        let sys_span = sys_span.and(&node_span.not());
        let node_span = node_span.and(&llc_span.not());
        let llc_span = llc_span.and(&core_span.not());
        core_span.clear_cpu(cpu_id).unwrap();

        // Convert them into arrays.
        let mut sys_order: Vec<usize> = sys_span.into_iter().collect();
        let mut node_order: Vec<usize> = node_span.into_iter().collect();
        let mut llc_order: Vec<usize> = llc_span.into_iter().collect();
        let mut core_order: Vec<usize> = core_span.into_iter().collect();

        // Shuffle them so that different CPUs follow different orders.
        // This isn't ideal as random shuffling won't give us complete
        // fairness. Can be improved by making each CPU radiate in both
        // directions. For shuffling, use predictable seeds so that
        // orderings are reproducible.
        fastrand::seed(cpu_id as u64);
        fastrand::shuffle(&mut sys_order);
        fastrand::shuffle(&mut node_order);
        fastrand::shuffle(&mut llc_order);
        fastrand::shuffle(&mut core_order);

        // Concatenate them and record the topology boundaries.
        let mut order: Vec<usize> = vec![];
        let mut idx: usize = 0;

        idx += 1;
        order.push(cpu_id);

        idx += core_order.len();
        order.append(&mut core_order);
        let core_end = idx;

        idx += llc_order.len();
        order.append(&mut llc_order);
        let llc_end = idx;

        idx += node_order.len();
        order.append(&mut node_order);
        let node_end = idx;

        idx += sys_order.len();
        order.append(&mut sys_order);
        let sys_end = idx;

        debug!(
            "CPU proximity map[{}/{}/{}/{}]: {:?}",
            core_end, llc_end, node_end, sys_end, &order
        );

        // Record in cpu_ctx.
        let pmap = &mut cpu_ctxs[cpu_id].prox_map;
        for (i, &cpu) in order.iter().enumerate() {
            pmap.cpus[i] = cpu as u16;
        }
        pmap.core_end = core_end as u32;
        pmap.llc_end = llc_end as u32;
        pmap.node_end = node_end as u32;
        pmap.sys_end = sys_end as u32;
    }
}

fn convert_cpu_ctxs(cpu_ctxs: Vec<bpf_intf::cpu_ctx>) -> Vec<Vec<u8>> {
    cpu_ctxs
        .into_iter()
        .map(|cpu_ctx| {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &cpu_ctx as *const bpf_intf::cpu_ctx as *const u8,
                    std::mem::size_of::<bpf_intf::cpu_ctx>(),
                )
            };
            bytes.to_vec()
        })
        .collect()
}

fn initialize_cpu_ctxs(skel: &BpfSkel, topo: &Topology) -> Result<()> {
    let key = (0_u32).to_ne_bytes();
    let mut cpu_ctxs: Vec<bpf_intf::cpu_ctx> = vec![];
    let cpu_ctxs_vec = skel
        .maps
        .cpu_ctxs
        .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        .context("Failed to lookup cpu_ctx")?
        .unwrap();

    // FIXME - this incorrectly assumes all possible CPUs are consecutive.
    for cpu in 0..*NR_CPUS_POSSIBLE {
        cpu_ctxs.push(*unsafe {
            &*(cpu_ctxs_vec[cpu].as_slice().as_ptr() as *const bpf_intf::cpu_ctx)
        });

        let topo_cpu = topo.all_cpus.get(&cpu).unwrap();
        let is_big = topo_cpu.core_type == CoreType::Big { turbo: true };
        cpu_ctxs[cpu].cpu = cpu as i32;
        cpu_ctxs[cpu].layer_id = MAX_LAYERS as u32;
        cpu_ctxs[cpu].task_layer_id = MAX_LAYERS as u32;
        cpu_ctxs[cpu].is_big = is_big;
    }

    init_cpu_prox_map(topo, &mut cpu_ctxs);

    skel.maps
        .cpu_ctxs
        .update_percpu(&key, &convert_cpu_ctxs(cpu_ctxs), libbpf_rs::MapFlags::ANY)
        .context("Failed to update cpu_ctx")?;

    Ok(())
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

        for cpu in 0..*NR_CPUS_POSSIBLE {
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

#[derive(Clone, Debug)]
struct Stats {
    nr_layers: usize,
    at: Instant,

    nr_layer_tasks: Vec<usize>,

    nr_nodes: usize,
    total_load: f64,
    layer_loads: Vec<f64>,

    total_util: f64, // Running AVG of sum of layer_utils
    layer_utils: Vec<Vec<f64>>,
    prev_layer_usages: Vec<Vec<u64>>,

    cpu_busy: f64, // Read from /proc, maybe higher than total_util
    prev_total_cpu: procfs::CpuStat,

    bpf_stats: BpfStats,
    prev_bpf_stats: BpfStats,

    processing_dur: Duration,
    prev_processing_dur: Duration,

    layer_slice_us: Vec<u64>,
}

impl Stats {
    fn read_layer_loads(skel: &mut BpfSkel, nr_layers: usize) -> (f64, Vec<f64>) {
        let now_mono = now_monotonic();
        let layer_loads: Vec<f64> = skel
            .maps
            .bss_data
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

    fn read_layer_usages(cpu_ctxs: &[bpf_intf::cpu_ctx], nr_layers: usize) -> Vec<Vec<u64>> {
        let mut layer_usages = vec![vec![0u64; NR_LAYER_USAGES]; nr_layers];

        for cpu in 0..*NR_CPUS_POSSIBLE {
            for layer in 0..nr_layers {
                for usage in 0..NR_LAYER_USAGES {
                    layer_usages[layer][usage] += cpu_ctxs[cpu].layer_usages[layer][usage];
                }
            }
        }

        layer_usages
    }

    fn new(skel: &mut BpfSkel, proc_reader: &procfs::ProcReader) -> Result<Self> {
        let nr_layers = skel.maps.rodata_data.nr_layers as usize;
        let cpu_ctxs = read_cpu_ctxs(skel)?;
        let bpf_stats = BpfStats::read(&cpu_ctxs, nr_layers);
        let nr_nodes = skel.maps.rodata_data.nr_nodes as usize;

        Ok(Self {
            at: Instant::now(),
            nr_layers,

            nr_layer_tasks: vec![0; nr_layers],

            nr_nodes,
            total_load: 0.0,
            layer_loads: vec![0.0; nr_layers],

            total_util: 0.0,
            layer_utils: vec![vec![0.0; NR_LAYER_USAGES]; nr_layers],
            prev_layer_usages: Self::read_layer_usages(&cpu_ctxs, nr_layers),

            cpu_busy: 0.0,
            prev_total_cpu: read_total_cpu(&proc_reader)?,

            bpf_stats: bpf_stats.clone(),
            prev_bpf_stats: bpf_stats,

            processing_dur: Default::default(),
            prev_processing_dur: Default::default(),

            layer_slice_us: vec![0; nr_layers],
        })
    }

    fn refresh(
        &mut self,
        skel: &mut BpfSkel,
        proc_reader: &procfs::ProcReader,
        now: Instant,
        cur_processing_dur: Duration,
    ) -> Result<()> {
        let elapsed = now.duration_since(self.at).as_secs_f64() as f64;
        let cpu_ctxs = read_cpu_ctxs(skel)?;

        let nr_layer_tasks: Vec<usize> = skel
            .maps
            .bss_data
            .layers
            .iter()
            .take(self.nr_layers)
            .map(|layer| layer.nr_tasks as usize)
            .collect();
        let layer_slice_us: Vec<u64> = skel
            .maps
            .bss_data
            .layers
            .iter()
            .take(self.nr_layers)
            .map(|layer| layer.slice_ns / 1000 as u64)
            .collect();

        let (total_load, layer_loads) = Self::read_layer_loads(skel, self.nr_layers);

        let cur_layer_usages = Self::read_layer_usages(&cpu_ctxs, self.nr_layers);
        let cur_layer_utils: Vec<Vec<f64>> = cur_layer_usages
            .iter()
            .zip(self.prev_layer_usages.iter())
            .map(|(cur, prev)| {
                cur.iter()
                    .zip(prev.iter())
                    .map(|(c, p)| (c - p) as f64 / 1_000_000_000.0 / elapsed)
                    .collect()
            })
            .collect();
        let layer_utils: Vec<Vec<f64>> = cur_layer_utils
            .iter()
            .zip(self.layer_utils.iter())
            .map(|(cur, prev)| {
                cur.iter()
                    .zip(prev.iter())
                    .map(|(c, p)| {
                        let decay = USAGE_DECAY.powf(elapsed);
                        p * decay + c * (1.0 - decay)
                    })
                    .collect()
            })
            .collect();

        let cur_total_cpu = read_total_cpu(proc_reader)?;
        let cpu_busy = calc_util(&cur_total_cpu, &self.prev_total_cpu)?;

        let cur_bpf_stats = BpfStats::read(&cpu_ctxs, self.nr_layers);
        let bpf_stats = &cur_bpf_stats - &self.prev_bpf_stats;

        let processing_dur = cur_processing_dur
            .checked_sub(self.prev_processing_dur)
            .unwrap();

        *self = Self {
            at: now,
            nr_layers: self.nr_layers,

            nr_layer_tasks,

            nr_nodes: self.nr_nodes,
            total_load,
            layer_loads,

            total_util: layer_utils.iter().flatten().sum(),
            layer_utils: layer_utils.try_into().unwrap(),
            prev_layer_usages: cur_layer_usages,

            cpu_busy,
            prev_total_cpu: cur_total_cpu,

            bpf_stats,
            prev_bpf_stats: cur_bpf_stats,

            processing_dur,
            prev_processing_dur: cur_processing_dur,

            layer_slice_us,
        };
        Ok(())
    }
}

#[derive(Debug)]
struct Layer {
    name: String,
    kind: LayerKind,
    core_order: Vec<usize>,

    nr_cpus: usize,
    cpus: BitVec,
    allowed_cpus: BitVec,
}

impl Layer {
    fn new(spec: &LayerSpec, idx: usize, cpu_pool: &CpuPool, topo: &Topology) -> Result<Self> {
        let name = &spec.name;
        let kind = spec.kind.clone();
        let mut cpus = bitvec![0; cpu_pool.nr_cpus];
        cpus.fill(false);
        let mut allowed_cpus = bitvec![0; cpu_pool.nr_cpus];
        match &kind {
            LayerKind::Confined {
                cpus_range,
                util_range,
                common: LayerCommon { nodes, llcs, .. },
                ..
            } => {
                let cpus_range = cpus_range.unwrap_or((0, std::usize::MAX));
                if cpus_range.0 > cpus_range.1 || cpus_range.1 == 0 {
                    bail!("invalid cpus_range {:?}", cpus_range);
                }
                if nodes.len() == 0 && llcs.len() == 0 {
                    allowed_cpus.fill(true);
                } else {
                    // build up the cpus bitset
                    for (node_id, node) in &topo.nodes {
                        // first do the matching for nodes
                        if nodes.contains(node_id) {
                            for (&id, _cpu) in &node.all_cpus {
                                allowed_cpus.set(id, true);
                            }
                        }
                        // next match on any LLCs
                        for (llc_id, llc) in &node.llcs {
                            if llcs.contains(llc_id) {
                                for (&id, _cpu) in &llc.all_cpus {
                                    allowed_cpus.set(id, true);
                                }
                            }
                        }
                    }
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
            LayerKind::Grouped {
                common: LayerCommon { nodes, llcs, .. },
                ..
            }
            | LayerKind::Open {
                common: LayerCommon { nodes, llcs, .. },
                ..
            } => {
                if nodes.len() == 0 && llcs.len() == 0 {
                    allowed_cpus.fill(true);
                } else {
                    // build up the cpus bitset
                    for (node_id, node) in &topo.nodes {
                        // first do the matching for nodes
                        if nodes.contains(node_id) {
                            for (&id, _cpu) in &node.all_cpus {
                                allowed_cpus.set(id, true);
                            }
                        }
                        // next match on any LLCs
                        for (llc_id, llc) in &node.llcs {
                            if llcs.contains(llc_id) {
                                for (&id, _cpu) in &llc.all_cpus {
                                    allowed_cpus.set(id, true);
                                }
                            }
                        }
                    }
                }
            }
        }

        let layer_growth_algo = kind.common().growth_algo.clone();

        let core_order = layer_growth_algo.layer_core_order(cpu_pool, spec, idx, topo);
        debug!(
            "layer: {} algo: {:?} core order: {:?}",
            name, &layer_growth_algo, core_order
        );

        Ok(Self {
            name: name.into(),
            kind,
            core_order,

            nr_cpus: 0,
            cpus,
            allowed_cpus,
        })
    }

    fn free_some_cpus(&mut self, cpu_pool: &mut CpuPool, max_to_free: usize) -> Result<usize> {
        let cpus_to_free = match cpu_pool.next_to_free(&self.cpus)? {
            Some(ret) => ret.clone(),
            None => return Ok(0),
        };

        let nr_to_free = cpus_to_free.count_ones();

        Ok(if nr_to_free <= max_to_free {
            trace!("[{}] freeing CPUs: {}", self.name, &cpus_to_free);
            self.cpus &= !cpus_to_free.clone();
            self.nr_cpus -= nr_to_free;
            cpu_pool.free(&cpus_to_free)?;
            nr_to_free
        } else {
            0
        })
    }

    fn alloc_some_cpus(&mut self, cpu_pool: &mut CpuPool) -> Result<usize> {
        let new_cpus = match cpu_pool
            .alloc_cpus(&self.allowed_cpus, &self.core_order)
            .clone()
        {
            Some(ret) => ret.clone(),
            None => {
                trace!("layer-{} can't grow, no CPUs", &self.name);
                return Ok(0);
            }
        };

        let nr_new_cpus = new_cpus.count_ones();

        trace!("[{}] adding CPUs: {}", &self.name, &new_cpus);
        self.cpus |= &new_cpus;
        self.nr_cpus += nr_new_cpus;
        Ok(nr_new_cpus)
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    layer_specs: Vec<LayerSpec>,

    sched_intv: Duration,

    cpu_pool: CpuPool,
    layers: Vec<Layer>,

    proc_reader: procfs::ProcReader,
    sched_stats: Stats,

    nr_layer_cpus_ranges: Vec<(usize, usize)>,
    processing_dur: Duration,

    topo: Topology,
    netdevs: BTreeMap<String, NetDev>,
    stats_server: StatsServer<StatsReq, StatsRes>,
}

impl<'a> Scheduler<'a> {
    fn init_layers(
        skel: &mut OpenBpfSkel,
        opts: &Opts,
        specs: &Vec<LayerSpec>,
        topo: &Topology,
    ) -> Result<()> {
        skel.maps.rodata_data.nr_layers = specs.len() as u32;
        let mut perf_set = false;

        let mut layer_iteration_order = (0..specs.len()).collect::<Vec<_>>();
        let mut layer_weights: Vec<usize> = vec![];

        for (spec_i, spec) in specs.iter().enumerate() {
            let layer = &mut skel.maps.bss_data.layers[spec_i];

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
                        LayerMatch::PcommPrefix(prefix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_PCOMM_PREFIX as i32;
                            copy_into_cstr(&mut mt.pcomm_prefix, prefix.as_str());
                        }
                        LayerMatch::NiceAbove(nice) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_NICE_ABOVE as i32;
                            mt.nice = *nice;
                        }
                        LayerMatch::NiceBelow(nice) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_NICE_BELOW as i32;
                            mt.nice = *nice;
                        }
                        LayerMatch::NiceEquals(nice) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_NICE_EQUALS as i32;
                            mt.nice = *nice;
                        }
                        LayerMatch::UIDEquals(user_id) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_USER_ID_EQUALS as i32;
                            mt.user_id = *user_id;
                        }
                        LayerMatch::GIDEquals(group_id) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_GROUP_ID_EQUALS as i32;
                            mt.group_id = *group_id;
                        }
                        LayerMatch::PIDEquals(pid) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_PID_EQUALS as i32;
                            mt.pid = *pid;
                        }
                        LayerMatch::PPIDEquals(ppid) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_PPID_EQUALS as i32;
                            mt.ppid = *ppid;
                        }
                        LayerMatch::TGIDEquals(tgid) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_TGID_EQUALS as i32;
                            mt.tgid = *tgid;
                        }
                    }
                }
                layer.matches[or_i].nr_match_ands = or.len() as i32;
            }

            layer.nr_match_ors = spec.matches.len() as u32;
            layer.kind = spec.kind.as_bpf_enum();

            {
                let LayerCommon {
                    min_exec_us,
                    yield_ignore,
                    perf,
                    preempt,
                    preempt_first,
                    exclusive,
                    idle_smt,
                    growth_algo,
                    nodes,
                    slice_us,
                    weight,
                    ..
                } = spec.kind.common();

                layer.slice_ns = if *slice_us > 0 {
                    *slice_us * 1000
                } else {
                    opts.slice_us * 1000
                };
                layer.min_exec_ns = min_exec_us * 1000;
                layer.yield_step_ns = if *yield_ignore > 0.999 {
                    0
                } else if *yield_ignore < 0.001 {
                    layer.slice_ns
                } else {
                    (layer.slice_ns as f64 * (1.0 - *yield_ignore)) as u64
                };
                let mut layer_name: String = spec.name.clone();
                layer_name.truncate(MAX_LAYER_NAME);
                copy_into_cstr(&mut layer.name, layer_name.as_str());
                layer.preempt.write(*preempt);
                layer.preempt_first.write(*preempt_first);
                layer.exclusive.write(*exclusive);
                layer.idle_smt.write(*idle_smt);
                layer.growth_algo = growth_algo.as_bpf_enum();
                layer.weight = if *weight <= MAX_LAYER_WEIGHT && *weight >= MIN_LAYER_WEIGHT {
                    *weight
                } else {
                    DEFAULT_LAYER_WEIGHT
                };
                layer_weights.push(layer.weight.try_into().unwrap());
                layer.perf = u32::try_from(*perf)?;
                layer.node_mask = nodemask_from_nodes(nodes) as u64;
                for (topo_node_id, topo_node) in &topo.nodes {
                    if !nodes.is_empty() && !nodes.contains(&topo_node_id) {
                        continue;
                    }
                    layer.llc_mask |= llcmask_from_llcs(&topo_node.llcs) as u64;
                }
            }

            perf_set |= layer.perf > 0;
        }

        layer_iteration_order.sort_by(|i, j| layer_weights[*i].cmp(&layer_weights[*j]));
        for (idx, layer_idx) in layer_iteration_order.iter().enumerate() {
            skel.maps.rodata_data.layer_iteration_order[idx] = *layer_idx as u32;
        }

        if perf_set && !compat::ksym_exists("scx_bpf_cpuperf_set")? {
            warn!("cpufreq support not available, ignoring perf configurations");
        }

        Ok(())
    }

    fn init_nodes(skel: &mut OpenBpfSkel, _opts: &Opts, topo: &Topology) {
        skel.maps.rodata_data.nr_nodes = topo.nodes.len() as u32;
        skel.maps.rodata_data.nr_llcs = 0;

        for (&node_id, node) in &topo.nodes {
            debug!("configuring node {}, LLCs {:?}", node_id, node.llcs.len());
            skel.maps.rodata_data.nr_llcs += node.llcs.len() as u32;
            let raw_numa_slice = node.span.as_raw_slice();
            let node_cpumask_slice = &mut skel.maps.rodata_data.numa_cpumasks[node_id];
            let (left, _) = node_cpumask_slice.split_at_mut(raw_numa_slice.len());
            left.clone_from_slice(raw_numa_slice);
            debug!(
                "node {} mask: {:?}",
                node_id, skel.maps.rodata_data.numa_cpumasks[node_id]
            );

            for llc in node.llcs.values() {
                debug!("configuring llc {:?} for node {:?}", llc.id, node_id);
                skel.maps.rodata_data.llc_numa_id_map[llc.id] = node_id as u32;
            }
        }

        for cpu in topo.all_cpus.values() {
            skel.maps.rodata_data.cpu_llc_id_map[cpu.id] = cpu.llc_id as u32;
        }
    }

    fn init(
        opts: &Opts,
        layer_specs: &[LayerSpec],
        open_object: &'a mut MaybeUninit<OpenObject>,
    ) -> Result<Self> {
        let nr_layers = layer_specs.len();
        let mut disable_topology = opts.disable_topology.unwrap_or(false);

        let topo = if disable_topology {
            Topology::with_flattened_llc_node()?
        } else {
            Topology::new()?
        };
        let netdevs = if opts.netdev_irq_balance {
            warn!(
                "Experimental netdev IRQ balancing enabled. Reset IRQ masks of network devices after use!!!"
            );
            read_netdevs()?
        } else {
            BTreeMap::new()
        };

        if !disable_topology {
            if topo.nodes.len() == 1 && topo.nodes[&0].llcs.len() == 1 {
                disable_topology = true;
            };
            info!(
                "Topology awareness not specified, selecting {} based on hardware",
                if disable_topology {
                    "disabled"
                } else {
                    "enabled"
                }
            );
        };

        let cpu_pool = CpuPool::new(&topo)?;

        // If disabling topology awareness clear out any set NUMA/LLC configs and
        // it will fallback to using all cores.
        let layer_specs: Vec<_> = if disable_topology {
            info!("Disabling topology awareness");
            layer_specs
                .into_iter()
                .cloned()
                .map(|mut s| {
                    s.kind.common_mut().nodes.clear();
                    s.kind.common_mut().llcs.clear();
                    s
                })
                .collect()
        } else {
            layer_specs.to_vec()
        };

        // Open the BPF prog first for verification.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 1);
        init_libbpf_logging(None);
        let mut skel = scx_ops_open!(skel_builder, open_object, layered)?;
        skel.maps.rodata_data.slice_ns = scx_enums.SCX_SLICE_DFL;
        skel.maps.rodata_data.max_exec_ns = 20 * scx_enums.SCX_SLICE_DFL;

        // Initialize skel according to @opts.
        skel.struct_ops.layered_mut().exit_dump_len = opts.exit_dump_len;

        skel.maps.rodata_data.debug = opts.verbose as u32;
        skel.maps.rodata_data.slice_ns = opts.slice_us * 1000;
        skel.maps.rodata_data.max_exec_ns = if opts.max_exec_us > 0 {
            opts.max_exec_us * 1000
        } else {
            opts.slice_us * 1000 * 20
        };
        skel.maps.rodata_data.nr_possible_cpus = *NR_CPUS_POSSIBLE as u32;
        skel.maps.rodata_data.smt_enabled = cpu_pool.nr_cpus > cpu_pool.nr_cores;
        skel.maps.rodata_data.has_little_cores = topo.has_little_cores();
        skel.maps.rodata_data.disable_topology = disable_topology;
        skel.maps.rodata_data.xnuma_preemption = opts.xnuma_preemption;
        skel.maps.rodata_data.local_llc_iteration = opts.local_llc_iteration;
        skel.maps.rodata_data.antistall_sec = opts.antistall_sec;
        if opts.monitor_disable {
            skel.maps.rodata_data.monitor_disable = opts.monitor_disable;
        }
        if opts.disable_antistall {
            skel.maps.rodata_data.enable_antistall = !opts.disable_antistall;
        }
        for (cpu, sib) in cpu_pool.sibling_cpu.iter().enumerate() {
            skel.maps.rodata_data.__sibling_cpu[cpu] = *sib;
        }
        for cpu in cpu_pool.all_cpus.iter_ones() {
            skel.maps.rodata_data.all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }
        Self::init_layers(&mut skel, opts, &layer_specs, &topo)?;
        Self::init_nodes(&mut skel, opts, &topo);

        let mut skel = scx_ops_load!(skel, layered, uei)?;

        let mut layers = vec![];
        for (idx, spec) in layer_specs.iter().enumerate() {
            layers.push(Layer::new(&spec, idx, &cpu_pool, &topo)?);
        }
        initialize_cpu_ctxs(&skel, &topo).unwrap();

        // Other stuff.
        let proc_reader = procfs::ProcReader::new();

        // XXX If we try to refresh the cpumasks here before attaching, we
        // sometimes (non-deterministically) don't see the updated values in
        // BPF. It would be better to update the cpumasks here before we
        // attach, but the value will quickly converge anyways so it's not a
        // huge problem in the interim until we figure it out.

        // Attach.
        let struct_ops = scx_ops_attach!(skel, layered)?;
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        let sched = Self {
            struct_ops: Some(struct_ops),
            layer_specs,

            sched_intv: Duration::from_secs_f64(opts.interval),

            cpu_pool,
            layers,

            sched_stats: Stats::new(&mut skel, &proc_reader)?,

            nr_layer_cpus_ranges: vec![(0, 0); nr_layers],
            processing_dur: Default::default(),

            proc_reader,
            skel,

            topo,
            netdevs,
            stats_server,
        };

        info!("Layered Scheduler Attached. Run `scx_layered --monitor` for metrics.");

        Ok(sched)
    }

    fn update_bpf_layer_cpumask(layer: &Layer, bpf_layer: &mut types::layer) {
        trace!("[{}] Updating BPF CPUs: {}", layer.name, &layer.cpus);
        for bit in 0..layer.cpus.len() {
            if layer.cpus[bit] {
                bpf_layer.cpus[bit / 8] |= 1 << (bit % 8);
            } else {
                bpf_layer.cpus[bit / 8] &= !(1 << (bit % 8));
            }
        }
        bpf_layer.refresh_cpus = 1;
    }

    fn update_netdev_cpumasks(&mut self) -> Result<()> {
        let available_cpus = self.cpu_pool.available_cpus();
        if available_cpus.is_empty() {
            return Ok(());
        }

        for (iface, netdev) in self.netdevs.iter_mut() {
            let node = self
                .topo
                .nodes
                .values()
                .take_while(|n| n.id == netdev.node())
                .next()
                .ok_or_else(|| anyhow!("Failed to get netdev node"))?;
            let node_cpus = node.span.clone();
            for (irq, irqmask) in netdev.irqs.iter_mut() {
                irqmask.clear();
                for cpu in available_cpus.iter_ones() {
                    if !node_cpus.test_cpu(cpu) {
                        continue;
                    }
                    let _ = irqmask.set_cpu(cpu);
                }
                // If no CPUs are available in the node then spread the load across the node
                if irqmask.weight() == 0 {
                    for cpu in node_cpus.as_raw_bitvec().iter_ones() {
                        let _ = irqmask.set_cpu(cpu);
                    }
                }
                trace!("{} updating irq {} cpumask {:?}", iface, irq, irqmask);
            }
            netdev.apply_cpumasks()?;
        }

        Ok(())
    }

    /// Calculate how many CPUs each layer would like to have if there were
    /// no competition. The CPU range is determined by applying the inverse
    /// of util_range and then capping by cpus_range. If the current
    /// allocation is within the acceptable range, no change is made.
    /// Returns (target, min) pair for each layer.
    fn calc_target_nr_cpus(&self) -> Vec<(usize, usize)> {
        let nr_cpus = self.cpu_pool.nr_cpus;
        let utils = &self.sched_stats.layer_utils;

        let mut targets: Vec<(usize, usize)> = vec![];

        for (idx, layer) in self.layers.iter().enumerate() {
            targets.push(match &layer.kind {
                LayerKind::Confined {
                    util_range,
                    cpus_range,
                    ..
                }
                | LayerKind::Grouped {
                    util_range,
                    cpus_range,
                    ..
                } => {
                    // Guide layer sizing by utilization within each layer
                    // to avoid oversizing grouped layers. As an empty layer
                    // can only get CPU time through fallback or open
                    // execution, use open cputime for empty layers.
                    let util = if layer.nr_cpus > 0 {
                        utils[idx][LAYER_USAGE_OWNED]
                    } else {
                        utils[idx][LAYER_USAGE_OPEN]
                    };

                    let util = if util < 0.01 { 0.0 } else { util };
                    let low = (util / util_range.1).ceil() as usize;
                    let high = ((util / util_range.0).floor() as usize).max(low);
                    let target = layer.cpus.count_ones().clamp(low, high);
                    let cpus_range = cpus_range.unwrap_or((0, nr_cpus));
                    (target.clamp(cpus_range.0, cpus_range.1), cpus_range.0)
                }
                LayerKind::Open { .. } => (0, 0),
            });
        }

        trace!("initial targets: {:?}", &targets);
        targets
    }

    /// Given (target, min) pair for each layer which was determined
    /// assuming infinite number of CPUs, distribute the actual CPUs
    /// according to their weights.
    fn weighted_target_nr_cpus(&self, targets: &Vec<(usize, usize)>) -> Vec<usize> {
        let mut nr_left = self.cpu_pool.nr_cpus;
        let weights: Vec<usize> = self
            .layers
            .iter()
            .map(|layer| layer.kind.common().weight as usize)
            .collect();
        let mut cands: BTreeMap<usize, (usize, usize, usize)> = targets
            .iter()
            .zip(&weights)
            .enumerate()
            .map(|(i, ((target, min), weight))| (i, (*target, *min, *weight)))
            .collect();
        let mut weight_sum: usize = weights.iter().sum();
        let mut weighted: Vec<usize> = vec![0; self.layers.len()];

        trace!("cands: {:?}", &cands);

        // First, accept all layers that are <= min.
        cands.retain(|&i, &mut (target, min, weight)| {
            if target <= min {
                let target = target.min(nr_left);
                weighted[i] = target;
                weight_sum -= weight;
                nr_left -= target;
                false
            } else {
                true
            }
        });

        trace!("cands after accepting mins: {:?}", &cands);

        // Keep accepting ones under their allotted share.
        let calc_share = |nr_left, weight, weight_sum| {
            (((nr_left * weight) as f64 / weight_sum as f64).ceil() as usize).min(nr_left)
        };

        while !cands.is_empty() {
            let mut progress = false;

            cands.retain(|&i, &mut (target, _min, weight)| {
                let share = calc_share(nr_left, weight, weight_sum);
                if target <= share {
                    weighted[i] = target;
                    weight_sum -= weight;
                    nr_left -= target;
                    progress = true;
                    false
                } else {
                    true
                }
            });

            if !progress {
                break;
            }
        }

        trace!("cands after accepting under allotted: {:?}", &cands);

        // The remaining candidates are in contention with each other,
        // distribute according to the shares.
        let nr_to_share = nr_left;
        for (i, (_target, _min, weight)) in cands.into_iter() {
            let share = calc_share(nr_to_share, weight, weight_sum).min(nr_left);
            weighted[i] = share;
            nr_left -= share;
        }

        trace!("weighted: {:?}", &weighted);

        weighted
    }

    fn refresh_cpumasks(&mut self) -> Result<()> {
        let layer_is_open = |layer: &Layer| match layer.kind {
            LayerKind::Open { .. } => true,
            _ => false,
        };

        let mut updated = false;
        let targets = self.calc_target_nr_cpus();
        let targets = self.weighted_target_nr_cpus(&targets);

        let mut ascending: Vec<(usize, usize)> = targets.iter().copied().enumerate().collect();
        ascending.sort_by(|a, b| a.1.cmp(&b.1));

        // If any layer is growing from 0 CPU, guarantee that the largest
        // layer that is freeing CPUs frees at least one CPU.
        let mut force_free = self
            .layers
            .iter()
            .zip(targets.iter())
            .any(|(layer, &target)| layer.nr_cpus == 0 && target > 0);

        // Shrink all layers first so that CPUs are available for
        // redistribution. Do so in the descending target number of CPUs
        // order.
        for &(idx, target) in ascending.iter().rev() {
            let layer = &mut self.layers[idx];
            if layer_is_open(layer) {
                continue;
            }

            let nr_cur = layer.cpus.count_ones();
            if nr_cur <= target {
                continue;
            }
            let mut nr_to_free = nr_cur - target;

            // There's some dampening built into util metrics but slow down
            // freeing further to avoid unnecessary changes. This is solely
            // based on intution. Drop or update according to real-world
            // behavior.
            let nr_to_break_at = nr_to_free / 2;

            let mut freed = false;

            while nr_to_free > 0 {
                let max_to_free = if force_free {
                    force_free = false;
                    layer.nr_cpus
                } else {
                    nr_to_free
                };

                let nr_freed = layer.free_some_cpus(&mut self.cpu_pool, max_to_free)?;
                if nr_freed == 0 {
                    break;
                }
                nr_to_free -= nr_freed;
                freed = true;

                if nr_to_free <= nr_to_break_at {
                    break;
                }
            }

            if freed {
                Self::update_bpf_layer_cpumask(layer, &mut self.skel.maps.bss_data.layers[idx]);
                updated = true;
            }
        }

        // Grow layers. Do so in the ascending target number of CPUs order
        // so that we're always more generous to smaller layers. This avoids
        // starving small layers and shouldn't make noticable difference for
        // bigger layers as work conservation should still be achieved
        // through open execution.
        for &(idx, target) in &ascending {
            let layer = &mut self.layers[idx];

            if layer_is_open(layer) {
                continue;
            }

            let nr_cur = layer.cpus.count_ones();
            if nr_cur >= target {
                continue;
            }

            let mut nr_to_alloc = target - nr_cur;
            let mut alloced = false;

            while nr_to_alloc > 0 {
                let nr_alloced = layer.alloc_some_cpus(&mut self.cpu_pool)?;
                if nr_alloced == 0 {
                    break;
                }
                alloced = true;
                nr_to_alloc -= nr_alloced.min(nr_to_alloc);
            }

            if alloced {
                Self::update_bpf_layer_cpumask(layer, &mut self.skel.maps.bss_data.layers[idx]);
                updated = true;
            }
        }

        // Give the rest to the open layers.
        if updated {
            for (idx, layer) in self.layers.iter_mut().enumerate() {
                if !layer_is_open(layer) {
                    continue;
                }

                let bpf_layer = &mut self.skel.maps.bss_data.layers[idx];
                let available_cpus = self.cpu_pool.available_cpus_in_mask(&layer.allowed_cpus);
                let nr_available_cpus = available_cpus.count_ones();

                // Open layers need the intersection of allowed cpus and
                // available cpus.
                layer.cpus.copy_from_bitslice(&available_cpus);
                layer.nr_cpus = nr_available_cpus;
                Self::update_bpf_layer_cpumask(layer, bpf_layer);
            }

            self.skel.maps.bss_data.fallback_cpu = self.cpu_pool.fallback_cpu as u32;

            for (lidx, layer) in self.layers.iter().enumerate() {
                self.nr_layer_cpus_ranges[lidx] = (
                    self.nr_layer_cpus_ranges[lidx].0.min(layer.nr_cpus),
                    self.nr_layer_cpus_ranges[lidx].1.max(layer.nr_cpus),
                );
            }
            let input = ProgramInput {
                ..Default::default()
            };
            let prog = &mut self.skel.progs.refresh_layer_cpumasks;
            let _ = prog.test_run(input);
        }

        let _ = self.update_netdev_cpumasks();
        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        let started_at = Instant::now();
        self.sched_stats.refresh(
            &mut self.skel,
            &self.proc_reader,
            started_at,
            self.processing_dur,
        )?;
        self.refresh_cpumasks()?;
        self.processing_dur += Instant::now().duration_since(started_at);
        Ok(())
    }

    fn generate_sys_stats(
        &mut self,
        stats: &Stats,
        cpus_ranges: &mut Vec<(usize, usize)>,
    ) -> Result<SysStats> {
        let bstats = &stats.bpf_stats;
        let mut sys_stats = SysStats::new(stats, bstats, self.cpu_pool.fallback_cpu)?;

        for (lidx, (spec, layer)) in self.layer_specs.iter().zip(self.layers.iter()).enumerate() {
            let layer_stats = LayerStats::new(lidx, layer, stats, bstats, cpus_ranges[lidx]);
            sys_stats.layers.insert(spec.name.to_string(), layer_stats);
            cpus_ranges[lidx] = (layer.nr_cpus, layer.nr_cpus);
        }

        Ok(sys_stats)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let mut next_sched_at = Instant::now() + self.sched_intv;
        let mut cpus_ranges = HashMap::<ThreadId, Vec<(usize, usize)>>::new();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            let now = Instant::now();

            if now >= next_sched_at {
                self.step()?;
                while next_sched_at < now {
                    next_sched_at += self.sched_intv;
                }
            }

            match req_ch.recv_deadline(next_sched_at) {
                Ok(StatsReq::Hello(tid)) => {
                    cpus_ranges.insert(
                        tid,
                        self.layers.iter().map(|l| (l.nr_cpus, l.nr_cpus)).collect(),
                    );
                    let stats = Stats::new(&mut self.skel, &self.proc_reader)?;
                    res_ch.send(StatsRes::Hello(stats))?;
                }
                Ok(StatsReq::Refresh(tid, mut stats)) => {
                    // Propagate self's layer cpu ranges into each stat's.
                    for i in 0..self.nr_layer_cpus_ranges.len() {
                        for (_, ranges) in cpus_ranges.iter_mut() {
                            ranges[i] = (
                                ranges[i].0.min(self.nr_layer_cpus_ranges[i].0),
                                ranges[i].1.max(self.nr_layer_cpus_ranges[i].1),
                            );
                        }
                        self.nr_layer_cpus_ranges[i] =
                            (self.layers[i].nr_cpus, self.layers[i].nr_cpus);
                    }

                    stats.refresh(&mut self.skel, &self.proc_reader, now, self.processing_dur)?;
                    let sys_stats =
                        self.generate_sys_stats(&stats, cpus_ranges.get_mut(&tid).unwrap())?;
                    res_ch.send(StatsRes::Refreshed((stats, sys_stats)))?;
                }
                Ok(StatsReq::Bye(tid)) => {
                    cpus_ranges.remove(&tid);
                    res_ch.send(StatsRes::Bye)?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        self.struct_ops.take();
        uei_report!(&self.skel, uei)
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
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    Ok(f.write_all(serde_json::to_string_pretty(&*EXAMPLE_CONFIG)?.as_bytes())?)
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
                    LayerMatch::PcommPrefix(prefix) => {
                        if prefix.len() > MAX_COMM {
                            bail!("Spec {:?} has too long a process name prefix", spec.name);
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
                ..
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

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    if opts.no_load_frac_limit {
        warn!("--no-load-frac-limit is deprecated and noop");
    }
    if opts.layer_preempt_weight_disable != 0.0 {
        warn!("--layer-preempt-weight-disable is deprecated and noop");
    }
    if opts.layer_growth_weight_disable != 0.0 {
        warn!("--layer-growth-weight-disable is deprecated and noop");
    }

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

    if let Some(path) = &opts.example {
        write_example_file(path)?;
        return Ok(());
    }

    let mut layer_config = match opts.run_example {
        true => EXAMPLE_CONFIG.clone(),
        false => LayerConfig { specs: vec![] },
    };

    for (idx, input) in opts.specs.iter().enumerate() {
        layer_config.specs.append(
            &mut LayerSpec::parse(input)
                .context(format!("Failed to parse specs[{}] ({:?})", idx, input))?,
        );
    }

    debug!("specs={}", serde_json::to_string_pretty(&layer_config)?);
    verify_layer_specs(&layer_config.specs)?;

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &layer_config.specs, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
