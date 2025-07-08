// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
mod stats;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::mem::MaybeUninit;
use std::ops::Sub;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
pub use bpf_skel::*;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use lazy_static::lazy_static;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::info;
use log::trace;
use log::warn;
use log::{debug, error};
use nix::sched::CpuSet;
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::Nvml;
use once_cell::sync::OnceCell;
use scx_layered::*;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::pm::{cpu_idle_resume_latency_supported, update_cpu_idle_resume_latency};
use scx_utils::read_netdevs;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::Llc;
use scx_utils::NetDev;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::NR_CPU_IDS;
use stats::LayerStats;
use stats::StatsReq;
use stats::StatsRes;
use stats::SysStats;
use std::collections::VecDeque;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

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
const LAYER_USAGE_SUM_UPTO: usize = bpf_intf::layer_usage_LAYER_USAGE_SUM_UPTO as usize;
const LAYER_USAGE_PROTECTED: usize = bpf_intf::layer_usage_LAYER_USAGE_PROTECTED as usize;
const LAYER_USAGE_PROTECTED_PREEMPT: usize =
    bpf_intf::layer_usage_LAYER_USAGE_PROTECTED_PREEMPT as usize;
const NR_LAYER_USAGES: usize = bpf_intf::layer_usage_NR_LAYER_USAGES as usize;

const NR_GSTATS: usize = bpf_intf::global_stat_id_NR_GSTATS as usize;
const NR_LSTATS: usize = bpf_intf::layer_stat_id_NR_LSTATS as usize;
const NR_LLC_LSTATS: usize = bpf_intf::llc_layer_stat_id_NR_LLC_LSTATS as usize;

const NR_LAYER_MATCH_KINDS: usize = bpf_intf::layer_match_kind_NR_LAYER_MATCH_KINDS as usize;

static NVML: OnceCell<Nvml> = OnceCell::new();

fn nvml() -> Result<&'static Nvml, NvmlError> {
    NVML.get_or_try_init(Nvml::init)
}

lazy_static! {
    static ref USAGE_DECAY: f64 = 0.5f64.powf(1.0 / USAGE_HALF_LIFE_F64);
    static ref DFL_DISALLOW_OPEN_AFTER_US: u64 = 2 * scx_enums.SCX_SLICE_DFL / 1000;
    static ref DFL_DISALLOW_PREEMPT_AFTER_US: u64 = 4 * scx_enums.SCX_SLICE_DFL / 1000;
    static ref EXAMPLE_CONFIG: LayerConfig = LayerConfig {
        specs: vec![
            LayerSpec {
                name: "batch".into(),
                comment: Some("tasks under system.slice or tasks with nice value > 0".into()),
                cpuset: None,
                template: None,
                matches: vec![
                    vec![LayerMatch::CgroupPrefix("system.slice/".into())],
                    vec![LayerMatch::NiceAbove(0)],
                ],
                kind: LayerKind::Confined {
                    util_range: (0.8, 0.9),
                    cpus_range: Some((0, 16)),
                    cpus_range_frac: None,
                    protected: false,
                    common: LayerCommon {
                        min_exec_us: 1000,
                        yield_ignore: 0.0,
                        preempt: false,
                        preempt_first: false,
                        exclusive: false,
                        allow_node_aligned: false,
                        skip_remote_node: false,
                        prev_over_idle_core: false,
                        idle_smt: None,
                        slice_us: 20000,
                        fifo: false,
                        weight: DEFAULT_LAYER_WEIGHT,
                        disallow_open_after_us: None,
                        disallow_preempt_after_us: None,
                        xllc_mig_min_us: 1000.0,
                        growth_algo: LayerGrowthAlgo::Sticky,
                        idle_resume_us: None,
                        perf: 1024,
                        nodes: vec![],
                        llcs: vec![],
                        placement: LayerPlacement::Standard,
                    },
                },
            },
            LayerSpec {
                name: "immediate".into(),
                comment: Some("tasks under workload.slice with nice value < 0".into()),
                cpuset: None,
                template: None,
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
                        allow_node_aligned: true,
                        skip_remote_node: false,
                        prev_over_idle_core: true,
                        idle_smt: None,
                        slice_us: 20000,
                        fifo: false,
                        weight: DEFAULT_LAYER_WEIGHT,
                        disallow_open_after_us: None,
                        disallow_preempt_after_us: None,
                        xllc_mig_min_us: 0.0,
                        growth_algo: LayerGrowthAlgo::Sticky,
                        perf: 1024,
                        idle_resume_us: None,
                        nodes: vec![],
                        llcs: vec![],
                        placement: LayerPlacement::Standard,
                    },
                },
            },
            LayerSpec {
                name: "stress-ng".into(),
                comment: Some("stress-ng test layer".into()),
                cpuset: None,
                template: None,
                matches: vec![
                    vec![LayerMatch::CommPrefix("stress-ng".into()),],
                    vec![LayerMatch::PcommPrefix("stress-ng".into()),]
                ],
                kind: LayerKind::Confined {
                    cpus_range: None,
                    util_range: (0.2, 0.8),
                    protected: false,
                    cpus_range_frac: None,
                    common: LayerCommon {
                        min_exec_us: 800,
                        yield_ignore: 0.0,
                        preempt: true,
                        preempt_first: false,
                        exclusive: false,
                        allow_node_aligned: false,
                        skip_remote_node: false,
                        prev_over_idle_core: false,
                        idle_smt: None,
                        slice_us: 800,
                        fifo: false,
                        weight: DEFAULT_LAYER_WEIGHT,
                        disallow_open_after_us: None,
                        disallow_preempt_after_us: None,
                        xllc_mig_min_us: 0.0,
                        growth_algo: LayerGrowthAlgo::Topo,
                        perf: 1024,
                        idle_resume_us: None,
                        nodes: vec![],
                        llcs: vec![],
                        placement: LayerPlacement::Standard,
                    },
                },
            },
            LayerSpec {
                name: "normal".into(),
                comment: Some("the rest".into()),
                cpuset: None,
                template: None,
                matches: vec![vec![]],
                kind: LayerKind::Grouped {
                    cpus_range: None,
                    util_range: (0.5, 0.6),
                    util_includes_open_cputime: true,
                    protected: false,
                    cpus_range_frac: None,
                    common: LayerCommon {
                        min_exec_us: 200,
                        yield_ignore: 0.0,
                        preempt: false,
                        preempt_first: false,
                        exclusive: false,
                        allow_node_aligned: false,
                        skip_remote_node: false,
                        prev_over_idle_core: false,
                        idle_smt: None,
                        slice_us: 20000,
                        fifo: false,
                        weight: DEFAULT_LAYER_WEIGHT,
                        disallow_open_after_us: None,
                        disallow_preempt_after_us: None,
                        xllc_mig_min_us: 100.0,
                        growth_algo: LayerGrowthAlgo::Linear,
                        perf: 1024,
                        idle_resume_us: None,
                        nodes: vec![],
                        llcs: vec![],
                        placement: LayerPlacement::Standard,
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
/// - NSPIDEquals: Matches if the task's namespace id and pid matches the values.
///
/// - NSEquals: Matches if the task's namespace id matches the values.
///
/// - IsGroupLeader: Bool. When true, matches if the task is group leader
///   (i.e. PID == TGID), aka the thread from which other threads are made.
///   When false, matches if the task is *not* the group leader (i.e. the rest).
///
/// - CmdJoin: Matches when the task uses pthread_setname_np to send a join/leave
/// command to the scheduler. See examples/cmdjoin.c for more details.
///
/// - UsedGpuTid: Bool. When true, matches if the tasks which have used
///   gpus by tid.
///
/// - UsedGpuPid: Bool. When true, matches if the tasks which have used gpu
///   by tgid/pid.
///
/// - [EXPERIMENTAL] AvgRuntime: (u64, u64). Match tasks whose average runtime
///   is within the provided values [min, max).
///
/// While there are complexity limitations as the matches are performed in
/// BPF, it is straightforward to add more types of matches.
///
/// Templates
/// ---------
///
/// Templates let us create a variable number of layers dynamically at initialization
/// time out of a cgroup name suffix/prefix. Sometimes we know there are multiple
/// applications running on a machine, each with their own cgroup but do not know the
/// exact names of the applications or cgroups, e.g., in cloud computing contexts where
/// workloads are placed on machines dynamically and run under cgroups whose name is
/// autogenerated. In that case, we cannot hardcode the cgroup match rules when writing
/// the configuration. We thus cannot easily prevent tasks from different cgroups from
/// falling into the same layer and affecting each other's performance.
///
///
/// Templates offer a solution to this problem by generating one layer for each such cgroup,
/// provided these cgroups share a suffix, and that the suffix is unique to them. Templates
/// have a cgroup suffix rule that we use to find the relevant cgroups in the system. For each
/// such cgroup, we copy the layer config and add a matching rule that matches just this cgroup.
///
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
///   idle CPUs outside the allocated ones. The range can optionally be
///   restricted with the "cpus_range" property.
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
/// - slice_us: Scheduling slice duration in microseconds.
///
/// - fifo: Use FIFO queues within the layer instead of the default vtime.
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
/// - allow_node_aligned: Put node aligned tasks on layer DSQs instead of lo
///   fallback. This is a hack to support node-affine tasks without making
///   the whole scheduler node aware and should only be used with open
///   layers on non-saturated machines to avoid possible stalls.
///
/// - prev_over_idle_core: On SMT enabled systems, prefer using the same CPU
///   when picking a CPU for tasks on this layer, even if that CPUs SMT
///   sibling is processing a task.
///
/// - weight: Weight of the layer, which is a range from 1 to 10000 with a
///   default of 100. Layer weights are used during contention to prevent
///   starvation across layers. Weights are used in combination with
///   utilization to determine the infeasible adjusted weight with higher
///   weights having a larger adjustment in adjusted utilization.
///
/// - disallow_open_after_us: Duration to wait after machine reaches saturation
///   before confining tasks in Open layers.
///
/// - cpus_range_frac: Array of 2 floats between 0 and 1.0. Lower and upper
///   bound fractions of all CPUs to give to a layer. Mutually exclusive
///   with cpus_range.
///
/// - disallow_preempt_after_us: Duration to wait after machine reaches saturation
///   before confining tasks to preempt.
///
/// - xllc_mig_min_us: Skip cross-LLC migrations if they are likely to run on
///   their existing LLC sooner than this.
///
/// - idle_smt: *** DEPRECATED ****
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
/// - idle_resume_us: Sets the idle resume QoS value. CPU idle time governors are expected to
///   regard the minimum of the global (effective) CPU latency limit and the effective resume
///   latency constraint for the given CPU as the upper limit for the exit latency of the idle
///   states. See the latest kernel docs for more details:
///   https://www.kernel.org/doc/html/latest/admin-guide/pm/cpuidle.html
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

    /// ***DEPRECATED *** Enables iteration over local LLCs first for
    /// dispatch.
    #[clap(long, default_value = "false")]
    local_llc_iteration: bool,

    /// Low priority fallback DSQs are used to execute tasks with custom CPU
    /// affinities. These DSQs are immediately executed iff a CPU is
    /// otherwise idle. However, after the specified wait, they are
    /// guranteed upto --lo-fb-share fraction of each CPU.
    #[clap(long, default_value = "10000")]
    lo_fb_wait_us: u64,

    /// The fraction of CPU time guaranteed to low priority fallback DSQs.
    /// See --lo-fb-wait-us.
    #[clap(long, default_value = ".05")]
    lo_fb_share: f64,

    /// Disable antistall
    #[clap(long, default_value = "false")]
    disable_antistall: bool,

    /// Enable numa topology based gpu task affinitization.
    #[clap(long, default_value = "false")]
    enable_gpu_affinitize: bool,

    /// Interval at which to reaffinitize gpu tasks to numa nodes.
    /// Defaults to 900s
    #[clap(long, default_value = "900")]
    gpu_affinitize_secs: u64,

    /// Enable match debug
    /// This stores a mapping of task tid
    /// to layer id such that bpftool map dump
    /// can be used to debug layer matches.
    #[clap(long, default_value = "false")]
    enable_match_debug: bool,

    /// Maximum task runnable_at delay (in seconds) before antistall turns on
    #[clap(long, default_value = "3")]
    antistall_sec: u64,

    /// Enable gpu support
    #[clap(long, default_value = "false")]
    enable_gpu_support: bool,

    /// Gpu Kprobe Level
    /// The value set here determines how agressive
    /// the kprobes enabled on gpu driver functions are.
    /// Higher values are more aggressive, incurring more system overhead
    /// and more accurately identifying PIDs using GPUs in a more timely manner.
    /// Lower values incur less system overhead, at the cost of less accurately
    /// identifying GPU pids and taking longer to do so.
    #[clap(long, default_value = "3")]
    gpu_kprobe_level: u64,

    /// Enable netdev IRQ balancing. This is experimental and should be used with caution.
    #[clap(long, default_value = "false")]
    netdev_irq_balance: bool,

    /// Disable queued wakeup optimization.
    #[clap(long, default_value = "false")]
    disable_queued_wakeup: bool,

    /// Per-cpu kthreads are preempting by default. Make it not so.
    #[clap(long, default_value = "false")]
    disable_percpu_kthread_preempt: bool,

    /// Only highpri (nice < 0) per-cpu kthreads are preempting by default.
    /// Make every per-cpu kthread preempting. Meaningful only if
    /// --disable-percpu-kthread-preempt is not set.
    #[clap(long, default_value = "false")]
    percpu_kthread_preempt_all: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    /// Layer specification. See --help.
    specs: Vec<String>,

    /// Periodically force tasks in layers using the AvgRuntime match rule to reevaluate which layer they belong to. Default period of 2s.
    /// turns this off.
    #[clap(long, default_value = "2000")]
    layer_refresh_ms_avgruntime: u64,

    /// Set the path for pinning the task hint map.
    #[clap(long, default_value = "")]
    task_hint_map: String,

    /// Print the config (after template expansion) and exit.
    #[clap(long, default_value = "false")]
    print_and_exit: bool,
}

fn read_total_cpu(reader: &fb_procfs::ProcReader) -> Result<fb_procfs::CpuStat> {
    reader
        .read_stat()
        .context("Failed to read procfs")?
        .total_cpu
        .ok_or_else(|| anyhow!("Could not read total cpu stat in proc"))
}

fn calc_util(curr: &fb_procfs::CpuStat, prev: &fb_procfs::CpuStat) -> Result<f64> {
    match (curr, prev) {
        (
            fb_procfs::CpuStat {
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
            fb_procfs::CpuStat {
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

#[derive(Clone, Debug)]
struct BpfStats {
    gstats: Vec<u64>,
    lstats: Vec<Vec<u64>>,
    lstats_sums: Vec<u64>,
    llc_lstats: Vec<Vec<Vec<u64>>>, // [layer][llc][stat]
}

impl BpfStats {
    fn read(skel: &BpfSkel, cpu_ctxs: &[bpf_intf::cpu_ctx]) -> Self {
        let nr_layers = skel.maps.rodata_data.nr_layers as usize;
        let nr_llcs = skel.maps.rodata_data.nr_llcs as usize;
        let mut gstats = vec![0u64; NR_GSTATS];
        let mut lstats = vec![vec![0u64; NR_LSTATS]; nr_layers];
        let mut llc_lstats = vec![vec![vec![0u64; NR_LLC_LSTATS]; nr_llcs]; nr_layers];

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

        for llc_id in 0..nr_llcs {
            // XXX - This would be a lot easier if llc_ctx were in
            // the bss. Unfortunately, kernel < v6.12 crashes and
            // kernel >= v6.12 fails verification after such
            // conversion due to seemingly verifier bugs. Convert to
            // bss maps later.
            let key = llc_id as u32;
            let llc_id_slice =
                unsafe { std::slice::from_raw_parts((&key as *const u32) as *const u8, 4) };
            let v = skel
                .maps
                .llc_data
                .lookup(llc_id_slice, libbpf_rs::MapFlags::ANY)
                .unwrap()
                .unwrap();
            let llcc = unsafe { *(v.as_slice().as_ptr() as *const bpf_intf::llc_ctx) };

            for layer_id in 0..nr_layers {
                for stat_id in 0..NR_LLC_LSTATS {
                    llc_lstats[layer_id][llc_id][stat_id] = llcc.lstats[layer_id][stat_id];
                }
            }
        }

        Self {
            gstats,
            lstats,
            lstats_sums,
            llc_lstats,
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
            llc_lstats: self
                .llc_lstats
                .iter()
                .zip(rhs.llc_lstats.iter())
                .map(|(l_layer, r_layer)| {
                    l_layer
                        .iter()
                        .zip(r_layer.iter())
                        .map(|(l_llc, r_llc)| {
                            let (l_llc, mut r_llc) = (l_llc.clone(), r_llc.clone());
                            // Lat is not subtractable, take L side.
                            r_llc[bpf_intf::llc_layer_stat_id_LLC_LSTAT_LAT as usize] = 0;
                            vec_sub(&l_llc, &r_llc)
                        })
                        .collect()
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
struct Stats {
    at: Instant,
    elapsed: Duration,
    nr_layers: usize,
    nr_layer_tasks: Vec<usize>,
    nr_nodes: usize,

    total_util: f64, // Running AVG of sum of layer_utils
    layer_utils: Vec<Vec<f64>>,
    prev_layer_usages: Vec<Vec<u64>>,

    cpu_busy: f64, // Read from /proc, maybe higher than total_util
    prev_total_cpu: fb_procfs::CpuStat,

    bpf_stats: BpfStats,
    prev_bpf_stats: BpfStats,

    processing_dur: Duration,
    prev_processing_dur: Duration,

    layer_slice_us: Vec<u64>,

    gpu_tasks_affinitized: u64,
    gpu_task_affinitization_ms: u64,
}

impl Stats {
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

    fn new(
        skel: &mut BpfSkel,
        proc_reader: &fb_procfs::ProcReader,
        gpu_task_affinitizer: &GpuTaskAffinitizer,
    ) -> Result<Self> {
        let nr_layers = skel.maps.rodata_data.nr_layers as usize;
        let cpu_ctxs = read_cpu_ctxs(skel)?;
        let bpf_stats = BpfStats::read(skel, &cpu_ctxs);
        let nr_nodes = skel.maps.rodata_data.nr_nodes as usize;

        Ok(Self {
            at: Instant::now(),
            elapsed: Default::default(),
            nr_layers,
            nr_layer_tasks: vec![0; nr_layers],
            nr_nodes,

            total_util: 0.0,
            layer_utils: vec![vec![0.0; NR_LAYER_USAGES]; nr_layers],
            prev_layer_usages: Self::read_layer_usages(&cpu_ctxs, nr_layers),

            cpu_busy: 0.0,
            prev_total_cpu: read_total_cpu(proc_reader)?,

            bpf_stats: bpf_stats.clone(),
            prev_bpf_stats: bpf_stats,

            processing_dur: Default::default(),
            prev_processing_dur: Default::default(),

            layer_slice_us: vec![0; nr_layers],
            gpu_tasks_affinitized: gpu_task_affinitizer.tasks_affinitized,
            gpu_task_affinitization_ms: gpu_task_affinitizer.last_task_affinitization_ms,
        })
    }

    fn refresh(
        &mut self,
        skel: &mut BpfSkel,
        proc_reader: &fb_procfs::ProcReader,
        now: Instant,
        cur_processing_dur: Duration,
        gpu_task_affinitizer: &GpuTaskAffinitizer,
    ) -> Result<()> {
        let elapsed = now.duration_since(self.at);
        let elapsed_f64 = elapsed.as_secs_f64();
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
            .map(|layer| layer.slice_ns / 1000_u64)
            .collect();

        let cur_layer_usages = Self::read_layer_usages(&cpu_ctxs, self.nr_layers);
        let cur_layer_utils: Vec<Vec<f64>> = cur_layer_usages
            .iter()
            .zip(self.prev_layer_usages.iter())
            .map(|(cur, prev)| {
                cur.iter()
                    .zip(prev.iter())
                    .map(|(c, p)| (c - p) as f64 / 1_000_000_000.0 / elapsed_f64)
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
                        let decay = USAGE_DECAY.powf(elapsed_f64);
                        p * decay + c * (1.0 - decay)
                    })
                    .collect()
            })
            .collect();

        let cur_total_cpu = read_total_cpu(proc_reader)?;
        let cpu_busy = calc_util(&cur_total_cpu, &self.prev_total_cpu)?;

        let cur_bpf_stats = BpfStats::read(skel, &cpu_ctxs);
        let bpf_stats = &cur_bpf_stats - &self.prev_bpf_stats;

        let processing_dur = cur_processing_dur
            .checked_sub(self.prev_processing_dur)
            .unwrap();

        *self = Self {
            at: now,
            elapsed,
            nr_layers: self.nr_layers,
            nr_layer_tasks,
            nr_nodes: self.nr_nodes,

            total_util: layer_utils
                .iter()
                .map(|x| x.iter().take(LAYER_USAGE_SUM_UPTO + 1).sum::<f64>())
                .sum(),
            layer_utils,
            prev_layer_usages: cur_layer_usages,

            cpu_busy,
            prev_total_cpu: cur_total_cpu,

            bpf_stats,
            prev_bpf_stats: cur_bpf_stats,

            processing_dur,
            prev_processing_dur: cur_processing_dur,

            layer_slice_us,
            gpu_tasks_affinitized: gpu_task_affinitizer.tasks_affinitized,
            gpu_task_affinitization_ms: gpu_task_affinitizer.last_task_affinitization_ms,
        };
        Ok(())
    }
}

#[derive(Debug)]
struct Layer {
    name: String,
    kind: LayerKind,
    growth_algo: LayerGrowthAlgo,
    core_order: Vec<usize>,

    target_llc_cpus: (usize, usize),
    assigned_llcs: Vec<usize>,

    nr_cpus: usize,
    nr_llc_cpus: Vec<usize>,
    cpus: Cpumask,
    allowed_cpus: Cpumask,
}

fn get_kallsyms_addr(sym_name: &str) -> Result<u64> {
    fs::read_to_string("/proc/kallsyms")?
        .lines()
        .find(|line| line.contains(sym_name))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|addr| u64::from_str_radix(addr, 16).ok())
        .ok_or_else(|| anyhow!("Symbol '{}' not found", sym_name))
}

fn resolve_cpus_pct_range(
    cpus_range: &Option<(usize, usize)>,
    cpus_range_frac: &Option<(f64, f64)>,
    max_cpus: usize,
) -> Result<(usize, usize)> {
    match (cpus_range, cpus_range_frac) {
        (Some(_x), Some(_y)) => {
            bail!("cpus_range cannot be used with cpus_pct.");
        }
        (Some((cpus_range_min, cpus_range_max)), None) => Ok((*cpus_range_min, *cpus_range_max)),
        (None, Some((cpus_frac_min, cpus_frac_max))) => {
            if *cpus_frac_min < 0_f64
                || *cpus_frac_min > 1_f64
                || *cpus_frac_max < 0_f64
                || *cpus_frac_max > 1_f64
            {
                bail!("cpus_range_frac values must be between 0.0 and 1.0");
            }
            let cpus_min_count = ((max_cpus as f64) * cpus_frac_min).round_ties_even() as usize;
            let cpus_max_count = ((max_cpus as f64) * cpus_frac_max).round_ties_even() as usize;
            Ok((
                std::cmp::max(cpus_min_count, 1),
                std::cmp::min(cpus_max_count, max_cpus),
            ))
        }
        (None, None) => Ok((0, max_cpus)),
    }
}

impl Layer {
    fn new(spec: &LayerSpec, topo: &Topology, core_order: &Vec<usize>) -> Result<Self> {
        let name = &spec.name;
        let kind = spec.kind.clone();
        let mut allowed_cpus = Cpumask::new();
        match &kind {
            LayerKind::Confined {
                cpus_range,
                cpus_range_frac,
                common: LayerCommon { nodes, llcs, .. },
                ..
            } => {
                let cpus_range =
                    resolve_cpus_pct_range(cpus_range, cpus_range_frac, topo.all_cpus.len())?;
                if cpus_range.0 > cpus_range.1 || cpus_range.1 == 0 {
                    bail!("invalid cpus_range {:?}", cpus_range);
                }
                if nodes.is_empty() && llcs.is_empty() {
                    allowed_cpus.set_all();
                } else {
                    // build up the cpus bitset
                    for (node_id, node) in &topo.nodes {
                        // first do the matching for nodes
                        if nodes.contains(node_id) {
                            for &id in node.all_cpus.keys() {
                                allowed_cpus.set_cpu(id)?;
                            }
                        }
                        // next match on any LLCs
                        for (llc_id, llc) in &node.llcs {
                            if llcs.contains(llc_id) {
                                for &id in llc.all_cpus.keys() {
                                    allowed_cpus.set_cpu(id)?;
                                }
                            }
                        }
                    }
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
                if nodes.is_empty() && llcs.is_empty() {
                    allowed_cpus.set_all();
                } else {
                    // build up the cpus bitset
                    for (node_id, node) in &topo.nodes {
                        // first do the matching for nodes
                        if nodes.contains(node_id) {
                            for &id in node.all_cpus.keys() {
                                allowed_cpus.set_cpu(id)?;
                            }
                        }
                        // next match on any LLCs
                        for (llc_id, llc) in &node.llcs {
                            if llcs.contains(llc_id) {
                                for &id in llc.all_cpus.keys() {
                                    allowed_cpus.set_cpu(id)?;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Util can be above 1.0 for grouped layers if
        // util_includes_open_cputime is set.
        if let Some(util_range) = kind.util_range() {
            if util_range.0 < 0.0 || util_range.1 < 0.0 || util_range.0 >= util_range.1 {
                bail!("invalid util_range {:?}", util_range);
            }
        }

        let layer_growth_algo = kind.common().growth_algo.clone();

        debug!(
            "layer: {} algo: {:?} core order: {:?}",
            name, &layer_growth_algo, core_order
        );

        Ok(Self {
            name: name.into(),
            kind,
            growth_algo: layer_growth_algo,
            core_order: core_order.clone(),

            target_llc_cpus: (0, 0),
            assigned_llcs: vec![],

            nr_cpus: 0,
            nr_llc_cpus: vec![0; topo.all_llcs.len()],
            cpus: Cpumask::new(),
            allowed_cpus,
        })
    }

    fn free_some_cpus(&mut self, cpu_pool: &mut CpuPool, max_to_free: usize) -> Result<usize> {
        let cpus_to_free = match cpu_pool.next_to_free(&self.cpus, self.core_order.iter().rev())? {
            Some(ret) => ret.clone(),
            None => return Ok(0),
        };

        let nr_to_free = cpus_to_free.weight();

        Ok(if nr_to_free <= max_to_free {
            trace!("[{}] freeing CPUs: {}", self.name, &cpus_to_free);
            self.cpus &= &cpus_to_free.not();
            self.nr_cpus -= nr_to_free;
            for cpu in cpus_to_free.iter() {
                self.nr_llc_cpus[cpu_pool.topo.all_cpus[&cpu].llc_id] -= 1;
            }
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

        let nr_new_cpus = new_cpus.weight();

        trace!("[{}] adding CPUs: {}", &self.name, &new_cpus);
        self.cpus |= &new_cpus;
        self.nr_cpus += nr_new_cpus;
        for cpu in new_cpus.iter() {
            self.nr_llc_cpus[cpu_pool.topo.all_cpus[&cpu].llc_id] += 1;
        }
        Ok(nr_new_cpus)
    }
}
#[derive(Debug, Clone)]
struct NodeInfo {
    node_mask: nix::sched::CpuSet,
    _node_id: usize,
}

#[derive(Debug)]
struct GpuTaskAffinitizer {
    // This struct tracks information neccessary to numa affinitize
    // gpu tasks periodically when needed.
    gpu_devs_to_node_info: HashMap<u32, NodeInfo>,
    gpu_pids_to_devs: HashMap<Pid, u32>,
    last_process_time: Option<Instant>,
    sys: System,
    pid_map: HashMap<Pid, Vec<Pid>>,
    poll_interval: Duration,
    enable: bool,
    tasks_affinitized: u64,
    last_task_affinitization_ms: u64,
}

impl GpuTaskAffinitizer {
    pub fn new(poll_interval: u64, enable: bool) -> GpuTaskAffinitizer {
        GpuTaskAffinitizer {
            gpu_devs_to_node_info: HashMap::new(),
            gpu_pids_to_devs: HashMap::new(),
            last_process_time: None,
            sys: System::default(),
            pid_map: HashMap::new(),
            poll_interval: Duration::from_secs(poll_interval),
            enable,
            tasks_affinitized: 0,
            last_task_affinitization_ms: 0,
        }
    }

    fn find_one_cpu(&self, affinity: Vec<u64>) -> Result<u32> {
        for (chunk, &mask) in affinity.iter().enumerate() {
            let mut inner_offset: u64 = 1;
            for _ in 0..64 {
                if (mask & inner_offset) != 0 {
                    return Ok((64 * chunk + u64::trailing_zeros(inner_offset) as usize) as u32);
                }
                inner_offset = inner_offset << 1;
            }
        }
        anyhow::bail!("unable to get CPU from NVML bitmask");
    }

    fn node_to_cpuset(&self, node: &scx_utils::Node) -> Result<CpuSet> {
        let mut cpuset = CpuSet::new();
        for (cpu_id, _cpu) in &node.all_cpus {
            cpuset.set(*cpu_id)?;
        }
        Ok(cpuset)
    }

    fn init_dev_node_map(&mut self, topo: Arc<Topology>) -> Result<()> {
        let nvml = nvml()?;
        let device_count = nvml.device_count()?;

        for idx in 0..device_count {
            let dev = nvml.device_by_index(idx)?;
            // For machines w/ up to 1024 CPUs.
            let cpu = dev.cpu_affinity(16)?;
            let ideal_cpu = self.find_one_cpu(cpu)?;
            if let Some(cpu) = topo.all_cpus.get(&(ideal_cpu as usize)) {
                self.gpu_devs_to_node_info.insert(
                    idx,
                    NodeInfo {
                        node_mask: self.node_to_cpuset(
                            topo.nodes.get(&cpu.node_id).expect("topo missing node"),
                        )?,
                        _node_id: cpu.node_id,
                    },
                );
            }
        }
        Ok(())
    }

    fn update_gpu_pids(&mut self) -> Result<()> {
        let nvml = nvml()?;
        for i in 0..nvml.device_count()? {
            let device = nvml.device_by_index(i)?;
            for proc in device
                .running_compute_processes()?
                .into_iter()
                .chain(device.running_graphics_processes()?.into_iter())
            {
                self.gpu_pids_to_devs.insert(Pid::from_u32(proc.pid), i);
            }
        }
        Ok(())
    }

    fn update_process_info(&mut self) -> Result<()> {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing(),
        );
        self.pid_map.clear();
        for (pid, proc_) in self.sys.processes() {
            if let Some(ppid) = proc_.parent() {
                self.pid_map.entry(ppid).or_default().push(*pid);
            }
        }
        Ok(())
    }

    fn get_child_pids_and_tids(&self, root_pid: Pid) -> HashSet<Pid> {
        let mut work = VecDeque::from([root_pid]);
        let mut pids_and_tids: HashSet<Pid> = HashSet::new();

        while let Some(pid) = work.pop_front() {
            if pids_and_tids.insert(pid) {
                if let Some(kids) = self.pid_map.get(&pid) {
                    work.extend(kids);
                }
                if let Some(proc_) = self.sys.process(pid) {
                    if let Some(tasks) = proc_.tasks() {
                        pids_and_tids.extend(tasks.iter().copied());
                    }
                }
            }
        }
        pids_and_tids
    }

    fn affinitize_gpu_pids(&mut self) -> Result<()> {
        if !self.enable {
            return Ok(());
        }
        for (pid, dev) in &self.gpu_pids_to_devs {
            let node_info = self
                .gpu_devs_to_node_info
                .get(&dev)
                .expect("Unable to get gpu pid node mask");
            for child in self.get_child_pids_and_tids(*pid) {
                match nix::sched::sched_setaffinity(
                    nix::unistd::Pid::from_raw(child.as_u32() as i32),
                    &node_info.node_mask,
                ) {
                    Ok(_) => {
                        // Increment the global counter for successful affinitization
                        self.tasks_affinitized += 1;
                    }
                    Err(_) => {
                        warn!(
                            "Error affinitizing gpu pid {} to node {:#?}",
                            child.as_u32(),
                            node_info
                        );
                    }
                };
            }
        }
        Ok(())
    }

    pub fn maybe_affinitize(&mut self) {
        if !self.enable {
            return;
        }
        let now = Instant::now();

        if let Some(last_process_time) = self.last_process_time {
            if (now - last_process_time) < self.poll_interval {
                return;
            }
        }

        match self.update_gpu_pids() {
            Ok(_) => {}
            Err(e) => {
                error!("Error updating GPU PIDs: {}", e);
            }
        };
        match self.update_process_info() {
            Ok(_) => {}
            Err(e) => {
                error!("Error updating process info to affinitize GPU PIDs: {}", e);
            }
        };
        match self.affinitize_gpu_pids() {
            Ok(_) => {}
            Err(e) => {
                error!("Error updating GPU PIDs: {}", e);
            }
        };
        self.last_process_time = Some(now);
        self.last_task_affinitization_ms = (Instant::now() - now).as_millis() as u64;

        return;
    }

    pub fn init(&mut self, topo: Arc<Topology>) {
        if !self.enable || self.last_process_time.is_some() {
            return;
        }

        match self.init_dev_node_map(topo) {
            Ok(_) => {}
            Err(e) => {
                error!("Error initializing gpu node dev map: {}", e);
            }
        };
        self.sys = System::new_all();
        return;
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    layer_specs: Vec<LayerSpec>,

    sched_intv: Duration,
    layer_refresh_intv: Duration,

    cpu_pool: CpuPool,
    layers: Vec<Layer>,
    idle_qos_enabled: bool,

    proc_reader: fb_procfs::ProcReader,
    sched_stats: Stats,

    nr_layer_cpus_ranges: Vec<(usize, usize)>,
    processing_dur: Duration,

    topo: Arc<Topology>,
    netdevs: BTreeMap<String, NetDev>,
    stats_server: StatsServer<StatsReq, StatsRes>,
    gpu_task_handler: GpuTaskAffinitizer,
}

impl<'a> Scheduler<'a> {
    fn init_layers(skel: &mut OpenBpfSkel, specs: &[LayerSpec], topo: &Topology) -> Result<()> {
        skel.maps.rodata_data.nr_layers = specs.len() as u32;
        let mut perf_set = false;

        let mut layer_iteration_order = (0..specs.len()).collect::<Vec<_>>();
        let mut layer_weights: Vec<usize> = vec![];

        for (spec_i, spec) in specs.iter().enumerate() {
            let layer = &mut skel.maps.bss_data.layers[spec_i];

            for (or_i, or) in spec.matches.iter().enumerate() {
                for (and_i, and) in or.iter().enumerate() {
                    let mt = &mut layer.matches[or_i].matches[and_i];

                    // Rules are allowlist-based by default
                    mt.exclude.write(false);

                    match and {
                        LayerMatch::CgroupPrefix(prefix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_CGROUP_PREFIX as i32;
                            copy_into_cstr(&mut mt.cgroup_prefix, prefix.as_str());
                        }
                        LayerMatch::CgroupSuffix(suffix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_CGROUP_SUFFIX as i32;
                            copy_into_cstr(&mut mt.cgroup_suffix, suffix.as_str());
                        }
                        LayerMatch::CgroupContains(substr) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_CGROUP_CONTAINS as i32;
                            copy_into_cstr(&mut mt.cgroup_substr, substr.as_str());
                        }
                        LayerMatch::CommPrefix(prefix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_COMM_PREFIX as i32;
                            copy_into_cstr(&mut mt.comm_prefix, prefix.as_str());
                        }
                        LayerMatch::CommPrefixExclude(prefix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_COMM_PREFIX as i32;
                            mt.exclude.write(true);
                            copy_into_cstr(&mut mt.comm_prefix, prefix.as_str());
                        }
                        LayerMatch::PcommPrefix(prefix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_PCOMM_PREFIX as i32;
                            copy_into_cstr(&mut mt.pcomm_prefix, prefix.as_str());
                        }
                        LayerMatch::PcommPrefixExclude(prefix) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_PCOMM_PREFIX as i32;
                            mt.exclude.write(true);
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
                        LayerMatch::NSPIDEquals(nsid, pid) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_NSPID_EQUALS as i32;
                            mt.nsid = *nsid;
                            mt.pid = *pid;
                        }
                        LayerMatch::NSEquals(nsid) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_NS_EQUALS as i32;
                            mt.nsid = *nsid as u64;
                        }
                        LayerMatch::CmdJoin(joincmd) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_SCXCMD_JOIN as i32;
                            copy_into_cstr(&mut mt.comm_prefix, joincmd);
                        }
                        LayerMatch::IsGroupLeader(polarity) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_IS_GROUP_LEADER as i32;
                            mt.is_group_leader.write(*polarity);
                        }
                        LayerMatch::IsKthread(polarity) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_IS_KTHREAD as i32;
                            mt.is_kthread.write(*polarity);
                        }
                        LayerMatch::UsedGpuTid(polarity) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_USED_GPU_TID as i32;
                            mt.used_gpu_tid.write(*polarity);
                        }
                        LayerMatch::UsedGpuPid(polarity) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_USED_GPU_PID as i32;
                            mt.used_gpu_pid.write(*polarity);
                        }
                        LayerMatch::AvgRuntime(min, max) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_AVG_RUNTIME as i32;
                            mt.min_avg_runtime_us = *min;
                            mt.max_avg_runtime_us = *max;
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
                    allow_node_aligned,
                    skip_remote_node,
                    prev_over_idle_core,
                    growth_algo,
                    nodes,
                    slice_us,
                    fifo,
                    weight,
                    disallow_open_after_us,
                    disallow_preempt_after_us,
                    xllc_mig_min_us,
                    placement,
                    ..
                } = spec.kind.common();

                layer.slice_ns = *slice_us * 1000;
                layer.fifo.write(*fifo);
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
                layer.excl.write(*exclusive);
                layer.allow_node_aligned.write(*allow_node_aligned);
                layer.skip_remote_node.write(*skip_remote_node);
                layer.prev_over_idle_core.write(*prev_over_idle_core);
                layer.growth_algo = growth_algo.as_bpf_enum();
                layer.weight = *weight;
                layer.disallow_open_after_ns = match disallow_open_after_us.unwrap() {
                    v if v == u64::MAX => v,
                    v => v * 1000,
                };
                layer.disallow_preempt_after_ns = match disallow_preempt_after_us.unwrap() {
                    v if v == u64::MAX => v,
                    v => v * 1000,
                };
                layer.xllc_mig_min_ns = (xllc_mig_min_us * 1000.0) as u64;
                layer_weights.push(layer.weight.try_into().unwrap());
                layer.perf = u32::try_from(*perf)?;
                layer.node_mask = nodemask_from_nodes(nodes) as u64;
                for (topo_node_id, topo_node) in &topo.nodes {
                    if !nodes.is_empty() && !nodes.contains(topo_node_id) {
                        continue;
                    }
                    layer.llc_mask |= llcmask_from_llcs(&topo_node.llcs) as u64;
                }

                let task_place = |place: u32| crate::types::layer_task_place(place);
                layer.task_place = match placement {
                    LayerPlacement::Standard => {
                        task_place(bpf_intf::layer_task_place_PLACEMENT_STD as u32)
                    }
                    LayerPlacement::Sticky => {
                        task_place(bpf_intf::layer_task_place_PLACEMENT_STICK as u32)
                    }
                    LayerPlacement::Floating => {
                        task_place(bpf_intf::layer_task_place_PLACEMENT_FLOAT as u32)
                    }
                };
            }

            layer.is_protected.write(match spec.kind {
                LayerKind::Open { .. } => false,
                LayerKind::Confined { protected, .. } | LayerKind::Grouped { protected, .. } => {
                    protected
                }
            });

            match &spec.cpuset {
                Some(mask) => {
                    Self::update_cpumask(&mask, &mut layer.cpuset);
                }
                None => {
                    for i in 0..layer.cpuset.len() {
                        layer.cpuset[i] = u8::MAX;
                    }
                }
            };

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

    fn init_cpu_prox_map(topo: &Topology, cpu_ctxs: &mut [bpf_intf::cpu_ctx]) {
        let radiate = |mut vec: Vec<usize>, center_id: usize| -> Vec<usize> {
            vec.sort_by_key(|&id| (center_id as i32 - id as i32).abs());
            vec
        };
        let radiate_cpu =
            |mut vec: Vec<usize>, center_cpu: usize, center_core: usize| -> Vec<usize> {
                vec.sort_by_key(|&id| {
                    (
                        (center_core as i32 - topo.all_cpus.get(&id).unwrap().core_id as i32).abs(),
                        (center_cpu as i32 - id as i32).abs(),
                    )
                });
                vec
            };

        for (&cpu_id, cpu) in &topo.all_cpus {
            // Collect the spans.
            let mut core_span = topo.all_cores[&cpu.core_id].span.clone();
            let llc_span = &topo.all_llcs[&cpu.llc_id].span;
            let node_span = &topo.nodes[&cpu.node_id].span;
            let sys_span = &topo.span;

            // Make the spans exclusive.
            let sys_span = sys_span.and(&node_span.not());
            let node_span = node_span.and(&llc_span.not());
            let llc_span = llc_span.and(&core_span.not());
            core_span.clear_cpu(cpu_id).unwrap();

            // Convert them into arrays.
            let mut sys_order: Vec<usize> = sys_span.iter().collect();
            let mut node_order: Vec<usize> = node_span.iter().collect();
            let mut llc_order: Vec<usize> = llc_span.iter().collect();
            let mut core_order: Vec<usize> = core_span.iter().collect();

            // Shuffle them so that different CPUs follow different orders.
            // Each CPU radiates in both directions based on the cpu id and
            // radiates out to the closest cores based on core ids.

            sys_order = radiate_cpu(sys_order, cpu_id, cpu.core_id);
            node_order = radiate(node_order, cpu.node_id);
            llc_order = radiate_cpu(llc_order, cpu_id, cpu.core_id);
            core_order = radiate_cpu(core_order, cpu_id, cpu.core_id);

            // Concatenate and record the topology boundaries.
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
                "CPU[{}] proximity map[{}/{}/{}/{}]: {:?}",
                cpu_id, core_end, llc_end, node_end, sys_end, &order
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

    fn init_cpus(skel: &BpfSkel, layer_specs: &[LayerSpec], topo: &Topology) -> Result<()> {
        let key = (0_u32).to_ne_bytes();
        let mut cpu_ctxs: Vec<bpf_intf::cpu_ctx> = vec![];
        let cpu_ctxs_vec = skel
            .maps
            .cpu_ctxs
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
            .context("Failed to lookup cpu_ctx")?
            .unwrap();

        let op_layers: Vec<u32> = layer_specs
            .iter()
            .enumerate()
            .filter(|(_idx, spec)| match &spec.kind {
                LayerKind::Open { .. } => spec.kind.common().preempt,
                _ => false,
            })
            .map(|(idx, _)| idx as u32)
            .collect();
        let on_layers: Vec<u32> = layer_specs
            .iter()
            .enumerate()
            .filter(|(_idx, spec)| match &spec.kind {
                LayerKind::Open { .. } => !spec.kind.common().preempt,
                _ => false,
            })
            .map(|(idx, _)| idx as u32)
            .collect();
        let gp_layers: Vec<u32> = layer_specs
            .iter()
            .enumerate()
            .filter(|(_idx, spec)| match &spec.kind {
                LayerKind::Grouped { .. } => spec.kind.common().preempt,
                _ => false,
            })
            .map(|(idx, _)| idx as u32)
            .collect();
        let gn_layers: Vec<u32> = layer_specs
            .iter()
            .enumerate()
            .filter(|(_idx, spec)| match &spec.kind {
                LayerKind::Grouped { .. } => !spec.kind.common().preempt,
                _ => false,
            })
            .map(|(idx, _)| idx as u32)
            .collect();

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

            fastrand::seed(cpu as u64);

            let mut ogp_order = op_layers.clone();
            ogp_order.append(&mut gp_layers.clone());
            fastrand::shuffle(&mut ogp_order);

            let mut ogn_order = on_layers.clone();
            ogn_order.append(&mut gn_layers.clone());
            fastrand::shuffle(&mut ogn_order);

            let mut op_order = op_layers.clone();
            fastrand::shuffle(&mut op_order);

            let mut on_order = on_layers.clone();
            fastrand::shuffle(&mut on_order);

            let mut gp_order = gp_layers.clone();
            fastrand::shuffle(&mut gp_order);

            let mut gn_order = gn_layers.clone();
            fastrand::shuffle(&mut gn_order);

            for i in 0..MAX_LAYERS {
                cpu_ctxs[cpu].ogp_layer_order[i] =
                    ogp_order.get(i).cloned().unwrap_or(MAX_LAYERS as u32);
                cpu_ctxs[cpu].ogn_layer_order[i] =
                    ogn_order.get(i).cloned().unwrap_or(MAX_LAYERS as u32);

                cpu_ctxs[cpu].op_layer_order[i] =
                    op_order.get(i).cloned().unwrap_or(MAX_LAYERS as u32);
                cpu_ctxs[cpu].on_layer_order[i] =
                    on_order.get(i).cloned().unwrap_or(MAX_LAYERS as u32);
                cpu_ctxs[cpu].gp_layer_order[i] =
                    gp_order.get(i).cloned().unwrap_or(MAX_LAYERS as u32);
                cpu_ctxs[cpu].gn_layer_order[i] =
                    gn_order.get(i).cloned().unwrap_or(MAX_LAYERS as u32);
            }
        }

        Self::init_cpu_prox_map(topo, &mut cpu_ctxs);

        skel.maps
            .cpu_ctxs
            .update_percpu(
                &key,
                &Self::convert_cpu_ctxs(cpu_ctxs),
                libbpf_rs::MapFlags::ANY,
            )
            .context("Failed to update cpu_ctx")?;

        Ok(())
    }

    fn init_llc_prox_map(skel: &mut BpfSkel, topo: &Topology) -> Result<()> {
        for (&llc_id, llc) in &topo.all_llcs {
            // Collect the orders.
            let mut node_order: Vec<usize> =
                topo.nodes[&llc.node_id].llcs.keys().cloned().collect();
            let mut sys_order: Vec<usize> = topo.all_llcs.keys().cloned().collect();

            // Make the orders exclusive.
            sys_order.retain(|id| !node_order.contains(id));
            node_order.retain(|&id| id != llc_id);

            // Shufle so that different LLCs follow different orders. See
            // init_cpu_prox_map().
            fastrand::seed(llc_id as u64);
            fastrand::shuffle(&mut sys_order);
            fastrand::shuffle(&mut node_order);

            // Concatenate and record the node boundary.
            let mut order: Vec<usize> = vec![];
            let mut idx: usize = 0;

            idx += 1;
            order.push(llc_id);

            idx += node_order.len();
            order.append(&mut node_order);
            let node_end = idx;

            idx += sys_order.len();
            order.append(&mut sys_order);
            let sys_end = idx;

            debug!(
                "LLC[{}] proximity map[{}/{}]: {:?}",
                llc_id, node_end, sys_end, &order
            );

            // Record in llc_ctx.
            //
            // XXX - This would be a lot easier if llc_ctx were in the bss.
            // See BpfStats::read().
            let key = llc_id as u32;
            let llc_id_slice =
                unsafe { std::slice::from_raw_parts((&key as *const u32) as *const u8, 4) };
            let v = skel
                .maps
                .llc_data
                .lookup(llc_id_slice, libbpf_rs::MapFlags::ANY)
                .unwrap()
                .unwrap();
            let mut llcc = unsafe { *(v.as_slice().as_ptr() as *const bpf_intf::llc_ctx) };

            let pmap = &mut llcc.prox_map;
            for (i, &llc_id) in order.iter().enumerate() {
                pmap.llcs[i] = llc_id as u16;
            }
            pmap.node_end = node_end as u32;
            pmap.sys_end = sys_end as u32;

            let v = unsafe {
                std::slice::from_raw_parts(
                    &llcc as *const bpf_intf::llc_ctx as *const u8,
                    std::mem::size_of::<bpf_intf::llc_ctx>(),
                )
            };

            skel.maps
                .llc_data
                .update(llc_id_slice, v, libbpf_rs::MapFlags::ANY)?
        }

        Ok(())
    }

    fn init(
        opts: &'a Opts,
        layer_specs: &[LayerSpec],
        open_object: &'a mut MaybeUninit<OpenObject>,
    ) -> Result<Self> {
        let nr_layers = layer_specs.len();
        let mut disable_topology = opts.disable_topology.unwrap_or(false);

        let topo = Arc::new(if disable_topology {
            Topology::with_flattened_llc_node()?
        } else {
            Topology::new()?
        });

        /*
         * FIXME: scx_layered incorrectly assumes that node, LLC and CPU IDs
         * are consecutive. Verify that they are on this system and bail if
         * not. It's lucky that core ID is not used anywhere as core IDs are
         * not consecutive on some Ryzen CPUs.
         */
        if topo.nodes.keys().enumerate().any(|(i, &k)| i != k) {
            bail!("Holes in node IDs detected: {:?}", topo.nodes.keys());
        }
        if topo.all_llcs.keys().enumerate().any(|(i, &k)| i != k) {
            bail!("Holes in LLC IDs detected: {:?}", topo.all_llcs.keys());
        }
        if topo.all_cpus.keys().enumerate().any(|(i, &k)| i != k) {
            bail!("Holes in CPU IDs detected: {:?}", topo.all_cpus.keys());
        }

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

        let cpu_pool = CpuPool::new(topo.clone())?;

        // If disabling topology awareness clear out any set NUMA/LLC configs and
        // it will fallback to using all cores.
        let layer_specs: Vec<_> = if disable_topology {
            info!("Disabling topology awareness");
            layer_specs
                .iter()
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
        info!(
            "Running scx_layered (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        let mut skel = scx_ops_open!(skel_builder, open_object, layered)?;

        // enable autoloads for conditionally loaded things
        // immediately after creating skel (because this is always before loading)
        if opts.enable_gpu_support {
            // by default, enable open if gpu support is enabled.
            // open has been observed to be relatively cheap to kprobe.
            if opts.gpu_kprobe_level >= 1 {
                compat::cond_kprobe_enable("nvidia_open", &skel.progs.kprobe_nvidia_open)?;
            }
            // enable the rest progressively based upon how often they are called
            // for observed workloads
            if opts.gpu_kprobe_level >= 2 {
                compat::cond_kprobe_enable("nvidia_mmap", &skel.progs.kprobe_nvidia_mmap)?;
            }
            if opts.gpu_kprobe_level >= 3 {
                compat::cond_kprobe_enable("nvidia_poll", &skel.progs.kprobe_nvidia_poll)?;
            }
        }

        let ext_sched_class_addr = get_kallsyms_addr("ext_sched_class");
        let idle_sched_class_addr = get_kallsyms_addr("idle_sched_class");

        if ext_sched_class_addr.is_ok() && idle_sched_class_addr.is_ok() {
            skel.maps.rodata_data.ext_sched_class_addr = ext_sched_class_addr.unwrap();
            skel.maps.rodata_data.idle_sched_class_addr = idle_sched_class_addr.unwrap();
        } else {
            warn!(
                "Unable to get sched_class addresses from /proc/kallsyms, disabling skip_preempt."
            );
        }

        skel.maps.rodata_data.slice_ns = scx_enums.SCX_SLICE_DFL;
        skel.maps.rodata_data.max_exec_ns = 20 * scx_enums.SCX_SLICE_DFL;

        // Initialize skel according to @opts.
        skel.struct_ops.layered_mut().exit_dump_len = opts.exit_dump_len;

        if !opts.disable_queued_wakeup {
            match *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP {
                0 => info!("Kernel does not support queued wakeup optimization"),
                v => skel.struct_ops.layered_mut().flags |= v,
            }
        }

        skel.maps.rodata_data.percpu_kthread_preempt = !opts.disable_percpu_kthread_preempt;
        skel.maps.rodata_data.percpu_kthread_preempt_all =
            !opts.disable_percpu_kthread_preempt && opts.percpu_kthread_preempt_all;
        skel.maps.rodata_data.debug = opts.verbose as u32;
        skel.maps.rodata_data.slice_ns = opts.slice_us * 1000;
        skel.maps.rodata_data.max_exec_ns = if opts.max_exec_us > 0 {
            opts.max_exec_us * 1000
        } else {
            opts.slice_us * 1000 * 20
        };
        skel.maps.rodata_data.nr_cpu_ids = *NR_CPU_IDS as u32;
        skel.maps.rodata_data.nr_possible_cpus = *NR_CPUS_POSSIBLE as u32;
        skel.maps.rodata_data.smt_enabled = topo.smt_enabled;
        skel.maps.rodata_data.has_little_cores = topo.has_little_cores();
        skel.maps.rodata_data.xnuma_preemption = opts.xnuma_preemption;
        skel.maps.rodata_data.antistall_sec = opts.antistall_sec;
        skel.maps.rodata_data.monitor_disable = opts.monitor_disable;
        skel.maps.rodata_data.lo_fb_wait_ns = opts.lo_fb_wait_us * 1000;
        skel.maps.rodata_data.lo_fb_share_ppk = ((opts.lo_fb_share * 1024.0) as u32).clamp(1, 1024);
        skel.maps.rodata_data.enable_antistall = !opts.disable_antistall;
        skel.maps.rodata_data.enable_match_debug = opts.enable_match_debug;
        skel.maps.rodata_data.enable_gpu_support = opts.enable_gpu_support;

        for (cpu, sib) in topo.sibling_cpus().iter().enumerate() {
            skel.maps.rodata_data.__sibling_cpu[cpu] = *sib;
        }
        for cpu in topo.all_cpus.keys() {
            skel.maps.rodata_data.all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }

        skel.maps.rodata_data.nr_op_layers = layer_specs
            .iter()
            .filter(|spec| match &spec.kind {
                LayerKind::Open { .. } => spec.kind.common().preempt,
                _ => false,
            })
            .count() as u32;
        skel.maps.rodata_data.nr_on_layers = layer_specs
            .iter()
            .filter(|spec| match &spec.kind {
                LayerKind::Open { .. } => !spec.kind.common().preempt,
                _ => false,
            })
            .count() as u32;
        skel.maps.rodata_data.nr_gp_layers = layer_specs
            .iter()
            .filter(|spec| match &spec.kind {
                LayerKind::Grouped { .. } => spec.kind.common().preempt,
                _ => false,
            })
            .count() as u32;
        skel.maps.rodata_data.nr_gn_layers = layer_specs
            .iter()
            .filter(|spec| match &spec.kind {
                LayerKind::Grouped { .. } => !spec.kind.common().preempt,
                _ => false,
            })
            .count() as u32;
        skel.maps.rodata_data.nr_excl_layers = layer_specs
            .iter()
            .filter(|spec| spec.kind.common().exclusive)
            .count() as u32;

        let mut min_open = u64::MAX;
        let mut min_preempt = u64::MAX;

        for spec in layer_specs.iter() {
            if let LayerKind::Open { common, .. } = &spec.kind {
                min_open = min_open.min(common.disallow_open_after_us.unwrap());
                min_preempt = min_preempt.min(common.disallow_preempt_after_us.unwrap());
            }
        }

        skel.maps.rodata_data.min_open_layer_disallow_open_after_ns = match min_open {
            u64::MAX => *DFL_DISALLOW_OPEN_AFTER_US,
            v => v,
        };
        skel.maps
            .rodata_data
            .min_open_layer_disallow_preempt_after_ns = match min_preempt {
            u64::MAX => *DFL_DISALLOW_PREEMPT_AFTER_US,
            v => v,
        };

        // Consider all layers empty at the beginning.
        for i in 0..layer_specs.len() {
            skel.maps.bss_data.empty_layer_ids[i] = i as u32;
        }
        skel.maps.bss_data.nr_empty_layer_ids = nr_layers as u32;

        Self::init_layers(&mut skel, &layer_specs, &topo)?;
        Self::init_nodes(&mut skel, opts, &topo);

        // We set the pin path before loading the skeleton. This will ensure
        // libbpf creates and pins the map, or reuses the pinned map fd for us,
        // so that we can keep reusing the older map already pinned on scheduler
        // restarts.
        let layered_task_hint_map_path = &opts.task_hint_map;
        let hint_map = &mut skel.maps.scx_layered_task_hint_map;
        // Only set pin path if a path is provided.
        if layered_task_hint_map_path.is_empty() == false {
            hint_map.set_pin_path(layered_task_hint_map_path).unwrap();
        }

        let mut skel = scx_ops_load!(skel, layered, uei)?;

        let mut layers = vec![];
        let layer_growth_orders =
            LayerGrowthAlgo::layer_core_orders(&cpu_pool, &layer_specs, &topo)?;
        for (idx, spec) in layer_specs.iter().enumerate() {
            let growth_order = layer_growth_orders
                .get(&idx)
                .with_context(|| "layer has no growth order".to_string())?;
            layers.push(Layer::new(spec, &topo, growth_order)?);
        }

        let mut idle_qos_enabled = layers
            .iter()
            .any(|layer| layer.kind.common().idle_resume_us.unwrap_or(0) > 0);
        if idle_qos_enabled && !cpu_idle_resume_latency_supported() {
            warn!("idle_resume_us not supported, ignoring");
            idle_qos_enabled = false;
        }

        Self::init_cpus(&skel, &layer_specs, &topo)?;
        Self::init_llc_prox_map(&mut skel, &topo)?;

        // Other stuff.
        let proc_reader = fb_procfs::ProcReader::new();

        // Handle setup if layered is running in a pid namespace.
        let input = ProgramInput {
            ..Default::default()
        };
        let prog = &mut skel.progs.initialize_pid_namespace;

        let _ = prog.test_run(input);

        // XXX If we try to refresh the cpumasks here before attaching, we
        // sometimes (non-deterministically) don't see the updated values in
        // BPF. It would be better to update the cpumasks here before we
        // attach, but the value will quickly converge anyways so it's not a
        // huge problem in the interim until we figure it out.

        // Allow all tasks to open and write to BPF task hint map, now that
        // we should have it pinned at the desired location.
        if layered_task_hint_map_path.is_empty() == false {
            let path = CString::new(layered_task_hint_map_path.as_bytes()).unwrap();
            let mode: libc::mode_t = 0o666;
            unsafe {
                if libc::chmod(path.as_ptr(), mode) != 0 {
                    trace!("'chmod' to 666 of task hint map failed, continuing...");
                }
            }
        }

        // Attach.
        let struct_ops = scx_ops_attach!(skel, layered)?;
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        let mut gpu_task_handler =
            GpuTaskAffinitizer::new(opts.gpu_affinitize_secs, opts.enable_gpu_affinitize);
        gpu_task_handler.init(topo.clone());
        let sched = Self {
            struct_ops: Some(struct_ops),
            layer_specs,

            sched_intv: Duration::from_secs_f64(opts.interval),
            layer_refresh_intv: Duration::from_millis(opts.layer_refresh_ms_avgruntime),

            cpu_pool,
            layers,
            idle_qos_enabled,

            sched_stats: Stats::new(&mut skel, &proc_reader, &gpu_task_handler)?,

            nr_layer_cpus_ranges: vec![(0, 0); nr_layers],
            processing_dur: Default::default(),

            proc_reader,
            skel,

            topo,
            netdevs,
            stats_server,
            gpu_task_handler,
        };

        info!("Layered Scheduler Attached. Run `scx_layered --monitor` for metrics.");

        Ok(sched)
    }

    fn update_cpumask(mask: &Cpumask, bpfmask: &mut [u8]) {
        for cpu in 0..mask.len() {
            if mask.test_cpu(cpu) {
                bpfmask[cpu / 8] |= 1 << (cpu % 8);
            } else {
                bpfmask[cpu / 8] &= !(1 << (cpu % 8));
            }
        }
    }

    fn update_bpf_layer_cpumask(layer: &Layer, bpf_layer: &mut types::layer) {
        trace!("[{}] Updating BPF CPUs: {}", layer.name, &layer.cpus);
        Self::update_cpumask(&layer.cpus, &mut bpf_layer.cpus);

        bpf_layer.nr_cpus = layer.nr_cpus as u32;
        for (llc_id, &nr_llc_cpus) in layer.nr_llc_cpus.iter().enumerate() {
            bpf_layer.nr_llc_cpus[llc_id] = nr_llc_cpus as u32;
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
                irqmask.clear_all();
                for cpu in available_cpus.iter() {
                    if !node_cpus.test_cpu(cpu) {
                        continue;
                    }
                    let _ = irqmask.set_cpu(cpu);
                }
                // If no CPUs are available in the node then spread the load across the node
                if irqmask.weight() == 0 {
                    for cpu in node_cpus.iter() {
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
        let nr_cpus = self.cpu_pool.topo.all_cpus.len();
        let utils = &self.sched_stats.layer_utils;

        let mut records: Vec<(u64, u64, u64, usize, usize, usize)> = vec![];
        let mut targets: Vec<(usize, usize)> = vec![];

        for (idx, layer) in self.layers.iter().enumerate() {
            targets.push(match &layer.kind {
                LayerKind::Confined {
                    util_range,
                    cpus_range,
                    cpus_range_frac,
                    ..
                }
                | LayerKind::Grouped {
                    util_range,
                    cpus_range,
                    cpus_range_frac,
                    ..
                } => {
                    // A grouped layer can choose to include open cputime
                    // for sizing. Also, as an empty layer can only get CPU
                    // time through fallback (counted as owned) or open
                    // execution, add open cputime for empty layers.
                    let owned = utils[idx][LAYER_USAGE_OWNED];
                    let open = utils[idx][LAYER_USAGE_OPEN];

                    let mut util = owned;
                    if layer.kind.util_includes_open_cputime() || layer.nr_cpus == 0 {
                        util += open;
                    }

                    let util = if util < 0.01 { 0.0 } else { util };
                    let low = (util / util_range.1).ceil() as usize;
                    let high = ((util / util_range.0).floor() as usize).max(low);
                    let target = layer.cpus.weight().clamp(low, high);
                    let cpus_range =
                        resolve_cpus_pct_range(cpus_range, cpus_range_frac, nr_cpus).unwrap();

                    records.push((
                        (owned * 100.0) as u64,
                        (open * 100.0) as u64,
                        (util * 100.0) as u64,
                        low,
                        high,
                        target,
                    ));

                    (target.clamp(cpus_range.0, cpus_range.1), cpus_range.0)
                }
                LayerKind::Open { .. } => (0, 0),
            });
        }

        trace!("initial targets: {:?}", &targets);
        trace!("(owned, open, util, low, high, target): {:?}", &records);
        targets
    }

    /// Given (target, min) pair for each layer which was determined
    /// assuming infinite number of CPUs, distribute the actual CPUs
    /// according to their weights.
    fn weighted_target_nr_cpus(&self, targets: &[(usize, usize)]) -> Vec<usize> {
        let mut nr_left = self.cpu_pool.topo.all_cpus.len();
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

    // Figure out a tuple (LLCs, extra_cpus) in terms of the target CPUs
    // computed by weighted_target_nr_cpus. Returns the number of full LLCs
    // occupied by a layer, and any extra CPUs that don't occupy a full LLC.
    fn compute_target_llcs(target: usize, topo: &Topology) -> (usize, usize) {
        // TODO(kkd): We assume each LLC has equal number of cores.
        let cores_per_llc = topo.all_cores.len() / topo.all_llcs.len();
        // TODO(kkd): We assume each core has fixed number of threads.
        let cpus_per_core = topo.all_cores.first_key_value().unwrap().1.cpus.len();
        let cpus_per_llc = cores_per_llc * cpus_per_core;

        let full = target / cpus_per_llc;
        let extra = target % cpus_per_llc;

        (full, extra.div_ceil(cpus_per_core))
    }

    // Recalculate the core order for layers using StickyDynamic growth
    // algorithm. Tuples from compute_target_llcs are used to decide how many
    // LLCs and cores should be assigned to each layer, logic to alloc and free
    // CPUs operates on that core order. This happens in three logical steps, we
    // first free LLCs from layers that shrunk from last recomputation, then
    // distribute freed LLCs to growing layers, and then spill over remaining
    // cores in free LLCs.
    fn recompute_layer_core_order(&mut self, layer_targets: &Vec<(usize, usize)>) {
        // Collect freed LLCs from shrinking layers.
        debug!(
            " free: before pass: free_llcs={:?}",
            self.cpu_pool.free_llcs
        );
        for &(idx, target) in layer_targets.iter().rev() {
            let layer = &mut self.layers[idx];
            let old_tlc = layer.target_llc_cpus;
            let new_tlc = Self::compute_target_llcs(target, &self.topo);

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            let mut to_free = (old_tlc.0 as i32 - new_tlc.0 as i32).max(0) as usize;

            debug!(
                " free: layer={} old_tlc={:?} new_tlc={:?} to_free={} assigned={} free={}",
                layer.name,
                old_tlc,
                new_tlc,
                to_free,
                layer.assigned_llcs.len(),
                self.cpu_pool.free_llcs.len()
            );

            while to_free > 0 && layer.assigned_llcs.len() > 0 {
                let llc = layer.assigned_llcs.pop().unwrap();
                self.cpu_pool.free_llcs.push((llc, 0));
                to_free -= 1;

                debug!(" layer={} freed_llc={}", layer.name, llc);
            }
        }
        debug!(" free: after pass: free_llcs={:?}", self.cpu_pool.free_llcs);

        // Redistribute the freed LLCs to growing layers.
        for &(idx, target) in layer_targets.iter().rev() {
            let layer = &mut self.layers[idx];
            let old_tlc = layer.target_llc_cpus;
            let new_tlc = Self::compute_target_llcs(target, &self.topo);

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            let mut to_alloc = (new_tlc.0 as i32 - old_tlc.0 as i32).max(0) as usize;

            debug!(
                " alloc: layer={} old_tlc={:?} new_tlc={:?} to_alloc={} assigned={} free={}",
                layer.name,
                old_tlc,
                new_tlc,
                to_alloc,
                layer.assigned_llcs.len(),
                self.cpu_pool.free_llcs.len()
            );

            while to_alloc > 0
                && self.cpu_pool.free_llcs.len() > 0
                && to_alloc <= self.cpu_pool.free_llcs.len()
            {
                let llc = self.cpu_pool.free_llcs.pop().unwrap().0;
                layer.assigned_llcs.push(llc);
                to_alloc -= 1;

                debug!(" layer={} alloc_llc={}", layer.name, llc);
            }

            debug!(
                " alloc: layer={} assigned_llcs={:?}",
                layer.name, layer.assigned_llcs
            );

            // Update for next iteration.
            layer.target_llc_cpus = new_tlc;
        }

        // Spillover overflowing cores into free LLCs. Bigger layers get to take
        // a chunk before smaller layers.
        for &(idx, _) in layer_targets.iter() {
            let mut core_order = vec![];
            let layer = &mut self.layers[idx];

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            let tlc = layer.target_llc_cpus;
            let mut extra = tlc.1;
            // TODO(kkd): Move this logic into cpu_pool? What's the best place?
            let cores_per_llc = self.topo.all_cores.len() / self.topo.all_llcs.len();
            let cpus_per_core = self.topo.all_cores.first_key_value().unwrap().1.cpus.len();
            let cpus_per_llc = cores_per_llc * cpus_per_core;

            // Consume from front since we pop from the back.
            for i in 0..self.cpu_pool.free_llcs.len() {
                let free_vec = &mut self.cpu_pool.free_llcs;
                // Available CPUs in LLC.
                let avail = cpus_per_llc - free_vec[i].1;
                // The amount we'll use.
                let mut used = extra.min(avail);

                let shift = free_vec[i].1;
                free_vec[i].1 += used;

                let llc_id = free_vec[i].0;
                let llc = self.topo.all_llcs.get(&llc_id).unwrap();

                for core in llc.cores.iter().skip(shift) {
                    core_order.push(core.1.id);
                    if used == 0 {
                        break;
                    }
                    used -= 1;
                }

                extra -= used;
                if extra == 0 {
                    break;
                }
            }

            core_order.reverse();
            layer.core_order = core_order;
        }

        // Reset consumed entries in free LLCs.
        for i in 0..self.cpu_pool.free_llcs.len() {
            self.cpu_pool.free_llcs[i].1 = 0;
        }

        for &(idx, _) in layer_targets.iter() {
            let layer = &mut self.layers[idx];

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            for core in self.topo.all_cores.iter() {
                let llc_id = core.1.llc_id;
                if layer.assigned_llcs.contains(&llc_id) {
                    layer.core_order.push(core.1.id);
                }
            }
            // Update core_order for the layer, but reverse to keep the start stable.
            layer.core_order.reverse();

            debug!(
                " alloc: layer={} core_order={:?}",
                layer.name, layer.core_order
            );
        }
    }

    fn refresh_cpumasks(&mut self) -> Result<()> {
        let layer_is_open = |layer: &Layer| matches!(layer.kind, LayerKind::Open { .. });

        let mut updated = false;
        let targets = self.calc_target_nr_cpus();
        let targets = self.weighted_target_nr_cpus(&targets);

        let mut ascending: Vec<(usize, usize)> = targets.iter().copied().enumerate().collect();
        ascending.sort_by(|a, b| a.1.cmp(&b.1));

        self.recompute_layer_core_order(&ascending);

        // If any layer is growing, guarantee that the largest layer that is
        // freeing CPUs frees at least one CPU.
        let mut force_free = self
            .layers
            .iter()
            .zip(targets.iter())
            .any(|(layer, &target)| layer.nr_cpus < target);

        // Shrink all layers first so that CPUs are available for
        // redistribution. Do so in the descending target number of CPUs
        // order.
        for &(idx, target) in ascending.iter().rev() {
            let layer = &mut self.layers[idx];
            if layer_is_open(layer) {
                continue;
            }

            let nr_cur = layer.cpus.weight();
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

                nr_to_free = nr_to_free.saturating_sub(nr_freed);
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

            let nr_cur = layer.cpus.weight();
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
                let available_cpus = self.cpu_pool.available_cpus().and(&layer.allowed_cpus);
                let nr_available_cpus = available_cpus.weight();

                // Open layers need the intersection of allowed cpus and
                // available cpus.
                layer.cpus = available_cpus;
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

            // Trigger updates on the BPF side.
            let input = ProgramInput {
                ..Default::default()
            };
            let prog = &mut self.skel.progs.refresh_layer_cpumasks;
            let _ = prog.test_run(input);

            // Update empty_layers.
            let empty_layer_ids: Vec<u32> = self
                .layers
                .iter()
                .enumerate()
                .filter(|(_idx, layer)| layer.nr_cpus == 0)
                .map(|(idx, _layer)| idx as u32)
                .collect();
            for i in 0..self.layers.len() {
                self.skel.maps.bss_data.empty_layer_ids[i] =
                    empty_layer_ids.get(i).cloned().unwrap_or(MAX_LAYERS as u32);
            }
            self.skel.maps.bss_data.nr_empty_layer_ids = empty_layer_ids.len() as u32;
        }

        let _ = self.update_netdev_cpumasks();
        Ok(())
    }

    fn refresh_idle_qos(&mut self) -> Result<()> {
        if !self.idle_qos_enabled {
            return Ok(());
        }

        let mut cpu_idle_qos = vec![0; *NR_CPU_IDS];
        for layer in self.layers.iter() {
            let idle_resume_us = layer.kind.common().idle_resume_us.unwrap_or(0) as i32;
            for cpu in layer.cpus.iter() {
                cpu_idle_qos[cpu] = idle_resume_us;
            }
        }

        for (cpu, idle_resume_usec) in cpu_idle_qos.iter().enumerate() {
            update_cpu_idle_resume_latency(cpu, *idle_resume_usec)?;
        }

        Ok(())
    }

    fn step(&mut self) -> Result<()> {
        let started_at = Instant::now();
        self.sched_stats.refresh(
            &mut self.skel,
            &self.proc_reader,
            started_at,
            self.processing_dur,
            &self.gpu_task_handler,
        )?;
        self.refresh_cpumasks()?;
        self.refresh_idle_qos()?;
        self.gpu_task_handler.maybe_affinitize();
        self.processing_dur += Instant::now().duration_since(started_at);
        Ok(())
    }

    fn generate_sys_stats(
        &mut self,
        stats: &Stats,
        cpus_ranges: &mut [(usize, usize)],
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
        let enable_layer_refresh = !self.layer_refresh_intv.is_zero();
        let mut next_layer_refresh_at = Instant::now() + self.layer_refresh_intv;
        let mut cpus_ranges = HashMap::<ThreadId, Vec<(usize, usize)>>::new();

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            let now = Instant::now();

            if now >= next_sched_at {
                self.step()?;
                while next_sched_at < now {
                    next_sched_at += self.sched_intv;
                }
            }

            if enable_layer_refresh && now >= next_layer_refresh_at {
                self.skel.maps.bss_data.layer_refresh_seq_avgruntime += 1;
                while next_layer_refresh_at < now {
                    next_layer_refresh_at += self.layer_refresh_intv;
                }
            }

            match req_ch.recv_deadline(next_sched_at) {
                Ok(StatsReq::Hello(tid)) => {
                    cpus_ranges.insert(
                        tid,
                        self.layers.iter().map(|l| (l.nr_cpus, l.nr_cpus)).collect(),
                    );
                    let stats =
                        Stats::new(&mut self.skel, &self.proc_reader, &self.gpu_task_handler)?;
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

                    stats.refresh(
                        &mut self.skel,
                        &self.proc_reader,
                        now,
                        self.processing_dur,
                        &self.gpu_task_handler,
                    )?;
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

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
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
            if spec.matches.is_empty() {
                bail!("Non-terminal spec {:?} has NULL matches", spec.name);
            }
        } else {
            if spec.matches.len() != 1 || !spec.matches[0].is_empty() {
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
                    LayerMatch::CgroupSuffix(suffix) => {
                        if suffix.len() > MAX_PATH {
                            bail!("Spec {:?} has too long a cgroup suffix", spec.name);
                        }
                    }
                    LayerMatch::CgroupContains(substr) => {
                        if substr.len() > MAX_PATH {
                            bail!("Spec {:?} has too long a cgroup substr", spec.name);
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

fn name_suffix(cgroup: &str, len: usize) -> String {
    let suffixlen = std::cmp::min(len, cgroup.len());
    let suffixrev: String = cgroup.chars().rev().take(suffixlen).collect();

    suffixrev.chars().rev().collect()
}

fn traverse_sysfs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = vec![];

    if !dir.is_dir() {
        panic!("path {:?} does not correspond to directory", dir);
    }

    let direntries = fs::read_dir(dir)?;

    for entry in direntries {
        let path = entry?.path();
        if path.is_dir() {
            paths.append(&mut traverse_sysfs(&path)?);
            paths.push(path);
        }
    }

    Ok(paths)
}

fn find_cpumask(cgroup: &str) -> Cpumask {
    let mut path = String::from(cgroup);
    path.push_str("/cpuset.cpus.effective");

    let description = fs::read_to_string(&mut path).unwrap();

    Cpumask::from_cpulist(&description).unwrap()
}

fn expand_template(rule: &LayerMatch) -> Result<Vec<(LayerMatch, Cpumask)>> {
    match rule {
        LayerMatch::CgroupSuffix(suffix) => Ok(traverse_sysfs(Path::new("/sys/fs/cgroup"))?
            .into_iter()
            .map(|cgroup| String::from(cgroup.to_str().expect("could not parse cgroup path")))
            .filter(|cgroup| cgroup.ends_with(suffix))
            .map(|cgroup| {
                (
                    {
                        let mut slashterminated = cgroup.clone();
                        slashterminated.push('/');
                        LayerMatch::CgroupSuffix(name_suffix(&slashterminated, 64))
                    },
                    find_cpumask(&cgroup),
                )
            })
            .collect()),
        _ => panic!("Unimplemented template enum {:?}", rule),
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "scx_layered {}",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

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
    if opts.local_llc_iteration {
        warn!("--local_llc_iteration is deprecated and noop");
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

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
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

    if let Some(path) = &opts.example {
        write_example_file(path)?;
        return Ok(());
    }

    let mut layer_config = match opts.run_example {
        true => EXAMPLE_CONFIG.clone(),
        false => LayerConfig { specs: vec![] },
    };

    for (idx, input) in opts.specs.iter().enumerate() {
        let specs = LayerSpec::parse(input)
            .context(format!("Failed to parse specs[{}] ({:?})", idx, input))?;

        for spec in specs {
            match spec.template {
                Some(ref rule) => {
                    let matches = expand_template(&rule)?;
                    // in the absence of matching cgroups, have template layers
                    // behave as non-template layers do.
                    if matches.is_empty() {
                        layer_config.specs.push(spec);
                    } else {
                        for (mt, mask) in matches {
                            let mut genspec = spec.clone();

                            genspec.cpuset = Some(mask);

                            // Push the new "and" rule into each "or" term.
                            for orterm in &mut genspec.matches {
                                orterm.push(mt.clone());
                            }

                            match &mt {
                                LayerMatch::CgroupSuffix(cgroup) => genspec.name.push_str(cgroup),
                                _ => bail!("Template match has unexpected type"),
                            }

                            // Push the generated layer into the config
                            layer_config.specs.push(genspec);
                        }
                    }
                }

                None => {
                    layer_config.specs.push(spec);
                }
            }
        }
    }

    for spec in layer_config.specs.iter_mut() {
        let common = spec.kind.common_mut();

        if common.slice_us == 0 {
            common.slice_us = opts.slice_us;
        }

        if common.weight == 0 {
            common.weight = DEFAULT_LAYER_WEIGHT;
        }
        common.weight = common.weight.clamp(MIN_LAYER_WEIGHT, MAX_LAYER_WEIGHT);

        if common.preempt {
            if common.disallow_open_after_us.is_some() {
                warn!(
                    "Preempt layer {} has non-null disallow_open_after_us, ignored",
                    &spec.name
                );
            }
            if common.disallow_preempt_after_us.is_some() {
                warn!(
                    "Preempt layer {} has non-null disallow_preempt_after_us, ignored",
                    &spec.name
                );
            }
            common.disallow_open_after_us = Some(u64::MAX);
            common.disallow_preempt_after_us = Some(u64::MAX);
        } else {
            if common.disallow_open_after_us.is_none() {
                common.disallow_open_after_us = Some(*DFL_DISALLOW_OPEN_AFTER_US);
            }

            if common.disallow_preempt_after_us.is_none() {
                common.disallow_preempt_after_us = Some(*DFL_DISALLOW_PREEMPT_AFTER_US);
            }
        }

        if common.idle_smt.is_some() {
            warn!("Layer {} has deprecated flag \"idle_smt\"", &spec.name);
        }
    }

    if opts.print_and_exit {
        println!("specs={}", serde_json::to_string_pretty(&layer_config)?);
        return Ok(());
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
