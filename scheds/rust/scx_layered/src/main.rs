// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
mod stats;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
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

use inotify::{Inotify, WatchMask};
use std::os::unix::io::AsRawFd;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
pub use bpf_skel::*;
use clap::Parser;
use crossbeam::channel::Receiver;
use crossbeam::select;
use lazy_static::lazy_static;
use libbpf_rs::libbpf_sys;
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use nix::sched::CpuSet;
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::Nvml;
use once_cell::sync::OnceCell;
use regex::Regex;
use scx_layered::alloc::{unified_alloc, LayerAlloc, LayerDemand};
use scx_layered::*;
use scx_raw_pmu::PMUManager;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::init_libbpf_logging;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::perf;
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
use scx_utils::NetDev;
use scx_utils::Topology;
use scx_utils::TopologyArgs;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::NR_CPU_IDS;
use stats::LayerStats;
use stats::StatsReq;
use stats::StatsRes;
use stats::SysStats;
use std::collections::VecDeque;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::filter::EnvFilter;
use walkdir::WalkDir;

const SCHEDULER_NAME: &str = "scx_layered";
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
    static ref EXAMPLE_CONFIG: LayerConfig = serde_json::from_str(
        r#"[
          {
            "name": "batch",
            "comment": "tasks under system.slice or tasks with nice value > 0",
            "matches": [[{"CgroupPrefix": "system.slice/"}], [{"NiceAbove": 0}]],
            "kind": {"Confined": {
              "util_range": [0.8, 0.9], "cpus_range": [0, 16],
              "min_exec_us": 1000, "slice_us": 20000, "weight": 100,
              "xllc_mig_min_us": 1000.0, "perf": 1024
            }}
          },
          {
            "name": "immediate",
            "comment": "tasks under workload.slice with nice value < 0",
            "matches": [[{"CgroupPrefix": "workload.slice/"}, {"NiceBelow": 0}]],
            "kind": {"Open": {
              "min_exec_us": 100, "yield_ignore": 0.25, "slice_us": 20000,
              "preempt": true, "exclusive": true,
              "prev_over_idle_core": true,
              "weight": 100, "perf": 1024
            }}
          },
          {
            "name": "stress-ng",
            "comment": "stress-ng test layer",
            "matches": [[{"CommPrefix": "stress-ng"}], [{"PcommPrefix": "stress-ng"}]],
            "kind": {"Confined": {
              "util_range": [0.2, 0.8],
              "min_exec_us": 800, "preempt": true, "slice_us": 800,
              "weight": 100, "growth_algo": "Topo", "perf": 1024
            }}
          },
          {
            "name": "normal",
            "comment": "the rest",
            "matches": [[]],
            "kind": {"Grouped": {
              "util_range": [0.5, 0.6], "util_includes_open_cputime": true,
              "min_exec_us": 200, "slice_us": 20000, "weight": 100,
              "xllc_mig_min_us": 100.0, "growth_algo": "Linear", "perf": 1024
            }}
          }
        ]"#,
    )
    .unwrap();
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
///   command to the scheduler. See examples/cmdjoin.c for more details.
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
/// - HintEquals: u64. Match tasks whose hint value equals this value.
///   The value must be in the range [0, 1024].
///
/// - SystemCpuUtilBelow: f64. Match when the system CPU utilization fraction
///   is below the specified threshold (a value in the range [0.0, 1.0]). This
///   option can only be used in conjunction with HintEquals.
///
/// - DsqInsertBelow: f64. Match when the layer DSQ insertion fraction is below
///   the specified threshold (a value in the range [0.0, 1.0]). This option can
///   only be used in conjunction with HintEquals.
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
/// - allow_node_aligned: DEPRECATED. Node-aligned tasks are now always
///   dispatched on layer DSQs. This field is ignored if specified.
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
/// - growth_algo: Determines the order in which CPUs are allocated to the
///   layer as it grows. All algorithms are NUMA-aware and produce per-node
///   core orderings. Most are locality algorithms that prefer the layer's
///   home node and spill to remote nodes only when local capacity is
///   exhausted. NUMA-spread algorithms (RoundRobin, NodeSpread*) instead
///   enforce equal CPU counts across all NUMA nodes. Default: Sticky.
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
///   busy= 34.2 util= 1733.6 load=  21744.1 fb_cpus=[n0:1]
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
    /// Deprecated, noop, use RUST_LOG or --log-level instead.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

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

    /// Specify the logging level. Accepts rust's envfilter syntax for modular
    /// logging: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax. Examples: ["info", "warn,tokio=info"]
    #[clap(long, default_value = "info")]
    log_level: String,

    /// Disable topology awareness. When enabled, the "nodes" and "llcs" settings on
    /// a layer are ignored. Defaults to false on topologies with multiple NUMA nodes
    /// or LLCs, and true otherwise.
    #[arg(short = 't', long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    disable_topology: Option<bool>,

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

    /// Column limit for stats monitor output.
    #[clap(long, default_value = "95")]
    stats_columns: usize,

    /// Disable per-LLC stats in monitor output.
    #[clap(long)]
    stats_no_llc: bool,

    /// Run with example layer specifications (useful for e.g. CI pipelines)
    #[clap(long)]
    run_example: bool,

    /// Allocate CPUs at an SMT granularity (not core)
    #[clap(long)]
    allow_partial_core: bool,

    /// ***DEPRECATED *** Enables iteration over local LLCs first for
    /// dispatch.
    #[clap(long, default_value = "false")]
    local_llc_iteration: bool,

    /// Low priority fallback DSQs are used to execute tasks with custom CPU
    /// affinities. These DSQs are immediately executed iff a CPU is
    /// otherwise idle. However, after the specified wait, they are
    /// guaranteed upto --lo-fb-share fraction of each CPU.
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
    /// The value set here determines how aggressive
    /// the kprobes enabled on gpu driver functions are.
    /// Higher values are more aggressive, incurring more system overhead
    /// and more accurately identifying PIDs using GPUs in a more timely manner.
    /// Lower values incur less system overhead, at the cost of less accurately
    /// identifying GPU pids and taking longer to do so.
    #[clap(long, default_value = "3")]
    gpu_kprobe_level: u64,

    /// Enable utilization compensation for unattributed CPU work (irq, softirq, stolen). When
    /// enabled, each CPU's layer usage is scaled by the inverse of available capacity to account
    /// for time lost to interrupts.
    #[clap(long, default_value = "false")]
    util_compensation: bool,

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

    /// Optional run ID for tracking scheduler instances.
    #[clap(long)]
    run_id: Option<u64>,

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

    /// Enable affinitized task to use hi fallback queue to get more CPU time.
    #[clap(long, default_value = "")]
    hi_fb_thread_name: String,

    #[clap(flatten, next_help_heading = "Topology Options")]
    topology: TopologyArgs,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

// Cgroup event types for inter-thread communication
#[derive(Debug, Clone)]
enum CgroupEvent {
    Created {
        path: String,
        cgroup_id: u64,    // inode number
        match_bitmap: u64, // bitmap of matched regex rules
    },
    Removed {
        path: String,
        cgroup_id: u64, // inode number
    },
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

#[allow(clippy::needless_range_loop)]
fn read_cpu_ctxs(skel: &BpfSkel) -> Result<Vec<bpf_intf::cpu_ctx>> {
    let mut cpu_ctxs = vec![];
    let cpu_ctxs_vec = skel
        .maps
        .cpu_ctxs
        .lookup_percpu(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
        .context("Failed to lookup cpu_ctx")?
        .unwrap();
    for cpu in 0..*NR_CPUS_POSSIBLE {
        cpu_ctxs.push(
            *plain::from_bytes(cpu_ctxs_vec[cpu].as_slice())
                .expect("cpu_ctx: short or misaligned buffer"),
        );
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
    #[allow(clippy::needless_range_loop)]
    fn read(skel: &BpfSkel, cpu_ctxs: &[bpf_intf::cpu_ctx]) -> Self {
        let nr_layers = skel.maps.rodata_data.as_ref().unwrap().nr_layers as usize;
        let nr_llcs = skel.maps.rodata_data.as_ref().unwrap().nr_llcs as usize;
        let mut gstats = vec![0u64; NR_GSTATS];
        let mut lstats = vec![vec![0u64; NR_LSTATS]; nr_layers];
        let mut llc_lstats = vec![vec![vec![0u64; NR_LLC_LSTATS]; nr_llcs]; nr_layers];

        for cpu in 0..*NR_CPUS_POSSIBLE {
            for (stat, value) in gstats.iter_mut().enumerate() {
                *value += cpu_ctxs[cpu].gstats[stat];
            }
            for (layer, layer_stats) in lstats.iter_mut().enumerate() {
                for (stat, value) in layer_stats.iter_mut().enumerate() {
                    *value += cpu_ctxs[cpu].lstats[layer][stat];
                }
            }
        }

        let mut lstats_sums = vec![0u64; NR_LSTATS];
        for layer_stats in lstats.iter() {
            for (stat, value) in lstats_sums.iter_mut().enumerate() {
                *value += layer_stats[stat];
            }
        }

        for llc_id in 0..nr_llcs {
            // XXX - This would be a lot easier if llc_ctx were in
            // the bss. Unfortunately, kernel < v6.12 crashes and
            // kernel >= v6.12 fails verification after such
            // conversion due to seemingly verifier bugs. Convert to
            // bss maps later.
            let v = skel
                .maps
                .llc_data
                .lookup(&(llc_id as u32).to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .unwrap()
                .unwrap();
            let llcc: &bpf_intf::llc_ctx =
                plain::from_bytes(v.as_slice()).expect("llc_ctx: short or misaligned buffer");

            for (layer_id, layer_llc_stats) in llc_lstats.iter_mut().enumerate() {
                for (stat_id, stat_value) in layer_llc_stats[llc_id].iter_mut().enumerate() {
                    *stat_value = llcc.lstats[layer_id][stat_id];
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

impl<'b> Sub<&'b BpfStats> for &BpfStats {
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
    topo: Arc<Topology>,
    nr_layers: usize,
    nr_layer_tasks: Vec<usize>,
    layer_nr_node_pinned_tasks: Vec<Vec<u64>>,

    total_util: f64, // Running AVG of sum of layer_utils
    layer_utils: Vec<Vec<f64>>,
    layer_node_pinned_utils: Vec<Vec<f64>>,
    prev_layer_node_pinned_usages: Vec<Vec<u64>>,
    layer_node_utils: Vec<Vec<f64>>,
    prev_layer_node_usages: Vec<Vec<u64>>,
    layer_node_duty_sums: Vec<Vec<f64>>, // Per-node per-layer duty in CPU units (EWMA)
    prev_layer_node_duty_raw: Vec<Vec<u64>>, // Raw accumulated layer_duty_sum values

    layer_membws: Vec<Vec<f64>>, // Estimated memory bandsidth consumption
    prev_layer_membw_agg: Vec<Vec<u64>>, // Estimated aggregate membw consumption

    cpu_busy: f64, // Read from /proc, maybe higher than total_util
    prev_total_cpu: fb_procfs::CpuStat,
    prev_pmu_resctrl_membw: (u64, u64), // (PMU-reported membw, resctrl-reported membw)

    util_compensation: bool,
    layer_utils_compensated: Vec<Vec<f64>>, // EWMA of per-CPU-scaled layer utils
    prev_cpu_layer_usages: Vec<u64>,        // Per-CPU per-layer usages for computing deltas
    prev_per_cpu_stats: BTreeMap<u32, fb_procfs::CpuStat>,

    system_cpu_util_ewma: f64,       // 10s EWMA of system CPU utilization
    layer_dsq_insert_ewma: Vec<f64>, // 10s EWMA of per-layer DSQ insertion ratio

    bpf_stats: BpfStats,
    prev_bpf_stats: BpfStats,

    processing_dur: Duration,
    prev_processing_dur: Duration,

    layer_slice_us: Vec<u64>,

    gpu_tasks_affinitized: u64,
    gpu_task_affinitization_ms: u64,
}

impl Stats {
    #[allow(clippy::needless_range_loop)]
    fn read_layer_membw_agg(cpu_ctxs: &[bpf_intf::cpu_ctx], nr_layers: usize) -> Vec<Vec<u64>> {
        let mut layer_membw_agg = vec![vec![0u64; NR_LAYER_USAGES]; nr_layers];

        for cpu in 0..*NR_CPUS_POSSIBLE {
            for (layer, layer_membw) in layer_membw_agg.iter_mut().enumerate() {
                for (usage, value) in layer_membw.iter_mut().enumerate() {
                    *value += cpu_ctxs[cpu].layer_membw_agg[layer][usage];
                }
            }
        }

        layer_membw_agg
    }

    #[allow(clippy::needless_range_loop)]
    fn read_layer_node_pinned_usages(
        cpu_ctxs: &[bpf_intf::cpu_ctx],
        topo: &Topology,
        nr_layers: usize,
        nr_nodes: usize,
    ) -> Vec<Vec<u64>> {
        let mut usages = vec![vec![0u64; nr_nodes]; nr_layers];

        for cpu in 0..*NR_CPUS_POSSIBLE {
            let node = topo.all_cpus.get(&cpu).map_or(0, |c| c.node_id);
            for (layer, layer_usages) in usages.iter_mut().enumerate().take(nr_layers) {
                layer_usages[node] += cpu_ctxs[cpu].node_pinned_usage[layer];
            }
        }

        usages
    }

    #[allow(clippy::needless_range_loop)]
    fn read_layer_node_usages(
        cpu_ctxs: &[bpf_intf::cpu_ctx],
        topo: &Topology,
        nr_layers: usize,
        nr_nodes: usize,
    ) -> Vec<Vec<u64>> {
        let mut usages = vec![vec![0u64; nr_nodes]; nr_layers];

        for cpu in 0..*NR_CPUS_POSSIBLE {
            let node = topo.all_cpus.get(&cpu).map_or(0, |c| c.node_id);
            for (layer, layer_usages) in usages.iter_mut().enumerate().take(nr_layers) {
                for usage in 0..=LAYER_USAGE_SUM_UPTO {
                    layer_usages[node] += cpu_ctxs[cpu].layer_usages[layer][usage];
                }
            }
        }

        usages
    }

    #[allow(clippy::needless_range_loop)]
    fn read_layer_node_duty_raw(
        cpu_ctxs: &[bpf_intf::cpu_ctx],
        topo: &Topology,
        nr_layers: usize,
        nr_nodes: usize,
    ) -> Vec<Vec<u64>> {
        let mut sums = vec![vec![0u64; nr_nodes]; nr_layers];

        for cpu in 0..*NR_CPUS_POSSIBLE {
            let node = topo.all_cpus.get(&cpu).map_or(0, |c| c.node_id);
            for (layer, layer_sums) in sums.iter_mut().enumerate().take(nr_layers) {
                layer_sums[node] += cpu_ctxs[cpu].layer_duty_sum[layer];
            }
        }

        sums
    }

    #[allow(clippy::needless_range_loop)]
    fn read_per_cpu_layer_usages(cpu_ctxs: &[bpf_intf::cpu_ctx], nr_layers: usize) -> Vec<u64> {
        let stride = nr_layers * NR_LAYER_USAGES;
        let mut flat = vec![0u64; *NR_CPUS_POSSIBLE * stride];

        for cpu in 0..*NR_CPUS_POSSIBLE {
            let base = cpu * stride;
            for layer in 0..nr_layers {
                for usage in 0..NR_LAYER_USAGES {
                    flat[base + layer * NR_LAYER_USAGES + usage] =
                        cpu_ctxs[cpu].layer_usages[layer][usage];
                }
            }
        }

        flat
    }

    /// Use the membw reported by resctrl to normalize the values reported by hw counters.
    /// We have the following problem:
    /// 1) We want per-task memory bandwidth reporting. We cannot do this with resctrl, much
    ///    less transparently, since we would require different RMID for each task.
    /// 2) We want to directly use perf counters for tracking per-task memory bandwidth, but
    ///    we can't: Non-resctrl counters do not measure the right thing (e.g., they only measure
    ///    proxies like load operations),
    /// 3) Resctrl counters are not accessible directly so we cannot read them from the BPF side.
    ///
    /// Approximate per-task memory bandwidth using perf counters to measure _relative_ memory
    /// bandwidth usage.
    fn resctrl_read_total_membw() -> Result<u64> {
        let mut total_membw = 0u64;
        for entry in WalkDir::new("/sys/fs/resctrl/mon_data")
            .min_depth(1)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|x| x.path().is_dir())
        {
            let mut path = entry.path().to_path_buf();
            path.push("mbm_total_bytes");
            total_membw += fs::read_to_string(path)?.trim().parse::<u64>()?;
        }

        Ok(total_membw)
    }

    fn new(
        skel: &mut BpfSkel,
        proc_reader: &fb_procfs::ProcReader,
        topo: Arc<Topology>,
        gpu_task_affinitizer: &GpuTaskAffinitizer,
        util_compensation: bool,
    ) -> Result<Self> {
        let nr_layers = skel.maps.rodata_data.as_ref().unwrap().nr_layers as usize;
        let nr_nodes = topo.nodes.len();
        let cpu_ctxs = read_cpu_ctxs(skel)?;
        let bpf_stats = BpfStats::read(skel, &cpu_ctxs);
        let pmu_membw = Self::read_layer_membw_agg(&cpu_ctxs, nr_layers);

        Ok(Self {
            at: Instant::now(),
            elapsed: Default::default(),

            topo: topo.clone(),
            nr_layers,
            nr_layer_tasks: vec![0; nr_layers],
            layer_nr_node_pinned_tasks: vec![vec![0; nr_nodes]; nr_layers],

            total_util: 0.0,
            layer_utils: vec![vec![0.0; NR_LAYER_USAGES]; nr_layers],
            layer_node_pinned_utils: vec![vec![0.0; nr_nodes]; nr_layers],
            prev_layer_node_pinned_usages: Self::read_layer_node_pinned_usages(
                &cpu_ctxs, &topo, nr_layers, nr_nodes,
            ),
            layer_node_utils: vec![vec![0.0; nr_nodes]; nr_layers],
            prev_layer_node_usages: Self::read_layer_node_usages(
                &cpu_ctxs, &topo, nr_layers, nr_nodes,
            ),
            layer_node_duty_sums: vec![vec![0.0; nr_nodes]; nr_layers],
            prev_layer_node_duty_raw: Self::read_layer_node_duty_raw(
                &cpu_ctxs, &topo, nr_layers, nr_nodes,
            ),
            layer_membws: vec![vec![0.0; NR_LAYER_USAGES]; nr_layers],
            // This is not normalized because we don't have enough history to do so.
            // It should not matter too much, since the value is dropped on the first
            // iteration.
            prev_layer_membw_agg: pmu_membw,
            prev_pmu_resctrl_membw: (0, 0),

            cpu_busy: 0.0,
            prev_total_cpu: read_total_cpu(proc_reader)?,
            util_compensation,
            layer_utils_compensated: vec![vec![0.0; NR_LAYER_USAGES]; nr_layers],
            prev_cpu_layer_usages: Self::read_per_cpu_layer_usages(&cpu_ctxs, nr_layers),
            prev_per_cpu_stats: BTreeMap::new(),
            system_cpu_util_ewma: 0.0,
            layer_dsq_insert_ewma: vec![0.0; nr_layers],

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

        let layers = &skel.maps.bss_data.as_ref().unwrap().layers;
        let nr_layer_tasks: Vec<usize> = layers
            .iter()
            .take(self.nr_layers)
            .map(|layer| layer.nr_tasks as usize)
            .collect();
        let layer_nr_node_pinned_tasks: Vec<Vec<u64>> = layers
            .iter()
            .take(self.nr_layers)
            .map(|layer| {
                layer.node[..self.topo.nodes.len()]
                    .iter()
                    .map(|n| n.nr_pinned_tasks)
                    .collect()
            })
            .collect();
        let layer_slice_us: Vec<u64> = layers
            .iter()
            .take(self.nr_layers)
            .map(|layer| layer.slice_ns / 1000_u64)
            .collect();

        let cur_layer_node_pinned_usages = Self::read_layer_node_pinned_usages(
            &cpu_ctxs,
            &self.topo,
            self.nr_layers,
            self.topo.nodes.len(),
        );
        let cur_layer_node_usages = Self::read_layer_node_usages(
            &cpu_ctxs,
            &self.topo,
            self.nr_layers,
            self.topo.nodes.len(),
        );
        let cur_layer_node_duty_raw = Self::read_layer_node_duty_raw(
            &cpu_ctxs,
            &self.topo,
            self.nr_layers,
            self.topo.nodes.len(),
        );
        let cur_layer_membw_agg = Self::read_layer_membw_agg(&cpu_ctxs, self.nr_layers);

        // Memory BW normalization. It requires finding the delta according to perf, the delta
        // according to resctl, and finding the factor between them. This also helps in
        // determining whether this delta is stable.
        //
        // We scale only the raw PMC delta - the part of the counter incremented between two
        // periods. This is because the scaling factor is only valid for that time period.
        // Non-scaled samples are not comparable, while scaled ones are.
        let (pmu_prev, resctrl_prev) = self.prev_pmu_resctrl_membw;
        let pmu_cur: u64 = cur_layer_membw_agg
            .iter()
            .map(|membw_agg| membw_agg[LAYER_USAGE_OPEN] + membw_agg[LAYER_USAGE_OWNED])
            .sum();
        let resctrl_cur = Self::resctrl_read_total_membw()?;
        let factor = (resctrl_cur - resctrl_prev) as f64 / (pmu_cur - pmu_prev) as f64;

        // Computes the runtime deltas and converts them from ns to s.
        let compute_diff = |cur_agg: &Vec<Vec<u64>>, prev_agg: &Vec<Vec<u64>>| {
            cur_agg
                .iter()
                .zip(prev_agg.iter())
                .map(|(cur, prev)| {
                    cur.iter()
                        .zip(prev.iter())
                        .map(|(c, p)| (c - p) as f64 / 1_000_000_000.0 / elapsed_f64)
                        .collect()
                })
                .collect()
        };

        // Computes the total memory traffic done since last computation and normalizes to GBs.
        // We derive the rate of consumption elsewhere.
        let compute_mem_diff = |cur_agg: &Vec<Vec<u64>>, prev_agg: &Vec<Vec<u64>>| {
            cur_agg
                .iter()
                .zip(prev_agg.iter())
                .map(|(cur, prev)| {
                    cur.iter()
                        .zip(prev.iter())
                        .map(|(c, p)| (*c as i64 - *p as i64) as f64 / 1024_f64.powf(3.0))
                        .collect()
                })
                .collect()
        };

        // Scale the raw value delta by the resctrl/pmc computed factor.
        let cur_layer_membw: Vec<Vec<f64>> =
            compute_mem_diff(&cur_layer_membw_agg, &self.prev_layer_membw_agg);

        let cur_layer_membw: Vec<Vec<f64>> = cur_layer_membw
            .iter()
            .map(|x| x.iter().map(|x| *x * factor).collect())
            .collect();

        let metric_decay =
            |cur_metric: Vec<Vec<f64>>, prev_metric: &Vec<Vec<f64>>, decay_rate: f64| {
                cur_metric
                    .iter()
                    .zip(prev_metric.iter())
                    .map(|(cur, prev)| {
                        cur.iter()
                            .zip(prev.iter())
                            .map(|(c, p)| {
                                let decay = decay_rate.powf(elapsed_f64);
                                p * decay + c * (1.0 - decay)
                            })
                            .collect()
                    })
                    .collect()
            };

        let cur_node_pinned_utils: Vec<Vec<f64>> = compute_diff(
            &cur_layer_node_pinned_usages,
            &self.prev_layer_node_pinned_usages,
        );
        let layer_node_pinned_utils: Vec<Vec<f64>> = metric_decay(
            cur_node_pinned_utils,
            &self.layer_node_pinned_utils,
            *USAGE_DECAY,
        );
        let cur_node_utils: Vec<Vec<f64>> =
            compute_diff(&cur_layer_node_usages, &self.prev_layer_node_usages);
        let layer_node_utils: Vec<Vec<f64>> =
            metric_decay(cur_node_utils, &self.layer_node_utils, *USAGE_DECAY);
        let cur_node_duty: Vec<Vec<f64>> =
            compute_diff(&cur_layer_node_duty_raw, &self.prev_layer_node_duty_raw);
        let layer_node_duty_sums: Vec<Vec<f64>> =
            metric_decay(cur_node_duty, &self.layer_node_duty_sums, *USAGE_DECAY);

        let layer_membws: Vec<Vec<f64>> = metric_decay(cur_layer_membw, &self.layer_membws, 0.0);

        let proc_stat = proc_reader
            .read_stat()
            .context("Failed to read /proc/stat")?;
        let cur_total_cpu = proc_stat
            .total_cpu
            .ok_or_else(|| anyhow!("Could not read total cpu stat in proc"))?;
        let cpu_busy = calc_util(&cur_total_cpu, &self.prev_total_cpu)?;

        // Calculate system CPU utilization EWMA (10 second window)
        const SYS_CPU_UTIL_EWMA_SECS: f64 = 10.0;
        let elapsed_f64 = elapsed.as_secs_f64();
        let alpha = elapsed_f64 / SYS_CPU_UTIL_EWMA_SECS.max(elapsed_f64);
        let system_cpu_util_ewma = alpha * cpu_busy + (1.0 - alpha) * self.system_cpu_util_ewma;

        // Per-CPU scale factors: s[c] = Δt / (Δt - irq - softirq - stolen).
        // When compensation is off, all scales stay 1.0.
        let cur_per_cpu_stats = proc_stat.cpus_map.unwrap_or_default();
        let mut cpu_scales = vec![1.0f64; *NR_CPUS_POSSIBLE];
        if self.util_compensation {
            for (&cpu_id, cur_cpu_stat) in &cur_per_cpu_stats {
                let cpu = cpu_id as usize;
                if let Some(prev_cpu_stat) = self.prev_per_cpu_stats.get(&cpu_id) {
                    if let (
                        fb_procfs::CpuStat {
                            user_usec: Some(cu),
                            nice_usec: Some(cn),
                            system_usec: Some(cs),
                            idle_usec: Some(ci),
                            iowait_usec: Some(cw),
                            irq_usec: Some(cq),
                            softirq_usec: Some(cf),
                            stolen_usec: Some(ct),
                            ..
                        },
                        fb_procfs::CpuStat {
                            user_usec: Some(pu),
                            nice_usec: Some(pn),
                            system_usec: Some(ps),
                            idle_usec: Some(pi),
                            iowait_usec: Some(pw),
                            irq_usec: Some(pq),
                            softirq_usec: Some(pf),
                            stolen_usec: Some(pt),
                            ..
                        },
                    ) = (cur_cpu_stat, prev_cpu_stat)
                    {
                        let delta_total = cu.saturating_sub(*pu)
                            + cn.saturating_sub(*pn)
                            + cs.saturating_sub(*ps)
                            + ci.saturating_sub(*pi)
                            + cw.saturating_sub(*pw)
                            + cq.saturating_sub(*pq)
                            + cf.saturating_sub(*pf)
                            + ct.saturating_sub(*pt);
                        let overhead = cq.saturating_sub(*pq)
                            + cf.saturating_sub(*pf)
                            + ct.saturating_sub(*pt);
                        let available = delta_total.saturating_sub(overhead);
                        cpu_scales[cpu] = if available > 0 {
                            (delta_total as f64 / available as f64).clamp(1.0, 20.0)
                        } else {
                            1.0
                        };
                    }
                }
            }
        }

        // Single pass over all CPUs: build both raw and compensated layer
        // util streams. When compensation is off, all scales are 1.0 so
        // comp == raw naturally.
        let cur_cpu_layer_usages = Self::read_per_cpu_layer_usages(&cpu_ctxs, self.nr_layers);
        let stride = self.nr_layers * NR_LAYER_USAGES;
        let mut raw_sums = vec![vec![0.0f64; NR_LAYER_USAGES]; self.nr_layers];
        let mut scaled_sums = vec![vec![0.0f64; NR_LAYER_USAGES]; self.nr_layers];
        #[allow(clippy::needless_range_loop)]
        for cpu in 0..*NR_CPUS_POSSIBLE {
            let scale = cpu_scales[cpu];
            let base = cpu * stride;
            for layer in 0..self.nr_layers {
                for usage in 0..NR_LAYER_USAGES {
                    let idx = base + layer * NR_LAYER_USAGES + usage;
                    let delta =
                        cur_cpu_layer_usages[idx].saturating_sub(self.prev_cpu_layer_usages[idx]);
                    if delta > 0 {
                        let delta_f = delta as f64;
                        raw_sums[layer][usage] += delta_f;
                        scaled_sums[layer][usage] += delta_f * scale;
                    }
                }
            }
        }
        let normalize = |sums: Vec<Vec<f64>>| -> Vec<Vec<f64>> {
            sums.into_iter()
                .map(|layer_sums| {
                    layer_sums
                        .into_iter()
                        .map(|s| s / 1_000_000_000.0 / elapsed_f64)
                        .collect()
                })
                .collect()
        };
        let layer_utils: Vec<Vec<f64>> =
            metric_decay(normalize(raw_sums), &self.layer_utils, *USAGE_DECAY);
        let layer_utils_compensated: Vec<Vec<f64>> = metric_decay(
            normalize(scaled_sums),
            &self.layer_utils_compensated,
            *USAGE_DECAY,
        );

        let cur_bpf_stats = BpfStats::read(skel, &cpu_ctxs);
        let bpf_stats = &cur_bpf_stats - &self.prev_bpf_stats;

        // Calculate per-layer DSQ insertion EWMA (10 second window)
        const DSQ_INSERT_EWMA_SECS: f64 = 10.0;
        let dsq_alpha = elapsed_f64 / DSQ_INSERT_EWMA_SECS.max(elapsed_f64);
        let layer_dsq_insert_ewma: Vec<f64> = (0..self.nr_layers)
            .map(|layer_id| {
                let sel_local = bpf_stats.lstats[layer_id]
                    [bpf_intf::layer_stat_id_LSTAT_SEL_LOCAL as usize]
                    as f64;
                let enq_local = bpf_stats.lstats[layer_id]
                    [bpf_intf::layer_stat_id_LSTAT_ENQ_LOCAL as usize]
                    as f64;
                let enq_dsq = bpf_stats.lstats[layer_id]
                    [bpf_intf::layer_stat_id_LSTAT_ENQ_DSQ as usize]
                    as f64;
                let total_dispatches = sel_local + enq_local + enq_dsq;

                let cur_ratio = if total_dispatches > 0.0 {
                    enq_dsq / total_dispatches
                } else {
                    0.0
                };

                dsq_alpha * cur_ratio + (1.0 - dsq_alpha) * self.layer_dsq_insert_ewma[layer_id]
            })
            .collect();

        let processing_dur = cur_processing_dur
            .checked_sub(self.prev_processing_dur)
            .unwrap();

        *self = Self {
            at: now,
            elapsed,
            topo: self.topo.clone(),
            nr_layers: self.nr_layers,
            nr_layer_tasks,
            layer_nr_node_pinned_tasks,

            total_util: layer_utils
                .iter()
                .map(|x| x.iter().take(LAYER_USAGE_SUM_UPTO + 1).sum::<f64>())
                .sum(),
            layer_utils,
            layer_node_pinned_utils,
            prev_layer_node_pinned_usages: cur_layer_node_pinned_usages,
            layer_node_utils,
            prev_layer_node_usages: cur_layer_node_usages,
            layer_node_duty_sums,
            prev_layer_node_duty_raw: cur_layer_node_duty_raw,

            layer_membws,
            prev_layer_membw_agg: cur_layer_membw_agg,
            // Was updated during normalization.
            prev_pmu_resctrl_membw: (pmu_cur, resctrl_cur),

            cpu_busy,
            prev_total_cpu: cur_total_cpu,
            util_compensation: self.util_compensation,
            layer_utils_compensated,
            prev_cpu_layer_usages: cur_cpu_layer_usages,
            prev_per_cpu_stats: cur_per_cpu_stats,
            system_cpu_util_ewma,
            layer_dsq_insert_ewma,

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
    core_order: Vec<Vec<usize>>,

    assigned_llcs: Vec<Vec<usize>>,

    nr_cpus: usize,
    nr_llc_cpus: Vec<usize>,
    nr_node_cpus: Vec<usize>,
    cpus: Cpumask,
    allowed_cpus: Cpumask,

    /// Per-node count of CPUs allocated for pinned demand.
    nr_pinned_cpus: Vec<usize>,
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
                std::cmp::min(std::cmp::max(cpus_max_count, 1), max_cpus),
            ))
        }
        (None, None) => Ok((0, max_cpus)),
    }
}

impl Layer {
    fn new(spec: &LayerSpec, topo: &Topology, core_order: &Vec<Vec<usize>>) -> Result<Self> {
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

            assigned_llcs: vec![vec![]; topo.nodes.len()],

            nr_cpus: 0,
            nr_llc_cpus: vec![0; topo.all_llcs.len()],
            nr_node_cpus: vec![0; topo.nodes.len()],
            cpus: Cpumask::new(),
            allowed_cpus,

            nr_pinned_cpus: vec![0; topo.nodes.len()],
        })
    }
}
#[derive(Debug, Clone)]
struct NodeInfo {
    node_mask: nix::sched::CpuSet,
    _node_id: usize,
}

#[derive(Debug)]
struct GpuTaskAffinitizer {
    // This struct tracks information necessary to numa affinitize
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
                inner_offset <<= 1;
            }
        }
        anyhow::bail!("unable to get CPU from NVML bitmask");
    }

    fn node_to_cpuset(&self, node: &scx_utils::Node) -> Result<CpuSet> {
        let mut cpuset = CpuSet::new();
        for cpu_id in node.all_cpus.keys() {
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
                .get(dev)
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
                        debug!(
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

    cgroup_regexes: Option<HashMap<u32, Regex>>,

    nr_layer_cpus_ranges: Vec<(usize, usize)>,
    xnuma_mig_src: Vec<Vec<bool>>,
    growth_denied: Vec<Vec<bool>>,
    processing_dur: Duration,

    topo: Arc<Topology>,
    netdevs: BTreeMap<String, NetDev>,
    stats_server: StatsServer<StatsReq, StatsRes>,
    gpu_task_handler: GpuTaskAffinitizer,
}

const DUTY_CYCLE_SCALE: f64 = (1u64 << 20) as f64;
const XNUMA_RATE_DAMPEN: f64 = 0.5;

/// Result of xnuma water-fill computation for a single layer.
struct XnumaRates {
    /// rates[src][dst]: migration rate in duty-cycle-scaled units.
    rates: Vec<Vec<u64>>,
}

/// Determine per-node migration source state with two-threshold hysteresis.
///
/// Each (layer, node) independently decides if it's a migration source.
/// Open (is_mig_src=true) requires all three:
///   1. load/alloc > threshold.1 (significant load)
///   2. surplus/alloc > delta.1 (significant imbalance)
///   3. growth_denied (allocation can't solve it)
///
/// Close (is_mig_src=false) when any one:
///   1. load/alloc < threshold.0 (load dropped)
///   2. surplus/alloc < delta.0 (imbalance resolved)
///   3. !growth_denied (growth succeeded)
fn xnuma_check_active(
    duty_sums: &[f64],
    allocs: &[usize],
    threshold: (f64, f64),
    threshold_delta: (f64, f64),
    growth_denied: &[bool],
    currently_active: &[bool],
) -> Vec<bool> {
    let nr_nodes = duty_sums.len();
    let total_duty: f64 = duty_sums.iter().sum();
    let total_alloc: f64 = allocs.iter().map(|&a| a as f64).sum();
    let eq_ratio = if total_alloc > 0.0 {
        total_duty / total_alloc
    } else {
        0.0
    };

    let (thresh_lo, thresh_hi) = threshold;
    let (delta_lo, delta_hi) = threshold_delta;

    let mut result = vec![false; nr_nodes];
    for nid in 0..nr_nodes {
        let alloc = allocs[nid] as f64;
        if alloc <= 0.0 {
            if duty_sums[nid] > 0.0 && growth_denied[nid] {
                result[nid] = true;
            }
            continue;
        }

        let load_ratio = duty_sums[nid] / alloc;
        let surplus = duty_sums[nid] - eq_ratio * alloc;
        let surplus_ratio = surplus / alloc;

        let should_activate =
            load_ratio > thresh_hi && surplus_ratio > delta_hi && growth_denied[nid];
        let should_deactivate =
            load_ratio < thresh_lo || surplus_ratio < delta_lo || !growth_denied[nid];

        if should_activate {
            result[nid] = true;
        } else if should_deactivate {
            result[nid] = false;
        } else {
            result[nid] = currently_active[nid];
        }
    }
    result
}

/// Compute water-fill migration rates for a single layer.
///
/// Finds the equalization ratio (water line) across all nodes, then
/// computes per-(src, dst) migration rates proportional to each source's
/// surplus and each destination's share of total deficit.
fn xnuma_compute_rates(duty_sums: &[f64], allocs: &[usize]) -> XnumaRates {
    let nr_nodes = duty_sums.len();
    let total_duty: f64 = duty_sums.iter().sum();
    let total_alloc: f64 = allocs.iter().map(|&a| a as f64).sum();

    if total_alloc <= 0.0 {
        return XnumaRates {
            rates: vec![vec![0u64; nr_nodes]; nr_nodes],
        };
    }

    let eq_ratio = total_duty / total_alloc;

    let mut surpluses = vec![0.0f64; nr_nodes];
    let mut deficits = vec![0.0f64; nr_nodes];
    for nid in 0..nr_nodes {
        let expected = eq_ratio * allocs[nid] as f64;
        let delta = duty_sums[nid] - expected;
        if delta > 0.0 {
            surpluses[nid] = delta;
        } else {
            deficits[nid] = -delta;
        }
    }

    let total_deficit: f64 = deficits.iter().sum();

    let mut rates = vec![vec![0u64; nr_nodes]; nr_nodes];
    for src in 0..nr_nodes {
        for dst in 0..nr_nodes {
            if src == dst || total_deficit <= 0.0 || surpluses[src] <= 0.0 {
                continue;
            }
            // Dampen: transfer half the surplus per cycle so convergence
            // is gradual rather than a single-step overcorrection.
            let migration = surpluses[src] * deficits[dst] / total_deficit * XNUMA_RATE_DAMPEN;
            rates[src][dst] = (migration * DUTY_CYCLE_SCALE) as u64;
        }
    }

    XnumaRates { rates }
}

impl<'a> Scheduler<'a> {
    fn init_layers(
        skel: &mut OpenBpfSkel,
        specs: &[LayerSpec],
        topo: &Topology,
    ) -> Result<HashMap<u32, Regex>> {
        skel.maps.rodata_data.as_mut().unwrap().nr_layers = specs.len() as u32;
        let mut perf_set = false;

        let mut layer_iteration_order = (0..specs.len()).collect::<Vec<_>>();
        let mut layer_weights: Vec<usize> = vec![];
        let mut cgroup_regex_id = 0;
        let mut cgroup_regexes = HashMap::new();

        for (spec_i, spec) in specs.iter().enumerate() {
            let layer = &mut skel.maps.bss_data.as_mut().unwrap().layers[spec_i];

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
                        LayerMatch::CgroupRegex(regex_str) => {
                            if cgroup_regex_id >= bpf_intf::consts_MAX_CGROUP_REGEXES {
                                bail!(
                                    "Too many cgroup regex rules. Maximum allowed: {}",
                                    bpf_intf::consts_MAX_CGROUP_REGEXES
                                );
                            }

                            // CgroupRegex matching handled in userspace via cgroup watcher
                            mt.kind = bpf_intf::layer_match_kind_MATCH_CGROUP_REGEX as i32;
                            mt.cgroup_regex_id = cgroup_regex_id;

                            let regex = Regex::new(regex_str).with_context(|| {
                                format!("Invalid regex '{}' in layer '{}'", regex_str, spec.name)
                            })?;
                            cgroup_regexes.insert(cgroup_regex_id, regex);
                            cgroup_regex_id += 1;
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
                        LayerMatch::HintEquals(hint) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_HINT_EQUALS as i32;
                            mt.hint = *hint;
                        }
                        LayerMatch::SystemCpuUtilBelow(threshold) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_SYSTEM_CPU_UTIL_BELOW as i32;
                            mt.system_cpu_util_below = (*threshold * 10000.0) as u64;
                        }
                        LayerMatch::DsqInsertBelow(threshold) => {
                            mt.kind = bpf_intf::layer_match_kind_MATCH_DSQ_INSERT_BELOW as i32;
                            mt.dsq_insert_below = (*threshold * 10000.0) as u64;
                        }
                        LayerMatch::NumaNode(node_id) => {
                            if *node_id as usize >= topo.nodes.len() {
                                bail!(
                                    "Spec {:?} has invalid NUMA node ID {} (available nodes: 0-{})",
                                    spec.name,
                                    node_id,
                                    topo.nodes.len() - 1
                                );
                            }
                            mt.kind = bpf_intf::layer_match_kind_MATCH_NUMA_NODE as i32;
                            mt.numa_node_id = *node_id;
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
                    skip_remote_node,
                    prev_over_idle_core,
                    growth_algo,
                    slice_us,
                    fifo,
                    weight,
                    disallow_open_after_us,
                    disallow_preempt_after_us,
                    xllc_mig_min_us,
                    placement,
                    member_expire_ms,
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
                layer.skip_remote_node.write(*skip_remote_node);
                layer.prev_over_idle_core.write(*prev_over_idle_core);
                layer.growth_algo = growth_algo.as_bpf_enum();
                layer.weight = *weight;
                layer.member_expire_ms = *member_expire_ms;
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

                let task_place = |place: u32| crate::types::layer_task_place(place);
                layer.task_place = match placement {
                    LayerPlacement::Standard => {
                        task_place(bpf_intf::layer_task_place_PLACEMENT_STD)
                    }
                    LayerPlacement::Sticky => {
                        task_place(bpf_intf::layer_task_place_PLACEMENT_STICK)
                    }
                    LayerPlacement::Floating => {
                        task_place(bpf_intf::layer_task_place_PLACEMENT_FLOAT)
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
                    Self::update_cpumask(mask, &mut layer.cpuset);
                    layer.has_cpuset.write(true);
                }
                None => {
                    for i in 0..layer.cpuset.len() {
                        layer.cpuset[i] = u8::MAX;
                    }
                    layer.has_cpuset.write(false);
                }
            };

            perf_set |= layer.perf > 0;
        }

        layer_iteration_order.sort_by(|i, j| layer_weights[*i].cmp(&layer_weights[*j]));
        for (idx, layer_idx) in layer_iteration_order.iter().enumerate() {
            skel.maps
                .rodata_data
                .as_mut()
                .unwrap()
                .layer_iteration_order[idx] = *layer_idx as u32;
        }

        if perf_set && !compat::ksym_exists("scx_bpf_cpuperf_set")? {
            warn!("cpufreq support not available, ignoring perf configurations");
        }

        Ok(cgroup_regexes)
    }

    fn init_nodes(skel: &mut OpenBpfSkel, _opts: &Opts, topo: &Topology) {
        skel.maps.rodata_data.as_mut().unwrap().nr_nodes = topo.nodes.len() as u32;
        skel.maps.rodata_data.as_mut().unwrap().nr_llcs = 0;

        for (&node_id, node) in &topo.nodes {
            debug!("configuring node {}, LLCs {:?}", node_id, node.llcs.len());
            skel.maps.rodata_data.as_mut().unwrap().nr_llcs += node.llcs.len() as u32;
            let raw_numa_slice = node.span.as_raw_slice();
            let node_cpumask_slice =
                &mut skel.maps.rodata_data.as_mut().unwrap().numa_cpumasks[node_id];
            let (left, _) = node_cpumask_slice.split_at_mut(raw_numa_slice.len());
            left.clone_from_slice(raw_numa_slice);
            debug!(
                "node {} mask: {:?}",
                node_id,
                skel.maps.rodata_data.as_ref().unwrap().numa_cpumasks[node_id]
            );

            for llc in node.llcs.values() {
                debug!("configuring llc {:?} for node {:?}", llc.id, node_id);
                skel.maps.rodata_data.as_mut().unwrap().llc_numa_id_map[llc.id] = node_id as u32;
            }
        }

        for cpu in topo.all_cpus.values() {
            skel.maps.rodata_data.as_mut().unwrap().cpu_llc_id_map[cpu.id] = cpu.llc_id as u32;
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
            .iter()
            .map(|cpu_ctx| unsafe { plain::as_bytes(cpu_ctx) }.to_vec())
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
            cpu_ctxs.push(
                *plain::from_bytes(cpu_ctxs_vec[cpu].as_slice())
                    .expect("cpu_ctx: short or misaligned buffer"),
            );

            let topo_cpu = topo.all_cpus.get(&cpu).unwrap();
            let is_big = topo_cpu.core_type == CoreType::Big { turbo: true };
            cpu_ctxs[cpu].cpu = cpu as i32;
            cpu_ctxs[cpu].layer_id = MAX_LAYERS as u32;
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

            // Shuffle so that different LLCs follow different orders. See
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
            let key = (llc_id as u32).to_ne_bytes();
            let v = skel
                .maps
                .llc_data
                .lookup(&key, libbpf_rs::MapFlags::ANY)
                .unwrap()
                .unwrap();
            let mut llcc: bpf_intf::llc_ctx =
                *plain::from_bytes(v.as_slice()).expect("llc_ctx: short or misaligned buffer");

            let pmap = &mut llcc.prox_map;
            for (i, &llc_id) in order.iter().enumerate() {
                pmap.llcs[i] = llc_id as u16;
            }
            pmap.node_end = node_end as u32;
            pmap.sys_end = sys_end as u32;

            skel.maps.llc_data.update(
                &key,
                unsafe { plain::as_bytes(&llcc) },
                libbpf_rs::MapFlags::ANY,
            )?
        }

        Ok(())
    }

    fn init_node_prox_map(skel: &mut BpfSkel, topo: &Topology) -> Result<()> {
        for (&node_id, node) in &topo.nodes {
            let mut order: Vec<(usize, usize)> = node
                .distance
                .iter()
                .enumerate()
                .filter(|&(nid, _)| nid != node_id)
                .map(|(nid, &dist)| (nid, dist))
                .collect();
            order.sort_by_key(|&(_, dist)| dist);

            let key = (node_id as u32).to_ne_bytes();

            // The map entry may not exist yet — create a zeroed one.
            let v = skel.maps.node_data.lookup(&key, libbpf_rs::MapFlags::ANY);
            let mut nodec: bpf_intf::node_ctx = match v {
                Ok(Some(v)) => {
                    *plain::from_bytes(v.as_slice()).expect("node_ctx: short or misaligned buffer")
                }
                _ => unsafe { MaybeUninit::zeroed().assume_init() },
            };

            let pmap = &mut nodec.prox_map;
            for (i, &(nid, _)) in order.iter().enumerate() {
                pmap.nodes[i] = nid as u16;
            }
            pmap.sys_end = order.len() as u32;

            debug!(
                "NODE[{}] prox_map[{}]: {:?}",
                node_id,
                pmap.sys_end,
                &order.iter().map(|(n, d)| (*n, *d)).collect::<Vec<_>>()
            );

            skel.maps.node_data.update(
                &key,
                unsafe { plain::as_bytes(&nodec) },
                libbpf_rs::MapFlags::ANY,
            )?;
        }
        Ok(())
    }

    fn init_node_ctx(skel: &mut BpfSkel, topo: &Topology, nr_layers: usize) -> Result<()> {
        let all_layers: Vec<u32> = (0..nr_layers as u32).collect();
        let node_empty_layers: Vec<Vec<u32>> =
            (0..topo.nodes.len()).map(|_| all_layers.clone()).collect();
        Self::refresh_node_ctx(skel, topo, &node_empty_layers, true);
        Ok(())
    }

    fn init(
        opts: &'a Opts,
        layer_specs: &[LayerSpec],
        open_object: &'a mut MaybeUninit<OpenObject>,
        hint_to_layer_map: &HashMap<u64, HintLayerInfo>,
        membw_tracking: bool,
    ) -> Result<Self> {
        let nr_layers = layer_specs.len();
        let mut disable_topology = opts.disable_topology.unwrap_or(false);

        let topo = Arc::new(if disable_topology {
            Topology::with_flattened_llc_node()?
        } else if opts.topology.virt_llc.is_some() {
            Topology::with_args(&opts.topology)?
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
            let devs = read_netdevs()?;
            let total_irqs: usize = devs.values().map(|d| d.irqs.len()).sum();
            let breakdown = devs
                .iter()
                .map(|(iface, d)| format!("{iface}={}", d.irqs.len()))
                .collect::<Vec<_>>()
                .join(", ");
            info!(
                "Netdev IRQ balancing enabled: overriding {total_irqs} IRQ{} \
                 across {} interface{} [{breakdown}]",
                if total_irqs == 1 { "" } else { "s" },
                devs.len(),
                if devs.len() == 1 { "" } else { "s" },
            );
            devs
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

        let cpu_pool = CpuPool::new(topo.clone(), opts.allow_partial_core)?;

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

        // Validate that spec node/LLC references exist in the topology.
        for spec in layer_specs.iter() {
            let mut seen = BTreeSet::new();
            for &node_id in spec.nodes().iter() {
                if !topo.nodes.contains_key(&node_id) {
                    bail!(
                        "layer {:?}: nodes references node {} which does not \
                         exist in the topology (available: {:?})",
                        spec.name,
                        node_id,
                        topo.nodes.keys().collect::<Vec<_>>()
                    );
                }
                if !seen.insert(node_id) {
                    bail!(
                        "layer {:?}: nodes contains duplicate node {}",
                        spec.name,
                        node_id
                    );
                }
            }

            seen.clear();
            for &llc_id in spec.llcs().iter() {
                if !topo.all_llcs.contains_key(&llc_id) {
                    bail!(
                        "layer {:?}: llcs references LLC {} which does not \
                         exist in the topology (available: {:?})",
                        spec.name,
                        llc_id,
                        topo.all_llcs.keys().collect::<Vec<_>>()
                    );
                }
                if !seen.insert(llc_id) {
                    bail!(
                        "layer {:?}: llcs contains duplicate LLC {}",
                        spec.name,
                        llc_id
                    );
                }
            }
        }

        for spec in layer_specs.iter() {
            let has_numa_node_match = spec
                .matches
                .iter()
                .flatten()
                .any(|m| matches!(m, LayerMatch::NumaNode(_)));
            let has_node_spread_algo = matches!(
                spec.kind.common().growth_algo,
                LayerGrowthAlgo::NodeSpread
                    | LayerGrowthAlgo::NodeSpreadReverse
                    | LayerGrowthAlgo::NodeSpreadRandom
            );
            if has_numa_node_match && has_node_spread_algo {
                bail!(
                    "layer {:?}: NumaNode matcher cannot be combined with {:?} \
                     growth algorithm. NodeSpread* allocates CPUs equally across \
                     ALL NUMA nodes, but NumaNode restricts tasks to one node's \
                     CPUs — CPUs on other nodes are wasted and utilization \
                     will never exceed 1/numa_nodes. Use a non-spread algorithm \
                     (e.g. Linear, Topo) instead.",
                    spec.name,
                    spec.kind.common().growth_algo
                );
            }
        }

        // Check kernel features
        init_libbpf_logging(None);
        let kfuncs_in_syscall = scx_bpf_compat::kfuncs_supported_in_syscall()?;
        if !kfuncs_in_syscall {
            warn!("Using slow path: kfuncs not supported in syscall programs (a8e03b6bbb2c ∉ ker)");
        }

        // Open the BPF prog first for verification.
        let debug_level = if opts.log_level.contains("trace") {
            2
        } else if opts.log_level.contains("debug") {
            1
        } else {
            0
        };
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(debug_level > 1);

        info!(
            "Running scx_layered (build ID: {})",
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, layered, open_opts)?;

        // No memory BW tracking by default
        skel.progs.scx_pmu_switch_tc.set_autoload(membw_tracking);
        skel.progs.scx_pmu_tick_tc.set_autoload(membw_tracking);

        let mut loaded_kprobes = HashSet::new();

        // enable autoloads for conditionally loaded things
        // immediately after creating skel (because this is always before loading)
        if opts.enable_gpu_support {
            // by default, enable open if gpu support is enabled.
            // open has been observed to be relatively cheap to kprobe.
            if opts.gpu_kprobe_level >= 1 {
                compat::cond_kprobe_load("nvidia_open", &skel.progs.kprobe_nvidia_open)?;
                loaded_kprobes.insert("nvidia_open");
            }
            // enable the rest progressively based upon how often they are called
            // for observed workloads
            if opts.gpu_kprobe_level >= 2 {
                compat::cond_kprobe_load("nvidia_mmap", &skel.progs.kprobe_nvidia_mmap)?;
                loaded_kprobes.insert("nvidia_mmap");
            }
            if opts.gpu_kprobe_level >= 3 {
                compat::cond_kprobe_load("nvidia_poll", &skel.progs.kprobe_nvidia_poll)?;
                loaded_kprobes.insert("nvidia_poll");
            }
        }

        let ext_sched_class_addr = get_kallsyms_addr("ext_sched_class");
        let idle_sched_class_addr = get_kallsyms_addr("idle_sched_class");

        let event = if membw_tracking {
            setup_membw_tracking(&mut skel)?
        } else {
            0
        };

        let rodata = skel.maps.rodata_data.as_mut().unwrap();

        if let (Ok(ext_addr), Ok(idle_addr)) = (ext_sched_class_addr, idle_sched_class_addr) {
            rodata.ext_sched_class_addr = ext_addr;
            rodata.idle_sched_class_addr = idle_addr;
        } else {
            warn!(
                "Unable to get sched_class addresses from /proc/kallsyms, disabling skip_preempt."
            );
        }

        rodata.slice_ns = scx_enums.SCX_SLICE_DFL;
        rodata.max_exec_ns = 20 * scx_enums.SCX_SLICE_DFL;

        // Initialize skel according to @opts.
        skel.struct_ops.layered_mut().exit_dump_len = opts.exit_dump_len;

        if !opts.disable_queued_wakeup {
            match *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP {
                0 => info!("Kernel does not support queued wakeup optimization"),
                v => skel.struct_ops.layered_mut().flags |= v,
            }
        }

        rodata.percpu_kthread_preempt = !opts.disable_percpu_kthread_preempt;
        rodata.percpu_kthread_preempt_all =
            !opts.disable_percpu_kthread_preempt && opts.percpu_kthread_preempt_all;
        rodata.debug = debug_level as u32;
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.max_exec_ns = if opts.max_exec_us > 0 {
            opts.max_exec_us * 1000
        } else {
            opts.slice_us * 1000 * 20
        };
        rodata.nr_cpu_ids = *NR_CPU_IDS as u32;
        rodata.nr_possible_cpus = *NR_CPUS_POSSIBLE as u32;
        rodata.smt_enabled = topo.smt_enabled;
        rodata.has_little_cores = topo.has_little_cores();
        rodata.antistall_sec = opts.antistall_sec;
        rodata.monitor_disable = opts.monitor_disable;
        rodata.lo_fb_wait_ns = opts.lo_fb_wait_us * 1000;
        rodata.lo_fb_share_ppk = ((opts.lo_fb_share * 1024.0) as u32).clamp(1, 1024);
        rodata.enable_antistall = !opts.disable_antistall;
        rodata.enable_match_debug = opts.enable_match_debug;
        rodata.enable_gpu_support = opts.enable_gpu_support;
        rodata.kfuncs_supported_in_syscall = kfuncs_in_syscall;

        for (cpu, sib) in topo.sibling_cpus().iter().enumerate() {
            rodata.__sibling_cpu[cpu] = *sib;
        }
        for cpu in topo.all_cpus.keys() {
            rodata.all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }

        rodata.nr_op_layers = layer_specs
            .iter()
            .filter(|spec| match &spec.kind {
                LayerKind::Open { .. } => spec.kind.common().preempt,
                _ => false,
            })
            .count() as u32;
        rodata.nr_on_layers = layer_specs
            .iter()
            .filter(|spec| match &spec.kind {
                LayerKind::Open { .. } => !spec.kind.common().preempt,
                _ => false,
            })
            .count() as u32;
        rodata.nr_gp_layers = layer_specs
            .iter()
            .filter(|spec| match &spec.kind {
                LayerKind::Grouped { .. } => spec.kind.common().preempt,
                _ => false,
            })
            .count() as u32;
        rodata.nr_gn_layers = layer_specs
            .iter()
            .filter(|spec| match &spec.kind {
                LayerKind::Grouped { .. } => !spec.kind.common().preempt,
                _ => false,
            })
            .count() as u32;
        rodata.nr_excl_layers = layer_specs
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

        rodata.min_open_layer_disallow_open_after_ns = match min_open {
            u64::MAX => *DFL_DISALLOW_OPEN_AFTER_US,
            v => v,
        };
        rodata.min_open_layer_disallow_preempt_after_ns = match min_preempt {
            u64::MAX => *DFL_DISALLOW_PREEMPT_AFTER_US,
            v => v,
        };

        // We set the pin path before loading the skeleton. This will ensure
        // libbpf creates and pins the map, or reuses the pinned map fd for us,
        // so that we can keep reusing the older map already pinned on scheduler
        // restarts.
        let layered_task_hint_map_path = &opts.task_hint_map;
        let hint_map = &mut skel.maps.scx_layered_task_hint_map;
        // Only set pin path if a path is provided.
        if !layered_task_hint_map_path.is_empty() {
            hint_map.set_pin_path(layered_task_hint_map_path).unwrap();
            rodata.task_hint_map_enabled = true;
        }

        if !opts.hi_fb_thread_name.is_empty() {
            let bpf_hi_fb_thread_name = &mut rodata.hi_fb_thread_name;
            copy_into_cstr(bpf_hi_fb_thread_name, opts.hi_fb_thread_name.as_str());
            rodata.enable_hi_fb_thread_name_match = true;
        }

        let cgroup_regexes = Self::init_layers(&mut skel, &layer_specs, &topo)?;
        skel.maps.rodata_data.as_mut().unwrap().nr_cgroup_regexes = cgroup_regexes.len() as u32;
        Self::init_nodes(&mut skel, opts, &topo);

        let mut skel = scx_ops_load!(skel, layered, uei)?;

        // Populate the mapping of hints to layer IDs for faster lookups
        if !hint_to_layer_map.is_empty() {
            for (k, v) in hint_to_layer_map.iter() {
                let key: u32 = *k as u32;

                // Create hint_layer_info struct
                let mut info_bytes = vec![0u8; std::mem::size_of::<bpf_intf::hint_layer_info>()];
                let info_ptr = info_bytes.as_mut_ptr() as *mut bpf_intf::hint_layer_info;
                unsafe {
                    (*info_ptr).layer_id = v.layer_id as u32;
                    (*info_ptr).system_cpu_util_below = match v.system_cpu_util_below {
                        Some(threshold) => (threshold * 10000.0) as u64,
                        None => u64::MAX, // disabled sentinel
                    };
                    (*info_ptr).dsq_insert_below = match v.dsq_insert_below {
                        Some(threshold) => (threshold * 10000.0) as u64,
                        None => u64::MAX, // disabled sentinel
                    };
                }

                skel.maps.hint_to_layer_id_map.update(
                    &key.to_ne_bytes(),
                    &info_bytes,
                    libbpf_rs::MapFlags::ANY,
                )?;
            }
        }

        if membw_tracking {
            create_perf_fds(&mut skel, event)?;
        }

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
        Self::init_node_prox_map(&mut skel, &topo)?;
        Self::init_node_ctx(&mut skel, &topo, nr_layers)?;

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
        if !layered_task_hint_map_path.is_empty() {
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

        // Turn on installed kprobes
        if opts.enable_gpu_support {
            if loaded_kprobes.contains("nvidia_open") {
                compat::cond_kprobe_attach("nvidia_open", &skel.progs.kprobe_nvidia_open)?;
            }
            if loaded_kprobes.contains("nvidia_mmap") {
                compat::cond_kprobe_attach("nvidia_mmap", &skel.progs.kprobe_nvidia_mmap)?;
            }
            if loaded_kprobes.contains("nvidia_poll") {
                compat::cond_kprobe_attach("nvidia_poll", &skel.progs.kprobe_nvidia_poll)?;
            }
        }

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

            sched_stats: Stats::new(
                &mut skel,
                &proc_reader,
                topo.clone(),
                &gpu_task_handler,
                opts.util_compensation,
            )?,

            cgroup_regexes: Some(cgroup_regexes),
            nr_layer_cpus_ranges: vec![(0, 0); nr_layers],
            xnuma_mig_src: vec![vec![false; topo.nodes.len()]; nr_layers],
            growth_denied: vec![vec![false; topo.nodes.len()]; nr_layers],
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
        for (node_id, &nr_node_cpus) in layer.nr_node_cpus.iter().enumerate() {
            bpf_layer.node[node_id].nr_cpus = nr_node_cpus as u32;
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
                .find(|n| n.id == netdev.node())
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
            debug!(
                "{iface}: applied affinity override to {} IRQ{}",
                netdev.irqs.len(),
                if netdev.irqs.len() == 1 { "" } else { "s" },
            );
        }

        Ok(())
    }

    fn clamp_target_by_membw(
        &self,
        layer: &Layer,
        membw_limit: f64,
        membw: f64,
        curtarget: u64,
    ) -> usize {
        let ncpu: u64 = layer.cpus.weight() as u64;
        let membw = (membw * 1024_f64.powf(3.0)).round() as u64;
        let membw_limit = (membw_limit * 1024_f64.powf(3.0)).round() as u64;
        let last_membw_percpu = if ncpu > 0 { membw / ncpu } else { 0 };

        // Either there is no memory bandwidth limit set, or the counters
        // are not fully initialized yet. Just return the current target.
        if membw_limit == 0 || last_membw_percpu == 0 {
            return curtarget as usize;
        }

        (membw_limit / last_membw_percpu) as usize
    }

    /// Decompose per-layer CPU targets into per-node pinned demand and
    /// unpinned demand for unified_alloc(). Uses layer_node_pinned_utils
    /// to split each layer's target. All outputs are in alloc units.
    fn calc_raw_demands(&self, targets: &[(usize, usize)]) -> Vec<LayerDemand> {
        let au = self.cpu_pool.alloc_unit();
        let pinned_utils = &self.sched_stats.layer_node_pinned_utils;
        let nr_nodes = self.topo.nodes.len();

        targets
            .iter()
            .enumerate()
            .map(|(idx, &(target, _min))| {
                let layer = &self.layers[idx];
                let weight = layer.kind.common().weight as usize;

                // Open layers don't participate in allocation.
                if matches!(layer.kind, LayerKind::Open { .. }) {
                    return LayerDemand {
                        raw_pinned: vec![0; nr_nodes],
                        raw_unpinned: 0,
                        weight,
                        spread: false,
                    };
                }

                let spread = matches!(
                    layer.growth_algo,
                    LayerGrowthAlgo::NodeSpread
                        | LayerGrowthAlgo::NodeSpreadReverse
                        | LayerGrowthAlgo::NodeSpreadRandom
                        | LayerGrowthAlgo::RoundRobin
                );

                let util_high = match &layer.kind {
                    LayerKind::Confined { util_range, .. }
                    | LayerKind::Grouped { util_range, .. } => util_range.1,
                    _ => 1.0,
                };

                // Convert per-node pinned utilization to CPU demand.
                let mut raw_pinned = vec![0usize; nr_nodes];
                for n in 0..nr_nodes {
                    let pu = pinned_utils[idx][n];
                    if pu < 0.01 {
                        continue;
                    }
                    // Check this layer has allowed_cpus on this node.
                    let node_span = &self.topo.nodes[&n].span;
                    if layer.allowed_cpus.and(node_span).is_empty() {
                        continue;
                    }
                    let cpus = (pu / util_high).ceil() as usize;
                    // Round up to alloc units.
                    let units = cpus.div_ceil(au);
                    raw_pinned[n] = units;
                }

                // Unpinned = remainder of the target.
                let target_units = target.div_ceil(au);
                let pinned_units: usize = raw_pinned.iter().sum();
                let raw_unpinned = target_units.saturating_sub(pinned_units);

                LayerDemand {
                    raw_pinned,
                    raw_unpinned,
                    weight,
                    spread,
                }
            })
            .collect()
    }

    /// Calculate how many CPUs each layer would like to have if there were
    /// no competition. When util_compensation is enabled, compensated
    /// utilization (scaled for irq/softirq/stolen overhead) is used
    /// instead of raw utilization. The CPU range is determined by
    /// applying the inverse of util_range and capping by cpus_range.
    /// If the current allocation is within the acceptable range, no
    /// change is made. Returns (target, min) pair for each layer.
    fn calc_target_nr_cpus(&self) -> Vec<(usize, usize)> {
        let nr_cpus = self.cpu_pool.topo.all_cpus.len();
        let utils = if self.sched_stats.util_compensation {
            &self.sched_stats.layer_utils_compensated
        } else {
            &self.sched_stats.layer_utils
        };
        let membws = &self.sched_stats.layer_membws;

        let mut records: Vec<(u64, u64, u64, usize, usize, usize)> = vec![];
        let mut targets: Vec<(usize, usize)> = vec![];

        for (idx, layer) in self.layers.iter().enumerate() {
            targets.push(match &layer.kind {
                LayerKind::Confined {
                    util_range,
                    cpus_range,
                    cpus_range_frac,
                    membw_gb,
                    ..
                }
                | LayerKind::Grouped {
                    util_range,
                    cpus_range,
                    cpus_range_frac,
                    membw_gb,
                    ..
                } => {
                    let cpus_range =
                        resolve_cpus_pct_range(cpus_range, cpus_range_frac, nr_cpus).unwrap();

                    // A grouped layer can choose to include open cputime
                    // for sizing. Also, as an empty layer can only get CPU
                    // time through fallback (counted as owned) or open
                    // execution, add open cputime for empty layers.
                    let owned = utils[idx][LAYER_USAGE_OWNED];
                    let open = utils[idx][LAYER_USAGE_OPEN];

                    let membw_owned = membws[idx][LAYER_USAGE_OWNED];
                    let membw_open = membws[idx][LAYER_USAGE_OPEN];

                    let mut util = owned;
                    let mut membw = membw_owned;
                    if layer.kind.util_includes_open_cputime() || layer.nr_cpus == 0 {
                        util += open;
                        membw += membw_open;
                    }

                    let util = if util < 0.01 { 0.0 } else { util };

                    let low = (util / util_range.1).ceil() as usize;
                    let high = ((util / util_range.0).floor() as usize).max(low);

                    let membw_limit = match membw_gb {
                        Some(membw_limit) => *membw_limit,
                        None => 0.0,
                    };

                    trace!(
                        "layer {0} (membw, membw_limit): ({membw} gi_b, {membw_limit} gi_b)",
                        layer.name
                    );

                    let target = layer.cpus.weight().clamp(low, high);

                    records.push((
                        (owned * 100.0) as u64,
                        (open * 100.0) as u64,
                        (util * 100.0) as u64,
                        low,
                        high,
                        target,
                    ));

                    let target = target.clamp(cpus_range.0, cpus_range.1);
                    let membw_target =
                        self.clamp_target_by_membw(layer, membw_limit, membw, target as u64);

                    trace!("CPU target pre- and post-membw adjustment: {target} -> {membw_target}");

                    // If there's no way to drop our memory usage down enough,
                    // pin the target CPUs to low and drop a warning.
                    if membw_target < cpus_range.0 {
                        warn!("cannot satisfy memory bw limit for layer {}", layer.name);
                        warn!("membw_target {membw_target} low {}", cpus_range.0);
                    };

                    // Memory bandwidth target cannot override imposed limits or bump
                    // the target above what CPU usage-based throttling requires.
                    let target = membw_target.clamp(cpus_range.0, target);

                    (target, cpus_range.0)
                }
                LayerKind::Open { .. } => (0, 0),
            });
        }

        trace!("(owned, open, util, low, high, target): {:?}", &records);
        targets
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
    // algorithm. Uses per-node targets from unified_alloc() to decide how
    // many LLCs each layer gets on each node, then builds core_order and
    // applies CPU changes.
    fn recompute_layer_core_order(
        &mut self,
        layer_targets: &[(usize, usize)],
        layer_allocs: &[LayerAlloc],
        au: usize,
    ) -> Result<bool> {
        let nr_nodes = self.topo.nodes.len();

        // Phase 1 — Free per-node: return excess LLCs to cpu_pool.
        debug!(
            " free: before pass: free_llcs={:?}",
            self.cpu_pool.free_llcs
        );
        for &(idx, _) in layer_targets.iter().rev() {
            let layer = &mut self.layers[idx];

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            let alloc = &layer_allocs[idx];

            for n in 0..nr_nodes {
                let assigned_on_n = layer.assigned_llcs[n].len();
                let target_full_n =
                    Self::compute_target_llcs(alloc.node_target(n) * au, &self.topo).0;
                let mut to_free = assigned_on_n.saturating_sub(target_full_n);

                debug!(
                    " free: layer={} node={} assigned={} target_full={} to_free={}",
                    layer.name, n, assigned_on_n, target_full_n, to_free,
                );

                while to_free > 0 {
                    if let Some(llc) = layer.assigned_llcs[n].pop() {
                        self.cpu_pool.return_llc(llc);
                        to_free -= 1;
                        debug!(" layer={} freed_llc={} from node={}", layer.name, llc, n);
                    } else {
                        break;
                    }
                }
            }
        }
        debug!(" free: after pass: free_llcs={:?}", self.cpu_pool.free_llcs);

        // Phase 2 — Acquire per-node: claim LLCs from cpu_pool.
        for &(idx, _) in layer_targets.iter().rev() {
            let layer = &mut self.layers[idx];

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            let alloc = &layer_allocs[idx];

            for n in 0..nr_nodes {
                let cur_on_n = layer.assigned_llcs[n].len();
                let target_full_n =
                    Self::compute_target_llcs(alloc.node_target(n) * au, &self.topo).0;
                let mut to_alloc = target_full_n.saturating_sub(cur_on_n);

                debug!(
                    " alloc: layer={} node={} cur={} target_full={} to_alloc={} free={}",
                    layer.name,
                    n,
                    cur_on_n,
                    target_full_n,
                    to_alloc,
                    self.cpu_pool.free_llcs.get(&n).map_or(0, |v| v.len()),
                );

                while to_alloc > 0 {
                    if let Some(llc) = self.cpu_pool.take_llc_from_node(n) {
                        layer.assigned_llcs[n].push(llc);
                        to_alloc -= 1;
                        debug!(" layer={} alloc_llc={} on node={}", layer.name, llc, n);
                    } else {
                        break;
                    }
                }
            }

            debug!(
                " alloc: layer={} assigned_llcs={:?}",
                layer.name, layer.assigned_llcs
            );
        }

        // Phase 3 — Spillover per-node: consume extra cores from free LLCs.
        let cores_per_llc = self.topo.all_cores.len() / self.topo.all_llcs.len();
        let cpus_per_core = self.topo.all_cores.first_key_value().unwrap().1.cpus.len();
        let cpus_per_llc = cores_per_llc * cpus_per_core;

        for &(idx, _) in layer_targets.iter() {
            let layer = &mut self.layers[idx];

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            layer.core_order = vec![Vec::new(); nr_nodes];
            let alloc = &layer_allocs[idx];

            for n in 0..nr_nodes {
                let mut extra = Self::compute_target_llcs(alloc.node_target(n) * au, &self.topo).1;

                if let Some(node_llcs) = self.cpu_pool.free_llcs.get_mut(&n) {
                    for entry in node_llcs.iter_mut() {
                        if extra == 0 {
                            break;
                        }
                        let avail = cpus_per_llc - entry.1;
                        let mut used = extra.min(avail);
                        let cores_to_add = used;

                        let shift = entry.1;
                        entry.1 += used;

                        let llc_id = entry.0;
                        let llc = self.topo.all_llcs.get(&llc_id).unwrap();

                        for core in llc.cores.iter().skip(shift) {
                            if used == 0 {
                                break;
                            }
                            layer.core_order[n].push(core.1.id);
                            used -= 1;
                        }

                        extra -= cores_to_add;
                    }
                }
            }

            for node_cores in &mut layer.core_order {
                node_cores.reverse();
            }
        }

        // Reset consumed entries in free LLCs.
        for node_llcs in self.cpu_pool.free_llcs.values_mut() {
            for entry in node_llcs.iter_mut() {
                entry.1 = 0;
            }
        }

        // Phase 4 — Build core_order: append cores from assigned LLCs.
        for &(idx, _) in layer_targets.iter() {
            let layer = &mut self.layers[idx];

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            let all_assigned: HashSet<usize> =
                layer.assigned_llcs.iter().flatten().copied().collect();

            for core in self.topo.all_cores.iter() {
                let llc_id = core.1.llc_id;
                if all_assigned.contains(&llc_id) {
                    let nid = core.1.node_id;
                    layer.core_order[nid].push(core.1.id);
                }
            }
            for node_cores in &mut layer.core_order {
                node_cores.reverse();
            }

            debug!(
                " alloc: layer={} core_order={:?}",
                layer.name, layer.core_order
            );
        }

        // Phase 5 — Apply CPU changes for StickyDynamic layers.
        // Two phases: first free per-node, then allocate per-node.
        let mut updated = false;

        // Free excess CPUs per-node.
        for &(idx, _) in layer_targets.iter() {
            let layer = &mut self.layers[idx];

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            for n in 0..nr_nodes {
                let mut node_target = Cpumask::new();
                for &core_id in &layer.core_order[n] {
                    if let Some(core) = self.topo.all_cores.get(&core_id) {
                        node_target |= &core.span;
                    }
                }
                node_target &= &layer.allowed_cpus;

                let node_span = &self.topo.nodes[&n].span;
                let node_cur = layer.cpus.and(node_span);
                let cpus_to_free = node_cur.and(&node_target.not());

                if cpus_to_free.weight() > 0 {
                    debug!(
                        " apply: layer={} freeing CPUs on node {}: {}",
                        layer.name, n, cpus_to_free
                    );
                    layer.cpus &= &cpus_to_free.not();
                    layer.nr_cpus -= cpus_to_free.weight();
                    for cpu in cpus_to_free.iter() {
                        layer.nr_llc_cpus[self.cpu_pool.topo.all_cpus[&cpu].llc_id] -= 1;
                        layer.nr_node_cpus[n] -= 1;
                    }
                    self.cpu_pool.free(&cpus_to_free)?;
                    updated = true;
                }
            }
        }

        // Allocate needed CPUs per-node.
        for &(idx, _) in layer_targets.iter() {
            let layer = &mut self.layers[idx];

            if layer.growth_algo != LayerGrowthAlgo::StickyDynamic {
                continue;
            }

            for n in 0..nr_nodes {
                let mut node_target = Cpumask::new();
                for &core_id in &layer.core_order[n] {
                    if let Some(core) = self.topo.all_cores.get(&core_id) {
                        node_target |= &core.span;
                    }
                }
                node_target &= &layer.allowed_cpus;

                let available_cpus = self.cpu_pool.available_cpus();
                let desired_to_alloc = node_target.and(&layer.cpus.clone().not());
                let cpus_to_alloc = desired_to_alloc.clone().and(&available_cpus);

                if desired_to_alloc.weight() > cpus_to_alloc.weight() {
                    debug!(
                        " apply: layer={} node {} wanted to alloc {} CPUs but only {} available",
                        layer.name,
                        n,
                        desired_to_alloc.weight(),
                        cpus_to_alloc.weight()
                    );
                }

                if cpus_to_alloc.weight() > 0 {
                    debug!(
                        " apply: layer={} allocating CPUs on node {}: {}",
                        layer.name, n, cpus_to_alloc
                    );
                    layer.cpus |= &cpus_to_alloc;
                    layer.nr_cpus += cpus_to_alloc.weight();
                    for cpu in cpus_to_alloc.iter() {
                        layer.nr_llc_cpus[self.cpu_pool.topo.all_cpus[&cpu].llc_id] += 1;
                        layer.nr_node_cpus[n] += 1;
                    }
                    self.cpu_pool.mark_allocated(&cpus_to_alloc)?;
                    updated = true;
                }
            }

            debug!(
                " apply: layer={} final cpus.weight()={} nr_cpus={}",
                layer.name,
                layer.cpus.weight(),
                layer.nr_cpus
            );
        }

        Ok(updated)
    }

    fn refresh_node_ctx(
        skel: &mut BpfSkel,
        topo: &Topology,
        node_empty_layers: &[Vec<u32>],
        init: bool,
    ) {
        for &nid in topo.nodes.keys() {
            let mut arg: bpf_intf::refresh_node_ctx_arg =
                unsafe { MaybeUninit::zeroed().assume_init() };
            arg.node_id = nid as u32;
            arg.init = init as u32;

            let empty = &node_empty_layers[nid];
            arg.nr_empty_layer_ids = empty.len() as u32;
            for (i, &lid) in empty.iter().enumerate() {
                arg.empty_layer_ids[i] = lid;
            }
            for i in empty.len()..MAX_LAYERS {
                arg.empty_layer_ids[i] = MAX_LAYERS as u32;
            }

            if init {
                // Per-node LLC list — static topology, only set during init.
                let node = &topo.nodes[&nid];
                let llcs: Vec<u32> = node.llcs.keys().map(|&id| id as u32).collect();
                arg.nr_llcs = llcs.len() as u32;
                for (i, &llc_id) in llcs.iter().enumerate() {
                    arg.llcs[i] = llc_id;
                }
            }

            let input = ProgramInput {
                context_in: Some(unsafe { plain::as_mut_bytes(&mut arg) }),
                ..Default::default()
            };
            let _ = skel.progs.refresh_node_ctx.test_run(input);
        }
    }

    fn refresh_cpumasks(&mut self) -> Result<()> {
        let layer_is_open = |layer: &Layer| matches!(layer.kind, LayerKind::Open { .. });

        let mut updated = false;
        let raw_targets = self.calc_target_nr_cpus();
        let au = self.cpu_pool.alloc_unit();
        let total_cpus = self.cpu_pool.topo.all_cpus.len();

        // Dampen shrink: only drop halfway per cycle to avoid unnecessary
        // changes. There's some dampening built into util metrics but slow
        // down freeing further. This is solely based on intuition. Drop or
        // update according to real-world behavior.
        let targets: Vec<(usize, usize)> = raw_targets
            .iter()
            .enumerate()
            .map(|(idx, &(target, min))| {
                let cur = self.layers[idx].nr_cpus;
                if target < cur {
                    let dampened = cur - (cur - target).div_ceil(2);
                    (dampened.max(min), min)
                } else {
                    (target, min)
                }
            })
            .collect();

        // Build demands for unified_alloc and compute per-node allocations.
        let demands = self.calc_raw_demands(&targets);
        let nr_nodes = self.topo.nodes.len();
        let node_caps: Vec<usize> = self
            .topo
            .nodes
            .values()
            .map(|n| n.span.weight() / au)
            .collect();
        let all_layer_nodes: Vec<&[usize]> = self
            .layer_specs
            .iter()
            .map(|s| s.nodes().as_slice())
            .collect();
        let norders: Vec<Vec<usize>> = (0..self.layers.len())
            .map(|idx| {
                layer_core_growth::node_order(
                    self.layer_specs[idx].nodes(),
                    &self.topo,
                    idx,
                    &all_layer_nodes,
                )
            })
            .collect();
        let cur_node_cpus: Vec<Vec<usize>> = self
            .layers
            .iter()
            .map(|layer| (0..nr_nodes).map(|n| layer.nr_node_cpus[n] / au).collect())
            .collect();
        let layer_allocs = unified_alloc(
            total_cpus / au,
            &node_caps,
            &demands,
            &cur_node_cpus,
            &norders,
        );

        // Convert allocations back to CPU counts. Shrink dampening is
        // already applied to the targets fed into unified_alloc above.
        let cpu_targets: Vec<usize> = layer_allocs.iter().map(|a| a.total() * au).collect();

        // Snapshot per-layer CPU counts for ALLOC debug logging.
        let prev_nr_cpus: Vec<usize> = self.layers.iter().map(|l| l.nr_cpus).collect();

        let mut ascending: Vec<(usize, usize)> = cpu_targets.iter().copied().enumerate().collect();
        ascending.sort_by(|a, b| a.1.cmp(&b.1));

        // Snapshot per-layer per-node CPU counts before allocation changes.
        let prev_node_cpus: Vec<Vec<usize>> =
            self.layers.iter().map(|l| l.nr_node_cpus.clone()).collect();

        // Per-node SD allocation requires multiple LLCs. On flat topologies
        // (single LLC, e.g. VMs with topology disabled), SD layers fall through
        // to the non-SD grow/shrink loops below.
        let use_sd_alloc = self.topo.all_llcs.len() > 1;
        let sticky_dynamic_updated = if use_sd_alloc {
            self.recompute_layer_core_order(&ascending, &layer_allocs, au)?
        } else {
            false
        };
        updated |= sticky_dynamic_updated;

        // Update BPF cpumasks for StickyDynamic layers if they were updated
        if sticky_dynamic_updated {
            for (idx, layer) in self.layers.iter().enumerate() {
                if layer.growth_algo == LayerGrowthAlgo::StickyDynamic {
                    Self::update_bpf_layer_cpumask(
                        layer,
                        &mut self.skel.maps.bss_data.as_mut().unwrap().layers[idx],
                    );
                }
            }
        }

        // Shrink per-node: free excess CPUs from each node.
        for &(idx, _target) in ascending.iter().rev() {
            let layer = &mut self.layers[idx];
            if layer_is_open(layer) {
                continue;
            }

            // Skip StickyDynamic layers when per-node SD allocation is active.
            if layer.growth_algo == LayerGrowthAlgo::StickyDynamic && use_sd_alloc {
                continue;
            }

            let alloc = &layer_allocs[idx];
            let mut freed = false;

            for n in 0..nr_nodes {
                let desired = alloc.node_target(n) * au;
                let mut to_free = layer.nr_node_cpus[n].saturating_sub(desired);
                let node_span = &self.topo.nodes[&n].span;

                while to_free > 0 {
                    let node_cands = layer.cpus.and(node_span);
                    let cpus_to_free = match self
                        .cpu_pool
                        .next_to_free(&node_cands, layer.core_order[n].iter().rev())?
                    {
                        Some(ret) => ret,
                        None => break,
                    };
                    let nr = cpus_to_free.weight();
                    trace!(
                        "[{}] freeing CPUs on node {}: {}",
                        layer.name,
                        n,
                        &cpus_to_free
                    );
                    layer.cpus &= &cpus_to_free.not();
                    layer.nr_cpus -= nr;
                    for cpu in cpus_to_free.iter() {
                        let node_id = self.cpu_pool.topo.all_cpus[&cpu].node_id;
                        layer.nr_llc_cpus[self.cpu_pool.topo.all_cpus[&cpu].llc_id] -= 1;
                        layer.nr_node_cpus[node_id] -= 1;
                        layer.nr_pinned_cpus[node_id] =
                            layer.nr_pinned_cpus[node_id].min(layer.nr_node_cpus[node_id]);
                    }
                    self.cpu_pool.free(&cpus_to_free)?;
                    to_free = to_free.saturating_sub(nr);
                    freed = true;
                }
            }

            if freed {
                Self::update_bpf_layer_cpumask(
                    layer,
                    &mut self.skel.maps.bss_data.as_mut().unwrap().layers[idx],
                );
                updated = true;
            }
        }

        // Grow layers per-node using allocations from unified_alloc.
        for &(idx, _target) in &ascending {
            let layer = &mut self.layers[idx];

            if layer_is_open(layer) {
                continue;
            }

            // Skip StickyDynamic layers when per-node SD allocation is active.
            if layer.growth_algo == LayerGrowthAlgo::StickyDynamic && use_sd_alloc {
                continue;
            }

            let alloc = &layer_allocs[idx];
            let norder = &norders[idx];
            let mut alloced = false;

            for &node_id in norder.iter() {
                let node_target = alloc.node_target(node_id) * au;
                let cur_node = layer.nr_node_cpus[node_id];
                if node_target <= cur_node {
                    continue;
                }
                let pinned_target = alloc.pinned[node_id] * au;
                let mut nr_to_alloc = node_target - cur_node;
                let node_span = &self.topo.nodes[&node_id].span;
                let node_allowed = layer.allowed_cpus.and(node_span);

                while nr_to_alloc > 0 {
                    let nr_alloced = match self.cpu_pool.alloc_cpus(
                        &node_allowed,
                        &layer.core_order[node_id],
                        nr_to_alloc,
                    ) {
                        Some(new_cpus) => {
                            let nr = new_cpus.weight();
                            layer.cpus |= &new_cpus;
                            layer.nr_cpus += nr;
                            for cpu in new_cpus.iter() {
                                layer.nr_llc_cpus[self.cpu_pool.topo.all_cpus[&cpu].llc_id] += 1;
                                let nid = self.cpu_pool.topo.all_cpus[&cpu].node_id;
                                layer.nr_node_cpus[nid] += 1;
                                if layer.nr_pinned_cpus[nid] < pinned_target {
                                    layer.nr_pinned_cpus[nid] += 1;
                                }
                            }
                            nr
                        }
                        None => 0,
                    };
                    if nr_alloced == 0 {
                        break;
                    }
                    alloced = true;
                    nr_to_alloc -= nr_alloced.min(nr_to_alloc);
                }
            }

            if alloced {
                Self::update_bpf_layer_cpumask(
                    layer,
                    &mut self.skel.maps.bss_data.as_mut().unwrap().layers[idx],
                );
                updated = true;
            }
        }

        // Recompute growth_denied: for each node, check whether the
        // unpinned portion of the layer warranted growth (unpinned util /
        // util_high > unpinned CPUs) but the node didn't gain CPUs.  Only
        // unpinned matters because pinned tasks can't migrate cross-node.
        let node_utils = &self.sched_stats.layer_node_utils;
        let pinned_utils = &self.sched_stats.layer_node_pinned_utils;
        for (idx, layer) in self.layers.iter().enumerate() {
            self.growth_denied[idx].fill(false);
            let util_high = match layer.kind.util_range() {
                Some((_, high)) => high,
                None => continue,
            };
            for n in 0..nr_nodes {
                let unpinned_util = (node_utils[idx][n] - pinned_utils[idx][n]).max(0.0);
                let unpinned_cpus_needed = unpinned_util / util_high;
                let unpinned_cpus_have =
                    layer.nr_node_cpus[n].saturating_sub(layer.nr_pinned_cpus[n]) as f64;
                let wanted = unpinned_cpus_needed > unpinned_cpus_have;
                let got = layer.nr_node_cpus[n] > prev_node_cpus[idx][n];
                if wanted && !got {
                    self.growth_denied[idx][n] = true;
                }
            }
        }

        // Log per-layer allocation changes.
        if updated {
            for (idx, layer) in self.layers.iter().enumerate() {
                if layer_is_open(layer) {
                    continue;
                }
                let prev = prev_nr_cpus[idx];
                let cur = layer.nr_cpus;
                if prev != cur {
                    debug!(
                        "ALLOC {} algo={:?} cpus:{}→{} mask={:x}",
                        layer.name, layer.growth_algo, prev, cur, layer.cpus,
                    );
                }
            }
            debug!(
                "ALLOC pool_available={}",
                self.cpu_pool.available_cpus().weight()
            );
        }

        // Log allocation changes.
        if updated {
            let nr_nodes = self.topo.nodes.len();
            for (idx, layer) in self.layers.iter().enumerate() {
                if layer_is_open(layer) {
                    continue;
                }
                let prev = &prev_node_cpus[idx];
                let cur = &layer.nr_node_cpus;
                if prev == cur {
                    continue;
                }
                let per_node: String = (0..nr_nodes)
                    .map(|n| format!("n{}:{}→{}", n, prev[n], cur[n]))
                    .collect::<Vec<_>>()
                    .join(" ");
                let prev_total: usize = prev.iter().sum();
                let cur_total: usize = cur[..nr_nodes].iter().sum();
                let target: String = (0..nr_nodes)
                    .map(|n| format!("n{}:{}", n, layer_allocs[idx].node_target(n) * au))
                    .collect::<Vec<_>>()
                    .join(" ");
                debug!(
                    "ALLOC {} algo={:?} {} total:{}→{} target:[{}] mask={:x}",
                    layer.name,
                    layer.growth_algo,
                    per_node,
                    prev_total,
                    cur_total,
                    target,
                    layer.cpus,
                );
            }
            debug!(
                "ALLOC pool_available={}",
                self.cpu_pool.available_cpus().weight()
            );
        }

        // Give the rest to the open layers.
        if updated {
            for (idx, layer) in self.layers.iter_mut().enumerate() {
                if !layer_is_open(layer) {
                    continue;
                }

                let bpf_layer = &mut self.skel.maps.bss_data.as_mut().unwrap().layers[idx];
                let available_cpus = self.cpu_pool.available_cpus().and(&layer.allowed_cpus);
                let nr_available_cpus = available_cpus.weight();

                // Open layers need the intersection of allowed cpus and
                // available cpus. Recompute per-LLC and per-node counts
                // since open layers bypass alloc/free.
                layer.cpus = available_cpus;
                layer.nr_cpus = nr_available_cpus;
                for llc in self.cpu_pool.topo.all_llcs.values() {
                    layer.nr_llc_cpus[llc.id] = layer.cpus.and(&llc.span).weight();
                }
                for node in self.cpu_pool.topo.nodes.values() {
                    layer.nr_node_cpus[node.id] = layer.cpus.and(&node.span).weight();
                    layer.nr_pinned_cpus[node.id] = 0;
                }
                Self::update_bpf_layer_cpumask(layer, bpf_layer);
            }

            for (&node_id, &cpu) in &self.cpu_pool.fallback_cpus {
                self.skel.maps.bss_data.as_mut().unwrap().fallback_cpus[node_id] = cpu as u32;
            }

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

            // Update per-node empty layer IDs via BPF prog.
            let nr_nodes = self.topo.nodes.len();
            let node_empty_layers: Vec<Vec<u32>> = (0..nr_nodes)
                .map(|nid| {
                    self.layers
                        .iter()
                        .enumerate()
                        .filter(|(_lidx, layer)| layer.nr_node_cpus[nid] == 0)
                        .map(|(lidx, _)| lidx as u32)
                        .collect()
                })
                .collect();
            Self::refresh_node_ctx(&mut self.skel, &self.topo, &node_empty_layers, false);
        }

        if let Err(e) = self.update_netdev_cpumasks() {
            warn!("Failed to update netdev IRQ cpumasks: {:#}", e);
        }
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

    fn refresh_xnuma(&mut self) {
        let nr_nodes = self.topo.nodes.len();
        if nr_nodes <= 1 {
            return;
        }

        let duty_sums = &self.sched_stats.layer_node_duty_sums;

        for (layer_idx, spec) in self.layer_specs.iter().enumerate() {
            let common = spec.kind.common();
            let threshold = common.xnuma_threshold;
            let threshold_delta = common.xnuma_threshold_delta;
            let bpf_layer = &mut self.skel.maps.bss_data.as_mut().unwrap().layers[layer_idx];

            if threshold.0 <= 0.0 && threshold.1 <= 0.0 {
                // Off — all open, infinite budget
                for src in 0..nr_nodes {
                    bpf_layer.node[src].xnuma_is_mig_src.write(true);
                    for dst in 0..nr_nodes {
                        bpf_layer.node[src].xnuma[dst].rate = u64::MAX;
                    }
                }
                self.xnuma_mig_src[layer_idx].fill(false);
                continue;
            }

            let layer = &self.layers[layer_idx];
            let is_mig_src = xnuma_check_active(
                &duty_sums[layer_idx],
                &layer.nr_node_cpus,
                threshold,
                threshold_delta,
                &self.growth_denied[layer_idx],
                &self.xnuma_mig_src[layer_idx],
            );

            self.xnuma_mig_src[layer_idx] = is_mig_src.clone();

            let result = xnuma_compute_rates(&duty_sums[layer_idx], &layer.nr_node_cpus);

            // Write rates before is_mig_src so BPF sees valid rates
            // when the gate activates.
            for src in 0..nr_nodes {
                for dst in 0..nr_nodes {
                    bpf_layer.node[src].xnuma[dst].rate = result.rates[src][dst];
                }
            }
            for (nid, is_src) in is_mig_src.iter().enumerate().take(nr_nodes) {
                bpf_layer.node[nid].xnuma_is_mig_src.write(*is_src);
            }
        }
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

        // Update BPF with EWMA values
        self.skel
            .maps
            .bss_data
            .as_mut()
            .unwrap()
            .system_cpu_util_ewma = (self.sched_stats.system_cpu_util_ewma * 10000.0) as u64;

        for layer_id in 0..self.sched_stats.nr_layers {
            self.skel
                .maps
                .bss_data
                .as_mut()
                .unwrap()
                .layer_dsq_insert_ewma[layer_id] =
                (self.sched_stats.layer_dsq_insert_ewma[layer_id] * 10000.0) as u64;
        }

        self.refresh_cpumasks()?;
        self.refresh_xnuma();
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
        let mut sys_stats = SysStats::new(stats, bstats, &self.cpu_pool.fallback_cpus)?;

        for (lidx, (spec, layer)) in self.layer_specs.iter().zip(self.layers.iter()).enumerate() {
            let layer_stats = LayerStats::new(
                lidx,
                layer,
                stats,
                bstats,
                cpus_ranges[lidx],
                self.xnuma_mig_src[lidx].iter().any(|&a| a),
            );
            sys_stats.layers.insert(spec.name.to_string(), layer_stats);
            cpus_ranges[lidx] = (layer.nr_cpus, layer.nr_cpus);
        }

        Ok(sys_stats)
    }

    // Helper function to process a cgroup creation (common logic for walkdir and inotify)
    fn process_cgroup_creation(
        path: &Path,
        cgroup_regexes: &HashMap<u32, Regex>,
        cgroup_path_to_id: &mut HashMap<String, u64>,
        sender: &crossbeam::channel::Sender<CgroupEvent>,
    ) {
        let path_str = path.to_string_lossy().to_string();

        // Get cgroup ID (inode number)
        let cgroup_id = std::fs::metadata(path)
            .map(|metadata| {
                use std::os::unix::fs::MetadataExt;
                metadata.ino()
            })
            .unwrap_or(0);

        // Build match bitmap by testing against CgroupRegex rules
        let mut match_bitmap = 0u64;
        for (rule_id, regex) in cgroup_regexes {
            if regex.is_match(&path_str) {
                match_bitmap |= 1u64 << rule_id;
            }
        }

        // Store in hash
        cgroup_path_to_id.insert(path_str.clone(), cgroup_id);

        // Send event
        if let Err(e) = sender.send(CgroupEvent::Created {
            path: path_str,
            cgroup_id,
            match_bitmap,
        }) {
            error!("Failed to send cgroup creation event: {}", e);
        }
    }

    fn start_cgroup_watcher(
        shutdown: Arc<AtomicBool>,
        cgroup_regexes: HashMap<u32, Regex>,
    ) -> Result<Receiver<CgroupEvent>> {
        let mut inotify = Inotify::init().context("Failed to initialize inotify")?;
        let mut wd_to_path = HashMap::new();

        // Create crossbeam channel for cgroup events (bounded to prevent memory issues)
        let (sender, receiver) = crossbeam::channel::bounded::<CgroupEvent>(1024);

        // Watch for directory creation and deletion events
        let root_wd = inotify
            .watches()
            .add("/sys/fs/cgroup", WatchMask::CREATE | WatchMask::DELETE)
            .context("Failed to add watch for /sys/fs/cgroup")?;
        wd_to_path.insert(root_wd, PathBuf::from("/sys/fs/cgroup"));

        // Also recursively watch existing directories for new subdirectories
        Self::add_recursive_watches(&mut inotify, &mut wd_to_path, Path::new("/sys/fs/cgroup"))?;

        // Spawn watcher thread
        std::thread::spawn(move || {
            let mut buffer = [0; 4096];
            let inotify_fd = inotify.as_raw_fd();
            // Maintain hash of cgroup path -> cgroup ID (inode number)
            let mut cgroup_path_to_id = HashMap::<String, u64>::new();

            // Populate existing cgroups
            for entry in WalkDir::new("/sys/fs/cgroup")
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_dir())
            {
                let path = entry.path();
                Self::process_cgroup_creation(
                    path,
                    &cgroup_regexes,
                    &mut cgroup_path_to_id,
                    &sender,
                );
            }

            while !shutdown.load(Ordering::Relaxed) {
                // Use select to wait for events with a 100ms timeout
                let ready = unsafe {
                    let mut read_fds: libc::fd_set = std::mem::zeroed();
                    libc::FD_ZERO(&mut read_fds);
                    libc::FD_SET(inotify_fd, &mut read_fds);

                    let mut timeout = libc::timeval {
                        tv_sec: 0,
                        tv_usec: 100_000, // 100ms
                    };

                    libc::select(
                        inotify_fd + 1,
                        &mut read_fds,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut timeout,
                    )
                };

                if ready <= 0 {
                    // Timeout or error, continue loop to check shutdown
                    continue;
                }

                // Read events non-blocking
                let events = match inotify.read_events(&mut buffer) {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading inotify events: {}", e);
                        break;
                    }
                };

                for event in events {
                    if !event.mask.contains(inotify::EventMask::CREATE)
                        && !event.mask.contains(inotify::EventMask::DELETE)
                    {
                        continue;
                    }

                    let name = match event.name {
                        Some(name) => name,
                        None => continue,
                    };

                    let parent_path = match wd_to_path.get(&event.wd) {
                        Some(parent) => parent,
                        None => {
                            warn!("Unknown watch descriptor: {:?}", event.wd);
                            continue;
                        }
                    };

                    let path = parent_path.join(name.to_string_lossy().as_ref());

                    if event.mask.contains(inotify::EventMask::CREATE) {
                        if !path.is_dir() {
                            continue;
                        }

                        Self::process_cgroup_creation(
                            &path,
                            &cgroup_regexes,
                            &mut cgroup_path_to_id,
                            &sender,
                        );

                        // Add watch for this new directory
                        match inotify
                            .watches()
                            .add(&path, WatchMask::CREATE | WatchMask::DELETE)
                        {
                            Ok(wd) => {
                                wd_to_path.insert(wd, path.clone());
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to add watch for new cgroup {}: {}",
                                    path.display(),
                                    e
                                );
                            }
                        }
                    } else if event.mask.contains(inotify::EventMask::DELETE) {
                        let path_str = path.to_string_lossy().to_string();

                        // Get cgroup ID from our hash (since the directory is gone, we can't stat it)
                        let cgroup_id = cgroup_path_to_id.remove(&path_str).unwrap_or(0);

                        // Send removal event to main thread
                        if let Err(e) = sender.send(CgroupEvent::Removed {
                            path: path_str,
                            cgroup_id,
                        }) {
                            error!("Failed to send cgroup removal event: {}", e);
                        }

                        // Find and remove the watch descriptor for this path
                        let wd_to_remove = wd_to_path.iter().find_map(|(wd, watched_path)| {
                            if watched_path == &path {
                                Some(wd.clone())
                            } else {
                                None
                            }
                        });
                        if let Some(wd) = wd_to_remove {
                            wd_to_path.remove(&wd);
                        }
                    }
                }
            }
        });

        Ok(receiver)
    }

    fn add_recursive_watches(
        inotify: &mut Inotify,
        wd_to_path: &mut HashMap<inotify::WatchDescriptor, PathBuf>,
        path: &Path,
    ) -> Result<()> {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_dir())
            .skip(1)
        {
            let entry_path = entry.path();
            // Add watch for this directory
            match inotify
                .watches()
                .add(entry_path, WatchMask::CREATE | WatchMask::DELETE)
            {
                Ok(wd) => {
                    wd_to_path.insert(wd, entry_path.to_path_buf());
                }
                Err(e) => {
                    debug!("Failed to add watch for {}: {}", entry_path.display(), e);
                }
            }
        }
        Ok(())
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let mut next_sched_at = Instant::now() + self.sched_intv;
        let enable_layer_refresh = !self.layer_refresh_intv.is_zero();
        let mut next_layer_refresh_at = Instant::now() + self.layer_refresh_intv;
        let mut cpus_ranges = HashMap::<ThreadId, Vec<(usize, usize)>>::new();

        // Start the cgroup watcher only if there are CgroupRegex rules
        let cgroup_regexes = self.cgroup_regexes.take().unwrap();
        let cgroup_event_rx = if !cgroup_regexes.is_empty() {
            Some(Self::start_cgroup_watcher(
                shutdown.clone(),
                cgroup_regexes,
            )?)
        } else {
            None
        };

        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            let now = Instant::now();

            if now >= next_sched_at {
                self.step()?;
                while next_sched_at < now {
                    next_sched_at += self.sched_intv;
                }
            }

            if enable_layer_refresh && now >= next_layer_refresh_at {
                self.skel
                    .maps
                    .bss_data
                    .as_mut()
                    .unwrap()
                    .layer_refresh_seq_avgruntime += 1;
                while next_layer_refresh_at < now {
                    next_layer_refresh_at += self.layer_refresh_intv;
                }
            }

            // Handle both stats requests and cgroup events with timeout
            let timeout_duration = next_sched_at.saturating_duration_since(Instant::now());
            let never_rx = crossbeam::channel::never();
            let cgroup_rx = cgroup_event_rx.as_ref().unwrap_or(&never_rx);

            select! {
                recv(req_ch) -> msg => match msg {
                    Ok(StatsReq::Hello(tid)) => {
                        cpus_ranges.insert(
                            tid,
                            self.layers.iter().map(|l| (l.nr_cpus, l.nr_cpus)).collect(),
                        );
                        let stats =
                            Stats::new(&mut self.skel, &self.proc_reader, self.topo.clone(), &self.gpu_task_handler, self.sched_stats.util_compensation)?;
                        res_ch.send(StatsRes::Hello(Box::new(stats)))?;
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
                        res_ch.send(StatsRes::Refreshed(Box::new((*stats, sys_stats))))?;
                    }
                    Ok(StatsReq::Bye(tid)) => {
                        cpus_ranges.remove(&tid);
                        res_ch.send(StatsRes::Bye)?;
                    }
                    Err(e) => Err(e)?,
                },

                recv(cgroup_rx) -> event => match event {
                    Ok(CgroupEvent::Created { path, cgroup_id, match_bitmap }) => {
                        // Insert into BPF map
                        self.skel.maps.cgroup_match_bitmap.update(
                            &cgroup_id.to_ne_bytes(),
                            &match_bitmap.to_ne_bytes(),
                            libbpf_rs::MapFlags::ANY,
                        ).with_context(|| format!(
                            "Failed to insert cgroup {}({}) into BPF map. Cgroup map may be full \
                             (max 16384 entries). Aborting.",
                            cgroup_id, path
                        ))?;

                        debug!("Added cgroup {} to BPF map with bitmap 0x{:x}", cgroup_id, match_bitmap);
                    }
                    Ok(CgroupEvent::Removed { path, cgroup_id }) => {
                        // Delete from BPF map
                        if let Err(e) = self.skel.maps.cgroup_match_bitmap.delete(&cgroup_id.to_ne_bytes()) {
                            warn!("Failed to delete cgroup {} from BPF map: {}", cgroup_id, e);
                        } else {
                            debug!("Removed cgroup {}({}) from BPF map", cgroup_id, path);
                        }
                    }
                    Err(e) => {
                        error!("Error receiving cgroup event: {}", e);
                    }
                },

                recv(crossbeam::channel::after(timeout_duration)) -> _ => {
                    // Timeout - continue main loop
                }
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");

        if !self.netdevs.is_empty() {
            for (iface, netdev) in &self.netdevs {
                if let Err(e) = netdev.restore_cpumasks() {
                    warn!("Failed to restore {iface} IRQ affinity: {e}");
                }
            }
            info!("Restored original netdev IRQ affinity");
        }

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

struct HintLayerInfo {
    layer_id: usize,
    system_cpu_util_below: Option<f64>,
    dsq_insert_below: Option<f64>,
}

fn verify_layer_specs(specs: &[LayerSpec]) -> Result<HashMap<u64, HintLayerInfo>> {
    let mut hint_to_layer_map = HashMap::<u64, (usize, String, Option<f64>, Option<f64>)>::new();

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
        } else if spec.matches.len() != 1 || !spec.matches[0].is_empty() {
            bail!("Terminal spec {:?} must have an empty match", spec.name);
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
            let mut hint_equals_cnt = 0;
            let mut system_cpu_util_below_cnt = 0;
            let mut dsq_insert_below_cnt = 0;
            let mut hint_value: Option<u64> = None;
            let mut system_cpu_util_threshold: Option<f64> = None;
            let mut dsq_insert_threshold: Option<f64> = None;
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
                    LayerMatch::SystemCpuUtilBelow(threshold) => {
                        if *threshold < 0.0 || *threshold > 1.0 {
                            bail!(
                                "Spec {:?} has SystemCpuUtilBelow threshold outside the range [0.0, 1.0]",
                                spec.name
                            );
                        }
                        system_cpu_util_threshold = Some(*threshold);
                        system_cpu_util_below_cnt += 1;
                    }
                    LayerMatch::DsqInsertBelow(threshold) => {
                        if *threshold < 0.0 || *threshold > 1.0 {
                            bail!(
                                "Spec {:?} has DsqInsertBelow threshold outside the range [0.0, 1.0]",
                                spec.name
                            );
                        }
                        dsq_insert_threshold = Some(*threshold);
                        dsq_insert_below_cnt += 1;
                    }
                    LayerMatch::HintEquals(hint) => {
                        if *hint > 1024 {
                            bail!(
                                "Spec {:?} has hint value outside the range [0, 1024]",
                                spec.name
                            );
                        }
                        hint_value = Some(*hint);
                        hint_equals_cnt += 1;
                    }
                    _ => {}
                }
            }
            if hint_equals_cnt > 1 {
                bail!("Only 1 HintEquals match permitted per AND block");
            }
            let high_freq_matcher_cnt = system_cpu_util_below_cnt + dsq_insert_below_cnt;
            if high_freq_matcher_cnt > 0 {
                if hint_equals_cnt != 1 {
                    bail!("High-frequency matchers (SystemCpuUtilBelow, DsqInsertBelow) must be used with one HintEquals");
                }
                if system_cpu_util_below_cnt > 1 {
                    bail!("Only 1 SystemCpuUtilBelow match permitted per AND block");
                }
                if dsq_insert_below_cnt > 1 {
                    bail!("Only 1 DsqInsertBelow match permitted per AND block");
                }
                if ands.len() != hint_equals_cnt + system_cpu_util_below_cnt + dsq_insert_below_cnt
                {
                    bail!("High-frequency matchers must be used only with HintEquals (no other matchers)");
                }
            } else if hint_equals_cnt == 1 && ands.len() != 1 {
                bail!("HintEquals match cannot be in conjunction with other matches");
            }

            // Insert hint into map if present
            if let Some(hint) = hint_value {
                if let Some((layer_id, name, _, _)) = hint_to_layer_map.get(&hint) {
                    if *layer_id != idx {
                        bail!(
                            "Spec {:?} has hint value ({}) that is already mapped to Spec {:?}",
                            spec.name,
                            hint,
                            name
                        );
                    }
                } else {
                    hint_to_layer_map.insert(
                        hint,
                        (
                            idx,
                            spec.name.clone(),
                            system_cpu_util_threshold,
                            dsq_insert_threshold,
                        ),
                    );
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

    Ok(hint_to_layer_map
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                HintLayerInfo {
                    layer_id: v.0,
                    system_cpu_util_below: v.2,
                    dsq_insert_below: v.3,
                },
            )
        })
        .collect())
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
        LayerMatch::CgroupRegex(expr) => Ok(traverse_sysfs(Path::new("/sys/fs/cgroup"))?
            .into_iter()
            .map(|cgroup| String::from(cgroup.to_str().expect("could not parse cgroup path")))
            .filter(|cgroup| {
                let re = Regex::new(expr).unwrap();
                re.is_match(cgroup)
            })
            .map(|cgroup| {
                (
                    // Here we convert the regex match into a suffix match because we still need to
                    // do the matching on the bpf side and doing a regex match in bpf isn't
                    // easily done.
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

fn create_perf_fds(skel: &mut BpfSkel, event: u64) -> Result<()> {
    let mut attr = perf::bindings::perf_event_attr {
        size: std::mem::size_of::<perf::bindings::perf_event_attr>() as u32,
        type_: perf::bindings::PERF_TYPE_RAW,
        config: event,
        sample_type: 0u64,
        ..Default::default()
    };
    attr.__bindgen_anon_1.sample_period = 0u64;
    attr.set_disabled(0);

    let perf_events_map = &skel.maps.scx_pmu_map;
    let map_fd = unsafe { libbpf_sys::bpf_map__fd(perf_events_map.as_libbpf_object().as_ptr()) };

    let mut failures = 0u64;

    for cpu in 0..*NR_CPUS_POSSIBLE {
        let fd = unsafe { perf::perf_event_open(&mut attr as *mut _, -1, cpu as i32, -1, 0) };
        if fd < 0 {
            failures += 1;
            trace!(
                "perf_event_open failed cpu={cpu} errno={}",
                std::io::Error::last_os_error()
            );
            continue;
        }

        let key = cpu as u32;
        let val = fd as u32;
        let ret = unsafe {
            libbpf_sys::bpf_map_update_elem(
                map_fd,
                &key as *const _ as *const _,
                &val as *const _ as *const _,
                0,
            )
        };
        if ret != 0 {
            trace!("bpf_map_update_elem failed cpu={cpu} fd={fd} ret={ret}");
        } else {
            trace!("mapped cpu={cpu} -> fd={fd}");
        }
    }

    if failures > 0 {
        println!("membw tracking: failed to install {failures} counters");
        // Keep going, do not fail the scheduler for this
    }

    Ok(())
}

// Set up the counters
fn setup_membw_tracking(skel: &mut OpenBpfSkel) -> Result<u64> {
    let pmumanager = PMUManager::new()?;
    let codename = &pmumanager.codename as &str;

    let pmuspec = match codename {
        "amdzen1" | "amdzen2" | "amdzen3" => {
            trace!("found AMD codename {codename}");
            pmumanager.pmus.get("ls_any_fills_from_sys.mem_io_local")
        }
        "amdzen4" | "amdzen5" => {
            trace!("found AMD codename {codename}");
            pmumanager.pmus.get("ls_any_fills_from_sys.dram_io_all")
        }

        "haswell" | "broadwell" | "broadwellde" | "broadwellx" | "skylake" | "skylakex"
        | "cascadelakex" | "arrowlake" | "meteorlake" | "sapphirerapids" | "emeraldrapids"
        | "graniterapids" => {
            trace!("found Intel codename {codename}");
            pmumanager.pmus.get("LONGEST_LAT_CACHE.MISS")
        }

        _ => {
            trace!("found unknown codename {codename}");
            None
        }
    };

    let spec = pmuspec.ok_or("not_found").unwrap();
    let config = (spec.umask << 8) | spec.event[0];

    // Install the counter in the BPF map
    skel.maps.rodata_data.as_mut().unwrap().membw_event = config;

    Ok(config)
}

#[clap_main::clap_main]
fn main(opts: Opts) -> Result<()> {
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

    debug!("opts={:?}", &opts);

    if let Some(run_id) = opts.run_id {
        info!("scx_layered run_id: {}", run_id);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let stats_columns = opts.stats_columns;
        let stats_no_llc = opts.stats_no_llc;
        let jh = std::thread::spawn(move || {
            match stats::monitor(
                Duration::from_secs_f64(intv),
                shutdown_copy,
                stats_columns,
                stats_no_llc,
            ) {
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
                    let matches = expand_template(rule)?;
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

        if common.allow_node_aligned.is_some() {
            warn!("Layer {} has deprecated flag \"allow_node_aligned\", node-aligned tasks are now always dispatched on layer DSQs", &spec.name);
        }
    }

    let membw_required = layer_config.specs.iter().any(|spec| match spec.kind {
        LayerKind::Confined { membw_gb, .. } | LayerKind::Grouped { membw_gb, .. } => {
            membw_gb.is_some()
        }
        LayerKind::Open { .. } => false,
    });

    if opts.print_and_exit {
        println!("specs={}", serde_json::to_string_pretty(&layer_config)?);
        return Ok(());
    }

    debug!("specs={}", serde_json::to_string_pretty(&layer_config)?);
    let hint_to_layer_map = verify_layer_specs(&layer_config.specs)?;

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(
            &opts,
            &layer_config.specs,
            &mut open_object,
            &hint_to_layer_map,
            membw_required,
        )?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod xnuma_tests {
    use super::*;

    // Default thresholds for tests
    const THRESH: (f64, f64) = (0.6, 0.7);
    const DELTA: (f64, f64) = (0.2, 0.3);

    // =====================================================================
    // xnuma_check_active tests — per-(layer, node) two-threshold
    // =====================================================================

    #[test]
    fn test_activation_below_threshold() {
        // Both nodes below threshold — both closed
        let duty = vec![40.0, 40.0];
        let allocs = vec![96, 96];
        let gd = vec![true, true];
        let cur = vec![false, false];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // ratio = 0.42 < 0.6 (low) → deactivate
        assert!(!result[0]);
        assert!(!result[1]);
    }

    #[test]
    fn test_activation_above_all_thresholds() {
        // N0 overloaded + imbalanced + growth denied → open
        let duty = vec![90.0, 20.0];
        let allocs = vec![96, 96];
        let gd = vec![true, false];
        let cur = vec![false, false];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // N0: load=0.94>0.7, eq=110/192=0.573, surplus=90-55=35, ratio=0.365>0.3, gd=true → open
        assert!(result[0]);
        // N1: load=0.21<0.6 → closed
        assert!(!result[1]);
    }

    #[test]
    fn test_activation_requires_growth_denied() {
        // N0 overloaded + imbalanced but growth NOT denied → closed
        let duty = vec![90.0, 20.0];
        let allocs = vec![96, 96];
        let gd = vec![false, false]; // growth succeeded
        let cur = vec![false, false];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        assert!(!result[0]); // !growth_denied → deactivate
    }

    #[test]
    fn test_symmetric_high_load_stays_closed() {
        // Both nodes above threshold but balanced (delta=0) → closed
        let duty = vec![80.0, 80.0];
        let allocs = vec![96, 96];
        let gd = vec![true, true];
        let cur = vec![false, false];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // load=0.83>0.7 but surplus=0, surplus_ratio=0 < 0.3 → no activation
        assert!(!result[0]);
        assert!(!result[1]);
    }

    #[test]
    fn test_hysteresis_stays_active() {
        // N0 was active, now between thresholds → stays active
        let duty = vec![75.0, 20.0];
        let allocs = vec![96, 96];
        let gd = vec![true, false];
        let cur = vec![true, false]; // N0 was active
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // N0: load=0.78 > 0.6(lo) and < 0.7(hi), surplus=(75-20)/2=27.5, ratio=0.286 > 0.2(lo)
        // gd=true. activate: 0.78<0.7 NO. deactivate: 0.78>0.6 NO, 0.286>0.2 NO, gd=true NO
        // → hysteresis preserves true
        assert!(result[0]);
    }

    #[test]
    fn test_hysteresis_stays_inactive() {
        // N0 was inactive, in hysteresis band → stays inactive
        let duty = vec![75.0, 20.0];
        let allocs = vec![96, 96];
        let gd = vec![true, false];
        let cur = vec![false, false]; // N0 was inactive
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // Same conditions but currently inactive → stays inactive
        assert!(!result[0]);
    }

    #[test]
    fn test_deactivation_load_drops() {
        // N0 was active, load drops below low → closes
        let duty = vec![50.0, 50.0];
        let allocs = vec![96, 96];
        let gd = vec![true, true];
        let cur = vec![true, false];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // N0: load=0.52 < 0.6(lo) → deactivate
        assert!(!result[0]);
    }

    #[test]
    fn test_deactivation_growth_succeeds() {
        // N0 was active, growth now succeeds → closes
        let duty = vec![90.0, 20.0];
        let allocs = vec![96, 96];
        let gd = vec![false, false]; // growth succeeded
        let cur = vec![true, false];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // !growth_denied → deactivate regardless of load/delta
        assert!(!result[0]);
    }

    #[test]
    fn test_zero_alloc_with_duty_and_growth_denied() {
        // Zero alloc but duty > 0 and growth denied → open
        let duty = vec![50.0, 0.0];
        let allocs = vec![0, 96];
        let gd = vec![true, false];
        let cur = vec![false, false];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        assert!(result[0]); // zero alloc + duty + gd → source
    }

    #[test]
    fn test_all_zero_alloc() {
        let duty = vec![0.0, 0.0];
        let allocs = vec![0, 0];
        let gd = vec![true, true];
        let cur = vec![true, true];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        assert!(!result[0]);
        assert!(!result[1]);
    }

    #[test]
    fn test_three_nodes_mixed() {
        // 3 nodes: N0 overloaded+imbalanced+gd, N1 moderate, N2 low
        let duty = vec![90.0, 40.0, 10.0];
        let allocs = vec![96, 96, 96];
        let gd = vec![true, true, false];
        let cur = vec![false, false, false];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // eq_ratio = 140/288 ≈ 0.486
        // N0: load=0.94>0.7, surplus=90-46.7=43.3, ratio=0.451>0.3, gd=true → open
        assert!(result[0]);
        // N1: load=0.42<0.6 → deactivate
        assert!(!result[1]);
        // N2: load=0.10<0.6 → deactivate
        assert!(!result[2]);
    }

    #[test]
    fn test_per_node_independence() {
        // N0 active, N1 deactivates independently
        let duty = vec![90.0, 50.0];
        let allocs = vec![96, 96];
        let gd = vec![true, true];
        let cur = vec![true, true];
        let result = xnuma_check_active(&duty, &allocs, THRESH, DELTA, &gd, &cur);
        // N0: load=0.94>0.7, eq=140/192=0.729, surplus=90-70=20, ratio=0.208>0.2(lo)
        //   activate: 0.94>0.7 YES, 0.208>0.3 NO → no activate
        //   deactivate: 0.94>0.6 NO, 0.208>0.2 NO, gd=true NO → no deactivate → preserve true
        assert!(result[0]);
        // N1: load=0.52<0.6 → deactivate
        assert!(!result[1]);
    }

    // =====================================================================
    // xnuma_compute_rates tests — basic
    // =====================================================================

    #[test]
    fn test_rates_balanced_load() {
        // Equal load per CPU on both nodes — no migration needed
        let duty = vec![48.0, 48.0];
        let allocs = vec![96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // No surplus/deficit → all rates zero
        for src in 0..2 {
            for dst in 0..2 {
                assert_eq!(result.rates[src][dst], 0);
            }
        }
    }

    #[test]
    fn test_rates_one_overloaded() {
        // N0 has 80 CPUs of duty, N1 has 40. Both have 96 CPUs.
        // eq_ratio = 120/192 = 0.625
        // N0 expected = 0.625 * 96 = 60, surplus = 80 - 60 = 20
        // N1 expected = 0.625 * 96 = 60, deficit = 60 - 40 = 20
        let duty = vec![80.0, 40.0];
        let allocs = vec![96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // rate[0][1] should be positive (migrate from N0 to N1)
        assert!(result.rates[0][1] > 0);
        // rate[1][0] should be 0 (N1 has no surplus)
        assert_eq!(result.rates[1][0], 0);
        // Self-rates always 0
        assert_eq!(result.rates[0][0], 0);
        assert_eq!(result.rates[1][1], 0);

        // Verify the rate magnitude: migration = 20.0 * DAMPEN, scaled
        let expected_rate = (20.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        assert_eq!(result.rates[0][1], expected_rate);
    }

    #[test]
    fn test_rates_asymmetric_allocation() {
        // N0 has 48 CPUs, N1 has 144 CPUs. Duty 48 each.
        // eq_ratio = 96/192 = 0.5
        // N0 expected = 0.5 * 48 = 24, surplus = 48 - 24 = 24
        // N1 expected = 0.5 * 144 = 72, deficit = 72 - 48 = 24
        let duty = vec![48.0, 48.0];
        let allocs = vec![48, 144];
        let result = xnuma_compute_rates(&duty, &allocs);

        let expected_rate = (24.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        assert_eq!(result.rates[0][1], expected_rate);
        assert_eq!(result.rates[1][0], 0);
    }

    // =====================================================================
    // xnuma_compute_rates tests — multi-node
    // =====================================================================

    #[test]
    fn test_rates_three_nodes_one_source() {
        // N0 overloaded, N1 and N2 are deficit
        // allocs: 96 each, duty: N0=120, N1=30, N2=30
        // eq_ratio = 180/288 = 0.625
        // N0 expected = 60, surplus = 60
        // N1 expected = 60, deficit = 30
        // N2 expected = 60, deficit = 30
        let duty = vec![120.0, 30.0, 30.0];
        let allocs = vec![96, 96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // Total deficit = 60. N1 gets 30/60 = 50%, N2 gets 30/60 = 50%
        // rate[0][1] = 60 * 30/60 * DAMPEN = 15
        // rate[0][2] = 60 * 30/60 * DAMPEN = 15
        let rate_01 = (30.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        let rate_02 = (30.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        assert_eq!(result.rates[0][1], rate_01);
        assert_eq!(result.rates[0][2], rate_02);

        // No reverse flow
        assert_eq!(result.rates[1][0], 0);
        assert_eq!(result.rates[2][0], 0);
        assert_eq!(result.rates[1][2], 0);
        assert_eq!(result.rates[2][1], 0);
    }

    #[test]
    fn test_rates_three_nodes_unequal_deficit() {
        // N0 overloaded. N1 slight deficit, N2 large deficit.
        // allocs: 96 each, duty: N0=120, N1=50, N2=10
        // eq_ratio = 180/288 = 0.625
        // N0: expected=60, surplus=60
        // N1: expected=60, deficit=10
        // N2: expected=60, deficit=50
        let duty = vec![120.0, 50.0, 10.0];
        let allocs = vec![96, 96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // Total deficit = 60. N1 share = 10/60, N2 share = 50/60
        // rate[0][1] = 60 * 10/60 * DAMPEN = 5
        // rate[0][2] = 60 * 50/60 * DAMPEN = 25
        let rate_01 = (10.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        let rate_02 = (50.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        assert_eq!(result.rates[0][1], rate_01);
        assert_eq!(result.rates[0][2], rate_02);
    }

    #[test]
    fn test_rates_two_sources_one_sink() {
        // N0 and N1 overloaded, N2 deficit
        // allocs: 96 each, duty: N0=80, N1=70, N2=30
        // total = 180, eq_ratio = 180/288 = 0.625
        // N0: expected=60, surplus=20
        // N1: expected=60, surplus=10
        // N2: expected=60, deficit=30
        let duty = vec![80.0, 70.0, 30.0];
        let allocs = vec![96, 96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // Total deficit = 30. Only N2 is deficit, so deficit share = 1.0
        // rate[0][2] = 20 * 1.0 * DAMPEN = 10
        // rate[1][2] = 10 * 1.0 * DAMPEN = 5
        let rate_02 = (20.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        let rate_12 = (10.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        assert_eq!(result.rates[0][2], rate_02);
        assert_eq!(result.rates[1][2], rate_12);

        // No flow between sources
        assert_eq!(result.rates[0][1], 0);
        assert_eq!(result.rates[1][0], 0);
    }

    // =====================================================================
    // Conservation invariants
    // =====================================================================

    #[test]
    fn test_conservation_per_source_outbound() {
        // Each source's total outbound should equal its surplus * DAMPEN (scaled).
        // Total outbound from src = surplus[src] * DAMPEN * DUTY_CYCLE_SCALE
        let duty = vec![100.0, 30.0, 50.0, 20.0];
        let allocs = vec![96, 96, 96, 96];
        let nr = 4;
        let result = xnuma_compute_rates(&duty, &allocs);

        let total_duty: f64 = duty.iter().sum();
        let total_alloc: f64 = allocs.iter().map(|&a| a as f64).sum();
        let eq_ratio = total_duty / total_alloc;

        for src in 0..nr {
            let expected = eq_ratio * allocs[src] as f64;
            let surplus = (duty[src] - expected).max(0.0);
            let total_outbound: u64 = (0..nr).map(|dst| result.rates[src][dst]).sum();
            let expected_rate = (surplus * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
            assert_eq!(
                total_outbound, expected_rate,
                "node {} outbound mismatch",
                src
            );
        }
    }

    #[test]
    fn test_conservation_surplus_equals_deficit() {
        // Mathematical invariant: total surplus == total deficit in water-fill
        let duty = vec![100.0, 30.0, 50.0];
        let allocs = vec![96, 96, 96];

        let total_duty: f64 = duty.iter().sum();
        let total_alloc: f64 = allocs.iter().map(|&a| a as f64).sum();
        let eq_ratio = total_duty / total_alloc;

        let mut total_surplus = 0.0f64;
        let mut total_deficit = 0.0f64;
        for i in 0..3 {
            let expected = eq_ratio * allocs[i] as f64;
            let delta = duty[i] - expected;
            if delta > 0.0 {
                total_surplus += delta;
            } else {
                total_deficit += -delta;
            }
        }
        assert!((total_surplus - total_deficit).abs() < 1e-10);
    }

    #[test]
    fn test_self_rates_always_zero() {
        let duty = vec![100.0, 30.0, 50.0];
        let allocs = vec![96, 96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        for nid in 0..3 {
            assert_eq!(result.rates[nid][nid], 0);
        }
    }

    #[test]
    fn test_deficit_nodes_have_zero_outbound() {
        // Deficit nodes should have zero outbound rates
        let duty = vec![100.0, 20.0, 30.0, 50.0];
        let allocs = vec![96, 96, 96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // eq_ratio = 200/384 ≈ 0.521. N0: surplus=50, N3: surplus=0
        // N1: deficit=30, N2: deficit=20
        // Deficit nodes (outbound sum == 0) should have all zero rates
        for nid in 0..4 {
            let outbound: u64 = (0..4).map(|dst| result.rates[nid][dst]).sum();
            if outbound == 0 {
                for dst in 0..4 {
                    assert_eq!(
                        result.rates[nid][dst], 0,
                        "deficit node {} has non-zero rate to {}",
                        nid, dst
                    );
                }
            }
        }
    }

    // =====================================================================
    // Edge cases
    // =====================================================================

    #[test]
    fn test_rates_zero_duty_everywhere() {
        let duty = vec![0.0, 0.0];
        let allocs = vec![96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        for src in 0..2 {
            for dst in 0..2 {
                assert_eq!(result.rates[src][dst], 0);
            }
        }
    }

    #[test]
    fn test_rates_zero_alloc() {
        let duty = vec![50.0, 50.0];
        let allocs = vec![0, 0];
        let result = xnuma_compute_rates(&duty, &allocs);

        // total_alloc = 0 → early return with all zeros
        for src in 0..2 {
            for dst in 0..2 {
                assert_eq!(result.rates[src][dst], 0);
            }
        }
    }

    #[test]
    fn test_rates_all_load_one_node() {
        // All duty on N0, nothing on N1
        // allocs: 96 each, duty: N0=96, N1=0
        // eq_ratio = 96/192 = 0.5
        // N0: expected=48, surplus=48
        // N1: expected=48, deficit=48
        let duty = vec![96.0, 0.0];
        let allocs = vec![96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        let expected_rate = (48.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        assert_eq!(result.rates[0][1], expected_rate);
    }

    #[test]
    fn test_rates_single_node() {
        // Single node — balanced by definition
        let duty = vec![96.0];
        let allocs = vec![96];
        let result = xnuma_compute_rates(&duty, &allocs);

        assert_eq!(result.rates[0][0], 0);
    }

    #[test]
    fn test_rates_one_node_zero_alloc() {
        // N0 has allocation, N1 has zero
        // eq_ratio = 80/96
        // N0: expected=80, surplus=0 → balanced
        // N1: expected=0, deficit=0 → zero alloc skipped effectively
        let duty = vec![80.0, 0.0];
        let allocs = vec![96, 0];
        let result = xnuma_compute_rates(&duty, &allocs);

        // N0: surplus = 80 - (80/96 * 96) = 0
        // N1: deficit = (80/96 * 0) - 0 = 0
        // All zeros — nothing to migrate
        assert_eq!(result.rates[0][1], 0);
        assert_eq!(result.rates[1][0], 0);
    }

    // =====================================================================
    // Rate magnitude and scaling
    // =====================================================================

    #[test]
    fn test_rate_scaling() {
        // Verify rates are in DUTY_CYCLE_SCALE units
        let duty = vec![80.0, 40.0];
        let allocs = vec![96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // surplus = 20, deficit = 20 → migration = 20 * DAMPEN = 10
        // rate = 10 * (1 << 20)
        let expected = (20.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
        assert_eq!(result.rates[0][1], expected);
        assert_eq!(expected, 10 * (1 << 20));
    }

    #[test]
    fn test_rates_tiny_imbalance() {
        // Very small imbalance — should still produce non-zero rate
        let duty = vec![48.001, 47.999];
        let allocs = vec![96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // surplus ≈ 0.001, rate ≈ 0.001 * 2^20 ≈ 1048
        assert!(result.rates[0][1] > 0);
        assert!(result.rates[0][1] < (1 << 20)); // Less than 1.0 CPU worth
    }

    #[test]
    fn test_rates_large_values() {
        // Large system: 8 nodes, 96 CPUs each
        let duty = vec![300.0, 100.0, 50.0, 50.0, 50.0, 50.0, 50.0, 50.0];
        let allocs = vec![96, 96, 96, 96, 96, 96, 96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // eq_ratio = 700/768 ≈ 0.911. N0 surplus=212.5, N1 surplus=12.5
        // N2-N7 deficit=37.5 each. N0 and N1 have surplus.
        assert!(result.rates[0][2] > 0); // N0 → N2 (deficit node)
        assert!(result.rates[1][2] > 0); // N1 → N2 (N1 also has surplus)

        // Verify conservation: per-source outbound ≈ surplus * DAMPEN (within
        // truncation tolerance — each `as u64` can lose up to 1 per cell)
        let total_duty: f64 = duty.iter().sum();
        let total_alloc: f64 = allocs.iter().map(|&a| a as f64).sum();
        let eq_ratio = total_duty / total_alloc;
        let nr = 8;
        for src in 0..nr {
            let surplus = (duty[src] - eq_ratio * allocs[src] as f64).max(0.0);
            let outbound: u64 = (0..nr).map(|dst| result.rates[src][dst]).sum();
            let expected = (surplus * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64;
            let tolerance = nr as u64; // up to 1 per destination cell
            assert!(
                outbound.abs_diff(expected) <= tolerance,
                "node {} outbound {} vs expected {}, diff {}",
                src,
                outbound,
                expected,
                outbound.abs_diff(expected)
            );
        }
    }

    // =====================================================================
    // Hysteresis integration
    // =====================================================================

    #[test]
    fn test_hysteresis_cycle() {
        let allocs = vec![96, 96];
        let gd = vec![true, false]; // N0 growth denied

        // Start: all closed, low load
        let active =
            xnuma_check_active(&[40.0, 40.0], &allocs, THRESH, DELTA, &gd, &[false, false]);
        assert!(!active[0]); // load 0.42 < 0.6(lo) → deactivate

        // N0 overloaded + imbalanced + gd → opens
        let active =
            xnuma_check_active(&[90.0, 20.0], &allocs, THRESH, DELTA, &gd, &[false, false]);
        assert!(active[0]); // load 0.94>0.7, surplus=35, ratio=0.365>0.3, gd=true

        // Load decreases but in hysteresis band → stays open
        let active = xnuma_check_active(&[75.0, 20.0], &allocs, THRESH, DELTA, &gd, &[true, false]);
        assert!(active[0]); // load 0.78 between 0.6 and 0.7, surplus ok, gd → preserve

        // Load drops below low threshold → closes
        let active = xnuma_check_active(&[50.0, 50.0], &allocs, THRESH, DELTA, &gd, &[true, false]);
        assert!(!active[0]); // load 0.52 < 0.6(lo) → deactivate
    }

    #[test]
    fn test_hysteresis_growth_toggle() {
        // N0 was open, then growth succeeds → closes
        let allocs = vec![96, 96];
        let gd_denied = vec![true, false];
        let gd_ok = vec![false, false];

        // Active with growth denied
        let active = xnuma_check_active(
            &[90.0, 20.0],
            &allocs,
            THRESH,
            DELTA,
            &gd_denied,
            &[false, false],
        );
        assert!(active[0]);

        // Growth succeeds → !gd → deactivate
        let active = xnuma_check_active(
            &[90.0, 20.0],
            &allocs,
            THRESH,
            DELTA,
            &gd_ok,
            &[true, false],
        );
        assert!(!active[0]); // !growth_denied → deactivate
    }

    // =====================================================================
    // Proportional distribution to multiple sinks
    // =====================================================================

    #[test]
    fn test_proportional_sink_distribution() {
        // 4 nodes: N0 source, N1-N3 sinks with different deficits
        // allocs: 96 each, duty: N0=180, N1=20, N2=40, N3=0
        // total = 240, eq_ratio = 240/384 = 0.625
        // N0: expected=60, surplus=120
        // N1: expected=60, deficit=40
        // N2: expected=60, deficit=20
        // N3: expected=60, deficit=60
        // total_deficit = 120
        let duty = vec![180.0, 20.0, 40.0, 0.0];
        let allocs = vec![96, 96, 96, 96];
        let result = xnuma_compute_rates(&duty, &allocs);

        // rate[0][1] = 120 * 40/120 * DAMPEN = 20
        // rate[0][2] = 120 * 20/120 * DAMPEN = 10
        // rate[0][3] = 120 * 60/120 * DAMPEN = 30
        assert_eq!(
            result.rates[0][1],
            (40.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64
        );
        assert_eq!(
            result.rates[0][2],
            (20.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64
        );
        assert_eq!(
            result.rates[0][3],
            (60.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64
        );

        // Total outbound from N0 = 20 + 10 + 30 = 60 (half of surplus, dampened)
        let total_from_n0: u64 = (0..4).map(|dst| result.rates[0][dst]).sum();
        assert_eq!(
            total_from_n0,
            (120.0 * XNUMA_RATE_DAMPEN * DUTY_CYCLE_SCALE) as u64
        );
    }
}

#[cfg(test)]
mod util_compensation_tests {
    /// Compute the scale factor: s = Δt / (Δt - irq - softirq - stolen)
    fn compute_scale(delta_total: u64, overhead: u64) -> f64 {
        let available = delta_total.saturating_sub(overhead);
        if available > 0 {
            (delta_total as f64 / available as f64).clamp(1.0, 20.0)
        } else {
            1.0
        }
    }

    /// Simulate the per-CPU-scaled aggregation that refresh() does.
    fn scaled_aggregate(
        deltas: &[Vec<u64>],
        scales: &[f64],
        nr_layers: usize,
        elapsed: f64,
    ) -> Vec<f64> {
        (0..nr_layers)
            .map(|layer| {
                let mut sum = 0.0f64;
                for (cpu, cpu_deltas) in deltas.iter().enumerate() {
                    sum += cpu_deltas[layer] as f64 * scales[cpu];
                }
                sum / 1_000_000_000.0 / elapsed
            })
            .collect()
    }

    #[test]
    fn test_scale_no_overhead() {
        // No irq/softirq/stolen → scale = 1.0
        assert!((compute_scale(1000, 0) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_scale_half_overhead() {
        // 50% overhead → s = 1000/500 = 2.0
        assert!((compute_scale(1000, 500) - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_scale_high_overhead() {
        // 90% overhead → s = 1000/100 = 10.0
        assert!((compute_scale(1000, 900) - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_scale_very_high_overhead() {
        // 95% overhead → s = 1000/50 = 20.0 (at clamp boundary)
        assert!((compute_scale(1000, 950) - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_scale_clamped_at_max() {
        // 98% overhead → ratio = 50.0, clamped to 20.0
        assert!((compute_scale(1000, 980) - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_scale_all_overhead() {
        // 100% overhead → available = 0, returns 1.0
        assert!((compute_scale(1000, 1000) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_scale_idle_cpu() {
        // Idle CPU: delta_total = 0 → returns 1.0
        assert!((compute_scale(0, 0) - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_scale_small_overhead_mostly_idle() {
        // 1% softirq + 1% user + 98% idle = total 10000, overhead 100
        // s = 10000 / 9900 ≈ 1.01 — nearly 1.0, not pathological
        let s = compute_scale(10000, 100);
        assert!((s - 1.01).abs() < 0.01, "expected ~1.01, got {}", s);
    }

    #[test]
    fn test_uniform_scale_matches_unscaled() {
        let deltas = vec![vec![1_000_000_000u64; 2]; 4];
        let scales = vec![1.0; 4];
        let result = scaled_aggregate(&deltas, &scales, 2, 1.0);
        assert!((result[0] - 4.0).abs() < 0.01);
        assert!((result[1] - 4.0).abs() < 0.01);
    }

    #[test]
    fn test_hot_cpu_weighted_more() {
        // CPU 0: scale=2.0, CPU 1: scale=1.0
        // Layer 0: 900ms on CPU 0, 100ms on CPU 1
        // Compensated: 900*2.0 + 100*1.0 = 1900ms = 1.9
        let deltas = vec![vec![900_000_000, 0], vec![100_000_000, 0]];
        let scales = vec![2.0, 1.0];
        let result = scaled_aggregate(&deltas, &scales, 2, 1.0);
        assert!(
            (result[0] - 1.9).abs() < 0.01,
            "expected 1.9, got {}",
            result[0]
        );
    }

    #[test]
    fn test_cold_cpu_weighted_less() {
        let deltas = vec![vec![100_000_000, 0], vec![900_000_000, 0]];
        let scales = vec![2.0, 1.0];
        let result = scaled_aggregate(&deltas, &scales, 2, 1.0);
        assert!(
            (result[0] - 1.1).abs() < 0.01,
            "expected 1.1, got {}",
            result[0]
        );
    }

    #[test]
    fn test_no_usage_no_compensation() {
        let deltas = vec![vec![0u64; 2]; 4];
        let scales = vec![5.0; 4];
        let result = scaled_aggregate(&deltas, &scales, 2, 1.0);
        assert_eq!(result[0], 0.0);
        assert_eq!(result[1], 0.0);
    }

    #[test]
    fn test_multilayer_independent_scaling() {
        let deltas = vec![
            vec![800_000_000, 200_000_000],
            vec![200_000_000, 800_000_000],
        ];
        let scales = vec![3.0, 1.0];
        let result = scaled_aggregate(&deltas, &scales, 2, 1.0);
        assert!((result[0] - 2.6).abs() < 0.01);
        assert!((result[1] - 1.4).abs() < 0.01);
    }

    #[test]
    fn test_elapsed_time_normalization() {
        let deltas = vec![vec![500_000_000u64; 1]; 1];
        let scales = vec![1.0];
        let result = scaled_aggregate(&deltas, &scales, 1, 2.0);
        assert!((result[0] - 0.25).abs() < 0.01);
    }

    #[test]
    fn test_many_cpus_mixed_scales() {
        let deltas = vec![vec![1_000_000_000u64; 1]; 8];
        let scales = vec![2.5, 1.0, 2.5, 1.0, 2.5, 1.0, 2.5, 1.0];
        let result = scaled_aggregate(&deltas, &scales, 1, 1.0);
        assert!((result[0] - 14.0).abs() < 0.01);
    }

    #[test]
    fn test_compensated_ge_raw() {
        // Since scale >= 1.0 always, compensated >= raw for any input.
        let deltas = vec![
            vec![500_000_000u64; 3],
            vec![300_000_000; 3],
            vec![200_000_000; 3],
        ];
        let scales_raw = vec![1.0; 3];
        let scales_comp = vec![1.5, 2.0, 1.0];
        let raw = scaled_aggregate(&deltas, &scales_raw, 3, 1.0);
        let comp = scaled_aggregate(&deltas, &scales_comp, 3, 1.0);
        for i in 0..3 {
            assert!(
                comp[i] >= raw[i] - 0.001,
                "layer {}: comp {} < raw {}",
                i,
                comp[i],
                raw[i]
            );
        }
    }
}
