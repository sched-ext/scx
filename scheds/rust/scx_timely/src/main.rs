// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::ffi::{c_int, c_ulong};
use std::fmt::Write;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::warn;
use log::{debug, info};
use scx_stats::prelude::*;
use scx_utils::autopower::{fetch_power_profile, PowerProfile};
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::pm::{cpu_idle_resume_latency_supported, update_cpu_idle_resume_latency};
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_timely";
const DEFAULT_SLICE_US: u64 = 1000;
const DEFAULT_SLICE_MIN_US: u64 = 0;
const DEFAULT_SLICE_US_LAG: u64 = 40000;
const DEFAULT_THROTTLE_US: u64 = 0;
const DEFAULT_IDLE_RESUME_US: i64 = -1;
const DEFAULT_PRIMARY_DOMAIN: &str = "auto";
const DEFAULT_TIMELY_TLOW_US: u64 = 1_000;
const DEFAULT_TIMELY_THIGH_US: u64 = 2_000;
const DEFAULT_TIMELY_GAIN_MIN_FP: u32 = 320;
const DEFAULT_TIMELY_GAIN_STEP_FP: u32 = 64;
const DEFAULT_TIMELY_HAI_THRESHOLD: u32 = 5;
const DEFAULT_TIMELY_HAI_MULTIPLIER: u32 = 5;
const DEFAULT_TIMELY_BACKOFF_HIGH_FP: u32 = 960;
const DEFAULT_TIMELY_BACKOFF_GRADIENT_FP: u32 = 992;
const DEFAULT_TIMELY_GRADIENT_MARGIN_US: u64 = 187;
const DEFAULT_TIMELY_CONTROL_INTERVAL_US: u64 = 500;
const DEFAULT_V2_LOCALITY_WAKEUP_FREQ: u64 = 8;
const DEFAULT_V2_LOCALITY_MAX_CPUQ: u64 = 0;
const DEFAULT_V2_LOCALITY_CONGESTED_NODEQ: u64 = 2;
const DEFAULT_V2_LOCALITY_CONGESTED_MAX_CPUQ: u64 = 1;
const DEFAULT_V2_LOCAL_HEAD_BIAS_SLACK_US: u64 = 250;
const DEFAULT_V2_PRESSURE_ENTER_STREAK: u32 = 3;
const DEFAULT_V2_PRESSURE_EXIT_STREAK: u32 = 3;
const DEFAULT_V2_EXPAND_THRESHOLD: u32 = 75;
const DEFAULT_V2_CONTRACT_THRESHOLD: u32 = 50;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum TimelyMode {
    Desktop,
    Powersave,
    Server,
}

#[derive(Clone, Debug)]
struct EffectiveConfig {
    mode: TimelyMode,
    slice_us: u64,
    slice_min_us: u64,
    slice_us_lag: u64,
    timely_tlow_us: u64,
    timely_thigh_us: u64,
    timely_gain_min_fp: u32,
    timely_gain_step_fp: u32,
    timely_hai_threshold: u32,
    timely_hai_multiplier: u32,
    timely_backoff_high_fp: u32,
    timely_backoff_gradient_fp: u32,
    timely_gradient_margin_us: u64,
    timely_control_interval_us: u64,
    v2_locality_fallback: bool,
    v2_locality_wakeup_freq: u64,
    v2_locality_max_cpuq: u64,
    v2_locality_congested_nodeq: u64,
    v2_locality_congested_max_cpuq: u64,
    v2_local_head_bias: bool,
    v2_local_head_bias_slack_us: u64,
    v2_pressure_enter_streak: u32,
    v2_pressure_exit_streak: u32,
    v2_expand_threshold: u32,
    v2_contract_threshold: u32,
    throttle_us: u64,
    idle_resume_us: i64,
    primary_domain: String,
    preferred_idle_scan: bool,
    local_pcpu: bool,
    local_kthreads: bool,
    sticky_tasks: bool,
    no_wake_sync: bool,
    cpufreq: bool,
}

impl EffectiveConfig {
    fn from_opts(opts: &Opts) -> Self {
        let mut config = match opts.mode {
            TimelyMode::Desktop => Self {
                mode: opts.mode,
                slice_us: DEFAULT_SLICE_US,
                slice_min_us: DEFAULT_SLICE_MIN_US,
                slice_us_lag: DEFAULT_SLICE_US_LAG,
                timely_tlow_us: DEFAULT_TIMELY_TLOW_US,
                timely_thigh_us: DEFAULT_TIMELY_THIGH_US,
                timely_gain_min_fp: DEFAULT_TIMELY_GAIN_MIN_FP,
                timely_gain_step_fp: DEFAULT_TIMELY_GAIN_STEP_FP,
                timely_hai_threshold: DEFAULT_TIMELY_HAI_THRESHOLD,
                timely_hai_multiplier: DEFAULT_TIMELY_HAI_MULTIPLIER,
                timely_backoff_high_fp: DEFAULT_TIMELY_BACKOFF_HIGH_FP,
                timely_backoff_gradient_fp: DEFAULT_TIMELY_BACKOFF_GRADIENT_FP,
                timely_gradient_margin_us: DEFAULT_TIMELY_GRADIENT_MARGIN_US,
                timely_control_interval_us: DEFAULT_TIMELY_CONTROL_INTERVAL_US,
                v2_locality_fallback: true,
                v2_locality_wakeup_freq: DEFAULT_V2_LOCALITY_WAKEUP_FREQ,
                v2_locality_max_cpuq: DEFAULT_V2_LOCALITY_MAX_CPUQ,
                v2_locality_congested_nodeq: DEFAULT_V2_LOCALITY_CONGESTED_NODEQ,
                v2_locality_congested_max_cpuq: DEFAULT_V2_LOCALITY_CONGESTED_MAX_CPUQ,
                v2_local_head_bias: true,
                v2_local_head_bias_slack_us: DEFAULT_V2_LOCAL_HEAD_BIAS_SLACK_US,
                v2_pressure_enter_streak: DEFAULT_V2_PRESSURE_ENTER_STREAK,
                v2_pressure_exit_streak: DEFAULT_V2_PRESSURE_EXIT_STREAK,
                v2_expand_threshold: DEFAULT_V2_EXPAND_THRESHOLD,
                v2_contract_threshold: DEFAULT_V2_CONTRACT_THRESHOLD,
                throttle_us: DEFAULT_THROTTLE_US,
                idle_resume_us: DEFAULT_IDLE_RESUME_US,
                primary_domain: DEFAULT_PRIMARY_DOMAIN.into(),
                preferred_idle_scan: true,
                local_pcpu: false,
                local_kthreads: false,
                sticky_tasks: false,
                no_wake_sync: false,
                cpufreq: false,
            },
            TimelyMode::Powersave => Self {
                mode: opts.mode,
                slice_us: 1500,
                slice_min_us: 500,
                slice_us_lag: 20000,
                timely_tlow_us: 2_000,
                timely_thigh_us: 4_500,
                timely_gain_min_fp: 320,
                timely_gain_step_fp: 40,
                timely_hai_threshold: 6,
                timely_hai_multiplier: 4,
                timely_backoff_high_fp: 976,
                timely_backoff_gradient_fp: 1000,
                timely_gradient_margin_us: 500,
                timely_control_interval_us: 1250,
                v2_locality_fallback: false,
                v2_locality_wakeup_freq: DEFAULT_V2_LOCALITY_WAKEUP_FREQ,
                v2_locality_max_cpuq: DEFAULT_V2_LOCALITY_MAX_CPUQ,
                v2_locality_congested_nodeq: 0,
                v2_locality_congested_max_cpuq: 0,
                v2_local_head_bias: false,
                v2_local_head_bias_slack_us: DEFAULT_V2_LOCAL_HEAD_BIAS_SLACK_US,
                v2_pressure_enter_streak: 4,
                v2_pressure_exit_streak: 4,
                v2_expand_threshold: 65,
                v2_contract_threshold: 40,
                throttle_us: 100,
                idle_resume_us: 5000,
                primary_domain: "powersave".into(),
                preferred_idle_scan: false,
                local_pcpu: false,
                local_kthreads: false,
                sticky_tasks: false,
                no_wake_sync: false,
                cpufreq: true,
            },
            TimelyMode::Server => Self {
                mode: opts.mode,
                slice_us: 2000,
                slice_min_us: 250,
                slice_us_lag: 80000,
                timely_tlow_us: 1_500,
                timely_thigh_us: 3_000,
                timely_gain_min_fp: 256,
                timely_gain_step_fp: 32,
                timely_hai_threshold: DEFAULT_TIMELY_HAI_THRESHOLD,
                timely_hai_multiplier: DEFAULT_TIMELY_HAI_MULTIPLIER,
                timely_backoff_high_fp: 960,
                timely_backoff_gradient_fp: 992,
                timely_gradient_margin_us: 187,
                timely_control_interval_us: 750,
                v2_locality_fallback: false,
                v2_locality_wakeup_freq: DEFAULT_V2_LOCALITY_WAKEUP_FREQ,
                v2_locality_max_cpuq: DEFAULT_V2_LOCALITY_MAX_CPUQ,
                v2_locality_congested_nodeq: 0,
                v2_locality_congested_max_cpuq: 0,
                v2_local_head_bias: false,
                v2_local_head_bias_slack_us: DEFAULT_V2_LOCAL_HEAD_BIAS_SLACK_US,
                v2_pressure_enter_streak: 2,
                v2_pressure_exit_streak: 2,
                v2_expand_threshold: 80,
                v2_contract_threshold: 55,
                throttle_us: 0,
                idle_resume_us: DEFAULT_IDLE_RESUME_US,
                primary_domain: "all".into(),
                preferred_idle_scan: false,
                local_pcpu: true,
                local_kthreads: true,
                sticky_tasks: true,
                no_wake_sync: false,
                cpufreq: false,
            },
        };

        if opts.slice_us != DEFAULT_SLICE_US {
            config.slice_us = opts.slice_us;
        }
        if opts.slice_min_us != DEFAULT_SLICE_MIN_US {
            config.slice_min_us = opts.slice_min_us;
        }
        if opts.slice_us_lag != DEFAULT_SLICE_US_LAG {
            config.slice_us_lag = opts.slice_us_lag;
        }
        if opts.delay_target_us != 0 {
            config.timely_thigh_us = opts.delay_target_us;
            config.timely_tlow_us = std::cmp::max(opts.delay_target_us / 2, 1);
        }
        if opts.timely_tlow_us != 0 {
            config.timely_tlow_us = opts.timely_tlow_us;
        }
        if opts.timely_thigh_us != 0 {
            config.timely_thigh_us = opts.timely_thigh_us;
        }
        if opts.timely_gain_min_fp != 0 {
            config.timely_gain_min_fp = opts.timely_gain_min_fp;
        }
        if opts.timely_gain_step_fp != 0 {
            config.timely_gain_step_fp = opts.timely_gain_step_fp;
        }
        if opts.timely_hai_threshold != 0 {
            config.timely_hai_threshold = opts.timely_hai_threshold;
        }
        if opts.timely_hai_multiplier != 0 {
            config.timely_hai_multiplier = opts.timely_hai_multiplier;
        }
        if opts.timely_backoff_high_fp != 0 {
            config.timely_backoff_high_fp = opts.timely_backoff_high_fp;
        }
        if opts.timely_backoff_gradient_fp != 0 {
            config.timely_backoff_gradient_fp = opts.timely_backoff_gradient_fp;
        }
        if opts.timely_gradient_margin_us != 0 {
            config.timely_gradient_margin_us = opts.timely_gradient_margin_us;
        }
        if opts.timely_control_interval_us != 0 {
            config.timely_control_interval_us = opts.timely_control_interval_us;
        }
        if opts.v2_locality_wakeup_freq != 0 {
            config.v2_locality_wakeup_freq = opts.v2_locality_wakeup_freq;
        }
        if opts.v2_locality_max_cpuq != DEFAULT_V2_LOCALITY_MAX_CPUQ {
            config.v2_locality_max_cpuq = opts.v2_locality_max_cpuq;
        }
        if opts.v2_locality_congested_nodeq != 0 {
            config.v2_locality_congested_nodeq = opts.v2_locality_congested_nodeq;
        }
        if opts.v2_locality_congested_max_cpuq != 0 {
            config.v2_locality_congested_max_cpuq = opts.v2_locality_congested_max_cpuq;
        }
        if opts.v2_local_head_bias_slack_us != 0 {
            config.v2_local_head_bias_slack_us = opts.v2_local_head_bias_slack_us;
        }
        if opts.v2_pressure_enter_streak != 0 {
            config.v2_pressure_enter_streak = opts.v2_pressure_enter_streak;
        }
        if opts.v2_pressure_exit_streak != 0 {
            config.v2_pressure_exit_streak = opts.v2_pressure_exit_streak;
        }
        if opts.v2_expand_threshold != 0 {
            config.v2_expand_threshold = opts.v2_expand_threshold;
        }
        if opts.v2_contract_threshold != 0 {
            config.v2_contract_threshold = opts.v2_contract_threshold;
        }
        if opts.throttle_us != DEFAULT_THROTTLE_US {
            config.throttle_us = opts.throttle_us;
        }
        if opts.idle_resume_us != DEFAULT_IDLE_RESUME_US {
            config.idle_resume_us = opts.idle_resume_us;
        }
        if opts.primary_domain != DEFAULT_PRIMARY_DOMAIN {
            config.primary_domain = opts.primary_domain.clone();
        }

        if config.timely_tlow_us >= config.timely_thigh_us {
            config.timely_tlow_us = std::cmp::max(config.timely_thigh_us / 2, 1);
        }

        config.v2_locality_fallback |= opts.v2_locality_fallback;
        config.v2_local_head_bias |= opts.v2_local_head_bias;
        config.preferred_idle_scan |= opts.preferred_idle_scan;
        config.local_pcpu |= opts.local_pcpu;
        config.local_kthreads |= opts.local_kthreads;
        config.sticky_tasks |= opts.sticky_tasks;
        config.no_wake_sync |= opts.no_wake_sync;
        config.cpufreq |= opts.cpufreq;

        config
    }
}

#[derive(PartialEq)]
enum Powermode {
    Turbo,
    Performance,
    Powersave,
    Any,
}

fn get_primary_cpus(mode: Powermode) -> std::io::Result<Vec<usize>> {
    let topo = Topology::new().unwrap();

    let cpus: Vec<usize> = topo
        .all_cores
        .values()
        .flat_map(|core| &core.cpus)
        .filter_map(|(cpu_id, cpu)| match (&mode, &cpu.core_type) {
            // Performance mode: add all the Big CPUs (either Turbo or non-Turbo)
            (Powermode::Performance, CoreType::Big { .. }) |
            // Powersave mode: add all the Little CPUs
            (Powermode::Powersave, CoreType::Little) => Some(*cpu_id),
            (Powermode::Any, ..) => Some(*cpu_id),
            _ => None,
        })
        .collect();

    Ok(cpus)
}

// Convert an array of CPUs to the corresponding cpumask of any arbitrary size.
fn cpus_to_cpumask(cpus: &Vec<usize>) -> String {
    if cpus.is_empty() {
        return String::from("none");
    }

    // Determine the maximum CPU ID to create a sufficiently large byte vector.
    let max_cpu_id = *cpus.iter().max().unwrap();

    // Create a byte vector with enough bytes to cover all CPU IDs.
    let mut bitmask = vec![0u8; max_cpu_id.div_ceil(8)];

    // Set the appropriate bits for each CPU ID.
    for cpu_id in cpus {
        let byte_index = cpu_id / 8;
        let bit_index = cpu_id % 8;
        bitmask[byte_index] |= 1 << bit_index;
    }

    // Convert the byte vector to a hexadecimal string.
    let hex_str: String = bitmask.iter().rev().fold(String::new(), |mut f, byte| {
        let _ = write!(&mut f, "{:02x}", byte);
        f
    });

    format!("0x{}", hex_str)
}

/// scx_timely: a BPF-first sched_ext scheduler bootstrapped from scx_bpfland.
///
/// The current tree intentionally stays close to upstream bpfland behavior so
/// the standalone repo keeps a small, buildable, reviewer-safe base while the
/// TIMELY-inspired control layer is adapted on top.
#[derive(Debug, Parser)]
struct Opts {
    /// Select a high-level scheduler mode.
    #[clap(long, value_enum, default_value = "desktop")]
    mode: TimelyMode,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Maximum scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "1000")]
    slice_us: u64,

    /// Minimum scheduling slice duration in microseconds (0 = no minimum time slice).
    #[clap(short = 'L', long, default_value = "0")]
    slice_min_us: u64,

    /// Maximum time slice lag in microseconds.
    ///
    /// A positive value can help to enhance the responsiveness of interactive tasks, but it can
    /// also make performance more "spikey".
    #[clap(short = 'l', long, default_value = "40000")]
    slice_us_lag: u64,

    /// Legacy shorthand for the TIMELY high-delay threshold in microseconds (0 = mode default).
    ///
    /// If set, this also resets the low-delay threshold to half of the provided value unless
    /// --timely-tlow-us is explicitly provided.
    #[clap(long, default_value = "0")]
    delay_target_us: u64,

    /// TIMELY low-delay threshold in microseconds (0 = mode default).
    #[clap(long, default_value = "0")]
    timely_tlow_us: u64,

    /// TIMELY high-delay threshold in microseconds (0 = mode default).
    #[clap(long, default_value = "0")]
    timely_thigh_us: u64,

    /// Minimum fixed-point Timely gain floor (0 = mode default, 1024 = 1.0x).
    #[clap(long, default_value = "0")]
    timely_gain_min_fp: u32,

    /// Additive fixed-point gain recovery step (0 = mode default, 1024 = 1.0x).
    #[clap(long, default_value = "0")]
    timely_gain_step_fp: u32,

    /// Consecutive favorable nominal-region samples required before HAI activates (0 = mode default).
    #[clap(long, default_value = "0")]
    timely_hai_threshold: u32,

    /// Additive multiplier applied while HAI is active (0 = mode default).
    #[clap(long, default_value = "0")]
    timely_hai_multiplier: u32,

    /// Multiplicative high-delay backoff factor in fixed-point form (0 = mode default, 1024 = 1.0x).
    #[clap(long, default_value = "0")]
    timely_backoff_high_fp: u32,

    /// Multiplicative rising-gradient backoff factor in fixed-point form (0 = mode default, 1024 = 1.0x).
    #[clap(long, default_value = "0")]
    timely_backoff_gradient_fp: u32,

    /// Delay-gradient trigger margin in microseconds (0 = mode default).
    #[clap(long, default_value = "0")]
    timely_gradient_margin_us: u64,

    /// Minimum time between Timely control updates in microseconds (0 = mode default).
    #[clap(long, default_value = "0")]
    timely_control_interval_us: u64,

    /// Enable the v2 locality fallback.
    ///
    /// When no idle CPU is available, wake-heavy tasks may fall back to prev_cpu's local DSQ
    /// instead of always entering the shared node queue.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    v2_locality_fallback: bool,

    /// Wakeup-frequency threshold for the v2 locality fallback (0 = mode default).
    #[clap(long, default_value = "0")]
    v2_locality_wakeup_freq: u64,

    /// Maximum allowed local per-CPU queue depth for the v2 locality fallback.
    #[clap(long, default_value = "0")]
    v2_locality_max_cpuq: u64,

    /// Minimum shared node-queue depth before the v2 locality fallback broadens under congestion.
    #[clap(long, default_value = "0")]
    v2_locality_congested_nodeq: u64,

    /// Maximum local per-CPU queue depth allowed for the broadened congested-node v2 fallback.
    #[clap(long, default_value = "0")]
    v2_locality_congested_max_cpuq: u64,

    /// Enable a small local-head dispatch bias for wake-heavy work in the per-CPU DSQ.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    v2_local_head_bias: bool,

    /// Maximum deadline slack in microseconds for the v2 local-head bias (0 = mode default).
    #[clap(long, default_value = "0")]
    v2_local_head_bias_slack_us: u64,

    /// Consecutive delay-pressured fresh samples required to enter v2 pressure mode (0 = mode default).
    #[clap(long, default_value = "0")]
    v2_pressure_enter_streak: u32,

    /// Consecutive recovered fresh samples required to exit v2 pressure mode (0 = mode default).
    #[clap(long, default_value = "0")]
    v2_pressure_exit_streak: u32,

    /// v2 expand mode threshold: percentage of primary-domain CPUs with work to trigger expand mode (0 = mode default).
    ///
    /// When the system reaches this saturation level, the scheduler switches from
    /// "contract" (locality-first) to "expand" (balance-first) mode, skipping
    /// the locality fallback and dispatching directly to shared queues for better load distribution.
    #[clap(long, default_value = "0")]
    v2_expand_threshold: u32,

    /// v2 contract mode threshold: percentage of primary-domain CPUs with work to exit expand mode (0 = mode default).
    ///
    /// This should be lower than v2_expand_threshold to create hysteresis and prevent
    /// rapid oscillation between modes.
    #[clap(long, default_value = "0")]
    v2_contract_threshold: u32,

    /// Throttle the running CPUs by periodically injecting idle cycles.
    ///
    /// This option can help extend battery life on portable devices, reduce heating, fan noise
    /// and overall energy consumption (0 = disable).
    #[clap(short = 't', long, default_value = "0")]
    throttle_us: u64,

    /// Set CPU idle QoS resume latency in microseconds (-1 = disabled).
    ///
    /// Setting a lower latency value makes CPUs less likely to enter deeper idle states, enhancing
    /// performance at the cost of higher power consumption. Alternatively, increasing the latency
    /// value may reduce performance, but also improve power efficiency.
    #[clap(short = 'I', long, allow_hyphen_values = true, default_value = "-1")]
    idle_resume_us: i64,

    /// Enable per-CPU tasks prioritization.
    ///
    /// This allows to prioritize per-CPU tasks that usually tend to be de-prioritized (since they
    /// can't be migrated when their only usable CPU is busy). Enabling this option can introduce
    /// unfairness and potentially trigger stalls, but it can improve performance of server-type
    /// workloads (such as large parallel builds).
    #[clap(short = 'p', long, action = clap::ArgAction::SetTrue)]
    local_pcpu: bool,

    /// Enable kthreads prioritization (EXPERIMENTAL).
    ///
    /// Enabling this can improve system performance, but it may also introduce noticeable
    /// interactivity issues or unfairness in scenarios with high kthread activity, such as heavy
    /// I/O or network traffic.
    ///
    /// Use it only when conducting specific experiments or if you have a clear understanding of
    /// its implications.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    local_kthreads: bool,

    /// Disable direct dispatch during synchronous wakeups.
    ///
    /// Enabling this option can lead to a more uniform load distribution across available cores,
    /// potentially improving performance in certain scenarios. However, it may come at the cost of
    /// reduced efficiency for pipe-intensive workloads that benefit from tighter producer-consumer
    /// coupling.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Enable sticky tasks.
    ///
    /// If enabled force tasks with a high rate of enqueues/sec to stay on the same CPU, to reduce
    /// locking contention on the shared runqueues.
    ///
    /// This can help making the scheduler more robust with intensive scheduling workloads and
    /// benchmarks, but it can negatively impact on latency.
    #[clap(short = 'S', long, action = clap::ArgAction::SetTrue)]
    sticky_tasks: bool,

    /// Specifies the initial set of CPUs, represented as a bitmask in hex (e.g., 0xff), that the
    /// scheduler will use to dispatch tasks, until the system becomes saturated, at which point
    /// tasks may overflow to other available CPUs.
    ///
    /// Special values:
    ///  - "auto" = automatically detect the CPUs based on the active power profile
    ///  - "performance" = automatically detect and prioritize the fastest CPUs
    ///  - "powersave" = automatically detect and prioritize the slowest CPUs
    ///  - "all" = all CPUs assigned to the primary domain
    ///  - "none" = no prioritization, tasks are dispatched on the first CPU available
    #[clap(short = 'm', long, default_value = "auto")]
    primary_domain: String,

    /// Enable preferred idle CPU scanning.
    ///
    /// With this option enabled, the scheduler will prioritize assigning tasks to higher-ranked
    /// cores before considering lower-ranked ones.
    #[clap(short = 'P', long, action = clap::ArgAction::SetTrue)]
    preferred_idle_scan: bool,

    /// Disable SMT awareness.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// Disable NUMA awareness.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Enable CPU frequency control (only with schedutil governor).
    ///
    /// With this option enabled the CPU frequency will be automatically scaled based on the load.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    cpufreq: bool,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable BPF debugging via /sys/kernel/tracing/trace_pipe.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    config: EffectiveConfig,
    topo: Topology,
    power_profile: PowerProfile,
    stats_server: StatsServer<(), Metrics>,
    user_restart: bool,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();
        let config = EffectiveConfig::from_opts(opts);

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = !opts.disable_smt && topo.smt_enabled;

        // Determine the amount of non-empty NUMA nodes in the system.
        let nr_nodes = topo
            .nodes
            .values()
            .filter(|node| !node.all_cpus.is_empty())
            .count();
        info!("NUMA nodes: {}", nr_nodes);

        // Automatically disable NUMA optimizations when running on non-NUMA systems.
        let numa_enabled = !opts.disable_numa && nr_nodes > 1;
        if !numa_enabled {
            info!("Disabling NUMA optimizations");
        }

        // Determine the primary scheduling domain.
        let power_profile = Self::power_profile();
        let domain =
            Self::resolve_energy_domain(&config.primary_domain, power_profile).map_err(|err| {
                anyhow!(
                    "failed to resolve primary domain '{}': {}",
                    &config.primary_domain,
                    err
                )
            })?;

        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );
        info!(
            "mode={:?} slice_us={} slice_min_us={} slice_us_lag={} timely_tlow_us={} timely_thigh_us={} throttle_us={} primary_domain={} cpufreq={}",
            config.mode,
            config.slice_us,
            config.slice_min_us,
            config.slice_us_lag,
            config.timely_tlow_us,
            config.timely_thigh_us,
            config.throttle_us,
            config.primary_domain,
            config.cpufreq
        );
        info!(
            "timely control: tlow_us={} thigh_us={} gain_min_fp={} gain_step_fp={} hai_threshold={} hai_multiplier={} backoff_high_fp={} backoff_gradient_fp={} gradient_margin_us={} control_interval_us={} v2_locality_fallback={} v2_locality_wakeup_freq={} v2_locality_max_cpuq={} v2_locality_congested_nodeq={} v2_locality_congested_max_cpuq={} v2_local_head_bias={} v2_local_head_bias_slack_us={} v2_pressure_enter_streak={} v2_pressure_exit_streak={} v2_expand_threshold={} v2_contract_threshold={}",
            config.timely_tlow_us,
            config.timely_thigh_us,
            config.timely_gain_min_fp,
            config.timely_gain_step_fp,
            config.timely_hai_threshold,
            config.timely_hai_multiplier,
            config.timely_backoff_high_fp,
            config.timely_backoff_gradient_fp,
            config.timely_gradient_margin_us,
            config.timely_control_interval_us,
            config.v2_locality_fallback,
            config.v2_locality_wakeup_freq,
            config.v2_locality_max_cpuq,
            config.v2_locality_congested_nodeq,
            config.v2_locality_congested_max_cpuq,
            config.v2_local_head_bias,
            config.v2_local_head_bias_slack_us,
            config.v2_pressure_enter_streak,
            config.v2_pressure_exit_streak,
            config.v2_expand_threshold,
            config.v2_contract_threshold
        );

        if config.idle_resume_us >= 0 {
            if !cpu_idle_resume_latency_supported() {
                warn!("idle resume latency not supported");
            } else {
                info!("Setting idle QoS to {} us", config.idle_resume_us);
                for cpu in topo.all_cpus.values() {
                    update_cpu_idle_resume_latency(
                        cpu.id,
                        config.idle_resume_us.try_into().unwrap(),
                    )?;
                }
            }
        }

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, timely_ops, open_opts)?;

        skel.struct_ops.timely_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.debug = opts.debug;
        rodata.smt_enabled = smt_enabled;
        rodata.numa_enabled = numa_enabled;
        rodata.local_pcpu = config.local_pcpu;
        rodata.no_wake_sync = config.no_wake_sync;
        rodata.sticky_tasks = config.sticky_tasks;
        rodata.slice_max = config.slice_us * 1000;
        rodata.slice_min = config.slice_min_us * 1000;
        rodata.slice_lag = config.slice_us_lag * 1000;
        rodata.timely_tlow_ns = config.timely_tlow_us * 1000;
        rodata.timely_thigh_ns = config.timely_thigh_us * 1000;
        rodata.timely_gain_min = config.timely_gain_min_fp;
        rodata.timely_gain_step = config.timely_gain_step_fp;
        rodata.timely_hai_threshold = config.timely_hai_threshold;
        rodata.timely_hai_multiplier = config.timely_hai_multiplier;
        rodata.timely_backoff_high_fp = config.timely_backoff_high_fp;
        rodata.timely_backoff_gradient_fp = config.timely_backoff_gradient_fp;
        rodata.timely_gradient_margin_ns = config.timely_gradient_margin_us * 1000;
        rodata.timely_control_interval_ns = config.timely_control_interval_us * 1000;
        rodata.v2_locality_fallback = config.v2_locality_fallback;
        rodata.v2_locality_wakeup_freq = config.v2_locality_wakeup_freq;
        rodata.v2_locality_max_cpuq = config.v2_locality_max_cpuq;
        rodata.v2_locality_congested_nodeq = config.v2_locality_congested_nodeq;
        rodata.v2_locality_congested_max_cpuq = config.v2_locality_congested_max_cpuq;
        rodata.v2_local_head_bias = config.v2_local_head_bias;
        rodata.v2_local_head_bias_slack_ns = config.v2_local_head_bias_slack_us * 1000;
        rodata.v2_pressure_enter_streak = config.v2_pressure_enter_streak;
        rodata.v2_pressure_exit_streak = config.v2_pressure_exit_streak;
        rodata.v2ExpandThreshold = config.v2_expand_threshold;
        rodata.v2ContractThreshold = config.v2_contract_threshold;
        rodata.throttle_ns = config.throttle_us * 1000;
        rodata.primary_all = domain.weight() == *NR_CPU_IDS;

        // Generate the list of available CPUs sorted by capacity in descending order.
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
        for (i, cpu) in cpus.iter().enumerate() {
            rodata.cpu_capacity[cpu.id] = cpu.cpu_capacity as c_ulong;
            rodata.preferred_cpus[i] = cpu.id as u64;
        }
        if config.preferred_idle_scan {
            info!(
                "Preferred CPUs: {:?}",
                &rodata.preferred_cpus[0..cpus.len()]
            );
        }
        rodata.preferred_idle_scan = config.preferred_idle_scan;

        // Implicitly enable direct dispatch of per-CPU kthreads if CPU throttling is enabled
        // (it's never a good idea to throttle per-CPU kthreads).
        rodata.local_kthreads = config.local_kthreads || config.throttle_us > 0;

        // Set scheduler flags.
        skel.struct_ops.timely_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | if numa_enabled {
                *compat::SCX_OPS_BUILTIN_IDLE_PER_NODE
            } else {
                0
            };
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.timely_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, timely_ops, uei)?;

        // Initialize the primary scheduling domain.
        Self::init_energy_domain(&mut skel, &domain).map_err(|err| {
            anyhow!(
                "failed to initialize primary domain 0x{:x}: {}",
                domain,
                err
            )
        })?;

        // Initialize CPU frequency scaling.
        if let Err(err) = Self::init_cpufreq_perf(&mut skel, &config.primary_domain, config.cpufreq)
        {
            bail!(
                "failed to initialize cpufreq performance level: error {}",
                err
            );
        }

        // Initialize SMT domains.
        if smt_enabled {
            Self::init_smt_domains(&mut skel, &topo)?;
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, timely_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            config,
            topo,
            power_profile,
            stats_server,
            user_restart: false,
        })
    }

    fn enable_primary_cpu(skel: &mut BpfSkel<'_>, cpu: i32) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_primary_cpu;
        let mut args = cpu_arg {
            cpu_id: cpu as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn epp_to_cpumask(profile: Powermode) -> Result<Cpumask> {
        let mut cpus = get_primary_cpus(profile).unwrap_or_default();
        if cpus.is_empty() {
            cpus = get_primary_cpus(Powermode::Any).unwrap_or_default();
        }
        Cpumask::from_str(&cpus_to_cpumask(&cpus))
    }

    fn resolve_energy_domain(primary_domain: &str, power_profile: PowerProfile) -> Result<Cpumask> {
        let domain = match primary_domain {
            "powersave" => Self::epp_to_cpumask(Powermode::Powersave)?,
            "performance" => Self::epp_to_cpumask(Powermode::Performance)?,
            "turbo" => Self::epp_to_cpumask(Powermode::Turbo)?,
            "auto" => match power_profile {
                PowerProfile::Powersave => Self::epp_to_cpumask(Powermode::Powersave)?,
                PowerProfile::Balanced { .. }
                | PowerProfile::Performance
                | PowerProfile::Unknown => Self::epp_to_cpumask(Powermode::Any)?,
            },
            "all" => Self::epp_to_cpumask(Powermode::Any)?,
            &_ => Cpumask::from_str(primary_domain)?,
        };

        Ok(domain)
    }

    fn init_energy_domain(skel: &mut BpfSkel<'_>, domain: &Cpumask) -> Result<()> {
        info!("primary CPU domain = 0x{:x}", domain);

        // Clear the primary domain by passing a negative CPU id.
        if let Err(err) = Self::enable_primary_cpu(skel, -1) {
            bail!("failed to reset primary domain: error {}", err);
        }

        // Update primary scheduling domain.
        for cpu in 0..*NR_CPU_IDS {
            if domain.test_cpu(cpu) {
                if let Err(err) = Self::enable_primary_cpu(skel, cpu as i32) {
                    bail!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        Ok(())
    }

    // Update hint for the cpufreq governor.
    fn init_cpufreq_perf(skel: &mut BpfSkel<'_>, primary_domain: &str, auto: bool) -> Result<()> {
        // If we are using the powersave profile always scale the CPU frequency to the minimum,
        // otherwise use the maximum, unless automatic frequency scaling is enabled.
        let perf_lvl: i64 = match primary_domain {
            "powersave" => 0,
            _ if auto => -1,
            _ => 1024,
        };
        info!(
            "cpufreq performance level: {}",
            match perf_lvl {
                1024 => "max".into(),
                0 => "min".into(),
                n if n < 0 => "auto".into(),
                _ => perf_lvl.to_string(),
            }
        );
        skel.maps.bss_data.as_mut().unwrap().cpufreq_perf_lvl = perf_lvl;

        Ok(())
    }

    fn power_profile() -> PowerProfile {
        let profile = fetch_power_profile(true);
        if profile == PowerProfile::Unknown {
            fetch_power_profile(false)
        } else {
            profile
        }
    }

    fn refresh_sched_domain(&mut self) -> bool {
        if self.power_profile != PowerProfile::Unknown {
            let power_profile = Self::power_profile();
            if power_profile != self.power_profile {
                self.power_profile = power_profile;

                if self.config.primary_domain == "auto" {
                    return true;
                }
                if let Err(err) = Self::init_cpufreq_perf(
                    &mut self.skel,
                    &self.config.primary_domain,
                    self.config.cpufreq,
                ) {
                    warn!("failed to refresh cpufreq performance level: error {}", err);
                }
            }
        }

        false
    }

    fn enable_sibling_cpu(
        skel: &mut BpfSkel<'_>,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            cpu_id: cpu as c_int,
            sibling_cpu_id: sibling_cpu as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn init_smt_domains(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<(), std::io::Error> {
        let smt_siblings = topo.sibling_cpus();

        info!("SMT sibling CPUs: {:?}", smt_siblings);
        for (cpu, sibling_cpu) in smt_siblings.iter().enumerate() {
            Self::enable_sibling_cpu(skel, cpu, *sibling_cpu as usize).unwrap();
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_running: bss_data.nr_running,
            nr_cpus: bss_data.nr_online_cpus,
            nr_kthread_dispatches: bss_data.nr_kthread_dispatches,
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_shared_dispatches: bss_data.nr_shared_dispatches,
            nr_delay_scaled_dispatches: bss_data.nr_delay_scaled_dispatches,
            nr_delay_gradient_dispatches: bss_data.nr_delay_gradient_dispatches,
            nr_delay_recovery_dispatches: bss_data.nr_delay_recovery_dispatches,
            nr_delay_middle_add_dispatches: bss_data.nr_delay_middle_add_dispatches,
            nr_delay_fast_recovery_dispatches: bss_data.nr_delay_fast_recovery_dispatches,
            nr_delay_rate_limited_dispatches: bss_data.nr_delay_rate_limited_dispatches,
            nr_gain_floor_dispatches: bss_data.nr_gain_floor_dispatches,
            nr_gain_ceiling_dispatches: bss_data.nr_gain_ceiling_dispatches,
            nr_delay_low_region_samples: bss_data.nr_delay_low_region_samples,
            nr_delay_mid_region_samples: bss_data.nr_delay_mid_region_samples,
            nr_delay_high_region_samples: bss_data.nr_delay_high_region_samples,
            nr_gain_floor_resident_samples: bss_data.nr_gain_floor_resident_samples,
            nr_gain_mid_resident_samples: bss_data.nr_gain_mid_resident_samples,
            nr_gain_ceiling_resident_samples: bss_data.nr_gain_ceiling_resident_samples,
            nr_idle_select_path_picks: bss_data.nr_idle_select_path_picks,
            nr_idle_enqueue_path_picks: bss_data.nr_idle_enqueue_path_picks,
            nr_idle_prev_cpu_picks: bss_data.nr_idle_prev_cpu_picks,
            nr_idle_primary_picks: bss_data.nr_idle_primary_picks,
            nr_idle_spill_picks: bss_data.nr_idle_spill_picks,
            nr_idle_pick_failures: bss_data.nr_idle_pick_failures,
            nr_idle_primary_domain_misses: bss_data.nr_idle_primary_domain_misses,
            nr_idle_global_misses: bss_data.nr_idle_global_misses,
            nr_waker_cpu_biases: bss_data.nr_waker_cpu_biases,
            nr_keep_running_reuses: bss_data.nr_keep_running_reuses,
            nr_keep_running_queue_empty: bss_data.nr_keep_running_queue_empty,
            nr_keep_running_smt_blocked: bss_data.nr_keep_running_smt_blocked,
            nr_keep_running_queued_work: bss_data.nr_keep_running_queued_work,
            nr_dispatch_cpu_dsq_consumes: bss_data.nr_dispatch_cpu_dsq_consumes,
            nr_dispatch_node_dsq_consumes: bss_data.nr_dispatch_node_dsq_consumes,
            nr_v2_locality_cpu_dispatches: bss_data.nr_v2_locality_cpu_dispatches,
            nr_v2_congested_locality_cpu_dispatches: bss_data
                .nr_v2_congested_locality_cpu_dispatches,
            nr_v2_delay_locality_cpu_dispatches: bss_data.nr_v2_delay_locality_cpu_dispatches,
            nr_v2_local_head_biases: bss_data.nr_v2_local_head_biases,
            nr_v2_pressure_mode_entries: bss_data.nr_v2_pressure_mode_entries,
            nr_v2_pressure_mode_exits: bss_data.nr_v2_pressure_mode_exits,
            nr_v2_pressure_shared_dispatches: bss_data.nr_v2_pressure_shared_dispatches,
            nr_v2_expand_mode_dispatches: bss_data.nr_v2_expand_mode_dispatches,
            nr_v2_contract_mode_dispatches: bss_data.nr_v2_contract_mode_dispatches,
            nr_cpu_release_reenqueue: bss_data.nr_cpu_release_reenqueue,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn log_metrics_snapshot(&self, prefix: &str) {
        let metrics = self.get_metrics();
        info!("{prefix}: {}", metrics.summary_line());
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if self.refresh_sched_domain() {
                self.user_restart = true;
                break;
            }
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            self.log_metrics_snapshot("Scheduler metrics at shutdown request");
        } else if self.exited() {
            self.log_metrics_snapshot("Scheduler metrics before exit report");
        } else if self.user_restart {
            self.log_metrics_snapshot("Scheduler metrics before user-requested restart");
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");

        // Restore default CPU idle QoS resume latency.
        if self.config.idle_resume_us >= 0 && cpu_idle_resume_latency_supported() {
            for cpu in self.topo.all_cpus.values() {
                update_cpu_idle_resume_latency(cpu.id, cpu.pm_qos_resume_latency_us as i32)
                    .unwrap();
            }
        }
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

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

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            if sched.user_restart {
                continue;
            }
            break;
        }
    }

    Ok(())
}
