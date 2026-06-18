// SPDX-License-Identifier: GPL-2.0
// scx_cake - CAKE-inspired sched_ext scheduler for low-latency CPU scheduling

mod dump_compare;
#[cfg(debug_assertions)]
mod task_anatomy;
mod telemetry_report;
mod topology;
mod trust;
mod tui;

use core::sync::atomic::Ordering;
#[cfg(all(cake_bpf_release, cake_game_diag))]
use std::ffi::CString;
use std::io::IsTerminal;
#[cfg(all(cake_bpf_release, cake_game_diag))]
use std::os::unix::ffi::OsStrExt;
#[cfg(all(cake_bpf_release, cake_game_diag))]
use std::os::unix::fs::PermissionsExt;
#[cfg(all(cake_bpf_release, cake_game_diag))]
use std::path::Path;
use std::path::PathBuf;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
#[cfg(all(cake_bpf_release, cake_game_diag))]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use log::info;

#[cfg(cake_needs_arena)]
use scx_arena::ArenaLib;
use scx_utils::build_id;
use scx_utils::UserExitInfo;
#[cfg(cake_needs_arena)]
use scx_utils::NR_CPU_IDS;
// Include the generated interface bindings
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
}

// Include the generated BPF skeleton
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}
use bpf_skel::*;

const SCHEDULER_NAME: &str = "scx_cake";

/// Scheduler profile presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    /// Ultra-low-latency for competitive esports (750us quantum)
    Esports,
    /// Low-latency profile optimized for gaming and interactive workloads
    Gaming,
    /// Balanced profile for general desktop use
    Balanced,
    /// Optimized for older/lower-power hardware (4ms quantum)
    Legacy,
}

impl Profile {
    #[cfg(not(cake_bpf_release))]
    fn quantum_us(&self) -> u64 {
        match self {
            Profile::Esports => 750,
            Profile::Gaming => 1000,
            Profile::Balanced => 2000,
            Profile::Legacy => 4000,
        }
    }

    #[cfg(not(cake_bpf_release))]
    fn as_str(&self) -> &'static str {
        match self {
            Profile::Esports => "esports",
            Profile::Gaming => "gaming",
            Profile::Balanced => "balanced",
            Profile::Legacy => "legacy",
        }
    }

    // Older DVFS controls were removed. Profiles currently only select quantum.
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BusyWakeKickMode {
    /// Use Cake's owner-runtime pressure policy.
    Policy = 0,
    /// Always preempt on same-CPU busy wakeups.
    Preempt = 1,
    /// Always use an idle kick on same-CPU busy wakeups.
    Idle = 2,
}

#[cfg(not(cake_bpf_release))]
impl BusyWakeKickMode {
    fn as_str(&self) -> &'static str {
        match self {
            BusyWakeKickMode::Policy => "policy",
            BusyWakeKickMode::Preempt => "preempt",
            BusyWakeKickMode::Idle => "idle",
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StormGuardMode {
    /// Keep the baseline busy-wake policy.
    Off = 0,
    /// Count storm-guard candidates without changing placement.
    Shadow = 1,
    /// Allow conservative extra local busy handoff for saturated owners.
    Shield = 2,
    /// Allow broad local busy handoff for wake-storm A/B testing.
    Full = 3,
}

impl StormGuardMode {
    #[cfg(not(cake_bpf_release))]
    fn as_str(&self) -> &'static str {
        match self {
            StormGuardMode::Off => "off",
            StormGuardMode::Shadow => "shadow",
            StormGuardMode::Shield => "shield",
            StormGuardMode::Full => "full",
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum QueuePolicy {
    /// Default local-first fallback policy used by the benchmark-guided release path.
    Local = 0,
    /// Per-LLC vtime fallback queues similar to the 1.1.0 queue shape.
    LlcVtime = 1,
}

impl QueuePolicy {
    #[cfg(not(cake_bpf_release))]
    fn as_str(&self) -> &'static str {
        match self {
            QueuePolicy::Local => "local",
            QueuePolicy::LlcVtime => "llc-vtime",
        }
    }
}

const LLC_DSQ_BASE: u64 = 200;
const CPU_FAST_SCAN_SLOTS: usize = 4;
const CPU_FAST_PROBE_SLOTS: usize = 4;
const CPU_FAST_PROBE_PACK_SLOT_BITS: usize = if topology::MAX_CPUS < 256 { 8 } else { 16 };
const CPU_FAST_PROBE_PACK_SLOT_MASK: u64 = (1u64 << CPU_FAST_PROBE_PACK_SLOT_BITS) - 1;
const CPU_META_PRIMARY: u64 = 1u64 << 48;
const CPU_META_SMT: u64 = 1u64 << 49;

#[derive(Debug, Default, Clone, serde::Serialize)]
struct ReleaseGameDiagTotals {
    nfw_entry: u64,
    nfw_hit: u64,
    nfw_hit_prev_cpu: u64,
    nfw_hit_other_cpu: u64,
    nfw_hit_select_cpu: u64,
    nfw_hit_prev_primary: u64,
    nfw_hit_other_primary: u64,
    nfw_hit_game_thread: u64,
    nfw_hit_render_thread: u64,
    nfw_hit_taskgraph_thread: u64,
    nfw_hit_pool_thread: u64,
    nfw_hit_fpsaim_thread: u64,
    nfw_hit_chrome_thread: u64,
    nfw_hit_crgpu_thread: u64,
    nfw_hit_dxvk_thread: u64,
    nfw_hit_audio_thread: u64,
    nfw_hit_other_thread: u64,
    nfw_hit_local_depth_sample: u64,
    nfw_hit_local_depth_nonzero: u64,
    nfw_hit_local_depth_gt1: u64,
    nfw_hit_local_depth_gt3: u64,
    nfw_prev_idle_attempt: u64,
    nfw_prev_idle_sibling_block: u64,
    nfw_prev_idle_claim: u64,
    nfw_prev_idle_fallback_attempt: u64,
    nfw_prev_idle_fallback_hit: u64,
    nfw_prev_idle_fallback_prev: u64,
    nfw_prev_idle_fallback_other: u64,
    nfw_miss: u64,
    nfw_miss_shared: u64,
    nfw_miss_tunnel: u64,
    nfw_fallthrough: u64,
    nfw_direct_insert: u64,
    select_tunnel: u64,
    enqueue_call: u64,
    enqueue_wakeup: u64,
    enqueue_initial: u64,
    enqueue_requeue: u64,
    enqueue_preserve: u64,
    enqueue_non_wakeup: u64,
    enqueue_direct_local: u64,
    enqueue_wake_direct: u64,
    enqueue_wake_idle: u64,
    enqueue_wake_busy: u64,
    enqueue_wake_busy_local: u64,
    enqueue_wake_busy_remote: u64,
    wake_kick_idle: u64,
    wake_kick_preempt: u64,
    kthread_direct_insert: u64,
    kthread_wake_preempt: u64,
    frame_stop_runnable: u64,
    frame_preempt_by_self: u64,
    frame_preempt_by_kworker: u64,
    frame_preempt_by_kthread: u64,
    frame_preempt_by_game: u64,
    frame_preempt_by_user: u64,
    local_waiter_attempt: u64,
    local_waiter_insert: u64,
    local_waiter_reject: u64,
    local_waiter_quench: u64,
    shared_escape: u64,
    shared_vtime_insert: u64,
    dispatch_call: u64,
    dispatch_idle_core_rescue_hit: u64,
    dispatch_idle_llc_rescue_hit: u64,
    llc_nonwake_insert: u64,
    llc_nonwake_kick_idle: u64,
    llc_rescue_enter: u64,
    llc_rescue_pending_lost_save: u64,
    dispatch_cache_hit: u64,
    dispatch_throughput_hit: u64,
    dispatch_core_steal_hit: u64,
    dispatch_llc_pull_hit: u64,
    dispatch_keep_running: u64,
    dispatch_idle: u64,
    publish_idle_call: u64,
    publish_idle_write: u64,
    publish_idle_noop: u64,
    publish_running_call: u64,
    publish_running_write: u64,
    publish_running_noop: u64,
    publish_owner_call: u64,
    publish_owner_write: u64,
    publish_owner_noop: u64,
    stopping_call: u64,
    stopping_runnable: u64,
    stopping_blocked: u64,
    stopping_owner_update: u64,
    stopping_route_observe: u64,
    stopping_route_pending: u64,
    stopping_route_no_pending: u64,
    stopping_account_relaxed: u64,
    stopping_account_audit: u64,
    stopping_scoreboard_owner_result: u64,
    stopping_lean_return: u64,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
#[cfg_attr(not(all(cake_bpf_release, cake_game_diag)), allow(dead_code))]
struct ReleaseGameDiagCpuSnapshot {
    cpu: usize,
    #[serde(flatten)]
    totals: ReleaseGameDiagTotals,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
#[cfg_attr(not(all(cake_bpf_release, cake_game_diag)), allow(dead_code))]
struct ReleaseGameDiagDerived {
    nfw_hit_pct: f64,
    nfw_hit_prev_cpu_pct: f64,
    nfw_hit_other_cpu_pct: f64,
    nfw_hit_select_cpu_pct: f64,
    nfw_hit_prev_primary_pct: f64,
    nfw_hit_other_primary_pct: f64,
    nfw_hit_game_thread_pct: f64,
    nfw_hit_render_thread_pct: f64,
    nfw_hit_taskgraph_thread_pct: f64,
    nfw_hit_pool_thread_pct: f64,
    nfw_hit_fpsaim_thread_pct: f64,
    nfw_hit_chrome_thread_pct: f64,
    nfw_hit_crgpu_thread_pct: f64,
    nfw_hit_dxvk_thread_pct: f64,
    nfw_hit_audio_thread_pct: f64,
    nfw_hit_other_thread_pct: f64,
    nfw_hit_local_depth_nonzero_pct: f64,
    nfw_hit_local_depth_gt1_pct: f64,
    nfw_hit_local_depth_gt3_pct: f64,
    nfw_prev_idle_attempt_pct: f64,
    nfw_prev_idle_sibling_block_pct: f64,
    nfw_prev_idle_claim_pct: f64,
    nfw_prev_idle_fallback_hit_pct: f64,
    nfw_prev_idle_fallback_prev_pct: f64,
    nfw_prev_idle_fallback_other_pct: f64,
    nfw_miss_pct: f64,
    nfw_miss_shared_pct: f64,
    nfw_miss_tunnel_pct: f64,
    nfw_fallthrough_pct: f64,
    enqueue_wakeup_pct: f64,
    enqueue_wake_direct_pct: f64,
    enqueue_wake_busy_pct: f64,
    enqueue_wake_busy_local_pct: f64,
    enqueue_wake_busy_remote_pct: f64,
    wake_kick_idle_pct: f64,
    wake_kick_preempt_pct: f64,
    local_waiter_insert_pct: f64,
    local_waiter_reject_pct: f64,
    local_waiter_quench_pct: f64,
    shared_escape_pct: f64,
    stopping_runnable_pct: f64,
    stopping_blocked_pct: f64,
    stopping_owner_update_pct: f64,
    stopping_route_observe_pct: f64,
    stopping_route_pending_pct: f64,
    stopping_route_no_pending_pct: f64,
    stopping_account_relaxed_pct: f64,
    stopping_account_audit_pct: f64,
    stopping_scoreboard_owner_result_pct: f64,
    stopping_lean_return_pct: f64,
    dispatch_idle_core_rescue_hit_pct: f64,
    dispatch_idle_llc_rescue_hit_pct: f64,
    dispatch_cache_hit_pct: f64,
    dispatch_throughput_hit_pct: f64,
    dispatch_core_steal_hit_pct: f64,
    dispatch_llc_pull_hit_pct: f64,
    dispatch_keep_running_pct: f64,
    dispatch_idle_pct: f64,
    publish_idle_write_pct: f64,
    publish_idle_noop_pct: f64,
    publish_running_write_pct: f64,
    publish_running_noop_pct: f64,
    publish_owner_write_pct: f64,
    publish_owner_noop_pct: f64,
}

impl ReleaseGameDiagDerived {
    #[cfg_attr(not(all(cake_bpf_release, cake_game_diag)), allow(dead_code))]
    fn from_totals(totals: &ReleaseGameDiagTotals) -> Self {
        let stopping_account_total =
            totals.stopping_account_relaxed + totals.stopping_account_audit;
        let stopping_route_total = totals.stopping_route_pending + totals.stopping_route_no_pending;

        Self {
            nfw_hit_pct: pct_u64(totals.nfw_hit, totals.nfw_entry),
            nfw_hit_prev_cpu_pct: pct_u64(totals.nfw_hit_prev_cpu, totals.nfw_hit),
            nfw_hit_other_cpu_pct: pct_u64(totals.nfw_hit_other_cpu, totals.nfw_hit),
            nfw_hit_select_cpu_pct: pct_u64(totals.nfw_hit_select_cpu, totals.nfw_hit),
            nfw_hit_prev_primary_pct: pct_u64(totals.nfw_hit_prev_primary, totals.nfw_hit),
            nfw_hit_other_primary_pct: pct_u64(totals.nfw_hit_other_primary, totals.nfw_hit),
            nfw_hit_game_thread_pct: pct_u64(totals.nfw_hit_game_thread, totals.nfw_hit),
            nfw_hit_render_thread_pct: pct_u64(totals.nfw_hit_render_thread, totals.nfw_hit),
            nfw_hit_taskgraph_thread_pct: pct_u64(totals.nfw_hit_taskgraph_thread, totals.nfw_hit),
            nfw_hit_pool_thread_pct: pct_u64(totals.nfw_hit_pool_thread, totals.nfw_hit),
            nfw_hit_fpsaim_thread_pct: pct_u64(totals.nfw_hit_fpsaim_thread, totals.nfw_hit),
            nfw_hit_chrome_thread_pct: pct_u64(totals.nfw_hit_chrome_thread, totals.nfw_hit),
            nfw_hit_crgpu_thread_pct: pct_u64(totals.nfw_hit_crgpu_thread, totals.nfw_hit),
            nfw_hit_dxvk_thread_pct: pct_u64(totals.nfw_hit_dxvk_thread, totals.nfw_hit),
            nfw_hit_audio_thread_pct: pct_u64(totals.nfw_hit_audio_thread, totals.nfw_hit),
            nfw_hit_other_thread_pct: pct_u64(totals.nfw_hit_other_thread, totals.nfw_hit),
            nfw_hit_local_depth_nonzero_pct: pct_u64(
                totals.nfw_hit_local_depth_nonzero,
                totals.nfw_hit_local_depth_sample,
            ),
            nfw_hit_local_depth_gt1_pct: pct_u64(
                totals.nfw_hit_local_depth_gt1,
                totals.nfw_hit_local_depth_sample,
            ),
            nfw_hit_local_depth_gt3_pct: pct_u64(
                totals.nfw_hit_local_depth_gt3,
                totals.nfw_hit_local_depth_sample,
            ),
            nfw_prev_idle_attempt_pct: pct_u64(totals.nfw_prev_idle_attempt, totals.nfw_entry),
            nfw_prev_idle_sibling_block_pct: pct_u64(
                totals.nfw_prev_idle_sibling_block,
                totals.nfw_prev_idle_attempt,
            ),
            nfw_prev_idle_claim_pct: pct_u64(
                totals.nfw_prev_idle_claim,
                totals.nfw_prev_idle_attempt,
            ),
            nfw_prev_idle_fallback_hit_pct: pct_u64(
                totals.nfw_prev_idle_fallback_hit,
                totals.nfw_prev_idle_fallback_attempt,
            ),
            nfw_prev_idle_fallback_prev_pct: pct_u64(
                totals.nfw_prev_idle_fallback_prev,
                totals.nfw_prev_idle_fallback_hit,
            ),
            nfw_prev_idle_fallback_other_pct: pct_u64(
                totals.nfw_prev_idle_fallback_other,
                totals.nfw_prev_idle_fallback_hit,
            ),
            nfw_miss_pct: pct_u64(totals.nfw_miss, totals.nfw_entry),
            nfw_miss_shared_pct: pct_u64(totals.nfw_miss_shared, totals.nfw_miss),
            nfw_miss_tunnel_pct: pct_u64(totals.nfw_miss_tunnel, totals.nfw_miss),
            nfw_fallthrough_pct: pct_u64(totals.nfw_fallthrough, totals.nfw_miss),
            enqueue_wakeup_pct: pct_u64(totals.enqueue_wakeup, totals.enqueue_call),
            enqueue_wake_direct_pct: pct_u64(totals.enqueue_wake_direct, totals.enqueue_wakeup),
            enqueue_wake_busy_pct: pct_u64(totals.enqueue_wake_busy, totals.enqueue_wakeup),
            enqueue_wake_busy_local_pct: pct_u64(
                totals.enqueue_wake_busy_local,
                totals.enqueue_wake_busy,
            ),
            enqueue_wake_busy_remote_pct: pct_u64(
                totals.enqueue_wake_busy_remote,
                totals.enqueue_wake_busy,
            ),
            wake_kick_idle_pct: pct_u64(totals.wake_kick_idle, totals.enqueue_wakeup),
            wake_kick_preempt_pct: pct_u64(totals.wake_kick_preempt, totals.enqueue_wake_busy),
            local_waiter_insert_pct: pct_u64(
                totals.local_waiter_insert,
                totals.local_waiter_attempt,
            ),
            local_waiter_reject_pct: pct_u64(
                totals.local_waiter_reject,
                totals.local_waiter_attempt,
            ),
            local_waiter_quench_pct: pct_u64(
                totals.local_waiter_quench,
                totals.local_waiter_insert,
            ),
            shared_escape_pct: pct_u64(totals.shared_escape, totals.enqueue_wakeup),
            stopping_runnable_pct: pct_u64(totals.stopping_runnable, totals.stopping_call),
            stopping_blocked_pct: pct_u64(totals.stopping_blocked, totals.stopping_call),
            stopping_owner_update_pct: pct_u64(totals.stopping_owner_update, totals.stopping_call),
            stopping_route_observe_pct: pct_u64(
                totals.stopping_route_observe,
                totals.stopping_call,
            ),
            stopping_route_pending_pct: pct_u64(
                totals.stopping_route_pending,
                stopping_route_total,
            ),
            stopping_route_no_pending_pct: pct_u64(
                totals.stopping_route_no_pending,
                stopping_route_total,
            ),
            stopping_account_relaxed_pct: pct_u64(
                totals.stopping_account_relaxed,
                stopping_account_total,
            ),
            stopping_account_audit_pct: pct_u64(
                totals.stopping_account_audit,
                stopping_account_total,
            ),
            stopping_scoreboard_owner_result_pct: pct_u64(
                totals.stopping_scoreboard_owner_result,
                totals.stopping_call,
            ),
            stopping_lean_return_pct: pct_u64(totals.stopping_lean_return, totals.stopping_call),
            dispatch_idle_core_rescue_hit_pct: pct_u64(
                totals.dispatch_idle_core_rescue_hit,
                totals.dispatch_call,
            ),
            dispatch_idle_llc_rescue_hit_pct: pct_u64(
                totals.dispatch_idle_llc_rescue_hit,
                totals.dispatch_call,
            ),
            dispatch_cache_hit_pct: pct_u64(totals.dispatch_cache_hit, totals.dispatch_call),
            dispatch_throughput_hit_pct: pct_u64(
                totals.dispatch_throughput_hit,
                totals.dispatch_call,
            ),
            dispatch_core_steal_hit_pct: pct_u64(
                totals.dispatch_core_steal_hit,
                totals.dispatch_call,
            ),
            dispatch_llc_pull_hit_pct: pct_u64(totals.dispatch_llc_pull_hit, totals.dispatch_call),
            dispatch_keep_running_pct: pct_u64(totals.dispatch_keep_running, totals.dispatch_call),
            dispatch_idle_pct: pct_u64(totals.dispatch_idle, totals.dispatch_call),
            publish_idle_write_pct: pct_u64(totals.publish_idle_write, totals.publish_idle_call),
            publish_idle_noop_pct: pct_u64(totals.publish_idle_noop, totals.publish_idle_call),
            publish_running_write_pct: pct_u64(
                totals.publish_running_write,
                totals.publish_running_call,
            ),
            publish_running_noop_pct: pct_u64(
                totals.publish_running_noop,
                totals.publish_running_call,
            ),
            publish_owner_write_pct: pct_u64(totals.publish_owner_write, totals.publish_owner_call),
            publish_owner_noop_pct: pct_u64(totals.publish_owner_noop, totals.publish_owner_call),
        }
    }
}

impl ReleaseGameDiagTotals {
    #[cfg_attr(not(all(cake_bpf_release, cake_game_diag)), allow(dead_code))]
    fn add_assign(&mut self, other: &ReleaseGameDiagTotals) {
        self.nfw_entry += other.nfw_entry;
        self.nfw_hit += other.nfw_hit;
        self.nfw_hit_prev_cpu += other.nfw_hit_prev_cpu;
        self.nfw_hit_other_cpu += other.nfw_hit_other_cpu;
        self.nfw_hit_select_cpu += other.nfw_hit_select_cpu;
        self.nfw_hit_prev_primary += other.nfw_hit_prev_primary;
        self.nfw_hit_other_primary += other.nfw_hit_other_primary;
        self.nfw_hit_game_thread += other.nfw_hit_game_thread;
        self.nfw_hit_render_thread += other.nfw_hit_render_thread;
        self.nfw_hit_taskgraph_thread += other.nfw_hit_taskgraph_thread;
        self.nfw_hit_pool_thread += other.nfw_hit_pool_thread;
        self.nfw_hit_fpsaim_thread += other.nfw_hit_fpsaim_thread;
        self.nfw_hit_chrome_thread += other.nfw_hit_chrome_thread;
        self.nfw_hit_crgpu_thread += other.nfw_hit_crgpu_thread;
        self.nfw_hit_dxvk_thread += other.nfw_hit_dxvk_thread;
        self.nfw_hit_audio_thread += other.nfw_hit_audio_thread;
        self.nfw_hit_other_thread += other.nfw_hit_other_thread;
        self.nfw_hit_local_depth_sample += other.nfw_hit_local_depth_sample;
        self.nfw_hit_local_depth_nonzero += other.nfw_hit_local_depth_nonzero;
        self.nfw_hit_local_depth_gt1 += other.nfw_hit_local_depth_gt1;
        self.nfw_hit_local_depth_gt3 += other.nfw_hit_local_depth_gt3;
        self.nfw_prev_idle_attempt += other.nfw_prev_idle_attempt;
        self.nfw_prev_idle_sibling_block += other.nfw_prev_idle_sibling_block;
        self.nfw_prev_idle_claim += other.nfw_prev_idle_claim;
        self.nfw_prev_idle_fallback_attempt += other.nfw_prev_idle_fallback_attempt;
        self.nfw_prev_idle_fallback_hit += other.nfw_prev_idle_fallback_hit;
        self.nfw_prev_idle_fallback_prev += other.nfw_prev_idle_fallback_prev;
        self.nfw_prev_idle_fallback_other += other.nfw_prev_idle_fallback_other;
        self.nfw_miss += other.nfw_miss;
        self.nfw_miss_shared += other.nfw_miss_shared;
        self.nfw_miss_tunnel += other.nfw_miss_tunnel;
        self.nfw_fallthrough += other.nfw_fallthrough;
        self.nfw_direct_insert += other.nfw_direct_insert;
        self.select_tunnel += other.select_tunnel;
        self.enqueue_call += other.enqueue_call;
        self.enqueue_wakeup += other.enqueue_wakeup;
        self.enqueue_initial += other.enqueue_initial;
        self.enqueue_requeue += other.enqueue_requeue;
        self.enqueue_preserve += other.enqueue_preserve;
        self.enqueue_non_wakeup += other.enqueue_non_wakeup;
        self.enqueue_direct_local += other.enqueue_direct_local;
        self.enqueue_wake_direct += other.enqueue_wake_direct;
        self.enqueue_wake_idle += other.enqueue_wake_idle;
        self.enqueue_wake_busy += other.enqueue_wake_busy;
        self.enqueue_wake_busy_local += other.enqueue_wake_busy_local;
        self.enqueue_wake_busy_remote += other.enqueue_wake_busy_remote;
        self.wake_kick_idle += other.wake_kick_idle;
        self.wake_kick_preempt += other.wake_kick_preempt;
        self.kthread_direct_insert += other.kthread_direct_insert;
        self.kthread_wake_preempt += other.kthread_wake_preempt;
        self.local_waiter_attempt += other.local_waiter_attempt;
        self.local_waiter_insert += other.local_waiter_insert;
        self.local_waiter_reject += other.local_waiter_reject;
        self.local_waiter_quench += other.local_waiter_quench;
        self.shared_escape += other.shared_escape;
        self.shared_vtime_insert += other.shared_vtime_insert;
        self.dispatch_call += other.dispatch_call;
        self.dispatch_idle_core_rescue_hit += other.dispatch_idle_core_rescue_hit;
        self.dispatch_idle_llc_rescue_hit += other.dispatch_idle_llc_rescue_hit;
        self.llc_nonwake_insert += other.llc_nonwake_insert;
        self.llc_nonwake_kick_idle += other.llc_nonwake_kick_idle;
        self.llc_rescue_enter += other.llc_rescue_enter;
        self.llc_rescue_pending_lost_save += other.llc_rescue_pending_lost_save;
        self.dispatch_cache_hit += other.dispatch_cache_hit;
        self.dispatch_throughput_hit += other.dispatch_throughput_hit;
        self.dispatch_core_steal_hit += other.dispatch_core_steal_hit;
        self.dispatch_llc_pull_hit += other.dispatch_llc_pull_hit;
        self.dispatch_keep_running += other.dispatch_keep_running;
        self.dispatch_idle += other.dispatch_idle;
        self.publish_idle_call += other.publish_idle_call;
        self.publish_idle_write += other.publish_idle_write;
        self.publish_idle_noop += other.publish_idle_noop;
        self.publish_running_call += other.publish_running_call;
        self.publish_running_write += other.publish_running_write;
        self.publish_running_noop += other.publish_running_noop;
        self.publish_owner_call += other.publish_owner_call;
        self.publish_owner_write += other.publish_owner_write;
        self.publish_owner_noop += other.publish_owner_noop;
        self.stopping_call += other.stopping_call;
        self.stopping_runnable += other.stopping_runnable;
        self.stopping_blocked += other.stopping_blocked;
        self.stopping_owner_update += other.stopping_owner_update;
        self.stopping_route_observe += other.stopping_route_observe;
        self.stopping_route_pending += other.stopping_route_pending;
        self.stopping_route_no_pending += other.stopping_route_no_pending;
        self.stopping_account_relaxed += other.stopping_account_relaxed;
        self.stopping_account_audit += other.stopping_account_audit;
        self.stopping_scoreboard_owner_result += other.stopping_scoreboard_owner_result;
        self.stopping_lean_return += other.stopping_lean_return;
        self.frame_stop_runnable += other.frame_stop_runnable;
        self.frame_preempt_by_self += other.frame_preempt_by_self;
        self.frame_preempt_by_kworker += other.frame_preempt_by_kworker;
        self.frame_preempt_by_kthread += other.frame_preempt_by_kthread;
        self.frame_preempt_by_game += other.frame_preempt_by_game;
        self.frame_preempt_by_user += other.frame_preempt_by_user;
    }
}

#[cfg_attr(not(all(cake_bpf_release, cake_game_diag)), allow(dead_code))]
fn pct_u64(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        ((num as f64 * 100_000.0 / den as f64).round()) / 1_000.0
    }
}

#[cfg_attr(not(all(cake_bpf_release, cake_game_diag)), allow(dead_code))]
fn format_release_game_diag_json(
    uptime_secs: f64,
    totals: &ReleaseGameDiagTotals,
    per_cpu: Vec<ReleaseGameDiagCpuSnapshot>,
) -> serde_json::Value {
    let derived = ReleaseGameDiagDerived::from_totals(totals);

    serde_json::json!({
        "schema_version": 1,
        "artifact_kind": "scx_cake_release_game_diag",
        "uptime_secs": ((uptime_secs * 1_000.0).round()) / 1_000.0,
        "release_game_diag": {
            "totals": totals,
            "derived": derived,
            "per_cpu": per_cpu,
        },
    })
}

#[cfg_attr(not(all(cake_bpf_release, cake_game_diag)), allow(dead_code))]
fn format_release_game_diag_text(uptime_secs: f64, totals: &ReleaseGameDiagTotals) -> String {
    format!(
        concat!(
            "release_game_diag: uptime_secs={:.3} ",
            "nfw_entry={} nfw_hit={} nfw_hit_prev_cpu={} nfw_hit_other_cpu={} ",
            "nfw_hit_select_cpu={} nfw_hit_prev_primary={} nfw_hit_other_primary={} ",
            "nfw_hit_game_thread={} nfw_hit_render_thread={} nfw_hit_pool_thread={} ",
            "nfw_hit_taskgraph_thread={} nfw_hit_chrome_thread={} nfw_hit_dxvk_thread={} ",
            "nfw_hit_local_depth_sample={} nfw_hit_local_depth_nonzero={} ",
            "nfw_hit_local_depth_gt1={} nfw_hit_local_depth_gt3={} ",
            "nfw_prev_idle_attempt={} nfw_prev_idle_sibling_block={} ",
            "nfw_prev_idle_claim={} nfw_prev_idle_fallback_attempt={} ",
            "nfw_prev_idle_fallback_hit={} nfw_prev_idle_fallback_prev={} ",
            "nfw_prev_idle_fallback_other={} ",
            "nfw_miss={} nfw_miss_shared={} nfw_miss_tunnel={} ",
            "enqueue_call={} enqueue_wakeup={} enqueue_wake_busy={} ",
            "enqueue_wake_busy_local={} enqueue_wake_busy_remote={} ",
            "wake_kick_idle={} wake_kick_preempt={} ",
            "local_waiter_attempt={} local_waiter_insert={} local_waiter_reject={} ",
            "shared_escape={} shared_vtime_insert={} ",
            "dispatch_call={} dispatch_idle_core_rescue_hit={} ",
            "dispatch_idle_llc_rescue_hit={} ",
            "llc_nonwake_insert={} llc_nonwake_kick_idle={} ",
            "llc_rescue_enter={} llc_rescue_pending_lost_save={} ",
            "dispatch_cache_hit={} ",
            "dispatch_throughput_hit={} dispatch_core_steal_hit={} ",
            "dispatch_llc_pull_hit={} dispatch_keep_running={} dispatch_idle={} ",
            "publish_idle_call={} publish_idle_write={} publish_idle_noop={} ",
            "publish_running_call={} publish_running_write={} publish_running_noop={} ",
            "publish_owner_call={} publish_owner_write={} publish_owner_noop={} ",
            "stopping_call={} stopping_runnable={} stopping_blocked={} ",
            "stopping_owner_update={} stopping_route_observe={} ",
            "stopping_route_pending={} stopping_route_no_pending={} ",
            "stopping_account_relaxed={} stopping_account_audit={} ",
            "stopping_scoreboard_owner_result={} stopping_lean_return={} ",
            "frame_stop_runnable={} frame_preempt_by_self={} ",
            "frame_preempt_by_kworker={} frame_preempt_by_kthread={} ",
            "frame_preempt_by_game={} frame_preempt_by_user={}\n"
        ),
        uptime_secs,
        totals.nfw_entry,
        totals.nfw_hit,
        totals.nfw_hit_prev_cpu,
        totals.nfw_hit_other_cpu,
        totals.nfw_hit_select_cpu,
        totals.nfw_hit_prev_primary,
        totals.nfw_hit_other_primary,
        totals.nfw_hit_game_thread,
        totals.nfw_hit_render_thread,
        totals.nfw_hit_pool_thread,
        totals.nfw_hit_taskgraph_thread,
        totals.nfw_hit_chrome_thread,
        totals.nfw_hit_dxvk_thread,
        totals.nfw_hit_local_depth_sample,
        totals.nfw_hit_local_depth_nonzero,
        totals.nfw_hit_local_depth_gt1,
        totals.nfw_hit_local_depth_gt3,
        totals.nfw_prev_idle_attempt,
        totals.nfw_prev_idle_sibling_block,
        totals.nfw_prev_idle_claim,
        totals.nfw_prev_idle_fallback_attempt,
        totals.nfw_prev_idle_fallback_hit,
        totals.nfw_prev_idle_fallback_prev,
        totals.nfw_prev_idle_fallback_other,
        totals.nfw_miss,
        totals.nfw_miss_shared,
        totals.nfw_miss_tunnel,
        totals.enqueue_call,
        totals.enqueue_wakeup,
        totals.enqueue_wake_busy,
        totals.enqueue_wake_busy_local,
        totals.enqueue_wake_busy_remote,
        totals.wake_kick_idle,
        totals.wake_kick_preempt,
        totals.local_waiter_attempt,
        totals.local_waiter_insert,
        totals.local_waiter_reject,
        totals.shared_escape,
        totals.shared_vtime_insert,
        totals.dispatch_call,
        totals.dispatch_idle_core_rescue_hit,
        totals.dispatch_idle_llc_rescue_hit,
        totals.llc_nonwake_insert,
        totals.llc_nonwake_kick_idle,
        totals.llc_rescue_enter,
        totals.llc_rescue_pending_lost_save,
        totals.dispatch_cache_hit,
        totals.dispatch_throughput_hit,
        totals.dispatch_core_steal_hit,
        totals.dispatch_llc_pull_hit,
        totals.dispatch_keep_running,
        totals.dispatch_idle,
        totals.publish_idle_call,
        totals.publish_idle_write,
        totals.publish_idle_noop,
        totals.publish_running_call,
        totals.publish_running_write,
        totals.publish_running_noop,
        totals.publish_owner_call,
        totals.publish_owner_write,
        totals.publish_owner_noop,
        totals.stopping_call,
        totals.stopping_runnable,
        totals.stopping_blocked,
        totals.stopping_owner_update,
        totals.stopping_route_observe,
        totals.stopping_route_pending,
        totals.stopping_route_no_pending,
        totals.stopping_account_relaxed,
        totals.stopping_account_audit,
        totals.stopping_scoreboard_owner_result,
        totals.stopping_lean_return,
        totals.frame_stop_runnable,
        totals.frame_preempt_by_self,
        totals.frame_preempt_by_kworker,
        totals.frame_preempt_by_kthread,
        totals.frame_preempt_by_game,
        totals.frame_preempt_by_user
    )
}

#[cfg(all(cake_bpf_release, cake_game_diag))]
fn release_game_diag_from_bpf(
    cpu: usize,
    row: &bpf_skel::types::cake_game_diag,
) -> ReleaseGameDiagCpuSnapshot {
    ReleaseGameDiagCpuSnapshot {
        cpu,
        totals: ReleaseGameDiagTotals {
            nfw_entry: row.nfw_entry,
            nfw_hit: row.nfw_hit,
            nfw_hit_prev_cpu: row.nfw_hit_prev_cpu,
            nfw_hit_other_cpu: row.nfw_hit_other_cpu,
            nfw_hit_select_cpu: row.nfw_hit_select_cpu,
            nfw_hit_prev_primary: row.nfw_hit_prev_primary,
            nfw_hit_other_primary: row.nfw_hit_other_primary,
            nfw_hit_game_thread: row.nfw_hit_game_thread,
            nfw_hit_render_thread: row.nfw_hit_render_thread,
            nfw_hit_taskgraph_thread: row.nfw_hit_taskgraph_thread,
            nfw_hit_pool_thread: row.nfw_hit_pool_thread,
            nfw_hit_fpsaim_thread: row.nfw_hit_fpsaim_thread,
            nfw_hit_chrome_thread: row.nfw_hit_chrome_thread,
            nfw_hit_crgpu_thread: row.nfw_hit_crgpu_thread,
            nfw_hit_dxvk_thread: row.nfw_hit_dxvk_thread,
            nfw_hit_audio_thread: row.nfw_hit_audio_thread,
            nfw_hit_other_thread: row.nfw_hit_other_thread,
            nfw_hit_local_depth_sample: row.nfw_hit_local_depth_sample,
            nfw_hit_local_depth_nonzero: row.nfw_hit_local_depth_nonzero,
            nfw_hit_local_depth_gt1: row.nfw_hit_local_depth_gt1,
            nfw_hit_local_depth_gt3: row.nfw_hit_local_depth_gt3,
            nfw_prev_idle_attempt: row.nfw_prev_idle_attempt,
            nfw_prev_idle_sibling_block: row.nfw_prev_idle_sibling_block,
            nfw_prev_idle_claim: row.nfw_prev_idle_claim,
            nfw_prev_idle_fallback_attempt: row.nfw_prev_idle_fallback_attempt,
            nfw_prev_idle_fallback_hit: row.nfw_prev_idle_fallback_hit,
            nfw_prev_idle_fallback_prev: row.nfw_prev_idle_fallback_prev,
            nfw_prev_idle_fallback_other: row.nfw_prev_idle_fallback_other,
            nfw_miss: row.nfw_miss,
            nfw_miss_shared: row.nfw_miss_shared,
            nfw_miss_tunnel: row.nfw_miss_tunnel,
            nfw_fallthrough: row.nfw_fallthrough,
            nfw_direct_insert: row.nfw_direct_insert,
            select_tunnel: row.select_tunnel,
            enqueue_call: row.enqueue_call,
            enqueue_wakeup: row.enqueue_wakeup,
            enqueue_initial: row.enqueue_initial,
            enqueue_requeue: row.enqueue_requeue,
            enqueue_preserve: row.enqueue_preserve,
            enqueue_non_wakeup: row.enqueue_non_wakeup,
            enqueue_direct_local: row.enqueue_direct_local,
            enqueue_wake_direct: row.enqueue_wake_direct,
            enqueue_wake_idle: row.enqueue_wake_idle,
            enqueue_wake_busy: row.enqueue_wake_busy,
            enqueue_wake_busy_local: row.enqueue_wake_busy_local,
            enqueue_wake_busy_remote: row.enqueue_wake_busy_remote,
            wake_kick_idle: row.wake_kick_idle,
            wake_kick_preempt: row.wake_kick_preempt,
            kthread_direct_insert: row.kthread_direct_insert,
            kthread_wake_preempt: row.kthread_wake_preempt,
            local_waiter_attempt: row.local_waiter_attempt,
            local_waiter_insert: row.local_waiter_insert,
            local_waiter_reject: row.local_waiter_reject,
            local_waiter_quench: row.local_waiter_quench,
            shared_escape: row.shared_escape,
            shared_vtime_insert: row.shared_vtime_insert,
            dispatch_call: row.dispatch_call,
            dispatch_idle_core_rescue_hit: row.dispatch_idle_core_rescue_hit,
            dispatch_idle_llc_rescue_hit: row.dispatch_idle_llc_rescue_hit,
            llc_nonwake_insert: row.llc_nonwake_insert,
            llc_nonwake_kick_idle: row.llc_nonwake_kick_idle,
            llc_rescue_enter: row.llc_rescue_enter,
            llc_rescue_pending_lost_save: row.llc_rescue_pending_lost_save,
            dispatch_cache_hit: row.dispatch_cache_hit,
            dispatch_throughput_hit: row.dispatch_throughput_hit,
            dispatch_core_steal_hit: row.dispatch_core_steal_hit,
            dispatch_llc_pull_hit: row.dispatch_llc_pull_hit,
            dispatch_keep_running: row.dispatch_keep_running,
            dispatch_idle: row.dispatch_idle,
            publish_idle_call: row.publish_idle_call,
            publish_idle_write: row.publish_idle_write,
            publish_idle_noop: row.publish_idle_noop,
            publish_running_call: row.publish_running_call,
            publish_running_write: row.publish_running_write,
            publish_running_noop: row.publish_running_noop,
            publish_owner_call: row.publish_owner_call,
            publish_owner_write: row.publish_owner_write,
            publish_owner_noop: row.publish_owner_noop,
            stopping_call: row.stopping_call,
            stopping_runnable: row.stopping_runnable,
            stopping_blocked: row.stopping_blocked,
            stopping_owner_update: row.stopping_owner_update,
            stopping_route_observe: row.stopping_route_observe,
            stopping_route_pending: row.stopping_route_pending,
            stopping_route_no_pending: row.stopping_route_no_pending,
            stopping_account_relaxed: row.stopping_account_relaxed,
            stopping_account_audit: row.stopping_account_audit,
            stopping_scoreboard_owner_result: row.stopping_scoreboard_owner_result,
            stopping_lean_return: row.stopping_lean_return,
            frame_stop_runnable: row.frame_stop_runnable,
            frame_preempt_by_self: row.frame_preempt_by_self,
            frame_preempt_by_kworker: row.frame_preempt_by_kworker,
            frame_preempt_by_kthread: row.frame_preempt_by_kthread,
            frame_preempt_by_game: row.frame_preempt_by_game,
            frame_preempt_by_user: row.frame_preempt_by_user,
        },
    }
}

#[cfg(all(cake_bpf_release, cake_game_diag))]
fn collect_release_game_diag(
    skel: &BpfSkel,
    nr_cpus: usize,
) -> (ReleaseGameDiagTotals, Vec<ReleaseGameDiagCpuSnapshot>) {
    use libbpf_rs::MapCore as _;
    let mut totals = ReleaseGameDiagTotals::default();
    let mut per_cpu = Vec::new();
    // game_diag is a BPF_MAP_TYPE_PERCPU_ARRAY (single element, key 0).
    // lookup_percpu returns one byte buffer per CPU; reinterpret each as
    // cake_game_diag and sum. No atomics / no remote indexing on the BPF side.
    let per_cpu_vals = match skel
        .maps
        .game_diag
        .lookup_percpu(&0u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
    {
        Ok(Some(vals)) => vals,
        _ => return (totals, per_cpu),
    };
    let sz = std::mem::size_of::<bpf_skel::types::cake_game_diag>();
    for (cpu, bytes) in per_cpu_vals.iter().enumerate().take(nr_cpus) {
        if bytes.len() < sz {
            continue;
        }
        // SAFETY: cake_game_diag is a POD of u64 counters and the per-CPU buffer
        // is exactly sizeof(cake_game_diag); read_unaligned avoids any alignment
        // assumption on the Vec<u8> backing store.
        let row: bpf_skel::types::cake_game_diag =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const _) };
        let snap = release_game_diag_from_bpf(cpu, &row);
        totals.add_assign(&snap.totals);
        per_cpu.push(snap);
    }
    (totals, per_cpu)
}

#[cfg(all(cake_bpf_release, cake_game_diag))]
fn sudo_invoking_owner() -> Option<(libc::uid_t, libc::gid_t)> {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<libc::uid_t>().ok())?;
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse::<libc::gid_t>().ok())?;
    (uid != 0).then_some((uid, gid))
}

#[cfg(all(cake_bpf_release, cake_game_diag))]
fn restore_diag_path_owner(path: &Path, is_dir: bool) {
    let Some((uid, gid)) = sudo_invoking_owner() else {
        return;
    };
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        log::warn!(
            "release game diag ownership handoff skipped for non-C path {}",
            path.display()
        );
        return;
    };
    let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if rc != 0 {
        log::warn!(
            "release game diag chown failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    let mode = if is_dir { 0o755 } else { 0o644 };
    if let Err(err) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        log::warn!(
            "release game diag chmod failed for {}: {err}",
            path.display()
        );
    }
}

#[cfg(all(cake_bpf_release, cake_game_diag))]
fn atomic_write_text(path: &Path, text: &str) -> Result<()> {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "cake_diag".into());
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    restore_diag_path_owner(&tmp, false);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
    restore_diag_path_owner(path, false);
    Ok(())
}

#[cfg(all(cake_bpf_release, cake_game_diag))]
fn release_game_diag_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(all(cake_bpf_release, cake_game_diag))]
fn write_release_game_diag_snapshot(
    skel: &BpfSkel,
    nr_cpus: usize,
    diag_dir: &Path,
    started: Instant,
    timestamped: bool,
) -> Result<()> {
    std::fs::create_dir_all(diag_dir)
        .with_context(|| format!("create diag dir {}", diag_dir.display()))?;
    restore_diag_path_owner(diag_dir, true);
    let uptime_secs = started.elapsed().as_secs_f64();
    let (totals, per_cpu) = collect_release_game_diag(skel, nr_cpus);
    let json_obj = format_release_game_diag_json(uptime_secs, &totals, per_cpu);
    let json_text = serde_json::to_string_pretty(&json_obj)? + "\n";
    let text = format_release_game_diag_text(uptime_secs, &totals);

    atomic_write_text(&diag_dir.join("cake_diag_latest.json"), &json_text)?;
    atomic_write_text(&diag_dir.join("cake_diag_latest.txt"), &text)?;

    if timestamped {
        let stamp = release_game_diag_timestamp();
        atomic_write_text(
            &diag_dir.join(format!("cake_diag_{stamp}.json")),
            &json_text,
        )?;
        atomic_write_text(&diag_dir.join(format!("cake_diag_{stamp}.txt")), &text)?;
    }
    Ok(())
}

#[cfg(all(cake_bpf_release, cake_game_diag))]
fn run_release_game_diag_recorder(
    skel: &mut BpfSkel,
    trust_governor: &mut trust::TrustGovernor,
    shutdown: Arc<AtomicBool>,
    interval_secs: u64,
    diag_dir: PathBuf,
    diag_period_secs: u64,
    nr_cpus: usize,
) -> Result<()> {
    let interval = Duration::from_secs(interval_secs.max(1));
    let period = (diag_period_secs > 0).then(|| Duration::from_secs(diag_period_secs));
    let started = Instant::now();
    let mut last_write: Option<Instant> = None;

    info!(
        "release game diagnostic recorder active: dir={} period={}s",
        diag_dir.display(),
        diag_period_secs
    );

    while !shutdown.load(Ordering::Relaxed) {
        trust_governor.tick(skel, nr_cpus);
        if let Some(period) = period {
            let due = last_write
                .map(|last| last.elapsed() >= period)
                .unwrap_or(true);
            if due {
                write_release_game_diag_snapshot(skel, nr_cpus, &diag_dir, started, false)?;
                last_write = Some(Instant::now());
            }
        }
        if scx_utils::uei_exited!(skel, uei) {
            break;
        }
        std::thread::sleep(interval);
    }

    write_release_game_diag_snapshot(skel, nr_cpus, &diag_dir, started, true)
}

#[cfg(cake_futex_trace)]
fn log_futex_trace(skel: &BpfSkel, nr_cpus: usize) {
    let Some(bss) = skel.maps.bss_data.as_ref() else {
        return;
    };

    let mut total = [0u64; 23];
    let mut service = [0u64; 12];
    for row in bss
        .futex_trace
        .iter()
        .take(nr_cpus.min(bss.futex_trace.len()))
    {
        total[0] += row.select_enter;
        total[1] += row.select_futex;
        total[2] += row.idle_found;
        total[3] += row.idle_scoreboard;
        total[4] += row.idle_core_spread;
        total[5] += row.idle_native;
        total[6] += row.native_noidle;
        total[7] += row.direct_clean_enter;
        total[8] += row.direct_clean_futex;
        total[9] += row.direct_clean_lane_active;
        total[10] += row.direct_clean_first;
        total[11] += row.tunnel_enter;
        total[12] += row.tunnel_futex;
        total[13] += row.tunnel_futex_insert;
        total[14] += row.enqueue_futex;
        total[15] += row.local_waiter_futex_insert;
        total[16] += row.local_waiter_futex_reject;
        total[17] += row.running_futex;
        total[18] += row.running_futex_changed;
        total[19] += row.running_futex_same;
        total[20] += row.stopping_futex;
        total[21] += row.stopping_futex_runnable;
        total[22] += row.stopping_futex_blocked;
        service[0] += row.schbench_direct_reset;
        service[1] += row.schbench_enqueue_reset;
        service[2] += row.schbench_stopping_reset;
        service[3] += row.schbench_stopping_runnable;
        service[4] += row.schbench_stopping_blocked;
        service[5] += row.latency_reset_enter;
        service[6] += row.latency_reset_decision;
        service[7] += row.latency_reset_owner_avg;
        service[8] += row.latency_reset_owner_runs;
        service[9] += row.latency_reset_cache_simple;
        service[10] += row.latency_reset_stream_pending;
        service[11] += row.latency_reset_status;
    }

    info!(
        "futex_trace total select_enter={} select_futex={} idle_found={} idle_scoreboard={} idle_core_spread={} idle_native={} native_noidle={} direct_enter={} direct_futex={} direct_active={} direct_first={} tunnel_enter={} tunnel_futex={} tunnel_insert={} enqueue_futex={} waiter_insert={} waiter_reject={} running_futex={} running_changed={} running_same={} stopping_futex={} stopping_runnable={} stopping_blocked={}",
        total[0],
        total[1],
        total[2],
        total[3],
        total[4],
        total[5],
        total[6],
        total[7],
        total[8],
        total[9],
        total[10],
        total[11],
        total[12],
        total[13],
        total[14],
        total[15],
        total[16],
        total[17],
        total[18],
        total[19],
        total[20],
        total[21],
        total[22],
    );
    info!(
        "service_trace total schbench_direct_reset={} schbench_enqueue_reset={} schbench_stopping_reset={} schbench_stopping_runnable={} schbench_stopping_blocked={} latency_reset_enter={} latency_reset_decision={} latency_reset_owner_avg={} latency_reset_owner_runs={} latency_reset_cache_simple={} latency_reset_stream_pending={} latency_reset_status={}",
        service[0],
        service[1],
        service[2],
        service[3],
        service[4],
        service[5],
        service[6],
        service[7],
        service[8],
        service[9],
        service[10],
        service[11],
    );

    for (cpu, row) in bss
        .futex_trace
        .iter()
        .take(nr_cpus.min(bss.futex_trace.len()))
        .enumerate()
    {
        let cpu_total = row.select_futex
            + row.idle_found
            + row.native_noidle
            + row.tunnel_futex
            + row.tunnel_futex_insert
            + row.enqueue_futex
            + row.running_futex
            + row.stopping_futex
            + row.schbench_direct_reset
            + row.schbench_enqueue_reset
            + row.schbench_stopping_reset
            + row.latency_reset_enter;
        if cpu_total == 0 {
            continue;
        }
        info!(
            "futex_trace cpu={} sf={} idle={} sb={} core={} native={} noidle={} df={} da={} first={} tun={} tins={} enq={} wi={} wr={} run={} run_chg={} run_same={} stop={} stop_run={} stop_blk={} fs_pid={} fs_ord={} fi_pid={} fi_ord={} ft_pid={} ft_ord={} fe_pid={} fe_ord={} fr_pid={} fr_ord={}",
            cpu,
            row.select_futex,
            row.idle_found,
            row.idle_scoreboard,
            row.idle_core_spread,
            row.idle_native,
            row.native_noidle,
            row.direct_clean_futex,
            row.direct_clean_lane_active,
            row.direct_clean_first,
            row.tunnel_futex,
            row.tunnel_futex_insert,
            row.enqueue_futex,
            row.local_waiter_futex_insert,
            row.local_waiter_futex_reject,
            row.running_futex,
            row.running_futex_changed,
            row.running_futex_same,
            row.stopping_futex,
            row.stopping_futex_runnable,
            row.stopping_futex_blocked,
            row.first_select_pid,
            row.first_select_order,
            row.first_idle_pid,
            row.first_idle_order,
            row.first_tunnel_pid,
            row.first_tunnel_order,
            row.first_enqueue_pid,
            row.first_enqueue_order,
            row.first_run_pid,
            row.first_run_order,
        );
        if row.schbench_direct_reset
            + row.schbench_enqueue_reset
            + row.schbench_stopping_reset
            + row.latency_reset_enter
            > 0
        {
            info!(
                "service_trace cpu={} sch_dir={} sch_enq={} sch_stop={} sch_stop_run={} sch_stop_blk={} reset={} dec={} avg={} runs={} cache={} stream={} status={}",
                cpu,
                row.schbench_direct_reset,
                row.schbench_enqueue_reset,
                row.schbench_stopping_reset,
                row.schbench_stopping_runnable,
                row.schbench_stopping_blocked,
                row.latency_reset_enter,
                row.latency_reset_decision,
                row.latency_reset_owner_avg,
                row.latency_reset_owner_runs,
                row.latency_reset_cache_simple,
                row.latency_reset_stream_pending,
                row.latency_reset_status,
            );
        }
    }

    for row in bss.futex_task_trace.iter() {
        if row.pid == 0 {
            continue;
        }
        info!(
            "futex_task pid={} order={} first_cpu={} sel={} idle={} tun={} enq={} run={} sel_mask={:#x} idle_mask={:#x} tun_mask={:#x} enq_mask={:#x} run_mask={:#x}",
            row.pid,
            row.first_order,
            row.first_cpu,
            row.select_count,
            row.idle_count,
            row.tunnel_count,
            row.enqueue_count,
            row.run_count,
            row.select_cpu_mask,
            row.idle_cpu_mask,
            row.tunnel_cpu_mask,
            row.enqueue_cpu_mask,
            row.run_cpu_mask,
        );
    }
}

#[inline]
fn pack_cpu_meta(
    sibling_cpu: u16,
    primary_cpu: u16,
    llc_id: u32,
    core_id: u32,
    is_primary: bool,
    has_smt_sibling: bool,
) -> u64 {
    let mut meta = (u64::from(sibling_cpu) & 0xffff)
        | ((u64::from(primary_cpu) & 0xffff) << 16)
        | ((u64::from(llc_id) & 0xff) << 32)
        | ((u64::from(core_id) & 0xff) << 40);

    if is_primary {
        meta |= CPU_META_PRIMARY;
    }
    if has_smt_sibling {
        meta |= CPU_META_SMT;
    }
    meta
}

#[inline]
fn precompute_cpu_llc_dsq_id(llc_id: u32) -> u64 {
    LLC_DSQ_BASE + u64::from(llc_id)
}

#[inline]
fn primary_cpu_for(topo: &topology::TopologyInfo, cpu: usize, nr_cpus: usize) -> u16 {
    if cpu >= nr_cpus {
        return u16::MAX;
    }
    if topo.cpu_thread_bit[cpu] == 1 {
        return cpu as u16;
    }

    let sibling = topo.cpu_sibling_map[cpu] as usize;
    if sibling < nr_cpus && topo.cpu_thread_bit[sibling] == 1 {
        return sibling as u16;
    }

    cpu as u16
}

fn build_fast_scan_slots(
    cpu: usize,
    nr_cpus: usize,
    cpu_sibling_map: &[u16],
    cpu_thread_bit: &[u8],
    cpu_llc_id: &[u8],
) -> [u16; CPU_FAST_SCAN_SLOTS] {
    fn push_unique(
        slots: &mut [u16; CPU_FAST_SCAN_SLOTS],
        next: &mut usize,
        cpu: usize,
        nr: usize,
    ) {
        if cpu >= nr || *next >= CPU_FAST_SCAN_SLOTS {
            return;
        }
        let cpu = cpu as u16;
        if slots.iter().take(*next).any(|&seen| seen == cpu) {
            return;
        }
        slots[*next] = cpu;
        *next += 1;
    }

    let mut slots = [u16::MAX; CPU_FAST_SCAN_SLOTS];
    let mut next = 0;
    if cpu >= nr_cpus {
        return slots;
    }

    push_unique(&mut slots, &mut next, cpu, nr_cpus);

    let sibling = cpu_sibling_map.get(cpu).copied().unwrap_or(u16::MAX) as usize;
    let primary = if cpu_thread_bit.get(cpu).copied().unwrap_or(0) == 1 {
        cpu
    } else if sibling < nr_cpus && cpu_thread_bit.get(sibling).copied().unwrap_or(0) == 1 {
        sibling
    } else {
        cpu
    };
    push_unique(&mut slots, &mut next, primary, nr_cpus);

    let llc = cpu_llc_id.get(cpu).copied().unwrap_or(0);
    for candidate in 0..nr_cpus {
        if cpu_llc_id.get(candidate).copied().unwrap_or(u8::MAX) != llc {
            continue;
        }
        if cpu_thread_bit.get(candidate).copied().unwrap_or(0) != 1 {
            continue;
        }
        push_unique(&mut slots, &mut next, candidate, nr_cpus);
        if next >= CPU_FAST_SCAN_SLOTS {
            break;
        }
    }
    push_unique(&mut slots, &mut next, sibling, nr_cpus);

    slots
}

#[allow(dead_code)]
fn read_cpu_perf_score(cpu: usize) -> u32 {
    let highest_perf = format!("/sys/devices/system/cpu/cpu{cpu}/acpi_cppc/highest_perf");
    if let Ok(raw) = std::fs::read_to_string(&highest_perf) {
        if let Ok(score) = raw.trim().parse::<u32>() {
            return score.max(1);
        }
    }

    let pref_rank = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/amd_pstate_prefcore_ranking");
    if let Ok(raw) = std::fs::read_to_string(&pref_rank) {
        if let Ok(rank) = raw.trim().parse::<u32>() {
            /*
             * amd_pstate_prefcore_ranking polarity has changed across kernel
             * discussions and vendor docs, while ACPI CPPC highest_perf is
             * directly "larger is faster". If highest_perf is unavailable,
             * keep the ranking useful but conservative by inverting the common
             * small-is-fast form into a larger-is-better score.
             */
            return 1024u32.saturating_sub(rank.min(1023)).max(1);
        }
    }

    1
}

#[allow(dead_code)]
fn cpu_perf_scores(nr_cpus: usize) -> [u32; topology::MAX_CPUS] {
    let mut scores = [1u32; topology::MAX_CPUS];

    for (cpu, score) in scores
        .iter_mut()
        .enumerate()
        .take(nr_cpus.min(topology::MAX_CPUS))
    {
        *score = read_cpu_perf_score(cpu);
    }

    scores
}

/// Per-CPU hardirq rates from two /proc/interrupts samples `gap_ms` apart.
/// Row format: "NNN:  <count per cpu>...  <desc>"; non-numeric rows (ERR/MIS)
/// and the header are skipped.
fn sample_irq_rates(nr_cpus: usize, gap_ms: u64) -> Vec<u64> {
    fn per_cpu_totals(nr_cpus: usize) -> Vec<u64> {
        let mut totals = vec![0u64; nr_cpus];
        if let Ok(raw) = std::fs::read_to_string("/proc/interrupts") {
            for line in raw.lines().skip(1) {
                let mut cols = line.split_whitespace();
                let Some(label) = cols.next() else { continue };
                if !label.ends_with(':') || !label[..label.len() - 1].chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                for (cpu, col) in cols.take(nr_cpus).enumerate() {
                    if let Ok(n) = col.parse::<u64>() {
                        totals[cpu] += n;
                    }
                }
            }
        }
        totals
    }
    let a = per_cpu_totals(nr_cpus);
    std::thread::sleep(std::time::Duration::from_millis(gap_ms));
    let b = per_cpu_totals(nr_cpus);
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| y.saturating_sub(*x) * 1000 / gap_ms.max(1))
        .collect()
}

/// Voluntary-ctxt-switch counts for a set of threads from /proc status.
fn rt_thread_wake_counts(tids: &[(u32, u32)]) -> Vec<u64> {
    tids.iter()
        .map(|(tid, _)| {
            std::fs::read_to_string(format!("/proc/{tid}/status"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("voluntary_ctxt_switches"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse::<u64>().ok())
                })
                .unwrap_or(0)
        })
        .collect()
}

/// Find user-competing RT (FIFO/RR) threads and their resident CPUs.
/// Per-CPU kernel housekeeping (migration/N, idle_inject/N, cpuhp/N) is
/// excluded: bound to its own CPU, dormant or stop-class, not a residency
/// signal worth demoting a core over.
fn rt_resident_threads() -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else { return out };
    for pid_entry in proc_dir.flatten() {
        let Some(pid_name) = pid_entry.file_name().to_str().map(String::from) else { continue };
        if !pid_name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid_name}/task")) else { continue };
        for task in tasks.flatten() {
            let Some(tid) = task.file_name().to_str().and_then(|t| t.parse::<u32>().ok()) else { continue };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{tid}/stat")) else { continue };
            // Fields after the parenthesized comm: split on the LAST ')'.
            let Some(rest) = stat.rsplit_once(')').map(|(_, r)| r) else { continue };
            let cols: Vec<&str> = rest.split_whitespace().collect();
            // rest[0]=state(field 3) ... psr=field 39 -> rest[36], policy=field 41 -> rest[38]
            let (Some(psr), Some(policy)) = (
                cols.get(36).and_then(|v| v.parse::<u32>().ok()),
                cols.get(38).and_then(|v| v.parse::<u32>().ok()),
            ) else { continue };
            if policy != 1 && policy != 2 {
                continue; // not SCHED_FIFO/SCHED_RR
            }
            let comm = std::fs::read_to_string(format!("/proc/{tid}/comm")).unwrap_or_default();
            let comm = comm.trim();
            if comm.starts_with("migration/")
                || comm.starts_with("idle_inject/")
                || comm.starts_with("cpuhp/")
            {
                continue;
            }
            out.push((tid, psr));
        }
    }
    out
}

/// Dynamic frame-anchor reserve governor (--frame-reserve).
///
/// Static reservation failed (GameThread nvCtx 411->5718/s when an RT thread
/// drifted onto the fixed core); RT residency moves, so the safe core must
/// too. Every ~2s: rescan FIFO/RR thread residency + per-CPU hardirq rates,
/// pick the highest-perf PRIMARY core that is RT-free and irq-quiet, publish
/// to BPF bss (cake_frame_reserve_cpu_dyn, cpu+1 encoding). Hysteresis: keep
/// the current reserve while it stays clean (cache warmth beats a marginally
/// better core).
struct FrameReserveGovernor {
    enabled: bool,
    tick: u64,
    prev_irq_totals: Vec<u64>,
    prev_rt_wakes: std::collections::HashMap<u32, u64>,
    reserve: u32, // cpu+1, 0=none
    alt: u32,
}

impl FrameReserveGovernor {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            tick: 0,
            prev_irq_totals: Vec::new(),
            prev_rt_wakes: std::collections::HashMap::new(),
            reserve: 0,
            alt: 0,
        }
    }

    fn tick(&mut self, skel: &mut BpfSkel, nr_cpus: usize) {
        if !self.enabled {
            return;
        }
        self.tick += 1;
        if self.tick % 2 != 1 {
            return; // every 2nd second
        }
        let irq_totals = {
            let mut totals = vec![0u64; nr_cpus];
            if let Ok(raw) = std::fs::read_to_string("/proc/interrupts") {
                for line in raw.lines().skip(1) {
                    let mut cols = line.split_whitespace();
                    let Some(label) = cols.next() else { continue };
                    if !label.ends_with(':')
                        || !label[..label.len() - 1].chars().all(|c| c.is_ascii_digit())
                    {
                        continue;
                    }
                    for (cpu, col) in cols.take(nr_cpus).enumerate() {
                        if let Ok(n) = col.parse::<u64>() {
                            totals[cpu] += n;
                        }
                    }
                }
            }
            totals
        };
        let mut irq_noisy = vec![false; nr_cpus];
        if self.prev_irq_totals.len() == nr_cpus {
            for cpu in 0..nr_cpus {
                // ~2s window; >=2000/s sustained marks the CPU irq-noisy.
                if irq_totals[cpu].saturating_sub(self.prev_irq_totals[cpu]) >= 4000 {
                    irq_noisy[cpu] = true;
                }
            }
        }
        self.prev_irq_totals = irq_totals;

        // Only ACTIVE RT threads poison a core — dormant per-CPU irq/rcu
        // FIFO threads exist on every CPU and never preempt. Rate-gate on
        // voluntary wakes across the ~2s tick window, like the loader scan.
        let mut rt_resident = vec![false; nr_cpus];
        let rt = rt_resident_threads();
        let counts = rt_thread_wake_counts(&rt);
        let mut next_prev = std::collections::HashMap::new();
        for (i, &(tid, psr)) in rt.iter().enumerate() {
            next_prev.insert(tid, counts[i]);
            if let Some(&prev) = self.prev_rt_wakes.get(&tid) {
                let per_s = counts[i].saturating_sub(prev) / 2;
                if per_s >= 300 && (psr as usize) < nr_cpus {
                    rt_resident[psr as usize] = true;
                }
            }
        }
        self.prev_rt_wakes = next_prev;

        let clean = |cpu: usize| -> bool { !rt_resident[cpu] && !irq_noisy[cpu] };
        let is_primary = |cpu: usize| -> bool {
            std::fs::read_to_string(format!(
                "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
            ))
            .ok()
            .and_then(|s| {
                s.trim()
                    .split([',', '-'])
                    .next()
                    .and_then(|v| v.parse::<usize>().ok())
            })
            .map(|first| first == cpu)
            .unwrap_or(true)
        };

        // Hysteresis: keep a still-clean reserve.
        if self.reserve != 0 {
            let cur = (self.reserve - 1) as usize;
            if cur < nr_cpus && clean(cur) {
                return;
            }
        }

        let mut ranked: Vec<(usize, u32)> = (0..nr_cpus)
            .filter(|&c| clean(c) && is_primary(c))
            .map(|c| (c, read_cpu_perf_score(c)))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let (new_reserve, new_alt) = match (ranked.first(), ranked.get(1)) {
            (Some(&(r, _)), Some(&(a, _))) => (r as u32 + 1, a as u32 + 1),
            (Some(&(r, _)), None) => (r as u32 + 1, 0),
            _ => (0, 0),
        };
        if new_reserve == 0 {
            log::warn!(
                "frame-reserve: no clean primary core found (rt={:?})",
                (0..nr_cpus).filter(|&c| rt_resident[c]).collect::<Vec<_>>()
            );
            return;
        }
        if new_reserve != self.reserve || new_alt != self.alt {
            let Some(bss) = &mut skel.maps.bss_data else {
                log::warn!("frame-reserve: bss_data unavailable; cannot publish");
                return;
            };
            bss.cake_frame_reserve_cpu_dyn = new_reserve;
            bss.cake_frame_reserve_alt_dyn = new_alt;
            info!(
                "frame-reserve: anchor core -> {} (alt {})",
                new_reserve as i64 - 1,
                new_alt as i64 - 1
            );
            self.reserve = new_reserve;
            self.alt = new_alt;
        }
    }
}

/// SCX_CAKE_IRQ_AVOID: demote IRQ-storm CPUs in the routing perf scores.
///
/// Measured 2026-06-10 (9800X3D, Kovaaks ~1240fps): the nvidia GPU interrupt
/// lands exclusively on one CPU (12.4k hardirqs/s) and its FIFO-50 threaded
/// handler preempts anything sched_ext puts there — but that CPU sat in
/// cake's top-4 frame cores by ACPI perf score, so GameThread ate ~425
/// involuntary switches/s (14x EEVDF's wait per slice). EEVDF diffuses off
/// the noisy core statistically via load balancing; cake routes
/// deterministically, so it must dodge deterministically.
///
/// Values: unset/"0"=off, "1"/"auto"=detect (>=2000 hardirq/s over a 100ms
/// startup sample), or an explicit comma list of CPU ids ("13" / "12,13").
/// Detection samples at load time, after the game/GPU is already running in
/// the A/B flow; boot-time loads with an idle GPU won't see the storm — use
/// the explicit list there. Demotion is score/3: 196 -> 65, below every
/// clean core on this part, so the noisy CPU becomes a last-resort target
/// without being removed from the topology.
fn apply_irq_avoid_penalty(
    scores: &mut [u32; topology::MAX_CPUS],
    nr_cpus: usize,
    cli_knob: Option<&str>,
) {
    // Default "auto" since 2026-06-10 (championship config): demoting
    // RT/IRQ-noisy cores won maxFT/jitMax with 3-4x tighter spreads and
    // regressed nothing. Costs ~300ms of startup sampling. "0" disables.
    let env_knob = std::env::var("SCX_CAKE_IRQ_AVOID").unwrap_or_default();
    let mut knob = cli_knob.unwrap_or(&env_knob).trim();
    if knob.is_empty() {
        knob = "auto";
    }
    if knob == "0" {
        return;
    }
    const IRQ_NOISY_RATE_PER_S: u64 = 2000;
    /* RT threads wake-rate threshold: KWin compositor threads measured
     * 5-6k wakes/s (FIFO-1) and PipeWire data-loops 370-750/s (FIFO-20)
     * resident on the top frame cores; rcu_preempt idles ~260/s and is
     * deliberately below the bar. Every RT wake can preempt an scx task
     * mid-burst — measured 99.7% of GameThread's involuntary switches
     * were RT-sandwich preemptions (frame_preempt_by_self diag). */
    const RT_NOISY_WAKES_PER_S: u64 = 300;
    let noisy: Vec<usize> = if knob == "1" || knob.eq_ignore_ascii_case("auto") {
        let mut set: std::collections::BTreeSet<usize> = sample_irq_rates(nr_cpus, 100)
            .iter()
            .enumerate()
            .filter(|(_, &r)| r >= IRQ_NOISY_RATE_PER_S)
            .map(|(cpu, _)| cpu)
            .collect();
        let rt = rt_resident_threads();
        let before = rt_thread_wake_counts(&rt);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let after = rt_thread_wake_counts(&rt);
        for (i, &(tid, psr)) in rt.iter().enumerate() {
            let rate = after[i].saturating_sub(before[i]) * 5;
            if rate >= RT_NOISY_WAKES_PER_S && (psr as usize) < nr_cpus {
                info!(
                    "IRQ-avoid: RT thread tid={} ({} wakes/s) resident on cpu{}",
                    tid, rate, psr
                );
                set.insert(psr as usize);
            }
        }
        set.into_iter().collect()
    } else {
        knob.split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|&c| c < nr_cpus)
            .collect()
    };
    if noisy.is_empty() {
        info!("IRQ-avoid: enabled but no IRQ-noisy CPUs detected");
        return;
    }
    for &cpu in &noisy {
        scores[cpu] /= 3;
    }
    info!(
        "IRQ-avoid: demoted IRQ-noisy CPUs {:?} in routing perf scores",
        noisy
    );
}

#[allow(dead_code)]
fn build_core_spread_slots(
    cpu: usize,
    nr_cpus: usize,
    cpu_sibling_map: &[u16],
    cpu_thread_bit: &[u8],
    cpu_llc_id: &[u8],
    cpu_perf_score: &[u32],
) -> [u16; CPU_FAST_SCAN_SLOTS] {
    let mut slots = [u16::MAX; CPU_FAST_SCAN_SLOTS];
    if cpu >= nr_cpus {
        return slots;
    }

    let llc = cpu_llc_id.get(cpu).copied().unwrap_or(0);
    let sibling = cpu_sibling_map.get(cpu).copied().unwrap_or(u16::MAX) as usize;
    let prev_primary = if cpu_thread_bit.get(cpu).copied().unwrap_or(0) == 1 {
        cpu
    } else if sibling < nr_cpus && cpu_thread_bit.get(sibling).copied().unwrap_or(0) == 1 {
        sibling
    } else {
        cpu
    };

    let mut candidates: Vec<(usize, u32, usize)> = (0..nr_cpus)
        .filter(|&candidate| {
            candidate != cpu
                && candidate != prev_primary
                && cpu_llc_id.get(candidate).copied().unwrap_or(u8::MAX) == llc
                && cpu_thread_bit.get(candidate).copied().unwrap_or(0) == 1
        })
        .map(|candidate| {
            let score = cpu_perf_score.get(candidate).copied().unwrap_or(1);
            let distance = candidate.abs_diff(cpu);
            (candidate, score, distance)
        })
        .collect();

    candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.2.cmp(&b.2)).then(a.0.cmp(&b.0)));

    for (slot, (candidate, _, _)) in candidates.into_iter().take(CPU_FAST_SCAN_SLOTS).enumerate() {
        slots[slot] = candidate as u16;
    }

    slots
}

#[inline]
fn active_fast_scan_probe_slots(slots: [u16; CPU_FAST_SCAN_SLOTS]) -> [u16; CPU_FAST_PROBE_SLOTS] {
    [slots[0], slots[1], slots[2], slots[3]]
}

#[inline]
fn pack_fast_scan_probe_slots(slots: [u16; CPU_FAST_SCAN_SLOTS]) -> u64 {
    let mut packed = 0u64;

    for (slot, &cpu) in slots.iter().take(CPU_FAST_PROBE_SLOTS).enumerate() {
        let shift = slot * CPU_FAST_PROBE_PACK_SLOT_BITS;

        if usize::from(cpu) < topology::MAX_CPUS {
            packed |= (u64::from(cpu) & CPU_FAST_PROBE_PACK_SLOT_MASK) << shift;
        } else {
            packed |= CPU_FAST_PROBE_PACK_SLOT_MASK << shift;
        }
    }

    packed
}

#[inline]
fn fast_scan_probe_bits(slots: [u16; CPU_FAST_SCAN_SLOTS]) -> u64 {
    let mut bits = 0u64;

    for &cpu in slots.iter().take(CPU_FAST_PROBE_SLOTS) {
        if usize::from(cpu) < topology::MAX_CPUS {
            bits |= 1u64 << (u32::from(cpu) & 63);
        }
    }

    bits
}

/// 🍰 scx_cake: A CAKE-inspired sched_ext CPU scheduler
///
/// This scheduler adapts CAKE's low-latency scheduling ideas to CPU time.
/// The current design centers on topology-aware CPU selection, per-LLC
/// vtime fallback queues, and lightweight per-task accounting in BPF.
///
/// Release builds bake profile, quantum, queue policy, storm guard, busy-wake
/// kick, learned locality, and wake-chain locality at compile time.
/// Debug builds keep those options as runtime A/B controls.
///
/// Game detection and older multi-mode policy logic have been removed.
/// The scheduler now runs one general low-latency policy for all tasks.
///
/// EXAMPLES:
///   scx_cake                          # Run with gaming profile (default)
///   scx_cake -p esports               # Ultra-low-latency for competitive play
///   scx_cake -p balanced              # Balanced desktop / mixed-use profile
///   scx_cake --quantum 1500           # Gaming profile with custom quantum
///   scx_cake --wake-chain-locality=true # A/B enable learned wake-chain guard
///   scx_cake --learned-locality=true # A/B enable learned locality steering
///   scx_cake --busy-wake-kick=preempt # A/B force same-CPU busy wake preemption
///   scx_cake --queue-policy local # A/B use 1.1.1 local fallback queues
///   scx_cake -v                       # Run with live TUI stats display
///   scx_cake -v --diag-dir /tmp/cake  # Headless recorder; directory must exist
#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    disable_version_flag = true,
    about = "🍰 A CAKE-inspired sched_ext scheduler for low-latency CPU scheduling",
    verbatim_doc_comment
)]
struct Args {
    /// Scheduler profile preset.
    ///
    /// Profiles configure the base quantum in debug builds. Release builds use
    /// SCX_CAKE_PROFILE at build time.
    ///
    /// ESPORTS: Ultra-low-latency for competitive gaming.
    ///   - Quantum: 750µs
    ///
    /// GAMING: Optimized for low-latency gaming and interactive workloads.
    ///   - Quantum: 1000µs
    ///
    /// BALANCED: Balanced profile for general desktop use.
    ///   - Quantum: 2000µs
    ///
    /// LEGACY: Optimized for older/lower-power hardware.
    ///   - Quantum: 4000µs
    #[arg(long, short, value_enum, default_value_t = Profile::Gaming, verbatim_doc_comment)]
    profile: Profile,

    /// Base scheduling time slice in MICROSECONDS [default: 1000].
    ///
    /// Debug builds patch this at startup. Release builds use
    /// SCX_CAKE_QUANTUM_US at build time.
    ///
    /// How long a task runs before potentially yielding.
    ///
    /// Smaller quantum = more responsive but higher overhead.
    /// Esports: 750µs | Gaming: 1000µs | Balanced: 2000µs | Legacy: 4000µs
    /// Recommended range: 1000-8000µs
    #[arg(long, verbatim_doc_comment)]
    quantum: Option<u64>,

    /// Enable learned wake-chain locality guard.
    ///
    /// This generic behavior-based guard keeps hot short blocking wake chains
    /// near their learned CPU instead of broadening every idle scan. It defaults
    /// off in debug builds for A/B work. Release builds use
    /// SCX_CAKE_WAKE_CHAIN_LOCALITY at build time.
    #[arg(
        long,
        default_value_t = false,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        verbatim_doc_comment
    )]
    wake_chain_locality: bool,

    /// Enable learned locality steering.
    ///
    /// This controls the arena-backed home/core/primary steering policy used
    /// after a task has enough history. It defaults off in debug builds for A/B
    /// work. Release builds use SCX_CAKE_LEARNED_LOCALITY at build time.
    #[arg(
        long,
        default_value_t = false,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        action = clap::ArgAction::Set,
        verbatim_doc_comment
    )]
    learned_locality: bool,

    /// Same-CPU busy wake kick behavior.
    ///
    /// POLICY uses Cake's current owner-runtime/pressure policy.
    /// PREEMPT forces immediate preempt kicks for local busy wakeups.
    /// IDLE forces gentler idle kicks for local busy wakeups.
    #[arg(long, value_enum, default_value_t = BusyWakeKickMode::Policy, verbatim_doc_comment)]
    busy_wake_kick: BusyWakeKickMode,

    /// Storm-guard busy-wake handoff policy.
    ///
    /// OFF keeps the baseline policy.
    /// SHADOW records storm-guard candidates without changing placement.
    /// SHIELD allows conservative extra local handoff for saturated owners.
    /// FULL allows broad local handoff during wake-storm A/B testing.
    #[arg(long, value_enum, default_value_t = StormGuardMode::Shield, verbatim_doc_comment)]
    storm_guard: StormGuardMode,

    /// Queueing policy for busy fallback work.
    ///
    /// Debug builds patch this at startup. Release builds use
    /// SCX_CAKE_QUEUE_POLICY at build time.
    ///
    /// LOCAL keeps busy fallback work in the selected CPU's local DSQ.
    /// LLC-VTIME A/B tests the 1.1.0-style shape: fallback work is inserted
    /// into a per-LLC vtime DSQ that dispatch() pulls from.
    #[arg(long, value_enum, default_value_t = QueuePolicy::Local, verbatim_doc_comment)]
    queue_policy: QueuePolicy,

    /// Enable live TUI (Terminal User Interface) with real-time statistics.
    ///
    /// Shows live scheduler stats, wait/run timing, and system topology
    /// information. Debug builds compile the full verbose capture surface by
    /// default; release builds compile telemetry out.
    /// Press 'q' to exit TUI mode.
    #[arg(long, short, verbatim_doc_comment)]
    verbose: bool,

    /// Statistics refresh interval in SECONDS (only with --verbose).
    ///
    /// How often the TUI updates. Lower values = more responsive but
    /// higher overhead. Has no effect without --verbose.
    ///
    /// Default: 1 second
    #[arg(long, default_value_t = 1, verbatim_doc_comment)]
    interval: u64,

    /// Directory for headless --verbose diagnostic snapshots.
    ///
    /// When --verbose is used without an interactive terminal, scx_cake records
    /// text and JSON diagnostic dumps here instead of trying to draw the TUI.
    #[arg(long, default_value = ".", verbatim_doc_comment)]
    diag_dir: PathBuf,

    /// Headless --verbose diagnostic write interval in SECONDS.
    ///
    /// A value of 0 disables periodic latest writes. A timestamped final dump
    /// is still written when scx_cake exits.
    #[arg(long, default_value_t = 60, verbatim_doc_comment)]
    diag_period: u64,

    /// Fold the enqueue idle-kick into the local-DSQ insert (SCX_ENQ_KICK_IDLE).
    ///
    /// Requires a kernel with the SCX_ENQ_KICK_IDLE enq_flag (for-7.2+, arighi
    /// aee94395c1f7); on older kernels this falls back to the explicit kick with
    /// a warning. Equivalent to SCX_CAKE_ENQ_KICK_IDLE=1 — the flag form exists
    /// because game-capture harnesses pass per-target activation_args but cannot
    /// inject env vars through the privileged launch path.
    #[arg(long, action = clap::ArgAction::SetTrue, verbatim_doc_comment)]
    enq_kick_idle: bool,

    /// Demote IRQ-storm CPUs in core routing: "auto" (detect at load) or a
    /// comma list of CPU ids (e.g. "13"). Equivalent to SCX_CAKE_IRQ_AVOID;
    /// flag form exists for capture harnesses that pass activation_args.
    /// See apply_irq_avoid_penalty for the measured rationale.
    #[arg(long, value_name = "AUTO_OR_CPUS", verbatim_doc_comment)]
    irq_avoid: Option<String>,

    /// Reserve the top routing core exclusively for the frame anchor
    /// (GameThread): anchor always selects it, other user tasks bounce to
    /// the second-best core, and the reserve core never pulls shared-lane
    /// work. Equivalent to SCX_CAKE_FRAME_RESERVE=1. Measured rationale in
    /// cake.bpf.c at cake_frame_reserve_cpu: RT compositor/audio preemptions
    /// follow the pipeline (sync wakes), so isolation — not avoidance — is
    /// the counter. Combine with --irq-avoid so the reserved core is clean.
    #[arg(long, action = clap::ArgAction::SetTrue, verbatim_doc_comment)]
    frame_reserve: bool,

    /// Print scheduler version and exit.
    #[arg(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Compare two scx_cake TUI dump files and exit without loading BPF.
    #[arg(long, value_names = ["BASELINE", "CANDIDATE"], num_args = 2)]
    compare_dump: Option<Vec<PathBuf>>,
}

impl Args {
    #[cfg(not(cake_bpf_release))]
    fn quantum_us(&self) -> u64 {
        self.quantum.unwrap_or(self.profile.quantum_us())
    }

    fn effective_quantum_us(&self) -> u64 {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_QUANTUM_US
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.quantum_us()
        }
    }

    fn effective_profile(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_PROFILE
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.profile.as_str()
        }
    }

    fn effective_queue_policy(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_QUEUE_POLICY
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.queue_policy.as_str()
        }
    }

    fn effective_storm_guard(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_STORM_GUARD
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.storm_guard.as_str()
        }
    }

    fn effective_busy_wake_kick(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_BUSY_WAKE_KICK
        }
        #[cfg(not(cake_bpf_release))]
        {
            self.busy_wake_kick.as_str()
        }
    }

    fn effective_learned_locality(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_LEARNED_LOCALITY
        }
        #[cfg(not(cake_bpf_release))]
        {
            if self.learned_locality {
                "on"
            } else {
                "off"
            }
        }
    }

    fn effective_wake_chain_locality(&self) -> &'static str {
        #[cfg(cake_bpf_release)]
        {
            topology::BAKED_WAKE_CHAIN_LOCALITY
        }
        #[cfg(not(cake_bpf_release))]
        {
            if self.wake_chain_locality {
                "on"
            } else {
                "off"
            }
        }
    }
}

#[cfg(cake_bpf_release)]
fn cli_arg_present(long: &str, short: Option<&str>) -> bool {
    let long_with_value = format!("{long}=");
    std::env::args().skip(1).any(|arg| {
        arg == long
            || arg.starts_with(&long_with_value)
            || short.map_or(false, |short| arg == short)
    })
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    args: Args,
    topology: topology::TopologyInfo,
    latency_matrix: Vec<Vec<f64>>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn new(
        args: Args,
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        #[cfg(cake_needs_arena)]
        use libbpf_rs::skel::Skel;
        use libbpf_rs::skel::{OpenSkel, SkelBuilder};

        // ═══ scx_ops_open! equivalent ═══
        // Matches scx_ops_open!(skel_builder, open_object, cake_ops, None)
        // Cake can't use the macro directly (custom arena architecture),
        // so we inline the critical functionality.
        scx_utils::compat::check_min_requirements()?;

        let skel_builder = BpfSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        // Inject version suffix into ops name: "cake" → "cake_<version>_g<hash>_<target>"
        // This is what scx_loader reads from /sys/kernel/sched_ext/root/ops
        {
            let ops = open_skel.struct_ops.cake_ops_mut();
            let name_field = &mut ops.name;

            let version_suffix = scx_utils::build_id::ops_version_suffix(env!("CARGO_PKG_VERSION"));
            let bytes = version_suffix.as_bytes();
            let mut i = 0;
            let mut bytes_idx = 0;
            let mut found_null = false;

            while i < name_field.len() - 1 {
                found_null |= name_field[i] == 0;
                if !found_null {
                    i += 1;
                    continue;
                }

                if bytes_idx < bytes.len() {
                    name_field[i] = bytes[bytes_idx] as i8;
                    bytes_idx += 1;
                } else {
                    break;
                }
                i += 1;
            }
            name_field[i] = 0;
        }

        // Read hotplug sequence number — enables kernel-requested restarts on CPU hotplug
        {
            let path = std::path::Path::new("/sys/kernel/sched_ext/hotplug_seq");
            let val = std::fs::read_to_string(path)
                .context("Failed to read /sys/kernel/sched_ext/hotplug_seq")?;
            open_skel.struct_ops.cake_ops_mut().hotplug_seq = val
                .trim()
                .parse::<u64>()
                .context("Failed to parse hotplug_seq")?;
        }

        // Honor SCX_TIMEOUT_MS environment variable (matches scx_ops_open! behavior)
        if let Ok(s) = std::env::var("SCX_TIMEOUT_MS") {
            let ms: u32 = s.parse().context("SCX_TIMEOUT_MS has invalid value")?;
            info!("Setting timeout_ms to {} based on environment", ms);
            open_skel.struct_ops.cake_ops_mut().timeout_ms = ms;
        }

        // Populate SCX enum RODATA from kernel BTF (SCX_DSQ_LOCAL_ON, SCX_KICK_PREEMPT, etc.)
        scx_utils::import_enums!(open_skel);

        // Detect system topology (CCDs, P/E cores)
        let topo = topology::detect()?;

        // Get effective values. Release bakes these in build.rs; debug keeps
        // profile + CLI overrides for runtime A/B.
        #[cfg(not(cake_bpf_release))]
        let quantum = args.effective_quantum_us();

        // Latency matrix: zeroed, populated by TUI Topology tab if --verbose
        let latency_matrix = vec![vec![0.0; topo.nr_cpus]; topo.nr_cpus];

        // Configure the scheduler via rodata (read-only data)
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            #[cfg(not(cake_bpf_release))]
            {
                rodata.quantum_ns = quantum * 1000;
                rodata.queue_policy = args.queue_policy as u32;
                rodata.enable_learned_locality = args.learned_locality;
                rodata.enable_wake_chain_locality = args.wake_chain_locality;
                rodata.busy_wake_kick_mode = args.busy_wake_kick as u32;
                rodata.storm_guard_mode = args.storm_guard as u32;
            }
            // Stats/telemetry: only available in debug builds (CAKE_RELEASE omits the field).
            // In release, --verbose is silently ignored.
            #[cfg(debug_assertions)]
            {
                rodata.enable_stats = args.verbose;
            }

            // SCX_ENQ_KICK_IDLE (kernel for-7.2+, arighi): fold the enqueue
            // idle-kick into the insert's enq_flags — one kfunc crossing instead
            // of dsq_insert + scx_bpf_kick_cpu. Resolve the flag bit from the
            // BOOTED kernel's BTF; 0 if the kernel predates it, so cake falls back
            // to the explicit kick. Gated by SCX_CAKE_ENQ_KICK_IDLE=1 so it can be
            // A/B'd against the explicit-kick path. Unconditional (runtime rodata,
            // present in both release and debug builds).
            // Default-ON since 2026-06-10: the fold is strictly cheaper
            // (cake_enqueue 164.6 -> 46.8 ns/call in-game) with zero frame
            // regression in a 4-cycle ABBA, and the BTF probe fails safe to
            // the explicit kick on kernels without the flag.
            // SCX_CAKE_ENQ_KICK_IDLE=0 disables for A/B.
            let enq_kick_idle_on = args.enq_kick_idle
                || std::env::var("SCX_CAKE_ENQ_KICK_IDLE")
                    .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
                    .unwrap_or(true);
            rodata.cake_enq_kick_idle_flag = if enq_kick_idle_on {
                match scx_utils::compat::read_enum("scx_enq_flags", "SCX_ENQ_KICK_IDLE") {
                    Ok(bit) => {
                        info!(
                            "SCX_ENQ_KICK_IDLE on: folding enqueue idle-kick into insert (flag=0x{:x})",
                            bit
                        );
                        bit
                    }
                    Err(_) => {
                        log::warn!(
                            "SCX_CAKE_ENQ_KICK_IDLE=1 but booted kernel lacks SCX_ENQ_KICK_IDLE; using explicit kick"
                        );
                        0
                    }
                }
            } else {
                0
            };

            // Populate topology metadata used by local-first steering and telemetry.
            let llc_count = topo.llc_cpu_mask.iter().filter(|&&m| m != 0).count() as u32;
            rodata.nr_llcs = llc_count.max(1);
            rodata.nr_cpus = topo.nr_cpus.min(topology::MAX_CPUS) as u32;
            // nr_phys_cpus REMOVED: zero BPF readers.

            // Ferry topology arrays into BPF RODATA — compile-time scaled

            // Heterogeneous Gaming Topology — only compiled when CAKE_HAS_HYBRID
            #[cfg(cake_has_hybrid)]
            {
                for i in 0..topo
                    .big_core_phys_mask
                    .len()
                    .min(rodata.big_core_phys_mask.len())
                {
                    rodata.big_core_phys_mask[i] = topo.big_core_phys_mask[i];
                }
                for i in 0..topo
                    .big_core_smt_mask
                    .len()
                    .min(rodata.big_core_smt_mask.len())
                {
                    rodata.big_core_smt_mask[i] = topo.big_core_smt_mask[i];
                }
                for i in 0..topo
                    .little_core_mask
                    .len()
                    .min(rodata.little_core_mask.len())
                {
                    rodata.little_core_mask[i] = topo.little_core_mask[i];
                }
                rodata.has_hybrid_cores = topo.big_core_phys_mask.iter().any(|&w| w != 0);
            }
            // vcache_llc_mask/has_vcache REMOVED from BPF: zero BPF readers.
            // Rust TUI reads topology directly.

            for i in 0..topo.cpu_sibling_map.len().min(rodata.cpu_sibling_map.len()) {
                rodata.cpu_sibling_map[i] = topo.cpu_sibling_map[i] as _;
            }
            for i in 0..topo.cpu_thread_bit.len().min(rodata.cpu_thread_bit.len()) {
                rodata.cpu_thread_bit[i] = topo.cpu_thread_bit[i];
            }
            for i in 0..topo.llc_cpu_mask.len().min(rodata.llc_cpu_mask.len()) {
                rodata.llc_cpu_mask[i] = topo.llc_cpu_mask[i];
            }
            // core_cpu_mask REMOVED from BPF: zero BPF readers.

            for (i, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
                rodata.cpu_llc_id[i] = llc_id as u32;
            }
            for i in 0..topo.cpu_core_id.len().min(rodata.cpu_core_id.len()) {
                rodata.cpu_core_id[i] = topo.cpu_core_id[i];
            }

            let nr = topo.nr_cpus.min(topology::MAX_CPUS);
            let mut cpu_perf_score = cpu_perf_scores(nr);
            apply_irq_avoid_penalty(&mut cpu_perf_score, nr, args.irq_avoid.as_deref());
            for i in 0..nr.min(rodata.cpu_meta.len()) {
                let sibling = topo.cpu_sibling_map[i];
                let has_smt_sibling = (sibling as usize) < nr && sibling as usize != i;
                let primary = primary_cpu_for(&topo, i, nr);
                let is_primary = primary as usize == i;
                let llc_id = topo.cpu_llc_id[i] as u32;

                rodata.cpu_meta[i] = pack_cpu_meta(
                    sibling,
                    primary,
                    llc_id,
                    topo.cpu_core_id[i] as u32,
                    is_primary,
                    has_smt_sibling,
                );
                rodata.cpu_llc_dsq[i] = precompute_cpu_llc_dsq_id(llc_id);
                let fast_scan = build_fast_scan_slots(
                    i,
                    nr,
                    &topo.cpu_sibling_map,
                    &topo.cpu_thread_bit,
                    &topo.cpu_llc_id,
                );
                rodata.cpu_fast_probe[i] = active_fast_scan_probe_slots(fast_scan);
                rodata.cpu_fast_probe_pack[i] = pack_fast_scan_probe_slots(fast_scan) as _;
                rodata.cpu_fast_probe_bits[i] = fast_scan_probe_bits(fast_scan);

                let core_spread = build_core_spread_slots(
                    i,
                    nr,
                    &topo.cpu_sibling_map,
                    &topo.cpu_thread_bit,
                    &topo.cpu_llc_id,
                    &cpu_perf_score,
                );
                rodata.cpu_core_spread_pack[i] = pack_fast_scan_probe_slots(core_spread) as _;
            }

            info!("Topology Strategy: Per-CPU local-first dispatch");
            let mut perf_order: Vec<(usize, u32)> =
                (0..nr).map(|cpu| (cpu, cpu_perf_score[cpu])).collect();
            perf_order.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            info!(
                "Core spread route table: top CPUs {:?}",
                perf_order.iter().take(6).collect::<Vec<_>>()
            );

            let frame_reserve_on = args.frame_reserve
                || std::env::var("SCX_CAKE_FRAME_RESERVE")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
            if frame_reserve_on && perf_order.len() >= 2 {
                rodata.cake_frame_reserve_on = 1;
                info!(
                    "Frame-anchor reservation on (dynamic): governor republishes the anchor core every ~2s"
                );
            }

            // Performance-ordered CPU scan arrays — HYBRID ONLY
            #[cfg(cake_has_hybrid)]
            {
                let nr = topo.nr_cpus.min(topology::MAX_CPUS);
                let mut rankings: Vec<(usize, u32)> = (0..nr)
                    .map(|cpu| {
                        let path = format!(
                            "/sys/devices/system/cpu/cpu{}/cpufreq/amd_pstate_prefcore_ranking",
                            cpu
                        );
                        let rank = std::fs::read_to_string(&path)
                            .ok()
                            .and_then(|s| s.trim().parse::<u32>().ok())
                            .unwrap_or(100);
                        (cpu, rank)
                    })
                    .collect();

                rankings.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

                let mut fast_to_slow: Vec<u16> = Vec::with_capacity(nr);
                let mut used = vec![false; nr];
                for &(cpu, _) in &rankings {
                    if used[cpu] {
                        continue;
                    }
                    fast_to_slow.push(cpu as u16);
                    used[cpu] = true;
                    let sib = topo.cpu_sibling_map.get(cpu).copied().unwrap_or(0xFFFF);
                    if (sib as usize) < nr && !used[sib as usize] {
                        fast_to_slow.push(sib);
                        used[sib as usize] = true;
                    }
                }

                for i in 0..topology::MAX_CPUS {
                    if i >= rodata.cpus_fast_to_slow.len() {
                        break;
                    }
                    if i < fast_to_slow.len() {
                        rodata.cpus_fast_to_slow[i] = fast_to_slow[i] as _;
                        rodata.cpus_slow_to_fast[i] = fast_to_slow[fast_to_slow.len() - 1 - i] as _;
                    } else {
                        rodata.cpus_fast_to_slow[i] = rodata.cpus_fast_to_slow[i].wrapping_sub(1);
                        rodata.cpus_slow_to_fast[i] = rodata.cpus_slow_to_fast[i].wrapping_sub(1);
                    }
                }

                let top_cpus: Vec<_> = fast_to_slow.iter().take(4).collect();
                info!(
                    "Core steering: fast→slow order {:?} ({} CPUs)",
                    top_cpus, nr
                );
            }

            #[cfg(cake_needs_arena)]
            {
                // Arena library: nr_cpu_ids must be set before load() — arena_init
                // checks this and returns -ENODEV (errno 19) if uninitialized.
                rodata.nr_cpu_ids = *NR_CPU_IDS as u32;
            }
        }

        // ═══ scx_ops_load! equivalent ═══
        // Set UEI dump buffer size before load (matches scx_ops_load! behavior)
        scx_utils::uei_set_size!(open_skel, cake_ops, uei);

        #[cfg(cake_needs_arena)]
        let mut skel = open_skel.load().context("Failed to load BPF program")?;
        #[cfg(not(cake_needs_arena))]
        let skel = open_skel.load().context("Failed to load BPF program")?;

        #[cfg(cake_needs_arena)]
        {
            // Initialize the BPF arena library.
            // Must happen after load() (BPF maps are now live) but before attach_struct_ops()
            // (scheduler not yet running, so init_task hasn't fired yet).
            // ArenaLib::setup() runs SEC("syscall") probes:
            //   1. arena_init: allocates static pages, inits task stack allocator
            //   2. arena_topology_node_init: registers topology nodes for arena traversal
            let task_ctx_size = std::mem::size_of::<bpf_intf::cake_task_ctx>();
            let arena = ArenaLib::init(skel.object_mut(), task_ctx_size, topo.nr_cpus)
                .context("Failed to create ArenaLib")?;
            arena.setup().context("Failed to initialize BPF arena")?;
            info!(
                "BPF arena initialized (task_ctx_size={}B, nr_cpus={})",
                task_ctx_size, topo.nr_cpus
            );
        }

        Ok(Self {
            skel,
            args,
            topology: topo,
            latency_matrix,
            struct_ops: None,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        use libbpf_rs::skel::Skel;

        // ═══ scx_ops_attach! equivalent ═══
        // Guard: prevent loading if another sched_ext scheduler is already active
        if scx_utils::compat::is_sched_ext_enabled().unwrap_or(false) {
            anyhow::bail!("another sched_ext scheduler is already running");
        }

        // Attach non-struct_ops BPF programs first, then struct_ops
        self.skel
            .attach()
            .context("Failed to attach non-struct_ops BPF programs")?;
        self.struct_ops = Some(
            self.skel
                .maps
                .cake_ops
                .attach_struct_ops()
                .context("Failed to attach struct_ops BPF programs")?,
        );

        // Release builds: --verbose is unavailable (stats compiled out).
        // Warn early so user knows this flag requires a debug build.
        #[cfg(not(debug_assertions))]
        if self.args.verbose {
            #[cfg(all(cake_bpf_release, cake_game_diag))]
            {
                log::warn!(
                    "--verbose using SCX_CAKE_GAME_DIAG release recorder; full TUI telemetry remains compiled out"
                );
            }
            #[cfg(not(all(cake_bpf_release, cake_game_diag)))]
            {
                log::warn!(
                    "--verbose requires a debug build (telemetry is compiled out in release)."
                );
                log::warn!("Rebuild without --release: cargo build -p scx_cake");
                self.args.verbose = false;
            }
        }

        #[cfg(cake_bpf_release)]
        if self.args.quantum.is_some()
            || cli_arg_present("--profile", Some("-p"))
            || cli_arg_present("--queue-policy", None)
            || cli_arg_present("--storm-guard", None)
            || cli_arg_present("--busy-wake-kick", None)
            || cli_arg_present("--learned-locality", None)
            || cli_arg_present("--wake-chain-locality", None)
        {
            log::warn!(
                "release build uses baked profile={}, quantum={}us, queue-policy={}, storm-guard={}, busy-wake-kick={}, learned-locality={}, wake-chain-locality={}, release-route-pred={}, release-confidence={}, release-llc-pending={}, release-local-waiter={}, release-domain-drr={}; rebuild with SCX_CAKE_PROFILE, SCX_CAKE_QUANTUM_US, SCX_CAKE_QUEUE_POLICY, SCX_CAKE_STORM_GUARD, SCX_CAKE_BUSY_WAKE_KICK, SCX_CAKE_LEARNED_LOCALITY, SCX_CAKE_WAKE_CHAIN_LOCALITY, SCX_CAKE_RELEASE_ROUTE_PRED, SCX_CAKE_RELEASE_CONFIDENCE, SCX_CAKE_RELEASE_LLC_PENDING, SCX_CAKE_RELEASE_LOCAL_WAITER, or SCX_CAKE_RELEASE_DOMAIN_DRR to change hot-path knobs",
                topology::BAKED_PROFILE,
                topology::BAKED_QUANTUM_US,
                topology::BAKED_QUEUE_POLICY,
                topology::BAKED_STORM_GUARD,
                topology::BAKED_BUSY_WAKE_KICK,
                topology::BAKED_LEARNED_LOCALITY,
                topology::BAKED_WAKE_CHAIN_LOCALITY,
                topology::BAKED_RELEASE_ROUTE_PRED,
                topology::BAKED_RELEASE_CONFIDENCE,
                topology::BAKED_RELEASE_LLC_PENDING,
                topology::BAKED_RELEASE_LOCAL_WAITER,
                topology::BAKED_RELEASE_DOMAIN_DRR
            );
        }

        // Standard startup banner: follows scx_cosmos/scx_bpfland convention
        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if self.topology.smt_enabled {
                "SMT on"
            } else {
                "SMT off"
            }
        );

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        #[cfg(cake_bpf_release)]
        info!(
            "release accelerators: route-pred={}, confidence={}, llc-pending={}, local-waiter={}, domain-drr={}, trust-maps={}, core-steal-dhq={}",
            topology::BAKED_RELEASE_ROUTE_PRED,
            topology::BAKED_RELEASE_CONFIDENCE,
            topology::BAKED_RELEASE_LLC_PENDING,
            topology::BAKED_RELEASE_LOCAL_WAITER,
            topology::BAKED_RELEASE_DOMAIN_DRR,
            topology::BAKED_RELEASE_TRUST_MAPS,
            topology::BAKED_CORE_STEAL_DHQ
        );

        info!(
            "{} CPUs, {} LLCs, profile: {}, quantum: {}us, queue-policy: {}, storm-guard: {}, busy-wake-kick: {}, learned-locality: {}, wake-chain-locality: {}, core-steal-dhq: {}",
            self.topology.nr_cpus,
            self.topology
                .llc_cpu_mask
                .iter()
                .filter(|&&m| m != 0)
                .count()
                .max(1),
            self.args.effective_profile(),
            self.args.effective_quantum_us(),
            self.args.effective_queue_policy(),
            self.args.effective_storm_guard(),
            self.args.effective_busy_wake_kick(),
            self.args.effective_learned_locality(),
            self.args.effective_wake_chain_locality(),
            topology::BAKED_CORE_STEAL_DHQ
        );
        let trust_governor_enabled = cfg!(cake_trust_maps)
            && (!cfg!(cake_bpf_release)
                || (topology::BAKED_RELEASE_ROUTE_PRED_VALUE != 0
                    && topology::BAKED_RELEASE_CONFIDENCE_VALUE != 0));
        let mut trust_governor =
            trust::TrustGovernor::new(self.topology.nr_cpus, trust_governor_enabled);

        let ran_release_game_diag = {
            #[cfg(all(cake_bpf_release, cake_game_diag))]
            {
                if self.args.verbose {
                    run_release_game_diag_recorder(
                        &mut self.skel,
                        &mut trust_governor,
                        shutdown.clone(),
                        self.args.interval,
                        self.args.diag_dir.clone(),
                        self.args.diag_period,
                        self.topology.nr_cpus,
                    )?;
                    true
                } else {
                    false
                }
            }
            #[cfg(not(all(cake_bpf_release, cake_game_diag)))]
            {
                false
            }
        };

        if ran_release_game_diag {
            // Snapshot loop already ran until shutdown or UEI exit.
        } else if self.args.verbose && std::io::stdout().is_terminal() {
            tui::run_tui(
                &mut self.skel,
                &mut trust_governor,
                shutdown.clone(),
                self.args.interval,
                self.args.effective_quantum_us(),
                self.topology.clone(),
                self.latency_matrix.clone(),
            )?;
        } else if self.args.verbose {
            tui::run_headless_recorder(
                &mut self.skel,
                &mut trust_governor,
                tui::HeadlessRecorderConfig {
                    shutdown: shutdown.clone(),
                    interval_secs: self.args.interval,
                    quantum_us: self.args.effective_quantum_us(),
                    topology: self.topology.clone(),
                    latency_matrix: self.latency_matrix.clone(),
                    diag_dir: self.args.diag_dir.clone(),
                    diag_period_secs: self.args.diag_period,
                },
            )?;
        } else {
            // Dynamic frame-anchor governor rides the headless loop only;
            // --verbose/TUI paths skip it (A/B captures run headless).
            let mut frame_governor = FrameReserveGovernor::new(
                self.args.frame_reserve
                    || std::env::var("SCX_CAKE_FRAME_RESERVE")
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false),
            );
            while !shutdown.load(Ordering::Relaxed) {
                trust_governor.tick(&mut self.skel, self.topology.nr_cpus);
                frame_governor.tick(&mut self.skel, self.topology.nr_cpus);
                std::thread::sleep(std::time::Duration::from_secs(1));
                if scx_utils::uei_exited!(&self.skel, uei) {
                    break;
                }
            }
        }

        info!("{SCHEDULER_NAME} scheduler shutting down");
        #[cfg(cake_futex_trace)]
        log_futex_trace(&self.skel, self.topology.nr_cpus);

        // Drop struct_ops link BEFORE uei_report — this triggers the kernel to
        // set UEI kind=SCX_EXIT_UNREG. Matches scx_bpfland/scx_cosmos/scx_lavd
        // pattern: `let _ = self.struct_ops.take(); uei_report!(...)`
        let _ = self.struct_ops.take();

        // Standard UEI exit report — returns UserExitInfo for should_restart().
        scx_utils::uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // Route libbpf messages through log crate — trim trailing \n to avoid double-newlines.
    libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Debug, |level, msg| {
        let msg = msg.trim_end();
        match level {
            libbpf_rs::PrintLevel::Debug => log::debug!("{msg}"),
            libbpf_rs::PrintLevel::Info => log::info!("{msg}"),
            libbpf_rs::PrintLevel::Warn => log::warn!("{msg}"),
        }
    })));

    let args = Args::parse();

    // Handle --version before anything else (matches cosmos/bpfland)
    if args.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if let Some(paths) = args.compare_dump.as_ref() {
        dump_compare::run_compare(&paths[0], &paths[1])?;
        return Ok(());
    }

    // Set up signal handler: ctrlc handles both SIGINT and SIGTERM on Linux.
    // This is the same pattern cosmos/bpfland use — no SigSet blocking or
    // SignalFd complexity needed.
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    // Create open object for BPF - needs to outlive scheduler
    let mut open_object = std::mem::MaybeUninit::uninit();

    // Restart loop: matches cosmos/bpfland pattern.
    // Kernel can request restart via UEI (e.g., CPU hotplug).
    loop {
        let mut scheduler = Scheduler::new(args.clone(), &mut open_object)?;
        if !scheduler.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_policy_defaults_to_local() {
        let args = Args::try_parse_from(["scx_cake"]).unwrap();

        assert_eq!(args.queue_policy, QueuePolicy::Local);
    }

    #[test]
    fn queue_policy_parses_local() {
        let args = Args::try_parse_from(["scx_cake", "--queue-policy", "local"]).unwrap();

        assert_eq!(args.queue_policy, QueuePolicy::Local);
    }

    #[test]
    fn storm_guard_defaults_to_shield_and_parses_full() {
        let args = Args::try_parse_from(["scx_cake"]).unwrap();
        assert_eq!(args.storm_guard, StormGuardMode::Shield);

        let args = Args::try_parse_from(["scx_cake", "--storm-guard", "full"]).unwrap();
        assert_eq!(args.storm_guard, StormGuardMode::Full);
    }

    #[test]
    fn cpu_meta_packs_static_topology_fact() {
        let meta = pack_cpu_meta(300, 260, 12, 44, true, true);

        assert_eq!(meta & 0xffff, 300);
        assert_eq!((meta >> 16) & 0xffff, 260);
        assert_eq!((meta >> 32) & 0xff, 12);
        assert_eq!((meta >> 40) & 0xff, 44);
        assert_ne!(meta & CPU_META_PRIMARY, 0);
        assert_ne!(meta & CPU_META_SMT, 0);
    }

    #[test]
    fn precomputed_dsq_ids_match_bpf_layout() {
        assert_eq!(precompute_cpu_llc_dsq_id(2), 202);
    }

    #[test]
    fn fast_scan_slots_are_init_built_nearby_cpu_order() {
        let siblings = [1, 0, 3, 2];
        let thread_bits = [1, 2, 1, 2];
        let llcs = [0, 0, 0, 0];

        let slots = build_fast_scan_slots(1, 4, &siblings, &thread_bits, &llcs);

        assert_eq!(slots, [1, 0, 2, u16::MAX]);

        let primary_slots = build_fast_scan_slots(0, 4, &siblings, &thread_bits, &llcs);

        assert_eq!(primary_slots, [0, 2, 1, u16::MAX]);
    }

    #[test]
    fn core_spread_slots_prefer_perf_ranked_full_cores() {
        let siblings = [4, 5, 6, 7, 0, 1, 2, 3];
        let thread_bits = [1, 1, 1, 1, 2, 2, 2, 2];
        let llcs = [0; 8];
        let perf = [176, 186, 181, 191, 176, 186, 181, 191];

        let slots = build_core_spread_slots(0, 8, &siblings, &thread_bits, &llcs, &perf);

        assert_eq!(slots, [3, 1, 2, u16::MAX]);
    }

    #[test]
    fn core_spread_slots_stay_in_llc_and_skip_prev_core() {
        let siblings = [4, 5, 6, 7, 0, 1, 2, 3];
        let thread_bits = [1, 1, 1, 1, 2, 2, 2, 2];
        let llcs = [0, 0, 1, 1, 0, 0, 1, 1];
        let perf = [10, 30, 100, 90, 10, 30, 100, 90];

        let slots = build_core_spread_slots(5, 8, &siblings, &thread_bits, &llcs, &perf);

        assert_eq!(slots, [0, u16::MAX, u16::MAX, u16::MAX]);
    }

    #[test]
    fn active_fast_scan_probe_slots_are_prev_then_primary() {
        let slots = [7, 4, 2, u16::MAX];

        assert_eq!(active_fast_scan_probe_slots(slots), [7, 4, 2, u16::MAX]);
    }

    #[test]
    fn packed_fast_scan_probe_preserves_valid_slots_and_invalid_tail() {
        let slots = [7, 4, 2, u16::MAX];
        let packed = pack_fast_scan_probe_slots(slots);

        assert_eq!(packed & CPU_FAST_PROBE_PACK_SLOT_MASK, 7);
        assert_eq!(
            (packed >> CPU_FAST_PROBE_PACK_SLOT_BITS) & CPU_FAST_PROBE_PACK_SLOT_MASK,
            4
        );
        assert_eq!(
            (packed >> (CPU_FAST_PROBE_PACK_SLOT_BITS * 2)) & CPU_FAST_PROBE_PACK_SLOT_MASK,
            2
        );
        assert_eq!(
            (packed >> (CPU_FAST_PROBE_PACK_SLOT_BITS * 3)) & CPU_FAST_PROBE_PACK_SLOT_MASK,
            CPU_FAST_PROBE_PACK_SLOT_MASK
        );
    }

    #[test]
    fn fast_scan_probe_bits_omits_invalid_tail_slots() {
        let slots = [7, 4, 2, u16::MAX];
        let bits = fast_scan_probe_bits(slots);

        assert_eq!(bits, (1u64 << 7) | (1u64 << 4) | (1u64 << 2));
    }

    #[test]
    fn release_game_diag_json_includes_totals_and_derived_rates() {
        let mut totals = ReleaseGameDiagTotals::default();
        totals.nfw_entry = 100;
        totals.nfw_hit = 25;
        totals.nfw_hit_prev_cpu = 10;
        totals.nfw_hit_other_cpu = 15;
        totals.nfw_hit_select_cpu = 5;
        totals.nfw_hit_prev_primary = 12;
        totals.nfw_hit_other_primary = 13;
        totals.nfw_hit_game_thread = 7;
        totals.nfw_hit_render_thread = 3;
        totals.nfw_hit_taskgraph_thread = 4;
        totals.nfw_hit_pool_thread = 5;
        totals.nfw_hit_fpsaim_thread = 2;
        totals.nfw_hit_chrome_thread = 1;
        totals.nfw_hit_crgpu_thread = 1;
        totals.nfw_hit_dxvk_thread = 1;
        totals.nfw_hit_audio_thread = 1;
        totals.nfw_hit_local_depth_sample = 25;
        totals.nfw_hit_local_depth_nonzero = 5;
        totals.nfw_hit_local_depth_gt1 = 2;
        totals.nfw_hit_local_depth_gt3 = 1;
        totals.nfw_prev_idle_attempt = 80;
        totals.nfw_prev_idle_sibling_block = 20;
        totals.nfw_prev_idle_claim = 30;
        totals.nfw_prev_idle_fallback_attempt = 50;
        totals.nfw_prev_idle_fallback_hit = 40;
        totals.nfw_prev_idle_fallback_prev = 10;
        totals.nfw_prev_idle_fallback_other = 30;
        totals.nfw_miss = 75;
        totals.nfw_miss_tunnel = 60;
        totals.enqueue_wakeup = 200;
        totals.enqueue_wake_busy = 150;
        totals.wake_kick_preempt = 45;
        totals.local_waiter_attempt = 20;
        totals.local_waiter_reject = 15;
        totals.stopping_call = 100;
        totals.stopping_runnable = 40;
        totals.stopping_blocked = 60;
        totals.stopping_owner_update = 90;
        totals.stopping_route_observe = 80;
        totals.stopping_route_pending = 30;
        totals.stopping_route_no_pending = 50;
        totals.stopping_account_relaxed = 75;
        totals.stopping_account_audit = 25;
        totals.stopping_scoreboard_owner_result = 25;
        totals.stopping_lean_return = 10;
        totals.dispatch_call = 200;
        totals.dispatch_idle_core_rescue_hit = 10;
        totals.dispatch_idle_llc_rescue_hit = 5;
        totals.dispatch_cache_hit = 20;
        totals.dispatch_throughput_hit = 30;
        totals.dispatch_core_steal_hit = 15;
        totals.dispatch_llc_pull_hit = 40;
        totals.dispatch_keep_running = 60;
        totals.dispatch_idle = 20;
        totals.publish_idle_call = 100;
        totals.publish_idle_write = 25;
        totals.publish_idle_noop = 75;
        totals.publish_running_call = 200;
        totals.publish_running_write = 50;
        totals.publish_running_noop = 150;
        totals.publish_owner_call = 400;
        totals.publish_owner_write = 100;
        totals.publish_owner_noop = 300;

        let json = format_release_game_diag_json(60.0, &totals, Vec::new());

        assert_eq!(json["artifact_kind"], "scx_cake_release_game_diag");
        assert_eq!(json["release_game_diag"]["totals"]["nfw_entry"], 100);
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_hit_prev_cpu_pct"],
            40.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_hit_other_primary_pct"],
            52.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_hit_game_thread_pct"],
            28.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_hit_pool_thread_pct"],
            20.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_hit_local_depth_nonzero_pct"],
            20.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_hit_local_depth_gt1_pct"],
            8.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_hit_local_depth_gt3_pct"],
            4.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_prev_idle_attempt_pct"],
            80.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_prev_idle_sibling_block_pct"],
            25.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_prev_idle_claim_pct"],
            37.5
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_prev_idle_fallback_hit_pct"],
            80.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_prev_idle_fallback_prev_pct"],
            25.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_prev_idle_fallback_other_pct"],
            75.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["nfw_miss_tunnel_pct"],
            80.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["enqueue_wake_busy_pct"],
            75.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["local_waiter_reject_pct"],
            75.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["stopping_runnable_pct"],
            40.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["stopping_account_relaxed_pct"],
            75.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["stopping_route_pending_pct"],
            37.5
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["stopping_route_no_pending_pct"],
            62.5
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["stopping_account_audit_pct"],
            25.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["stopping_scoreboard_owner_result_pct"],
            25.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["stopping_lean_return_pct"],
            10.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["dispatch_idle_core_rescue_hit_pct"],
            5.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["dispatch_llc_pull_hit_pct"],
            20.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["dispatch_keep_running_pct"],
            30.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["dispatch_idle_pct"],
            10.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["publish_idle_write_pct"],
            25.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["publish_idle_noop_pct"],
            75.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["publish_running_write_pct"],
            25.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["publish_running_noop_pct"],
            75.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["publish_owner_write_pct"],
            25.0
        );
        assert_eq!(
            json["release_game_diag"]["derived"]["publish_owner_noop_pct"],
            75.0
        );
    }
}
