#![allow(dead_code)]

use std::collections::HashMap;

pub const SHAPE_SHORT_BURSTY: u32 = 1 << 0;
pub const SHAPE_STEADY_RUNNER: u32 = 1 << 1;
pub const SHAPE_SLEEPY_WORKER: u32 = 1 << 2;
pub const SHAPE_BLOCKED_WAITER: u32 = 1 << 3;
pub const SHAPE_WAKE_FANOUT: u32 = 1 << 4;
pub const SHAPE_AFFINITY_NARROW: u32 = 1 << 5;
pub const SHAPE_MIGRATION_HEAVY: u32 = 1 << 6;
pub const SHAPE_SMT_CONTENDED: u32 = 1 << 7;
pub const SHAPE_THROUGHPUT_HEAVY: u32 = 1 << 8;
pub const SHAPE_KERNEL_WORKER: u32 = 1 << 9;

pub const LANE_INPUT: u32 = 1 << 0;
pub const LANE_RENDER_FRAME: u32 = 1 << 1;
pub const LANE_NETWORK: u32 = 1 << 2;
pub const LANE_SHADER_IO: u32 = 1 << 3;
pub const LANE_THROUGHPUT: u32 = 1 << 4;

pub const STRICT_WAKE_CLASS_NONE: u8 = 0;
pub const STRICT_WAKE_CLASS_NORMAL: u8 = 1;
pub const STRICT_WAKE_CLASS_SHIELD: u8 = 2;
pub const STRICT_WAKE_CLASS_CONTAIN: u8 = 3;

pub const STRICT_WAKE_REASON_LOW_UTIL: u32 = 1 << 0;
pub const STRICT_WAKE_REASON_SHORT_RUN: u32 = 1 << 1;
pub const STRICT_WAKE_REASON_WAKE_DENSE: u32 = 1 << 2;
pub const STRICT_WAKE_REASON_LATENCY_PRIO: u32 = 1 << 3;
pub const STRICT_WAKE_REASON_RUNTIME_HEAVY: u32 = 1 << 4;
pub const STRICT_WAKE_REASON_PREEMPT_HEAVY: u32 = 1 << 5;
pub const STRICT_WAKE_REASON_PRESSURE_HIGH: u32 = 1 << 6;
pub const STRICT_WAKE_REASON_YIELD_HEAVY: u32 = 1 << 7;
pub const STRICT_WAKE_REASON_WAIT_TAIL: u32 = 1 << 8;

pub const WAKE_CHAIN_SCORE_HIGH: u8 = 8;

pub const WAKE_CHAIN_REASON_SHORT_RUN: u32 = 1 << 0;
pub const WAKE_CHAIN_REASON_WAKE_DENSE: u32 = 1 << 1;
pub const WAKE_CHAIN_REASON_BLOCKS_EARLY: u32 = 1 << 2;
pub const WAKE_CHAIN_REASON_WAIT_TAIL: u32 = 1 << 3;
pub const WAKE_CHAIN_REASON_MIGRATION_PAIN: u32 = 1 << 4;
pub const WAKE_CHAIN_REASON_SMT_PAIN: u32 = 1 << 5;
pub const WAKE_CHAIN_REASON_LATENCY_PRIO: u32 = 1 << 6;

pub const WAKE_CHAIN_DECAY_FULL_QUANTUM: u32 = 1 << 0;
pub const WAKE_CHAIN_DECAY_LONG_RUN: u32 = 1 << 1;
pub const WAKE_CHAIN_DECAY_LOW_ACTIVITY: u32 = 1 << 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DebugTelemetryCost {
    pub iter_read_us: u64,
    pub proc_refresh_us: u64,
    pub anatomy_derive_us: u64,
    pub render_us: u64,
    pub dump_us: u64,
    pub iter_rows: u32,
    pub proc_refreshes: u32,
    pub proc_cache_hits: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TruthSource {
    Derived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneSource {
    Behavior,
    ProcHint,
    Mixed,
    Unknown,
}

impl LaneSource {
    pub fn label(self) -> &'static str {
        match self {
            LaneSource::Behavior => "behavior",
            LaneSource::ProcHint => "proc_hint",
            LaneSource::Mixed => "mixed",
            LaneSource::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaskAnatomyInput {
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub comm: String,
    pub pelt_util: u32,
    pub runs_per_sec: f64,
    pub migrations_per_sec: f64,
    pub runtime_ms_per_sec: f64,
    pub avg_runtime_us: u64,
    pub max_runtime_us: u32,
    pub last_wait_us: u64,
    pub max_dispatch_gap_us: u64,
    pub allowed_cpus: u16,
    pub system_cpus: u16,
    pub smt_contended_pct: f64,
    pub smt_overlap_pct: f64,
    pub wake_same_tgid_count: u32,
    pub wake_cross_tgid_count: u32,
    pub quantum_full: u64,
    pub quantum_yield: u64,
    pub quantum_preempt: u64,
    pub task_flags: u32,
    pub task_policy: u32,
    pub task_prio: u32,
    pub task_static_prio: u32,
    pub task_normal_prio: u32,
    pub task_has_mm: bool,
    pub task_is_kthread: bool,
    pub last_select_path: u8,
    pub last_select_reason: u8,
    pub last_place_class: u8,
    pub last_waker_place_class: u8,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcInfo {
    pub exe: String,
    pub cmdline: String,
    pub comm: String,
    pub start_time_ticks: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskAnatomy {
    pub shape_flags: u32,
    pub lane_flags: u32,
    pub source: TruthSource,
    pub lane_source: LaneSource,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StrictWakePolicyInput {
    pub task_prio: u32,
    pub task_weight: u16,
    pub total_runs: u64,
    pub total_runtime_ns: u64,
    pub quantum_full: u64,
    pub quantum_yield: u64,
    pub quantum_preempt: u64,
    pub yield_count: u64,
    pub wait_duration_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StrictWakePolicyDecision {
    pub class: u8,
    pub reason_mask: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakeChainScore {
    pub score: u8,
    pub reason_mask: u32,
    pub decay_mask: u32,
}

impl TaskAnatomy {
    pub fn has_shape(&self, flag: u32) -> bool {
        self.shape_flags & flag != 0
    }

    pub fn has_lane(&self, flag: u32) -> bool {
        self.lane_flags & flag != 0
    }

    pub fn risk_label(&self) -> &'static str {
        match (
            self.has_shape(SHAPE_MIGRATION_HEAVY),
            self.has_shape(SHAPE_SMT_CONTENDED),
        ) {
            (true, true) => "migration+smt",
            (true, false) => "migration",
            (false, true) => "smt",
            (false, false) => "ok",
        }
    }
}

pub fn derive_wake_chain_score(input: &TaskAnatomyInput) -> WakeChainScore {
    let mut raw_score = 0i16;
    let mut reason_mask = 0u32;
    let mut decay_mask = 0u32;
    let q_total = input
        .quantum_full
        .saturating_add(input.quantum_yield)
        .saturating_add(input.quantum_preempt);

    if input.avg_runtime_us > 0 && input.avg_runtime_us <= 125 && input.runs_per_sec >= 50.0 {
        raw_score += 2;
        reason_mask |= WAKE_CHAIN_REASON_SHORT_RUN;
    }
    if input.runs_per_sec >= 200.0 {
        raw_score += 2;
        reason_mask |= WAKE_CHAIN_REASON_WAKE_DENSE;
    }
    if q_total >= 32 && input.quantum_yield.saturating_mul(100) >= q_total.saturating_mul(70) {
        raw_score += 2;
        reason_mask |= WAKE_CHAIN_REASON_BLOCKS_EARLY;
    }
    if input.last_wait_us >= 200 {
        raw_score += 2;
        reason_mask |= WAKE_CHAIN_REASON_WAIT_TAIL;
    }
    if input.migrations_per_sec >= 1000.0 {
        raw_score += 2;
        reason_mask |= WAKE_CHAIN_REASON_MIGRATION_PAIN;
    }
    if input.smt_contended_pct >= 15.0 || input.smt_overlap_pct >= 15.0 {
        raw_score += 2;
        reason_mask |= WAKE_CHAIN_REASON_SMT_PAIN;
    }
    if input.task_prio > 0 && input.task_prio < 120 {
        raw_score += 2;
        reason_mask |= WAKE_CHAIN_REASON_LATENCY_PRIO;
    }

    if q_total >= 32 && input.quantum_full.saturating_mul(100) >= q_total.saturating_mul(25) {
        raw_score -= 5;
        decay_mask |= WAKE_CHAIN_DECAY_FULL_QUANTUM;
    }
    if input.avg_runtime_us >= 500 || input.runtime_ms_per_sec >= 750.0 {
        raw_score -= 4;
        decay_mask |= WAKE_CHAIN_DECAY_LONG_RUN;
    }
    if input.runs_per_sec < 10.0 {
        raw_score -= 3;
        decay_mask |= WAKE_CHAIN_DECAY_LOW_ACTIVITY;
    }

    WakeChainScore {
        score: raw_score.clamp(0, 15) as u8,
        reason_mask,
        decay_mask,
    }
}

#[derive(Default)]
pub struct TaskProcCache {
    entries: HashMap<u32, ProcInfo>,
}

impl TaskProcCache {
    pub fn get_if_current(&self, pid: u32, start_time_ticks: u64) -> Option<&ProcInfo> {
        self.entries
            .get(&pid)
            .filter(|entry| entry.start_time_ticks == start_time_ticks)
    }

    #[cfg(test)]
    pub fn insert_for_test(&mut self, pid: u32, start_time_ticks: u64, mut info: ProcInfo) {
        info.start_time_ticks = start_time_ticks;
        self.entries.insert(pid, info);
    }
}

pub fn derive_task_anatomy(input: &TaskAnatomyInput, proc_info: Option<&ProcInfo>) -> TaskAnatomy {
    let mut shape_flags = 0u32;
    let mut lane_flags = 0u32;
    let mut lane_source = LaneSource::Unknown;

    let q_total = input.quantum_full + input.quantum_yield + input.quantum_preempt;
    let full_pct = if q_total > 0 {
        input.quantum_full as f64 * 100.0 / q_total as f64
    } else {
        0.0
    };

    if input.avg_runtime_us <= 250 && input.runs_per_sec >= 50.0 && input.pelt_util <= 192 {
        shape_flags |= SHAPE_SHORT_BURSTY;
    }
    if input.runtime_ms_per_sec >= 75.0 && input.avg_runtime_us >= 500 {
        shape_flags |= SHAPE_STEADY_RUNNER;
    }
    if input.runs_per_sec < 10.0 && input.runtime_ms_per_sec < 5.0 {
        shape_flags |= SHAPE_SLEEPY_WORKER;
    }
    if input.last_wait_us >= 1000 || input.max_dispatch_gap_us >= 5000 {
        shape_flags |= SHAPE_BLOCKED_WAITER;
    }
    if input.wake_same_tgid_count + input.wake_cross_tgid_count >= 1000 {
        shape_flags |= SHAPE_WAKE_FANOUT;
    }
    if input.allowed_cpus > 0 && input.system_cpus > 0 && input.allowed_cpus < input.system_cpus {
        shape_flags |= SHAPE_AFFINITY_NARROW;
    }
    if input.migrations_per_sec >= 1000.0 {
        shape_flags |= SHAPE_MIGRATION_HEAVY;
    }
    if input.smt_contended_pct >= 15.0 || input.smt_overlap_pct >= 15.0 {
        shape_flags |= SHAPE_SMT_CONTENDED;
    }
    if input.runtime_ms_per_sec >= 150.0 || full_pct >= 50.0 {
        shape_flags |= SHAPE_THROUGHPUT_HEAVY;
    }
    if input.task_is_kthread || !input.task_has_mm {
        shape_flags |= SHAPE_KERNEL_WORKER;
    }

    if shape_flags & SHAPE_SHORT_BURSTY != 0
        && shape_flags & SHAPE_THROUGHPUT_HEAVY == 0
        && input.last_wait_us < 1000
    {
        lane_flags |= LANE_INPUT;
    }
    if shape_flags & SHAPE_STEADY_RUNNER != 0 && input.pelt_util >= 128 {
        lane_flags |= LANE_RENDER_FRAME;
    }
    let comm = input.comm.to_ascii_lowercase();
    if comm.contains("irq") || comm.contains("softirq") {
        lane_flags |= LANE_NETWORK;
    }
    if comm.contains("shader") || comm.contains("io_uring") {
        lane_flags |= LANE_SHADER_IO;
    }
    if shape_flags & SHAPE_THROUGHPUT_HEAVY != 0 {
        lane_flags |= LANE_THROUGHPUT;
    }
    if lane_flags != 0 {
        lane_source = LaneSource::Behavior;
    }

    if let Some(proc_info) = proc_info {
        let cmdline = proc_info.cmdline.to_ascii_lowercase();
        if cmdline.contains("shader") {
            lane_flags |= LANE_SHADER_IO;
            lane_source = if lane_source == LaneSource::Unknown {
                LaneSource::ProcHint
            } else {
                LaneSource::Mixed
            };
        }
    }

    TaskAnatomy {
        shape_flags,
        lane_flags,
        source: TruthSource::Derived,
        lane_source,
    }
}

pub fn derive_strict_wake_policy(input: &StrictWakePolicyInput) -> StrictWakePolicyDecision {
    let mut mask = 0u32;
    let mut short_run = false;
    let mut wake_dense = false;
    let mut yield_heavy = false;
    let mut runtime_heavy = false;
    let mut preempt_heavy = false;
    let mut wait_tail = false;

    if input.task_prio < 120 || input.task_weight > 120 {
        return StrictWakePolicyDecision {
            class: STRICT_WAKE_CLASS_SHIELD,
            reason_mask: STRICT_WAKE_REASON_LATENCY_PRIO,
        };
    }

    if input.total_runs > 0 {
        let avg_runtime = input.total_runtime_ns / input.total_runs;

        if avg_runtime > 0 {
            if input.total_runs >= 128 && avg_runtime <= 75_000 {
                short_run = true;
                mask |= STRICT_WAKE_REASON_SHORT_RUN;
            }
            if input.total_runs >= 1024 && avg_runtime <= 100_000 {
                wake_dense = true;
                mask |= STRICT_WAKE_REASON_WAKE_DENSE;
            }
        }

        if input.total_runs >= 64
            && input.yield_count >= 32
            && input.yield_count.saturating_mul(100) >= input.total_runs.saturating_mul(20)
        {
            yield_heavy = true;
            mask |= STRICT_WAKE_REASON_YIELD_HEAVY;
        }
    }

    let quantum_total = input
        .quantum_full
        .saturating_add(input.quantum_yield)
        .saturating_add(input.quantum_preempt);
    if quantum_total >= 64 {
        if input.quantum_full.saturating_mul(100) >= quantum_total.saturating_mul(25) {
            runtime_heavy = true;
            mask |= STRICT_WAKE_REASON_RUNTIME_HEAVY;
        }
        if input.quantum_preempt.saturating_mul(100) >= quantum_total.saturating_mul(12) {
            preempt_heavy = true;
            mask |= STRICT_WAKE_REASON_PREEMPT_HEAVY;
        }
    }

    if input.wait_duration_ns >= 200_000 {
        wait_tail = true;
        mask |= STRICT_WAKE_REASON_WAIT_TAIL;
    }

    let class = if runtime_heavy || preempt_heavy || yield_heavy {
        STRICT_WAKE_CLASS_CONTAIN
    } else if short_run && wake_dense && wait_tail {
        STRICT_WAKE_CLASS_SHIELD
    } else {
        STRICT_WAKE_CLASS_NORMAL
    };

    StrictWakePolicyDecision {
        class,
        reason_mask: mask,
    }
}

fn join_or_dash(labels: &[&'static str]) -> String {
    if labels.is_empty() {
        "-".to_string()
    } else {
        labels.join(",")
    }
}

pub fn wake_chain_reason_labels(mask: u32) -> String {
    let mut labels = Vec::new();
    if mask & WAKE_CHAIN_REASON_SHORT_RUN != 0 {
        labels.push("short_run");
    }
    if mask & WAKE_CHAIN_REASON_WAKE_DENSE != 0 {
        labels.push("wake_dense");
    }
    if mask & WAKE_CHAIN_REASON_BLOCKS_EARLY != 0 {
        labels.push("blocks_early");
    }
    if mask & WAKE_CHAIN_REASON_WAIT_TAIL != 0 {
        labels.push("wait_tail");
    }
    if mask & WAKE_CHAIN_REASON_MIGRATION_PAIN != 0 {
        labels.push("migration_pain");
    }
    if mask & WAKE_CHAIN_REASON_SMT_PAIN != 0 {
        labels.push("smt_pain");
    }
    if mask & WAKE_CHAIN_REASON_LATENCY_PRIO != 0 {
        labels.push("latency_prio");
    }
    join_or_dash(&labels)
}

pub fn wake_chain_decay_labels(mask: u32) -> String {
    let mut labels = Vec::new();
    if mask & WAKE_CHAIN_DECAY_FULL_QUANTUM != 0 {
        labels.push("full_quantum");
    }
    if mask & WAKE_CHAIN_DECAY_LONG_RUN != 0 {
        labels.push("long_run");
    }
    if mask & WAKE_CHAIN_DECAY_LOW_ACTIVITY != 0 {
        labels.push("low_activity");
    }
    join_or_dash(&labels)
}

pub fn shape_labels(anatomy: &TaskAnatomy) -> String {
    let mut labels = Vec::new();
    if anatomy.has_shape(SHAPE_SHORT_BURSTY) {
        labels.push("short_bursty");
    }
    if anatomy.has_shape(SHAPE_STEADY_RUNNER) {
        labels.push("steady_runner");
    }
    if anatomy.has_shape(SHAPE_SLEEPY_WORKER) {
        labels.push("sleepy_worker");
    }
    if anatomy.has_shape(SHAPE_BLOCKED_WAITER) {
        labels.push("blocked_waiter");
    }
    if anatomy.has_shape(SHAPE_WAKE_FANOUT) {
        labels.push("wake_fanout");
    }
    if anatomy.has_shape(SHAPE_AFFINITY_NARROW) {
        labels.push("affinity_narrow");
    }
    if anatomy.has_shape(SHAPE_MIGRATION_HEAVY) {
        labels.push("migration_heavy");
    }
    if anatomy.has_shape(SHAPE_SMT_CONTENDED) {
        labels.push("smt_contended");
    }
    if anatomy.has_shape(SHAPE_THROUGHPUT_HEAVY) {
        labels.push("throughput_heavy");
    }
    if anatomy.has_shape(SHAPE_KERNEL_WORKER) {
        labels.push("kernel_worker");
    }
    join_or_dash(&labels)
}

pub fn lane_labels(anatomy: &TaskAnatomy) -> String {
    let mut labels = Vec::new();
    if anatomy.has_lane(LANE_INPUT) {
        labels.push("input");
    }
    if anatomy.has_lane(LANE_RENDER_FRAME) {
        labels.push("render");
    }
    if anatomy.has_lane(LANE_NETWORK) {
        labels.push("network");
    }
    if anatomy.has_lane(LANE_SHADER_IO) {
        labels.push("shader_io");
    }
    if anatomy.has_lane(LANE_THROUGHPUT) {
        labels.push("throughput");
    }
    join_or_dash(&labels)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> TaskAnatomyInput {
        TaskAnatomyInput {
            pid: 10,
            tgid: 10,
            ppid: 1,
            comm: "game-worker".to_string(),
            pelt_util: 32,
            runs_per_sec: 250.0,
            migrations_per_sec: 5.0,
            runtime_ms_per_sec: 8.0,
            avg_runtime_us: 80,
            max_runtime_us: 400,
            last_wait_us: 20,
            max_dispatch_gap_us: 300,
            allowed_cpus: 16,
            system_cpus: 16,
            smt_contended_pct: 1.0,
            smt_overlap_pct: 1.0,
            wake_same_tgid_count: 100,
            wake_cross_tgid_count: 2,
            quantum_full: 0,
            quantum_yield: 90,
            quantum_preempt: 1,
            task_flags: 0,
            task_policy: 0,
            task_prio: 120,
            task_static_prio: 120,
            task_normal_prio: 120,
            task_has_mm: true,
            task_is_kthread: false,
            last_select_path: 3,
            last_select_reason: 6,
            last_place_class: 1,
            last_waker_place_class: 1,
        }
    }

    #[test]
    fn classifies_short_bursty_input_candidate() {
        let anatomy = derive_task_anatomy(&base_input(), None);
        assert!(anatomy.has_shape(SHAPE_SHORT_BURSTY));
        assert!(anatomy.has_lane(LANE_INPUT));
        assert_eq!(anatomy.lane_source, LaneSource::Behavior);
        assert!(!anatomy.has_lane(LANE_THROUGHPUT));
    }

    #[test]
    fn classifies_throughput_heavy_runner() {
        let mut input = base_input();
        input.pelt_util = 850;
        input.runtime_ms_per_sec = 420.0;
        input.avg_runtime_us = 1800;
        input.quantum_full = 900;
        input.quantum_yield = 20;
        let anatomy = derive_task_anatomy(&input, None);
        assert!(anatomy.has_shape(SHAPE_STEADY_RUNNER));
        assert!(anatomy.has_shape(SHAPE_THROUGHPUT_HEAVY));
        assert!(anatomy.has_lane(LANE_THROUGHPUT));
        assert!(!anatomy.has_lane(LANE_INPUT));
    }

    #[test]
    fn marks_smt_and_migration_risks() {
        let mut input = base_input();
        input.migrations_per_sec = 1500.0;
        input.smt_contended_pct = 24.0;
        let anatomy = derive_task_anatomy(&input, None);
        assert!(anatomy.has_shape(SHAPE_MIGRATION_HEAVY));
        assert!(anatomy.has_shape(SHAPE_SMT_CONTENDED));
        assert_eq!(anatomy.risk_label(), "migration+smt");
    }

    #[test]
    fn proc_cache_rejects_pid_reuse() {
        let mut cache = TaskProcCache::default();
        cache.insert_for_test(
            42,
            100,
            ProcInfo {
                exe: "/games/a".to_string(),
                cmdline: "a --flag".to_string(),
                comm: "a".to_string(),
                start_time_ticks: 100,
            },
        );
        assert!(cache.get_if_current(42, 100).is_some());
        assert!(cache.get_if_current(42, 101).is_none());
    }

    #[test]
    fn formats_shape_and_lane_labels() {
        let anatomy = TaskAnatomy {
            shape_flags: SHAPE_SHORT_BURSTY | SHAPE_SMT_CONTENDED,
            lane_flags: LANE_INPUT,
            source: TruthSource::Derived,
            lane_source: LaneSource::Behavior,
        };
        assert_eq!(shape_labels(&anatomy), "short_bursty,smt_contended");
        assert_eq!(lane_labels(&anatomy), "input");
    }

    #[test]
    fn empty_labels_render_dash() {
        let anatomy = TaskAnatomy {
            shape_flags: 0,
            lane_flags: 0,
            source: TruthSource::Derived,
            lane_source: LaneSource::Unknown,
        };
        assert_eq!(shape_labels(&anatomy), "-");
        assert_eq!(lane_labels(&anatomy), "-");
    }

    #[test]
    fn strict_policy_shields_latency_priority_tasks() {
        let decision = derive_strict_wake_policy(&StrictWakePolicyInput {
            task_prio: 110,
            task_weight: 100,
            ..StrictWakePolicyInput::default()
        });

        assert_eq!(decision.class, STRICT_WAKE_CLASS_SHIELD);
        assert_eq!(decision.reason_mask, STRICT_WAKE_REASON_LATENCY_PRIO);
    }

    #[test]
    fn strict_policy_contains_runtime_heavy_tasks() {
        let decision = derive_strict_wake_policy(&StrictWakePolicyInput {
            task_prio: 120,
            task_weight: 100,
            total_runs: 512,
            total_runtime_ns: 512 * 250_000,
            quantum_full: 80,
            quantum_yield: 20,
            quantum_preempt: 5,
            ..StrictWakePolicyInput::default()
        });

        assert_eq!(decision.class, STRICT_WAKE_CLASS_CONTAIN);
        assert_ne!(decision.reason_mask & STRICT_WAKE_REASON_RUNTIME_HEAVY, 0);
    }

    #[test]
    fn strict_policy_shields_short_wake_dense_wait_tail_tasks() {
        let decision = derive_strict_wake_policy(&StrictWakePolicyInput {
            task_prio: 120,
            task_weight: 100,
            total_runs: 1024,
            total_runtime_ns: 1024 * 50_000,
            quantum_full: 0,
            quantum_yield: 16,
            quantum_preempt: 0,
            wait_duration_ns: 250_000,
            ..StrictWakePolicyInput::default()
        });

        assert_eq!(decision.class, STRICT_WAKE_CLASS_SHIELD);
        assert_ne!(decision.reason_mask & STRICT_WAKE_REASON_SHORT_RUN, 0);
        assert_ne!(decision.reason_mask & STRICT_WAKE_REASON_WAKE_DENSE, 0);
        assert_ne!(decision.reason_mask & STRICT_WAKE_REASON_WAIT_TAIL, 0);
    }

    #[test]
    fn wake_chain_scores_short_wake_dense_blocking_tasks() {
        let mut input = base_input();
        input.avg_runtime_us = 64;
        input.runs_per_sec = 2400.0;
        input.runtime_ms_per_sec = 180.0;
        input.last_wait_us = 450;
        input.migrations_per_sec = 1800.0;
        input.smt_contended_pct = 37.0;
        input.wake_same_tgid_count = 0;
        input.wake_cross_tgid_count = 4096;
        input.quantum_full = 4;
        input.quantum_yield = 996;
        input.quantum_preempt = 12;

        let score = derive_wake_chain_score(&input);

        assert!(score.score >= WAKE_CHAIN_SCORE_HIGH);
        assert_ne!(score.reason_mask & WAKE_CHAIN_REASON_SHORT_RUN, 0);
        assert_ne!(score.reason_mask & WAKE_CHAIN_REASON_WAKE_DENSE, 0);
        assert_ne!(score.reason_mask & WAKE_CHAIN_REASON_BLOCKS_EARLY, 0);
        assert_ne!(score.reason_mask & WAKE_CHAIN_REASON_MIGRATION_PAIN, 0);
        assert_ne!(score.reason_mask & WAKE_CHAIN_REASON_SMT_PAIN, 0);
    }

    #[test]
    fn wake_chain_does_not_protect_cpu_bound_full_quantum_work() {
        let mut input = base_input();
        input.avg_runtime_us = 1800;
        input.runs_per_sec = 400.0;
        input.runtime_ms_per_sec = 900.0;
        input.last_wait_us = 4000;
        input.migrations_per_sec = 2000.0;
        input.smt_contended_pct = 42.0;
        input.wake_same_tgid_count = 9000;
        input.wake_cross_tgid_count = 9000;
        input.quantum_full = 900;
        input.quantum_yield = 20;
        input.quantum_preempt = 10;

        let score = derive_wake_chain_score(&input);

        assert!(score.score < WAKE_CHAIN_SCORE_HIGH);
        assert_ne!(score.decay_mask & WAKE_CHAIN_DECAY_FULL_QUANTUM, 0);
        assert_ne!(score.decay_mask & WAKE_CHAIN_DECAY_LONG_RUN, 0);
    }

    #[test]
    fn wake_chain_score_ignores_identity_fields() {
        let mut first = base_input();
        first.pid = 100;
        first.tgid = 100;
        first.ppid = 1;
        first.comm = "plain-worker".to_string();
        first.avg_runtime_us = 70;
        first.runs_per_sec = 1200.0;
        first.wake_same_tgid_count = 0;
        first.wake_cross_tgid_count = 2048;
        first.quantum_full = 1;
        first.quantum_yield = 256;

        let mut second = first.clone();
        second.pid = 200;
        second.tgid = 7777;
        second.ppid = 4242;
        second.comm = "FPSAimTrainer-Win64-Shipping.exe".to_string();

        let a = derive_wake_chain_score(&first);
        let b = derive_wake_chain_score(&second);

        assert_eq!(a.score, b.score);
        assert_eq!(a.reason_mask, b.reason_mask);
        assert_eq!(a.decay_mask, b.decay_mask);
        assert!(!wake_chain_reason_labels(a.reason_mask).contains("tgid"));
        assert!(!wake_chain_reason_labels(a.reason_mask).contains("comm"));
        assert!(!wake_chain_reason_labels(a.reason_mask).contains("game"));
    }
}
