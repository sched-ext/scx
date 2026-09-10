/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Stats server and web snapshot for the flow scheduler.
 * Metrics mirrors the BPF counters plus uptime. Inserts
 * count fresh joins. Requeues count runnable slice ends.
 * Completions count blocks and exits. Park and steal
 * moves count dispatch moves. Kicks count idle wakeups.
 * Preempt counts cover busy kicks plus lumped skips.
 * One skipped count covers all fail-closed no-kicks.
 * Coalesced counts q2 idle skips in 50us at 160B.
 * EDF counts cover ordered inserts with clamp detail.
 * Group counts cover demote plus promote plus wake
 * promote plus pinned inflate plus steal skips. Wake
 * promote is the fast subset of promote by 8 short
 * blocks. Web metrics adds per-CPU cards with fixed
 * slice plus group plus delay plus depths plus pressure
 * plus version plus topology plus timestamp for the page
 * and the JSON log.
 */
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use scx_stats_derive::stat_doc;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Tasks now on a CPU")]
    #[serde(default)]
    pub on_cpu: u64,
    #[stat(desc = "Total runtime in nanoseconds")]
    #[serde(default)]
    pub total_runtime: u64,
    #[stat(desc = "Uptime since attach in nanoseconds")]
    #[serde(default)]
    pub uptime_ns: u64,
    #[stat(desc = "Fresh joins with a new estimate")]
    #[serde(default)]
    pub inserts: u64,
    #[stat(desc = "Runnable slice ends with requeue")]
    #[serde(default)]
    pub requeues: u64,
    #[stat(desc = "Blocks and exits with release")]
    #[serde(default)]
    pub completions: u64,
    #[stat(desc = "Moves from the park queue")]
    #[serde(default)]
    pub park_moves: u64,
    #[stat(desc = "Moves from a peer queue")]
    #[serde(default)]
    pub steal_moves: u64,
    #[stat(desc = "Idle wakeup kicks sent after insert")]
    #[serde(default)]
    pub kicks: u64,
    #[stat(desc = "Inserts without task state")]
    #[serde(default)]
    pub enq_no_tctx: u64,
    #[stat(desc = "Ordered inserts with deadline")]
    #[serde(default)]
    pub edf_enqueued: u64,
    #[stat(desc = "Sleeper clamps to one slice")]
    #[serde(default)]
    pub edf_clamped: u64,
    #[stat(desc = "Kernel queue inserts in order")]
    #[serde(default)]
    pub edf_ordered: u64,
    #[stat(desc = "Light to hog moves by burn")]
    #[serde(default)]
    pub group_demote: u64,
    #[stat(desc = "Hog to light moves after low wins")]
    #[serde(default)]
    pub group_promote: u64,
    #[stat(desc = "Pinned hog deadlines with extra")]
    #[serde(default)]
    pub pinned_hog_inflated: u64,
    #[stat(desc = "Cross group picks skipped")]
    #[serde(default)]
    pub group_steal_skipped: u64,
    #[stat(desc = "Hog to light moves by wake hits")]
    #[serde(default)]
    pub group_wake_promote: u64,
    #[stat(desc = "Busy kicks after armed delay")]
    #[serde(default)]
    pub preempt_kicks: u64,
    #[stat(desc = "All fail-closed busy no-kicks")]
    #[serde(default)]
    pub preempt_skipped: u64,
    #[stat(desc = "Q2 idle kicks skipped in 50us")]
    #[serde(default)]
    pub kick_coalesced: u64,
}

/*
 * One card of the per-CPU grid. Static fields come from
 * topology once at attach. Dynamic fields come from the
 * per-CPU map on each poll. The slice holds the fixed
 * slice at 1ms. Group holds 0 for light and 1 for hog.
 */
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerCpuMetrics {
    /* CPU id. */
    #[serde(default)]
    pub id: u32,
    /* Max frequency in kilohertz. Zero when unknown. */
    #[serde(default)]
    pub freq_khz: u64,
    /* Live frequency in kilohertz. Zero when unknown. */
    #[serde(default)]
    pub cur_freq_khz: u64,
    /* Cache domain id. Zero when unknown. */
    #[serde(default)]
    pub llc_id: u32,
    /* True for the second thread of a core. */
    #[serde(default)]
    pub smt: bool,
    /* Group id. 0 is light. 1 is hog. */
    #[serde(default)]
    pub group: u8,
    /* Estimate of the task now on the CPU. Zero idle. */
    #[serde(default)]
    pub running_est_ns: u64,
    /* Pid now on the CPU. Zero when idle. */
    #[serde(default)]
    pub running_pid: u32,
    /* Nice now on the CPU. Zero when idle. Display only. */
    #[serde(default)]
    pub running_nice: i32,
    /* Weight now on the CPU. 1024 when idle. Display only. */
    #[serde(default)]
    pub running_weight: u32,
    /* Delay window in 32us units. 16 arms. Display only. */
    #[serde(default)]
    pub delay_win: u8,
    /* True when latched arm 16 stand 8 holds. Display only. */
    #[serde(default)]
    pub delay_armed: bool,
    /* Current fixed slice in nanos. */
    /* Renamed from tq_ns; old JSON with tq_ns still */
    /* decodes via the alias for one release. */
    #[serde(default, alias = "tq_ns")]
    pub slice_ns: u64,
}

/*
 * Snapshot for the web dashboard. All fields are gauges.
 * The run loop pushes one per iteration. The web thread
 * keeps the newest behind a lock for the handlers.
 * Version plus timestamp plus topology plus depths plus
 * allowance join stats plus per-CPU for one screenshot
 * plus one JSON log with back compat defaults.
 */
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    /* Scheduler wide counters. Raw values. */
    pub stats: Metrics,
    /* One entry per online CPU. */
    #[serde(default)]
    pub per_cpu: Vec<PerCpuMetrics>,
    /* Scheduler version for the page plus the log. */
    #[serde(default)]
    pub version: String,
    /* Wall time in nanos since epoch for the log. */
    #[serde(default)]
    pub timestamp_ns: u64,
    /* One line topology summary for the page. */
    #[serde(default)]
    pub topology: String,
    /* Light queued depth capped at 4 for pressure. */
    #[serde(default)]
    pub light_depth: u64,
    /* Hog queued depth capped at 4 for display. */
    #[serde(default)]
    pub hog_depth: u64,
    /* Burst line in nanos for the light depth. */
    #[serde(default)]
    pub burst_allowance_ns: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime={} uptime={} \
            ins={} req={} done={} park={} steal={} \
            kick={} noctx={} edfenq={} edfclamp={} edford={} \
            demote={} promote={} wpromote={} pinfl={} gskip={} \
            pkick={} pskip={} kcoal={}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.inserts,
            self.requeues,
            self.completions,
            self.park_moves,
            self.steal_moves,
            self.kicks,
            self.enq_no_tctx,
            self.edf_enqueued,
            self.edf_clamped,
            self.edf_ordered,
            self.group_demote,
            self.group_promote,
            self.group_wake_promote,
            self.pinned_hog_inflated,
            self.group_steal_skipped,
            self.preempt_kicks,
            self.preempt_skipped,
            self.kick_coalesced,
        )?;
        Ok(())
    }

    /*
     * Interval delta. Counters move forward. Gauges pass
     * through unchanged.
     */
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            inserts: self.inserts.wrapping_sub(rhs.inserts),
            requeues: self.requeues.wrapping_sub(rhs.requeues),
            completions: self.completions.wrapping_sub(rhs.completions),
            park_moves: self.park_moves.wrapping_sub(rhs.park_moves),
            steal_moves: self.steal_moves.wrapping_sub(rhs.steal_moves),
            kicks: self.kicks.wrapping_sub(rhs.kicks),
            enq_no_tctx: self.enq_no_tctx.wrapping_sub(rhs.enq_no_tctx),
            edf_enqueued: self.edf_enqueued.wrapping_sub(rhs.edf_enqueued),
            edf_clamped: self.edf_clamped.wrapping_sub(rhs.edf_clamped),
            edf_ordered: self.edf_ordered.wrapping_sub(rhs.edf_ordered),
            group_demote: self.group_demote.wrapping_sub(rhs.group_demote),
            group_promote: self.group_promote.wrapping_sub(rhs.group_promote),
            pinned_hog_inflated: self
                .pinned_hog_inflated
                .wrapping_sub(rhs.pinned_hog_inflated),
            group_steal_skipped: self
                .group_steal_skipped
                .wrapping_sub(rhs.group_steal_skipped),
            group_wake_promote: self.group_wake_promote.wrapping_sub(rhs.group_wake_promote),
            preempt_kicks: self.preempt_kicks.wrapping_sub(rhs.preempt_kicks),
            preempt_skipped: self.preempt_skipped.wrapping_sub(rhs.preempt_skipped),
            kick_coalesced: self.kick_coalesced.wrapping_sub(rhs.kick_coalesced),
        }
    }
}

/*
 * Stats server with one top op. The op reports deltas
 * over the poll interval.
 */
type Opener = dyn StatsOpener<(), Metrics>;
type Reader = dyn StatsReader<(), Metrics>;
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<Opener> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;
        let read: Box<Reader> = Box::new(move |_a, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });
        Ok(read)
    });
    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

/*
 * Monitor loop. Polls the stats server and prints one
 * line per interval. Runs on its own thread.
 */
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |m| m.format(&mut std::io::stdout()),
    )
}
