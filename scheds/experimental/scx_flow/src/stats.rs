// SPDX-License-Identifier: GPL-2.0
/*
 * Stats server and web snapshot
 *
 * Exports the metrics view and the dashboard view from the BPF counters.
 * Metrics mirrors inserts, requeues, completions, dispatch moves, and kicks.
 * It also covers preempt detail with EDF and group detail. Web metrics adds
 * per CPU cards with slice, group, delay, depths, and pressure. It also
 * carries version, topology, and timestamp.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
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
/*
 * Counters at 296B with bound gate live since 4.2.41.
 * Kicks plus deserved plus group plus mask plus rate
 * stay live with armed retired frozen for compat.
 */
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
    #[stat(desc = "Live since 4.2.41, busy preempt kicks")]
    #[serde(default)]
    pub preempt_kicks: u64,
    #[stat(desc = "Total busy non-kicks without reason")]
    #[serde(default)]
    pub preempt_skipped: u64,
    #[stat(desc = "Q2 idle kicks skipped in 50us")]
    #[serde(default)]
    pub kick_coalesced: u64,
    #[stat(desc = "Frozen for compat, always zero")]
    #[serde(default)]
    pub preempt_skipped_armed: u64,
    #[stat(desc = "Live since 4.2.41, busy no-kicks for undeserved")]
    #[serde(default)]
    pub preempt_skipped_deserved: u64,
    #[stat(desc = "Live since 4.2.41, busy no-kicks for cross group")]
    #[serde(default)]
    pub preempt_skipped_group: u64,
    #[stat(desc = "Live since 4.2.41, defensive mask, expect ~0")]
    #[serde(default)]
    pub preempt_skipped_mask: u64,
    #[stat(desc = "Live since 4.2.41, busy no-kicks for rate held")]
    #[serde(default)]
    pub preempt_skipped_rate: u64,
    #[stat(desc = "Frozen for compat, always zero")]
    #[serde(default)]
    pub wheel_skips: u64,
    #[stat(desc = "Tail pins past the horizon")]
    #[serde(default)]
    pub wheel_overflow: u64,
    #[stat(desc = "Sleeper token spends")]
    #[serde(default)]
    pub token_boosts: u64,
    #[stat(desc = "Frozen for compat, always zero")]
    #[serde(default)]
    pub wheel_head_hits: u64,
    #[stat(desc = "Frozen for compat, always zero")]
    #[serde(default)]
    pub wheel_fine_hits: u64,
    #[stat(desc = "Frozen for compat, always zero")]
    #[serde(default)]
    pub wheel_coarse_hits: u64,
    #[stat(desc = "Frozen for compat, always zero")]
    #[serde(default)]
    pub wheel_empty: u64,
    #[stat(desc = "Safety net kicks sent")]
    #[serde(default)]
    pub slot_kicks: u64,
    #[stat(desc = "Lost token races")]
    #[serde(default)]
    pub token_cas_fails: u64,
    #[stat(desc = "FIFO tasks moved via slots")]
    #[serde(default)]
    pub slot_moves: u64,
    #[stat(desc = "Capped drains with work left")]
    #[serde(default)]
    pub slot_defer: u64,
    #[stat(desc = "Moves from a cross group peer queue")]
    #[serde(default)]
    pub steal_xmoves: u64,
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
    /* Renamed from tq_ns, and old JSON with tq_ns still */
    /* decodes via the alias for one release. */
    #[serde(default, alias = "tq_ns")]
    pub slice_ns: u64,
    /* Lifetime active nanos from BPF. Full u64 wrap deltas. */
    /* Display only for the energy probe plausibility. */
    #[serde(default)]
    pub active_ns: u64,
}

impl PerCpuMetrics {
    /*
     * Active delta since one older card. Full u64 wrap,
     * so BPF lifetime growth never traps in userspace.
     */
    pub fn active_delta(&self, prev: &Self) -> u64 {
        self.active_ns.wrapping_sub(prev.active_ns)
    }
}

/* Default state text of the energy object. Unavailable */
/* keeps old JSON honest with no silent zero headline. */
fn default_energy_state() -> String {
    "unavailable".to_string()
}

/*
 * Energy savings view for the web dashboard. One nested object with defaults on
 * every field, so old JSON without energy still decodes into the unavailable
 * state. Headline, daily, and yearly share one savings ratio from measured
 * package joules. Daily, yearly, and since running energies come from the same
 * saved W over different spans. Trace holds the live derivation in monospace
 * for the page.
 */
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnergyMetrics {
    /* Probe state. unavailable, baseline, collecting, waiting, backoff. */
    #[serde(default = "default_energy_state")]
    pub state: String,
    /* True once three accepted pairs back the headline. */
    #[serde(default)]
    pub has_headline: bool,
    /* True with three to four pairs. Yearly stays a projection. */
    #[serde(default)]
    pub low_confidence: bool,
    /* Saved percent from the ratio of sums. Signed. */
    #[serde(default)]
    pub headline_pct: f64,
    /* Accepted pairs in the sums. */
    #[serde(default)]
    pub accepted_pairs: u64,
    /* Rejected pairs kept out of the sums. */
    #[serde(default)]
    pub rejected_pairs: u64,
    /* Daily saved percent. Same ratio as the headline. */
    #[serde(default)]
    pub daily_pct: f64,
    /* Daily saved energy in kWh. */
    #[serde(default)]
    pub daily_kwh: f64,
    /* Yearly saved percent. Same ratio as the headline. */
    #[serde(default)]
    pub yearly_pct: f64,
    /* Yearly saved energy in kWh, a projection. */
    #[serde(default)]
    pub yearly_kwh: f64,
    /* Saved energy since attach in kWh, an estimate. */
    #[serde(default)]
    pub since_running_kwh: f64,
    /* Seconds left in the running arm or settle. */
    #[serde(default)]
    pub countdown_s: u64,
    /* Live derivation in monospace for the page. */
    #[serde(default)]
    pub trace: String,
}

impl Default for EnergyMetrics {
    /* Missing energy means unavailable, never zero headline. */
    fn default() -> Self {
        Self {
            state: default_energy_state(),
            has_headline: false,
            low_confidence: false,
            headline_pct: 0.0,
            accepted_pairs: 0,
            rejected_pairs: 0,
            daily_pct: 0.0,
            daily_kwh: 0.0,
            yearly_pct: 0.0,
            yearly_kwh: 0.0,
            since_running_kwh: 0.0,
            countdown_s: 0,
            trace: String::new(),
        }
    }
}

/*
 * Snapshot for the web dashboard. All fields are gauges.
 * The run loop pushes one per iteration. The web thread
 * keeps the newest behind a lock for the handlers.
 * Version, timestamp, topology, depths, allowance, perf mode, and governor
 * join stats and per-CPU. The set covers one screenshot and one JSON log
 * with back compat defaults.
 */
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    /* Scheduler wide counters. Raw values. */
    pub stats: Metrics,
    /* One entry per online CPU. */
    #[serde(default)]
    pub per_cpu: Vec<PerCpuMetrics>,
    /* Scheduler version for the page and the log. */
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
    /* Placement widen flag. Zero is strict, one is perf. */
    #[serde(default)]
    pub perf_mode: u8,
    /* Governor display with EPP and platform suffix. */
    #[serde(default)]
    pub governor: String,
    /* Energy savings view. Defaults to unavailable. */
    #[serde(default)]
    pub energy: EnergyMetrics,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime={} uptime={} \
            ins={} req={} done={} park={} steal={} \
            kick={} noctx={} edfenq={} edfclamp={} edford={} \
            demote={} promote={} wpromote={} pinfl={} gskip={} \
            pkick={} pskip={} kcoal={} \
            pskip_a={} pskip_d={} pskip_g={} pskip_m={} pskip_r={} \
            wskips={} wover={} tboost={} \
            whead={} wfine={} wcoarse={} wempty={} \
            skicks={} tcas={} smoves={} sdefer={} stealx={}",
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
            self.preempt_skipped_armed,
            self.preempt_skipped_deserved,
            self.preempt_skipped_group,
            self.preempt_skipped_mask,
            self.preempt_skipped_rate,
            self.wheel_skips,
            self.wheel_overflow,
            self.token_boosts,
            self.wheel_head_hits,
            self.wheel_fine_hits,
            self.wheel_coarse_hits,
            self.wheel_empty,
            self.slot_kicks,
            self.token_cas_fails,
            self.slot_moves,
            self.slot_defer,
            self.steal_xmoves,
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
            preempt_skipped_armed: self
                .preempt_skipped_armed
                .wrapping_sub(rhs.preempt_skipped_armed),
            preempt_skipped_deserved: self
                .preempt_skipped_deserved
                .wrapping_sub(rhs.preempt_skipped_deserved),
            preempt_skipped_group: self
                .preempt_skipped_group
                .wrapping_sub(rhs.preempt_skipped_group),
            preempt_skipped_mask: self
                .preempt_skipped_mask
                .wrapping_sub(rhs.preempt_skipped_mask),
            preempt_skipped_rate: self
                .preempt_skipped_rate
                .wrapping_sub(rhs.preempt_skipped_rate),
            wheel_skips: self.wheel_skips.wrapping_sub(rhs.wheel_skips),
            wheel_overflow: self.wheel_overflow.wrapping_sub(rhs.wheel_overflow),
            token_boosts: self.token_boosts.wrapping_sub(rhs.token_boosts),
            wheel_head_hits: self.wheel_head_hits.wrapping_sub(rhs.wheel_head_hits),
            wheel_fine_hits: self.wheel_fine_hits.wrapping_sub(rhs.wheel_fine_hits),
            wheel_coarse_hits: self.wheel_coarse_hits.wrapping_sub(rhs.wheel_coarse_hits),
            wheel_empty: self.wheel_empty.wrapping_sub(rhs.wheel_empty),
            slot_kicks: self.slot_kicks.wrapping_sub(rhs.slot_kicks),
            token_cas_fails: self.token_cas_fails.wrapping_sub(rhs.token_cas_fails),
            slot_moves: self.slot_moves.wrapping_sub(rhs.slot_moves),
            slot_defer: self.slot_defer.wrapping_sub(rhs.slot_defer),
            steal_xmoves: self.steal_xmoves.wrapping_sub(rhs.steal_xmoves),
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
