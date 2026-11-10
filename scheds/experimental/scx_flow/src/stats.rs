// SPDX-License-Identifier: GPL-2.0
//! Stats server for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Exports per LLC counters summed across LLCs.

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
/// Per LLC counters for queueing and kicks.
pub struct Metrics {
    #[stat(desc = "Tasks now queued in DSQ")]
    #[serde(default)]
    pub queued: u64,
    #[stat(desc = "Tasks moved to local in dispatch")]
    #[serde(default)]
    pub dispatched: u64,
    #[stat(desc = "Fallback inserts and duplicate drops")]
    #[serde(default)]
    pub fallback: u64,
    #[stat(desc = "Remote LLC queue moves in dispatch")]
    #[serde(default)]
    pub steal: u64,
    #[stat(desc = "Duplicate requeues dropped while queued")]
    #[serde(default)]
    pub fb_duplicate: u64,
    #[stat(desc = "Remote moves counted on the thief")]
    #[serde(default)]
    pub steal_llc: u64,
    #[stat(desc = "Preempt kicks on enqueue")]
    #[serde(default)]
    pub kick_preempt: u64,
    #[stat(desc = "Idle kicks on enqueue")]
    #[serde(default)]
    pub kick_idle: u64,
    #[stat(desc = "Skipped enqueue kicks")]
    #[serde(default)]
    pub kick_skip: u64,
    #[stat(desc = "Tasks that burnt the full slice")]
    #[serde(default)]
    pub overrun: u64,
    #[stat(desc = "Stops that leave the task still runnable")]
    #[serde(default)]
    pub blocked: u64,
    #[stat(desc = "Mask change kicks for queued tasks")]
    #[serde(default)]
    pub orphan_kick: u64,
    #[stat(desc = "Forwards where the head cannot run here")]
    #[serde(default)]
    pub hol_forward: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] queued={} dispatched={} fallback={} steal={} fb_duplicate={} steal_llc={} kick_preempt={} kick_idle={} kick_skip={} overrun={} blocked={} orphan_kick={} hol_forward={}",
            crate::cli::SCHEDULER_NAME,
            self.queued,
            self.dispatched,
            self.fallback,
            self.steal,
            self.fb_duplicate,
            self.steal_llc,
            self.kick_preempt,
            self.kick_idle,
            self.kick_skip,
            self.overrun,
            self.blocked,
            self.orphan_kick,
            self.hol_forward,
        )?;
        Ok(())
    }

    /// Single LLC row with the same fields plus the LLC index.
    /// Keeps struct order with no reorder.
    pub fn format_llc<W: Write>(&self, w: &mut W, llc: u32) -> Result<()> {
        write!(w, "[{}:llc{}] ", crate::cli::SCHEDULER_NAME, llc)?;
        self.format(w)
    }

    /// Interval delta. Queued passes through as a live gauge.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            queued: self.queued,
            dispatched: self.dispatched.wrapping_sub(rhs.dispatched),
            fallback: self.fallback.wrapping_sub(rhs.fallback),
            steal: self.steal.wrapping_sub(rhs.steal),
            fb_duplicate: self.fb_duplicate.wrapping_sub(rhs.fb_duplicate),
            steal_llc: self.steal_llc.wrapping_sub(rhs.steal_llc),
            kick_preempt: self.kick_preempt.wrapping_sub(rhs.kick_preempt),
            kick_idle: self.kick_idle.wrapping_sub(rhs.kick_idle),
            kick_skip: self.kick_skip.wrapping_sub(rhs.kick_skip),
            overrun: self.overrun.wrapping_sub(rhs.overrun),
            blocked: self.blocked.wrapping_sub(rhs.blocked),
            orphan_kick: self.orphan_kick.wrapping_sub(rhs.orphan_kick),
            hol_forward: self.hol_forward.wrapping_sub(rhs.hol_forward),
        }
    }
}

/// Stats printer loop for the monitor flag.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}

/// Server data for the stats server.
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open_top: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let cur: Metrics = res_ch.recv()?;
        let mut prev: Metrics = cur.clone();
        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur: Metrics = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur.clone();
            delta.to_json()
        });
        Ok(read)
    });
    StatsServerData::new().add_meta(Metrics::meta()).add_ops(
        "top",
        StatsOps {
            open: open_top,
            close: None,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::fold_llc_val;

    #[test]
    fn delta_keeps_gauge_and_wraps() {
        let mut cur = Metrics::default();
        let mut prev = Metrics::default();
        cur.queued = 3;
        prev.queued = 7;
        cur.dispatched = 5;
        prev.dispatched = 3;
        cur.hol_forward = 1;
        prev.hol_forward = 2;
        let d = cur.delta(&prev);
        assert_eq!(d.queued, 3);
        assert_eq!(d.dispatched, 2);
        assert_eq!(d.hol_forward, 1u64.wrapping_sub(2));
    }

    #[test]
    fn fold_len_guards_keep_tails() {
        let mut short = Metrics::default();
        let tiny = [0u8; 16];
        fold_llc_val(&mut short, &tiny);
        assert_eq!(short.queued, 0);
        assert_eq!(short.hol_forward, 0);

        let mut half = Metrics::default();
        let mut buf48 = [0u8; 48];
        buf48[40..48].copy_from_slice(&7u64.to_ne_bytes());
        fold_llc_val(&mut half, &buf48);
        assert_eq!(half.steal_llc, 7);
        assert_eq!(half.hol_forward, 0);

        let mut full = Metrics::default();
        let mut buf104 = [0u8; 104];
        buf104[0..8].copy_from_slice(&1u64.to_ne_bytes());
        buf104[96..104].copy_from_slice(&9u64.to_ne_bytes());
        fold_llc_val(&mut full, &buf104);
        assert_eq!(full.queued, 1);
        assert_eq!(full.hol_forward, 9);

        let mut over = Metrics::default();
        let mut buf112 = [0u8; 112];
        buf112[96..104].copy_from_slice(&4u64.to_ne_bytes());
        fold_llc_val(&mut over, &buf112);
        assert_eq!(over.hol_forward, 4);
    }
}
