// SPDX-License-Identifier: GPL-2.0
//! Statistics reported by scx_flow.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

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
/// Scheduler counters, summed over all LLCs or reported for one LLC.
pub struct Metrics {
    #[stat(desc = "Tasks waiting in the scheduler queues")]
    pub queued: u64,
    #[stat(desc = "Tasks moved from a scheduler queue to a CPU")]
    pub dispatched: u64,
    #[stat(desc = "Wakeups sent straight to an idle CPU")]
    pub direct: u64,
    #[stat(desc = "Tasks pulled from the queue of another LLC")]
    pub steal: u64,
    #[stat(desc = "Tasks queued on the fallback queue")]
    pub fallback: u64,
    #[stat(desc = "Idle CPUs woken up for a queued task")]
    pub kick_idle: u64,
    #[stat(desc = "Running tasks asked to give up their CPU")]
    pub kick_preempt: u64,
    #[stat(desc = "Tasks kept running with a new slice")]
    pub keep: u64,
    #[stat(desc = "Tasks stopped while still runnable")]
    pub preempted: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "queued={} dispatched={} direct={} steal={} fallback={} kick_idle={} kick_preempt={} keep={} preempted={}",
            self.queued,
            self.dispatched,
            self.direct,
            self.steal,
            self.fallback,
            self.kick_idle,
            self.kick_preempt,
            self.keep,
            self.preempted,
        )?;
        Ok(())
    }

    /// The totals of the whole scheduler.
    pub fn format_total<W: Write>(&self, w: &mut W) -> Result<()> {
        write!(w, "[{}] ", crate::cli::SCHEDULER_NAME)?;
        self.format(w)
    }

    /// The counters of one LLC.
    pub fn format_llc<W: Write>(&self, w: &mut W, llc: usize) -> Result<()> {
        write!(w, "[{}:llc{llc}] ", crate::cli::SCHEDULER_NAME)?;
        self.format(w)
    }

    /// Wrapping add, so that totals stay valid once a counter wraps.
    pub fn add(&mut self, rhs: &Self) {
        self.queued = self.queued.wrapping_add(rhs.queued);
        self.dispatched = self.dispatched.wrapping_add(rhs.dispatched);
        self.direct = self.direct.wrapping_add(rhs.direct);
        self.steal = self.steal.wrapping_add(rhs.steal);
        self.fallback = self.fallback.wrapping_add(rhs.fallback);
        self.kick_idle = self.kick_idle.wrapping_add(rhs.kick_idle);
        self.kick_preempt = self.kick_preempt.wrapping_add(rhs.kick_preempt);
        self.keep = self.keep.wrapping_add(rhs.keep);
        self.preempted = self.preempted.wrapping_add(rhs.preempted);
    }

    /// Events since @rhs was taken. The queue length is a gauge and is
    /// reported as it is.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            queued: self.queued,
            dispatched: self.dispatched.wrapping_sub(rhs.dispatched),
            direct: self.direct.wrapping_sub(rhs.direct),
            steal: self.steal.wrapping_sub(rhs.steal),
            fallback: self.fallback.wrapping_sub(rhs.fallback),
            kick_idle: self.kick_idle.wrapping_sub(rhs.kick_idle),
            kick_preempt: self.kick_preempt.wrapping_sub(rhs.kick_preempt),
            keep: self.keep.wrapping_sub(rhs.keep),
            preempted: self.preempted.wrapping_sub(rhs.preempted),
        }
    }
}

/// Print the statistics of a running scheduler every @intv.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format_total(&mut std::io::stdout()),
    )
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev: Metrics = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur: Metrics = res_ch.recv()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_keeps_the_gauge_and_wraps() {
        let cur = Metrics {
            queued: 3,
            dispatched: 5,
            preempted: 1,
            ..Default::default()
        };
        let prev = Metrics {
            queued: 7,
            dispatched: 3,
            preempted: 2,
            ..Default::default()
        };
        let d = cur.delta(&prev);
        assert_eq!(d.queued, 3);
        assert_eq!(d.dispatched, 2);
        assert_eq!(d.preempted, u64::MAX);
    }

    #[test]
    fn add_sums_every_field() {
        let one = Metrics {
            queued: 1,
            dispatched: 2,
            direct: 3,
            steal: 4,
            fallback: 5,
            kick_idle: 6,
            kick_preempt: 7,
            keep: 8,
            preempted: 9,
        };
        let mut sum = one.clone();
        sum.add(&one);
        assert_eq!(sum.delta(&one).dispatched, one.dispatched);
        assert_eq!(sum.queued, 2);
        assert_eq!(sum.preempted, 18);
    }
}
