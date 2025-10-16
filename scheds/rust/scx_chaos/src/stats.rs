use std::io::Write;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of times random delay chaos trait was applied")]
    pub trait_random_delays: u64,
    #[stat(desc = "Number of times CPU frequency chaos trait was applied")]
    pub trait_cpu_freq: u64,
    #[stat(desc = "Number of times performance degradation chaos trait was applied")]
    pub trait_degradation: u64,
    #[stat(desc = "Number of times chaos was excluded due to task matching")]
    pub chaos_excluded: u64,
    #[stat(desc = "Number of times chaos was skipped (TRAIT_NONE selected)")]
    pub chaos_skipped: u64,
    #[stat(desc = "Number of timer-based CPU kicks for delayed tasks")]
    pub timer_kicks: u64,
    #[stat(desc = "Number of times a kprobe caused a random delay to be applied")]
    pub kprobe_random_delays: u64,
    #[stat(desc = "Peek found empty DSQ")]
    pub peek_empty_dsq: u64,
    #[stat(desc = "Peek found task not ready")]
    pub peek_not_ready: u64,
    #[stat(desc = "Peek determined DSQ needs processing")]
    pub peek_needs_processing: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "chaos traits: random_delays/cpu_freq/degradation {}/{}/{}\n\tchaos excluded/skipped {}/{}\n\tkprobe_random_delays {}\n\ttimer kicks: {}",
            self.trait_random_delays,
            self.trait_cpu_freq,
            self.trait_degradation,
            self.chaos_excluded,
            self.chaos_skipped,
            self.kprobe_random_delays,
            self.timer_kicks,
        )?;
        writeln!(
            w,
            "peek: empty/not_ready/needs_proc {}/{}/{}",
            self.peek_empty_dsq, self.peek_not_ready, self.peek_needs_processing,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            trait_random_delays: self.trait_random_delays - rhs.trait_random_delays,
            trait_cpu_freq: self.trait_cpu_freq - rhs.trait_cpu_freq,
            trait_degradation: self.trait_degradation - rhs.trait_degradation,
            chaos_excluded: self.chaos_excluded - rhs.chaos_excluded,
            chaos_skipped: self.chaos_skipped - rhs.chaos_skipped,
            kprobe_random_delays: self.kprobe_random_delays - rhs.kprobe_random_delays,
            timer_kicks: self.timer_kicks - rhs.timer_kicks,
            peek_empty_dsq: self.peek_empty_dsq - rhs.peek_empty_dsq,
            peek_not_ready: self.peek_not_ready - rhs.peek_not_ready,
            peek_needs_processing: self.peek_needs_processing - rhs.peek_needs_processing,
        }
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
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

pub fn monitor(intv: Duration, shutdown: Arc<(Mutex<bool>, Condvar)>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || {
            let (lock, _) = &*shutdown;
            *lock.lock().unwrap()
        },
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
