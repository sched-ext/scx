use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
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
    #[stat(desc = "Number of task direct dispatches")]
    pub nr_direct_dispatches: u64,
    #[stat(desc = "Number of task enqueues to vtime-ordered DSQs")]
    pub nr_enqueues: u64,
    #[stat(desc = "Number of preemption dispatches on sleeper wakeup")]
    pub nr_preempt_dispatches: u64,
    #[stat(desc = "Number of dispatches from the local CPU DSQ")]
    pub nr_local_dispatches: u64,
    #[stat(desc = "Number of dispatches stolen from a remote CPU DSQ")]
    pub nr_remote_dispatches: u64,
    #[stat(desc = "Number of dispatches from the local LLC DSQ")]
    pub nr_llc_dispatches: u64,
    #[stat(desc = "Number of dispatches from the local NUMA node DSQ")]
    pub nr_node_dispatches: u64,
    #[stat(desc = "Number of dispatches from the global DSQ")]
    pub nr_global_dispatches: u64,
    #[stat(desc = "Number of task dequeue callbacks")]
    pub nr_dequeues: u64,
    #[stat(desc = "Number of regular dispatch dequeue callbacks")]
    pub nr_dispatch_dequeues: u64,
    #[stat(desc = "Number of scheduling property change dequeue callbacks")]
    pub nr_sched_change_dequeues: u64,
    #[stat(desc = "Number of task state tracking errors")]
    pub nr_task_state_errors: u64,
    #[stat(desc = "Number of event-heavy task migrations to an idle CPU")]
    pub nr_event_dispatches: u64,
    #[stat(desc = "Number of sticky direct dispatches keeping a task on its CPU")]
    pub nr_ev_sticky_dispatches: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] tasks -> dispatch -> d: {:<5} enq: {:<5} preempt: {:<5} l: {:<5} r: {:<5} llc: {:<5} node: {:<5} g: {:<5} deq: {:<5} dd: {:<5} change: {:<5} err: {:<5} ev: {:<5} sticky: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_direct_dispatches,
            self.nr_enqueues,
            self.nr_preempt_dispatches,
            self.nr_local_dispatches,
            self.nr_remote_dispatches,
            self.nr_llc_dispatches,
            self.nr_node_dispatches,
            self.nr_global_dispatches,
            self.nr_dequeues,
            self.nr_dispatch_dequeues,
            self.nr_sched_change_dequeues,
            self.nr_task_state_errors,
            self.nr_event_dispatches,
            self.nr_ev_sticky_dispatches,
        )?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            nr_direct_dispatches: self.nr_direct_dispatches - rhs.nr_direct_dispatches,
            nr_enqueues: self.nr_enqueues - rhs.nr_enqueues,
            nr_preempt_dispatches: self.nr_preempt_dispatches - rhs.nr_preempt_dispatches,
            nr_local_dispatches: self.nr_local_dispatches - rhs.nr_local_dispatches,
            nr_remote_dispatches: self.nr_remote_dispatches - rhs.nr_remote_dispatches,
            nr_llc_dispatches: self.nr_llc_dispatches - rhs.nr_llc_dispatches,
            nr_node_dispatches: self.nr_node_dispatches - rhs.nr_node_dispatches,
            nr_global_dispatches: self.nr_global_dispatches - rhs.nr_global_dispatches,
            nr_dequeues: self.nr_dequeues - rhs.nr_dequeues,
            nr_dispatch_dequeues: self.nr_dispatch_dequeues - rhs.nr_dispatch_dequeues,
            nr_sched_change_dequeues: self.nr_sched_change_dequeues - rhs.nr_sched_change_dequeues,
            nr_task_state_errors: self.nr_task_state_errors - rhs.nr_task_state_errors,
            nr_event_dispatches: self.nr_event_dispatches - rhs.nr_event_dispatches,
            nr_ev_sticky_dispatches: self.nr_ev_sticky_dispatches - rhs.nr_ev_sticky_dispatches,
            ..self.clone()
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

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
