use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Local;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of running tasks")]
    pub nr_running: u64,
    #[stat(desc = "Number of CPUs")]
    pub nr_cpus: u64,
    #[stat(desc = "Number of direct kthread dispatches")]
    pub nr_kthread_dispatches: u64,
    #[stat(desc = "Number of direct to idle cpu dispatches")]
    pub nr_direct_to_idle_dispatches: u64,
    #[stat(desc = "Number of vm queue dispatches")]
    pub nr_vm_dispatches: u64,
    #[stat(desc = "Number of preemptions per CPU")]
    pub per_cpu_preempted: Vec<u64>,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        let now = Local::now(); // Get the current local time
        write!(w, "{}", now.format("[%Y-%m-%d %H:%M:%S] "))?; // Add formatted timestamp

        // Fixed width for scheduler name and task details
        writeln!(
            w,
            "[{:<10}] tasks -> r: {:>2}/{:<2} | dispatch -> k: {:<5} d2i: {:<5} vm: {:<5}",
            crate::SCHEDULER_NAME,
            self.nr_running,
            self.nr_cpus,
            self.nr_kthread_dispatches,
            self.nr_direct_to_idle_dispatches,
            self.nr_vm_dispatches
        )?;

        // Limit preemption output to nr_cpus and align it in columns, with consistent padding
        writeln!(w, "     Preemptions:")?;
        for (cpu_id, preemptions) in self
            .per_cpu_preempted
            .iter()
            .enumerate()
            .take(self.nr_cpus as usize)
        {
            writeln!(w, "     CPU #{}: {:<5?}", cpu_id, preemptions)?; // Align CPU# output with padding
        }

        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        // Assuming per_cpu_preempted is a Vec or an array-like structure
        let per_cpu_preempted_delta: Vec<_> = self
            .per_cpu_preempted
            .iter()
            .zip(&rhs.per_cpu_preempted)
            .map(|(lhs, rhs)| lhs - rhs)
            .collect();

        Self {
            nr_kthread_dispatches: self.nr_kthread_dispatches - rhs.nr_kthread_dispatches,
            nr_direct_to_idle_dispatches: self.nr_direct_to_idle_dispatches
                - rhs.nr_direct_to_idle_dispatches,
            nr_vm_dispatches: self.nr_vm_dispatches - rhs.nr_vm_dispatches,
            per_cpu_preempted: per_cpu_preempted_delta, // Compute the delta for per_cpu_preempted
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
        &vec![],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
