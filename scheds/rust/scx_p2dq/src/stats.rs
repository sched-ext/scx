use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_p2dq::TOPO;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

// Global flag to track if thermal pressure tracking is enabled
static THERMAL_TRACKING_ENABLED: AtomicBool = AtomicBool::new(false);

// Global flag to track if energy-aware scheduling is enabled
static EAS_ENABLED: AtomicBool = AtomicBool::new(false);

static ATQ_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_thermal_tracking_enabled(enabled: bool) {
    THERMAL_TRACKING_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_thermal_tracking_enabled() -> bool {
    THERMAL_TRACKING_ENABLED.load(Ordering::Relaxed)
}

pub fn set_eas_enabled(enabled: bool) {
    EAS_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_eas_enabled() -> bool {
    EAS_ENABLED.load(Ordering::Relaxed)
}

pub fn set_atq_enabled(enabled: bool) {
    ATQ_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_atq_enabled() -> bool {
    ATQ_ENABLED.load(Ordering::Relaxed)
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of times a task was enqueued to a ATQ")]
    pub atq_enq: u64,
    #[stat(desc = "Number of times a task was re-enqueued to a ATQ")]
    pub atq_reenq: u64,
    #[stat(desc = "Number of times tasks have switched DSQs")]
    pub dsq_change: u64,
    #[stat(desc = "Number of times tasks have stayed on the same DSQ")]
    pub same_dsq: u64,
    #[stat(desc = "Number of times a task kept running")]
    pub keep: u64,
    #[stat(desc = "Number of times a task was enqueued to CPUC DSQ")]
    pub enq_cpu: u64,
    #[stat(desc = "Number of times a task was enqueued to LLC DSQ")]
    pub enq_llc: u64,
    #[stat(desc = "Number of times a task was enqueued to interactive DSQ")]
    pub enq_intr: u64,
    #[stat(desc = "Number of times a task was enqueued to migration DSQ")]
    pub enq_mig: u64,
    #[stat(desc = "Number of times a select_cpu pick 2 load balancing occurred")]
    pub select_pick2: u64,
    #[stat(desc = "Number of times a dispatch pick 2 load balancing occurred")]
    pub dispatch_pick2: u64,
    #[stat(desc = "Number of times a task migrated LLCs")]
    pub llc_migrations: u64,
    #[stat(desc = "Number of times a task migrated NUMA nodes")]
    pub node_migrations: u64,
    #[stat(desc = "Number of times tasks have directly been dispatched to local per CPU DSQs")]
    pub direct: u64,
    #[stat(desc = "Number of times tasks have dispatched to an idle local per CPU DSQs")]
    pub idle: u64,
    #[stat(desc = "Number of times tasks have been woken to the previous CPU")]
    pub wake_prev: u64,
    #[stat(desc = "Number of times tasks have been woken to the previous llc")]
    pub wake_llc: u64,
    #[stat(desc = "Number of times tasks have been woken and migrated llc")]
    pub wake_mig: u64,
    #[stat(desc = "Number of times fork balancing migrated to different LLC")]
    pub fork_balance: u64,
    #[stat(desc = "Number of times exec balancing migrated to different LLC")]
    pub exec_balance: u64,
    #[stat(desc = "Number of times fork stayed on same LLC")]
    pub fork_same_llc: u64,
    #[stat(desc = "Number of times exec stayed on same LLC")]
    pub exec_same_llc: u64,
    #[stat(desc = "Number of CPU kicks due to thermal pressure")]
    pub thermal_kick: u64,
    #[stat(desc = "Number of times throttled CPUs were avoided")]
    pub thermal_avoid: u64,
    #[stat(desc = "Number of times EAS placed task on little core")]
    pub eas_little_select: u64,
    #[stat(desc = "Number of times EAS placed task on big core")]
    pub eas_big_select: u64,
    #[stat(desc = "Number of times EAS fell back to non-preferred core type")]
    pub eas_fallback: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        let multi_llc = TOPO.all_llcs.len() > 1;
        let atq = is_atq_enabled();

        write!(
            w,
            "direct/idle/keep {}/{}/{}\n\tdsq same/migrate {}/{}",
            self.direct, self.idle, self.keep, self.same_dsq, self.dsq_change,
        )?;

        if atq {
            write!(w, "\n\tatq enq/reenq {}/{}", self.atq_enq, self.atq_reenq)?;
        }

        if multi_llc {
            writeln!(
                w,
                "\n\tenq cpu/llc/intr/mig {}/{}/{}/{}",
                self.enq_cpu, self.enq_llc, self.enq_intr, self.enq_mig,
            )?;
        } else {
            writeln!(
                w,
                "\n\tenq cpu/llc/intr {}/{}/{}",
                self.enq_cpu, self.enq_llc, self.enq_intr,
            )?;
        }

        let mut stats_line = format!("\twake prev {}", self.wake_prev);

        if multi_llc {
            stats_line.push_str(&format!(
                "/llc/mig {}/{}\n\tpick2 select/dispatch {}/{}\n\tmigrations llc/node {}/{}\n\tfork balance/same {}/{}\n\texec balance/same {}/{}",
                self.wake_llc,
                self.wake_mig,
                self.select_pick2,
                self.dispatch_pick2,
                self.llc_migrations,
                self.node_migrations,
                self.fork_balance,
                self.fork_same_llc,
                self.exec_balance,
                self.exec_same_llc,
            ));
        }

        if is_thermal_tracking_enabled() {
            stats_line.push_str(&format!(
                "\n\tthermal kick/avoid {}/{}",
                self.thermal_kick, self.thermal_avoid,
            ));
        }

        if is_eas_enabled() {
            stats_line.push_str(&format!(
                "\n\tEAS little/big/fallback {}/{}/{}",
                self.eas_little_select, self.eas_big_select, self.eas_fallback,
            ));
        }

        writeln!(w, "{}", stats_line)?;
        Ok(())
    }

    fn delta(&self, rhs: &Self) -> Self {
        Self {
            atq_enq: self.atq_enq - rhs.atq_enq,
            atq_reenq: self.atq_reenq - rhs.atq_reenq,
            direct: self.direct - rhs.direct,
            idle: self.idle - rhs.idle,
            dsq_change: self.dsq_change - rhs.dsq_change,
            same_dsq: self.same_dsq - rhs.same_dsq,
            keep: self.keep - rhs.keep,
            enq_cpu: self.enq_cpu - rhs.enq_cpu,
            enq_llc: self.enq_llc - rhs.enq_llc,
            enq_intr: self.enq_intr - rhs.enq_intr,
            enq_mig: self.enq_mig - rhs.enq_mig,
            select_pick2: self.select_pick2 - rhs.select_pick2,
            dispatch_pick2: self.dispatch_pick2 - rhs.dispatch_pick2,
            llc_migrations: self.llc_migrations - rhs.llc_migrations,
            node_migrations: self.node_migrations - rhs.node_migrations,
            wake_prev: self.wake_prev - rhs.wake_prev,
            wake_llc: self.wake_llc - rhs.wake_llc,
            wake_mig: self.wake_mig - rhs.wake_mig,
            fork_balance: self.fork_balance - rhs.fork_balance,
            exec_balance: self.exec_balance - rhs.exec_balance,
            fork_same_llc: self.fork_same_llc - rhs.fork_same_llc,
            exec_same_llc: self.exec_same_llc - rhs.exec_same_llc,
            thermal_kick: self.thermal_kick - rhs.thermal_kick,
            thermal_avoid: self.thermal_avoid - rhs.thermal_avoid,
            eas_little_select: self.eas_little_select - rhs.eas_little_select,
            eas_big_select: self.eas_big_select - rhs.eas_big_select,
            eas_fallback: self.eas_fallback - rhs.eas_fallback,
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
