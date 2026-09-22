use std::collections::BTreeMap;
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

use crate::console;

/// Kernel BPF run-time statistics of one sched_ext callback, see
/// BPF_ENABLE_STATS. Cumulative on the server side, per interval once the
/// client has taken the delta.
#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "op_", _om_label = "callback")]
pub struct OpStats {
    #[stat(desc = "Times the callback ran")]
    pub calls: u64,

    #[stat(desc = "Nanoseconds spent in the callback")]
    pub ns: u64,

    #[stat(desc = "Runs refused because the callback was already active on the CPU")]
    pub misses: u64,
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Monotonic nanoseconds covered by this sample")]
    pub elapsed_ns: u64,

    #[stat(desc = "Number of CPUs the overhead is spread over")]
    pub nr_cpus: u64,

    #[stat(desc = "Kernel BPF run-time statistics are enabled (1) or unavailable (0)")]
    pub ops_profiled: u64,

    #[stat(desc = "Periodic SIS_UTIL scan-budget updates")]
    pub nr_sis_updates: u64,

    #[stat(desc = "Sum of the scan budgets produced by SIS_UTIL updates")]
    pub sis_scan_sum: u64,

    #[stat(desc = "Latency-credit loans granted, counted only while the budget is bounded")]
    pub nr_credit_grants: u64,

    #[stat(desc = "Wakees refused the latency credit because their CPU was out of budget")]
    pub nr_credit_denied: u64,

    #[stat(desc = "Bytes of arena pages the kernel has allocated")]
    pub arena_bytes: u64,

    #[stat(desc = "Size of the arena map in bytes")]
    pub arena_max_bytes: u64,

    #[stat(
        desc = "Arena usage is known (1): counted at the allocator with --stats, or by the kernel"
    )]
    pub arena_counted: u64,

    #[stat(desc = "Arena allocator objects currently allocated, task contexts mostly")]
    pub arena_active_allocs: u64,

    #[stat(desc = "Arena allocations that failed because the kernel refused a page")]
    pub arena_alloc_failures: u64,

    #[stat(desc = "sched_ext callbacks, keyed by name, see BPF_ENABLE_STATS")]
    pub ops: BTreeMap<String, OpStats>,
}

impl Metrics {
    /// Per-interval view: counters become deltas, the rest stays as it is.
    fn delta(&self, rhs: &Self) -> Self {
        let ops = self
            .ops
            .iter()
            .map(|(name, cur)| {
                let prev = rhs.ops.get(name).cloned().unwrap_or_default();
                (
                    name.clone(),
                    OpStats {
                        calls: cur.calls.saturating_sub(prev.calls),
                        ns: cur.ns.saturating_sub(prev.ns),
                        misses: cur.misses.saturating_sub(prev.misses),
                    },
                )
            })
            .collect();

        Self {
            elapsed_ns: self.elapsed_ns.saturating_sub(rhs.elapsed_ns),
            nr_sis_updates: self.nr_sis_updates.saturating_sub(rhs.nr_sis_updates),
            sis_scan_sum: self.sis_scan_sum.saturating_sub(rhs.sis_scan_sum),
            nr_credit_grants: self.nr_credit_grants.saturating_sub(rhs.nr_credit_grants),
            nr_credit_denied: self.nr_credit_denied.saturating_sub(rhs.nr_credit_denied),
            ops,
            ..self.clone()
        }
    }

    /// Share of the loans the budget asked for that it could not make. The
    /// knob is a percentage, so this is what says whether it is binding.
    fn credit_refused(&self) -> f64 {
        let asked = self.nr_credit_grants + self.nr_credit_denied;
        if asked > 0 {
            self.nr_credit_denied as f64 * 100.0 / asked as f64
        } else {
            0.0
        }
    }

    fn calls(&self, op: &str) -> u64 {
        self.ops.get(op).map(|o| o.calls).unwrap_or(0)
    }

    fn secs(&self) -> f64 {
        (self.elapsed_ns.max(1)) as f64 / 1e9
    }

    fn ops_ns(&self) -> u64 {
        self.ops.values().map(|o| o.ns).sum()
    }

    /// Total callback time over the sample, as a fraction of one CPU.
    fn ops_cpu(&self) -> f64 {
        self.ops_ns() as f64 / self.elapsed_ns.max(1) as f64
    }

    fn sis_avg_scan(&self) -> f64 {
        if self.nr_sis_updates > 0 {
            self.sis_scan_sum as f64 / self.nr_sis_updates as f64
        } else {
            0.0
        }
    }
}

/// Display order of the callbacks: the task's life from wakeup to exit,
/// then the cgroup and scheduler-wide ones. Anything unlisted follows,
/// alphabetically.
const OP_ORDER: &[&str] = &[
    "select_cid",
    "enqueue",
    "dequeue",
    "dispatch",
    "running",
    "stopping",
    "quiescent",
    "tick",
    "yield",
    "core_sched_before",
    "update_idle",
    "set_weight",
    "set_cmask",
    "enable",
    "init_task",
    "exit_task",
    "cpuctl_init",
    "cpuctl_exit",
    "cpuctl_set_weight",
    "cpuctl_set_idle",
    "cpuctl_set_bandwidth",
    "cpuctl_move",
    "init",
    "exit",
];

fn op_rank(name: &str) -> usize {
    OP_ORDER
        .iter()
        .position(|&n| n == name)
        .unwrap_or(OP_ORDER.len())
}

/// Human scale for a rate or a count: 12.3k, 1.2M.
fn human(v: f64) -> String {
    if v >= 1e6 {
        format!("{:.1}M", v / 1e6)
    } else if v >= 1e4 {
        format!("{:.0}k", v / 1e3)
    } else if v >= 1e3 {
        format!("{:.1}k", v / 1e3)
    } else if v >= 10.0 || (v - v.round()).abs() < 0.05 {
        format!("{:.0}", v)
    } else {
        format!("{:.1}", v)
    }
}

/// Human scale for a size in bytes: 512 B, 1.5 MiB.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit + 1 < UNITS.len() {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

/// Human scale for a duration in nanoseconds.
fn human_ns(ns: f64) -> String {
    if ns >= 1e6 {
        format!("{:.2}ms", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.2}us", ns / 1e3)
    } else {
        format!("{:.0}ns", ns)
    }
}

/// Print the metrics as one block per interval, appended like a log so the
/// history stays in the scrollback and in any file the output goes to.
struct Dashboard {
    intv: Duration,
    frames: u64,
    started: std::time::Instant,
}

impl Dashboard {
    fn new(intv: Duration) -> Self {
        Self {
            intv,
            frames: 0,
            started: std::time::Instant::now(),
        }
    }

    fn render(&mut self, m: &Metrics) -> Result<()> {
        // The first read follows the open by microseconds and covers
        // nothing worth printing.
        if self.frames == 0 && m.elapsed_ns < self.intv.as_nanos() as u64 / 2 {
            return Ok(());
        }
        self.frames += 1;
        let mut buf = Vec::new();
        self.frame(&mut buf, m)?;
        for line in String::from_utf8_lossy(&buf).lines() {
            console::emit(line);
        }
        Ok(())
    }

    /// One frame: header, the callback table, the event rates.
    fn frame<W: Write>(&self, w: &mut W, m: &Metrics) -> Result<()> {
        let secs = m.secs();
        let up = self.started.elapsed().as_secs();

        let header = console::header(&[
            format!("up {:02}:{:02}:{:02}", up / 3600, (up / 60) % 60, up % 60),
            format!("{} CPUs", m.nr_cpus),
            format!("{secs:.1} s/sample"),
            format!("#{}", self.frames),
        ]);
        writeln!(w, "{header}")?;

        // sched_ext callbacks: the kernel's own run-time accounting.
        let cpu = m.ops_cpu();
        writeln!(
            w,
            "sched_ext callbacks   overhead {:.2}% of one CPU ({:.3}% of {})   {}",
            cpu * 100.0,
            cpu * 100.0 / m.nr_cpus.max(1) as f64,
            m.nr_cpus,
            if m.ops_profiled == 1 {
                "BPF_ENABLE_STATS on"
            } else {
                "BPF run-time stats unavailable"
            },
        )?;
        writeln!(
            w,
            "{:<21}{:>9}{:>10}{:>9}{:>8}  {}",
            "callback", "calls/s", "avg", "cpu%", "share", "of callback time"
        )?;
        // Every callback, every sample, in a fixed order, so a row keeps
        // its place from one block to the next.
        let mut ops: Vec<(&String, &OpStats)> = m.ops.iter().collect();
        ops.sort_by_key(|(name, _)| (op_rank(name), (*name).clone()));
        let total_ns = m.ops_ns().max(1) as f64;
        let bar_w = 30;
        for (name, o) in &ops {
            let avg = if o.calls > 0 {
                human_ns(o.ns as f64 / o.calls as f64)
            } else {
                "-".to_string()
            };
            let share = o.ns as f64 / total_ns;
            let filled = (share * bar_w as f64).round() as usize;
            let op_cpu = o.ns as f64 / m.elapsed_ns.max(1) as f64 * 100.0;
            let misses = if o.misses > 0 {
                format!(" {} misses", o.misses)
            } else {
                String::new()
            };
            writeln!(
                w,
                "{:<21}{:>9}{:>10}{:>8.2}%{:>7.1}%  {}{}{misses}",
                name,
                human(o.calls as f64 / secs),
                avg,
                op_cpu,
                share * 100.0,
                "#".repeat(filled),
                ".".repeat(bar_w - filled),
            )?;
        }
        if ops.is_empty() {
            writeln!(w, "no callback program found")?;
        }
        // Event rates, read off the callback counts.
        let per_switch = if m.calls("running") > 0 {
            m.ops_ns() as f64 / m.calls("running") as f64
        } else {
            0.0
        };
        // Four to a line, so the block stays narrower than the table.
        let rate =
            |name: &str, op: &str| format!("{name:<8}{:>5}", human(m.calls(op) as f64 / secs));
        writeln!(
            w,
            "events/s   {}  {}  {}  {}",
            rate("wakeups", "select_cid"),
            rate("switches", "running"),
            rate("sleeps", "quiescent"),
            rate("ticks", "tick"),
        )?;
        writeln!(
            w,
            "           {}  {}  {}  {}",
            rate("yields", "yield"),
            rate("forks", "init_task"),
            rate("exits", "exit_task"),
            rate("cmask", "set_cmask"),
        )?;
        writeln!(
            w,
            "callback time per context switch {}",
            human_ns(per_switch)
        )?;
        writeln!(
            w,
            "sis updates {}   avg scan budget {:.1}",
            m.nr_sis_updates,
            m.sis_avg_scan(),
        )?;
        if m.nr_credit_grants + m.nr_credit_denied > 0 {
            writeln!(
                w,
                "latency credit loans {}   refused on budget {} ({:.1}%)",
                m.nr_credit_grants,
                m.nr_credit_denied,
                m.credit_refused(),
            )?;
        }
        if m.arena_counted == 1 {
            writeln!(
                w,
                "BPF arena memory {} of {} ({:.2}%)   active allocations {}   failed allocations {}",
                human_bytes(m.arena_bytes),
                human_bytes(m.arena_max_bytes),
                m.arena_bytes as f64 * 100.0 / m.arena_max_bytes.max(1) as f64,
                m.arena_active_allocs,
                m.arena_alloc_failures,
            )?;
        } else {
            writeln!(
                w,
                "BPF arena memory {} reserved, usage counted with --stats   active allocations {}   failed allocations {}",
                human_bytes(m.arena_max_bytes),
                m.arena_active_allocs,
                m.arena_alloc_failures,
            )?;
        }
        Ok(())
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
        .add_meta(OpStats::meta())
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    let mut dash = Dashboard::new(intv);
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| dash.render(&metrics),
    )
}
