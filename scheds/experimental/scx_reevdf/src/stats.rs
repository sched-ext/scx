// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

// The sched_ext callback overhead, after scx_eevdf's stats.rs: the kernel's
// run-time accounting of every struct_ops program, BPF_ENABLE_STATS, served
// through scx_stats and printed as one block per interval with --stats or
// --monitor. The metric names are scx_eevdf's, so the same clients read
// either scheduler.
//
// The per-CID queues are read too, straight from the arena, see
// scx_rustsched_loader's queues.rs: what each queue counted and what the sampler
// saw of its depth, from which the block derives how long tasks wait.
//
// So is the balancers' per-CID state, see balance.rs: what the idle pull,
// periodic balance and active balance have settled on, as of the sample.

use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use scx_stats_derive::stat_doc;
use serde::Deserialize;
use serde::Serialize;

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

/// One CID's queue, read from the arena. Cumulative on the server side,
/// per interval once the client has taken the delta.
#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "edq_", _om_label = "cid")]
pub struct QueueStats {
    #[stat(desc = "Tasks queued on the CID, the queue's own count")]
    pub inserts: u64,

    #[stat(desc = "Sum of the queue depths the sampler saw")]
    pub depth_sum: u64,

    #[stat(desc = "Samples that found tasks queued")]
    pub busy: u64,

    #[stat(desc = "Samples that found the queue's lock held")]
    pub locked: u64,
}

impl QueueStats {
    fn delta(&self, rhs: &Self) -> Self {
        Self {
            inserts: self.inserts.saturating_sub(rhs.inserts),
            depth_sum: self.depth_sum.saturating_sub(rhs.depth_sum),
            busy: self.busy.saturating_sub(rhs.busy),
            locked: self.locked.saturating_sub(rhs.locked),
        }
    }

    fn add(&mut self, rhs: &Self) {
        self.inserts += rhs.inserts;
        self.depth_sum += rhs.depth_sum;
        self.busy += rhs.busy;
        self.locked += rhs.locked;
    }

    /// The average number of tasks queued over `samples` samples.
    fn depth(&self, samples: u64) -> f64 {
        self.depth_sum as f64 / samples.max(1) as f64
    }

    /// The average time a task waits in the queue, by Little's law: the
    /// average depth over the arrival rate. None when nothing was queued,
    /// or when the waits were too short for a sample to catch one.
    fn wait_ns(&self, samples: u64, elapsed_ns: u64) -> Option<f64> {
        (self.inserts > 0 && self.depth_sum > 0)
            .then(|| self.depth(samples) * elapsed_ns as f64 / self.inserts as f64)
    }
}

/// One CID's balance state, read from the arena. The values are those of
/// the moment of the sample, not counts over the interval.
#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "balance_", _om_label = "cid")]
pub struct BalanceStats {
    #[stat(desc = "Nanoseconds the CID stays idle after an idle pull, on average")]
    pub avg_idle_ns: u64,

    #[stat(desc = "Nanoseconds the worst idle pull has cost, decayed")]
    pub newidle_cost_ns: u64,

    #[stat(desc = "Of 1024, how often an idle pull is let scan the LLC")]
    pub newidle_ratio_llc: u64,

    #[stat(desc = "Of 1024, how often an idle pull is let scan the node")]
    pub newidle_ratio_node: u64,

    #[stat(desc = "Of 1024, how often an idle pull is let scan the system")]
    pub newidle_ratio_system: u64,

    #[stat(desc = "Idle pulls in a row that found work queued and took nothing")]
    pub newidle_failed: u64,

    #[stat(desc = "Milliseconds between periodic balance passes over the LLC")]
    pub busy_interval_llc_ms: u64,

    #[stat(desc = "Milliseconds between periodic balance passes over the node")]
    pub busy_interval_node_ms: u64,

    #[stat(desc = "Milliseconds between periodic balance passes over the system")]
    pub busy_interval_system_ms: u64,

    #[stat(desc = "LLC passes in a row that found an imbalance and moved nothing")]
    pub busy_failed_llc: u64,

    #[stat(desc = "Node passes in a row that found an imbalance and moved nothing")]
    pub busy_failed_node: u64,

    #[stat(desc = "System passes in a row that found an imbalance and moved nothing")]
    pub busy_failed_system: u64,

    #[stat(desc = "Milliseconds before the CID may ask for a running task again")]
    pub active_interval_ms: u64,
}

impl From<crate::balance::State> for BalanceStats {
    fn from(state: crate::balance::State) -> Self {
        let [ratio_llc, ratio_node, ratio_system] = state.newidle_ratio;
        let [interval_llc, interval_node, interval_system] = state.busy_interval_ms;
        let [failed_llc, failed_node, failed_system] = state.busy_failed;
        Self {
            avg_idle_ns: state.avg_idle_ns,
            newidle_cost_ns: state.newidle_cost_ns,
            newidle_ratio_llc: ratio_llc,
            newidle_ratio_node: ratio_node,
            newidle_ratio_system: ratio_system,
            newidle_failed: state.newidle_failed,
            busy_interval_llc_ms: interval_llc,
            busy_interval_node_ms: interval_node,
            busy_interval_system_ms: interval_system,
            busy_failed_llc: failed_llc,
            busy_failed_node: failed_node,
            busy_failed_system: failed_system,
            active_interval_ms: state.active_interval_ms,
        }
    }
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

    #[stat(desc = "Bytes of arena pages the kernel has allocated")]
    pub arena_bytes: u64,

    #[stat(desc = "Size of the arena map in bytes")]
    pub arena_max_bytes: u64,

    #[stat(desc = "Arena usage is known (1), from the kernel's memlock accounting")]
    pub arena_counted: u64,

    #[stat(desc = "Arena allocator objects currently allocated, task contexts mostly")]
    pub arena_active_allocs: u64,

    #[stat(desc = "Arena allocations that failed because the kernel refused a page")]
    pub arena_alloc_failures: u64,

    #[stat(desc = "sched_ext callbacks, keyed by name, see BPF_ENABLE_STATS")]
    pub ops: BTreeMap<String, OpStats>,

    #[stat(desc = "Passes of the queue sampler, each reading every CID's queue once")]
    pub edq_samples: u64,

    #[stat(desc = "Per-CID queues, keyed by CID, read from the arena")]
    pub queues: BTreeMap<String, QueueStats>,

    #[stat(desc = "Per-CID balance state, keyed by CID, read from the arena")]
    pub balance: BTreeMap<String, BalanceStats>,
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

        let queues = self
            .queues
            .iter()
            .map(|(cid, cur)| {
                let prev = rhs.queues.get(cid).cloned().unwrap_or_default();
                (cid.clone(), cur.delta(&prev))
            })
            .collect();

        Self {
            elapsed_ns: self.elapsed_ns.saturating_sub(rhs.elapsed_ns),
            nr_sis_updates: self.nr_sis_updates.saturating_sub(rhs.nr_sis_updates),
            sis_scan_sum: self.sis_scan_sum.saturating_sub(rhs.sis_scan_sum),
            ops,
            edq_samples: self.edq_samples.saturating_sub(rhs.edq_samples),
            queues,
            ..self.clone()
        }
    }

    fn sis_avg_scan(&self) -> f64 {
        if self.nr_sis_updates > 0 {
            self.sis_scan_sum as f64 / self.nr_sis_updates as f64
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
    "yield_task",
    "core_sched_before",
    "update_idle",
    "set_weight",
    "set_cmask",
    "enable",
    "init_task",
    "exit_task",
    "cgroup_init",
    "cgroup_exit",
    "cgroup_set_weight",
    "cgroup_set_idle",
    "cgroup_set_bandwidth",
    "cgroup_move",
    "init",
    "exit",
    "dump_task",
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
    if ns >= 1e9 {
        format!("{:.2}s", ns / 1e9)
    } else if ns >= 1e6 {
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
        print!("{}", String::from_utf8_lossy(&buf));
        Ok(())
    }

    /// One frame: header, the arena, the callback table, the event rates,
    /// the balancers, the queues.
    fn frame<W: Write>(&self, w: &mut W, m: &Metrics) -> Result<()> {
        let secs = m.secs();
        let up = self.started.elapsed().as_secs();

        let header = [
            format!("scx_reevdf {}", env!("CARGO_PKG_VERSION")),
            format!("up {:02}:{:02}:{:02}", up / 3600, (up / 60) % 60, up % 60),
            format!("{} CPUs", m.nr_cpus),
            format!("{secs:.1} s/sample"),
            format!("#{}", self.frames),
        ]
        .join(" | ");
        writeln!(w, "{header}")?;
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
                "BPF arena memory {} reserved   active allocations {}   failed allocations {}",
                human_bytes(m.arena_max_bytes),
                m.arena_active_allocs,
                m.arena_alloc_failures,
            )?;
        }

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
            "{:<21}{:>9}{:>10}{:>9}{:>8}  of callback time",
            "callback", "calls/s", "avg", "cpu%", "share"
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
            rate("yields", "yield_task"),
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
        self.balance(w, m)?;
        self.queues(w, m)
    }

    /// The balancers, in two lines whatever the number of CIDs: for the
    /// idle pull and for periodic and active balance, the average over
    /// the CIDs. These are the values of the moment of the sample: the
    /// balancers keep state, not counts.
    fn balance<W: Write>(&self, w: &mut W, m: &Metrics) -> Result<()> {
        if m.balance.is_empty() {
            return Ok(());
        }
        let count = m.balance.len() as f64;
        let avg = |value: &dyn Fn(&BalanceStats) -> u64| {
            m.balance.values().map(|cid| value(cid) as f64).sum::<f64>() / count
        };
        // Only the CID that leads its group passes over a wider level,
        // and one that has not ticked yet has passed over none: an
        // interval of 0 is no interval, and stays out of the average.
        let set = |value: &dyn Fn(&BalanceStats) -> u64| {
            let (sum, count) = m
                .balance
                .values()
                .map(value)
                .filter(|&value| value > 0)
                .fold((0, 0), |(sum, count), value| (sum + value, count + 1));
            sum as f64 / f64::from(count.max(1))
        };
        let pct = |ratio: f64| format!("{:.0}%", ratio * 100.0 / 1024.0);
        // A level the machine does not have never gets an interval.
        let ms = |value: f64| {
            if value > 0.0 {
                human_ns(value * 1e6)
            } else {
                "-".into()
            }
        };
        writeln!(
            w,
            "newidle    idle {:>8}  cost {:>8}  admit llc {:>4} node {:>4} sys {:>4}  failed {:>4}",
            human_ns(avg(&|cid| cid.avg_idle_ns)),
            human_ns(avg(&|cid| cid.newidle_cost_ns)),
            pct(avg(&|cid| cid.newidle_ratio_llc)),
            pct(avg(&|cid| cid.newidle_ratio_node)),
            pct(avg(&|cid| cid.newidle_ratio_system)),
            human(avg(&|cid| cid.newidle_failed)),
        )?;
        writeln!(
            w,
            "balance    llc {:>8} node {:>8} sys {:>8}  failed {:>4} {:>4} {:>4}  active {:>8}",
            ms(set(&|cid| cid.busy_interval_llc_ms)),
            ms(set(&|cid| cid.busy_interval_node_ms)),
            ms(set(&|cid| cid.busy_interval_system_ms)),
            human(avg(&|cid| cid.busy_failed_llc)),
            human(avg(&|cid| cid.busy_failed_node)),
            human(avg(&|cid| cid.busy_failed_system)),
            ms(set(&|cid| cid.active_interval_ms)),
        )?;
        Ok(())
    }

    /// The per-CID queues, in two lines whatever the number of CIDs: all
    /// of them as one, then the highest value any CID has in each field.
    /// For each, the tasks queued per second, how many
    /// are queued on average, how long one waits, and the share of the
    /// samples that found the queue non-empty and its lock held.
    fn queues<W: Write>(&self, w: &mut W, m: &Metrics) -> Result<()> {
        if m.queues.is_empty() {
            return Ok(());
        }
        let secs = m.secs();
        let mut all = QueueStats::default();
        for queue in m.queues.values() {
            all.add(queue);
        }
        // The same fields in the same columns on both lines, every
        // sample: what has no value yet shows as "-".
        let sampled = m.edq_samples > 0;
        let fields = |queued: f64, wait: Option<f64>, busy: f64, lock: f64| {
            let show = |text: String| if sampled { text } else { "-".into() };
            format!(
                "queued {:>7}  wait {:>8}  busy {:>6}  lock {:>6}",
                show(format!("{queued:.2}")),
                wait.map_or("-".into(), human_ns),
                show(format!("{:.1}%", busy * 100.0)),
                show(format!("{:.2}%", lock * 100.0)),
            )
        };
        let samples = m.edq_samples.max(1) as f64;
        let reads = samples * m.queues.len() as f64;
        writeln!(
            w,
            "EDQs       enq/s {:>5}  {}",
            human(all.inserts as f64 / secs),
            fields(
                all.depth(m.edq_samples),
                all.wait_ns(m.edq_samples, m.elapsed_ns),
                all.busy as f64 / reads,
                all.locked as f64 / reads,
            ),
        )?;
        // The highest value of each field over the CIDs, which need not
        // come from the same one.
        let max =
            |value: &dyn Fn(&QueueStats) -> f64| m.queues.values().map(value).fold(0.0, f64::max);
        writeln!(
            w,
            "{:>16}{:6}  {}",
            "max",
            "",
            fields(
                max(&|queue| queue.depth(m.edq_samples)),
                m.queues
                    .values()
                    .filter_map(|queue| queue.wait_ns(m.edq_samples, m.elapsed_ns))
                    .max_by(f64::total_cmp),
                max(&|queue| queue.busy as f64 / samples),
                max(&|queue| queue.locked as f64 / samples),
            ),
        )?;
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
        .add_meta(QueueStats::meta())
        .add_meta(BalanceStats::meta())
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

/// Print one block for each sample a client receives.
pub fn show() -> impl FnMut(Metrics, Duration) -> Result<()> {
    let mut dash = None;
    move |metrics, intv| {
        dash.get_or_insert_with(|| Dashboard::new(intv))
            .render(&metrics)
    }
}
