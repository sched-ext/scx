// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! The statistics of --stats and --monitor: what the scheduler's own
//! counters say, what each callback costs, and how deep the queues are.
//!
//! The counters are the scheduler's, one set per CPU that only that CPU
//! writes, summed here. The scheduler counts only when it was started
//! with --stats: --monitor on one started without shows them at zero.
//! The callbacks' calls and times are the kernel's
//! accounting of each BPF program, and the queues' depth is sampled from
//! the arena: both only while a client asks, and neither adds anything to
//! the scheduling paths.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use scx_rustsched_loader::{CidTableReader, Loaded, Object, OpsProfiler, QueueSampler, Result};
use scx_stats::prelude::*;
use scx_stats_derive::{Stats, stat_doc};
use serde::{Deserialize, Serialize};

/// The words of a CPU's counters, as `Counters` in ../bpf/src/main.rs
/// lays them out, padding included.
const COUNTER_WORDS: usize = 8;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "op_", _om_label = "callback")]
pub struct OpStats {
    #[stat(desc = "Times the callback ran")]
    pub calls: u64,
    #[stat(desc = "Nanoseconds spent in the callback")]
    pub ns: u64,
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Nanoseconds covered by this sample")]
    pub elapsed_ns: u64,
    #[stat(desc = "Number of CPUs")]
    pub nr_cpus: u64,
    #[stat(desc = "Wakeups sent straight to an idle CPU")]
    pub direct: u64,
    #[stat(desc = "Wakeups placed on borrowed virtual time")]
    pub borrowed: u64,
    #[stat(desc = "Wakeups queued on another CPU to take it")]
    pub moved: u64,
    #[stat(desc = "Searches for a CPU to take that found none")]
    pub missed: u64,
    #[stat(desc = "Preemptions of a running task by a waking one")]
    pub preempts: u64,
    #[stat(desc = "Tasks taken from another CPU's queue")]
    pub steals: u64,
    #[stat(desc = "Running tasks moved by the tick to a better idle CPU")]
    pub balanced: u64,
    #[stat(desc = "Tasks queued, the queues' own count")]
    pub queued: u64,
    #[stat(desc = "Samples of the queues' depth, per queue")]
    pub queue_samples: u64,
    #[stat(desc = "Sum of the depths sampled, over all queues")]
    pub queue_depth_sum: u64,
    #[stat(desc = "Samples that found a queue with tasks in it")]
    pub queue_busy: u64,
    #[stat(desc = "The kernel accounts the callbacks' run time (1) or cannot (0)")]
    pub ops_profiled: u64,
    #[stat(desc = "Calls and time of each callback")]
    pub ops: BTreeMap<String, OpStats>,
}

impl Metrics {
    /// What happened between `earlier` and this sample.
    fn delta(&self, earlier: &Self) -> Self {
        Self {
            elapsed_ns: self.elapsed_ns.saturating_sub(earlier.elapsed_ns),
            nr_cpus: self.nr_cpus,
            direct: self.direct.wrapping_sub(earlier.direct),
            borrowed: self.borrowed.wrapping_sub(earlier.borrowed),
            moved: self.moved.wrapping_sub(earlier.moved),
            missed: self.missed.wrapping_sub(earlier.missed),
            preempts: self.preempts.wrapping_sub(earlier.preempts),
            steals: self.steals.wrapping_sub(earlier.steals),
            balanced: self.balanced.wrapping_sub(earlier.balanced),
            queued: self.queued.wrapping_sub(earlier.queued),
            queue_samples: self.queue_samples.saturating_sub(earlier.queue_samples),
            queue_depth_sum: self.queue_depth_sum.saturating_sub(earlier.queue_depth_sum),
            queue_busy: self.queue_busy.saturating_sub(earlier.queue_busy),
            ops_profiled: self.ops_profiled,
            ops: self
                .ops
                .iter()
                .map(|(name, op)| {
                    let before = earlier.ops.get(name).cloned().unwrap_or_default();
                    let op = OpStats {
                        calls: op.calls.saturating_sub(before.calls),
                        ns: op.ns.saturating_sub(before.ns),
                    };
                    (name.clone(), op)
                })
                .collect(),
        }
    }
}

/// What the metrics are read with, set up at the first sample, once the
/// scheduler runs.
struct Sampler {
    profiler: OpsProfiler,
    counters: Option<CidTableReader>,
    queues: Option<QueueSampler>,
    started: Instant,
}

impl Sampler {
    fn new(object: &Loaded) -> Self {
        Self {
            profiler: OpsProfiler::new(),
            counters: CidTableReader::new(object, ".data.counters", COUNTER_WORDS)
                .inspect_err(|error| eprintln!("counters unavailable: {error:#}"))
                .ok(),
            queues: QueueSampler::new(object)
                .inspect_err(|error| eprintln!("queue statistics unavailable: {error:#}"))
                .ok(),
            started: Instant::now(),
        }
    }

    /// One sample, cumulative since the first.
    fn metrics(&mut self, object: &Object) -> Metrics {
        let mut metrics = Metrics {
            elapsed_ns: self.started.elapsed().as_nanos() as u64,
            ..Default::default()
        };
        if let Some(counters) = &self.counters {
            let sums = counters.sum();
            metrics.direct = sums[0];
            metrics.borrowed = sums[1];
            metrics.moved = sums[2];
            metrics.missed = sums[3];
            metrics.preempts = sums[4];
            metrics.steals = sums[5];
            metrics.balanced = sums[6];
        }
        if let Some(queues) = &self.queues {
            let (samples, queues) = queues.sample();
            metrics.nr_cpus = queues.len() as u64;
            metrics.queue_samples = samples;
            for queue in queues {
                metrics.queued = metrics.queued.wrapping_add(queue.inserts);
                metrics.queue_depth_sum += queue.depth_sum;
                metrics.queue_busy += queue.busy;
            }
        }
        metrics.ops = self
            .profiler
            .sample(object)
            .into_iter()
            .map(|(name, op)| {
                let op = OpStats {
                    calls: op.calls,
                    ns: op.ns,
                };
                (name, op)
            })
            .collect();
        metrics.ops_profiled = u64::from(self.profiler.enabled.is_some());
        metrics
    }
}

/// What a client of the stats server gets: the change since it last asked.
fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(requests, responses)| {
        requests.send(())?;
        let mut earlier = responses.recv()?;
        let read: Box<dyn StatsReader<(), Metrics>> =
            Box::new(move |_args, (requests, responses)| {
                requests.send(())?;
                let now = responses.recv()?;
                let delta = now.delta(&earlier);
                earlier = now;
                delta.to_json()
            });
        Ok(read)
    });
    StatsServerData::new()
        .add_meta(OpStats::meta())
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

/// Print one block for a sample.
fn show(metrics: Metrics, _interval: Duration) -> Result<()> {
    let seconds = (metrics.elapsed_ns as f64 / 1e9).max(1e-9);
    let rate = |count: u64| count as f64 / seconds;
    println!(
        "wakeups: direct {:.0}/s borrowed {:.0}/s moved {:.0}/s (missed {:.0}/s)",
        rate(metrics.direct),
        rate(metrics.borrowed),
        rate(metrics.moved),
        rate(metrics.missed),
    );
    println!(
        "preempt {:.0}/s steal {:.0}/s balance {:.0}/s",
        rate(metrics.preempts),
        rate(metrics.steals),
        rate(metrics.balanced),
    );
    let samples = (metrics.queue_samples * metrics.nr_cpus).max(1) as f64;
    println!(
        "queues: {:.0} tasks/s, depth {:.2} on average, busy {:.1}% of the time",
        rate(metrics.queued),
        metrics.queue_depth_sum as f64 / samples,
        100.0 * metrics.queue_busy as f64 / samples,
    );
    if metrics.ops_profiled == 0 {
        println!("callbacks: the kernel's run-time accounting is unavailable");
    } else {
        println!(
            "{:<16} {:>10} {:>8} {:>7}",
            "callback", "calls/s", "avg ns", "cpu%"
        );
        let mut total = 0;
        // Every callback, whether it ran or not: the block keeps its shape.
        for (name, op) in &metrics.ops {
            total += op.ns;
            println!(
                "{:<16} {:>10.0} {:>8.0} {:>7.2}",
                name,
                rate(op.calls),
                op.ns as f64 / op.calls.max(1) as f64,
                100.0 * op.ns as f64 / metrics.elapsed_ns.max(1) as f64,
            );
        }
        // The share is of one CPU's time, summed over all of them.
        println!(
            "{:<16} {:>10} {:>8} {:>7.2} (% of one CPU, over {} CPUs)",
            "total",
            "",
            "",
            100.0 * total as f64 / metrics.elapsed_ns.max(1) as f64,
            metrics.nr_cpus,
        );
    }
    println!();
    Ok(())
}

/// The scheduler's statistics, for the loader.
pub fn stats() -> scx_rustsched_loader::Stats {
    let sampler = Rc::new(RefCell::new(None::<Sampler>));
    let idle = sampler.clone();
    scx_rustsched_loader::Stats::new(
        server_data,
        move |object| {
            sampler
                .borrow_mut()
                .get_or_insert_with(|| Sampler::new(object))
                .metrics(object)
        },
        show,
    )
    .idle(move |_| {
        // The kernel's accounting goes once nobody has asked for a while.
        if let Some(sampler) = idle.borrow_mut().as_mut() {
            sampler.profiler.expire();
        }
    })
}
