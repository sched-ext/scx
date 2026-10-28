// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>

//! The system statistics, after scx_lavd's stats.rs: what the BPF
//! program's timer keeps in `.data.sys_stat`, served through scx_stats and
//! printed a line per interval with --stats or --monitor. The metric names
//! are lavd's, so a client reads either scheduler.

use std::ffi::OsStr;
use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::{MapCore, MapFlags, Object};
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use scx_stats_derive::stat_doc;
use serde::Deserialize;
use serde::Serialize;

/// The words of struct SysStat in bpf/src/sys_stat.rs, in its order.
#[allow(dead_code)]
mod word {
    pub const LAST_UPDATE_CLK: usize = 0;
    pub const AVG_UTIL_WALL: usize = 1;
    pub const AVG_UTIL_INVR: usize = 2;
    pub const AVG_SVC_TIME_IWGT: usize = 3;
    pub const NR_QUEUED_TASK: usize = 4;
    pub const SLICE_WALL: usize = 5;
    pub const AVG_LAT_CRI: usize = 6;
    pub const MAX_LAT_CRI: usize = 7;
    pub const THR_LAT_CRI: usize = 8;
    pub const MIN_PERF_CRI: usize = 9;
    pub const AVG_PERF_CRI: usize = 10;
    pub const MAX_PERF_CRI: usize = 11;
    pub const THR_PERF_CRI: usize = 12;
    pub const NR_STEALEE: usize = 13;
    pub const NR_ACTIVE: usize = 14;
    pub const NR_ACTIVE_CPDOMS: usize = 15;
    pub const NR_SCHED: usize = 16;
    pub const NR_PREEMPT: usize = 17;
    pub const NR_PERF_CRI: usize = 18;
    pub const NR_LAT_CRI: usize = 19;
    pub const NR_X_MIGRATION: usize = 20;
    pub const NR_BIG: usize = 21;
    pub const NR_PC_ON_BIG: usize = 22;
    pub const NR_LC_ON_BIG: usize = 23;
    pub const WORDS: usize = 24;
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Sequence ID of this message")]
    pub mseq: u64,

    #[stat(desc = "Number of runnable tasks in runqueues")]
    pub nr_queued_task: u64,

    #[stat(desc = "Number of active CPUs")]
    pub nr_active: u64,

    #[stat(desc = "Number of context switches")]
    pub nr_sched: u64,

    #[stat(desc = "Number of task preemption triggered")]
    pub nr_preempt: u64,

    #[stat(desc = "% of performance-critical tasks")]
    pub pc_pc: f64,

    #[stat(desc = "% of latency-critical tasks")]
    pub pc_lc: f64,

    #[stat(desc = "% of cross domain task migration")]
    pub pc_x_migration: f64,

    #[stat(desc = "Number of stealee domains")]
    pub nr_stealee: u64,

    #[stat(desc = "% of tasks scheduled on big cores")]
    pub pc_big: f64,

    #[stat(desc = "% of performance-critical tasks scheduled on big cores")]
    pub pc_pc_on_big: f64,

    #[stat(desc = "% of latency-critical tasks scheduled on big cores")]
    pub pc_lc_on_big: f64,

    #[stat(desc = "Average latency criticality")]
    pub avg_lat_cri: u64,

    #[stat(desc = "Latency criticality a task needs to preempt another")]
    pub thr_lat_cri: u64,

    #[stat(desc = "Base time slice in microseconds")]
    pub slice_us: u64,

    #[stat(desc = "% of CPU utilization")]
    pub util_pct: f64,
}

/// `part` of `whole`, in percent.
fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

impl Metrics {
    /// Read the statistics of the running scheduler.
    pub fn read(object: &Object, mseq: u64) -> Self {
        let mut bytes = [0_u8; word::WORDS * 8];
        if let Some(map) = object
            .maps()
            .find(|map| map.name() == OsStr::new(".data.sys_stat"))
        {
            let _ = map.lookup_into(&0_u32.to_ne_bytes(), &mut bytes, MapFlags::ANY);
        }
        let w = |index: usize| {
            u64::from_ne_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap_or([0; 8]))
        };
        let nr_sched = w(word::NR_SCHED);
        let nr_big = w(word::NR_BIG);
        Self {
            mseq,
            nr_queued_task: w(word::NR_QUEUED_TASK),
            nr_active: w(word::NR_ACTIVE),
            nr_sched,
            nr_preempt: w(word::NR_PREEMPT),
            pc_pc: pct(w(word::NR_PERF_CRI), nr_sched),
            pc_lc: pct(w(word::NR_LAT_CRI), nr_sched),
            pc_x_migration: pct(w(word::NR_X_MIGRATION), nr_sched),
            nr_stealee: w(word::NR_STEALEE),
            pc_big: pct(nr_big, nr_sched),
            pc_pc_on_big: pct(w(word::NR_PC_ON_BIG), w(word::NR_PERF_CRI)),
            pc_lc_on_big: pct(w(word::NR_LC_ON_BIG), w(word::NR_LAT_CRI)),
            avg_lat_cri: w(word::AVG_LAT_CRI),
            thr_lat_cri: w(word::THR_LAT_CRI),
            slice_us: w(word::SLICE_WALL) / 1000,
            util_pct: pct(w(word::AVG_UTIL_WALL), 1024),
        }
    }

    fn format_header<W: Write>(w: &mut W) -> Result<()> {
        writeln!(
            w,
            "\x1b[93m| {:8} | {:9} | {:9} | {:8} | {:9} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:6} |\x1b[0m",
            "MSEQ",
            "# Q TASK",
            "# ACT CPU",
            "# SCHED",
            "# PREEMPT",
            "PERF-CR%",
            "LAT-CR%",
            "X-MIG%",
            "# STLEE",
            "BIG%",
            "PC/BIG%",
            "LC/BIG%",
            "AVG-LC",
            "THR-LC",
            "SLICE-US",
            "UTIL%",
        )?;
        Ok(())
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        if self.mseq % 10 == 1 {
            Self::format_header(w)?;
        }
        let color = if self.mseq.is_multiple_of(2) {
            "\x1b[90m"
        } else {
            "\x1b[37m"
        };
        writeln!(
            w,
            "{color}| {:8} | {:9} | {:9} | {:8} | {:9} | {:8.2} | {:8.2} | {:8.2} | {:8} | {:8.2} | {:8.2} | {:8.2} | {:8} | {:8} | {:8} | {:6.1} |\x1b[0m",
            self.mseq,
            self.nr_queued_task,
            self.nr_active,
            self.nr_sched,
            self.nr_preempt,
            self.pc_pc,
            self.pc_lc,
            self.pc_x_migration,
            self.nr_stealee,
            self.pc_big,
            self.pc_pc_on_big,
            self.pc_lc_on_big,
            self.avg_lat_cri,
            self.thr_lat_cri,
            self.slice_us,
            self.util_pct,
        )?;
        Ok(())
    }
}

/// What the stats server serves: the latest sample on every request.
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |_| {
        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            res_ch.recv()?.to_json()
        });
        Ok(read)
    });
    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

/// Print a line for each sample a client receives.
pub fn show() -> impl FnMut(Metrics, Duration) -> Result<()> {
    move |metrics, _interval| metrics.format(&mut std::io::stdout())
}
