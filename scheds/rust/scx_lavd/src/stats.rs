use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::Duration;

use anyhow::bail;
use anyhow::{Context, Result};
use gpoint::GPoint;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct SysStats {
    #[stat(desc = "Sequence ID of this message")]
    pub mseq: u64,

    #[stat(desc = "Number of runnable tasks in runqueues")]
    pub nr_queued_task: u64,

    #[stat(desc = "Number of active CPUs when core compaction is enabled")]
    pub nr_active: u32,

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
    pub nr_stealee: u32,

    #[stat(desc = "% of tasks scheduled on big cores")]
    pub pc_big: f64,

    #[stat(desc = "% of performance-critical tasks scheduled on big cores")]
    pub pc_pc_on_big: f64,

    #[stat(desc = "% of latency-critical tasks scheduled on big cores")]
    pub pc_lc_on_big: f64,

    #[stat(desc = "Current power mode")]
    pub power_mode: String,

    #[stat(desc = "% of performance mode")]
    pub pc_performance: f64,

    #[stat(desc = "% of balanced mode")]
    pub pc_balanced: f64,

    #[stat(desc = "% of powersave mode")]
    pub pc_powersave: f64,
}

impl SysStats {
    pub fn format_header<W: Write>(w: &mut W) -> Result<()> {
        writeln!(
            w,
            "\x1b[93m| {:8} | {:9} | {:9} | {:8} | {:9} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:11} | {:12} | {:12} | {:12} |\x1b[0m",
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
            "POWER MODE",
            "PERFORMANCE%",
            "BALANCED%",
            "POWERSAVE%",
        )?;
        Ok(())
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        if self.mseq % 10 == 1 {
            Self::format_header(w)?;
        }

        let color = if self.mseq % 2 == 0 {
            "\x1b[90m" // Dark gray for even mseq
        } else {
            "\x1b[37m" // white for odd mseq
        };

        writeln!(
            w,
            "{color}| {:8} | {:9} | {:9} | {:8} | {:9} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:8} | {:11} | {:12} | {:12} | {:12} |\x1b[0m",
            self.mseq,
            self.nr_queued_task,
            self.nr_active,
            self.nr_sched,
            self.nr_preempt,
            GPoint(self.pc_pc),
            GPoint(self.pc_lc),
            GPoint(self.pc_x_migration),
            self.nr_stealee,
            GPoint(self.pc_big),
            GPoint(self.pc_pc_on_big),
            GPoint(self.pc_lc_on_big),
            self.power_mode,
            GPoint(self.pc_performance),
            GPoint(self.pc_balanced),
            GPoint(self.pc_powersave),
        )?;
        Ok(())
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top, _om_prefix = "s_", _om_label = "sched_sample")]
pub struct SchedSample {
    #[stat(desc = "Sequence ID of this message")]
    pub mseq: u64,
    #[stat(desc = "Process ID")]
    pub pid: i32,
    #[stat(desc = "Task name")]
    pub comm: String,
    #[stat(
        desc = "LR: 'L'atency-critical or 'R'egular, HI: performance-'H'ungry or performance-'I'nsensitive, BT: 'B'ig or li'T'tle, EG: 'E'ligible or 'G'reedy, PN: 'P'reempting or 'N'ot"
    )]
    pub stat: String,
    #[stat(desc = "CPU ID where this task is scheduled on")]
    pub cpu_id: u32,
    #[stat(desc = "CPU ID where a task ran last time.")]
    pub prev_cpu_id: u32,
    #[stat(desc = "CPU ID suggested when a task is enqueued.")]
    pub suggested_cpu_id: u32,
    #[stat(desc = "Waker's process ID")]
    pub waker_pid: i32,
    #[stat(desc = "Waker's task name")]
    pub waker_comm: String,
    #[stat(desc = "Assigned time slice")]
    pub slice: u64,
    #[stat(desc = "Amount of time actually used by task in a slice")]
    pub slice_used: u64,
    #[stat(desc = "Latency criticality of this task")]
    pub lat_cri: u32,
    #[stat(desc = "Average latency criticality in a system")]
    pub avg_lat_cri: u32,
    #[stat(desc = "Static priority (20 == nice 0)")]
    pub static_prio: u16,
    #[stat(desc = "Time interval from the last quiescent time to this runnable time.")]
    pub rerunnable_interval: u64,
    #[stat(desc = "Time interval from the last stopped time.")]
    pub resched_interval: u64,
    #[stat(desc = "How often this task is scheduled per second")]
    pub run_freq: u64,
    #[stat(desc = "Average runtime per schedule")]
    pub avg_runtime: u64,
    #[stat(desc = "How frequently this task waits for other tasks")]
    pub wait_freq: u64,
    #[stat(desc = "How frequently this task wakes other tasks")]
    pub wake_freq: u64,
    #[stat(desc = "Performance criticality of this task")]
    pub perf_cri: u32,
    #[stat(desc = "Performance criticality threshold")]
    pub thr_perf_cri: u32,
    #[stat(desc = "Target performance level of this CPU")]
    pub cpuperf_cur: u32,
    #[stat(desc = "CPU utilization of this CPU")]
    pub cpu_util: u64,
    #[stat(desc = "Scaled CPU utilization of this CPU")]
    pub cpu_sutil: u64,
    #[stat(desc = "Number of active CPUs when core compaction is enabled")]
    pub nr_active: u32,
    #[stat(desc = "DSQ ID where this task was dispatched from")]
    pub dsq_id: u64,
    #[stat(desc = "Consume latency of this DSQ (shows how contended the DSQ is)")]
    pub dsq_consume_lat: u64,
}

impl SchedSample {
    pub fn format_header<W: Write>(w: &mut W) -> Result<()> {
        writeln!(
            w,
            "\x1b[93m| {:6} | {:7} | {:17} | {:5} | {:4} | {:8} | {:8} | {:8} | {:17} | {:8} | {:8} | {:8} | {:7} | {:8} | {:12} | {:12} | {:9} | {:9} | {:9} | {:9} | {:8} | {:8} | {:8} | {:8} | {:9} | {:6} | {:6} | {:10} |\x1b[0m",
            "MSEQ",
            "PID",
            "COMM",
            "STAT",
            "CPU",
            "PRV_CPU",
            "SUG_CPU",
            "WKER_PID",
            "WKER_COMM",
            "SLC_NS",
            "SLC_USED_NS",
            "LAT_CRI",
            "AVG_LC",
            "ST_PRIO",
            "RERNBL_NS",
            "RESCHD_NS",
            "RUN_FREQ",
            "RUN_TM_NS",
            "WAIT_FREQ",
            "WAKE_FREQ",
            "PERF_CRI",
            "THR_PC",
            "CPUFREQ",
            "CPU_UTIL",
            "CPU_SUTIL",
            "NR_ACT",
            "DSQ_ID",
            "DSQ_LAT_NS",
        )?;
        Ok(())
    }

    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        if self.mseq % 10 == 1 {
            Self::format_header(w)?;
        }

        writeln!(
            w,
            "| {:6} | {:7} | {:17} | {:5} | {:4} | {:8} | {:8} | {:8} | {:17} | {:8} | {:8} | {:8} | {:7} | {:8} | {:12} | {:12} | {:9} | {:9} | {:9} | {:9} | {:8} | {:8} | {:8} | {:8} | {:9} | {:6} | {:12} | {:12} |",
            self.mseq,
            self.pid,
            self.comm,
            self.stat,
            self.cpu_id,
            self.prev_cpu_id,
            self.suggested_cpu_id,
            self.waker_pid,
            self.waker_comm,
            self.slice,
            self.slice_used,
            self.lat_cri,
            self.avg_lat_cri,
            self.static_prio,
            self.rerunnable_interval,
            self.resched_interval,
            self.run_freq,
            self.avg_runtime,
            self.wait_freq,
            self.wake_freq,
            self.perf_cri,
            self.thr_perf_cri,
            self.cpuperf_cur,
            self.cpu_util,
            self.cpu_sutil,
            self.nr_active,
            self.dsq_id,
            self.dsq_consume_lat,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
pub struct SchedSamples {
    pub samples: Vec<SchedSample>,
}

#[derive(Debug)]
pub enum StatsReq {
    NewSampler(ThreadId),
    SysStatsReq {
        tid: ThreadId,
    },
    SchedSamplesNr {
        tid: ThreadId,
        nr_samples: u64,
        interval_ms: u64,
    },
}

impl StatsReq {
    fn from_args_stats(tid: ThreadId) -> Result<Self> {
        Ok(Self::SysStatsReq { tid })
    }

    fn from_args_samples(
        tid: ThreadId,
        nr_cpus_onln: u64,
        args: &BTreeMap<String, String>,
    ) -> Result<Self> {
        let mut nr_samples = 1;

        if let Some(arg) = args.get("nr_samples") {
            nr_samples = arg.trim().parse()?;
        }

        let mut interval_ms = 1000;
        if nr_samples > nr_cpus_onln {
            // More samples, shorter sampling interval.
            let f = nr_samples / nr_cpus_onln * 2;
            interval_ms /= f;
        }

        Ok(Self::SchedSamplesNr {
            tid,
            nr_samples,
            interval_ms,
        })
    }
}

#[derive(Debug)]
pub enum StatsRes {
    Ack,
    Bye,
    SysStats(SysStats),
    SchedSamples(SchedSamples),
}

pub fn server_data(nr_cpus_onln: u64) -> StatsServerData<StatsReq, StatsRes> {
    let open: Box<dyn StatsOpener<StatsReq, StatsRes>> = Box::new(move |(req_ch, res_ch)| {
        let tid = std::thread::current().id();
        req_ch.send(StatsReq::NewSampler(tid))?;
        match res_ch.recv()? {
            StatsRes::Ack => {}
            res => bail!("invalid response: {:?}", res),
        }

        let read: Box<dyn StatsReader<StatsReq, StatsRes>> =
            Box::new(move |_args, (req_ch, res_ch)| {
                let req = StatsReq::from_args_stats(tid)?;
                req_ch.send(req)?;

                let stats = match res_ch.recv()? {
                    StatsRes::SysStats(v) => v,
                    StatsRes::Bye => bail!("preempted by another sampler"),
                    res => bail!("invalid response: {:?}", res),
                };

                stats.to_json()
            });
        Ok(read)
    });

    let samples_open: Box<dyn StatsOpener<StatsReq, StatsRes>> =
        Box::new(move |(req_ch, res_ch)| {
            let tid = std::thread::current().id();
            req_ch.send(StatsReq::NewSampler(tid))?;
            match res_ch.recv()? {
                StatsRes::Ack => {}
                res => bail!("invalid response: {:?}", res),
            }

            let read: Box<dyn StatsReader<StatsReq, StatsRes>> =
                Box::new(move |args, (req_ch, res_ch)| {
                    let req = StatsReq::from_args_samples(tid, nr_cpus_onln, args)?;
                    req_ch.send(req)?;

                    let samples = match res_ch.recv()? {
                        StatsRes::SchedSamples(v) => v,
                        StatsRes::Bye => bail!("preempted by another sampler"),
                        res => bail!("invalid response: {:?}", res),
                    };

                    samples.to_json()
                });
            Ok(read)
        });

    StatsServerData::new()
        .add_meta(SysStats::meta())
        .add_ops("top", StatsOps { open, close: None })
        .add_meta(SchedSample::meta())
        .add_ops(
            "sched_samples",
            StatsOps {
                open: samples_open,
                close: None,
            },
        )
}

pub fn monitor_sched_samples(nr_samples: u64, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<SchedSamples>(
        &vec![
            ("target".into(), "sched_samples".into()),
            ("nr_samples".into(), nr_samples.to_string()),
        ],
        Duration::from_secs(0),
        || shutdown.load(Ordering::Relaxed),
        |ts| {
            let mut stdout = std::io::stdout();
            for sample in ts.samples.iter() {
                sample.format(&mut stdout)?;
            }
            Ok(())
        },
    )
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<SysStats>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |sysstats| {
            sysstats
                .format(&mut std::io::stdout())
                .context("failed to format sysstats")?;
            Ok(())
        },
    )
}
