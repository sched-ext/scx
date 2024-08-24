use anyhow::bail;
use anyhow::Result;
use scx_stats::Meta;
use scx_stats::ScxStatsOps;
use scx_stats::ScxStatsServerData;
use scx_stats::StatsOpener;
use scx_stats::StatsReader;
use scx_stats::ToJson;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::Ordering;
use std::thread::ThreadId;
use std::time::Duration;

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
pub struct SchedSample {
    pub mseq: u64,
    pub pid: i32,
    pub comm: String,
    pub stat: String,
    pub cpu_id: u32,
    pub victim_cpu: i32,
    pub vdeadline_delta_ns: u64,
    pub slice_ns: u64,
    pub greedy_ratio: u32,
    pub lat_cri: u32,
    pub avg_lat_cri: u32,
    pub static_prio: u16,
    pub slice_boost_prio: u16,
    pub run_freq: u64,
    pub run_time_ns: u64,
    pub wait_freq: u64,
    pub wake_freq: u64,
    pub perf_cri: u32,
    pub avg_perf_cri: u32,
    pub cpuperf_cur: u32,
    pub cpu_util: u64,
    pub nr_active: u32,
}

impl SchedSample {
    pub fn format_header<W: Write>(w: &mut W) -> Result<()> {
        writeln!(
            w,
            "| {:6} | {:7} | {:17} \
                   | {:5} | {:4} | {:4} \
                   | {:14} | {:8} | {:7} \
                   | {:8} | {:7} | {:8} \
                   | {:7} | {:9} | {:9} \
                   | {:9} | {:9} | {:8} \
                   | {:8} | {:8} | {:8} \
                   | {:6} |",
            "mseq",
            "pid",
            "comm",
            "stat",
            "cpu",
            "vtmc",
            "vddln_ns",
            "slc_ns",
            "grdy_rt",
            "lat_cri",
            "avg_lc",
            "st_prio",
            "slc_bst",
            "run_freq",
            "run_tm_ns",
            "wait_freq",
            "wake_freq",
            "perf_cri",
            "avg_pc",
            "cpufreq",
            "cpu_util",
            "nr_act",
        )?;
        Ok(())
    }

    pub fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        if self.mseq % 32 == 1 {
            Self::format_header(w)?;
        }

        writeln!(
            w,
            "| {:6} | {:7} | {:17} \
               | {:5} | {:4} | {:4} \
               | {:14} | {:8} | {:7} \
               | {:8} | {:7} | {:8} \
               | {:7} | {:9} | {:9} \
               | {:9} | {:9} | {:8} \
               | {:8} | {:8} | {:8} \
               | {:6} |",
            self.mseq,
            self.pid,
            self.comm,
            self.stat,
            self.cpu_id,
            self.victim_cpu,
            self.vdeadline_delta_ns,
            self.slice_ns,
            self.greedy_ratio,
            self.lat_cri,
            self.avg_lat_cri,
            self.static_prio,
            self.slice_boost_prio,
            self.run_freq,
            self.run_time_ns,
            self.wait_freq,
            self.wake_freq,
            self.perf_cri,
            self.avg_perf_cri,
            self.cpuperf_cur,
            self.cpu_util,
            self.nr_active,
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
    SchedSamplesNr {
        tid: ThreadId,
        nr_samples: u64,
        interval_ms: u64,
    },
}

impl StatsReq {
    fn from_args(
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
    SchedSamples(SchedSamples),
}

pub fn server_data(nr_cpus_onln: u64) -> ScxStatsServerData<StatsReq, StatsRes> {
    let samples_open: Box<dyn StatsOpener<StatsReq, StatsRes>> =
        Box::new(move |(req_ch, res_ch)| {
            let tid = std::thread::current().id();
            req_ch.send(StatsReq::NewSampler(tid))?;
            match res_ch.recv()? {
                StatsRes::Ack => {}
                res => bail!("invalid response: {:?}", &res),
            }

            let read: Box<dyn StatsReader<StatsReq, StatsRes>> =
                Box::new(move |args, (req_ch, res_ch)| {
                    let req = StatsReq::from_args(tid, nr_cpus_onln, args)?;
                    req_ch.send(req)?;

                    let samples = match res_ch.recv()? {
                        StatsRes::SchedSamples(v) => v,
                        StatsRes::Bye => bail!("preempted by another sampler"),
                        res => bail!("invalid response: {:?}", &res),
                    };

                    samples.to_json()
                });
            Ok(read)
        });

    ScxStatsServerData::new()
        .add_meta(SchedSample::meta())
        .add_ops(
            "sched_samples",
            ScxStatsOps {
                open: samples_open,
                close: None,
            },
        )
}

pub fn monitor_sched_samples(nr_samples: u64) -> Result<()> {
    println!(
        "    stat: ('L'atency-critical, 'R'egular) (performance-'H'ungry, performance-'I'nsensitive) ('B'ig, li'T'tle) ('E'ligigle, 'G'reedy) ('P'reempting, 'N'ot)");

    scx_utils::monitor_stats::<SchedSamples>(
        &vec![
            ("target".into(), "sched_samples".into()),
            ("nr_samples".into(), nr_samples.to_string()),
        ],
        Duration::from_secs(0),
        || !crate::RUNNING.load(Ordering::Relaxed),
        |ts| {
            let mut stdout = std::io::stdout();
            for sample in ts.samples.iter() {
                sample.format(&mut stdout)?;
            }
            Ok(())
        },
    )
}
