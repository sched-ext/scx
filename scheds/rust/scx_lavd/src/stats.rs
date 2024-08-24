use anyhow::Result;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;
use std::io::Write;

#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
pub struct TaskSample {
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

impl TaskSample {
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
