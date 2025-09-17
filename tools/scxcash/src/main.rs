// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use clap::Parser;
use log::*;

mod monitors;
use monitors::HintsTlsMonitor;
use monitors::{CacheMonitor, CacheMonitorValue, PerfSampleMonitor, SoftDirtyCacheMonitor};
use std::mem::MaybeUninit;
pub mod bpf_intf;
pub mod bpf_skel; // generated at build time
pub use bpf_skel as bpf;

/// scxcash: Cache Usage Analyzer for sched_ext Schedulers
#[derive(Debug, Parser)]
#[command(verbatim_doc_comment)]
struct Opts {
    /// PID of the process to monitor for cache usage events.
    #[clap(short = 'p', long)]
    pid: Option<u32>,

    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Enable the soft-dirty cache monitor. If no monitor selection flags are
    /// provided, this monitor is enabled by default.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    soft_dirty: bool,

    /// Enable perf sampling monitor (prototype: samples HW cycles for now).
    #[clap(long, action = clap::ArgAction::SetTrue)]
    perf_sample: bool,

    /// Perf sampling frequency (samples per second).
    #[clap(long = "perf-freq", default_value_t = 1000)]
    perf_freq: u64,

    /// Output consumed monitor values as JSON (one per line). When not set,
    /// values are printed using Debug formatting.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    json: bool,

    /// Interval in seconds between poll/consume cycles. Defaults to 1s.
    #[clap(short = 'i', long, default_value_t = 1)]
    interval: u64,

    /// Ring buffer size in megabytes (default is 4 MB).
    #[clap(long, default_value_t = 4)]
    ring_mb: u32,

    /// Monitor task-local storage updates for a hint map.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    hints: bool,

    /// Pin path of the task hint TLS map (mandatory with --hints).
    #[clap(long = "hints-map")]
    hints_map: Option<String>,
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);

    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    // TODO(kkd): Set libbpf verbosity

    let pid_opt = opts.pid;

    let any_monitor_flag = opts.soft_dirty || opts.perf_sample || opts.hints;
    // For now support at most two monitors; use separate storages to simplify lifetimes.
    let mut soft_dirty_open: MaybeUninit<libbpf_rs::OpenObject> = MaybeUninit::uninit();
    let mut perf_open: MaybeUninit<libbpf_rs::OpenObject> = MaybeUninit::uninit();
    let mut hints_open: MaybeUninit<libbpf_rs::OpenObject> = MaybeUninit::uninit();

    let mut monitors: Vec<Box<dyn CacheMonitor<'_>>> = Vec::new();

    let ring_size_bytes = (opts.ring_mb as u64)
        .saturating_mul(1024 * 1024)
        .max(4 * 1024);

    if !any_monitor_flag || opts.soft_dirty {
        let monitor = SoftDirtyCacheMonitor::new(&mut soft_dirty_open, pid_opt, ring_size_bytes)?;
        monitors.push(Box::new(monitor));
    }
    if !any_monitor_flag || opts.perf_sample {
        let monitor = PerfSampleMonitor::new(&mut perf_open, pid_opt, opts.perf_freq)?;
        monitors.push(Box::new(monitor));
    }

    if !any_monitor_flag || opts.hints {
        let pin_path = opts
            .hints_map
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--hints-map must be provided with --hints"))?;
        let monitor = HintsTlsMonitor::new(&mut hints_open, pin_path, ring_size_bytes)?;
        monitors.push(Box::new(monitor));
    }

    if monitors.is_empty() {
        return Err(anyhow::anyhow!("No cache monitors selected"));
    }

    let sleep_dur = std::time::Duration::from_secs(opts.interval.max(1));
    let shutdown_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sf_clone = shutdown_flag.clone();
    ctrlc::set_handler(move || {
        sf_clone.store(true, std::sync::atomic::Ordering::Relaxed);
    })?;

    while !shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
        for m in monitors.iter_mut() {
            m.poll()?;
        }

        std::thread::sleep(sleep_dur);

        for m in monitors.iter_mut() {
            if opts.json {
                m.consume(
                    &mut |v: CacheMonitorValue| match serde_json::to_string(&v) {
                        Ok(s) => println!("{}", s),
                        Err(e) => error!("Failed to serialize value: {e}"),
                    },
                )?;
            } else {
                m.consume(&mut |v: CacheMonitorValue| println!("{:?}", v))?;
            }
        }
    }

    Ok(())
}
