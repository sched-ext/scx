// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use log::{debug, info, warn};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

use nix::unistd::{setuid, Uid};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

const SCHEDULER_NAME: &str = "scx_loud";

#[derive(Debug, clap::Parser)]
#[command(
    name = "scx_loud",
    version,
    disable_version_flag = true,
    about = "Yell at your PC to go faster."
)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    loudness: &'a Arc<Mutex<u32>>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>, loudness: &'a Arc<Mutex<u32>>) -> Result<Self> {
        try_set_rlimit_infinity();

        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
        );

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, loud_ops, None)?;

        skel.struct_ops.loud_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Set scheduler flags.
        skel.struct_ops.loud_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.loud_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, loud_ops, uei)?;

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, loud_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            loudness,
            struct_ops,
            stats_server,
        })
    }

    fn get_metrics(&self) -> Metrics {
        Metrics {
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_millis(250)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }

            let mut loudness = *self.loudness.lock().unwrap();
            if loudness <= 15 {
                loudness = 0;
            } else if loudness >= 20 {
                loudness = 100;
            }

            let nr_cpus = *NR_CPU_IDS as u32;
            let cpus = (loudness.min(100) * (nr_cpus - 1)) / 100 + 1;
            self.skel.maps.bss_data.as_mut().unwrap().nr_cpus = cpus;
            println!("loudness = {} cpus = {}", loudness, cpus);
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {} scheduler", SCHEDULER_NAME);
    }
}

fn mic_monitor(loudness_arc: Arc<Mutex<u32>>) {
    // We need to run as regular user to reuse the existing audio session.
    if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
        if let Ok(uid) = sudo_uid.parse::<u32>() {
            if let Err(e) = setuid(Uid::from_raw(uid)) {
                eprintln!("Failed to set UID: {}", e);
            }
        }
    }

    // Get the default host and input device
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .expect("Failed to get default input device");

     let config = match device.default_input_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to get default input config: {}", e);
            eprintln!("Use `sudo -E` to start the scheduler");
            std::process::exit(1);
        }
    };

    // Shared buffer for audio samples
    let samples_buffer = Arc::new(Mutex::new(Vec::<f32>::new()));

    // Clone for stream closure
    let buffer_for_stream = samples_buffer.clone();

    // Build input stream
    let err_fn = |err| eprintln!("an error occurred on stream: {}", err);

    let stream = match config.sample_format() {
        cpal::SampleFormat::F32 => device.build_input_stream(
            &config.into(),
            move |data: &[f32], _| {
                let mut buffer = buffer_for_stream.lock().unwrap();
                buffer.extend_from_slice(data);
            },
            err_fn,
            None,
        ),
        cpal::SampleFormat::I16 => device.build_input_stream(
            &config.into(),
            move |data: &[i16], _| {
                let mut buffer = buffer_for_stream.lock().unwrap();
                buffer.extend(data.iter().map(|&s| s as f32 / i16::MAX as f32));
            },
            err_fn,
            None,
        ),
        cpal::SampleFormat::U16 => device.build_input_stream(
            &config.into(),
            move |data: &[u16], _| {
                let mut buffer = buffer_for_stream.lock().unwrap();
                buffer.extend(data.iter().map(|&s| s as f32 / u16::MAX as f32 * 2.0 - 1.0));
            },
            err_fn,
            None,
        ),
        _ => panic!("Unsupported sample format"),
    }
    .expect("Failed to build input stream");

    stream.play().expect("Failed to play stream");

    // Spawn thread to analyze audio loudness
    let buffer_for_analysis = samples_buffer.clone();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let mut buffer = buffer_for_analysis.lock().unwrap();
        let mut loudness = loudness_arc.lock().unwrap();
        if buffer.is_empty() {
            *loudness = 0;
            continue;
        }
        let rms = (buffer.iter().map(|s| s * s).sum::<f32>() / buffer.len() as f32).sqrt();
        *loudness = (rms * 100.0).min(100.0).max(0.0).round() as u32;
        buffer.clear();
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                Ok(_) => {
                    debug!("stats monitor thread finished successfully")
                }
                Err(error_object) => {
                    warn!(
                        "stats monitor thread finished because of an error {}",
                        error_object
                    )
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

     let mut open_object = MaybeUninit::uninit();
    loop {
        let loudness = Arc::new(Mutex::new(0u32));
        let loudness_monitor = loudness.clone();

        std::thread::spawn(move || {
            // Give some time to the scheduler to settle down.
            std::thread::sleep(Duration::from_millis(1000));
            mic_monitor(loudness_monitor);
        });

        let mut sched = Scheduler::init(&opts, &mut open_object, &loudness)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
