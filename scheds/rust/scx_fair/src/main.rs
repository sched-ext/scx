// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::collections::HashMap;
use std::ffi::c_int;
use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use stats::Metrics;

const SCHEDULER_NAME: &'static str = "scx_fair";

#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Maximum scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "20000")]
    slice_us_max: u64,

    /// Mimimum scheduling slice duration in microseconds.
    #[clap(short = 'S', long, default_value = "1000")]
    slice_us_min: u64,

    /// Maximum time slice lag in microseconds.
    ///
    /// Increasing this value can help to enhance the responsiveness of interactive tasks, but it
    /// can also make performance more "spikey".
    #[clap(short = 'l', long, default_value = "20000")]
    slice_us_lag: u64,

    /// Enable kthreads prioritization.
    ///
    /// Enabling this can improve system performance, but it may also introduce interactivity
    /// issues or unfairness in scenarios with high kthread activity, such as heavy I/O or network
    /// traffic.
    #[clap(short = 'k', long, action = clap::ArgAction::SetTrue)]
    local_kthreads: bool,

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

fn is_smt_active() -> std::io::Result<i32> {
    let mut file = File::open("/sys/devices/system/cpu/smt/active")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let smt_active: i32 = contents.trim().parse().unwrap_or(0);

    Ok(smt_active)
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        set_rlimit_infinity();

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = match is_smt_active() {
            Ok(value) => value == 1,
            Err(e) => bail!("Failed to read SMT status: {}", e),
        };
        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            *build_id::SCX_FULL_VERSION,
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let mut skel = scx_ops_open!(skel_builder, open_object, fair_ops)?;

        skel.struct_ops.fair_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        skel.maps.rodata_data.slice_max = opts.slice_us_max * 1000;
        skel.maps.rodata_data.slice_min = opts.slice_us_min * 1000;
        skel.maps.rodata_data.slice_lag = opts.slice_us_lag * 1000;
        skel.maps.rodata_data.local_kthreads = opts.local_kthreads;

        skel.maps.rodata_data.smt_enabled = smt_enabled;

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, fair_ops, uei)?;

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();

        // Initialize LLC domain.
        Self::init_l3_cache_domains(&mut skel, &topo)?;

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, fair_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn enable_sibling_cpu(
        skel: &mut BpfSkel<'_>,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            cpu_id: cpu as c_int,
            sibling_cpu_id: sibling_cpu as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn init_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
        cache_lvl: usize,
        enable_sibling_cpu_fn: &dyn Fn(&mut BpfSkel<'_>, usize, usize, usize) -> Result<(), u32>,
    ) -> Result<(), std::io::Error> {
        // Determine the list of CPU IDs associated to each cache node.
        let mut cache_id_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for core in topo.cores().into_iter() {
            for (cpu_id, cpu) in core.cpus() {
                let cache_id = match cache_lvl {
                    2 => cpu.l2_id(),
                    3 => cpu.l3_id(),
                    _ => panic!("invalid cache level {}", cache_lvl),
                };
                cache_id_map
                    .entry(cache_id)
                    .or_insert_with(Vec::new)
                    .push(*cpu_id);
            }
        }

        // Update the BPF cpumasks for the cache domains.
        for (cache_id, cpus) in cache_id_map {
            info!(
                "L{} cache ID {}: sibling CPUs: {:?}",
                cache_lvl, cache_id, cpus
            );
            for cpu in &cpus {
                for sibling_cpu in &cpus {
                    match enable_sibling_cpu_fn(skel, cache_lvl, *cpu, *sibling_cpu) {
                        Ok(()) => {}
                        Err(_) => {
                            warn!(
                                "L{} cache ID {}: failed to set CPU {} sibling {}",
                                cache_lvl, cache_id, *cpu, *sibling_cpu
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn init_l3_cache_domains(
        skel: &mut BpfSkel<'_>,
        topo: &Topology,
    ) -> Result<(), std::io::Error> {
        Self::init_cache_domains(skel, topo, 3, &|skel, _lvl, cpu, sibling_cpu| {
            Self::enable_sibling_cpu(skel, cpu, sibling_cpu)
        })
    }

    fn get_metrics(&self) -> Metrics {
        Metrics {
            nr_kthread_dispatches: self.skel.maps.bss_data.nr_kthread_dispatches,
            nr_direct_dispatches: self.skel.maps.bss_data.nr_direct_dispatches,
            nr_shared_dispatches: self.skel.maps.bss_data.nr_shared_dispatches,
            nr_migrate_dispatches: self.skel.maps.bss_data.nr_migrate_dispatches,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        info!("Unregister {} scheduler", SCHEDULER_NAME);
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!("{} {}", SCHEDULER_NAME, *build_id::SCX_FULL_VERSION);
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
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
            stats::monitor(Duration::from_secs_f64(intv), shutdown_copy).unwrap()
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
