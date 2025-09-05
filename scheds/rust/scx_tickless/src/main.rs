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
use std::ffi::c_int;
use std::fs;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use affinity::set_thread_affinity;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::warn;
use log::{debug, info};
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Cpumask;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_tickless";

#[derive(Debug, Parser)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Define the set of CPUs, represented as a bitmask in hex (e.g., 0xff), dedicated to process
    /// scheduling events.
    ///
    /// 0x0 = autodetect the slowest CPU to process scheduling events.
    #[clap(short = 'm', long, default_value = "0")]
    primary_domain: String,

    /// Maximum scheduling slice duration in microseconds (applied only when multiple tasks are
    /// contending the same CPU).
    #[clap(short = 's', long, default_value = "20000")]
    slice_us: u64,

    /// Frequency of the tick triggered on the scheduling CPUs to check for task time slice
    /// expiration (0 == CONFIG_HZ).
    ///
    /// A higher frequency can increase the overall system responsiveness but it can also introduce
    /// more scheduling overhead and load on the primary CPUs.
    #[clap(short = 'f', long, default_value = "0")]
    frequency: u64,

    /// Disable SMT topology awareness.
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    nosmt: bool,

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

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

pub fn is_nohz_enabled() -> bool {
    if let Ok(contents) = fs::read_to_string("/sys/devices/system/cpu/nohz_full") {
        let trimmed = contents.trim();
        return trimmed != "(null)" && !trimmed.is_empty();
    }
    false
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        // Initialize CPU topology.
        let topo = Topology::new().unwrap();
        let smt_enabled = !opts.nosmt && topo.smt_enabled;
        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        // Check if nohz_full is enabled.
        if !is_nohz_enabled() {
            warn!("nohz_full is not enabled in the kernel");
        }

        // Generate the list of available CPUs sorted by capacity in descendind order.
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));

        // Process the domain of primary CPUs.
        let mut domain = Cpumask::from_str(&opts.primary_domain)?;
        if domain.is_empty() {
            if let Some(cpu) = cpus.last() {
                domain = Cpumask::from_str(&format!("{:x}", 1 << cpu.id).to_string())?;
            }
        }
        info!("primary CPU domain = 0x{:x}", domain);

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, tickless_ops, open_opts)?;
        skel.struct_ops.tickless_ops_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();

        rodata.smt_enabled = smt_enabled;
        rodata.nr_cpu_ids = *NR_CPU_IDS as u32;

        // Override default BPF scheduling parameters.
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.tick_freq = opts.frequency;

        for (i, cpu) in cpus.iter().enumerate() {
            rodata.preferred_cpus[i] = cpu.id as u64;
        }

        // Set scheduler flags.
        skel.struct_ops.tickless_ops_mut().flags = *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.tickless_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, tickless_ops, uei)?;

        // Set task affinity to the first primary CPU: this is required to start the scheduler's
        // timer on a primary CPU.
        let timer_cpu = domain.iter().next();
        if timer_cpu.is_none() {
            bail!("primary cpumask is empty");
        }
        if let Err(e) = set_thread_affinity(&[timer_cpu.unwrap() as usize]) {
            bail!("cannot set central CPU affinity: {}", e);
        }

        // Initialize the group of primary CPUs.
        if let Err(err) = Self::init_primary_domain(&mut skel, &domain) {
            warn!("failed to initialize primary domain: error {}", err);
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, tickless_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        // Reset task affinity.
        if let Err(e) = set_thread_affinity((0..*NR_CPU_IDS).collect::<Vec<usize>>()) {
            bail!("cannot reset CPU affinity: {}", e);
        }

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
        })
    }

    fn enable_primary_cpu(skel: &mut BpfSkel<'_>, cpu: i32) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_primary_cpu;
        let mut args = cpu_arg {
            cpu_id: cpu as c_int,
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

    fn init_primary_domain(skel: &mut BpfSkel<'_>, domain: &Cpumask) -> Result<()> {
        // Clear the primary domain by passing a negative CPU id.
        if let Err(err) = Self::enable_primary_cpu(skel, -1) {
            warn!("failed to reset primary domain: error {}", err as i32);
        }
        // Update primary scheduling domain.
        for cpu in 0..*NR_CPU_IDS {
            if domain.test_cpu(cpu) {
                if let Err(err) = Self::enable_primary_cpu(skel, cpu as i32) {
                    warn!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_ticks: bss_data.nr_ticks,
            nr_preemptions: bss_data.nr_preemptions,
            nr_direct_dispatches: bss_data.nr_direct_dispatches,
            nr_primary_dispatches: bss_data.nr_primary_dispatches,
            nr_timer_dispatches: bss_data.nr_timer_dispatches,
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

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
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
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
