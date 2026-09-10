// SPDX-License-Identifier: GPL-2.0
//
// Author: Timon Stipkovits <timon2201@gmail.com>
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;

use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::OpenObject;
use log::info;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;

const SCHEDULER_NAME: &str = "scx_lunar";

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum SchedulerMode {
    /// One DSQ set per last-level cache domain.
    #[value(name = "dsqs_per_llc")]
    DsqsPerLLC,
    /// One DSQ set per CPU, with work stealing.
    #[value(name = "dsqs_per_cpu")]
    DsqsPerCpu,
}

impl SchedulerMode {
    fn as_u32(self) -> u32 {
        match self {
            SchedulerMode::DsqsPerLLC => 0,
            SchedulerMode::DsqsPerCpu => 1,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "scx_lunar",
    version,
    disable_version_flag = true,
    about = "Multi-queue latency-focused sched_ext scheduler."
)]
struct Opts {
    /// Dispatch queue layout.
    #[clap(short = 'm', long, value_enum, default_value = "dsqs_per_cpu")]
    mode: SchedulerMode,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );

        // Open the BPF skeleton.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, lunar_ops, open_opts)?;

        skel.struct_ops.lunar_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Patch scheduler configuration into .rodata before load.
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.schedulerMode = opts.mode.as_u32();

        // CPU -> LLC mapping from scx_utils::Topology (replaces the sysfs
        // walker): kernel L3 cache ids are not guaranteed dense, so compress
        // them into 0..nr_llcs, which is what the BPF side's DSQ id layout
        // (bases spaced 64 apart, bpf_for over 0..nr_llcs) expects.
        let topo = Topology::new().context("failed to detect CPU topology")?;

        let max_cpus = rodata.cpu_to_llc.len();
        if *NR_CPU_IDS > max_cpus {
            bail!(
                "system has {} possible CPU ids, but MAX_CPUS is {}; bump it in defines.h",
                *NR_CPU_IDS,
                max_cpus
            );
        }

        let mut llc_dense: BTreeMap<usize, u32> = BTreeMap::new();
        for llc_id in topo.all_llcs.keys() {
            let next = llc_dense.len() as u32;
            llc_dense.insert(*llc_id, next);
        }
        let nr_llcs = llc_dense.len() as u32;
        if nr_llcs == 0 {
            bail!("topology reported zero LLC domains");
        }
        if nr_llcs > 64 {
            // LLC DSQ id bases are spaced 64 apart on the BPF side.
            bail!("detected {nr_llcs} LLC domains, but the DSQ id layout supports at most 64");
        }

        rodata.nr_llcs = nr_llcs;
        // CPUs absent from the topology (offline / possible-but-not-present)
        // keep the default llc 0; they never dispatch while offline.
        for (cpu_id, cpu) in topo.all_cpus.iter() {
            if *cpu_id < max_cpus {
                rodata.cpu_to_llc[*cpu_id] = llc_dense[&cpu.llc_id];
            }
        }

        info!(
            "topology: {} cpus, {} llc domain(s), mode: {:?}",
            topo.all_cpus.len(),
            nr_llcs,
            opts.mode
        );
        for (cpu_id, cpu) in topo.all_cpus.iter() {
            log::debug!("  cpu{} -> llc{}", cpu_id, llc_dense[&cpu.llc_id]);
        }

        // Load and verify the BPF program.
        let mut skel = scx_ops_load!(skel, lunar_ops, uei)?;

        // Attach: registers the scheduler with sched_ext.
        let struct_ops = Some(scx_ops_attach!(skel, lunar_ops)?);
        info!("{SCHEDULER_NAME} scheduler attached");

        Ok(Self { skel, struct_ops })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            sleep(Duration::from_secs(1));
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

    let loglevel = if opts.verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };
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

    // Restart loop: a hotplug-triggered exit reinitializes the scheduler
    // with fresh topology instead of quitting.
    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
