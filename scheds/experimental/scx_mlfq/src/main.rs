// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! scx_mlfq, a Multilevel Feedback Queue scheduler for sched_ext.
//!
//! Per-CPU, virtual-time-ordered user DSQs (Q1/Q2/Q3 per CPU) over an EEVDF
//! virtual-time substrate. Tasks are classified into queues by an EMA
//! interactivity gauge with band hysteresis, promoted by short-sleep and
//! aging, demoted by slice exhaustion. See README.md for the design
//! overview.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod config;
mod stats;
mod topology;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::generate;
use clap_complete::Shell;
use crossbeam::channel::RecvTimeoutError;
use log::info;
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
use scx_utils::UserExitInfo;

use config::Config;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_mlfq";

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /// Enable periodic statistics monitoring at the given interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in statistics monitoring mode; the scheduler is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable verbose libbpf/BPF debug logging.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Size of the exit dump buffer in bytes; the kernel fills it with
    /// per-CPU and per-task state when the scheduler exits on an error.
    #[clap(long, default_value = "1048576")]
    exit_dump_len: u32,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    /// Generate shell completions and exit.
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

/// Scheduler facade: owns the loaded skeleton, the struct_ops link and the
/// stats server; drives the run loop until shutdown or UEI exit.
struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    started_at: std::time::Instant,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.debug || opts.verbose);

        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, mlfq_ops, open_opts)?;

        // Write the validated constants into rodata before load; the rodata
        // section becomes read-only once the object is loaded.
        let config = Config::default();
        config.validate()?;
        config.apply(&mut skel)?;
        info!("Config: {}", config.describe());

        // Hybrid-capacity, cache-domain and NUMA placement data also goes
        // into rodata pre-load.
        let topology_plan = topology::init_topology(&mut skel)?;

        /*
         * Ops flags: honor exiting tasks, receive the SCX_ENQ_LAST enqueue
         * for the last runnable task on a CPU, never migrate
         * migration-disabled tasks, and allow queued-wakeup selection of
         * idle CPUs (the idle-CPU fast path depends on the latter two).
         *
         * The per-node built-in idle tracking flag is intentionally left
         * off: with per-node built-in idle tracking enabled, the kernel's
         * scx_bpf_get_idle_cpumask() and scx_bpf_pick_idle_cpu() error out
         * of the scheduler (ext_idle.c), and select_cpu.bpf.c calls exactly
         * those helpers; the per-node variants are never used. Leaving the
         * flag off keeps the kernel's own NUMA idle optimization active.
         */
        skel.struct_ops.mlfq_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;

        /*
         * Error exits capture the per-CPU and per-task state dump into
         * the exit report; without a buffer the kernel skips the dump
         * entirely, so a stall or a placement failure would leave no
         * evidence of where the task was parked.
         */
        skel.struct_ops.mlfq_ops_mut().exit_dump_len = opts.exit_dump_len;

        let mut skel = scx_ops_load!(skel, mlfq_ops, uei)?;

        // The membership bitmaps are written after load (the maps are only
        // available on the loaded object). An unpopulated primary bitmap
        // falls back to all-primary behavior; an empty LLC bitmap yields
        // no idle candidate there, so a failure only degrades the
        // placement hint.
        if let Err(e) = topology::write_primary_bitmap(&mut skel, &topology_plan.capacity) {
            log::warn!(
                "failed to write the primary bitmap, falling back to all-primary placement: {e:#}"
            );
        }
        if let Err(e) = topology::write_llc_bitmaps(&mut skel, &topology_plan.llcs) {
            log::warn!("failed to write the LLC bitmaps, disabling LLC-aware placement: {e:#}");
        }

        let struct_ops = scx_ops_attach!(skel, mlfq_ops)?;

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            started_at: std::time::Instant::now(),
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss_data missing, the BPF object has no .bss section");
        let s = &bss_data.mlfq_stats;
        Metrics {
            on_cpu: s.on_cpu,
            total_runtime: s.total_runtime,
            uptime_ns: self.started_at.elapsed().as_nanos() as u64,
            q1_placements: s.q1_placements,
            q2_placements: s.q2_placements,
            q3_placements: s.q3_placements,
            promotions: s.promotions,
            demotions: s.demotions,
            aging_boosts: s.aging_boosts,
            short_sleep_boosts: s.short_sleep_boosts,
            preemption_kicks: s.preemption_kicks,
            cpuperf_boosts: s.cpuperf_boosts,
            steals: s.steals,
            keep_running: s.keep_running,
            enq_no_tctx: s.enq_no_tctx,
            enq_bad_weight: s.enq_bad_weight,
            enq_no_deadline: s.enq_no_deadline,
            enq_fastpath: s.enq_fastpath,
            enq_regular: s.enq_regular,
            enq_pinned_idle: s.enq_pinned_idle,
            enq_pinned_busy: s.enq_pinned_busy,
            enq_pinned_global: s.enq_pinned_global,
        }
    }

    fn exited(&self) -> bool {
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
        }

        let m = self.get_metrics();
        log::info!(
            "mlfq exit counters: Q1={} Q2={} Q3={} fastpath={} regular={} pin_idle={} pin_busy={} pin_global={} drop_tctx={} drop_weight={} drop_deadline={} promotions={} demotions={} aging_boosts={} short_sleep_boosts={} cpuperf_boosts={} preempt_kicks={} runtime={} on_cpu={} steals={} keep_running={}",
            m.q1_placements, m.q2_placements, m.q3_placements, m.enq_fastpath,
            m.enq_regular, m.enq_pinned_idle, m.enq_pinned_busy,
            m.enq_pinned_global, m.enq_no_tctx, m.enq_bad_weight,
            m.enq_no_deadline, m.promotions, m.demotions, m.aging_boosts,
            m.short_sleep_boosts, m.cpuperf_boosts, m.preemption_kicks,
            m.total_runtime, m.on_cpu, m.steals, m.keep_running
        );
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

    if let Some(shell) = opts.completions {
        generate(
            shell,
            &mut Opts::command(),
            SCHEDULER_NAME,
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    let monitor_only = opts.monitor.is_some();

    // Print the version before any other work, so `scx_mlfq -V` works
    // without attaching anything.
    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    if !monitor_only {
        simplelog::TermLogger::init(
            if opts.debug {
                simplelog::LevelFilter::Debug
            } else {
                simplelog::LevelFilter::Info
            },
            simplelog::Config::default(),
            simplelog::TerminalMode::Stderr,
            simplelog::ColorChoice::Auto,
        )?;

        // The SMT annotation is appended when the host exposes it; an
        // unreadable knob omits the suffix rather than guessing.
        let smt_suffix = match topology::smt_enabled() {
            Some(true) => " SMT on",
            Some(false) => " SMT off",
            None => "",
        };
        info!("{} {}{}", SCHEDULER_NAME, full_version(), smt_suffix);
        info!(
            "scheduler options: {}",
            std::env::args().skip(1).collect::<Vec<_>>().join(" ")
        );
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let monitor_shutdown = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(err) = stats::monitor(Duration::from_secs_f64(intv), monitor_shutdown) {
                log::warn!("stats monitor thread finished with error: {err}");
            }
        });

        if monitor_only {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
        // Give the kernel time to finish the previous detachment before
        // re-initializing the BPF object for the next incarnation.
        std::thread::sleep(Duration::from_millis(100));
    }

    info!("Scheduler exited");

    Ok(())
}

#[cfg(test)]
mod math_test {
    use std::process::Command;

    fn host_cc() -> String {
        if let Ok(cc) = std::env::var("CC") {
            return cc;
        }
        // CI ships clang-19; prefer it, then fall back to the system compiler.
        for cand in ["clang", "cc", "gcc"] {
            if Command::new(cand).arg("--version").status().is_ok() {
                return cand.to_string();
            }
        }
        "cc".to_string()
    }

    #[test]
    fn mlfq_pure_math_native_harness() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let src = format!("{manifest_dir}/src/bpf/mlfq_math_test.c");
        let intf_dir = format!("{manifest_dir}/src/bpf");
        let out_dir = std::env::temp_dir().join("scx_mlfq_math_test");
        std::fs::create_dir_all(&out_dir).unwrap();
        let exe = out_dir.join("mlfq_math_test");

        let status = Command::new(host_cc())
            .args(["-O2", "-Wall", "-Werror", "-std=c11"])
            .args(["-I", &intf_dir])
            .arg(&src)
            .args(["-o", exe.to_str().unwrap()])
            .status()
            .expect("failed to compile mlfq_math_test.c");

        assert!(status.success(), "native harness failed to compile");

        let output = Command::new(&exe)
            .output()
            .expect("failed to run the native harness");

        let stdout = String::from_utf8_lossy(&output.stdout);
        print!("{stdout}");

        assert!(
            output.status.success(),
            "native harness failed:\n{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("All tests passed"),
            "native harness did not report success"
        );
    }
}
