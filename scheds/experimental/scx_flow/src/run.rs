// SPDX-License-Identifier: GPL-2.0
//! Loading and running the scx_flow BPF scheduler.
//!
//! With --performance, the busy CPUs are kept out of idle states that take
//! time to leave while the scheduler runs, see pmqos.rs, and the double
//! helix queues of the LLC pairs are created before the scheduler is
//! attached, see helix.bpf.h.
//!
//! The scheduler is loaded again when the kernel asks for it, as after CPU
//! hotplug, and after it fails, as on a stall, a few times with a growing
//! pause before giving up.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::collections::BTreeMap;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::ProgramInput;
use log::debug;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_read;

use crate::BpfSkel;
use crate::BpfSkelBuilder;
use crate::bpf_intf;
use crate::cache::CpuCaches;
use crate::cli::Opts;
use crate::cli::SCHEDULER_NAME;
use crate::pmqos::IdleLimits;
use crate::stats::Metrics;
use crate::topology::BpfTopology;

/// How often the idle state limits of --performance follow the busy CPUs.
const IDLE_LIMIT_INTERVAL: Duration = Duration::from_millis(100);

/// Topology lines printed at startup before the rest is summarized.
const TOPO_LOG_LINES: usize = 64;

/// Failures within FAILURE_WINDOW that are restarted before giving up.
const MAX_FAILURES: usize = 3;
/// The span in which failures count towards MAX_FAILURES.
const FAILURE_WINDOW: Duration = Duration::from_secs(600);

/// Pause before a restart after a failure, doubled for every failure in
/// the window.
const FAILURE_PAUSE: Duration = Duration::from_secs(1);

/// Shortest run before a restart the kernel asks for. A burst of hotplug
/// events then reloads the scheduler about once a second, not once per
/// event.
const RESTART_GAP: Duration = Duration::from_secs(1);

/// How a run of the scheduler ended.
pub(crate) enum RunEnd {
    /// Told to stop, or unregistered for good.
    Stop,
    /// The kernel asks for a restart, as after CPU hotplug.
    Restart,
    /// The scheduler failed, as on a stall.
    Failed(anyhow::Error),
}

pub(crate) struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    idle_limits: Option<IdleLimits>,
}

fn log_lines(level: log::Level, (lines, total): (Vec<String>, usize)) {
    let shown = lines.len();

    for line in lines {
        log::log!(level, "Topology: {line}");
    }
    if total > shown {
        log::log!(level, "Topology: ...+{} more", total - shown);
    }
}

fn log_topology(topo: &Topology, caches: &BTreeMap<usize, CpuCaches>) {
    info!("Topology: {}", crate::topology::describe_topo_summary(topo));
    log_lines(
        log::Level::Info,
        crate::topology::render_per_core_lines(topo, caches, TOPO_LOG_LINES),
    );
    if log::log_enabled!(log::Level::Debug) {
        log_lines(
            log::Level::Debug,
            crate::topology::render_topo_lines(topo, TOPO_LOG_LINES),
        );
    }
}

/// Create the double helix queues of --performance in the BPF arena.
/// Returns whether they exist. Without them, every LLC queues its tasks in
/// its own DSQ, which is no reason to give up the run.
fn create_helix_queues(skel: &BpfSkel<'_>) -> bool {
    match skel.progs.flow_helix_init.test_run(ProgramInput::default()) {
        Ok(out) if out.return_value == 0 => true,
        Ok(out) => {
            warn!(
                "double helix queues not created ({}), LLCs queue in their DSQs",
                out.return_value as i32
            );
            false
        }
        Err(e) => {
            warn!("double helix queues not created ({e:#}), LLCs queue in their DSQs");
            false
        }
    }
}

/// Copy per-CPU values into a BPF table indexed by CPU id.
fn fill_per_cpu(slots: &mut [u32], values: &BTreeMap<usize, u32>) {
    for (cpu, value) in values {
        if let Some(slot) = slots.get_mut(*cpu) {
            *slot = *value;
        }
    }
}

impl<'a> Scheduler<'a> {
    pub fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        let nr_cpus = *NR_CPU_IDS;
        let max_cpus = bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

        if nr_cpus > max_cpus {
            bail!("found {nr_cpus} possible CPUs, at most {max_cpus} are supported");
        }

        // Without a topology every CPU is treated as part of a single LLC.
        let topo = Topology::new()
            .inspect_err(|e| warn!("topology discovery failed, assuming a single LLC: {e:#}"))
            .ok();
        let caches = topo
            .as_ref()
            .map(|t| crate::cache::read_cpu_caches(t.all_cpus.keys().copied()))
            .unwrap_or_default();
        let tables = topo
            .as_ref()
            .map(|t| BpfTopology::new(t, &caches))
            .transpose()?;

        try_set_rlimit_infinity();
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, flow_ops, open_opts)
            .context("failed to open BPF object (check dmesg)")?;
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;

        // With --helicoprion, the wakeup and enqueue paths do the work of
        // these callbacks, see flow_wake_task().
        if opts.helicoprion {
            let ops = skel.struct_ops.flow_ops_mut();
            ops.runnable = std::ptr::null_mut();
            ops.stopping = std::ptr::null_mut();
            ops.quiescent = std::ptr::null_mut();
            skel.progs.flow_runnable.set_autoload(false);
            skel.progs.flow_stopping.set_autoload(false);
            skel.progs.flow_quiescent.set_autoload(false);
        } else {
            // Only --helicoprion follows the cgroup weights, see
            // flow_refresh_cgrp().
            let ops = skel.struct_ops.flow_ops_mut();
            ops.cgroup_init = std::ptr::null_mut();
            ops.cgroup_set_weight = std::ptr::null_mut();
            skel.progs.flow_cgroup_init.set_autoload(false);
            skel.progs.flow_cgroup_set_weight.set_autoload(false);
        }

        // With --performance, the kernel may queue a wakeup to the CPU of
        // the wakee and activate it there, which saves the waker the
        // remote runqueue lock. Kernels without it read zero here.
        let queued_wakeup = if opts.performance {
            *scx_utils::compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
        } else {
            0
        };
        skel.struct_ops.flow_ops_mut().flags |= queued_wakeup;

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF read-only data is not mapped")?;
        rodata.flow_nr_cpus = nr_cpus as u32;
        // The slice and the boost spread the work over the online CPUs,
        // and the statistics timer only looks at those.
        let online: Vec<usize> = match topo.as_ref() {
            Some(t) if !t.all_cpus.is_empty() => t.all_cpus.keys().copied().collect(),
            _ => (0..nr_cpus).collect(),
        };
        rodata.flow_nr_usable = online.len() as u32;
        for (slot, cpu) in rodata.flow_cpu_ids.iter_mut().zip(&online) {
            *slot = *cpu as u32;
        }
        rodata.flow_helicoprion = opts.helicoprion;
        rodata.flow_performance = opts.performance;
        rodata.flow_queued_wakeup = queued_wakeup != 0;
        for (cpu, slot) in rodata.flow_cpu_sibling.iter_mut().enumerate() {
            *slot = cpu as u32;
        }
        if let Some(t) = tables.as_ref() {
            rodata.flow_nr_llcs = t.nr_llcs;
            rodata.flow_nr_groups = t.nr_groups;
            fill_per_cpu(&mut rodata.flow_cpu_llc, &t.cpu_llc);
            fill_per_cpu(&mut rodata.flow_cpu_group, &t.cpu_group);
            fill_per_cpu(&mut rodata.flow_cpu_sibling, &t.cpu_sibling);
            for (slot, node) in rodata.flow_llc_node.iter_mut().zip(&t.llc_node) {
                *slot = *node;
            }
            for (slot, kb) in rodata.flow_llc_kb.iter_mut().zip(&t.llc_kb) {
                *slot = *kb;
            }
            for (slot, mate) in rodata.flow_llc_mate.iter_mut().zip(&t.llc_mate) {
                *slot = *mate;
            }
        }

        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        if let Some(t) = topo.as_ref() {
            log_topology(t, &caches);
        }
        let pairs = tables.as_ref().map_or(0, |t| t.nr_llc_pairs());
        let helix = opts.performance && pairs > 0 && create_helix_queues(&skel);
        let struct_ops = scx_ops_attach!(skel, flow_ops)?;

        // A run that was killed may have left the idle state limits of
        // --performance behind, whatever mode this run is in. The attach
        // fails while another scheduler runs, which may be an scx_flow that
        // still holds those limits, so they are only restored after it.
        crate::pmqos::restore_saved_limits();

        let stats_server = StatsServer::new(crate::stats::server_data()).launch()?;

        let idle_limits = opts.performance.then(|| {
            let cpus = match topo.as_ref() {
                Some(t) => t.all_cpus.keys().copied().collect(),
                None => (0..nr_cpus).collect(),
            };
            IdleLimits::new(cpus)
        });
        if opts.performance {
            info!(
                "Performance mode: urgent wakeups interrupt their CPU right away, and busy CPUs \
                 only poll while idle"
            );
        }
        if helix {
            info!("Performance mode: double helix queues for {pairs} LLC pair(s)");
        }

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            idle_limits,
        })
    }

    /// With --performance, keep the CPUs that the BPF side counts as busy
    /// out of deep idle states, see flow_track_busy().
    fn update_idle_limits(&mut self) {
        let (Some(limits), Some(bss)) =
            (self.idle_limits.as_mut(), self.skel.maps.bss_data.as_ref())
        else {
            return;
        };
        limits.update(|cpu| {
            bss.flow_cpu_states
                .get(cpu)
                .is_some_and(|cs| cs.shallow != 0)
        });
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn log_per_llc(&self) {
        if !log::log_enabled!(log::Level::Debug) {
            return;
        }
        for (llc, row) in crate::metrics::collect_per_llc(&self.skel)
            .iter()
            .enumerate()
        {
            let mut buf: Vec<u8> = Vec::new();
            if row.format_llc(&mut buf, llc).is_ok() {
                debug!("{}", String::from_utf8_lossy(&buf).trim_end());
            }
        }
    }

    pub fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<RunEnd> {
        let (res_ch, req_ch) = self.stats_server.channels();
        let wait = if self.idle_limits.is_some() {
            IDLE_LIMIT_INTERVAL
        } else {
            Duration::from_secs(1)
        };

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            self.update_idle_limits();
            match req_ch.recv_timeout(wait) {
                Ok(()) => {
                    res_ch.send(crate::metrics::collect(&self.skel))?;
                    self.log_per_llc();
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }
        let _ = self.struct_ops.take();
        let uei = uei_read!(&self.skel, uei);
        Ok(match uei.report() {
            Err(e) => RunEnd::Failed(e),
            Ok(()) if uei.should_restart() => RunEnd::Restart,
            Ok(()) => RunEnd::Stop,
        })
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

/// Sleep for @dur unless told to stop first. Returns whether to go on.
fn pause(dur: Duration, shutdown: &AtomicBool) -> bool {
    let end = Instant::now() + dur;

    while !shutdown.load(Ordering::Relaxed) {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(100)));
    }
    false
}

/// Run the scheduler until it is told to stop, restarting it when the
/// kernel asks for a restart or after it failed, see MAX_FAILURES.
pub fn drive(opts: &Opts) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    ctrlc::set_handler(move || sd.store(true, Ordering::Relaxed))
        .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let dur = crate::cli::poll_interval_secs(intv)?;
        let sd = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = crate::stats::monitor(dur, sd) {
                warn!("monitor failed: {e:#}");
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let mut failures: Vec<Instant> = Vec::new();
    while !shutdown.load(Ordering::Relaxed) {
        let started = Instant::now();
        let end = Scheduler::init(opts, &mut open_object)?.run(shutdown.clone())?;
        let go_on = match end {
            RunEnd::Stop => false,
            RunEnd::Restart => pause(RESTART_GAP.saturating_sub(started.elapsed()), &shutdown),
            RunEnd::Failed(e) => {
                let now = Instant::now();
                failures.retain(|t| now.duration_since(*t) < FAILURE_WINDOW);
                if failures.len() >= MAX_FAILURES {
                    return Err(e.context(format!(
                        "giving up after {MAX_FAILURES} failures within {} minutes",
                        FAILURE_WINDOW.as_secs() / 60
                    )));
                }
                failures.push(now);
                let wait = FAILURE_PAUSE * (1 << (failures.len() - 1));
                warn!("restarting in {} s after a failure: {e:#}", wait.as_secs());
                pause(wait, &shutdown)
            }
        };
        if !go_on {
            break;
        }
    }
    info!("Scheduler exited");
    Ok(())
}
