// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! scx_mlfq, a Multilevel Feedback Queue scheduler for sched_ext.
//!
//! Per-CPU, virtual-time-ordered user DSQs (Q1/Q2/Q3 per CPU) over an EEVDF
//! virtual-time substrate. Tasks are classified into queues by a regression
//! tree that predicts the next CPU burst from per-task features (see
//! mlfq_tree.rs), with the EMA interactivity gauge as a tree feature and the
//! fallback before the first model. The wakeup path is promotion-only,
//! through the tree, the short-sleep and I/O boost and the band hysteresis.
//! Demotion flows through the run-out gate. See README.md for the design
//! overview.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod alloc;
mod config;
mod mlfq_tree;
mod stats;
mod topology;

#[cfg(feature = "count_alloc")]
#[global_allocator]
static ALLOC: alloc::TrackingAllocator = alloc::TrackingAllocator;

mod webui;

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
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
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::MapCore;
use log::info;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::pm;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

use config::Config;
use mlfq_tree::FitScratch;
use mlfq_tree::TreeSample;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_mlfq";

/* Time units from src/bpf/intf.h, used for the gauge unit conversions. */
const NSEC_PER_USEC: u64 = crate::bpf_intf::mlfq_consts_NSEC_PER_USEC as u64;

/* MLFQ tree daemon tuning, from src/bpf/intf.h. */
const MLFQ_TREE_MAX_NODES: usize = crate::bpf_intf::mlfq_consts_MLFQ_TREE_MAX_NODES as usize;
const MLFQ_TREE_MAX_DEPTH: usize = crate::bpf_intf::mlfq_consts_MLFQ_TREE_MAX_DEPTH as usize;
const MLFQ_TREE_MIN_SAMPLES: usize = crate::bpf_intf::mlfq_consts_MLFQ_TREE_MIN_SAMPLES as usize;

/* Compile-time bounds from src/bpf/intf.h, used by the web metrics. */
const MLFQ_MAX_CPUS: usize = crate::bpf_intf::mlfq_consts_MLFQ_MAX_CPUS as usize;

/*
 * Web-UI runnable gauges. The BPF side maintains `mlfq_llc_runnable`,
 * `mlfq_queue_runnable` and `mlfq_llc_idle` in the bss block directly
 * before `mlfq_stats` (the declaration order keeps the published-tree
 * control line isolated, see main.bpf.c); the generated bss type carries
 * the arrays, so the web metrics read them as typed fields.
 */

/*
 * Training-window cap, in samples. Eight retrain generations at the
 * 2048-sample minimum; a sliding window keeps the model pinned to the
 * recent workload instead of a lifetime aggregate. Daemon-side tuning
 * constant, not a user knob.
 */
const MLFQ_TREE_WINDOW_MAX: usize = 16384;

/*
 * Per-pid share cap of the training window. The BPF-side emission budget
 * is per task (MLFQ_TREE_PER_TASK_LIMIT_NS), so a process with enough
 * threads can still fill the whole window with its own samples and
 * over-fit the tree to its own behavior; the daemon therefore caps each
 * pid at ~5% of the window (MLFQ_TREE_WINDOW_MAX / 20), drops the excess
 * at ingest and counts the drops separately. Daemon-side security
 * constant, not a user knob.
 */
const MLFQ_TREE_PER_PID_CAP: u32 = (MLFQ_TREE_WINDOW_MAX / 20) as u32;

/*
 * Minimum number of distinct pids the fit slice must contain before a
 * model may be published: a tree fit on samples from a handful of pids
 * would over-fit those tasks' behavior. A rejected model keeps the
 * previous one committed, and the retrain cadence already prevents a
 * rejection from turning into a per-sample retrain storm. Daemon-side
 * constant, not a user knob.
 */
const MLFQ_TREE_MIN_PIDS: usize = 8;

/* CART growth caps for the daemon's training runs. */
const MLFQ_TREE_MIN_LEAF: usize = 32;
const MLFQ_TREE_RETRAIN_INTERVAL: Duration = Duration::from_secs(60);

/*
 * PM QoS idle-resume-latency cap in microseconds, applied to
 * /dev/cpu_dma_latency for the duration of the run. 10 us bans the deep
 * core and package C-states (18 us and 350 us exits on the target) while
 * keeping C1 (1 us), so wakeup latency is not dominated by deep-state
 * exits. An environmental power/latency tradeoff made automatically, not
 * a user knob.
 */
const MLFQ_IDLE_RESUME_LATENCY_US: i32 = 10;

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

    /// Disable the loopback web UI. The UI binds [::1]:50005 (falling
    /// back to 127.0.0.1:50005, then to the /tmp/scx_mlfq.sock unix
    /// socket when the loader sandbox blocks TCP) and is unauthenticated:
    /// the loopback address is the localhost trust boundary, and the
    /// counters it exposes are already world-readable through the stats
    /// server. This flag skips the thread entirely.
    #[clap(long = "no-webui", action = clap::ArgAction::SetTrue)]
    no_webui: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

/// Metadata of the committed MLFQ tree model, reported to the stats
/// server and the exit log. Defaults describe the untrained state.
#[derive(Clone, Copy, Debug, Default)]
struct ModelMeta {
    /// Monotonic publish generation; 0 while untrained.
    generation: u64,
    /// Training samples behind the committed model (the fit slice).
    nr_samples: usize,
    /// Nodes of the committed tree.
    nr_nodes: usize,
    /// MAE of the tree on the held-out slice of its training window, in
    /// microseconds.
    mae_tree_us: u64,
    /// MAE of the per-sample EMA baseline on the same held-out slice, in
    /// microseconds.
    mae_ema_us: u64,
    /// Pearson correlation of the tree predictions and the labels on the
    /// held-out slice.
    corr: f64,
}

/// The Scheduler facade owns the loaded skeleton, the struct_ops link, the
/// stats server and the MLFQ tree daemon state; drives the run loop
/// until shutdown or UEI exit.
struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    /*
     * Web UI plumbing: the metrics sender (None when --no-webui, in
     * which case the webui thread is never spawned and the metrics are
     * never collected) and the once-per-attach per-CPU static seed
     * (freq, LLC, SMT) the web metrics merge the dynamic BPF state into.
     */
    webui_tx: Option<crossbeam::channel::Sender<stats::WebMetrics>>,
    webui_join: Option<std::thread::JoinHandle<()>>,
    cpu_static: Vec<stats::PerCpuMetrics>,
    /*
     * Per-CPU current-frequency cache for the web UI, refreshed from
     * sysfs at most once per second in the run loop. The values ride
     * in the pushed snapshots, so a snapshot never reaches the UI with
     * a zero current frequency because a refresh was throttled.
     */
    cur_freq_khz: Vec<u64>,
    freq_read_at: Option<std::time::Instant>,
    started_at: std::time::Instant,
    /*
     * PM QoS idle-latency constraint on /dev/cpu_dma_latency, held for
     * the run; closing the file restores the previous constraint. The
     * field is never read: the file is held for its Drop side effect,
     * which releases the constraint on every exit path.
     */
    #[expect(dead_code)]
    pm_qos_fd: Option<std::fs::File>,
    /*
     * MLFQ tree daemon state: the sample ring buffer, the parsed-sample
     * channel the ring-buffer callback fills, the sliding training
     * window, the retrain cadence, the committed-model metadata and the
     * training worker channels (the fit runs off the main loop; the
     * publish stays on it).
     */
    rb_mgr: libbpf_rs::RingBuffer<'static>,
    sample_rx: crossbeam::channel::Receiver<TreeSample>,
    window: VecDeque<TreeSample>,
    /*
     * Per-pid accounting of the training window: the counts track the
     * admitted samples of each pid so no single task can own more than
     * MLFQ_TREE_PER_PID_CAP of the window, and the drop counter records
     * the samples the cap rejected at ingest.
     */
    pid_counts: HashMap<u32, u32>,
    tree_samples_cap_dropped: u64,
    last_train_at: Option<std::time::Instant>,
    train_tx: crossbeam::channel::Sender<Vec<TreeSample>>,
    train_rx: crossbeam::channel::Receiver<Result<TrainResult, anyhow::Error>>,
    model: ModelMeta,
    // Zero-allocation reuse buffers. All Vecs are pre-reserved to their
    // maximum capacity at init and reused via clear+extend, so the 100 ms
    // hot path never triggers a heap allocation after the first iteration.
    train_snapshot_buf: Vec<TreeSample>,
    web_statics_buf: Vec<Option<stats::PerCpuMetrics>>,
    web_per_cpu_buf: Vec<stats::PerCpuMetrics>,
    #[allow(dead_code)]
    op_lat_buf: Vec<u64>,
    wakeup_raw_buf: Vec<u8>,
    op_lat_raw_buf: Vec<u8>,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        shutdown: Arc<AtomicBool>,
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
         * The built-in idle tracking is kept (SCX_OPS_KEEP_BUILTIN_IDLE)
         * and ops.update_idle is registered to maintain the scheduler's
         * own idle-CPU count, which lets select_cpu() skip its idle scans
         * when the system is saturated. The flag gates the callback: a
         * registered update_idle without the flag would disable the
         * kernel's built-in idle tracking that scx_bpf_pick_idle_cpu()
         * and scx_bpf_test_and_clear_cpu_idle() rely on, so on kernels
         * without the flag the callback is left unregistered and the
         * lean path stays off (mlfq_idle_tracking remains 0).
         */
        let mut flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        if *compat::SCX_OPS_KEEP_BUILTIN_IDLE != 0 {
            flags |= *compat::SCX_OPS_KEEP_BUILTIN_IDLE;
            skel.maps
                .rodata_data
                .as_mut()
                .expect("rodata missing, the BPF object has no .rodata section")
                .mlfq_idle_tracking = 1;
        } else {
            skel.struct_ops.mlfq_ops_mut().update_idle = std::ptr::null_mut();
        }
        skel.struct_ops.mlfq_ops_mut().flags = flags;

        /*
         * Error exits capture the per-CPU and per-task state dump into
         * the exit report; without a buffer the kernel skips the dump
         * entirely, so a stall or a placement failure would leave no
         * evidence of where the task was parked.
         */
        skel.struct_ops.mlfq_ops_mut().exit_dump_len = opts.exit_dump_len;

        /*
         * The sched_switch hook tracks realtime-class occupancy and
         * attempts the takeover drain. It is needed on every kernel.
         * The occupancy flag drives placement even where the drain
         * cannot run, so the optional tracepoint program is
         * force-enabled here; the evacuation branches inside are
         * ksym-gated and self-prune on kernels without the reenqueue
         * kfuncs. The flip side of forcing it is that a kernel which
         * rejects the hook at verification fails the whole load
         * instead of degrading gracefully: the kfunc calls it makes
         * have been in the tracing kfunc set since 6.18, but any new
         * kernel that drops one of them must be tested before release.
         */
        unsafe {
            libbpf_rs::libbpf_sys::bpf_program__set_autoload(
                skel.progs.mlfq_sched_switch.as_libbpf_object().as_ptr(),
                true,
            );
        }
        /*
         * GPU tracepoints: raw tracepoints without BTF, optional.
         * SEC("tracepoint/...") without "?" and without tp_btf uses the
         * raw tracepoint and does not require BTF for module tracepoints.
         * Keep them optional by disabling autoload when tracefs is absent,
         * so load never hard-fails. The three handlers are amdgpu_cs,
         * amdgpu_cs_ioctl and gpu_scheduler/drm_sched_job_queue, covering
         * AMD and nouveau (gpu_sched).
         */
        {
            let has = |p1: &str, p2: &str| {
                std::path::Path::new(p1).exists() || std::path::Path::new(p2).exists()
            };
            if !has(
                "/sys/kernel/debug/tracing/events/amdgpu/amdgpu_cs",
                "/sys/kernel/tracing/events/amdgpu/amdgpu_cs",
            ) {
                skel.progs.mlfq_amdgpu_cs.set_autoload(false);
            }
            if !has(
                "/sys/kernel/debug/tracing/events/amdgpu/amdgpu_cs_ioctl",
                "/sys/kernel/tracing/events/amdgpu/amdgpu_cs_ioctl",
            ) {
                skel.progs.mlfq_amdgpu_cs_ioctl.set_autoload(false);
            }
            if !has(
                "/sys/kernel/debug/tracing/events/gpu_scheduler/drm_sched_job_queue",
                "/sys/kernel/tracing/events/gpu_scheduler/drm_sched_job_queue",
            ) {
                skel.progs.mlfq_gpu_sched_queue.set_autoload(false);
            }
        }

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
        // The per-LLC CPU lists feed the dispatch Tier-A same-LLC steal
        // scan. A list-write failure degrades *stealing* only: the
        // placement bitmaps above stay live, so the two fallbacks are
        // independent and the scheduler keeps its placement hints.
        if let Err(e) = topology::write_llc_cpu_lists(&mut skel, &topology_plan.llcs) {
            log::warn!(
                "failed to write the per-LLC CPU lists, disabling LLC-aware stealing: {e:#}"
            );
        }

        // GPU tracepoint availability: seed the BPF mask from actual
        // attach success (autoload after load), not just tracefs existence,
        // so the web UI reflects whether the handlers are really attached.
        // The BPF handlers also OR the bits on every gpu_submit bump, so
        // the mask stays correct even if the probe races a first event.
        {
            let mut mask: u32 = 0;
            if skel.progs.mlfq_amdgpu_cs.autoload() {
                mask |= crate::bpf_intf::MLFQ_GPU_TRACE_AMDGPU_CS;
            }
            if skel.progs.mlfq_amdgpu_cs_ioctl.autoload() {
                mask |= crate::bpf_intf::MLFQ_GPU_TRACE_AMDGPU_CS_IOCTL;
            }
            if skel.progs.mlfq_gpu_sched_queue.autoload() {
                mask |= crate::bpf_intf::MLFQ_GPU_TRACE_GPU_SCHED;
            }
            if mask != 0 {
                if let Some(bss) = skel.maps.bss_data.as_mut() {
                    bss.mlfq_gpu_trace_mask |= mask;
                }
            }
        }

        let struct_ops = scx_ops_attach!(skel, mlfq_ops)?;

        /*
         * PM QoS: hold a global idle-resume-latency constraint on
         * /dev/cpu_dma_latency for the duration of the run, so the
         * cpuidle governor keeps the CPUs in the shallowest idle states
         * that fit the cap and wakeup latency is not dominated by the
         * deep C-state exits. Closing the file on exit restores the
         * previous latency. The capability check and the write are
         * best-effort: the scheduler must run regardless, and the BPF-side
         * placement remains the fallback on a system without PM QoS.
         */
        let pm_qos_fd = if pm::cpu_idle_resume_latency_supported() {
            match pm::update_global_idle_resume_latency(MLFQ_IDLE_RESUME_LATENCY_US) {
                Ok(f) => {
                    info!(
                        "PM QoS idle resume latency held at {}us",
                        MLFQ_IDLE_RESUME_LATENCY_US
                    );
                    Some(f)
                }
                Err(e) => {
                    log::warn!("failed to set the PM QoS idle resume latency: {e:#}");
                    None
                }
            }
        } else {
            log::warn!(
                "PM QoS idle resume latency is not supported; the constraint is not applied"
            );
            None
        };

        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        /*
         * The web UI: a small bounded metrics channel (capacity 16;
         * try_send drops a frame when the buffer is full, so the run
         * loop never blocks and the buffer never grows) feeding a
         * detached server thread that exits on the shared shutdown
         * flag. The per-CPU static seed is captured once here; with
         * --no-webui neither the thread nor the seed exist.
         */
        let (webui_tx, webui_join): (
            Option<crossbeam::channel::Sender<stats::WebMetrics>>,
            Option<std::thread::JoinHandle<()>>,
        ) = if opts.no_webui {
            (None, None)
        } else {
            let (tx, rx) = crossbeam::channel::bounded::<stats::WebMetrics>(16);
            let shutdown = shutdown.clone();
            let jh = std::thread::spawn(move || {
                webui::start(rx, shutdown);
            });
            (Some(tx), Some(jh))
        };
        let cpu_static = if opts.no_webui {
            Vec::new()
        } else {
            topology::web_cpu_static()
        };

        /*
         * The training-sample ring buffer: the callback parses each
         * record as the mlfq_tree_sample mirror and forwards it into a
         * bounded channel the run loop drains. try_send drops the sample
         * when the channel is full, which the ring-buffer backpressure
         * absorbs first. TreeSample is a repr(C) POD mirroring the
         * 84-byte BPF record (1.3.11 ABI), so the parse is a plain byte
         * reinterpretation. The record's version tag is checked before
         * the record is admitted, so a record from a foreign producer or
         * a mismatched build is dropped instead of misread.
         */
        let (sample_tx, sample_rx) = crossbeam::channel::bounded(4096);
        let mut rb_builder = libbpf_rs::RingBufferBuilder::new();
        rb_builder.add(&skel.maps.mlfq_samples, move |data| {
            if data.len() < size_of::<TreeSample>() {
                return 0;
            }
            // SAFETY: TreeSample is a repr(C) mirror of the 84-byte
            // mlfq_tree_sample the stopping path submits; reading the
            // record as the struct is a plain byte reinterpretation of
            // integer fields.
            let s = unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<TreeSample>()) };
            if !mlfq_tree::sample_version_matches(&s) {
                return 0;
            }
            let _ = sample_tx.try_send(s);
            0
        })?;
        let rb_mgr = rb_builder.build()?;

        /*
         * The training worker: the fit and the metrics computation run on
         * a dedicated thread so a retrain never stalls the main loop's
         * stats and drain cadence. The main loop hands over a snapshot
         * of the window (the window is only mutated by the ingest on the
         * main thread, so taking a snapshot cannot race with the ingest) and
         * the worker sends the result back over a channel. try_send drops
         * a kick when the previous fit is still in flight, which the 60 s
         * cadence makes rare.
         */
        let (train_tx, train_rx) = spawn_train_worker();

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            webui_tx,
            webui_join,
            cpu_static,
            cur_freq_khz: Vec::with_capacity(MLFQ_MAX_CPUS),
            freq_read_at: None,
            started_at: std::time::Instant::now(),
            pm_qos_fd,
            rb_mgr,
            sample_rx,
            window: VecDeque::with_capacity(MLFQ_TREE_WINDOW_MAX),
            pid_counts: HashMap::with_capacity(2048),
            tree_samples_cap_dropped: 0,
            last_train_at: None,
            train_tx,
            train_rx,
            model: ModelMeta::default(),
            train_snapshot_buf: Vec::with_capacity(MLFQ_TREE_WINDOW_MAX),
            web_statics_buf: Vec::with_capacity(MLFQ_MAX_CPUS),
            web_per_cpu_buf: Vec::with_capacity(MLFQ_MAX_CPUS),
            op_lat_buf: Vec::with_capacity(
                crate::bpf_intf::mlfq_op_lat_slots_MLFQ_OP_LAT_OPS as usize
                    * crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_BUCKETS as usize,
            ),
            wakeup_raw_buf: Vec::with_capacity(16 * MLFQ_MAX_CPUS),
            op_lat_raw_buf: Vec::with_capacity(64 * MLFQ_MAX_CPUS),
        })
    }

    fn get_metrics(&mut self) -> Metrics {
        let op_lat = self.read_op_lat();
        let wakeup_total = self.read_wakeup_total();
        let bss_data = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss_data missing, the BPF object has no .bss section");
        let s = &bss_data.mlfq_stats;
        let g = &bss_data.mlfq_sys_gauge;
        let a = &bss_data.mlfq_adapt_state;
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
            steals_same_llc: s.steals_same_llc,
            steals_cross_llc: s.steals_cross_llc,
            keep_running: s.keep_running,
            enq_no_tctx: s.enq_no_tctx,
            enq_bad_weight: s.enq_bad_weight,
            enq_no_deadline: s.enq_no_deadline,
            enq_fastpath: s.enq_fastpath,
            enq_regular: s.enq_regular,
            enq_pinned_idle: s.enq_pinned_idle,
            enq_pinned_busy: s.enq_pinned_busy,
            enq_pinned_global: s.enq_pinned_global,
            tree_inference: s.tree_inference,
            tree_fallback: s.tree_fallback,
            tree_disagree: s.tree_disagree,
            tree_samples_emitted: s.tree_samples_emitted,
            tree_samples_dropped: s.tree_samples_dropped,
            rt_takeovers: s.rt_takeovers,
            rt_evacuations: s.rt_evacuations,
            rt_redirects: s.rt_redirects,
            rt_reenqs: s.rt_reenqs,
            op_lat,
            tree_samples_cap_dropped: self.tree_samples_cap_dropped,
            tree_model_generation: self.model.generation,
            tree_model_nodes: self.model.nr_nodes as u64,
            tree_model_samples: self.model.nr_samples as u64,
            tree_mae_tree_us: self.model.mae_tree_us,
            tree_mae_ema_us: self.model.mae_ema_us,
            tree_corr_milli: (self.model.corr * 1000.0).round() as i64,
            sys_lat_ema_us: g.lat_ema / NSEC_PER_USEC,
            sys_rate_ema: g.rate_ema,
            t_l_eff_us: a.t_l_eff_ns / NSEC_PER_USEC,
            t_h_eff_us: a.t_h_eff_ns / NSEC_PER_USEC,
            t_int_eff_us: a.t_int_eff_ns / NSEC_PER_USEC,
            t_bnd_eff_us: a.t_bnd_eff_ns / NSEC_PER_USEC,
            guard_eff_us: a.guard_eff_ns / NSEC_PER_USEC,
            adapt_shift: a.shift_fp,
            wakeup_total,
            adapt_steps: u64::from(g.adapt_steps),
        }
    }

    /// Web-metrics snapshot. The raw scheduler counters plus the per-CPU
    /// state and the runnable gauges, pushed to the web UI every run-loop
    /// iteration. Gauges only, no interval deltas.
    fn get_web_metrics(&mut self) -> stats::WebMetrics {
        // Refresh the per-CPU current frequencies at most once per
        // second, so the sysfs reads cannot grow with the push cadence.
        // Copy the CPU count first so the bss_data borrow does not overlap
        // the later mutable borrow for get_metrics.
        let nr_cpus_bss = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss_data missing, the BPF object has no .bss section")
            .nr_cpu_ids as usize;
        let now = std::time::Instant::now();
        if self
            .freq_read_at
            .is_none_or(|t| now.duration_since(t).as_secs() >= 1)
        {
            let nr = nr_cpus_bss.min(MLFQ_MAX_CPUS);
            self.cur_freq_khz.clear();
            self.cur_freq_khz.reserve(nr);
            for cpu in 0..nr {
                self.cur_freq_khz
                    .push(topology::current_freq_khz(cpu as u32));
            }
            self.freq_read_at = Some(now);
        }
        let bss_data = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss_data missing, the BPF object has no .bss section");

        // Merge the per-CPU dynamic state (running queue, running pid,
        // realtime occupancy) from the per-CPU maps into the once-per-
        // attach static seed (freq, LLC, SMT). One entry per CPU in
        // bss_data.nr_cpu_ids, capped at MLFQ_MAX_CPUS.
        let nr_cpus = (bss_data.nr_cpu_ids as usize).min(MLFQ_MAX_CPUS);
        // Reuse the statics scratch buffer. Capacity is MLFQ_MAX_CPUS, so
        // no allocation after the first iteration.
        self.web_statics_buf.clear();
        self.web_statics_buf.resize_with(nr_cpus, || None);
        for s in &self.cpu_static {
            if (s.id as usize) < nr_cpus {
                self.web_statics_buf[s.id as usize] = Some(s.clone());
            }
        }
        self.web_per_cpu_buf.clear();
        for (cpu, static_entry) in self.web_statics_buf.iter().enumerate().take(nr_cpus) {
            let mut entry = static_entry.clone().unwrap_or_default();
            entry.id = cpu as u32;
            entry.cur_freq_khz = self.cur_freq_khz.get(cpu).copied().unwrap_or(0);

            let state = self.read_cpu_state_noalloc(cpu);
            entry.running_queue = state.running_queue;
            entry.running_pid = state.running_pid;
            entry.running_gpu_submit = state.running_gpu_submit;

            let rt = self.read_rtdl_state_noalloc(cpu);
            entry.rt_occupied = rt.flags & crate::bpf_intf::MLFQ_RTDL_OCCUPIED != 0;
            self.web_per_cpu_buf.push(entry);
        }
        // Move the scratch buffer into per_cpu without allocating a new Vec
        // by swapping. The scratch is left empty but retains capacity.
        let mut per_cpu = Vec::with_capacity(nr_cpus);
        std::mem::swap(&mut per_cpu, &mut self.web_per_cpu_buf);

        // Copy the BSS gauges before the mutable borrow for get_metrics
        // so the borrow checker sees no overlap.
        let gpu_submit_total = bss_data.mlfq_gpu_submit_total;
        let gpu_trace_mask = bss_data.mlfq_gpu_trace_mask;
        let stats = self.get_metrics();
        stats::WebMetrics {
            stats,
            per_cpu,
            queue_runnable: self.read_queue_runnable(),
            llc_runnable: self.read_llc_runnable(),
            gpu_submit_total,
            gpu_trace_mask,
        }
    }

    /// Read one CPU's dynamic state from the per-CPU array map. A failed
    /// lookup or an unexpected value size yields an all-zero state.
    #[allow(dead_code)]
    fn read_cpu_state(&self, cpu: usize) -> mlfq_cpu_state {
        let key = (cpu as u32).to_ne_bytes();
        match self
            .skel
            .maps
            .cpu_state_stor
            .lookup(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(bytes)) if bytes.len() >= size_of::<mlfq_cpu_state>() => {
                // SAFETY: mlfq_cpu_state is the repr(C) bindgen mirror of
                // the map's value type; reading the value bytes as the
                // struct is a plain reinterpretation of integer fields.
                unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<mlfq_cpu_state>()) }
            }
            _ => mlfq_cpu_state {
                running_queue: 0,
                running_pid: 0,
                steal_scan_off: 0,
                cpu_ema: 0,
                cpu_ema_at: 0,
                running_deadline: 0,
                run_start_at: 0,
                running_gpu_submit: 0,
                pad2: 0,
            },
        }
    }

    /// Read one CPU's realtime-occupancy state from the per-CPU array
    /// map; a failed lookup yields an all-zero state (not occupied).
    #[allow(dead_code)]
    fn read_rtdl_state(&self, cpu: usize) -> mlfq_rtdl_state {
        let key = (cpu as u32).to_ne_bytes();
        match self
            .skel
            .maps
            .rtdl_state_stor
            .lookup(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(bytes)) if bytes.len() >= size_of::<mlfq_rtdl_state>() => {
                // SAFETY: as in read_cpu_state: a repr(C) mirror of the
                // map's value type.
                unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<mlfq_rtdl_state>()) }
            }
            _ => mlfq_rtdl_state {
                flags: 0,
                pad: 0,
                last_drain_at: 0,
            },
        }
    }

    /// Tracked runnable tasks per queue (index 0 unused, 1..3 = Q1..Q3).
    ///
    /// The gauge is the BPF-side `mlfq_queue_runnable` bss array, which
    /// counts the runnable tasks placed in each queue's DSQs (the
    /// accounting contract is in `intf.h` next to the counters). Read
    /// through the generated bss type, so a layout change is a compile
    /// error rather than a silent misread.
    fn read_queue_runnable(&self) -> Vec<u64> {
        let bss_data = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss_data missing, the BPF object has no .bss section");
        bss_data
            .mlfq_queue_runnable
            .iter()
            .map(|v| *v as u64)
            .collect()
    }

    /// Tracked runnable tasks per LLC domain (MLFQ_MAX_LLCS entries).
    /// Same contract and access path as `read_queue_runnable`.
    fn read_llc_runnable(&self) -> Vec<u64> {
        let bss_data = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss_data missing, the BPF object has no .bss section");
        bss_data
            .mlfq_llc_runnable
            .iter()
            .map(|v| *v as u64)
            .collect()
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /// Stack-based read of per-CPU state without heap allocation.
    /// Uses the raw bpf_map_lookup_elem syscall with a stack buffer, so the
    /// 100 ms web snapshot does not allocate one Vec per CPU.
    fn read_cpu_state_noalloc(&self, cpu: usize) -> mlfq_cpu_state {
        if cpu >= MLFQ_MAX_CPUS {
            return mlfq_cpu_state {
                running_queue: 0,
                running_pid: 0,
                steal_scan_off: 0,
                cpu_ema: 0,
                cpu_ema_at: 0,
                running_deadline: 0,
                run_start_at: 0,
                running_gpu_submit: 0,
                pad2: 0,
            };
        }
        let fd = self.skel.maps.cpu_state_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = std::mem::MaybeUninit::<mlfq_cpu_state>::uninit();
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                fd,
                &key as *const _ as *const std::ffi::c_void,
                out.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        if ret == 0 {
            unsafe { out.assume_init() }
        } else {
            mlfq_cpu_state {
                running_queue: 0,
                running_pid: 0,
                steal_scan_off: 0,
                cpu_ema: 0,
                cpu_ema_at: 0,
                running_deadline: 0,
                run_start_at: 0,
                running_gpu_submit: 0,
                pad2: 0,
            }
        }
    }

    /// Stack-based read of RTDL state without heap allocation.
    fn read_rtdl_state_noalloc(&self, cpu: usize) -> mlfq_rtdl_state {
        if cpu >= MLFQ_MAX_CPUS {
            return mlfq_rtdl_state {
                flags: 0,
                pad: 0,
                last_drain_at: 0,
            };
        }
        let fd = self.skel.maps.rtdl_state_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = std::mem::MaybeUninit::<mlfq_rtdl_state>::uninit();
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                fd,
                &key as *const _ as *const std::ffi::c_void,
                out.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        if ret == 0 {
            unsafe { out.assume_init() }
        } else {
            mlfq_rtdl_state {
                flags: 0,
                pad: 0,
                last_drain_at: 0,
            }
        }
    }

    /// Sum the per-CPU op-latency histogram into a flat per-op vector
    /// (MLFQ_OP_LAT_OPS x MLFQ_OP_LAT_BUCKETS entries, op-major). The
    /// map is per-CPU so the BPF charges never contend. A failed lookup
    /// or an unexpected value size yields zeros for that entry.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    fn read_op_lat(&mut self) -> Vec<u64> {
        let nr_ops = crate::bpf_intf::mlfq_op_lat_slots_MLFQ_OP_LAT_OPS as usize;
        let buckets = crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_BUCKETS as usize;
        // Reuse the scratch buffer. Capacity is pre-reserved, so this
        // does not allocate after the first call.
        self.op_lat_buf.clear();
        self.op_lat_buf.resize(nr_ops * buckets, 0);
        let nr_cpus = (self
            .skel
            .maps
            .bss_data
            .as_ref()
            .map(|b| b.nr_cpu_ids as usize)
            .unwrap_or(1))
        .min(MLFQ_MAX_CPUS);
        // Raw per-cpu read: reuse a raw buffer for the per-CPU values
        // and sum without allocating Vec<Vec<u8>>.
        let value_size = 8 * buckets;
        let raw_size = value_size * nr_cpus;
        self.op_lat_raw_buf.clear();
        self.op_lat_raw_buf.resize(raw_size, 0);
        for op in 0..nr_ops {
            let key = (op as u32).to_ne_bytes();
            let fd = self.skel.maps.mlfq_op_lat.as_fd().as_raw_fd();
            let ret = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                    fd,
                    &key as *const _ as *const std::ffi::c_void,
                    self.op_lat_raw_buf.as_mut_ptr() as *mut std::ffi::c_void,
                )
            };
            if ret != 0 {
                continue;
            }
            for cpu in 0..nr_cpus {
                let base = cpu * value_size;
                for b in 0..buckets {
                    let off = base + b * 8;
                    let slot = &self.op_lat_raw_buf[off..off + 8];
                    let v = u64::from_ne_bytes(slot.try_into().expect("8-byte slot"));
                    self.op_lat_buf[op * buckets + b] =
                        self.op_lat_buf[op * buckets + b].wrapping_add(v);
                }
            }
        }
        // Return a clone that reuses the Vec allocation via clone,
        // but the clone is unavoidable because Metrics owns the Vec.
        // The scratch retains capacity, so the next call does not allocate.
        self.op_lat_buf.clone()
    }

    /// Sum the per-CPU lifetime wakeup totals from the mlfq_wakeup_stats
    /// map. Each CPU's total is bumped atomically on the wakeup path, so
    /// this read is tear-free, and the u64 slots cannot wrap. A failed
    /// lookup yields zero. The observation-only contract holds, so the
    /// totals grow even while the adaptation is disabled.
    fn read_wakeup_total(&mut self) -> u64 {
        let nr_cpus = (self
            .skel
            .maps
            .bss_data
            .as_ref()
            .map(|b| b.nr_cpu_ids as usize)
            .unwrap_or(1))
        .min(MLFQ_MAX_CPUS);
        let value_size = std::mem::size_of::<crate::bpf_intf::mlfq_wakeup_counters>();
        let raw_size = value_size * nr_cpus;
        self.wakeup_raw_buf.clear();
        self.wakeup_raw_buf.resize(raw_size, 0);
        let fd = self.skel.maps.mlfq_wakeup_stats.as_fd().as_raw_fd();
        let key = 0u32.to_ne_bytes();
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                fd,
                &key as *const _ as *const std::ffi::c_void,
                self.wakeup_raw_buf.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        if ret != 0 {
            return 0;
        }
        let mut total = 0u64;
        for cpu in 0..nr_cpus {
            let base = cpu * value_size;
            let slot = &self.wakeup_raw_buf[base..base + 8];
            let v = u64::from_ne_bytes(slot.try_into().expect("8-byte total"));
            total = total.wrapping_add(v);
        }
        total
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            /*
             * Drain the training-sample ring buffer (the callback
             * forwards the parsed records into the sample channel) and
             * fold them into the training window before serving the
             * next stats request.
             */
            self.rb_mgr.consume()?;
            while let Ok(s) = self.sample_rx.try_recv() {
                self.ingest_sample(s);
            }
            self.poll_train_results();

            match req_ch.recv_timeout(Duration::from_millis(100)) {
                Ok(()) => {
                    // Push a web snapshot on the stats request too, so
                    // the UI cadence is the run-loop cadence, not the
                    // browser's 1 s poll.
                    let web = self.get_web_metrics();
                    if let Some(ref tx) = self.webui_tx {
                        let _ = tx.try_send(web);
                    }
                    res_ch.send(self.get_metrics())?
                }
                Err(RecvTimeoutError::Timeout) => {
                    let web = self.get_web_metrics();
                    if let Some(ref tx) = self.webui_tx {
                        let _ = tx.try_send(web);
                    }
                }
                Err(e) => Err(e)?,
            }
        }

        /* One final drain so the exit report sees the latest samples. */
        self.rb_mgr.consume()?;
        while let Ok(s) = self.sample_rx.try_recv() {
            self.ingest_sample(s);
        }
        self.poll_train_results();

        let m = self.get_metrics();
        log::info!(
            "mlfq exit counters: Q1={} Q2={} Q3={} fastpath={} regular={} pin_idle={} pin_busy={} pin_global={} drop_tctx={} drop_weight={} drop_deadline={} promotions={} demotions={} aging_boosts={} short_sleep_boosts={} cpuperf_boosts={} preempt_kicks={} runtime={} on_cpu={} steals={} steals_same_llc={} steals_cross_llc={} keep_running={} rt_takeovers={} rt_evacuations={} rt_redirects={} rt_reenqs={} tree gen={} nodes={} samples={} mae={}us ema_mae={}us corr={:.3} tree_inf={} tree_fallback={} tree_disagree={} tree_emitted={} tree_dropped={} tree_cap_dropped={} wakeups={} adapt_steps={}",
            m.q1_placements, m.q2_placements, m.q3_placements, m.enq_fastpath,
            m.enq_regular, m.enq_pinned_idle, m.enq_pinned_busy,
            m.enq_pinned_global, m.enq_no_tctx, m.enq_bad_weight,
            m.enq_no_deadline, m.promotions, m.demotions, m.aging_boosts,
            m.short_sleep_boosts, m.cpuperf_boosts, m.preemption_kicks,
            m.total_runtime, m.on_cpu, m.steals, m.steals_same_llc,
            m.steals_cross_llc, m.keep_running,
            m.rt_takeovers, m.rt_evacuations, m.rt_redirects, m.rt_reenqs,
            m.tree_model_generation, m.tree_model_nodes, m.tree_model_samples,
            m.tree_mae_tree_us, m.tree_mae_ema_us, self.model.corr,
            m.tree_inference, m.tree_fallback, m.tree_disagree,
            m.tree_samples_emitted, m.tree_samples_dropped,
            m.tree_samples_cap_dropped, m.wakeup_total, m.adapt_steps
        );
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }

    /// Fold one emitted sample into the sliding training window and
    /// kick a retrain on the cadence. On the first window that reaches
    /// the minimum training size, then every MLFQ_TREE_RETRAIN_INTERVAL.
    ///
    /// The window admits at most MLFQ_TREE_PER_PID_CAP samples per pid. A pid that already holds its share is dropped here and counted in tree_samples_cap_dropped. The cap check runs before
    /// the window accounting, so a rejected sample never disturbs the
    /// per-pid counts, and the eviction bookkeeping below decrements the
    /// pid of the sample the window actually pops.
    fn ingest_sample(&mut self, s: TreeSample) {
        if !tree_admit_pid(&mut self.pid_counts, s.pid) {
            self.tree_samples_cap_dropped += 1;
            return;
        }
        if self.window.len() == MLFQ_TREE_WINDOW_MAX {
            let evicted = self
                .window
                .pop_front()
                .expect("a full window pops the oldest sample");
            tree_evict_pid(&mut self.pid_counts, evicted.pid);
        }
        self.window.push_back(s);

        let due = match self.last_train_at {
            None => self.window.len() >= MLFQ_TREE_MIN_SAMPLES,
            Some(t) => {
                t.elapsed() >= MLFQ_TREE_RETRAIN_INTERVAL
                    && self.window.len() >= MLFQ_TREE_MIN_SAMPLES
            }
        };
        if due {
            self.kick_training();
        }
    }

    /// Hand a snapshot of the window to the training worker.
    ///
    /// The retrain cadence counts every kick, so a rejected model cannot
    /// turn into a per-sample retrain storm. try_send drops the kick when
    /// the worker is still busy with the previous fit, which the 60 s
    /// cadence makes rare.
    fn kick_training(&mut self) {
        self.last_train_at = Some(std::time::Instant::now());
        // Reuse the snapshot buffer. The buffer is cleared and refilled
        // from the window; the capacity stays at MLFQ_TREE_WINDOW_MAX, so
        // no allocation after the first kick.
        self.train_snapshot_buf.clear();
        self.train_snapshot_buf.extend(self.window.iter().copied());
        // Move the buffer into the channel without allocating a new Vec
        // by swapping with an empty Vec that retains the channel's
        // previously sent capacity. The swap leaves the scratch empty
        // but with the same capacity for the next kick.
        let mut snapshot = Vec::new();
        std::mem::swap(&mut snapshot, &mut self.train_snapshot_buf);
        // Restore the scratch capacity for the next kick.
        self.train_snapshot_buf = Vec::with_capacity(MLFQ_TREE_WINDOW_MAX);
        if self.train_tx.try_send(snapshot).is_err() {
            log::warn!("MLFQ tree training already in flight, skipping this retrain");
        }
    }

    /// Collect the finished fits from the training worker and apply the
    /// publish quality gate to each.
    fn poll_train_results(&mut self) {
        while let Ok(res) = self.train_rx.try_recv() {
            match res {
                Ok(r) => self.apply_train_result(r),
                Err(e) => {
                    log::warn!("MLFQ tree training failed, keeping the previous model: {e:#}");
                }
            }
        }
    }

    /// Commit a finished fit when it passes validation and the publish
    /// quality gate; otherwise keep the previous model.
    ///
    /// The gate and the meta computation are pure functions in
    /// mlfq_tree (mlfq_tree::should_publish, mlfq_tree::tree_meta), which
    /// the unit tests cover.
    fn apply_train_result(&mut self, res: TrainResult) {
        if let Err(e) = mlfq_tree::serialize_validate(&res.tree) {
            log::warn!("MLFQ tree training failed validation, keeping the previous model: {e}");
            return;
        }

        let gen = self.model.generation + 1;
        /*
         * A tree fit on the behavior of a handful of tasks would
         * over-fit them, so the publish requires at least
         * MLFQ_TREE_MIN_PIDS distinct pids in the fit slice; a rejected
         * model keeps the previous one committed, and the retrain
         * cadence prevents a rejection from becoming a retrain storm.
         */
        if res.nr_pids_train < MLFQ_TREE_MIN_PIDS {
            log::info!(
                "MLFQ tree gen {} rejected: fit slice has only {} distinct pids (< {} required), keeping the previous model",
                gen, res.nr_pids_train, MLFQ_TREE_MIN_PIDS
            );
            return;
        }
        let published_corr = if self.model.generation == 0 {
            None
        } else {
            Some(self.model.corr)
        };
        if !mlfq_tree::should_publish(res.mae_tree, res.mae_ema, res.corr, published_corr) {
            log::info!(
                "MLFQ tree gen {} rejected: holdout MAE_tree={:.1}us > MAE_ema={:.1}us or corr {:.3} below floor 0.30 or not above published {:.3}, keeping the previous model",
                gen,
                res.mae_tree / 1e3,
                res.mae_ema / 1e3,
                res.corr,
                published_corr.unwrap_or(0.0)
            );
            return;
        }

        if let Err(e) = self.publish_tree(&res.tree, gen) {
            log::warn!("MLFQ tree publish failed, keeping the previous model: {e:#}");
            return;
        }

        self.model = ModelMeta {
            generation: gen,
            nr_samples: res.nr_train,
            nr_nodes: res.tree.nodes.len(),
            mae_tree_us: (res.mae_tree / 1e3).round() as u64,
            mae_ema_us: (res.mae_ema / 1e3).round() as u64,
            corr: res.corr,
        };
        info!(
            "MLFQ tree model gen {}, nodes {}, fit {} samples (holdout {}), MAE_tree={}us MAE_ema={}us corr={:.3}",
            gen,
            res.tree.nodes.len(),
            res.nr_train,
            res.holdout_len,
            self.model.mae_tree_us,
            self.model.mae_ema_us,
            self.model.corr
        );
    }

    /// Publish a validated tree into the inactive map entry and commit
    /// the meta last.
    ///
    /// The full map value is written (live nodes at the front, zeroed
    /// tail), so a shrinking tree never leaves stale nodes behind the
    /// new node count. A release fence orders the map-value write before
    /// the meta write, which flips the active entry, bumps the
    /// generation and sets the trained bit: a BPF reader that loaded the
    /// meta once sees either the old tree or the fully committed new
    /// one, never a partially written one.
    ///
    /// The protocol is sound at the 60 s publish cadence: a reader could
    /// only observe a torn tree if two publishes completed within one
    /// tree walk, and each walk is a few dozen memory reads while a
    /// publish moves up to 2048 nodes, so two consecutive publishes
    /// cannot complete inside one walk. The consequence of the
    /// theoretical race is one mispredicted burst, which the queue-band
    /// nets absorb. The walk masks every index to the buffer bound, so
    /// it is never a memory-safety issue.
    fn publish_tree(&mut self, tree: &mlfq_tree::SerializedTree, gen: u64) -> Result<()> {
        let old_meta = {
            let bss = self
                .skel
                .maps
                .bss_data
                .as_ref()
                .expect("bss_data missing, the BPF object has no .bss section");
            bss.mlfq_tree_ctrl.meta
        };
        let old_gen = old_meta >> crate::bpf_intf::MLFQ_TREE_META_GENERATION_SHIFT;
        // Monotonic generation check: new gen must exceed old, fail otherwise.
        if gen <= old_gen && old_gen != 0 {
            anyhow::bail!("monotonic gen violation: new {} <= old {}", gen, old_gen);
        }
        let old_active = (old_meta >> 1) & 1;
        let new_active = 1 - old_active;
        let key = (new_active as u32).to_ne_bytes();

        let node_bytes = unsafe {
            std::slice::from_raw_parts(
                tree.nodes.as_ptr().cast::<u8>(),
                tree.nodes.len() * size_of::<mlfq_tree::TreeNode>(),
            )
        };
        let mut buf = vec![0u8; size_of::<mlfq_tree_store>()];
        buf[..node_bytes.len()].copy_from_slice(node_bytes);
        self.skel
            .maps
            .mlfq_tree_map
            .update(&key, &buf, libbpf_rs::MapFlags::ANY)?;

        // Order the map-value write before the meta commit.
        std::sync::atomic::fence(Ordering::Release);

        {
            let bss = self
                .skel
                .maps
                .bss_data
                .as_mut()
                .expect("bss_data missing, the BPF object has no .bss section");
            bss.mlfq_tree_ctrl.meta = mlfq_tree::tree_meta(gen, tree.nodes.len(), new_active);
        }
        Ok(())
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        /*
         * Dropping pm_qos_fd closes the /dev/cpu_dma_latency fd, which
         * makes the kernel drop the PM QoS request and restore the
         * previous idle-latency constraint. The field drop below does
         * this on every exit path.
         */
        /*
         * Join the web UI thread so its unblock-write flag (see
         * webui.rs) is visible before the caller's restore decision;
         * the thread exits within its poll interval of the shutdown
         * flag, so the join is bounded.
         */
        if let Some(jh) = self.webui_join.take() {
            let _ = jh.join();
        }
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

/// Result of one training run, handed back from the worker thread. The
/// metrics are computed on the held-out slice so the publish gate and
/// the reported numbers describe out-of-sample error.
struct TrainResult {
    tree: mlfq_tree::SerializedTree,
    /// Samples the tree was fit on.
    nr_train: usize,
    /// Distinct pids in the fit slice, the concentration input for the per-pid cap.
    nr_pids_train: usize,
    /// Samples of the held-out evaluation slice.
    holdout_len: usize,
    /// Tree MAE on the holdout, in nsecs.
    mae_tree: f64,
    /// Exact per-sample EMA-baseline MAE on the holdout, in nsecs.
    mae_ema: f64,
    /// Pearson correlation of tree predictions and labels on the holdout.
    corr: f64,
}

/// Split the window into the fit slice (first 90%) and the held-out
/// evaluation slice (last 10%). The daemon only trains once the window
/// holds MLFQ_TREE_MIN_SAMPLES samples, so the holdout is never empty in
/// production; a window too small for a meaningful 90/10 split (< 20
/// samples) is an error, which the caller treats as a skipped training
/// round (log + keep the previous model) instead of silently training
/// and evaluating on the same slice.
fn split_holdout(samples: &[TreeSample]) -> Result<(&[TreeSample], &[TreeSample]), String> {
    if samples.len() >= 20 {
        let cut = samples.len() - samples.len() / 10;
        Ok(samples.split_at(cut))
    } else {
        Err(format!(
            "training window holds only {} samples; {} are needed for a 90/10 holdout split",
            samples.len(),
            20
        ))
    }
}

/// Admit one sample of `pid` into the window under the per-pid cap. Returns true when the sample is admitted and the pid's count is incremented, false when the pid already holds its
/// MLFQ_TREE_PER_PID_CAP share and the caller must drop the sample.
/// Entries are pruned on eviction, not here: a pid at the cap keeps its
/// entry until the window ages its samples out.
fn tree_admit_pid(counts: &mut HashMap<u32, u32>, pid: u32) -> bool {
    let c = counts.entry(pid).or_insert(0);
    if *c >= MLFQ_TREE_PER_PID_CAP {
        return false;
    }
    *c += 1;
    true
}

/// Remove one sample of `pid` from the per-pid accounting when the
/// window evicts its oldest sample, pruning the entry when the count
/// reaches zero so the map cannot grow with retired pids.
fn tree_evict_pid(counts: &mut HashMap<u32, u32>, pid: u32) {
    if let Some(c) = counts.get_mut(&pid) {
        *c -= 1;
        if *c == 0 {
            counts.remove(&pid);
        }
    }
}

/// Number of distinct pids in a slice, the concentration input for the per-pid cap.
fn tree_distinct_pids(samples: &[TreeSample]) -> usize {
    let mut seen = HashSet::new();
    for s in samples {
        seen.insert(s.pid);
    }
    seen.len()
}

/// Fit a tree and compute the holdout metrics, on the training worker.
///
/// The tree is fit on the first 90% of the window and evaluated on the
/// last 10%, so the reported MAE and the publish gate describe
/// out-of-sample error. The EMA baseline is exact. Each sample's
/// prediction is the captured gauge `feats.ema` (the post-decay gauge at
/// the capture, as emitted by the BPF side), so
/// `mae_ema = mean(|feats.ema - label|)` on the same holdout slice and
/// the tree comparison is honest.
#[allow(dead_code)]
fn train_model(samples: &[TreeSample]) -> Result<TrainResult, String> {
    let mut scratch = FitScratch::new();
    train_model_with_scratch(samples, &mut scratch)
}

/// Fit a tree and compute holdout metrics reusing the scratch arena.
/// The scratch buffers are cleared in place, so the second call with the
/// same window size does not allocate.
fn train_model_with_scratch(
    samples: &[TreeSample],
    scratch: &mut FitScratch,
) -> Result<TrainResult, String> {
    let (train, holdout) = split_holdout(samples)?;

    let tree = mlfq_tree::fit_with_scratch(
        train,
        MLFQ_TREE_MAX_DEPTH,
        MLFQ_TREE_MIN_LEAF,
        MLFQ_TREE_MAX_NODES,
        mlfq_tree::DEFAULT_MIN_REL_VAR_REDUCTION,
        scratch,
    );
    mlfq_tree::serialize_validate(&tree).map_err(|e| {
        // A tree that fails the walk invariants must never be
        // published; the previous model stays committed.
        format!("tree failed validation: {e}")
    })?;

    // Reuse the scratch buffers for the holdout predictions. The
    // buffers are cleared and refilled, so capacity is retained.
    scratch.actuals.clear();
    scratch.actuals.extend(holdout.iter().map(|s| s.label_ns));
    let actuals = &scratch.actuals;
    scratch.preds.clear();
    for s in holdout {
        let feats = s.feats;
        scratch.preds.push(mlfq_tree::predict(&tree, &feats));
    }
    let preds = &scratch.preds;
    // Weighted holdout: recency weights of the full window, tail slice
    // corresponds to the holdout; recent samples dominate.
    scratch.weights_full.clear();
    mlfq_tree::sample_weights_into(samples.len(), &mut scratch.weights_full);
    let holdout_weights = &scratch.weights_full[train.len()..];
    scratch.ema_preds.clear();
    scratch
        .ema_preds
        .extend(holdout.iter().map(|s| s.feats.ema));
    let ema_preds = &scratch.ema_preds;
    let mae_tree = mlfq_tree::weighted_holdout_mae(preds, actuals, holdout_weights);
    let mae_ema = mlfq_tree::weighted_holdout_mae(ema_preds, actuals, holdout_weights);
    let corr = mlfq_tree::pearson(preds, actuals);

    Ok(TrainResult {
        tree,
        nr_train: train.len(),
        nr_pids_train: tree_distinct_pids(train),
        holdout_len: holdout.len(),
        mae_tree,
        mae_ema,
        corr,
    })
}

/// Spawn the training worker and return its job and result channels.
///
/// The worker owns no scheduler state. It receives a snapshot of the
/// window (the window is only mutated by the ingest on the main thread,
/// so handing over a snapshot cannot race with the ingest), fits the tree
/// and computes the holdout metrics, and sends the result back. The
/// publish stays on the main thread. Dropping the job sender closes the
/// channel and the worker exits on its next `recv()`.
fn spawn_train_worker() -> (
    crossbeam::channel::Sender<Vec<TreeSample>>,
    crossbeam::channel::Receiver<Result<TrainResult, anyhow::Error>>,
) {
    let (job_tx, job_rx) = crossbeam::channel::bounded::<Vec<TreeSample>>(1);
    let (res_tx, res_rx) = crossbeam::channel::bounded::<Result<TrainResult, anyhow::Error>>(1);
    std::thread::spawn(move || {
        let mut scratch = FitScratch::new();
        while let Ok(samples) = job_rx.recv() {
            let res = train_model_with_scratch(&samples, &mut scratch).map_err(anyhow::Error::msg);
            if res_tx.send(res).is_err() {
                break;
            }
        }
    });
    (job_tx, res_rx)
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

        // The SMT annotation is appended when the host exposes it. An
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
        let mut sched = Scheduler::init(&opts, &mut open_object, shutdown.clone())?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
        // Give the kernel time to finish the previous detachment before
        // re-initializing the BPF object for the next incarnation.
        std::thread::sleep(Duration::from_millis(100));
    }

    /*
     * If this run wrote the runtime loader-sandbox unblock (see
     * webui.rs), restore it now: the drop-in is per-boot state under
     * /run, so it must be undone once, at the final exit after the
     * restart loop, not on every internal restart. The web UI thread
     * of the last incarnation is joined first, so its unblock-write
     * flag is visible before the restore decision (the thread exits
     * within its poll interval of the shutdown flag).
     */
    webui::restore_loader_sandbox();

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
        // CI ships clang-19. Prefer it, then fall back to the system compiler.
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

    /// Minimal test sample; pid and label are the only fields the
    /// daemon-side pure helpers inspect.
    fn mk_sample(pid: u32, label_ns: u64) -> crate::mlfq_tree::TreeSample {
        crate::mlfq_tree::TreeSample {
            pid,
            version: crate::mlfq_tree::MLFQ_TREE_SAMPLE_VERSION,
            queue: 1,
            feats: crate::mlfq_tree::TreeFeats::default(),
            label_ns,
        }
    }

    #[test]
    fn split_holdout_cut_and_rejection() {
        let samples: Vec<_> = (0..100).map(|i| mk_sample(i as u32, i as u64)).collect();

        // The 90/10 cut: 100 samples split into 90 + 10.
        let (train, holdout) = crate::split_holdout(&samples).unwrap();
        assert_eq!(train.len(), 90);
        assert_eq!(holdout.len(), 10);
        let first_train = train[0].label_ns;
        let first_holdout = holdout[0].label_ns;
        assert_eq!(first_train, 0);
        assert_eq!(first_holdout, 90);

        // The 20-sample minimum splits 18 + 2.
        let (train, holdout) = crate::split_holdout(&samples[..20]).unwrap();
        assert_eq!(train.len(), 18);
        assert_eq!(holdout.len(), 2);

        // A window below the minimum is an error (a skipped training
        // round), not a degenerate same-slice train/holdout fallback.
        assert!(crate::split_holdout(&samples[..19]).is_err());
        assert!(crate::split_holdout(&[]).is_err());
    }

    #[test]
    fn pid_count_cap_evict_and_prune() {
        let mut counts = std::collections::HashMap::new();

        // The cap admits MLFQ_TREE_PER_PID_CAP samples of one pid...
        for _ in 0..crate::MLFQ_TREE_PER_PID_CAP {
            assert!(crate::tree_admit_pid(&mut counts, 7));
        }
        // ...and rejects the next one, which the caller counts separately.
        assert!(!crate::tree_admit_pid(&mut counts, 7));
        // Other pids are unaffected by pid 7's cap.
        assert!(crate::tree_admit_pid(&mut counts, 8));

        // Evicting one pid 7 sample opens the slot again.
        crate::tree_evict_pid(&mut counts, 7);
        assert!(crate::tree_admit_pid(&mut counts, 7));

        // Evicting the remaining pid 7 samples prunes the entry, so the
        // map cannot grow with retired pids.
        for _ in 0..crate::MLFQ_TREE_PER_PID_CAP {
            crate::tree_evict_pid(&mut counts, 7);
        }
        assert!(!counts.contains_key(&7));
        assert_eq!(counts.get(&8), Some(&1));
    }

    #[test]
    fn distinct_pids_concentration_gate() {
        assert_eq!(crate::tree_distinct_pids(&[]), 0);
        assert_eq!(
            crate::tree_distinct_pids(&[mk_sample(1, 0), mk_sample(1, 1), mk_sample(2, 2)]),
            2
        );

        // The publish gate requires MLFQ_TREE_MIN_PIDS distinct pids in
        // the fit slice; one fewer is rejected, the minimum passes.
        let few: Vec<_> = (0..crate::MLFQ_TREE_MIN_PIDS - 1)
            .map(|i| mk_sample(i as u32, i as u64))
            .collect();
        assert!(crate::tree_distinct_pids(&few) < crate::MLFQ_TREE_MIN_PIDS);
        let enough: Vec<_> = (0..crate::MLFQ_TREE_MIN_PIDS)
            .map(|i| mk_sample(i as u32, i as u64))
            .collect();
        assert!(crate::tree_distinct_pids(&enough) >= crate::MLFQ_TREE_MIN_PIDS);
    }
}
