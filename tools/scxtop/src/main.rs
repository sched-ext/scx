// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scx_utils::compat;
use scxtop::bpf_skel::types::bpf_event;
use scxtop::cli::{generate_completions, Cli, Commands, TraceArgs, TuiArgs};
use scxtop::config::Config;
use scxtop::edm::{ActionHandler, BpfEventActionPublisher, BpfEventHandler, EventDispatchManager};
use scxtop::layered_util;
use scxtop::mangoapp::poll_mangoapp;
use scxtop::search;
use scxtop::tracer::Tracer;
use scxtop::util::{
    check_bpf_capability, get_capability_warning_message, get_clock_value, is_root,
    read_file_string,
};
use scxtop::Action;
use scxtop::App;
use scxtop::CpuStatTracker;
use scxtop::Event;
use scxtop::Key;
use scxtop::KeyMap;
use scxtop::MemStatSnapshot;
use scxtop::PerfettoTraceManager;
use scxtop::SystemStatAction;
use scxtop::Tui;
use scxtop::SCHED_NAME_PATH;
use scxtop::{available_kprobe_events, UpdateColVisibilityAction};
use scxtop::{bpf_skel::*, AppState};

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use clap::{CommandFactory, Parser};
use futures::future::join_all;
use libbpf_rs::libbpf_sys;
use libbpf_rs::num_possible_cpus;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;
use libbpf_rs::MapCore;
use libbpf_rs::ProgramInput;
use libbpf_rs::UprobeOpts;
use log::debug;
use log::info;
use ratatui::crossterm::event::{KeyCode::Char, KeyEvent};
use simplelog::{
    ColorChoice, Config as SimplelogConfig, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};
use std::ffi::CString;
use std::fs::File;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;
use tokio::sync::mpsc;

// Wrapper to make ring buffer pointer Send-safe for tokio spawn
// SAFETY: We ensure the pointer remains valid for the task lifetime
struct SendRingBuffer(*mut libbpf_sys::ring_buffer);
unsafe impl Send for SendRingBuffer {}

impl SendRingBuffer {
    fn poll(&self, timeout: i32) -> i32 {
        unsafe { libbpf_sys::ring_buffer__poll(self.0, timeout) }
    }

    fn consume(&self) -> i32 {
        unsafe { libbpf_sys::ring_buffer__consume(self.0) }
    }

    fn free(self) {
        unsafe { libbpf_sys::ring_buffer__free(self.0) }
    }
}

fn get_action(app: &App, keymap: &KeyMap, event: Event) -> Action {
    match event {
        Event::Error => Action::None,
        Event::Tick => Action::Tick,
        Event::TickRateChange(tick_rate_ms) => {
            Action::TickRateChange(std::time::Duration::from_millis(tick_rate_ms))
        }
        Event::Key(key) => handle_key_event(app, keymap, key),
        Event::Paste(paste) => handle_input_entry(app, paste).unwrap_or(Action::None),
        _ => Action::None,
    }
}

fn handle_key_event(app: &App, keymap: &KeyMap, key: KeyEvent) -> Action {
    match key.code {
        Char(c) => {
            // Check if we should handle this character as input for filtering
            if let Some(action) = handle_input_entry(app, c.to_string()) {
                action
            } else {
                // Check for state-specific key bindings before falling back to global keymap
                match (app.state(), c) {
                    // In BPF program detail view, 'p' toggles perf sampling
                    (AppState::BpfProgramDetail, 'p') => Action::ToggleBpfPerfSampling,
                    // Fall back to global keymap for all other cases
                    _ => keymap.action(&Key::Char(c)),
                }
            }
        }
        _ => keymap.action(&Key::Code(key.code)),
    }
}

fn handle_input_entry(app: &App, s: String) -> Option<Action> {
    match app.state() {
        AppState::PerfEvent | AppState::KprobeEvent => Some(Action::InputEntry(s)),
        AppState::Default
        | AppState::Llc
        | AppState::Node
        | AppState::Process
        | AppState::Memory
        | AppState::PerfTop
        | AppState::BpfPrograms
            if app.filtering() =>
        {
            Some(Action::InputEntry(s))
        }
        _ => None,
    }
}

/// Attaches BPF programs to the skel, handling non-root scenarios gracefully
fn attach_progs(skel: &mut BpfSkel) -> Result<(Vec<Link>, Vec<String>)> {
    attach_progs_selective(skel, &[])
}

/// Attaches specified BPF programs to the skel
/// If program_names is empty, attaches all programs
fn attach_progs_selective(
    skel: &mut BpfSkel,
    program_names: &[&str],
) -> Result<(Vec<Link>, Vec<String>)> {
    let mut links = Vec::new();
    let mut warnings = Vec::new();

    // Check capabilities before attempting to attach
    let has_bpf_cap = check_bpf_capability();

    if !has_bpf_cap {
        warnings
            .push("BPF programs cannot be attached - scheduler monitoring disabled".to_string());
        warnings.push("Try running as root or configure BPF permissions".to_string());
        return Ok((links, warnings));
    }

    let attach_all = program_names.is_empty();

    // Helper function to check if a program should be attached
    let should_attach = |name: &str| -> bool { attach_all || program_names.contains(&name) };

    // Helper macro to safely attach programs and collect warnings
    macro_rules! safe_attach {
        ($prog:expr, $name:literal) => {
            if should_attach($name) {
                match $prog.attach() {
                    Ok(link) => {
                        links.push(link);
                    }
                    Err(e) => {
                        if is_root() {
                            // If running as root and still failing, it's a real error
                            return Err(anyhow!(
                                "Failed to attach {} (running as root): {}",
                                $name,
                                e
                            ));
                        } else {
                            warnings.push(format!("Failed to attach {}: {}", $name, e));
                        }
                    }
                }
            }
        };
    }

    // Try to attach core scheduler probes
    safe_attach!(skel.progs.on_sched_cpu_perf, "sched_cpu_perf");
    safe_attach!(skel.progs.scx_sched_reg, "scx_sched_reg");
    safe_attach!(skel.progs.scx_sched_unreg, "scx_sched_unreg");
    safe_attach!(skel.progs.on_sched_switch, "on_sched_switch");
    safe_attach!(skel.progs.on_sched_wakeup, "on_sched_wakeup");
    safe_attach!(skel.progs.on_sched_wakeup_new, "sched_wakeup_new");
    safe_attach!(skel.progs.on_sched_waking, "on_sched_waking");
    safe_attach!(skel.progs.on_sched_migrate_task, "on_sched_migrate_task");
    safe_attach!(skel.progs.on_sched_fork, "sched_fork");
    safe_attach!(skel.progs.on_sched_exec, "sched_exec");
    safe_attach!(skel.progs.on_sched_exit, "sched_exit");

    // 6.13 compatibility probes
    if compat::ksym_exists("scx_bpf_dsq_insert_vtime")? {
        safe_attach!(skel.progs.scx_insert_vtime, "scx_insert_vtime");
        safe_attach!(skel.progs.scx_insert, "scx_insert");
        safe_attach!(skel.progs.scx_dsq_move, "scx_dsq_move");
        safe_attach!(skel.progs.scx_dsq_move_set_vtime, "scx_dsq_move_set_vtime");
        safe_attach!(skel.progs.scx_dsq_move_set_slice, "scx_dsq_move_set_slice");
    } else {
        safe_attach!(skel.progs.scx_dispatch, "scx_dispatch");
        safe_attach!(skel.progs.scx_dispatch_vtime, "scx_dispatch_vtime");
        safe_attach!(
            skel.progs.scx_dispatch_from_dsq_set_vtime,
            "scx_dispatch_from_dsq_set_vtime"
        );
        safe_attach!(
            skel.progs.scx_dispatch_from_dsq_set_slice,
            "scx_dispatch_from_dsq_set_slice"
        );
        safe_attach!(skel.progs.scx_dispatch_from_dsq, "scx_dispatch_from_dsq");
    }

    // Optional probes
    safe_attach!(skel.progs.on_cpuhp_enter, "cpuhp_enter");
    safe_attach!(skel.progs.on_cpuhp_exit, "cpuhp_exit");
    safe_attach!(skel.progs.on_softirq_entry, "on_softirq_entry");
    safe_attach!(skel.progs.on_softirq_exit, "on_softirq_exit");

    // If no links were successfully attached and we're not root, provide helpful guidance
    if links.is_empty() && !is_root() {
        warnings.extend(get_capability_warning_message());
    }

    Ok((links, warnings))
}

fn run_trace(trace_args: &TraceArgs) -> Result<()> {
    // Trace function always requires root privileges
    if !is_root() {
        return Err(anyhow!(
            "Trace functionality requires root privileges. Please run as root"
        ));
    }

    TermLogger::init(
        match trace_args.verbose {
            0 => simplelog::LevelFilter::Info,
            1 => simplelog::LevelFilter::Debug,
            _ => simplelog::LevelFilter::Trace,
        },
        SimplelogConfig::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let mut kprobe_events = available_kprobe_events()?;
    kprobe_events.sort();
    search::sorted_contains_all(&kprobe_events, &trace_args.kprobes)
        .then_some(())
        .ok_or_else(|| anyhow!("Invalid kprobe events"))?;

    let config = Config::default_config();
    let worker_threads = config.worker_threads() as usize;

    // Calculate how many ringbuffers we'll need to ensure enough worker threads
    let num_cpus = num_possible_cpus()?;
    let rb_cnt = scxtop::topology::calculate_default_ringbuf_count(num_cpus);

    // Ensure we have at least rb_cnt + 4 worker threads
    // (+4 for trace generation, stats, and other async tasks)
    let required_threads = std::cmp::max(rb_cnt + 4, worker_threads);

    info!(
        "Creating tokio runtime with {} worker threads for {} ringbuffers",
        required_threads, rb_cnt
    );

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(required_threads)
        .build()
        .unwrap()
        .block_on(async {
            let (action_tx, mut action_rx) = mpsc::unbounded_channel();

            // Set up the BPF skel and publisher
            let mut open_object = MaybeUninit::uninit();
            let mut builder = BpfSkelBuilder::default();
            if trace_args.verbose > 2 {
                builder.obj_builder.debug(true);
            }

            let mut skel = builder.open(&mut open_object)?;
            compat::cond_kprobe_enable("gpu_memory_total", &skel.progs.on_gpu_memory_total)?;
            compat::cond_kprobe_enable("hw_pressure_update", &skel.progs.on_hw_pressure_update)?;
            compat::cond_tracepoint_enable("sched:sched_process_wait", &skel.progs.on_sched_wait)?;
            compat::cond_tracepoint_enable("sched:sched_process_hang", &skel.progs.on_sched_hang)?;

            // Set up multiple ringbuffers for scalability
            let num_cpus = num_possible_cpus()?;
            let rb_cnt = scxtop::topology::calculate_default_ringbuf_count(num_cpus);
            let rb_cpu_mapping = scxtop::topology::setup_cpu_to_ringbuf_mapping(rb_cnt, num_cpus)?;

            log::info!("Using {} ringbuffers for {} CPUs", rb_cnt, num_cpus);

            // Set up CPU-to-ringbuffer mapping in BPF
            let cpu_cnt_pow2 = num_cpus.next_power_of_two();
            skel.maps.rodata_data.as_mut().unwrap().rb_cpu_map_mask = (cpu_cnt_pow2 - 1) as u64;

            // Set max entries for the CPU-to-ringbuf map array
            skel.maps
                .data_rb_cpu_map
                .set_max_entries(cpu_cnt_pow2 as u32)?;

            // Set max entries for events hash-of-maps
            skel.maps.events.set_max_entries(rb_cnt as u32)?;

            // Load the BPF skeleton (no graceful handling for trace mode - requires root)
            let mut skel = skel.load()?;

            // Populate the CPU-to-ringbuffer mapping after loading
            for (cpu_id, &rb_id) in rb_cpu_mapping.iter().enumerate() {
                if cpu_id < cpu_cnt_pow2 {
                    skel.maps.data_rb_cpu_map.update(
                        &(cpu_id as u32).to_ne_bytes(),
                        &rb_id.to_ne_bytes(),
                        libbpf_rs::MapFlags::ANY,
                    )?;
                }
            }

            skel.maps.data_data.as_mut().unwrap().enable_bpf_events = false;

            // Attach programs (no graceful handling for trace mode - requires root)
            let mut links = vec![
                skel.progs.on_sched_cpu_perf.attach()?,
                skel.progs.scx_sched_reg.attach()?,
                skel.progs.scx_sched_unreg.attach()?,
                skel.progs.on_sched_switch.attach()?,
                skel.progs.on_sched_wakeup.attach()?,
                skel.progs.on_sched_wakeup_new.attach()?,
                skel.progs.on_sched_waking.attach()?,
                skel.progs.on_sched_migrate_task.attach()?,
                skel.progs.on_sched_fork.attach()?,
                skel.progs.on_sched_exec.attach()?,
                skel.progs.on_sched_exit.attach()?,
            ];

            // 6.13 compatibility
            if compat::ksym_exists("scx_bpf_dsq_insert_vtime")? {
                if let Ok(link) = skel.progs.scx_insert_vtime.attach() {
                    links.push(link);
                }
                if let Ok(link) = skel.progs.scx_insert.attach() {
                    links.push(link);
                }
                if let Ok(link) = skel.progs.scx_dsq_move.attach() {
                    links.push(link);
                }
                if let Ok(link) = skel.progs.scx_dsq_move_set_vtime.attach() {
                    links.push(link);
                }
                if let Ok(link) = skel.progs.scx_dsq_move_set_slice.attach() {
                    links.push(link);
                }
            } else {
                if let Ok(link) = skel.progs.scx_dispatch.attach() {
                    links.push(link);
                }
                if let Ok(link) = skel.progs.scx_dispatch_vtime.attach() {
                    links.push(link);
                }
                if let Ok(link) = skel.progs.scx_dispatch_from_dsq_set_vtime.attach() {
                    links.push(link);
                }
                if let Ok(link) = skel.progs.scx_dispatch_from_dsq_set_slice.attach() {
                    links.push(link);
                }
                if let Ok(link) = skel.progs.scx_dispatch_from_dsq.attach() {
                    links.push(link);
                }
            }
            if let Ok(link) = skel.progs.on_cpuhp_enter.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.on_cpuhp_exit.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.on_softirq_entry.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.on_softirq_exit.attach() {
                links.push(link);
            }

            // Counter for events dropped due to invalid timestamps (userspace filtering)
            let dropped_invalid_ts = Arc::new(std::sync::atomic::AtomicU64::new(0));

            // Create shutdown flag early so it can be used in ringbuffer callbacks
            let shutdown = Arc::new(AtomicBool::new(false));

            // Create multiple ringbuffers and add them to the hash-of-maps
            let events_map_fd = skel.maps.events.as_fd().as_raw_fd();
            let mut rb_fds = Vec::new();
            let mut rb_managers: Vec<SendRingBuffer> = Vec::new();

            for rb_id in 0..rb_cnt {
                // Create individual ringbuffer (size must be power of 2)
                let rb_fd = unsafe {
                    libbpf_sys::bpf_map_create(
                        libbpf_sys::BPF_MAP_TYPE_RINGBUF,
                        std::ptr::null(),
                        0,
                        0,
                        (32 * 1024 * 1024) as u32, // 32MB per ringbuffer (must be power of 2)
                        std::ptr::null(),
                    )
                };

                if rb_fd < 0 {
                    bail!(
                        "Failed to create ringbuffer #{}: {}",
                        rb_id,
                        std::io::Error::last_os_error()
                    );
                }

                // Add ringbuffer to hash-of-maps
                let rb_id_u32 = rb_id as u32;
                let ret = unsafe {
                    libbpf_sys::bpf_map_update_elem(
                        events_map_fd,
                        &rb_id_u32 as *const u32 as *const std::ffi::c_void,
                        &rb_fd as *const i32 as *const std::ffi::c_void,
                        libbpf_sys::BPF_NOEXIST.into(),
                    )
                };

                if ret < 0 {
                    bail!(
                        "Failed to add ringbuffer #{} to hash-of-maps: {}",
                        rb_id,
                        std::io::Error::last_os_error()
                    );
                }

                rb_fds.push(rb_fd);
            }

            // Set up ring buffer managers using raw libbpf C API
            // We use the C API because we're creating ringbuffers dynamically
            struct RingBufContext {
                dropped_invalid_ts: Arc<std::sync::atomic::AtomicU64>,
                action_tx: mpsc::UnboundedSender<Action>,
                shutdown: Arc<AtomicBool>,
            }

            extern "C" fn ring_buffer_sample_callback(
                ctx: *mut std::ffi::c_void,
                data: *mut std::ffi::c_void,
                size: u64,
            ) -> std::ffi::c_int {
                unsafe {
                    let ctx = &*(ctx as *const RingBufContext);

                    // Stop processing if shutdown requested
                    if ctx.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                        return 0;
                    }

                    let data_slice = std::slice::from_raw_parts(data as *const u8, size as usize);

                    let mut event = bpf_event::default();
                    if plain::copy_from_bytes(&mut event, data_slice).is_err() {
                        return 0;
                    }

                    // Drop events with invalid timestamps
                    if event.ts == 0 {
                        ctx.dropped_invalid_ts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return 0;
                    }

                    let mut edm = EventDispatchManager::new(None, None);
                    edm.register_bpf_handler(Box::new(BpfEventActionPublisher::new(
                        ctx.action_tx.clone(),
                    )));
                    let _ = edm.on_event(&event);
                }
                0
            }

            for rb_fd in &rb_fds {
                let ctx = Box::new(RingBufContext {
                    dropped_invalid_ts: dropped_invalid_ts.clone(),
                    action_tx: action_tx.clone(),
                    shutdown: shutdown.clone(),
                });
                let ctx_ptr = Box::into_raw(ctx) as *mut std::ffi::c_void;

                let rb_ptr = unsafe {
                    libbpf_sys::ring_buffer__new(
                        *rb_fd,
                        Some(ring_buffer_sample_callback),
                        ctx_ptr,
                        std::ptr::null(),
                    )
                };

                if rb_ptr.is_null() {
                    unsafe {
                        let _ = Box::from_raw(ctx_ptr as *mut RingBufContext);
                    }
                    bail!("Failed to create ring buffer manager");
                }

                rb_managers.push(SendRingBuffer(rb_ptr));
            }

            // Set up the background threads to poll all ringbuffers
            let stop_poll = shutdown.clone();
            let stop_stats = shutdown.clone();

            let mut ringbuffer_handles = Vec::new();
            let mut producer_handles = Vec::new();

            // Spawn a separate blocking task for each ringbuffer
            // Use spawn_blocking because rb.poll() is a blocking C FFI call
            for (rb_id, rb) in rb_managers.into_iter().enumerate() {
                let stop_poll_clone = stop_poll.clone();
                ringbuffer_handles.push(tokio::task::spawn_blocking(move || {
                    info!("ringbuffer #{} task started", rb_id);
                    let mut poll_count = 0;
                    loop {
                        // Poll with 1ms timeout (blocking call)
                        rb.poll(1);
                        poll_count += 1;
                        if stop_poll_clone.load(Ordering::Relaxed) {
                            info!(
                                "ringbuffer #{} received shutdown after {} polls",
                                rb_id, poll_count
                            );
                            // Consume remaining events
                            let consumed = rb.consume();
                            info!("ringbuffer #{} consumed {} events", rb_id, consumed);
                            // Free the ring buffer
                            rb.free();
                            info!("ringbuffer #{} freed", rb_id);
                            break;
                        }
                    }
                    info!("ringbuffer #{} exiting", rb_id);
                }));
            }
            info!(
                "spawned {} ringbuffer polling tasks",
                ringbuffer_handles.len()
            );

            if trace_args.system_stats {
                let mut cpu_stat_tracker = CpuStatTracker::default();
                let mut mem_stats = MemStatSnapshot::default();
                let mut system = System::new_all();
                let action_tx_clone = action_tx.clone();

                producer_handles.push(tokio::spawn(async move {
                    info!("stats task started");
                    let mut stats_count = 0;
                    loop {
                        if stop_stats.load(Ordering::Relaxed) {
                            info!("stats task received shutdown after {} samples", stats_count);
                            break;
                        }
                        let ts = get_clock_value(libc::CLOCK_BOOTTIME);

                        cpu_stat_tracker
                            .update(&mut system)
                            .expect("Failed to update cpu stats");

                        mem_stats.update().expect("Failed to update mem stats");

                        let sys_stat_action = Action::SystemStat(SystemStatAction {
                            ts,
                            cpu_data_prev: cpu_stat_tracker.prev.clone(),
                            cpu_data_current: cpu_stat_tracker.current.clone(),
                            mem_info: mem_stats.clone(),
                        });
                        action_tx_clone
                            .send(sys_stat_action)
                            .expect("Failed to send CpuStat action");

                        stats_count += 1;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    info!("stats task exiting");
                }));
            }

            let trace_file_prefix = config.trace_file_prefix().to_string();
            let trace_file = trace_args.output_file.clone();
            let mut trace_manager = PerfettoTraceManager::new(trace_file_prefix, None);

            info!("starting trace for {}ms", trace_args.trace_ms);
            trace_manager.start()?;
            let mut tracer = Tracer::new(skel);
            tracer.trace(&trace_args.kprobes)?;

            let shutdown_trace = shutdown.clone();
            let trace_handle = tokio::spawn(async move {
                debug!("trace generation task started");
                let mut count = 0;
                let mut last_log = std::time::Instant::now();
                loop {
                    tokio::select! {
                        // Check shutdown flag to stop early if requested
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {
                            if shutdown_trace.load(Ordering::Relaxed) {
                                info!("trace task: shutdown requested, draining remaining events");
                                // Drain remaining events in the channel
                                while let Ok(a) = action_rx.try_recv() {
                                    count += 1;
                                    trace_manager
                                        .on_action(&a)
                                        .expect("Action should have been resolved");
                                }
                                info!("trace task: stopping trace manager");
                                trace_manager.stop(trace_file, None).unwrap();
                                info!("trace file compiled, collected {count} events");
                                break;
                            }
                        }
                        action = action_rx.recv() => {
                            if let Some(a) = action {
                                count += 1;
                                if last_log.elapsed() > std::time::Duration::from_secs(1) {
                                    debug!("trace task: {} events processed", count);
                                    last_log = std::time::Instant::now();
                                }
                                trace_manager
                                    .on_action(&a)
                                    .expect("Action should have been resolved");
                            } else {
                                info!("trace task: channel closed, stopping trace manager");
                                trace_manager.stop(trace_file, None).unwrap();
                                info!("trace file compiled, collected {count} events");
                                break;
                            }
                        }
                    }
                }
                info!("trace task: exiting");
            });

            info!("waiting for trace duration ({}ms)", trace_args.trace_ms);
            tokio::time::sleep(Duration::from_millis(trace_args.trace_ms)).await;
            info!("trace duration complete, beginning shutdown");

            // Proper shutdown sequence to avoid hanging:
            // 1) Stop new BPF events by detaching programs
            // 2) Set shutdown flag to stop polling tasks
            // 3) Wait for all ringbuffer tasks to consume remaining events and exit
            // 4) Wait for stats task to exit
            // 5) Drop action_tx to close the channel (all producers are done)
            // 6) Wait for trace generation to complete
            info!("shutdown: clearing BPF links");
            tracer.clear_links()?;
            info!("shutdown: BPF links cleared");
            drop(links);
            info!("shutdown: links dropped");

            info!("shutdown: setting shutdown flag");
            shutdown.store(true, Ordering::Relaxed);
            info!(
                "shutdown: flag set, waiting for {} ringbuffer tasks",
                ringbuffer_handles.len()
            );

            // Wait for all ringbuffer polling tasks to finish consuming
            let results = join_all(ringbuffer_handles).await;
            info!("shutdown: all {} ringbuffer tasks joined", results.len());
            for (idx, result) in results.iter().enumerate() {
                if let Err(e) = result {
                    eprintln!("Ringbuffer task {} panicked: {e}", idx);
                } else {
                    debug!("ringbuffer task {} exited successfully", idx);
                }
            }
            info!("shutdown: ringbuffer tasks complete");

            // Wait for producer tasks (stats) to complete
            info!(
                "shutdown: waiting for {} producer tasks",
                producer_handles.len()
            );
            let results = join_all(producer_handles).await;
            info!("shutdown: all {} producer tasks joined", results.len());
            for (idx, result) in results.iter().enumerate() {
                if let Err(e) = result {
                    eprintln!("Producer task {} panicked: {e}", idx);
                } else {
                    debug!("producer task {} exited successfully", idx);
                }
            }
            info!("shutdown: producer tasks complete");

            // Now safe to drop action_tx - all producers are done
            info!("shutdown: dropping action_tx");
            drop(action_tx);
            info!("shutdown: action_tx dropped, waiting for trace generation");

            // Wait for trace generation to complete
            if let Err(e) = trace_handle.await {
                eprintln!("Trace generation task panicked: {e}");
            }
            info!("shutdown: trace generation complete");

            info!("shutdown: collecting final stats");
            let stats = tracer.stats()?;
            info!("shutdown: {stats:?}");

            info!("shutdown: complete");
            Ok(())
        })
}

fn run_tui(tui_args: &TuiArgs) -> Result<()> {
    if let Ok(log_path) = std::env::var("RUST_LOG_PATH") {
        let log_level = match std::env::var("RUST_LOG") {
            Ok(v) => LevelFilter::from_str(&v)?,
            Err(_) => LevelFilter::Info,
        };

        WriteLogger::init(
            log_level,
            simplelog::Config::default(),
            File::create(log_path)?,
        )?;

        log_panics::Config::new()
            .backtrace_mode(log_panics::BacktraceMode::Resolved)
            .install_panic_hook();
    };

    let config = Config::merge([
        Config::from(tui_args.clone()),
        Config::load_or_default().expect("Failed to load config or load default config"),
    ]);
    let keymap = config.active_keymap.clone();

    // Calculate how many ringbuffers we'll need to ensure enough worker threads
    let worker_threads = config.worker_threads() as usize;
    let num_cpus = num_possible_cpus()?;
    let rb_cnt = scxtop::topology::calculate_default_ringbuf_count(num_cpus);

    // Ensure we have at least rb_cnt + 4 worker threads
    // (+4 for UI rendering, event handling, and other async tasks)
    let required_threads = std::cmp::max(rb_cnt + 4, worker_threads);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(required_threads)
        .build()
        .unwrap()
        .block_on(async {
            // Declare open_object at the very beginning so it lives for the entire async block
            let mut open_object = MaybeUninit::uninit();

            let (action_tx, mut action_rx) = mpsc::unbounded_channel();

            // Check capabilities early to determine if we can run with BPF functionality
            let has_bpf_cap = check_bpf_capability();
            let mut capability_warnings = Vec::new();
            let mut _bpf_enabled = false;
            let mut links = Vec::new();
            let mut event_rb_data_opt: Option<(
                Vec<i32>, // rb_fds
                Arc<std::sync::atomic::AtomicU64>, // dropped_invalid_ts
                mpsc::UnboundedSender<Action>, // action_tx for ringbuffer contexts
            )> = None;
            let mut skel_opt = None;

            if has_bpf_cap {
                // Try to initialize BPF components
                let mut builder = BpfSkelBuilder::default();
                if config.debug() {
                    builder.obj_builder.debug(true);
                }
                let bpf_publisher = BpfEventActionPublisher::new(action_tx.clone());
                let mut edm = EventDispatchManager::new(None, None);
                edm.register_bpf_handler(Box::new(bpf_publisher));

                // Try to open the BPF skeleton with graceful error handling
                match builder.open(&mut open_object) {
                    Ok(mut skel) => {
                        skel.maps.rodata_data.as_mut().unwrap().long_tail_tracing_min_latency_ns =
                            tui_args.experimental_long_tail_tracing_min_latency_ns;

                        let _map_handle = if tui_args.layered {
                            skel.maps.rodata_data.as_mut().unwrap().layered = true;
                            action_tx.send(Action::UpdateColVisibility(UpdateColVisibilityAction {
                                table: "Process".to_string(),
                                col: "Layer ID".to_string(),
                                visible: true,
                            }))?;
                            action_tx.send(Action::UpdateColVisibility(UpdateColVisibilityAction {
                                table: "Thread".to_string(),
                                col: "Layer ID".to_string(),
                                visible: true,
                            }))?;
                            match layered_util::attach_to_existing_map("task_ctxs", &mut skel.maps.task_ctxs) {
                                Ok(handle) => Some(handle),
                                Err(e) => {
                                    capability_warnings.push(format!("Failed to attach to layered map: {e}"));
                                    None
                                }
                            }
                        } else {
                            None
                        };

                        // Set up multiple ringbuffers for scalability
                        let num_cpus = num_possible_cpus()?;
                        let rb_cnt = scxtop::topology::calculate_default_ringbuf_count(num_cpus);
                        let rb_cpu_mapping = scxtop::topology::setup_cpu_to_ringbuf_mapping(rb_cnt, num_cpus)?;

                        log::info!("Using {} ringbuffers for {} CPUs", rb_cnt, num_cpus);

                        // Set up CPU-to-ringbuffer mapping in BPF
                        let cpu_cnt_pow2 = num_cpus.next_power_of_two();
                        skel.maps.rodata_data.as_mut().unwrap().rb_cpu_map_mask = (cpu_cnt_pow2 - 1) as u64;

                        // Set max entries for the CPU-to-ringbuf map array
                        if let Err(e) = skel.maps.data_rb_cpu_map.set_max_entries(cpu_cnt_pow2 as u32) {
                            capability_warnings.push(format!("Failed to set CPU-to-ringbuf map size: {e}"));
                        }

                        // Set max entries for events hash-of-maps
                        if let Err(e) = skel.maps.events.set_max_entries(rb_cnt as u32) {
                            capability_warnings.push(format!("Failed to set ringbuf count: {e}"));
                        }

                        if let Err(e) = compat::cond_kprobe_enable("gpu_memory_total", &skel.progs.on_gpu_memory_total) {
                            capability_warnings.push(format!("Failed to enable gpu_memory_total kprobe: {e}"));
                        }
                        if let Err(e) = compat::cond_kprobe_enable("hw_pressure_update", &skel.progs.on_hw_pressure_update) {
                            capability_warnings.push(format!("Failed to enable hw_pressure_update kprobe: {e}"));
                        }
                        if let Err(e) = compat::cond_tracepoint_enable("sched:sched_process_wait", &skel.progs.on_sched_wait) {
                            capability_warnings.push(format!("Failed to enable sched_process_wait tracepoint: {e}"));
                        }
                        if let Err(e) = compat::cond_tracepoint_enable("sched:sched_process_hang", &skel.progs.on_sched_hang) {
                            capability_warnings.push(format!("Failed to enable sched_process_hang tracepoint: {e}"));
                        }

                        // Try to load the BPF skeleton
                        match skel.load() {
                            Ok(mut loaded_skel) => {
                                // Populate the CPU-to-ringbuffer mapping after loading
                                for (cpu_id, &rb_id) in rb_cpu_mapping.iter().enumerate() {
                                    if cpu_id < cpu_cnt_pow2 {
                                        if let Err(e) = loaded_skel.maps.data_rb_cpu_map.update(
                                            &(cpu_id as u32).to_ne_bytes(),
                                            &rb_id.to_ne_bytes(),
                                            libbpf_rs::MapFlags::ANY,
                                        ) {
                                            capability_warnings.push(format!("Failed to set CPU {} -> ringbuf {}: {}", cpu_id, rb_id, e));
                                        }
                                    }
                                }

                                let (skel_links, attach_warnings) = attach_progs(&mut loaded_skel)?;
                                links = skel_links;
                                capability_warnings.extend(attach_warnings);

                                if !links.is_empty() || is_root() {
                                    // Only run scxtop_init if we have some BPF functionality
                                    if let Err(e) = loaded_skel.progs.scxtop_init.test_run(ProgramInput::default()) {
                                        capability_warnings.push(format!("Failed to initialize scxtop BPF program: {e}"));
                                    }
                                }

                                // Set up event ring buffer if we have any attached programs
                                if !links.is_empty() {
                                    // Counter for events dropped due to invalid timestamps (userspace filtering)
                                    let dropped_invalid_ts = Arc::new(std::sync::atomic::AtomicU64::new(0));

                                    // Create multiple ringbuffers and add them to the hash-of-maps
                                    let events_map_fd = loaded_skel.maps.events.as_fd().as_raw_fd();
                                    let mut rb_fds = Vec::new();

                                    for rb_id in 0..rb_cnt {
                                        // Create individual ringbuffer (size must be power of 2)
                                        let rb_fd = unsafe {
                                            libbpf_sys::bpf_map_create(
                                                libbpf_sys::BPF_MAP_TYPE_RINGBUF,
                                                std::ptr::null(),
                                                0,
                                                0,
                                                (32 * 1024 * 1024) as u32, // 32MB per ringbuffer (must be power of 2)
                                                std::ptr::null(),
                                            )
                                        };

                                        if rb_fd < 0 {
                                            capability_warnings.push(format!("Failed to create ringbuffer #{}: {}", rb_id, std::io::Error::last_os_error()));
                                            continue;
                                        }

                                        // Add ringbuffer to hash-of-maps
                                        let rb_id_u32 = rb_id as u32;
                                        let ret = unsafe {
                                            libbpf_sys::bpf_map_update_elem(
                                                events_map_fd,
                                                &rb_id_u32 as *const u32 as *const std::ffi::c_void,
                                                &rb_fd as *const i32 as *const std::ffi::c_void,
                                                libbpf_sys::BPF_NOEXIST.into(),
                                            )
                                        };

                                        if ret < 0 {
                                            capability_warnings.push(format!("Failed to add ringbuffer #{} to hash-of-maps: {}", rb_id, std::io::Error::last_os_error()));
                                            continue;
                                        }

                                        rb_fds.push(rb_fd);
                                    }

                                    if !rb_fds.is_empty() {
                                        // Save data for later ringbuffer manager creation (after app is created)
                                        event_rb_data_opt = Some((rb_fds, dropped_invalid_ts, action_tx.clone()));
                                        _bpf_enabled = true;
                                    }
                                }

                                skel_opt = Some(loaded_skel);
                            }
                            Err(e) => {
                                if is_root() {
                                    return Err(anyhow!("Failed to load BPF skeleton (running as root): {e}"));
                                } else {
                                    capability_warnings.push(format!("Failed to load BPF skeleton: {e}"));
                                    capability_warnings.extend(get_capability_warning_message());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if is_root() {
                            return Err(anyhow!("Failed to open BPF skeleton (running as root): {e}"));
                        } else {
                            capability_warnings.push(format!("Failed to open BPF skeleton: {e}"));
                            capability_warnings.extend(get_capability_warning_message());
                        }
                    }
                }
            } else {
                // No BPF capabilities detected
                capability_warnings.extend(get_capability_warning_message());
            }

            // Handle experimental long tail tracing if enabled and we have a skeleton
            if tui_args.experimental_long_tail_tracing {
                if let Some(ref mut skel) = skel_opt {
                    skel.maps.data_data.as_mut().unwrap().trace_duration_ns = config.trace_duration_ns();
                    skel.maps.data_data.as_mut().unwrap().trace_warmup_ns = config.trace_warmup_ns();

                    let binary = tui_args
                        .experimental_long_tail_tracing_binary
                        .clone()
                        .unwrap();
                    let symbol = tui_args
                        .experimental_long_tail_tracing_symbol
                        .clone()
                        .unwrap();

                    match skel.progs.long_tail_tracker_exit.attach_uprobe_with_opts(
                        -1, /* pid, -1 == all */
                        binary.clone(),
                        0,
                        UprobeOpts {
                            retprobe: true,
                            func_name: Some(symbol.clone()),
                            ..Default::default()
                        },
                    ) {
                        Ok(link) => links.push(link),
                        Err(e) => capability_warnings.push(format!("Failed to attach long tail tracker exit: {e}"))
                    }

                    match skel.progs.long_tail_tracker_entry.attach_uprobe_with_opts(
                        -1, /* pid, -1 == all */
                        binary.clone(),
                        0,
                        UprobeOpts {
                            retprobe: false,
                            func_name: Some(symbol.clone()),
                            ..Default::default()
                        },
                    ) {
                        Ok(link) => links.push(link),
                        Err(e) => capability_warnings.push(format!("Failed to attach long tail tracker entry: {e}"))
                    }
                } else {
                    capability_warnings.push("Long tail tracing requested but BPF skeleton not available".to_string());
                }
            }

            let mut tui = Tui::new(keymap.clone(), config.tick_rate_ms(), config.frame_rate_ms())?;
            let scheduler = read_file_string(SCHED_NAME_PATH).unwrap_or("".to_string());

            // Create app with or without BPF skeleton
            let mut app = if let Some(skel) = skel_opt {
                App::new(
                    config,
                    scheduler,
                    100,
                    tui_args.process_id,
                    tui_args.layered,
                    action_tx.clone(),
                    skel,
                )?
            } else {
                // Create app without BPF functionality
                App::new_without_bpf(
                    config,
                    scheduler,
                    100,
                    tui_args.process_id,
                    tui_args.layered,
                    action_tx.clone(),
                )?
            };

            // Pass warnings to the app if any exist
            if !capability_warnings.is_empty() {
                app.set_capability_warnings(capability_warnings);
            }

            tui.enter()?;

            // Start BPF event polling only if we have ringbuffer data
            let shutdown = app.should_quit.clone();
            let mut ringbuffer_handles = Vec::new();
            if let Some((rb_fds, dropped_invalid_ts, rb_action_tx)) = event_rb_data_opt {
                // Set up ring buffer managers using raw libbpf C API
                // Now that app is created, we can use app.should_quit for the callbacks
                struct RingBufContext {
                    dropped_invalid_ts: Arc<std::sync::atomic::AtomicU64>,
                    action_tx: mpsc::UnboundedSender<Action>,
                    shutdown: Arc<AtomicBool>,
                }

                extern "C" fn ring_buffer_sample_callback(
                    ctx: *mut std::ffi::c_void,
                    data: *mut std::ffi::c_void,
                    size: u64,
                ) -> std::ffi::c_int {
                    unsafe {
                        let ctx = &*(ctx as *const RingBufContext);

                        // Stop processing if shutdown requested
                        if ctx.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                            return 0;
                        }

                        let data_slice = std::slice::from_raw_parts(data as *const u8, size as usize);

                        let mut event = bpf_event::default();
                        if plain::copy_from_bytes(&mut event, data_slice).is_err() {
                            return 0;
                        }

                        // Drop events with invalid timestamps
                        if event.ts == 0 {
                            ctx.dropped_invalid_ts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return 0;
                        }

                        let mut edm = EventDispatchManager::new(None, None);
                        edm.register_bpf_handler(Box::new(BpfEventActionPublisher::new(ctx.action_tx.clone())));
                        let _ = edm.on_event(&event);
                    }
                    0
                }

                // Spawn a separate task for each ringbuffer
                for rb_fd in rb_fds {
                    let ctx = Box::new(RingBufContext {
                        dropped_invalid_ts: dropped_invalid_ts.clone(),
                        action_tx: rb_action_tx.clone(),
                        shutdown: shutdown.clone(),
                    });
                    let ctx_ptr = Box::into_raw(ctx) as *mut std::ffi::c_void;

                    let rb_ptr = unsafe {
                        libbpf_sys::ring_buffer__new(
                            rb_fd,
                            Some(ring_buffer_sample_callback),
                            ctx_ptr,
                            std::ptr::null(),
                        )
                    };

                    if rb_ptr.is_null() {
                        unsafe { let _ = Box::from_raw(ctx_ptr as *mut RingBufContext); }
                        log::warn!("Failed to create ring buffer manager");
                        continue;
                    }

                    let rb = SendRingBuffer(rb_ptr);
                    let shutdown_clone = shutdown.clone();
                    let rb_id = ringbuffer_handles.len();
                    // Use spawn_blocking because rb.poll() is a blocking C FFI call
                    ringbuffer_handles.push(tokio::task::spawn_blocking(move || {
                        loop {
                            // Poll with 1ms timeout (blocking call)
                            rb.poll(1);
                            if shutdown_clone.load(Ordering::Relaxed) {
                                // Consume remaining events
                                rb.consume();
                                // Free the ring buffer
                                rb.free();
                                log::debug!("ringbuffer #{} polling stopped", rb_id);
                                break;
                            }
                        }
                    }));
                }
            }

            if tui_args.mangoapp_tracing {
                let stop_mangoapp = app.should_quit.clone();
                let mangoapp_path = CString::new(tui_args.mangoapp_path.clone()).unwrap();
                let poll_intvl_ms = tui_args.mangoapp_poll_intvl_ms;
                let tx = action_tx.clone();
                tokio::spawn(async move {
                    poll_mangoapp(
                        mangoapp_path,
                        poll_intvl_ms,
                        tx,
                        stop_mangoapp,
                    )
                    .await
                });
            }

            loop {
                tokio::select! {
                    ev = tui.next() => {
                        let ev = ev?;
                        match ev {
                            Event::Quit => { action_tx.send(Action::Quit)?; },
                            Event::Tick => action_tx.send(Action::Tick)?,
                            Event::TickRateChange(tick_rate_ms) => action_tx.send(
                                Action::TickRateChange(std::time::Duration::from_millis(tick_rate_ms)),
                            )?,
                            Event::Render => {
                                if app.should_quit.load(Ordering::Relaxed) {
                                    break;
                                }
                                if app.state() != AppState::Pause {
                                    tui.draw(|f| app.render(f).expect("Failed to render application"))?;
                                }
                            }
                            Event::Key(_) => {
                                let action = get_action(&app, &keymap, ev);
                                action_tx.send(action)?;
                            }
                            _ => {}
                    }}

                    ac = action_rx.recv() => {
                        let ac = ac.ok_or(anyhow!("actions channel closed"))?;
                        app.handle_action(&ac)?;
                    }
                }
            }
            tui.exit()?;

            // Wait for all ringbuffer tasks to finish consuming remaining events
            log::debug!("waiting for {} ringbuffer tasks to complete", ringbuffer_handles.len());
            for handle in ringbuffer_handles {
                if let Err(e) = handle.await {
                    log::error!("Ringbuffer task panicked: {e}");
                }
            }

            drop(links);

            Ok(())
        })
}

fn run_mcp(mcp_args: &scxtop::cli::McpArgs) -> Result<()> {
    use scx_utils::Topology;
    use scxtop::mcp::{events::action_to_mcp_event, McpServer, McpServerConfig};
    use std::sync::Arc;

    // Set up logging to stderr (important: not stdout, which is used for MCP protocol)
    TermLogger::init(
        match mcp_args.verbose {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        },
        SimplelogConfig::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )?;

    // Initialize topology
    let topo = Topology::new().expect("Failed to create topology");
    let topo_arc = Arc::new(topo);

    let mcp_config = McpServerConfig {
        daemon_mode: mcp_args.daemon,
        enable_logging: mcp_args.enable_logging,
    };

    if mcp_args.daemon {
        // Daemon mode: Full BPF event processing
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(4)
            .build()
            .unwrap()
            .block_on(async {
                let mut open_object = MaybeUninit::uninit();
                let (action_tx, mut action_rx) = mpsc::unbounded_channel();

                // Create shared stats for MCP server
                use scxtop::mcp::create_shared_stats;
                let shared_stats = create_shared_stats();
                let shared_stats_for_event_handler = shared_stats.clone();

                // Set up BPF
                let builder = BpfSkelBuilder::default();
                let mut skel = builder.open(&mut open_object)?;

                // Set up multiple ringbuffers for scalability
                let num_cpus = num_possible_cpus()?;
                let rb_cnt = scxtop::topology::calculate_default_ringbuf_count(num_cpus);
                let rb_cpu_mapping = scxtop::topology::setup_cpu_to_ringbuf_mapping(rb_cnt, num_cpus)?;

                log::info!("Using {} ringbuffers for {} CPUs", rb_cnt, num_cpus);

                // Set up CPU-to-ringbuffer mapping in BPF
                let cpu_cnt_pow2 = num_cpus.next_power_of_two();
                skel.maps.rodata_data.as_mut().unwrap().rb_cpu_map_mask = (cpu_cnt_pow2 - 1) as u64;

                // Set max entries for the CPU-to-ringbuf map array
                skel.maps.data_rb_cpu_map.set_max_entries(cpu_cnt_pow2 as u32)?;

                // Set max entries for events hash-of-maps
                skel.maps.events.set_max_entries(rb_cnt as u32)?;

                let mut skel = skel.load()?;

                // Populate the CPU-to-ringbuffer mapping after loading
                for (cpu_id, &rb_id) in rb_cpu_mapping.iter().enumerate() {
                    if cpu_id < cpu_cnt_pow2 {
                        skel.maps.data_rb_cpu_map.update(
                            &(cpu_id as u32).to_ne_bytes(),
                            &rb_id.to_ne_bytes(),
                            libbpf_rs::MapFlags::ANY,
                        )?;
                    }
                }

                // Create ALL analyzers BEFORE setting up event handlers
                use scxtop::mcp::{
                    WakerWakeeAnalyzer, LatencyTracker, CpuHotspotAnalyzer, MigrationAnalyzer,
                    ProcessEventHistory, DsqMonitor, EventRateMonitor, WakeupChainTracker, EventBuffer,
                    SoftirqAnalyzer,
                };
                use std::sync::Mutex;

                // 1. Waker/Wakee Analyzer
                let mut waker_wakee = WakerWakeeAnalyzer::new();
                waker_wakee.set_topology(topo_arc.clone());
                let waker_wakee_arc = Arc::new(Mutex::new(waker_wakee));

                // 2. Latency Tracker
                let latency_tracker = LatencyTracker::new(1000); // 1 second window
                let latency_tracker_arc = Arc::new(Mutex::new(latency_tracker));

                // 3. CPU Hotspot Analyzer
                let cpu_hotspot = CpuHotspotAnalyzer::new(100); // 100ms window
                let cpu_hotspot_arc = Arc::new(Mutex::new(cpu_hotspot));

                // 4. Migration Analyzer
                let migration_analyzer = MigrationAnalyzer::new(1000); // 1 second window
                let migration_analyzer_arc = Arc::new(Mutex::new(migration_analyzer));

                // 5. Process Event History
                let process_history = ProcessEventHistory::new(100); // 100 events per process
                let process_history_arc = Arc::new(Mutex::new(process_history));

                // 6. DSQ Monitor
                let dsq_monitor = DsqMonitor::new();
                let dsq_monitor_arc = Arc::new(Mutex::new(dsq_monitor));

                // 7. Event Rate Monitor
                let rate_monitor = EventRateMonitor::new(1000, 10); // 1s window, 10 baselines
                let rate_monitor_arc = Arc::new(Mutex::new(rate_monitor));

                // 8. Wakeup Chain Tracker
                let wakeup_tracker = WakeupChainTracker::new(10); // max 10 chain length
                let wakeup_tracker_arc = Arc::new(Mutex::new(wakeup_tracker));

                // 9. Event Buffer
                let event_buffer = EventBuffer::new();
                let event_buffer_arc = Arc::new(Mutex::new(event_buffer));

                // 10. Softirq Analyzer
                let softirq_analyzer = SoftirqAnalyzer::new(10000); // 10 second window
                let softirq_analyzer_arc = Arc::new(Mutex::new(softirq_analyzer));

                // Set up event dispatch manager
                let mut edm = EventDispatchManager::new(None, None);
                edm.register_bpf_handler(Box::new(BpfEventActionPublisher::new(action_tx.clone())));

                // Counter for events dropped due to invalid timestamps (userspace filtering)
                let dropped_invalid_ts = Arc::new(std::sync::atomic::AtomicU64::new(0));

                // Create shutdown flag early so it can be used in ringbuffer callbacks
                let shutdown = Arc::new(AtomicBool::new(false));

                // Create multiple ringbuffers and add them to the hash-of-maps
                let events_map_fd = skel.maps.events.as_fd().as_raw_fd();
                let mut rb_fds = Vec::new();
                let mut rb_managers: Vec<SendRingBuffer> = Vec::new();

                for rb_id in 0..rb_cnt {
                    // Create individual ringbuffer (size must be power of 2)
                    let rb_fd = unsafe {
                        libbpf_sys::bpf_map_create(
                            libbpf_sys::BPF_MAP_TYPE_RINGBUF,
                            std::ptr::null(),
                            0,
                            0,
                            (32 * 1024 * 1024) as u32, // 32MB per ringbuffer (must be power of 2)
                            std::ptr::null(),
                        )
                    };

                    if rb_fd < 0 {
                        bail!("Failed to create ringbuffer #{}: {}", rb_id, std::io::Error::last_os_error());
                    }

                    // Add ringbuffer to hash-of-maps
                    let rb_id_u32 = rb_id as u32;
                    let ret = unsafe {
                        libbpf_sys::bpf_map_update_elem(
                            events_map_fd,
                            &rb_id_u32 as *const u32 as *const std::ffi::c_void,
                            &rb_fd as *const i32 as *const std::ffi::c_void,
                            libbpf_sys::BPF_NOEXIST.into(),
                        )
                    };

                    if ret < 0 {
                        bail!("Failed to add ringbuffer #{} to hash-of-maps: {}", rb_id, std::io::Error::last_os_error());
                    }

                    rb_fds.push(rb_fd);
                }

                // Set up ring buffer managers using raw libbpf C API
                // We use the C API because we're creating ringbuffers dynamically

                // Context struct holding all the data needed by the callback
                struct McpRingBufContext {
                    dropped_invalid_ts: Arc<std::sync::atomic::AtomicU64>,
                    shared_stats: Arc<std::sync::RwLock<scxtop::mcp::SharedStats>>,
                    action_tx: mpsc::UnboundedSender<Action>,
                    waker_wakee: Arc<std::sync::Mutex<scxtop::mcp::WakerWakeeAnalyzer>>,
                    cpu_hotspot: Arc<std::sync::Mutex<scxtop::mcp::CpuHotspotAnalyzer>>,
                    migration_analyzer: Arc<std::sync::Mutex<scxtop::mcp::MigrationAnalyzer>>,
                    process_history: Arc<std::sync::Mutex<scxtop::mcp::ProcessEventHistory>>,
                    rate_monitor: Arc<std::sync::Mutex<scxtop::mcp::EventRateMonitor>>,
                    wakeup_tracker: Arc<std::sync::Mutex<scxtop::mcp::WakeupChainTracker>>,
                    softirq_analyzer: Arc<std::sync::Mutex<scxtop::mcp::SoftirqAnalyzer>>,
                    shutdown: Arc<AtomicBool>,
                }

                extern "C" fn mcp_ring_buffer_callback(
                    ctx: *mut std::ffi::c_void,
                    data: *mut std::ffi::c_void,
                    size: u64,
                ) -> std::ffi::c_int {
                    unsafe {
                        let ctx = &*(ctx as *const McpRingBufContext);

                        // Stop processing if shutdown requested
                        if ctx.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                            return 0;
                        }

                        let data_slice = std::slice::from_raw_parts(data as *const u8, size as usize);

                        let mut event = bpf_event::default();
                        if plain::copy_from_bytes(&mut event, data_slice).is_err() {
                            return 0;
                        }

                        // Drop events with invalid timestamps
                        if event.ts == 0 {
                            ctx.dropped_invalid_ts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return 0;
                        }

                        // Update shared stats from BPF event
                        if let Ok(mut stats) = ctx.shared_stats.write() {
                            stats.update_from_event(&event);
                        }

                        // Feed events to all analyzers
                        use scxtop::bpf_intf;
                        let event_type = event.r#type as u32;

                        // 1. Waker/Wakee Analyzer
                        if let Ok(mut analyzer) = ctx.waker_wakee.try_lock() {
                            match event_type {
                                bpf_intf::event_type_SCHED_WAKEUP => {
                                    let wakeup = &event.event.wakeup;
                                    analyzer.record_wakeup(
                                        wakeup.pid, wakeup.waker_pid,
                                        &String::from_utf8_lossy(&wakeup.waker_comm),
                                        event.cpu, event.ts,
                                    );
                                }
                                bpf_intf::event_type_SCHED_WAKING => {
                                    let waking = &event.event.waking;
                                    analyzer.record_wakeup(
                                        waking.pid, waking.waker_pid,
                                        &String::from_utf8_lossy(&waking.waker_comm),
                                        event.cpu, event.ts,
                                    );
                                }
                                bpf_intf::event_type_SCHED_SWITCH => {
                                    let switch = &event.event.sched_switch;
                                    analyzer.record_wakee_run(
                                        switch.next_pid,
                                        &String::from_utf8_lossy(&switch.next_comm),
                                        event.cpu, event.ts,
                                    );
                                }
                                _ => {}
                            }
                        }

                        // 2. CPU Hotspot Analyzer
                        if let Ok(mut analyzer) = ctx.cpu_hotspot.try_lock() {
                            let json = serde_json::json!({
                                "cpu": event.cpu, "ts": event.ts, "event_type": event_type
                            });
                            analyzer.record_event(&json);
                        }

                        // 3. Migration Analyzer
                        if let Ok(mut analyzer) = ctx.migration_analyzer.try_lock() {
                            if event_type == bpf_intf::event_type_SCHED_MIGRATE {
                                let migrate = &event.event.migrate;
                                let json = serde_json::json!({
                                    "pid": migrate.pid, "from_cpu": event.cpu,
                                    "to_cpu": migrate.dest_cpu, "ts": event.ts
                                });
                                analyzer.record_migration(&json, event.ts);
                            }
                        }

                        // 4. Process Event History
                        if let Ok(mut history) = ctx.process_history.try_lock() {
                            let (event_type_str, pid) = match event_type {
                                bpf_intf::event_type_SCHED_SWITCH => ("sched_switch", event.event.sched_switch.next_pid),
                                bpf_intf::event_type_SCHED_WAKEUP => ("sched_wakeup", event.event.wakeup.pid),
                                bpf_intf::event_type_SCHED_WAKING => ("sched_waking", event.event.waking.pid),
                                bpf_intf::event_type_SCHED_MIGRATE => ("sched_migrate", event.event.migrate.pid),
                                bpf_intf::event_type_EXIT => ("exit", event.event.exit.pid),
                                bpf_intf::event_type_EXEC => ("exec", event.event.exec.pid),
                                _ => ("other", 0),
                            };
                            if pid > 0 {
                                history.record_event(
                                    pid, event_type_str.to_string(), Some(event.cpu),
                                    serde_json::json!({"ts": event.ts}), event.ts,
                                );
                            }
                        }

                        // 6. Event Rate Monitor
                        if let Ok(mut monitor) = ctx.rate_monitor.try_lock() {
                            let event_type_str = match event_type {
                                bpf_intf::event_type_SCHED_SWITCH => "sched_switch",
                                bpf_intf::event_type_SCHED_WAKEUP => "sched_wakeup",
                                bpf_intf::event_type_SCHED_WAKING => "sched_waking",
                                bpf_intf::event_type_SCHED_MIGRATE => "sched_migrate",
                                _ => "other",
                            };
                            monitor.record_event(event_type_str.to_string(), event.ts);
                        }

                        // 7. Wakeup Chain Tracker
                        if let Ok(mut tracker) = ctx.wakeup_tracker.try_lock() {
                            if event_type == bpf_intf::event_type_SCHED_WAKEUP || event_type == bpf_intf::event_type_SCHED_WAKING {
                                let (pid, waker_pid) = if event_type == bpf_intf::event_type_SCHED_WAKEUP {
                                    (event.event.wakeup.pid, event.event.wakeup.waker_pid)
                                } else {
                                    (event.event.waking.pid, event.event.waking.waker_pid)
                                };
                                let json = serde_json::json!({
                                    "pid": pid, "waker_pid": waker_pid, "ts": event.ts, "cpu": event.cpu
                                });
                                tracker.record_wakeup(&json, event.ts);
                            }
                        }

                        // 8. Softirq Analyzer
                        if let Ok(mut analyzer) = ctx.softirq_analyzer.try_lock() {
                            if event_type == bpf_intf::event_type_SOFTIRQ {
                                let softirq = &event.event.softirq;
                                let json = serde_json::json!({
                                    "type": "softirq", "pid": softirq.pid, "softirq_nr": softirq.softirq_nr,
                                    "entry_ts": softirq.entry_ts, "exit_ts": softirq.exit_ts, "cpu": event.cpu,
                                });
                                analyzer.record_event(&json);
                            }
                        }

                        // Dispatch to action channel
                        let mut edm = EventDispatchManager::new(None, None);
                        edm.register_bpf_handler(Box::new(BpfEventActionPublisher::new(ctx.action_tx.clone())));
                        let _ = edm.on_event(&event);
                    }
                    0
                }

                for rb_fd in &rb_fds {
                    let ctx = Box::new(McpRingBufContext {
                        dropped_invalid_ts: dropped_invalid_ts.clone(),
                        shared_stats: shared_stats_for_event_handler.clone(),
                        action_tx: action_tx.clone(),
                        waker_wakee: waker_wakee_arc.clone(),
                        cpu_hotspot: cpu_hotspot_arc.clone(),
                        migration_analyzer: migration_analyzer_arc.clone(),
                        process_history: process_history_arc.clone(),
                        rate_monitor: rate_monitor_arc.clone(),
                        wakeup_tracker: wakeup_tracker_arc.clone(),
                        softirq_analyzer: softirq_analyzer_arc.clone(),
                        shutdown: shutdown.clone(),
                    });
                    let ctx_ptr = Box::into_raw(ctx) as *mut std::ffi::c_void;

                    let rb_ptr = unsafe {
                        libbpf_sys::ring_buffer__new(
                            *rb_fd,
                            Some(mcp_ring_buffer_callback),
                            ctx_ptr,
                            std::ptr::null(),
                        )
                    };

                    if rb_ptr.is_null() {
                        unsafe { let _ = Box::from_raw(ctx_ptr as *mut McpRingBufContext); }
                        bail!("Failed to create ring buffer manager");
                    }

                    rb_managers.push(SendRingBuffer(rb_ptr));
                }

                // Attach BPF programs initially
                let (initial_links, _warnings) = attach_progs(&mut skel)?;

                // Initialize BPF program
                if !initial_links.is_empty() || is_root() {
                    skel.progs
                        .scxtop_init
                        .test_run(ProgramInput::default())
                        .ok();
                }

                // Create BPF perf event attacher BEFORE passing skeleton to App
                // This gives us a handle to attach perf events for profiling
                // We create a closure that captures a raw pointer to the program
                use scxtop::mcp::BpfPerfEventAttacher;
                // Get raw pointer to the perf_sample_handler program as usize to make it Send
                let perf_program_addr = &skel.progs.perf_sample_handler as *const _ as usize;

                let bpf_attacher = BpfPerfEventAttacher::new(move |perf_fd| {
                    // SAFETY: The skeleton is kept alive in the App and not dropped
                    // until the MCP server is done, so this pointer remains valid
                    unsafe {
                        // Cast back to ProgramImpl with Mut parameter
                        let prog =
                            &*(perf_program_addr as *const libbpf_rs::ProgramImpl<libbpf_rs::Mut>);
                        prog.attach_perf_event(perf_fd)
                            .map(|link| Box::new(link) as Box<dyn std::any::Any + Send>)
                            .map_err(|e| anyhow::anyhow!("Failed to attach perf event: {}", e))
                    }
                });
                let bpf_attacher_arc = Arc::new(bpf_attacher);

                // Create event control for dynamic BPF program attachment/detachment
                use scxtop::mcp::{AttachCallback, EventControl, StatsControlCommand};
                let mut event_control_instance = EventControl::new();

                // Create attach callback using skeleton pointer (similar to perf attacher)
                // SAFETY: Skeleton is kept alive in App until daemon shutdown
                let skel_ptr = &mut skel as *mut _ as usize;
                let attach_callback: AttachCallback = Box::new(move |program_names: &[&str]| {
                    unsafe {
                        let skel_ref = &mut *(skel_ptr as *mut BpfSkel);
                        attach_progs_selective(skel_ref, program_names).map(|(links, _)| links)
                    }
                });

                // Give EventControl the initial links and callback, then immediately detach
                // to start with minimal overhead
                event_control_instance.set_bpf_links(initial_links, attach_callback);
                event_control_instance.disable_event_tracking()?;
                info!("BPF programs detached by default - use control_event_tracking to enable");

                // Create stats control channel
                let (stats_tx, stats_rx) = mpsc::unbounded_channel::<StatsControlCommand>();
                event_control_instance.set_stats_control_channel(stats_tx);

                // Wrap in Arc after configuration
                let event_control = Arc::new(event_control_instance);

                // Create App (but don't use it in spawned tasks due to Send constraints)
                let config = Config::default_config();
                let scheduler =
                    read_file_string(SCHED_NAME_PATH).unwrap_or_else(|_| "".to_string());
                let mut app = App::new(
                    config,
                    scheduler,
                    100,
                    mcp_args.process_id,
                    mcp_args.layered,
                    action_tx.clone(),
                    skel,
                )?;

                // Create analyzer control and register ALL analyzers
                use scxtop::mcp::AnalyzerControl;

                let mut analyzer_control = AnalyzerControl::new();
                analyzer_control.set_event_control(event_control.clone());

                // Register all analyzers
                analyzer_control.set_event_buffer(event_buffer_arc.clone());
                analyzer_control.set_latency_tracker(latency_tracker_arc.clone());
                analyzer_control.set_cpu_hotspot_analyzer(cpu_hotspot_arc.clone());
                analyzer_control.set_migration_analyzer(migration_analyzer_arc.clone());
                analyzer_control.set_process_history(process_history_arc.clone());
                analyzer_control.set_dsq_monitor(dsq_monitor_arc.clone());
                analyzer_control.set_rate_monitor(rate_monitor_arc.clone());
                analyzer_control.set_wakeup_tracker(wakeup_tracker_arc.clone());
                analyzer_control.set_waker_wakee_analyzer(waker_wakee_arc.clone());
                analyzer_control.set_softirq_analyzer(softirq_analyzer_arc.clone());

                // Wrap analyzer control in Arc<Mutex<>>
                let analyzer_control = Arc::new(Mutex::new(analyzer_control));

                // Create trace cache for perfetto analysis
                use std::collections::HashMap;
                let trace_cache = Arc::new(Mutex::new(HashMap::new()));

                // Create MCP server
                let mut server = McpServer::new(mcp_config)
                    .with_topology(topo_arc)
                    .setup_scheduler_resource()
                    .setup_profiling_resources()
                    .with_bpf_perf_attacher(bpf_attacher_arc)
                    .with_shared_stats(shared_stats.clone())
                    .with_stats_client(None)
                    .with_event_control(event_control.clone())
                    .with_analyzer_control(analyzer_control.clone())
                    .with_trace_cache(trace_cache)
                    .setup_stats_resources();

                // Enable event streaming
                let _event_stream_rx = server.enable_event_streaming();
                let resources = server.get_resources_handle();

                // Get BPF stats collector for periodic sampling
                let bpf_stats = server.get_bpf_stats_collector();

                // Get perf profiler for stack trace collection
                let perf_profiler = server.get_perf_profiler();

                // Start BPF polling tasks - spawn a separate task for each ringbuffer
                let shutdown_poll = shutdown.clone();

                let mut ringbuffer_handles = Vec::new();
                for (rb_id, rb) in rb_managers.into_iter().enumerate() {
                    let stop_poll_clone = shutdown_poll.clone();
                    ringbuffer_handles.push(tokio::spawn(async move {
                        loop {
                            // Poll with 1ms timeout
                            rb.poll(1);
                            if stop_poll_clone.load(Ordering::Relaxed) {
                                // Consume remaining events
                                rb.consume();
                                // Free the ring buffer
                                rb.free();
                                debug!("ringbuffer #{} polling stopped", rb_id);
                                break;
                            }
                        }
                    }));
                }

                // Start controllable BPF stats collection task
                // Task responds to start/stop commands via channel, starts in stopped state
                if let Some(collector) = bpf_stats {
                    let shutdown_stats = shutdown.clone();
                    let mut stats_rx_task = stats_rx;
                    tokio::spawn(async move {
                        let mut running = false;
                        let mut interval_ms = 100u64;
                        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));

                        loop {
                            tokio::select! {
                                // Handle control commands
                                Some(cmd) = stats_rx_task.recv() => {
                                    match cmd {
                                        StatsControlCommand::Start(new_interval_ms) => {
                                            running = true;
                                            interval_ms = new_interval_ms;
                                            interval = tokio::time::interval(Duration::from_millis(interval_ms));
                                            info!("Stats collection started with {}ms interval", interval_ms);
                                        }
                                        StatsControlCommand::Stop => {
                                            running = false;
                                            info!("Stats collection stopped");
                                        }
                                    }
                                }

                                // Collect stats if running
                                _ = interval.tick(), if running => {
                                    if shutdown_stats.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    let _ = collector.collect_sample();
                                }

                                // Check shutdown even when not running
                                _ = tokio::time::sleep(Duration::from_millis(100)), if !running => {
                                    if shutdown_stats.load(Ordering::Relaxed) {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }

                info!("MCP daemon started, processing BPF events");

                // Main loop: handle both MCP server and action processing
                let mut mcp_server_task = Box::pin(server.run_async());
                let mcp_result;
                loop {
                    tokio::select! {
                        // Handle MCP server
                        result = &mut mcp_server_task => {
                            info!("MCP server exited");
                            shutdown.store(true, Ordering::Relaxed);
                            mcp_result = result;
                            break;
                        }

                        // Handle actions from BPF
                        Some(action) = action_rx.recv() => {
                            // Check for shutdown
                            if matches!(action, Action::Quit) {
                                info!("Received quit action");
                                shutdown.store(true, Ordering::Relaxed);
                                mcp_result = Ok(());
                                break;
                            }

                            // Feed perf samples to profiler if it's collecting
                            if let Some(ref profiler) = perf_profiler {
                                if let Action::PerfSample(ref perf_sample) = action {
                                    use scxtop::mcp::RawSample;
                                    profiler.add_sample(RawSample {
                                        address: perf_sample.instruction_pointer,
                                        pid: perf_sample.pid,
                                        cpu_id: perf_sample.cpu_id,
                                        is_kernel: perf_sample.is_kernel,
                                        kernel_stack: perf_sample.kernel_stack.clone(),
                                        user_stack: perf_sample.user_stack.clone(),
                                        layer_id: if perf_sample.layer_id >= 0 {
                                            Some(perf_sample.layer_id)
                                        } else {
                                            None
                                        },
                                    });
                                }
                            }

                            // Update app state
                            let _ = app.handle_action(&action);

                            // Convert action to MCP event and push to stream
                            if let Some(event) = action_to_mcp_event(&action) {
                                let _ = resources.push_event(event);
                            }
                        }
                    }
                }

                // Wait for all ringbuffer tasks to finish consuming remaining events
                debug!("waiting for {} ringbuffer tasks to complete", ringbuffer_handles.len());
                for handle in ringbuffer_handles {
                    if let Err(e) = handle.await {
                        log::error!("Ringbuffer task panicked: {e}");
                    }
                }

                // Links are managed by EventControl and will be dropped on shutdown
                mcp_result
            })
    } else {
        // One-shot mode: No BPF, just serve static data
        let mut server = McpServer::new(mcp_config)
            .with_topology(topo_arc)
            .setup_scheduler_resource()
            .setup_profiling_resources()
            .with_stats_client(None)
            .setup_stats_resources();
        server.run_blocking()
    }
}

fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command.unwrap_or(Commands::Tui(args.tui)) {
        Commands::Tui(tui_args) => {
            run_tui(tui_args)?;
        }
        Commands::Trace(trace_args) => {
            run_trace(trace_args)?;
        }
        Commands::Mcp(mcp_args) => {
            run_mcp(mcp_args)?;
        }
        Commands::GenerateCompletions { shell, output } => {
            generate_completions(Cli::command(), *shell, output.clone())
                .unwrap_or_else(|_| panic!("Failed to generate completions for {shell}"));
        }
    }
    Ok(())
}
