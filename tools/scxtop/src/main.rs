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
use anyhow::Result;
use clap::{CommandFactory, Parser};
use futures::future::join_all;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;
use libbpf_rs::ProgramInput;
use libbpf_rs::RingBufferBuilder;
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
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::System;
use tokio::sync::mpsc;

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
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(if worker_threads > 2 {
            worker_threads
        } else {
            4
        })
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

            let skel = builder.open(&mut open_object)?;
            compat::cond_kprobe_enable("gpu_memory_total", &skel.progs.on_gpu_memory_total)?;
            compat::cond_kprobe_enable("hw_pressure_update", &skel.progs.on_hw_pressure_update)?;
            compat::cond_tracepoint_enable("sched:sched_process_wait", &skel.progs.on_sched_wait)?;
            compat::cond_tracepoint_enable("sched:sched_process_hang", &skel.progs.on_sched_hang)?;

            // Load the BPF skeleton (no graceful handling for trace mode - requires root)
            let mut skel = skel.load()?;
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

            let bpf_publisher = BpfEventActionPublisher::new(action_tx.clone());

            // Set up the event buffer
            let mut event_rbb = RingBufferBuilder::new();
            let mut edm = EventDispatchManager::new(None, None);
            edm.register_bpf_handler(Box::new(bpf_publisher));
            let event_handler = move |data: &[u8]| {
                let mut event = bpf_event::default();
                plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
                let _ = edm.on_event(&event);
                0
            };
            event_rbb.add(&skel.maps.events, event_handler)?;
            let event_rb = event_rbb.build()?;

            // Set up the background threads
            let shutdown = Arc::new(AtomicBool::new(false));
            let stop_poll = shutdown.clone();
            let stop_stats = shutdown.clone();

            let mut handles = Vec::new();
            handles.push(tokio::spawn(async move {
                loop {
                    let _ = event_rb.poll(Duration::from_millis(1));
                    if stop_poll.load(Ordering::Relaxed) {
                        // Flush the ring buffer to ensure all events are processed
                        let _ = event_rb.consume();
                        debug!("polling stopped");
                        break;
                    }
                }
            }));

            if trace_args.system_stats {
                let mut cpu_stat_tracker = CpuStatTracker::default();
                let mut mem_stats = MemStatSnapshot::default();
                let mut system = System::new_all();
                let action_tx_clone = action_tx.clone();

                handles.push(tokio::spawn(async move {
                    loop {
                        if stop_stats.load(Ordering::Relaxed) {
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

                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }));
            }

            let trace_file_prefix = config.trace_file_prefix().to_string();
            let trace_file = trace_args.output_file.clone();
            let mut trace_manager = PerfettoTraceManager::new(trace_file_prefix, None);

            info!("starting trace for {}ms", trace_args.trace_ms);
            trace_manager.start()?;
            let mut tracer = Tracer::new(skel);
            tracer.trace(&trace_args.kprobes)?;

            handles.push(tokio::spawn(async move {
                let mut count = 0;
                loop {
                    let action = action_rx.recv().await;
                    if let Some(a) = action {
                        count += 1;
                        trace_manager
                            .on_action(&a)
                            .expect("Action should have been resolved");
                    } else {
                        trace_manager.stop(trace_file, None).unwrap();
                        info!("trace file compiled, collected {count} events");
                        break;
                    }
                }
            }));
            tokio::time::sleep(Duration::from_millis(trace_args.trace_ms)).await;

            // 1) set the shutdown variable to stop background tokio threads
            // 2) next, drop the links to detach the attached BPF programs
            // 3) drop the action_tx to ensure action_rx closes
            // 4) wait for the completion of the trace file generation to complete
            shutdown.store(true, Ordering::Relaxed);
            tracer.clear_links()?;
            drop(links);
            drop(action_tx);
            info!("generating trace");
            let results = join_all(handles).await;
            for result in results {
                if let Err(e) = result {
                    eprintln!("Task panicked: {e}");
                }
            }

            let stats = tracer.stats()?;
            info!("{stats:?}");

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

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(config.worker_threads() as usize)
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
            let mut event_rb_opt = None;
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
                                    let mut event_rbb = RingBufferBuilder::new();
                                    let event_handler = move |data: &[u8]| {
                                        let mut event = bpf_event::default();
                                        plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
                                        let _ = edm.on_event(&event);
                                        0
                                    };
                                    if let Err(e) = event_rbb.add(&loaded_skel.maps.events, event_handler) {
                                        capability_warnings.push(format!("Failed to add event handler: {e}"));
                                    } else {
                                        match event_rbb.build() {
                                            Ok(event_rb) => {
                                                event_rb_opt = Some(event_rb);
                                                _bpf_enabled = true;
                                            }
                                            Err(e) => {
                                                capability_warnings.push(format!("Failed to build event ring buffer: {e}"));
                                            }
                                        }
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

            // Start BPF event polling only if we have an event ring buffer
            let shutdown = app.should_quit.clone();
            if let Some(event_rb) = event_rb_opt {
                tokio::spawn(async move {
                    loop {
                        let _ = event_rb.poll(Duration::from_millis(1));
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                });
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
                let skel = builder.open(&mut open_object)?;
                let mut skel = skel.load()?;

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
                let bpf_publisher = BpfEventActionPublisher::new(action_tx.clone());
                let mut edm = EventDispatchManager::new(None, None);
                edm.register_bpf_handler(Box::new(bpf_publisher));

                // Clone all analyzers for event handler
                let waker_wakee_for_events = waker_wakee_arc.clone();
                let cpu_hotspot_for_events = cpu_hotspot_arc.clone();
                let migration_analyzer_for_events = migration_analyzer_arc.clone();
                let process_history_for_events = process_history_arc.clone();
                let rate_monitor_for_events = rate_monitor_arc.clone();
                let wakeup_tracker_for_events = wakeup_tracker_arc.clone();
                let softirq_analyzer_for_events = softirq_analyzer_arc.clone();

                // Set up ring buffer
                let mut event_rbb = RingBufferBuilder::new();
                let event_handler = move |data: &[u8]| {
                    let mut event = bpf_event::default();
                    plain::copy_from_bytes(&mut event, data)
                        .expect("Event data buffer was too short");

                    // Update shared stats from BPF event
                    if let Ok(mut stats) = shared_stats_for_event_handler.write() {
                        stats.update_from_event(&event);
                    }

                    // Feed events to all analyzers
                    use scxtop::bpf_intf;
                    let event_type = event.r#type as u32;

                    // 1. Waker/Wakee Analyzer - tracks wakeup relationships
                    if let Ok(mut analyzer) = waker_wakee_for_events.try_lock() {
                        match event_type {
                            bpf_intf::event_type_SCHED_WAKEUP => {
                                let wakeup = unsafe { &event.event.wakeup };
                                analyzer.record_wakeup(
                                    wakeup.pid,
                                    wakeup.waker_pid,
                                    &String::from_utf8_lossy(&wakeup.waker_comm),
                                    event.cpu,
                                    event.ts,
                                );
                            }
                            bpf_intf::event_type_SCHED_WAKING => {
                                let waking = unsafe { &event.event.waking };
                                analyzer.record_wakeup(
                                    waking.pid,
                                    waking.waker_pid,
                                    &String::from_utf8_lossy(&waking.waker_comm),
                                    event.cpu,
                                    event.ts,
                                );
                            }
                            bpf_intf::event_type_SCHED_SWITCH => {
                                let switch = unsafe { &event.event.sched_switch };
                                analyzer.record_wakee_run(
                                    switch.next_pid,
                                    &String::from_utf8_lossy(&switch.next_comm),
                                    event.cpu,
                                    event.ts,
                                );
                            }
                            _ => {}
                        }
                    }

                    // 2. CPU Hotspot Analyzer - tracks CPU activity
                    if let Ok(mut analyzer) = cpu_hotspot_for_events.try_lock() {
                        // Build simplified JSON for CPU hotspot tracking
                        let json = serde_json::json!({
                            "cpu": event.cpu,
                            "ts": event.ts,
                            "event_type": event_type
                        });
                        analyzer.record_event(&json);
                    }

                    // 3. Migration Analyzer - tracks process migrations
                    if let Ok(mut analyzer) = migration_analyzer_for_events.try_lock() {
                        if event_type == bpf_intf::event_type_SCHED_MIGRATE {
                            let migrate = unsafe { &event.event.migrate };
                            let json = serde_json::json!({
                                "pid": migrate.pid,
                                "from_cpu": event.cpu, // source CPU is the current CPU
                                "to_cpu": migrate.dest_cpu,
                                "ts": event.ts
                            });
                            analyzer.record_migration(&json, event.ts);
                        }
                    }

                    // 4. Process Event History - records all events per process
                    if let Ok(mut history) = process_history_for_events.try_lock() {
                        let event_type_str = match event_type {
                            bpf_intf::event_type_SCHED_SWITCH => "sched_switch",
                            bpf_intf::event_type_SCHED_WAKEUP => "sched_wakeup",
                            bpf_intf::event_type_SCHED_WAKING => "sched_waking",
                            bpf_intf::event_type_SCHED_MIGRATE => "sched_migrate",
                            bpf_intf::event_type_EXIT => "exit",
                            bpf_intf::event_type_EXEC => "exec",
                            _ => "other",
                        };

                        // Extract PID from event
                        let pid = match event_type {
                            bpf_intf::event_type_SCHED_SWITCH => unsafe { event.event.sched_switch.next_pid },
                            bpf_intf::event_type_SCHED_WAKEUP => unsafe { event.event.wakeup.pid },
                            bpf_intf::event_type_SCHED_WAKING => unsafe { event.event.waking.pid },
                            _ => 0,
                        };

                        if pid > 0 {
                            history.record_event(
                                pid,
                                event_type_str.to_string(),
                                Some(event.cpu),
                                serde_json::json!({"ts": event.ts}),
                                event.ts,
                            );
                        }
                    }

                    // 5. DSQ Monitor - tracks dispatch queue operations
                    // Note: DSQ events are scheduler-specific, only available with sched_ext schedulers

                    // 6. Event Rate Monitor - tracks event rates for anomaly detection
                    if let Ok(mut monitor) = rate_monitor_for_events.try_lock() {
                        let event_type_str = match event_type {
                            bpf_intf::event_type_SCHED_SWITCH => "sched_switch",
                            bpf_intf::event_type_SCHED_WAKEUP => "sched_wakeup",
                            bpf_intf::event_type_SCHED_WAKING => "sched_waking",
                            bpf_intf::event_type_SCHED_MIGRATE => "sched_migrate",
                            _ => "other",
                        };
                        monitor.record_event(event_type_str.to_string(), event.ts);
                    }

                    // 7. Wakeup Chain Tracker - tracks cascading wakeup chains
                    if let Ok(mut tracker) = wakeup_tracker_for_events.try_lock() {
                        if event_type == bpf_intf::event_type_SCHED_WAKEUP {
                            let wakeup = unsafe { &event.event.wakeup };
                            let json = serde_json::json!({
                                "pid": wakeup.pid,
                                "waker_pid": wakeup.waker_pid,
                                "ts": event.ts,
                                "cpu": event.cpu
                            });
                            tracker.record_wakeup(&json, event.ts);
                        } else if event_type == bpf_intf::event_type_SCHED_WAKING {
                            let waking = unsafe { &event.event.waking };
                            let json = serde_json::json!({
                                "pid": waking.pid,
                                "waker_pid": waking.waker_pid,
                                "ts": event.ts,
                                "cpu": event.cpu
                            });
                            tracker.record_wakeup(&json, event.ts);
                        }
                    }

                    // Note: Latency Tracker is updated by shared_stats which already handles it above

                    // 8. Softirq Analyzer - tracks software interrupt processing
                    if let Ok(mut analyzer) = softirq_analyzer_for_events.try_lock() {
                        if event_type == bpf_intf::event_type_SOFTIRQ {
                            let softirq = unsafe { &event.event.softirq };
                            let json = serde_json::json!({
                                "type": "softirq",
                                "pid": softirq.pid,
                                "softirq_nr": softirq.softirq_nr,
                                "entry_ts": softirq.entry_ts,
                                "exit_ts": softirq.exit_ts,
                                "cpu": event.cpu,
                            });
                            analyzer.record_event(&json);
                        }
                    }

                    let _ = edm.on_event(&event);
                    0
                };
                event_rbb.add(&skel.maps.events, event_handler)?;
                let event_rb = event_rbb.build()?;

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

                // Start BPF polling task
                let shutdown = Arc::new(AtomicBool::new(false));
                let shutdown_poll = shutdown.clone();
                tokio::spawn(async move {
                    loop {
                        let _ = event_rb.poll(Duration::from_millis(1));
                        if shutdown_poll.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                });

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
                loop {
                    tokio::select! {
                        // Handle MCP server
                        result = &mut mcp_server_task => {
                            info!("MCP server exited");
                            shutdown.store(true, Ordering::Relaxed);
                            // Links are managed by EventControl and will be dropped on shutdown
                            return result;
                        }

                        // Handle actions from BPF
                        Some(action) = action_rx.recv() => {
                            // Check for shutdown
                            if matches!(action, Action::Quit) {
                                info!("Received quit action");
                                shutdown.store(true, Ordering::Relaxed);
                                // Links are managed by EventControl and will be dropped on shutdown
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

                Ok(())
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
