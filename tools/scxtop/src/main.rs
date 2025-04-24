// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scx_utils::compat;
use scxtop::bpf_skel::types::bpf_event;
use scxtop::bpf_skel::*;
use scxtop::cli::{generate_completions, Cli, Commands, TraceArgs, TuiArgs};
use scxtop::config::Config;
use scxtop::edm::{ActionHandler, BpfEventActionPublisher, BpfEventHandler, EventDispatchManager};
use scxtop::mangoapp::poll_mangoapp;
use scxtop::read_file_string;
use scxtop::tracer::Tracer;
use scxtop::Action;
use scxtop::App;
use scxtop::Event;
use scxtop::Key;
use scxtop::KeyMap;
use scxtop::PerfettoTraceManager;
use scxtop::Tui;
use scxtop::SCHED_NAME_PATH;

use anyhow::anyhow;
use anyhow::Result;
use clap::{CommandFactory, Parser};
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;
use libbpf_rs::ProgramInput;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::UprobeOpts;
use log::debug;
use log::info;
use ratatui::crossterm::event::KeyCode::Char;
use simplelog::{
    ColorChoice, Config as SimplelogConfig, LevelFilter, TermLogger, TerminalMode, WriteLogger,
};
use std::sync::atomic::AtomicBool;
use tokio::sync::mpsc;

use std::ffi::CString;
use std::fs::File;
use std::mem::MaybeUninit;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn get_action(_app: &App, keymap: &KeyMap, event: Event) -> Action {
    match event {
        Event::Error => Action::None,
        Event::Tick => Action::Tick,
        Event::TickRateChange(tick_rate_ms) => {
            Action::TickRateChange(std::time::Duration::from_millis(tick_rate_ms))
        }
        Event::Key(key) => match key.code {
            Char(c) => keymap.action(&Key::Char(c)),
            _ => keymap.action(&Key::Code(key.code)),
        },
        _ => Action::None,
    }
}

/// Attaches BPF programs to the skel.
fn attach_progs(skel: &mut BpfSkel) -> Result<Vec<Link>> {
    // Attach probes
    let mut links = vec![
        skel.progs.on_sched_cpu_perf.attach()?,
        skel.progs.scx_sched_reg.attach()?,
        skel.progs.scx_sched_unreg.attach()?,
        skel.progs.on_sched_switch.attach()?,
        skel.progs.on_sched_wakeup.attach()?,
        skel.progs.on_sched_wakeup_new.attach()?,
        skel.progs.on_sched_waking.attach()?,
    ];

    // 6.13 compatibility
    if compat::ksym_exists("scx_insert_vtime")? {
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
    if let Ok(link) = skel.progs.on_pstate_sample.attach() {
        links.push(link);
    }

    Ok(links)
}

fn run_trace(trace_args: &TraceArgs) -> Result<()> {
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

            let mut open_object = MaybeUninit::uninit();
            let mut builder = BpfSkelBuilder::default();
            if trace_args.verbose > 2 {
                builder.obj_builder.debug(true);
            }

            let skel = builder.open(&mut open_object)?;
            // set sample rate to 1 here to populate the BPF tctxs
            skel.maps.data_data.sample_rate = 1;
            compat::cond_kprobe_enable("gpu_memory_total", &skel.progs.on_gpu_memory_total)?;
            compat::cond_kprobe_enable("hw_pressure_update", &skel.progs.on_hw_pressure_update)?;

            let mut skel = skel.load()?;
            let mut links = attach_progs(&mut skel)?;
            links.push(skel.progs.on_sched_fork.attach()?);
            links.push(skel.progs.on_sched_exec.attach()?);
            links.push(skel.progs.on_sched_exit.attach()?);

            let trace_dur = std::time::Duration::from_millis(trace_args.trace_ms);
            let bpf_publisher = BpfEventActionPublisher::new(action_tx.clone());

            let mut event_rbb = RingBufferBuilder::new();
            let mut edm = EventDispatchManager::new(None, None);
            let warmup_done = Arc::new(AtomicBool::new(false));
            edm.register_bpf_handler(Box::new(bpf_publisher));
            let event_handler = move |data: &[u8]| {
                let mut event = bpf_event::default();
                plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
                let _ = edm.on_event(&event);
                0
            };

            event_rbb.add(&skel.maps.events, event_handler)?;
            let event_rb = event_rbb.build()?;
            let shutdown = Arc::new(AtomicBool::new(false));
            let stop_poll = shutdown.clone();
            let stop_main = shutdown.clone();

            tokio::spawn(async move {
                loop {
                    let _ = event_rb.poll(Duration::from_millis(1));
                    if stop_poll.load(Ordering::Relaxed) {
                        debug!("polling stopped");
                        break;
                    }
                }
            });

            let (complete_tx, mut complete_rx) = mpsc::channel(1);
            let trace_file_prefix = config.trace_file_prefix().to_string();
            let trace_file = trace_args.output_file.clone();
            let mut trace_manager = PerfettoTraceManager::new(trace_file_prefix, None);
            info!("warming up for {}ms", trace_args.warmup_ms);
            tokio::time::sleep(Duration::from_millis(trace_args.warmup_ms)).await;
            debug!("starting trace");
            let thread_warmup = warmup_done.clone();
            trace_manager.start()?;
            thread_warmup.store(true, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut count = 0;
                loop {
                    let action = action_rx.recv().await;
                    if let Some(a) = action {
                        if thread_warmup.load(Ordering::Relaxed) {
                            count += 1;
                            trace_manager.on_action(&a).unwrap();
                        }
                    }
                    if stop_main.load(Ordering::Relaxed) {
                        trace_manager.stop(trace_file, None).unwrap();
                        info!("trace complete, collected {} events", count);
                        let _ = complete_tx.send(1).await;
                        break;
                    }
                }
            });

            let mut tracer = Tracer::new(skel);
            tracer.trace_async(trace_dur).await?;

            // The order is important here:
            // 1) first drop the links to detach the attached BPF programs
            // 2) set the shutdown variable to stop background tokio threads
            // 3) wait for the completion of the trace file generation to complete
            drop(links);
            shutdown.store(true, Ordering::Relaxed);
            let _ = complete_rx.recv().await;

            let stats = tracer.stats()?;
            info!("{:?}", stats);

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
        Config::load().unwrap_or(Config::default_config()),
    ]);
    let keymap = config.active_keymap.clone();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(config.worker_threads() as usize)
        .build()
        .unwrap()
        .block_on(async {
            let (action_tx, mut action_rx) = mpsc::unbounded_channel();

            let mut open_object = MaybeUninit::uninit();
            let mut builder = BpfSkelBuilder::default();
            if config.debug() {
                builder.obj_builder.debug(true);
            }
            let bpf_publisher = BpfEventActionPublisher::new(action_tx.clone());
            let mut edm = EventDispatchManager::new(None, None);
            edm.register_bpf_handler(Box::new(bpf_publisher));

            let skel = builder.open(&mut open_object)?;
            skel.maps.rodata_data.long_tail_tracing_min_latency_ns =
                tui_args.experimental_long_tail_tracing_min_latency_ns;

            compat::cond_kprobe_enable("gpu_memory_total", &skel.progs.on_gpu_memory_total)?;
            compat::cond_kprobe_enable("hw_pressure_update", &skel.progs.on_hw_pressure_update)?;
            let mut skel = skel.load()?;
            let mut links = attach_progs(&mut skel)?;
            skel.progs.scxtop_init.test_run(ProgramInput::default())?;

            if tui_args.experimental_long_tail_tracing {
                skel.maps.data_data.trace_duration_ns = config.trace_duration_ns();
                skel.maps.data_data.trace_warmup_ns = config.trace_warmup_ns();

                let binary = tui_args
                    .experimental_long_tail_tracing_binary
                    .clone()
                    .unwrap();
                let symbol = tui_args
                    .experimental_long_tail_tracing_symbol
                    .clone()
                    .unwrap();

                links.extend([
                    skel.progs.long_tail_tracker_exit.attach_uprobe_with_opts(
                        -1, /* pid, -1 == all */
                        binary.clone(),
                        0,
                        UprobeOpts {
                            retprobe: true,
                            func_name: symbol.clone(),
                            ..Default::default()
                        },
                    )?,
                    skel.progs.long_tail_tracker_entry.attach_uprobe_with_opts(
                        -1, /* pid, -1 == all */
                        binary.clone(),
                        0,
                        UprobeOpts {
                            retprobe: false,
                            func_name: symbol.clone(),
                            ..Default::default()
                        },
                    )?,
                ]);
            };

            let mut tui = Tui::new(keymap.clone(), config.tick_rate_ms())?;
            let mut event_rbb = RingBufferBuilder::new();
            let event_handler = move |data: &[u8]| {
                let mut event = bpf_event::default();
                plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");
                let _ = edm.on_event(&event);
                0
            };
            event_rbb.add(&skel.maps.events, event_handler)?;
            let event_rb = event_rbb.build()?;
            let scheduler = read_file_string(SCHED_NAME_PATH).unwrap_or("".to_string());

            let mut app = App::new(
                config,
                scheduler,
                100,
                tui_args.process_id,
                action_tx.clone(),
                skel,
            )?;

            tui.enter()?;

            let shutdown = app.should_quit.clone();
            tokio::spawn(async move {
                loop {
                    let _ = event_rb.poll(Duration::from_millis(1));
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                }
            });

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
                                tui.draw(|f| app.render(f).expect("Failed to render application"))?;
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

fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command.unwrap_or(Commands::Tui(args.tui)) {
        Commands::Tui(tui_args) => {
            run_tui(tui_args)?;
        }
        Commands::Trace(trace_args) => {
            run_trace(trace_args)?;
        }
        Commands::GenerateCompletions { shell, output } => {
            generate_completions(Cli::command(), *shell, output.clone())
                .unwrap_or_else(|_| panic!("Failed to generate completions for {}", shell));
        }
    }
    Ok(())
}
