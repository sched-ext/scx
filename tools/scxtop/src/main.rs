// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scxtop::bpf_intf::*;
use scxtop::bpf_skel::types::bpf_event;
use scxtop::bpf_skel::*;
use scxtop::cli::Cli;
use scxtop::config::get_config_path;
use scxtop::config::Config;
use scxtop::read_file_string;
use scxtop::App;
use scxtop::Event;
use scxtop::Key;
use scxtop::KeyMap;
use scxtop::PerfEvent;
use scxtop::Tui;
use scxtop::APP;
use scxtop::SCHED_NAME_PATH;
use scxtop::STATS_SOCKET_PATH;
use scxtop::{
    Action, IPIAction, RecordTraceAction, SchedCpuPerfSetAction, SchedSwitchAction,
    SchedWakeupAction, SchedWakingAction, SoftIRQAction,
};

use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::UprobeOpts;
use ratatui::crossterm::event::KeyCode::Char;
use simplelog::{LevelFilter, WriteLogger};
use tokio::sync::mpsc;

use std::fs;
use std::fs::File;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

fn get_action(_app: &App, keymap: &KeyMap, event: Event) -> Action {
    match event {
        Event::Error => Action::None,
        Event::Tick => Action::Tick,
        Event::TickRateChange(tick_rate_ms) => {
            Action::TickRateChange(std::time::Duration::from_millis(tick_rate_ms))
        }
        Event::Render => Action::Render,
        Event::Key(key) => match key.code {
            Char(c) => keymap.action(&Key::Char(c)),
            _ => keymap.action(&Key::Code(key.code)),
        },
        _ => Action::None,
    }
}

fn main() -> Result<()> {
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
    let args = Cli::parse();

    let mut config = Config::load().unwrap_or(Config::default_config());
    config = Config::merge_cli(&config, &args);
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

            let skel = builder.open(&mut open_object)?;
            skel.maps.rodata_data.long_tail_tracing_min_latency_ns =
                args.experimental_long_tail_tracing_min_latency_ns;

            let skel = skel.load()?;

            // Attach probes
            let mut links = vec![
                skel.progs.on_sched_cpu_perf.attach()?,
                skel.progs.scx_sched_reg.attach()?,
                skel.progs.scx_sched_unreg.attach()?,
                skel.progs.on_sched_switch.attach()?,
                skel.progs.on_sched_wakeup.attach()?,
            ];

            // 6.13 compatability
            if let Ok(link) = skel.progs.scx_insert_vtime.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_dispatch_vtime.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_insert.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_dispatch.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_dispatch_from_dsq_set_vtime.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_dsq_move_set_vtime.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_dsq_move_set_slice.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_dispatch_from_dsq_set_slice.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_dispatch_from_dsq.attach() {
                links.push(link);
            }
            if let Ok(link) = skel.progs.scx_dsq_move.attach() {
                links.push(link);
            }

            if args.experimental_long_tail_tracing {
                let binary = &args.experimental_long_tail_tracing_binary.unwrap();
                let symbol = &args.experimental_long_tail_tracing_symbol.unwrap();

                links.extend([
                    skel.progs.long_tail_tracker_exit.attach_uprobe_with_opts(
                        -1, /* pid, -1 == all */
                        binary,
                        0,
                        UprobeOpts {
                            retprobe: true,
                            func_name: symbol.into(),
                            ..Default::default()
                        },
                    )?,
                    skel.progs.long_tail_tracker_entry.attach_uprobe_with_opts(
                        -1, /* pid, -1 == all */
                        binary,
                        0,
                        UprobeOpts {
                            retprobe: false,
                            func_name: symbol.into(),
                            ..Default::default()
                        },
                    )?,
                ]);
            };

            let mut tui = Tui::new(keymap.clone(), config.tick_rate_ms())?;
            let mut event_rbb = RingBufferBuilder::new();
            let tx = action_tx.clone();
            let event_handler = move |data: &[u8]| {
                let mut event = bpf_event::default();
                // This works because the plain types were created in lib.rs
                plain::copy_from_bytes(&mut event, data).expect("Event data buffer was too short");

                let action: Action = event.try_into().expect("unrecognised bpf_event");
                tx.send(action).ok();

                0
            };
            event_rbb.add(&skel.maps.events, event_handler)?;
            let event_rb = event_rbb.build()?;
            let scheduler = read_file_string(SCHED_NAME_PATH).unwrap_or("".to_string());

            let mut app = App::new(
                config,
                scheduler,
                100,
                args.process_id,
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

            loop {
                let e = tui.next().await?;
                match e {
                    Event::Quit => action_tx.send(Action::Quit)?,
                    Event::Tick => action_tx.send(Action::Tick)?,
                    Event::TickRateChange(tick_rate_ms) => action_tx.send(
                        Action::TickRateChange(std::time::Duration::from_millis(tick_rate_ms)),
                    )?,
                    Event::Render => action_tx.send(Action::Render)?,
                    Event::Key(_) => {
                        let action = get_action(&app, &keymap, e);
                        action_tx.send(action)?;
                    }
                    _ => {}
                };

                while let Ok(action) = action_rx.try_recv() {
                    if let Action::Render = action {
                        tui.draw(|f| app.render(f).expect("Failed to render application"))?;
                    } else {
                        app.handle_action(&action)?;
                    }
                }

                if app.should_quit.load(Ordering::Relaxed) {
                    break;
                }
            }
            tui.exit()?;
            drop(links);

            Ok(())
        })
}
