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
                let event_type = event.r#type as u32;
                match event_type {
                    #[allow(non_upper_case_globals)]
                    event_type_SCHED_REG => {
                        tx.send(Action::SchedReg.clone()).ok();
                    }
                    #[allow(non_upper_case_globals)]
                    event_type_SCHED_UNREG => {
                        tx.send(Action::SchedUnreg.clone()).ok();
                    }
                    #[allow(non_upper_case_globals)]
                    event_type_CPU_PERF_SET => {
                        let action = Action::SchedCpuPerfSet(SchedCpuPerfSetAction {
                            cpu: event.cpu,
                            perf: unsafe { event.event.perf.perf },
                        });
                        tx.send(action).ok();
                    }
                    #[allow(non_upper_case_globals)]
                    event_type_IPI => {
                        let action = Action::IPI(IPIAction {
                            ts: event.ts,
                            cpu: event.cpu,
                            pid: unsafe { event.event.ipi.pid },
                            target_cpu: unsafe { event.event.ipi.target_cpu },
                        });
                        tx.send(action).ok();
                    }
                    #[allow(non_upper_case_globals)]
                    event_type_SOFTIRQ => unsafe {
                        let action = Action::SoftIRQ(SoftIRQAction {
                            cpu: event.cpu,
                            pid: event.event.softirq.pid,
                            entry_ts: event.event.softirq.entry_ts,
                            exit_ts: event.event.softirq.exit_ts,
                            softirq_nr: event.event.softirq.softirq_nr as usize,
                        });
                        tx.send(action).ok();
                    },
                    #[allow(non_upper_case_globals)]
                    event_type_SCHED_WAKEUP => {
                        let wakeup = unsafe { event.event.wakeup };
                        let comm = unsafe {
                            std::str::from_utf8(std::slice::from_raw_parts(
                                event.event.wakeup.comm.as_ptr() as *const u8,
                                16,
                            ))
                            .unwrap()
                        };
                        let action = Action::SchedWakeup(SchedWakeupAction {
                            ts: event.ts,
                            cpu: event.cpu,
                            pid: wakeup.pid,
                            prio: wakeup.prio,
                            comm: comm.into(),
                        });
                        tx.send(action).ok();
                    }
                    #[allow(non_upper_case_globals)]
                    event_type_SCHED_WAKING => {
                        let waking = unsafe { &event.event.waking };
                        let comm = std::str::from_utf8(unsafe {
                            std::slice::from_raw_parts(waking.comm.as_ptr() as *const u8, 16)
                        })
                        .unwrap();
                        let action = Action::SchedWaking(SchedWakingAction {
                            ts: event.ts,
                            cpu: event.cpu,
                            pid: waking.pid,
                            prio: waking.prio,
                            comm: comm.into(),
                        });
                        tx.send(action).ok();
                    }
                    #[allow(non_upper_case_globals)]
                    event_type_SCHED_SWITCH => {
                        let sched_switch = unsafe { &event.event.sched_switch };
                        let prev_comm = unsafe {
                            std::str::from_utf8(std::slice::from_raw_parts(
                                sched_switch.prev_comm.as_ptr() as *const u8,
                                sched_switch.prev_comm.len(),
                            ))
                            .unwrap()
                        };
                        let next_comm = unsafe {
                            std::str::from_utf8(std::slice::from_raw_parts(
                                sched_switch.next_comm.as_ptr() as *const u8,
                                sched_switch.next_comm.len(),
                            ))
                            .unwrap()
                        };

                        let action = Action::SchedSwitch(SchedSwitchAction {
                            ts: event.ts,
                            cpu: event.cpu,
                            preempt: unsafe { sched_switch.preempt.assume_init() },
                            next_dsq_id: sched_switch.next_dsq_id,
                            next_dsq_lat_us: sched_switch.next_dsq_lat_us,
                            next_dsq_nr_queued: sched_switch.next_dsq_nr,
                            next_dsq_vtime: sched_switch.next_dsq_vtime,
                            next_slice_ns: sched_switch.next_slice_ns,
                            next_pid: sched_switch.next_pid,
                            next_tgid: sched_switch.next_tgid,
                            next_prio: sched_switch.next_prio,
                            next_comm: next_comm.into(),
                            prev_dsq_id: sched_switch.prev_dsq_id,
                            prev_used_slice_ns: sched_switch.prev_slice_ns,
                            prev_slice_ns: sched_switch.prev_slice_ns,
                            prev_pid: sched_switch.prev_pid,
                            prev_tgid: sched_switch.prev_tgid,
                            prev_comm: prev_comm.into(),
                            prev_prio: sched_switch.prev_prio,
                            prev_state: sched_switch.prev_state,
                        });
                        tx.send(action).ok();
                    }
                    #[allow(non_upper_case_globals)]
                    event_type_START_TRACE => {
                        let action = Action::RecordTrace(RecordTraceAction { immediate: true });
                        tx.send(action).ok();
                    }
                    _ => {}
                }
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
