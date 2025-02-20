// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scxtop::bpf_intf::*;
use scxtop::bpf_skel::types::bpf_event;
use scxtop::bpf_skel::*;
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
use tokio::sync::mpsc;

use std::mem::MaybeUninit;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

const TRACE_FILE_PREFIX: &str = "scxtop_trace";

#[derive(Parser, Debug)]
#[command(about = APP)]
struct Args {
    /// App tick rate in milliseconds.
    #[arg(short = 'r', long, default_value_t = 250)]
    tick_rate_ms: usize,
    /// Extra verbose output.
    #[arg(short, long, default_value_t = false)]
    debug: bool,
    /// Exclude bpf event tracking.
    #[arg(short, long, default_value_t = false)]
    exclude_bpf: bool,
    /// Stats unix socket path.
    #[arg(short, long, default_value_t = STATS_SOCKET_PATH.to_string())]
    stats_socket_path: String,
    /// Trace file prefix for perfetto traces
    #[arg(short, long, default_value_t = TRACE_FILE_PREFIX.to_string())]
    trace_file_prefix: String,
    /// Number of ticks for traces.
    #[arg(long, default_value_t = 5)]
    trace_ticks: usize,
    /// Number of worker threads
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(2..128))]
    worker_threads: u16,
    /// Number of ticks to warmup before collecting traces.
    #[arg(long, default_value_t = 3)]
    trace_tick_warmup: usize,
    /// Process to monitor or all.
    #[arg(long, default_value_t = -1)]
    process_id: i32,

    /// Automatically start a trace when a function takes too long to return.
    #[arg(
        long,
        default_value_t = false,
        requires("experimental_long_tail_tracing_symbol"),
        requires("experimental_long_tail_tracing_binary")
    )]
    experimental_long_tail_tracing: bool,
    /// Symbol to automatically trace the long tail of.
    #[arg(long)]
    experimental_long_tail_tracing_symbol: Option<String>,
    /// Binary to attach the uprobe and uretprobe to.
    #[arg(long)]
    experimental_long_tail_tracing_binary: Option<String>,
    /// Minimum latency to trigger a trace.
    #[arg(long, default_value_t = 100000000)]
    experimental_long_tail_tracing_min_latency_ns: u64,
}

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
    let args = Args::parse();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(args.worker_threads as usize)
        .build()
        .unwrap()
        .block_on(async {
            let (action_tx, mut action_rx) = mpsc::unbounded_channel();

            let mut open_object = MaybeUninit::uninit();
            let mut builder = BpfSkelBuilder::default();
            if args.debug {
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

            let keymap = KeyMap::default();
            let mut tui = Tui::new(keymap.clone(), args.tick_rate_ms)?;
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
                    event_type_SCHED_WAKEUP => unsafe {
                        let comm = std::str::from_utf8(std::slice::from_raw_parts(
                            event.event.wakeup.comm.as_ptr() as *const u8,
                            16,
                        ))
                        .unwrap();
                        let action = Action::SchedWakeup(SchedWakeupAction {
                            ts: event.ts,
                            cpu: event.cpu,
                            pid: event.event.wakeup.pid,
                            prio: event.event.wakeup.prio,
                            comm: comm.to_string(),
                        });
                        tx.send(action).ok();
                    },
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
                            comm: comm.to_string(),
                        });
                        tx.send(action).ok();
                    }
                    #[allow(non_upper_case_globals)]
                    event_type_SCHED_SWITCH => unsafe {
                        let prev_comm = std::str::from_utf8(std::slice::from_raw_parts(
                            event.event.sched_switch.prev_comm.as_ptr() as *const u8,
                            16,
                        ))
                        .unwrap();
                        let next_comm = std::str::from_utf8(std::slice::from_raw_parts(
                            event.event.sched_switch.next_comm.as_ptr() as *const u8,
                            16,
                        ))
                        .unwrap();
                        let action = Action::SchedSwitch(SchedSwitchAction {
                            ts: event.ts,
                            cpu: event.cpu,
                            preempt: event.event.sched_switch.preempt.assume_init(),
                            next_dsq_id: event.event.sched_switch.next_dsq_id,
                            next_dsq_lat_us: event.event.sched_switch.next_dsq_lat_us,
                            next_dsq_nr_queued: event.event.sched_switch.next_dsq_nr,
                            next_dsq_vtime: event.event.sched_switch.next_dsq_vtime,
                            next_slice_ns: event.event.sched_switch.next_slice_ns,
                            next_pid: event.event.sched_switch.next_pid,
                            next_tgid: event.event.sched_switch.next_tgid,
                            next_prio: event.event.sched_switch.next_prio,
                            next_comm: next_comm.to_string(),
                            prev_dsq_id: event.event.sched_switch.prev_dsq_id,
                            prev_used_slice_ns: event.event.sched_switch.prev_slice_ns,
                            prev_slice_ns: event.event.sched_switch.prev_slice_ns,
                            prev_pid: event.event.sched_switch.prev_pid,
                            prev_tgid: event.event.sched_switch.prev_tgid,
                            prev_comm: prev_comm.to_string(),
                            prev_prio: event.event.sched_switch.prev_prio,
                            prev_state: event.event.sched_switch.prev_state,
                        });
                        tx.send(action).ok();
                    },
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
                args.stats_socket_path,
                args.trace_file_prefix.as_str(),
                scheduler,
                keymap.clone(),
                100,
                args.tick_rate_ms,
                args.trace_ticks,
                args.trace_tick_warmup,
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
