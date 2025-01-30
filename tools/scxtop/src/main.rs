// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use scxtop::bpf_intf::*;
use scxtop::bpf_skel::types::bpf_event;
use scxtop::bpf_skel::*;
use scxtop::read_file_string;
use scxtop::Action;
use scxtop::App;
use scxtop::Event;
use scxtop::Key;
use scxtop::KeyMap;
use scxtop::Tui;
use scxtop::APP;
use scxtop::SCHED_NAME_PATH;
use scxtop::STATS_SOCKET_PATH;
use std::mem::MaybeUninit;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ratatui::crossterm::event::KeyCode::Char;
use tokio::sync::mpsc;

const TRACE_FILE_PREFIX: &'static str = "scxtop_trace";

#[derive(Parser, Debug)]
#[command(about = APP)]
struct Args {
    /// App tick rate in milliseconds.
    #[arg(short, long, default_value_t = 250)]
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
}

fn get_action(_app: &App, keymap: &KeyMap, event: Event) -> Action {
    match event {
        Event::Error => Action::None,
        Event::Tick => Action::Tick,
        Event::TickRateChange(tick_rate_ms) => Action::TickRateChange { tick_rate_ms },
        Event::Render => Action::Render,
        Event::Key(key) => match key.code {
            Char(c) => keymap.action(&Key::Char(c)),
            _ => keymap.action(&Key::Code(key.code)),
        },
        _ => Action::None,
    }
}

async fn run() -> Result<()> {
    let (action_tx, mut action_rx) = mpsc::unbounded_channel();

    let args = Args::parse();

    let mut open_object = MaybeUninit::uninit();
    let mut builder = BpfSkelBuilder::default();
    if args.debug {
        builder.obj_builder.debug(true);
    }
    let open_skel = builder.open(&mut open_object)?;
    let skel = open_skel.load()?;

    let mut links = Vec::new();
    // Attach probes
    links.push(skel.progs.on_sched_cpu_perf.attach()?);
    links.push(skel.progs.scx_sched_reg.attach()?);
    links.push(skel.progs.scx_sched_unreg.attach()?);
    links.push(skel.progs.on_sched_switch.attach()?);

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

    let keymap = KeyMap::default();
    let tui = Tui::new(keymap.clone(), args.tick_rate_ms)?;
    let arc_tui = Arc::new(RwLock::new(tui));
    let mut rbb = RingBufferBuilder::new();
    let tx = action_tx.clone();
    rbb.add(&skel.maps.events, move |data: &[u8]| {
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
                let action = unsafe {
                    Action::SchedCpuPerfSet {
                        cpu: event.cpu,
                        perf: event.event.perf.perf,
                    }
                };
                tx.send(action).ok();
            }
            #[allow(non_upper_case_globals)]
            event_type_SCHED_WAKEUP => unsafe {
                let comm = std::str::from_utf8(std::slice::from_raw_parts(
                    event.event.wakeup.comm.as_ptr() as *const u8,
                    16,
                ))
                .unwrap();
                let action = Action::SchedWakeup {
                    ts: event.ts,
                    cpu: event.cpu,
                    pid: event.event.wakeup.pid,
                    prio: event.event.wakeup.prio,
                    comm: comm.to_string(),
                };
                tx.send(action).ok();
            },
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
                let action = Action::SchedSwitch {
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
                };
                tx.send(action).ok();
            },
            _ => {}
        }
        0
    })?;
    let rb = rbb.build()?;
    let scheduler = read_file_string(SCHED_NAME_PATH).unwrap_or("".to_string());

    let mut app = App::new(
        args.stats_socket_path,
        args.trace_file_prefix.as_str(),
        scheduler,
        keymap.clone(),
        100,
        args.tick_rate_ms,
        action_tx.clone(),
        skel,
    )?;

    let main_tui = arc_tui.clone();
    main_tui.write().unwrap().enter()?;

    let shutdown = app.should_quit.clone();
    tokio::spawn(async move {
        loop {
            let _ = rb.poll(Duration::from_millis(1));
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
        }
    });

    loop {
        let loop_tui = arc_tui.clone();
        let e = loop_tui.write().unwrap().next().await?;
        match e {
            Event::Quit => action_tx.send(Action::Quit)?,
            Event::Tick => action_tx.send(Action::Tick)?,
            Event::TickRateChange(tick_rate_ms) => {
                action_tx.send(Action::TickRateChange { tick_rate_ms })?
            }
            Event::Render => action_tx.send(Action::Render)?,
            Event::Key(_) => {
                let action = get_action(&app, &keymap, e);
                action_tx.send(action.clone())?;
            }
            _ => {}
        };

        while let Ok(action) = action_rx.try_recv() {
            app.handle_action(action.clone())?;
            if let Action::Render = action {
                loop_tui
                    .write()
                    .expect("Failed to draw application")
                    .draw(|f| app.render(f).expect("Failed to render application"))?;
            }
        }

        if app.should_quit.load(Ordering::Relaxed) {
            break;
        }
    }
    main_tui.write().unwrap().exit()?;
    drop(links);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let result = run().await;

    result?;

    Ok(())
}
