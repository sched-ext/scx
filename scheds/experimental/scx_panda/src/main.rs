// scx_panda -- A SCHED_EXT SCHEDULER BUILT FROM DISCARDED IDEAS AND UNSPENT
// POTENTIAL
//
// EVERY SCHEDULING DECISION IS MADE IN BPF. THIS BINARY LOADS THE PROGRAM,
// SIZES AND FILLS ITS TOPOLOGY TABLES FROM SYSFS, ATTACHES IT, RE-FILLS ON
// HOTPLUG, PRINTS COUNTERS WHEN ASKED AND RESTARTS WHEN THE KERNEL ASKS.

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use scx_panda::events::ScxEvents;
use scx_panda::scheduler::{PandaStats, Scheduler, verifier_lines};
use scx_panda::topology::CpuTopology;
use scx_panda::{log_info, log_warn};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// WHERE AN EXIT DUMP AND THE EXIT SUMMARY ARE WRITTEN WHOLE. A HARNESS THAT
// STARTS THIS BINARY AS AN ARM MAY DISCARD ITS STDOUT; THE FILES REMAIN.
const DUMP_DIR: &str = "/tmp/panda";
const DUMP_HEAD_LINES: usize = 60;

// THE ARM THIS BINARY WAS BUILT AS: "shipped", OR A MEASUREMENT ARM NAMED BY
// PANDA_MEASURE AT BUILD TIME. IT RIDES IN THE VERSION, THE BANNER AND THE
// SUMMARY, SO NO RUN IS READ AGAINST THE WRONG PROGRAM.
const ARM: &str = env!("PANDA_ARM");

#[derive(Parser)]
#[command(name = "scx_panda")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), env!("PANDA_BUILD_ID"), " ", env!("PANDA_TARGET"), " built against ", env!("PANDA_KERNEL"), " arm ", env!("PANDA_ARM")))]
#[command(
    about = "scx_panda -- a sched_ext scheduler built from discarded ideas and unspent potential"
)]
struct Cli {
    /// Print a counter line every second
    #[arg(short, long)]
    verbose: bool,

    /// Load the BPF program through the verifier, print its counts and exit without attaching
    #[arg(long)]
    check: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    ctrlc::set_handler(move || {
        SHUTDOWN.store(true, Ordering::Relaxed);
    })?;

    let nr_cpus = libbpf_rs::num_possible_cpus()? as u32;
    let governor = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .unwrap_or_default()
        .trim()
        .to_string();
    let smt_on = std::fs::read_to_string("/sys/devices/system/cpu/smt/active")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    log_info!(
        "scx_panda {}{} {} arm {} SMT {}",
        env!("CARGO_PKG_VERSION"),
        env!("PANDA_BUILD_ID"),
        env!("PANDA_TARGET"),
        ARM,
        if smt_on { "on" } else { "off" }
    );
    if ARM != "shipped" {
        log_warn!("MEASUREMENT ARM {}: not the shipped program", ARM);
    }
    log_info!(
        "CPUS: {} (governor: {})",
        nr_cpus,
        if governor.is_empty() {
            "unknown"
        } else {
            &governor
        }
    );

    if cli.check {
        let mut open_object = MaybeUninit::uninit();
        let mut sched = Scheduler::open_and_load(&mut open_object, nr_cpus, true)?;
        CpuTopology::detect_and_populate(&mut sched, nr_cpus as usize)?;
        for line in verifier_lines() {
            println!("[VERIFIER] {line}");
        }
        log_info!("CHECK: program loaded through the verifier and tables filled; not attached");
        return Ok(());
    }

    let mut is_restart = false;
    loop {
        // struct_ops UNREGISTER IS ASYNCHRONOUS; A RE-ATTACH THAT RACES IT
        // FAILS TO LOAD.
        if is_restart {
            std::thread::sleep(Duration::from_secs(2));
        }

        let mut open_object = MaybeUninit::uninit();
        let mut sched = Scheduler::open_and_load(&mut open_object, nr_cpus, false)?;

        // FILL BEFORE ATTACH, SO THE FIRST TICK SEES A FULL TABLE SET AND A
        // LIVE tau. THE SAME SEQUENCE RE-RUNS ON HOTPLUG.
        let mut last_online = CpuTopology::online_cpu_count();
        if let Err(e) = CpuTopology::detect_and_populate(&mut sched, nr_cpus as usize) {
            log_warn!("TOPOLOGY DETECT FAILED: {}", e);
        }
        sched.attach()?;
        log_info!("scx_panda IS ACTIVE (CTRL+C TO EXIT)");

        let mut prev = PandaStats::default();
        let mut prev_ev = ScxEvents::read().unwrap_or_default();
        while !SHUTDOWN.load(Ordering::Relaxed) && !sched.exited() {
            std::thread::sleep(Duration::from_secs(1));
            CpuTopology::poll_hotplug(&mut sched, nr_cpus as usize, &mut last_online);
            let stats = sched.read_stats();
            let ev = ScxEvents::read().unwrap_or_default();
            if cli.verbose {
                print_delta(&stats, &prev, &ev, &prev_ev);
            }
            prev = stats;
            prev_ev = ev;
        }

        let final_stats = sched.read_stats();
        print_summary(&final_stats, ScxEvents::read().as_ref());
        let should_restart = sched.read_exit_info();
        if sched.exited() {
            write_dump(&sched.read_exit_dump());
        }
        log_info!("scx_panda IS SHUTTING DOWN");

        if !should_restart || SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
        SHUTDOWN.store(false, Ordering::Relaxed);
        log_info!("RESTARTING scx_panda");
        is_restart = true;
    }

    log_info!("Shutdown complete");
    Ok(())
}

fn print_delta(s: &PandaStats, p: &PandaStats, ev: &ScxEvents, pev: &ScxEvents) {
    let d = |a: u64, b: u64| a.wrapping_sub(b);
    let disp = d(s.nr_dispatches, p.nr_dispatches);
    let idle = d(s.nr_idle_hits, p.nr_idle_hits);
    let wake_samples = d(s.wake_lat_samples, p.wake_lat_samples);
    let wake_us = if wake_samples > 0 {
        d(s.wake_lat_sum, p.wake_lat_sum) / wake_samples / 1000
    } else {
        0
    };
    let used = d(s.nr_seat_expect_used, p.nr_seat_expect_used);
    let over = d(s.nr_seat_expect_overrun, p.nr_seat_expect_overrun);
    println!(
        "d/s: {:<8} idle: {}% shared: {:<6} preempt: {:<4} keep: {:<4} kick: H={:<4} S={:<4} enq: W={:<4} R={:<4} wake: {}us steal: {:<4} expect: used={} overrun={} sjrn: {}ms{} ev: {}",
        disp,
        if disp > 0 { idle * 100 / disp } else { 0 },
        d(s.nr_shared, p.nr_shared),
        d(s.nr_preempt, p.nr_preempt),
        d(s.nr_keep_running, p.nr_keep_running),
        d(s.nr_hard_kicks, p.nr_hard_kicks),
        d(s.nr_soft_kicks, p.nr_soft_kicks),
        d(s.nr_enq_wakeup, p.nr_enq_wakeup),
        d(s.nr_enq_requeue, p.nr_enq_requeue),
        wake_us,
        d(s.nr_steal, p.nr_steal),
        used,
        over,
        s.batch_sojourn_ns / 1_000_000,
        if s.longrun_mode_active > 0 {
            " LONGRUN"
        } else {
            ""
        },
        ev.delta_line(pev),
    );
}

// THE RUN HABIT'S DISTRIBUTION, THE SEAT PRICE'S TWO COUNTERS AND THE
// KERNEL'S EVENT COUNTERS, ONCE AT EXIT, TO STDOUT AND TO A FILE. BUCKET i
// IS avg_run_ns IN [2^i us, 2^(i+1) us).
fn print_summary(s: &PandaStats, ev: Option<&ScxEvents>) {
    let x = &s.nr_cross_domain;
    let scatter: u64 = x[0..6].iter().sum();
    let mut lines = vec![format!(
        "[PANDA] dispatches={} idle_hits={} steal={} spill={} kick_declined={} cross_domain_scatter_pct={} expect_used={} expect_overrun={}",
        s.nr_dispatches,
        s.nr_idle_hits,
        s.nr_steal,
        s.nr_spill_kick_preempt,
        s.nr_kick_declined,
        if s.nr_dispatches > 0 {
            scatter * 100 / s.nr_dispatches
        } else {
            0
        },
        s.nr_seat_expect_used,
        s.nr_seat_expect_overrun,
    )];
    lines.push(format!(
        "[PANDA] codel_target_live_ns={}",
        s.codel_target_live
    ));
    let total: u64 = s.ewma_hist.iter().sum();
    let cells: Vec<String> = s
        .ewma_hist
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            format!(
                "{}us={}",
                1u64 << i,
                if total > 0 { c * 1000 / total } else { 0 }
            )
        })
        .collect();
    lines.push(format!("[PANDA] run_habit_permille {}", cells.join(" ")));
    if let Some(ev) = ev {
        lines.push(format!("[PANDA] events {}", ev.total_line()));
    }
    for line in &lines {
        println!("{line}");
    }
    write_summary(&lines);
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// THE SUMMARY UNDER /tmp/panda, HEADED BY THE VERSION AND THE ARM.
fn write_summary(lines: &[String]) {
    let path = format!("{DUMP_DIR}/summary-{}.txt", epoch_secs());
    let mut body = format!(
        "scx_panda {}{} arm {} kernel {}\n",
        env!("CARGO_PKG_VERSION"),
        env!("PANDA_BUILD_ID"),
        ARM,
        env!("PANDA_KERNEL")
    );
    body.push_str(&lines.join("\n"));
    body.push('\n');
    match std::fs::create_dir_all(DUMP_DIR).and_then(|_| std::fs::write(&path, body)) {
        Ok(()) => log_info!("summary written to {}", path),
        Err(e) => log_warn!("summary not written to {}: {}", path, e),
    }
}

// THE KERNEL'S EXIT DUMP: WHOLE TO A FILE UNDER /tmp/panda, ITS HEAD TO THE
// JOURNAL. AN EMPTY DUMP IS SAID SO.
fn write_dump(dump: &str) {
    if dump.trim().is_empty() {
        log_warn!("BPF exit dump: empty");
        return;
    }
    let lines: Vec<&str> = dump.lines().collect();
    let path = format!("{DUMP_DIR}/dump-{}.txt", epoch_secs());
    let written = std::fs::create_dir_all(DUMP_DIR)
        .and_then(|_| std::fs::write(&path, dump))
        .is_ok();
    if written {
        log_warn!("BPF exit dump: {} lines written to {}", lines.len(), path);
    } else {
        log_warn!(
            "BPF exit dump: {} lines (could not write {})",
            lines.len(),
            path
        );
    }
    for line in lines.iter().take(DUMP_HEAD_LINES) {
        println!("[DUMP] {line}");
    }
    if lines.len() > DUMP_HEAD_LINES {
        println!(
            "[DUMP] ... {} more lines in {}",
            lines.len() - DUMP_HEAD_LINES,
            path
        );
    }
}
