use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

// PRE-ALLOCATED SAMPLE BUFFER -- NO I/O DURING MEASUREMENT
const MAX_SAMPLES: usize = 16384;

/// Interactive wakeup probe.
/// When PANDEMONIUM is running, BPF records latencies to ring buffer.
/// For EEVDF baseline, we measure in userspace.
/// Either way: ZERO I/O during measurement, bulk output at end.
pub fn run_probe() {
    ctrlc::set_handler(move || {
        RUNNING.store(false, Ordering::Relaxed);
    })
    .ok();

    let mut samples: Vec<i64> = Vec::with_capacity(MAX_SAMPLES);

    let period_ns: i64 = 10_000_000; // 10MS PROBE PERIOD

    // COORDINATED-OMISSION-CORRECT: sleep to an ABSOLUTE running deadline
    // (CLOCK_MONOTONIC, TIMER_ABSTIME), not a relative nanosleep. When a
    // scheduler stall makes us oversleep past later deadlines, backfill one
    // sample per swallowed deadline (HdrHistogram recordValueWithExpectedInterval
    // semantics). A relative nanosleep records a single long overshoot and
    // drops the queue of deadlines the stall ate -- understating the tail.
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
    }
    let mut deadline_ns: i64 = now.tv_sec * 1_000_000_000 + now.tv_nsec + period_ns;

    while RUNNING.load(Ordering::Relaxed) && samples.len() < MAX_SAMPLES {
        let dl = libc::timespec {
            tv_sec: deadline_ns / 1_000_000_000,
            tv_nsec: deadline_ns % 1_000_000_000,
        };
        unsafe {
            libc::clock_nanosleep(
                libc::CLOCK_MONOTONIC,
                libc::TIMER_ABSTIME,
                &dl,
                std::ptr::null_mut(),
            );
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
        }
        let now_ns = now.tv_sec * 1_000_000_000 + now.tv_nsec;

        // SAMPLE THIS DEADLINE, THEN BACKFILL ANY DEADLINES THE STALL SWALLOWED.
        loop {
            let lateness_us = (now_ns - deadline_ns).max(0) / 1000;
            samples.push(lateness_us);
            deadline_ns += period_ns;
            if now_ns < deadline_ns || samples.len() >= MAX_SAMPLES {
                break;
            }
        }
    }

    // BULK OUTPUT AT END -- USE write() DIRECTLY TO MINIMIZE OVERHEAD
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    for s in &samples {
        let _ = writeln!(handle, "{}", s);
    }
}
