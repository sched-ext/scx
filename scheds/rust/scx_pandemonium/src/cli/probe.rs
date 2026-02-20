use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

// PRE-ALLOCATED SAMPLE BUFFER -- NO I/O DURING MEASUREMENT
const MAX_SAMPLES: usize = 16384;

/// Interactive wakeup probe.
/// When PANDEMONIUM is running, BPF records latencies to ring buffer.
/// For EEVDF baseline, we measure in userspace.
/// Either way: ZERO I/O during measurement, bulk output at end.
pub fn run_probe(death_pipe_fd: Option<i32>) {
    ctrlc::set_handler(move || {
        RUNNING.store(false, Ordering::Relaxed);
    })
    .ok();

    if let Some(fd) = death_pipe_fd {
        super::death_pipe::spawn_death_watcher(fd, &RUNNING);
    }

    let mut samples: Vec<i64> = Vec::with_capacity(MAX_SAMPLES);
    
    let target_ns: i64 = 10_000_000; // 10MS SLEEP TARGET
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: target_ns,
    };

    // HOT LOOP: MEASURE + BUFFER. ZERO I/O.
    while RUNNING.load(Ordering::Relaxed) && samples.len() < MAX_SAMPLES {
        let mut t0 = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let mut t1 = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t0);
            libc::nanosleep(&req, std::ptr::null_mut());
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t1);
        }
        let elapsed_ns = (t1.tv_sec - t0.tv_sec) * 1_000_000_000 + (t1.tv_nsec - t0.tv_nsec);
        let overshoot_us = (elapsed_ns - target_ns).max(0) / 1000;
        samples.push(overshoot_us);
    }

    // BULK OUTPUT AT END -- USE write() DIRECTLY TO MINIMIZE OVERHEAD
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    for s in &samples {
        let _ = writeln!(handle, "{}", s);
    }
}
