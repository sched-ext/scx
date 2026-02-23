// CPU-PINNED STRESS WORKER FOR BENCH-SCALE
// PURE COMPUTE SPIN LOOP. MATCHES THE WORKLOAD PROFILE OF BATCH CPU-BOUND TASKS.

use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn run_stress_worker(cpu: u32) {
    ctrlc::set_handler(move || {
        RUNNING.store(false, Ordering::Relaxed);
    })
    .ok();

    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu as usize, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }

    let mut x: u64 = 1;
    while RUNNING.load(Ordering::Relaxed) {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
    }
    std::hint::black_box(x);
}
