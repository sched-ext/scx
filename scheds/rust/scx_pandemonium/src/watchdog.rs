// MONITOR-LOOP WATCHDOG: ABORTS IF THE ADAPTIVE CONTROL LOOP OR BPF-ONLY
// TELEMETRY LOOP FAILS TO ADVANCE ITS HEARTBEAT WITHIN THE TIMEOUT. PROTECTS
// AGAINST HUNG LIBBPF MAP OPERATIONS (KERNEL STALL, VERIFIER RELOAD, PERCPU
// CONTENTION) THAT WOULD SILENTLY STOP KNOB UPDATES AND TELEMETRY.
//
// ABORT BYPASSES PROCDB SAVE INTENTIONALLY: A STALLED MONITOR LOOP MEANS
// BPF STATE IS WEDGED, AND WE PREFER KERNEL WATCHDOG TAKEOVER OVER LIMPING.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

pub static LOOP_HEARTBEAT: AtomicU64 = AtomicU64::new(0);

pub fn spawn(shutdown: &'static AtomicBool, timeout: Duration) {
    std::thread::Builder::new()
        .name("pand-watchdog".into())
        .spawn(move || {
            let mut last = LOOP_HEARTBEAT.load(Ordering::Relaxed);
            loop {
                std::thread::sleep(timeout);
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let cur = LOOP_HEARTBEAT.load(Ordering::Relaxed);
                if cur == last {
                    eprintln!(
                        "[WATCHDOG] monitor loop stalled for >{:?}; aborting",
                        timeout
                    );
                    std::process::abort();
                }
                last = cur;
            }
        })
        .expect("watchdog thread spawn");
}
