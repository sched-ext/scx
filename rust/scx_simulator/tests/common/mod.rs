use std::sync::MutexGuard;

use scx_simulator::SIM_LOCK;

/// Acquire the simulator lock and initialize tracing from `RUST_LOG`.
///
/// Returns the lock guard — hold it for the duration of the test.
/// `try_init()` is idempotent: first call in the process succeeds,
/// subsequent calls are silently ignored.
pub fn setup_test() -> MutexGuard<'static, ()> {
    let guard = SIM_LOCK.lock().unwrap();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    guard
}
