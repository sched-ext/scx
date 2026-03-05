pub mod bench;
pub mod check;
pub mod child_guard;
pub mod death_pipe;
pub mod probe;
pub mod report;
pub mod run;
pub mod stress;
pub mod test_gate;
pub const TARGET_DIR: &str = "/tmp/pandemonium-build";
pub const LOG_DIR: &str = "/tmp/pandemonium";

pub fn binary_path() -> String {
    format!("{}/release/pandemonium", TARGET_DIR)
}

pub fn self_exe() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from(binary_path()))
}

pub fn is_scx_active() -> bool {
    std::fs::read_to_string("/sys/kernel/sched_ext/root/ops")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

pub fn wait_for_activation(timeout_secs: u64) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < timeout_secs {
        if is_scx_active() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}
