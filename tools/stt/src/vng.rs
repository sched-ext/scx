use anyhow::{Context, Result};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

// Lock-free PID tracking. Signal handler must never block on a mutex.
const MAX_CHILDREN: usize = 128;
static ACTIVE_PIDS: [AtomicI32; MAX_CHILDREN] = {
    const ZERO: AtomicI32 = AtomicI32::new(0);
    [ZERO; MAX_CHILDREN]
};

/// Kill a process and all its descendants.
fn kill_tree(pid: i32, sig: i32) {
    // Kill children first (depth-first) by reading /proc/{pid}/task/*/children
    if let Ok(children) = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
        for child_pid in children.split_whitespace() {
            if let Ok(cpid) = child_pid.parse::<i32>() {
                kill_tree(cpid, sig);
            }
        }
    }
    unsafe { libc::kill(pid, sig); }
}

pub fn install_signal_handler() {
    ctrlc::set_handler(|| {
        for slot in &ACTIVE_PIDS {
            let pid = slot.load(Ordering::SeqCst);
            if pid > 0 { kill_tree(pid, libc::SIGTERM); }
        }
        std::thread::sleep(Duration::from_secs(1));
        for slot in &ACTIVE_PIDS {
            let pid = slot.load(Ordering::SeqCst);
            if pid > 0 { kill_tree(pid, libc::SIGKILL); }
        }
        std::process::exit(130);
    }).ok();
}

fn track(child: &Child) {
    let pid = child.id() as i32;
    for slot in &ACTIVE_PIDS {
        if slot.compare_exchange(0, pid, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
            return;
        }
    }
}

fn untrack(child: &Child) {
    let pid = child.id() as i32;
    for slot in &ACTIVE_PIDS {
        if slot.compare_exchange(pid, 0, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
            return;
        }
    }
}

fn tracked_pids() -> Vec<i32> {
    ACTIVE_PIDS.iter()
        .map(|s| s.load(Ordering::SeqCst))
        .filter(|&p| p > 0)
        .collect()
}

#[derive(Debug, Clone)]
pub struct VngTopology { pub sockets: usize, pub cores_per_socket: usize, pub threads_per_core: usize }

impl VngTopology {
    pub fn total_cpus(&self) -> usize { self.sockets * self.cores_per_socket * self.threads_per_core }
    pub fn num_llcs(&self) -> usize { self.sockets }
}

#[derive(Debug, Clone)]
pub struct VngConfig {
    pub kernel: Option<String>,
    pub topology: VngTopology,
    pub memory_mb: usize,
    pub vng_args: Vec<String>,
    pub timeout: Option<Duration>,
}

impl Default for VngConfig {
    fn default() -> Self {
        Self { kernel: None, topology: VngTopology { sockets: 2, cores_per_socket: 2, threads_per_core: 2 },
               memory_mb: 4096, vng_args: vec![], timeout: None }
    }
}

#[derive(Debug)]
pub struct VngResult {
    pub success: bool,
    pub exit_code: i32,
    pub duration: Duration,
    pub timed_out: bool,
    pub output: String,
    pub stderr: String,
}

use std::os::unix::fs::PermissionsExt;
use std::sync::Once;

static STABLE_BIN_INIT: Once = Once::new();
static STABLE_BIN_PATH: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Copy stt binary once to a stable path so rebuilds don't break running VMs.
fn stable_stt_bin() -> Result<String> {
    STABLE_BIN_INIT.call_once(|| {
        if let Ok(exe) = std::env::current_exe() {
            let stable = format!("/tmp/stt-bin-{}", std::process::id());
            if std::fs::copy(&exe, &stable).is_ok() {
                let _ = std::fs::set_permissions(&stable, std::fs::Permissions::from_mode(0o755));
                *STABLE_BIN_PATH.lock().unwrap() = Some(stable);
            }
        }
    });
    STABLE_BIN_PATH.lock().unwrap().clone()
        .ok_or_else(|| anyhow::anyhow!("failed to create stable stt binary"))
}

pub fn run_in_vng(cfg: &VngConfig, stt_args: &[String]) -> Result<VngResult> {
    let stt_bin_str = stable_stt_bin()?;
    let t = &cfg.topology;

    let mut cmd = Command::new("vng");
    cmd.args(["-r", "--force", "--disable-microvm"]);
    cmd.args(["--cpus", &t.total_cpus().to_string()]);
    cmd.args(["--memory", &format!("{}M", cfg.memory_mb)]);
    cmd.args(["--qemu-opts", &format!("-smp {},sockets={},cores={},threads={}",
        t.total_cpus(), t.sockets, t.cores_per_socket, t.threads_per_core)]);

    for a in &cfg.vng_args { cmd.arg(a); }

    cmd.arg("--");
    cmd.arg(&stt_bin_str);
    for a in stt_args { cmd.arg(a); }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let timeout = cfg.timeout.unwrap_or(Duration::from_secs(3600));
    let start = Instant::now();
    let mut child = cmd.spawn().context("spawn vng")?;
    track(&child);

    use std::io::Read;
    let stdout_handle = child.stdout.take().map(|s| {
        std::thread::spawn(move || { let mut buf = String::new(); let _ = std::io::BufReader::new(s).read_to_string(&mut buf); buf })
    });
    let stderr_handle = child.stderr.take().map(|s| {
        std::thread::spawn(move || { let mut buf = String::new(); let _ = std::io::BufReader::new(s).read_to_string(&mut buf); buf })
    });

    let mut timed_out = false;
    let mut exit_status = None;
    loop {
        match child.try_wait()? {
            Some(status) => { exit_status = Some(status); break; }
            None => {}
        }
        if start.elapsed() > timeout {
            let pid = child.id() as i32;
            kill_tree(pid, libc::SIGTERM);
            std::thread::sleep(Duration::from_secs(2));
            kill_tree(pid, libc::SIGKILL);
            let _ = child.wait();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    untrack(&child);

    let output = stdout_handle.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = stderr_handle.and_then(|h| h.join().ok()).unwrap_or_default();
    let exit_code = exit_status.and_then(|s| s.code()).unwrap_or(-1);

    Ok(VngResult {
        success: !timed_out && exit_code == 0,
        exit_code,
        duration: start.elapsed(), timed_out, output, stderr,
    })
}

pub fn filter_vm_output(raw: &str) -> String {
    raw.lines()
        .filter(|l| !l.starts_with('[') && !l.contains("Kernel panic") && !l.contains("vpanic") && !l.contains("---[ end"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn parse_exit_code(raw: &str) -> i32 {
    raw.lines()
        .find_map(|l| l.strip_prefix("STT_EXIT=").and_then(|s| s.trim().parse::<i32>().ok()))
        .unwrap_or(-1)
}

pub fn compute_timeout(num_runs: usize, duration_s: u64) -> Duration {
    Duration::from_secs(10 + num_runs as u64 * (duration_s + 2) * 2)
}

pub struct TopoPreset { pub name: &'static str, pub description: &'static str, pub topology: VngTopology, pub memory_mb: usize }

pub fn gauntlet_presets() -> Vec<TopoPreset> {
    let defs: &[(&str, &str, usize, usize, usize, usize)] = &[
        ("tiny-1llc",     "4 CPUs, 1 LLC",                    1,  4,  1,   512),
        ("tiny-2llc",     "4 CPUs, 2 LLCs",                   2,  2,  1,   512),
        ("odd-3llc",      "9 CPUs, 3 LLCs (odd)",             3,  3,  1,   512),
        ("odd-5llc",      "15 CPUs, 5 LLCs (prime)",          5,  3,  1,   512),
        ("odd-7llc",      "14 CPUs, 7 LLCs (prime)",          7,  2,  1,   512),
        ("smt-2llc",      "8 CPUs, 2 LLCs with SMT",          2,  2,  2,   512),
        ("smt-3llc",      "12 CPUs, 3 LLCs with SMT",         3,  2,  2,   512),
        ("medium-4llc",   "32 CPUs, 4 LLCs",                  4,  4,  2,  1024),
        ("medium-8llc",   "64 CPUs, 8 LLCs",                  8,  4,  2,  1024),
        ("large-4llc",    "128 CPUs, 4 LLCs",                 4, 16,  2,  2048),
        ("large-8llc",    "128 CPUs, 8 LLCs",                 8,  8,  2,  2048),
        ("near-max-llc",  "240 CPUs, 15 LLCs (near max)",    15,  8,  2,  2048),
        ("max-cpu",       "252 CPUs, 14 LLCs (near i440fx limit)", 14, 9, 2, 4096),
    ];
    defs.iter().map(|&(n, d, s, c, t, m)| TopoPreset {
        name: n, description: d, topology: VngTopology { sockets: s, cores_per_socket: c, threads_per_core: t }, memory_mb: m,
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_timeout_basic() {
        assert_eq!(compute_timeout(1, 20), Duration::from_secs(10 + 1 * (20 + 2) * 2));
    }

    #[test]
    fn compute_timeout_multiple_runs() {
        assert_eq!(compute_timeout(5, 15), Duration::from_secs(10 + 5 * (15 + 2) * 2));
    }

    #[test]
    fn vng_topology_total_cpus() {
        let t = VngTopology { sockets: 2, cores_per_socket: 4, threads_per_core: 2 };
        assert_eq!(t.total_cpus(), 16);
    }

    #[test]
    fn vng_topology_num_llcs() {
        let t = VngTopology { sockets: 3, cores_per_socket: 4, threads_per_core: 2 };
        assert_eq!(t.num_llcs(), 3);
    }

    #[test]
    fn gauntlet_presets_count() {
        assert_eq!(gauntlet_presets().len(), 13);
    }

    #[test]
    fn gauntlet_presets_unique_names() {
        let p = gauntlet_presets();
        let names: Vec<&str> = p.iter().map(|p| p.name).collect();
        let unique: std::collections::HashSet<&&str> = names.iter().collect();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn gauntlet_presets_total_cpus_match() {
        for p in &gauntlet_presets() {
            let cpus = p.topology.total_cpus();
            assert!(p.description.contains(&cpus.to_string()),
                "{}: description '{}' doesn't mention {} CPUs", p.name, p.description, cpus);
        }
    }

    #[test]
    fn vng_config_default() {
        let c = VngConfig::default();
        assert_eq!(c.topology.total_cpus(), 8);
        assert_eq!(c.memory_mb, 4096);
        assert!(c.kernel.is_none());
        assert!(c.timeout.is_none());
    }

    #[test]
    fn filter_vm_output_removes_kernel_lines() {
        let raw = "[    0.1] boot msg\nHELLO\n[    0.2] more boot\nSTT_EXIT=0\n[    0.3] Kernel panic - not syncing";
        let filtered = filter_vm_output(raw);
        assert!(filtered.contains("HELLO"));
        assert!(filtered.contains("STT_EXIT=0"));
        assert!(!filtered.contains("boot msg"));
        assert!(!filtered.contains("Kernel panic"));
    }

    #[test]
    fn filter_vm_output_removes_vpanic() {
        let raw = "output line\n vpanic+0x32d/0x380\nmore output";
        let filtered = filter_vm_output(raw);
        assert!(!filtered.contains("vpanic"));
        assert!(filtered.contains("output line"));
        assert!(filtered.contains("more output"));
    }

    #[test]
    fn filter_vm_output_removes_end_trace() {
        let raw = "good\n---[ end Kernel panic\nbad";
        let filtered = filter_vm_output(raw);
        assert!(filtered.contains("good"));
        assert!(!filtered.contains("---[ end"));
    }

    #[test]
    fn filter_vm_output_empty() {
        assert_eq!(filter_vm_output(""), "");
    }

    #[test]
    fn parse_exit_code_success() {
        assert_eq!(parse_exit_code("STT_EXIT=0\n"), 0);
    }

    #[test]
    fn parse_exit_code_failure() {
        assert_eq!(parse_exit_code("some output\nSTT_EXIT=1\npoweroff"), 1);
    }

    #[test]
    fn parse_exit_code_missing() {
        assert_eq!(parse_exit_code("no exit code here"), -1);
    }

    #[test]
    fn parse_exit_code_in_noise() {
        assert_eq!(parse_exit_code("[0.1] boot\nSTT_EXIT=42\n[0.2] panic"), 42);
    }

    #[test]
    fn parse_exit_code_non_numeric() {
        assert_eq!(parse_exit_code("STT_EXIT=abc"), -1);
    }

    #[test]
    fn gauntlet_presets_memory_sane() {
        for p in &gauntlet_presets() {
            assert!(p.memory_mb >= 512, "{} has too little memory: {}MB", p.name, p.memory_mb);
            let cpus = p.topology.total_cpus();
            assert!(p.memory_mb >= cpus * 8, "{} has {}MB for {} CPUs", p.name, p.memory_mb, cpus);
        }
    }

    // -- lock-free PID tracking tests --

    fn clear_all_slots() {
        for slot in &ACTIVE_PIDS { slot.store(0, Ordering::SeqCst); }
    }

    #[test]
    fn track_untrack_basic() {
        clear_all_slots();
        // Spawn a sleep process to get a real Child
        let child = Command::new("sleep").arg("999").spawn().unwrap();
        let pid = child.id() as i32;
        track(&child);
        assert!(tracked_pids().contains(&pid));
        untrack(&child);
        assert!(!tracked_pids().contains(&pid));
        // Clean up
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        clear_all_slots();
    }

    #[test]
    fn track_multiple() {
        clear_all_slots();
        let mut children: Vec<_> = (0..4).map(|_| Command::new("sleep").arg("999").spawn().unwrap()).collect();
        let pids: Vec<i32> = children.iter().map(|c| c.id() as i32).collect();
        for c in &children { track(c); }
        let tracked = tracked_pids();
        for pid in &pids { assert!(tracked.contains(pid), "missing pid {pid}"); }

        // Untrack first two
        untrack(&children[0]);
        untrack(&children[1]);
        let tracked = tracked_pids();
        assert!(!tracked.contains(&pids[0]));
        assert!(!tracked.contains(&pids[1]));
        assert!(tracked.contains(&pids[2]));
        assert!(tracked.contains(&pids[3]));

        for c in &mut children { let _ = c.kill(); let _ = c.wait(); }
        clear_all_slots();
    }

    #[test]
    fn tracked_pids_empty_initially() {
        clear_all_slots();
        assert!(tracked_pids().is_empty());
    }

    #[test]
    fn signal_handler_kills_tracked() {
        clear_all_slots();
        let mut child = Command::new("sleep").arg("999").spawn().unwrap();
        let pid = child.id() as i32;
        track(&child);
        // Simulate what the signal handler does (without exit)
        for slot in &ACTIVE_PIDS {
            let p = slot.load(Ordering::SeqCst);
            if p > 0 { unsafe { libc::kill(p, libc::SIGTERM); } }
        }
        std::thread::sleep(Duration::from_millis(100));
        let status = child.try_wait().unwrap();
        assert!(status.is_some(), "tracked child should be dead after SIGTERM");
        untrack(&child);
        let _ = child.wait();
        clear_all_slots();
    }
}
