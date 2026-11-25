// SPDX-License-Identifier: GPL-2.0
//! Idle state limits of --performance.
//!
//! A CPU that wakes up from an idle state first has to leave it, and the
//! deeper the state, the longer that takes. Even the shallowest one costs
//! a little on every wakeup, and a game wakes its threads up thousands of
//! times per second. With --performance, the CPUs that the BPF side counts
//! as busy get a PM QoS resume latency limit of zero, written as "n/a",
//! which leaves the idle governor nothing but polling. Polling burns power,
//! so CPUs that are not busy get their old limit back and may sleep as
//! deeply as before.
//!
//! The old limits are written back when the scheduler stops or restarts.
//! They are also saved in a file under /run, so that the next start writes
//! them back when the scheduler was killed before it could.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::fs;
use std::path::Path;

use log::info;
use log::warn;

/// The limits that IdleLimits may replace, one "path value" line each. /run
/// is emptied at boot, which also resets the limits.
const SAVED_LIMITS: &str = "/run/scx_flow/pmqos";

/// The limit of a busy CPU: no exit latency at all, so it only polls.
const BUSY_LIMIT: &str = "n/a";

fn limit_path(cpu: usize) -> String {
    format!("/sys/devices/system/cpu/cpu{cpu}/power/pm_qos_resume_latency_us")
}

/// Whether @path is the PM QoS resume latency file of a CPU.
fn is_limit_path(path: &str) -> bool {
    path.strip_prefix("/sys/devices/system/cpu/cpu")
        .and_then(|rest| rest.strip_suffix("/power/pm_qos_resume_latency_us"))
        .is_some_and(|cpu| !cpu.is_empty() && cpu.bytes().all(|b| b.is_ascii_digit()))
}

/// Parse the contents of SAVED_LIMITS, skipping lines that do not name the
/// limit file of a CPU.
fn parse_saved(saved: &str) -> Vec<(&str, &str)> {
    saved
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(path, _)| is_limit_path(path))
        .collect()
}

/// Remove SAVED_LIMITS, and its directory once nothing else is in it.
fn forget_saved_limits() {
    let path = Path::new(SAVED_LIMITS);
    if let Err(e) = fs::remove_file(path) {
        warn!("failed to remove {SAVED_LIMITS}: {e}");
    }
    if let Some(dir) = path.parent() {
        let _ = fs::remove_dir(dir);
    }
}

/// Write back the limits that a scheduler which was killed left behind.
/// The file is kept if any of them cannot be written back.
pub fn restore_saved_limits() {
    let Ok(saved) = fs::read_to_string(SAVED_LIMITS) else {
        return;
    };
    let mut restored = 0;
    let mut failed = false;
    for (path, old) in parse_saved(&saved) {
        if fs::read_to_string(path).is_ok_and(|cur| cur.trim() == old) {
            continue;
        }
        match fs::write(path, old) {
            Ok(()) => restored += 1,
            Err(e) => {
                warn!("failed to restore {old} in {path}: {e}");
                failed = true;
            }
        }
    }
    if restored > 0 {
        info!("restored the idle state limits of {restored} CPUs left behind by an earlier run");
    }
    if !failed {
        forget_saved_limits();
    }
}

struct CpuLimit {
    cpu: usize,
    path: String,
    /// The limit the CPU had before.
    old: String,
    limited: bool,
}

impl CpuLimit {
    /// Apply the busy limit or the old one. Returns whether it holds now.
    fn set(&mut self, limited: bool) -> bool {
        if self.limited == limited {
            return true;
        }
        let value = if limited { BUSY_LIMIT } else { &self.old };
        match fs::write(&self.path, value) {
            Ok(()) => {
                self.limited = limited;
                true
            }
            Err(e) => {
                warn!("failed to write {value} to {}: {e}", self.path);
                false
            }
        }
    }
}

/// The busy CPUs only poll while idle, see the module comment. The old
/// limits are written back when dropped.
pub struct IdleLimits {
    cpus: Vec<CpuLimit>,
}

impl IdleLimits {
    /// Prepare to limit @cpus. CPUs without a limit file are left alone, and
    /// so is every CPU if the old limits cannot be saved, or if an earlier
    /// run left limits behind that could not be written back. The current
    /// limits are not the old ones then.
    pub fn new(cpus: Vec<usize>) -> Self {
        if Path::new(SAVED_LIMITS).exists() {
            warn!(
                "{SAVED_LIMITS} is left from an earlier run, leaving the idle state limits alone"
            );
            return Self { cpus: Vec::new() };
        }
        let mut cpus: Vec<CpuLimit> = cpus
            .into_iter()
            .filter_map(|cpu| {
                let path = limit_path(cpu);
                let old = fs::read_to_string(&path).ok()?.trim().to_string();
                Some(CpuLimit {
                    cpu,
                    path,
                    old,
                    limited: false,
                })
            })
            .collect();
        let saved: String = cpus
            .iter()
            .map(|c| format!("{} {}\n", c.path, c.old))
            .collect();
        let dir = Path::new(SAVED_LIMITS).parent();
        if !cpus.is_empty()
            && let Err(e) = dir
                .map_or(Ok(()), fs::create_dir_all)
                .and_then(|()| fs::write(SAVED_LIMITS, saved))
        {
            warn!(
                "failed to save the idle state limits to {SAVED_LIMITS}, leaving them alone: {e}"
            );
            cpus.clear();
        }
        Self { cpus }
    }

    /// Limit the CPUs for which @busy is true and give the others their old
    /// limit back.
    pub fn update(&mut self, busy: impl Fn(usize) -> bool) {
        for c in self.cpus.iter_mut() {
            c.set(busy(c.cpu));
        }
    }
}

impl Drop for IdleLimits {
    fn drop(&mut self) {
        if self.cpus.is_empty() {
            return;
        }
        let mut restored = true;
        for c in self.cpus.iter_mut() {
            restored &= c.set(false);
        }
        if restored {
            forget_saved_limits();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_lines() {
        let saved = "/sys/devices/system/cpu/cpu0/power/pm_qos_resume_latency_us 0\n\
                     /sys/devices/system/cpu/cpu12/power/pm_qos_resume_latency_us n/a\n\
                     /sys/devices/system/cpu/cpu/power/pm_qos_resume_latency_us 0\n\
                     /etc/passwd 0\n\
                     garbage\n";
        assert_eq!(
            parse_saved(saved),
            [
                (
                    "/sys/devices/system/cpu/cpu0/power/pm_qos_resume_latency_us",
                    "0"
                ),
                (
                    "/sys/devices/system/cpu/cpu12/power/pm_qos_resume_latency_us",
                    "n/a"
                ),
            ]
        );
    }
}
