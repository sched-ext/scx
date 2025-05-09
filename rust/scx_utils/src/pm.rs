// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Result};
use glob::glob;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::misc::read_from_file;

/// Updates the global idle resume latency. When the returned file is closed the request is
/// dropped. See the following kernel docs for more details:
/// https://www.kernel.org/doc/html/latest/admin-guide/pm/cpuidle.html#power-management-quality-of-service-for-cpus
pub fn update_global_idle_resume_latency(value_us: i32) -> Result<File> {
    if value_us < 0 {
        return Err(anyhow!("Latency value must be non-negative"));
    }

    let mut file = OpenOptions::new()
        .write(true)
        .open("/dev/cpu_dma_latency")?;
    let bytes = value_us.to_le_bytes(); // Convert to little-endian bytes
    file.write_all(&bytes)?;
    Ok(file) // return file descriptor so it can be closed later
}

/// Updates per cpu idle resume latency.
pub fn update_cpu_idle_resume_latency(cpu_num: usize, value_us: i32) -> Result<()> {
    if value_us < 0 {
        return Err(anyhow!("Latency value must be non-negative"));
    }

    let path = format!(
        "/sys/devices/system/cpu/cpu{}/power/pm_qos_resume_latency_us",
        cpu_num
    );

    let mut file = File::create(Path::new(&path))?;
    write!(file, "{}", value_us)?;
    Ok(())
}

/// Returns if idle resume latency is supported.
pub fn cpu_idle_resume_latency_supported() -> bool {
    std::fs::exists("/sys/devices/system/cpu/cpu0/power/pm_qos_resume_latency_us").unwrap_or(false)
}

/// Updates per cpu idle state disable flag.
/// If state1 is disabled, state2 & state3 are also disabled.
pub fn update_cpuidle_state(cpu_num: usize, state: u32, disable: bool) -> Result<()> {
    let cpuidle_str = format!("/sys/devices/system/cpu/cpu{}/cpuidle/state{}/disable", cpu_num, state);
    let cpuidle_path = Path::new(&cpuidle_str);

    if !cpuidle_path.exists() {
        return Err(anyhow!("cpuidle/state{} does not exist", state));
    }

    let mut file = File::create(cpuidle_path)?;
    write!(file, "{}", if disable {1} else {0})?;
    Ok(())
}

/// Clear all CPU idle state disable flag
pub fn clear_all_cpuidle_states() -> Result<()> {
    let paths = glob("/sys/devices/system/cpu/cpu[0-9]*/cpuidle/state[0-9]*/disable")?;
    for path in paths.filter_map(Result::ok) {
        let mut file = File::create(path)?;
        write!(file, "0")?;
    }
    Ok(())
}

/// True if all CPU idle state disable flag is 0
pub fn all_cpuidle_state_enabled() -> Result<bool> {
    let paths = glob("/sys/devices/system/cpu/cpu[0-9]*/cpuidle/state[0-9]*/disable")?;
    for path in paths.filter_map(Result::ok) {
        let disable: usize = read_from_file(&path)?;
        if disable != 0 {
            return Ok(false);
        }
    }
    return Ok(true);
}

pub fn cpuidle_state_supported() -> bool {
    std::fs::exists("/sys/devices/system/cpu/cpu0/cpuidle/state0/disable").unwrap_or(false)
}
