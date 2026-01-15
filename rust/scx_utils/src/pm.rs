// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{anyhow, Result};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

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

    let path = format!("/sys/devices/system/cpu/cpu{cpu_num}/power/pm_qos_resume_latency_us");

    let mut file = File::create(Path::new(&path))?;
    write!(file, "{value_us}")?;
    Ok(())
}

/// Returns if idle resume latency is supported.
pub fn cpu_idle_resume_latency_supported() -> bool {
    std::fs::exists("/sys/devices/system/cpu/cpu0/power/pm_qos_resume_latency_us").unwrap_or(false)
}

const INTEL_UNCORE_FREQ_PATH: &str = "/sys/devices/system/cpu/intel_uncore_frequency";

/// Returns if Intel uncore frequency control is supported.
pub fn uncore_freq_supported() -> bool {
    std::fs::exists(INTEL_UNCORE_FREQ_PATH).unwrap_or(false)
}

/// Gets the initial max uncore frequency for a package/die in kHz.
pub fn get_uncore_max_freq_khz(package: u32, die: u32) -> Result<u32> {
    let path = format!(
        "{}/package_{:02}_die_{:02}/initial_max_freq_khz",
        INTEL_UNCORE_FREQ_PATH, package, die
    );
    let content = std::fs::read_to_string(&path)?;
    content
        .trim()
        .parse()
        .map_err(|e| anyhow!("Failed to parse uncore freq: {}", e))
}

/// Gets the initial min uncore frequency for a package/die in kHz.
pub fn get_uncore_min_freq_khz(package: u32, die: u32) -> Result<u32> {
    let path = format!(
        "{}/package_{:02}_die_{:02}/initial_min_freq_khz",
        INTEL_UNCORE_FREQ_PATH, package, die
    );
    let content = std::fs::read_to_string(&path)?;
    content
        .trim()
        .parse()
        .map_err(|e| anyhow!("Failed to parse uncore freq: {}", e))
}

/// Sets the max uncore frequency for a package/die in kHz.
pub fn set_uncore_max_freq_khz(package: u32, die: u32, freq_khz: u32) -> Result<()> {
    let path = format!(
        "{}/package_{:02}_die_{:02}/max_freq_khz",
        INTEL_UNCORE_FREQ_PATH, package, die
    );
    let mut file = File::create(Path::new(&path))?;
    write!(file, "{freq_khz}")?;
    Ok(())
}

/// Iterates over all package/die combinations and applies a function.
pub fn for_each_uncore_domain<F>(mut f: F) -> Result<()>
where
    F: FnMut(u32, u32) -> Result<()>,
{
    let entries = std::fs::read_dir(INTEL_UNCORE_FREQ_PATH)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix("package_") {
            let parts: Vec<&str> = rest.split("_die_").collect();
            if parts.len() == 2 {
                if let (Ok(pkg), Ok(die)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    f(pkg, die)?;
                }
            }
        }
    }
    Ok(())
}

const INTEL_PSTATE_PATH: &str = "/sys/devices/system/cpu/intel_pstate";

/// Returns if Intel pstate turbo control is supported.
pub fn turbo_supported() -> bool {
    std::fs::exists(format!("{}/no_turbo", INTEL_PSTATE_PATH)).unwrap_or(false)
}

/// Gets current turbo state (true = turbo enabled).
pub fn get_turbo_enabled() -> Result<bool> {
    let content = std::fs::read_to_string(format!("{}/no_turbo", INTEL_PSTATE_PATH))?;
    Ok(content.trim() == "0")
}

/// Sets turbo state (true = enable turbo).
pub fn set_turbo_enabled(enabled: bool) -> Result<()> {
    let value = if enabled { "0" } else { "1" };
    std::fs::write(format!("{}/no_turbo", INTEL_PSTATE_PATH), value)?;
    Ok(())
}

/// Returns if EPP (Energy Performance Preference) is supported.
pub fn epp_supported() -> bool {
    std::fs::exists("/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference")
        .unwrap_or(false)
}

/// Gets EPP for a CPU.
pub fn get_epp(cpu: usize) -> Result<String> {
    let path = format!(
        "/sys/devices/system/cpu/cpu{}/cpufreq/energy_performance_preference",
        cpu
    );
    Ok(std::fs::read_to_string(&path)?.trim().to_string())
}

/// Sets EPP for a CPU. Valid values: default, performance, balance_performance, balance_power, power
pub fn set_epp(cpu: usize, epp: &str) -> Result<()> {
    let path = format!(
        "/sys/devices/system/cpu/cpu{}/cpufreq/energy_performance_preference",
        cpu
    );
    std::fs::write(&path, epp)?;
    Ok(())
}
