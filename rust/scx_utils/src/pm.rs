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
