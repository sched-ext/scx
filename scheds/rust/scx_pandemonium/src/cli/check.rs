use std::io::Read;
use std::path::Path;
use std::process::Command;

use anyhow::Result;

fn check_tool(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn check_kernel_version() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            if major > 6 || (major == 6 && minor >= 12) {
                log_info!("Kernel {} (>= 6.12)", release);
                return true;
            }
            log_error!(
                "Kernel {}.{} is too old. PANDEMONIUM requires 6.12+.",
                major,
                minor
            );
            log_error!("sched_ext (CONFIG_SCHED_CLASS_EXT) was merged in Linux 6.12.");
            return false;
        }
    }
    log_warn!("Cannot parse kernel version from '{}'", release);
    false
}

fn check_vmlinux_cache() -> bool {
    let cache = Path::new("/tmp/pandemonium-vmlinux.h");
    if cache.exists() && cache.metadata().map(|m| m.len() > 1000).unwrap_or(false) {
        let size = cache.metadata().map(|m| m.len() / 1024).unwrap_or(0);
        log_info!("vmlinux.h cached ({size} KB)");
        return true;
    }
    log_warn!("vmlinux.h not cached (will be downloaded on first build)");
    true
}

fn check_kernel_config() -> bool {
    let file = match std::fs::File::open("/proc/config.gz") {
        Ok(f) => f,
        Err(_) => {
            log_warn!("/proc/config.gz not found (skipped)");
            return true;
        }
    };
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut config = String::new();
    if decoder.read_to_string(&mut config).is_err() {
        log_warn!("/proc/config.gz unreadable (skipped)");
        return true;
    }
    let found = config.contains("CONFIG_SCHED_CLASS_EXT=y");
    if found {
        log_info!("CONFIG_SCHED_CLASS_EXT=y found");
    } else {
        log_error!("CONFIG_SCHED_CLASS_EXT not found -- sched_ext may not be available");
    }
    found
}

pub fn run_check() -> Result<()> {
    log_info!("PANDEMONIUM dependency check");

    let mut ok = true;
    let tools = ["cargo", "rustc", "clang", "sudo"];
    for tool in &tools {
        if check_tool(tool) {
            log_info!("  {:<24}OK", tool);
        } else {
            log_error!("  {:<24}MISSING", tool);
            ok = false;
        }
    }

    log_info!("Kernel version:");
    if !check_kernel_version() {
        ok = false;
    }

    log_info!("Kernel config:");
    if !check_kernel_config() {
        ok = false;
    }

    log_info!("Build cache:");
    check_vmlinux_cache();

    let scx_path = Path::new("/sys/kernel/sched_ext/root/ops");
    if scx_path.exists() {
        let active = std::fs::read_to_string(scx_path).unwrap_or_default();
        let active = active.trim();
        if active.is_empty() {
            log_info!("sched_ext available (no scheduler active)");
        } else {
            log_info!("sched_ext active ({})", active);
        }
    } else {
        log_error!("sched_ext not available (sysfs path missing)");
        ok = false;
    }

    if ok {
        log_info!("All checks passed");
    } else {
        log_error!("Some checks failed");
        if !check_tool("cargo") || !check_tool("rustc") {
            log_info!("  Install Rust: https://rustup.rs");
        }
        if !check_tool("clang") {
            log_info!("  Install clang: pacman -S clang");
        }
        std::process::exit(1);
    }

    Ok(())
}
