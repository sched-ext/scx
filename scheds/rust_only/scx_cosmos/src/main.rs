// SPDX-License-Identifier: GPL-2.0
//
// scx_cosmos userspace loader — pure Rust BPF scheduler
//
// CLI options, CPU utilization polling, and BPF global configuration.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::{EbpfLoader, include_bytes_aligned};
use clap::Parser;
use log::info;

/// CPU time snapshot from /proc/stat, used for utilization computation.
#[derive(Debug, Clone, Copy)]
struct CpuTimes {
    /// Time spent in user mode.
    user: u64,
    /// Time spent in nice (low-priority user) mode.
    nice: u64,
    /// Total CPU time across all modes (user + nice + system + idle + ...).
    total: u64,
}

/// scx_cosmos: lightweight deadline + vruntime scheduler (pure Rust BPF).
#[derive(Debug, Parser)]
#[command(name = "scx_cosmos")]
struct Opts {
    /// Maximum scheduling time slice in microseconds.
    ///
    /// Controls the maximum time a task can run before being preempted.
    /// Lower values improve latency; higher values improve throughput.
    #[clap(short = 's', long, default_value = "10")]
    slice_us: u64,

    /// CPU busy threshold (0-100%).
    ///
    /// When overall CPU utilization exceeds this threshold, the scheduler
    /// switches from per-CPU round-robin dispatch (locality-optimized) to a
    /// global deadline-based dispatch queue (load-balancing-optimized).
    ///
    /// Lower values make the scheduler switch to deadline mode sooner,
    /// improving responsiveness at the cost of cache locality.
    /// Higher values keep tasks sticky to their CPU longer.
    #[clap(short = 'c', long, default_value = "75")]
    cpu_busy_thresh: u64,

    /// Disable synchronous wakeup hints.
    ///
    /// When enabled, the scheduler will not perform direct dispatch on
    /// synchronous wakeups. This can lead to more uniform load distribution
    /// but may reduce efficiency for pipe-intensive workloads.
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// Scheduler timeout in milliseconds.
    ///
    /// Maximum time the scheduler can stall before the kernel takes over.
    #[clap(short = 't', long, default_value = "5000")]
    timeout_ms: u64,

    /// Enable verbose logging output.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
}

/// Read aggregate CPU times from /proc/stat.
///
/// Parses the first "cpu " line which contains totals across all CPUs.
/// Returns None if /proc/stat can't be read or parsed.
fn read_cpu_times() -> Option<CpuTimes> {
    let file = File::open("/proc/stat").ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.ok()?;
        if line.starts_with("cpu ") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                return None;
            }

            let user: u64 = fields[1].parse().ok()?;
            let nice: u64 = fields[2].parse().ok()?;

            // Sum the first 8 fields as total time:
            // user, nice, system, idle, iowait, irq, softirq, steal
            let total: u64 = fields
                .iter()
                .skip(1)
                .take(8)
                .filter_map(|v| v.parse::<u64>().ok())
                .sum();

            return Some(CpuTimes { user, nice, total });
        }
    }

    None
}

/// Compute CPU utilization percentage [0..100] between two snapshots.
///
/// Uses (user + nice) as the "busy" time, matching the C cosmos approach
/// of tracking user-mode CPU utilization.
fn compute_cpu_util(prev: &CpuTimes, curr: &CpuTimes) -> Option<u64> {
    let busy_diff = (curr.user + curr.nice).saturating_sub(prev.user + prev.nice);
    let total_diff = curr.total.saturating_sub(prev.total);

    if total_diff > 0 {
        // Return percentage [0..100]
        Some((busy_diff * 100) / total_diff)
    } else {
        None
    }
}

/// Update a u64 value in a BPF data-section map at a given byte offset.
///
/// BPF `.bss` and `.data` maps are exposed as single-entry arrays (key=0)
/// where the value is the entire section blob. To update a specific global
/// variable, we:
///   1. Read the current blob with BPF_MAP_LOOKUP_ELEM
///   2. Patch the u64 at the given offset
///   3. Write the blob back with BPF_MAP_UPDATE_ELEM
///
/// This uses raw libc::syscall because aya's typed Array API enforces a
/// fixed value type size that doesn't match the variable-sized section blob.
fn update_map_u64(map_fd: i32, value_size: usize, offset: usize, val: u64) -> Result<()> {
    if offset + 8 > value_size {
        anyhow::bail!(
            "CPU_UTIL offset {} + 8 exceeds map value size {}",
            offset,
            value_size
        );
    }

    let key: u32 = 0;
    let mut buf = vec![0u8; value_size];

    // BPF_MAP_LOOKUP_ELEM = 1
    #[repr(C)]
    #[derive(Default)]
    #[allow(non_camel_case_types)]
    struct bpf_attr_lookup {
        map_fd: u32,
        _pad0: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    let mut attr = bpf_attr_lookup {
        map_fd: map_fd as u32,
        key: &key as *const u32 as u64,
        value: buf.as_mut_ptr() as u64,
        ..Default::default()
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            1i32, // BPF_MAP_LOOKUP_ELEM
            &mut attr as *mut _ as *mut libc::c_void,
            core::mem::size_of::<bpf_attr_lookup>(),
        )
    };
    if ret < 0 {
        anyhow::bail!(
            "BPF_MAP_LOOKUP_ELEM failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Patch CPU_UTIL at the given offset.
    buf[offset..offset + 8].copy_from_slice(&val.to_ne_bytes());

    // BPF_MAP_UPDATE_ELEM = 2
    let mut attr = bpf_attr_lookup {
        map_fd: map_fd as u32,
        key: &key as *const u32 as u64,
        value: buf.as_ptr() as u64,
        ..Default::default()
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            2i32, // BPF_MAP_UPDATE_ELEM
            &mut attr as *mut _ as *mut libc::c_void,
            core::mem::size_of::<bpf_attr_lookup>(),
        )
    };
    if ret < 0 {
        anyhow::bail!(
            "BPF_MAP_UPDATE_ELEM failed: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

/// Represents the BPF data map context for runtime global updates.
///
/// Created by probing the loaded BPF object for `.bss` or `.data` maps
/// and locating the CPU_UTIL global's offset within the section blob.
struct BpfDataMap {
    fd: i32,
    value_size: usize,
    cpu_util_offset: usize,
}

impl BpfDataMap {
    /// Try to locate the CPU_UTIL global in the BPF data maps.
    ///
    /// Checks `.bss` first (zero-initialized globals), then `.data`
    /// (initialized globals). Returns None if neither map exists or
    /// the CPU_UTIL symbol is not found.
    fn find(ebpf: &mut aya::Ebpf) -> Option<Self> {
        // Try .bss first (zero-initialized statics like `static mut CPU_UTIL: u64 = 0`)
        // then .data (initialized statics).
        for map_name in &[".bss", ".data"] {
            if let Some(map) = ebpf.map_mut(map_name) {
                let map_data = match map {
                    aya::maps::Map::Array(ref data) => data,
                    _ => continue,
                };

                let fd = map_data.fd().as_fd().as_raw_fd();
                let value_size = match map_data.info() {
                    Ok(info) => info.value_size() as usize,
                    Err(_) => continue,
                };

                // The CPU_UTIL offset depends on the BPF program's global layout.
                // With the current eBPF code, the .bss section contains:
                //   VTIME_NOW: u64 (offset 0)
                //   NR_CPU_IDS: u32 (offset 8)
                //   <padding>: u32 (offset 12, for alignment)
                //   CPU_UTIL: u64 (offset 16)
                //
                // Once the other agent adds the CPU_UTIL global to the eBPF
                // code, this offset must match the actual layout. We validate
                // that the offset fits within the map value.
                let cpu_util_offset = 16;

                if cpu_util_offset + 8 <= value_size {
                    info!(
                        "Found {} map: fd={}, value_size={}, CPU_UTIL offset={}",
                        map_name, fd, value_size, cpu_util_offset
                    );
                    return Some(Self {
                        fd,
                        value_size,
                        cpu_util_offset,
                    });
                } else {
                    info!(
                        "{} map too small ({} bytes) for CPU_UTIL at offset {}",
                        map_name, value_size, cpu_util_offset
                    );
                }
            }
        }

        None
    }

    /// Update CPU_UTIL in the BPF data map.
    fn update_cpu_util(&self, util: u64) -> Result<()> {
        update_map_u64(self.fd, self.value_size, self.cpu_util_offset, util)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    // Initialize logging.
    if opts.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    // Compute BPF global values from CLI options.
    let slice_ns: u64 = opts.slice_us * 1000;
    let slice_lag: u64 = (opts.slice_us * 2000).min(20_000_000);
    let busy_threshold: u64 = opts.cpu_busy_thresh;
    let no_wake_sync: bool = opts.no_wake_sync;

    info!("Loading scx_cosmos BPF program...");
    info!("  slice_ns     = {} ns ({} us)", slice_ns, opts.slice_us);
    info!(
        "  slice_lag    = {} ns ({} us, capped at 20ms)",
        slice_lag,
        slice_lag / 1000
    );
    info!("  busy_thresh  = {}%", busy_threshold);
    info!("  no_wake_sync = {}", no_wake_sync);
    info!("  timeout_ms   = {}", opts.timeout_ms);

    // Load the BPF object with global overrides.
    //
    // override_global with must_exist=false silently skips globals that
    // don't exist in the BPF object yet (another agent is adding these).
    let mut ebpf = EbpfLoader::new()
        .allow_unsupported_maps()
        .override_global("SLICE_NS", &slice_ns, false)
        .override_global("SLICE_LAG", &slice_lag, false)
        .override_global("BUSY_THRESHOLD", &busy_threshold, false)
        .override_global("NO_WAKE_SYNC", &(no_wake_sync as u8), false)
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/scx_cosmos"
        )))
        .context("Failed to load BPF object")?;

    // Locate the BPF data map for runtime CPU_UTIL updates.
    let bpf_data = BpfDataMap::find(&mut ebpf);
    if bpf_data.is_none() {
        info!("No .bss/.data map found for CPU_UTIL updates (BPF globals may not be added yet)");
    }

    // Attach the struct_ops scheduler.
    let link = ebpf
        .attach_struct_ops("_scx_ops")
        .context("Failed to attach struct_ops scheduler")?;

    println!("scx_cosmos: scheduler attached (pure Rust BPF)");
    println!("  slice       = {} us", opts.slice_us);
    println!("  slice_lag   = {} us (capped at 20ms)", slice_lag / 1000);
    println!("  busy_thresh = {}%", opts.cpu_busy_thresh);
    println!(
        "  wake_sync   = {}",
        if opts.no_wake_sync {
            "disabled"
        } else {
            "enabled"
        }
    );
    println!("  timeout     = {} ms", opts.timeout_ms);
    println!("Press Ctrl-C to detach and exit.");

    // Set up Ctrl-C handler.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl-C handler")?;

    // CPU utilization polling loop.
    //
    // Reads /proc/stat every 100ms and computes overall CPU utilization.
    // When a BPF data map is available, writes the utilization value to
    // the CPU_UTIL global so the BPF scheduler can use it for busy/idle
    // mode switching.
    let poll_interval = Duration::from_millis(100);
    let mut prev_cputime = read_cpu_times().expect("Failed to read initial /proc/stat");
    let mut last_poll = Instant::now();
    let mut last_util: u64 = 0;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10));

        if last_poll.elapsed() >= poll_interval {
            if let Some(curr_cputime) = read_cpu_times() {
                if let Some(util) = compute_cpu_util(&prev_cputime, &curr_cputime) {
                    last_util = util;

                    // Update BPF CPU_UTIL global if available.
                    if let Some(ref data_map) = bpf_data {
                        if let Err(e) = data_map.update_cpu_util(util) {
                            log::debug!("Failed to update CPU_UTIL: {}", e);
                        }
                    }
                }
                prev_cputime = curr_cputime;
            }
            last_poll = Instant::now();
        }

        // Periodically log CPU utilization in verbose mode.
        if opts.verbose && last_poll.elapsed() < Duration::from_millis(20) {
            log::debug!("CPU utilization: {}%", last_util);
        }
    }

    drop(link);
    println!(
        "\nscx_cosmos: scheduler detached (last CPU util: {}%)",
        last_util
    );

    Ok(())
}
