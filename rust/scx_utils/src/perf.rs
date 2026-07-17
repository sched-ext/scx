#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use libc::pid_t;
use std::os::raw::{c_int, c_ulong};

/// The `perf_event_open` system call.
///
/// See the [`perf_event_open(2) man page`][man] for details.
///
/// On error, this returns -1, and the C `errno` value (accessible via
/// `std::io::Error::last_os_error`) is set to indicate the error.
///
/// Note: The `attrs` argument needs to be a `*mut` because if the `size` field
/// is too small or too large, the kernel writes the size it was expecting back
/// into that field. It might do other things as well.
///
/// # Safety
///
/// The `attrs` argument must point to a properly initialized
/// `perf_event_attr` struct. The measurements and other behaviors its
/// contents request must be safe.
///
/// [man]: https://www.mankier.com/2/perf_event_open
pub unsafe fn perf_event_open(
    attrs: *mut bindings::perf_event_attr,
    pid: pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> c_int {
    unsafe {
        libc::syscall(
            bindings::__NR_perf_event_open as libc::c_long,
            attrs as *const bindings::perf_event_attr,
            pid,
            cpu,
            group_fd,
            flags,
        ) as c_int
    }
}

pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/perf_bindings.rs"));
}

pub mod ioctls {
    use crate::perf;
    use std::os::raw::{c_int, c_uint};

    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn enable(fd: c_int, arg: c_uint) -> c_int {
        unsafe { libc::ioctl(fd, perf::bindings::ENABLE as libc::Ioctl, arg) }
    }

    #[allow(clippy::missing_safety_doc)]
    pub unsafe fn reset(fd: c_int, arg: c_uint) -> c_int {
        unsafe { libc::ioctl(fd, perf::bindings::RESET as libc::Ioctl, arg) }
    }
}

use anyhow::Context as _;
use anyhow::Result;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;

/// Must match lib/pmu.bpf.c SCX_PMU_STRIDE for the perf_events map key layout.
pub const PERF_MAP_STRIDE: u32 = 4096;

/// Perf event specification: either hex (0xN) or a symbolic name (e.g.
/// cache-misses). `event_id` is the opaque id written to BPF rodata (it must
/// match between install and read); `type_`/`config` drive perf_event_open.
#[derive(Clone, Debug)]
pub struct PerfEventSpec {
    /// Opaque id for BPF (must match between install and read).
    pub event_id: u64,
    /// perf_event_attr.type (PERF_TYPE_RAW, PERF_TYPE_HARDWARE, etc.).
    pub type_: u32,
    /// perf_event_attr.config.
    pub config: u64,
    /// Original string for error messages.
    pub display_name: String,
}

fn parse_hardware_event(s: &str) -> Option<u64> {
    match s {
        "cpu-cycles" | "cycles" => Some(0),
        "instructions" => Some(1),
        "cache-references" => Some(2),
        "cache-misses" => Some(3),
        "branch-instructions" | "branches" => Some(4),
        "branch-misses" => Some(5),
        "bus-cycles" => Some(6),
        "stalled-cycles-frontend" | "idle-cycles-frontend" => Some(7),
        "stalled-cycles-backend" | "idle-cycles-backend" => Some(8),
        "ref-cycles" => Some(9),
        _ => None,
    }
}

fn parse_software_event(s: &str) -> Option<u64> {
    match s {
        "cpu-clock" => Some(0),
        "task-clock" => Some(1),
        "page-faults" | "faults" => Some(2),
        "context-switches" | "cs" => Some(3),
        "cpu-migrations" | "migrations" => Some(4),
        "minor-faults" => Some(5),
        "major-faults" => Some(6),
        "alignment-faults" => Some(7),
        "emulation-faults" => Some(8),
        "dummy" => Some(9),
        "bpf-output" => Some(10),
        _ => None,
    }
}

fn parse_hw_cache_event(s: &str) -> Option<u64> {
    let (cache_id, prefix_len) = if s.starts_with("L1-dcache-") {
        (0, 10)
    } else if s.starts_with("L1-icache-") {
        (1, 10)
    } else if s.starts_with("LLC-") {
        (2, 4)
    } else if s.starts_with("dTLB-") {
        (3, 5)
    } else if s.starts_with("iTLB-") {
        (4, 5)
    } else if s.starts_with("branch-") {
        (5, 7)
    } else if s.starts_with("node-") {
        (6, 5)
    } else {
        return None;
    };

    let suffix = &s[prefix_len..];
    let (op_id, result_id) = match suffix {
        "loads" => (0, 0),
        "load-misses" => (0, 1),
        "stores" => (1, 0),
        "store-misses" => (1, 1),
        "prefetches" => (2, 0),
        "prefetch-misses" => (2, 1),
        _ => return None,
    };

    Some((result_id << 16) | (op_id << 8) | cache_id)
}

/// Parse a perf event value: hex (0xN) or a symbolic name (e.g. cache-misses,
/// LLC-load-misses, page-faults). Intended for use as a clap `value_parser`.
pub fn parse_perf_event(s: &str) -> Result<PerfEventSpec, String> {
    let s = s.trim();
    if s.is_empty() || s == "0" || s.eq_ignore_ascii_case("0x0") {
        return Ok(PerfEventSpec {
            event_id: 0,
            type_: bindings::PERF_TYPE_RAW,
            config: 0,
            display_name: s.to_string(),
        });
    }

    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if let Ok(config) = u64::from_str_radix(hex_str, 16) {
            return Ok(PerfEventSpec {
                event_id: config,
                type_: bindings::PERF_TYPE_RAW,
                config,
                display_name: s.to_string(),
            });
        }
    }

    if let Some(config) = parse_hardware_event(s) {
        let event_id = (bindings::PERF_TYPE_HARDWARE as u64) << 32 | config;
        return Ok(PerfEventSpec {
            event_id,
            type_: bindings::PERF_TYPE_HARDWARE,
            config,
            display_name: s.to_string(),
        });
    }

    if let Some(config) = parse_software_event(s) {
        let event_id = (bindings::PERF_TYPE_SOFTWARE as u64) << 32 | config;
        return Ok(PerfEventSpec {
            event_id,
            type_: bindings::PERF_TYPE_SOFTWARE,
            config,
            display_name: s.to_string(),
        });
    }

    if let Some(config) = parse_hw_cache_event(s) {
        let event_id = (bindings::PERF_TYPE_HW_CACHE as u64) << 32 | config;
        return Ok(PerfEventSpec {
            event_id,
            type_: bindings::PERF_TYPE_HW_CACHE,
            config,
            display_name: s.to_string(),
        });
    }

    Err(format!(
        "Invalid perf event '{}': use hex (0xN) or a symbolic name (e.g. cache-misses, LLC-load-misses, page-faults)",
        s
    ))
}

/// Open a perf event on @cpu and register its fd in the given BPF PMU map (the
/// scheduler's `scx_pmu_map`) at the slot for (@cpu, @counter_idx). counter_idx
/// 0 is the migration event, 1 the sticky event, matching the PMU library
/// install order.
pub fn setup_perf_events(
    map: &impl MapCore,
    cpu: i32,
    spec: &PerfEventSpec,
    counter_idx: u32,
) -> Result<()> {
    if spec.event_id == 0 {
        return Ok(());
    }

    // `disabled` and `inherit` default to 0 via Default::default().
    let mut attrs = bindings::perf_event_attr {
        type_: spec.type_,
        config: spec.config,
        size: std::mem::size_of::<bindings::perf_event_attr>() as u32,
        ..Default::default()
    };

    let fd = unsafe { perf_event_open(&mut attrs, -1, cpu, -1, 0) };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "Failed to open perf event '{}' on CPU {}: {}",
            spec.display_name,
            cpu,
            err
        ));
    }

    let key = cpu as u32 + counter_idx * PERF_MAP_STRIDE;

    map.update(&key.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
        .with_context(|| "Failed to update perf_events map")?;

    Ok(())
}
