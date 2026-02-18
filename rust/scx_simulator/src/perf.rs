//! Minimal PMU-based Retired Branch Conditional (RBC) counter.
//!
//! Provides a deterministic, architecture-grounded measure of scheduler overhead
//! by counting retired conditional branches during scheduler C code execution.
//! Each retired conditional branch maps to a configurable number of nanoseconds.
//!
//! CPU detection covers Intel (family 0x06) and AMD Zen 1-5 (families 0x17/0x19/0x1A).
//!
//! Extracted from Reverie (BSD-2-Clause). Only the minimal subset needed:
//! open → reset → enable → disable → read.

use std::fmt;
use std::io;
use std::os::unix::io::RawFd;

use perf_event_open_sys as perf;

/// Errors from PMU counter operations.
#[derive(Debug)]
pub enum PerfError {
    /// The CPU architecture is not supported for RBC counting.
    UnsupportedCpu,
    /// `perf_event_open` syscall failed.
    Open(io::Error),
    /// ioctl on the perf fd failed.
    Ioctl(io::Error),
    /// read on the perf fd failed.
    Read(io::Error),
}

impl fmt::Display for PerfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PerfError::UnsupportedCpu => write!(f, "CPU does not support RBC counting"),
            PerfError::Open(e) => write!(f, "perf_event_open failed: {e}"),
            PerfError::Ioctl(e) => write!(f, "perf ioctl failed: {e}"),
            PerfError::Read(e) => write!(f, "perf read failed: {e}"),
        }
    }
}

/// PMU configuration for retired conditional branches.
///
/// Holds the raw `perf_event_attr.config` value detected via CPUID.
pub struct PmuConfig {
    /// Raw event selector (umask<<8 | event, for PERF_TYPE_RAW).
    pub rcb_event: u64,
}

/// CPUID vendor and family info extracted from leaf 0x0 and 0x1.
struct CpuIdInfo {
    vendor: [u8; 12],
    family: u32,
}

impl CpuIdInfo {
    /// Query CPUID to get vendor string and full family ID.
    fn detect() -> Self {
        // CPUID leaf 0: vendor string in EBX:EDX:ECX
        let leaf0 = unsafe { std::arch::x86_64::__cpuid(0) };
        let mut vendor = [0u8; 12];
        vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());

        // CPUID leaf 1: family/model in EAX
        let leaf1 = unsafe { std::arch::x86_64::__cpuid(1) };
        let eax = leaf1.eax;
        let base_family = (eax >> 8) & 0xF;
        let ext_family = (eax >> 20) & 0xFF;
        // Full family = base + extended (AMD convention for family >= 0x0F)
        let family = if base_family == 0x0F {
            base_family + ext_family
        } else {
            base_family
        };

        CpuIdInfo { vendor, family }
    }

    fn vendor_str(&self) -> &str {
        std::str::from_utf8(&self.vendor).unwrap_or("")
    }
}

impl PmuConfig {
    /// Detect the RBC event for the current CPU via CPUID.
    ///
    /// Returns `None` if the CPU family/vendor is not recognized.
    pub fn detect() -> Option<Self> {
        let info = CpuIdInfo::detect();

        let rcb_event = match info.vendor_str() {
            "GenuineIntel" if info.family == 0x06 => {
                // Intel: BR_INST_RETIRED.COND — event=0xC4, umask=0x01
                0x01c4
            }
            "AuthenticAMD" => match info.family {
                // Zen 1-2 (family 0x17), Zen 3-4 (0x19), Zen 5 (0x1A)
                0x17 | 0x19 | 0x1A => 0x00d1, // RETIRED_COND_BRANCH
                _ => return None,
            },
            _ => return None,
        };

        Some(PmuConfig { rcb_event })
    }
}

/// A PMU counter for retired conditional branches.
///
/// Wraps a `perf_event_open` file descriptor. The counter is pinned to the
/// current thread and CPU-independent (it follows the thread).
pub struct RbcCounter {
    fd: RawFd,
}

impl RbcCounter {
    /// Open a new RBC counter for the current thread.
    ///
    /// The counter starts disabled; call [`enable`](Self::enable) to start counting.
    pub fn new(config: &PmuConfig) -> Result<Self, PerfError> {
        let mut attr = perf::bindings::perf_event_attr {
            type_: perf::bindings::PERF_TYPE_RAW,
            size: std::mem::size_of::<perf::bindings::perf_event_attr>() as u32,
            config: config.rcb_event,
            ..Default::default()
        };
        attr.set_disabled(1);
        attr.set_exclude_kernel(1);
        attr.set_exclude_hv(1);

        // pid=0 (current thread), cpu=-1 (any CPU)
        let fd = unsafe { perf::perf_event_open(&mut attr, 0, -1, -1, 0) };
        if fd < 0 {
            return Err(PerfError::Open(io::Error::last_os_error()));
        }

        Ok(RbcCounter { fd })
    }

    /// Enable the counter.
    pub fn enable(&self) -> Result<(), PerfError> {
        let ret = unsafe {
            libc::ioctl(
                self.fd,
                perf::bindings::ENABLE as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(PerfError::Ioctl(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Disable the counter.
    pub fn disable(&self) -> Result<(), PerfError> {
        let ret = unsafe {
            libc::ioctl(
                self.fd,
                perf::bindings::DISABLE as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(PerfError::Ioctl(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Reset the counter to zero.
    pub fn reset(&self) -> Result<(), PerfError> {
        let ret = unsafe {
            libc::ioctl(
                self.fd,
                perf::bindings::RESET as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(PerfError::Ioctl(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Read the current counter value.
    pub fn read(&self) -> Result<u64, PerfError> {
        let mut count: u64 = 0;
        let ret = unsafe {
            libc::read(
                self.fd,
                &mut count as *mut u64 as *mut libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            return Err(PerfError::Read(io::Error::last_os_error()));
        }
        Ok(count)
    }
}

impl Drop for RbcCounter {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Try to create an RBC counter, returning `None` with a warning if unavailable.
///
/// This is the recommended entry point: it handles CPU detection failure and
/// perf_event_open permission errors gracefully.
pub fn try_create_rbc_counter() -> Option<RbcCounter> {
    let config = match PmuConfig::detect() {
        Some(c) => c,
        None => {
            tracing::warn!("RBC counter: CPU not supported (no CPUID match)");
            return None;
        }
    };
    match RbcCounter::new(&config) {
        Ok(counter) => Some(counter),
        Err(e) => {
            tracing::warn!("RBC counter unavailable: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pmu_detect() {
        // Just verify detection doesn't panic; it may return None on unsupported CPUs
        let _config = PmuConfig::detect();
    }

    #[test]
    fn test_rbc_counter_lifecycle() {
        let config = match PmuConfig::detect() {
            Some(c) => c,
            None => {
                eprintln!("skipping RBC test: unsupported CPU");
                return;
            }
        };

        let counter = match RbcCounter::new(&config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping RBC test: {e}");
                return;
            }
        };

        // Basic lifecycle: reset → enable → disable → read
        counter.reset().unwrap();
        counter.enable().unwrap();

        // Do some work to generate conditional branches
        let mut sum = 0u64;
        for i in 0..1000 {
            if i % 2 == 0 {
                sum += i;
            }
        }
        // Prevent optimization
        std::hint::black_box(sum);

        counter.disable().unwrap();
        let count = counter.read().unwrap();
        // Should have counted some conditional branches
        assert!(count > 0, "expected non-zero RBC count, got {count}");
    }

    #[test]
    fn test_try_create_rbc_counter() {
        // Should not panic regardless of platform
        let _counter = try_create_rbc_counter();
    }
}
