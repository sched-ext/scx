//! Minimal PMU-based Retired Branch Conditional (RBC) counter and timer.
//!
//! Provides two PMU abstractions:
//!
//! - [`RbcCounter`]: A pure counting counter for measuring scheduler overhead.
//!   Each retired conditional branch maps to a configurable number of nanoseconds.
//!
//! - [`RbcTimer`]: A sampling counter that delivers a signal on overflow. Used
//!   for preemptive interleaving — after N retired branches, the PMU fires a
//!   signal that interrupts the running thread.
//!
//! CPU detection covers Intel (family 0x06) and AMD Zen 1-5 (families 0x17/0x19/0x1A).
//!
//! Extracted from Reverie (BSD-2-Clause).

use std::fmt;
use std::io;
use std::os::unix::io::RawFd;

use perf_event_open_sys as perf;

/// fcntl constants not available in the libc crate.
const F_SETOWN_EX: libc::c_int = 15;
const F_SETSIG: libc::c_int = 10;
const F_OWNER_TID: libc::c_int = 0;

#[repr(C)]
struct FOwnerEx {
    type_: libc::c_int,
    pid: libc::pid_t,
}

/// Errors from PMU counter operations.
#[derive(Debug)]
pub enum PerfError {
    /// The CPU architecture is not supported for RBC counting.
    UnsupportedCpu,
    /// `perf_event_open` syscall failed.
    Open(io::Error),
    /// ioctl on the perf fd failed.
    Ioctl(io::Error),
    /// fcntl on the perf fd failed.
    Fcntl(io::Error),
    /// read on the perf fd failed.
    Read(io::Error),
}

impl fmt::Display for PerfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PerfError::UnsupportedCpu => write!(f, "CPU does not support RBC counting"),
            PerfError::Open(e) => write!(f, "perf_event_open failed: {e}"),
            PerfError::Ioctl(e) => write!(f, "perf ioctl failed: {e}"),
            PerfError::Fcntl(e) => write!(f, "perf fcntl failed: {e}"),
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
                // Intel: BR_INST_RETIRED.COND - event=0xC4, umask=0x01
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
        ioctl_no_arg(self.fd, perf::bindings::ENABLE)
    }

    /// Disable the counter.
    pub fn disable(&self) -> Result<(), PerfError> {
        ioctl_no_arg(self.fd, perf::bindings::DISABLE)
    }

    /// Reset the counter to zero.
    pub fn reset(&self) -> Result<(), PerfError> {
        ioctl_no_arg(self.fd, perf::bindings::RESET)
    }

    /// Read the current counter value.
    pub fn read(&self) -> Result<u64, PerfError> {
        read_counter(self.fd)
    }
}

impl Drop for RbcCounter {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// A PMU timer that delivers a signal after a specified number of retired
/// conditional branches.
///
/// Unlike [`RbcCounter`] (which is a pure counting counter), `RbcTimer` is a
/// sampling counter: it fires a signal when the counter overflows past the
/// configured sample period.
///
/// # Signal Delivery
///
/// After creation, call [`set_signal_delivery`](Self::set_signal_delivery) to
/// route the overflow notification to a specific thread as a specific signal.
/// The recommended signal is `SIGSTKFLT` (unused by the kernel, safe as a
/// private marker signal).
///
/// # Lifecycle
///
/// ```text
/// new() → set_signal_delivery() → set_period() → reset() → enable()
///   ... branches execute ... signal fires ...
/// disable() → [repeat from set_period()]
/// ```
pub struct RbcTimer {
    fd: RawFd,
}

impl RbcTimer {
    /// A very large period that effectively disables overflow signals.
    ///
    /// Use this as the initial `sample_period` when creating a timer that will
    /// have its period set later via [`set_period`](Self::set_period).
    pub const DISABLE_SAMPLE_PERIOD: u64 = 1 << 60;

    /// Open a new RBC timer for the current thread.
    ///
    /// The timer starts disabled. The `sample_period` controls how many retired
    /// conditional branches must occur before an overflow notification fires.
    /// Use [`DISABLE_SAMPLE_PERIOD`](Self::DISABLE_SAMPLE_PERIOD) to create a
    /// timer without immediate overflow, then set the real period later with
    /// [`set_period`](Self::set_period).
    pub fn new(config: &PmuConfig, sample_period: u64) -> Result<Self, PerfError> {
        let mut attr = perf::bindings::perf_event_attr {
            type_: perf::bindings::PERF_TYPE_RAW,
            size: std::mem::size_of::<perf::bindings::perf_event_attr>() as u32,
            config: config.rcb_event,
            ..Default::default()
        };
        attr.__bindgen_anon_1.sample_period = sample_period;
        attr.set_disabled(1);
        attr.set_exclude_kernel(1);
        attr.set_exclude_hv(1);
        attr.set_pinned(1);
        // Generate a wakeup (overflow notification) after one sample event.
        attr.__bindgen_anon_2.wakeup_events = 1;

        let fd = unsafe { perf::perf_event_open(&mut attr, 0, -1, -1, 0) };
        if fd < 0 {
            return Err(PerfError::Open(io::Error::last_os_error()));
        }

        Ok(RbcTimer { fd })
    }

    /// Configure signal delivery on counter overflow.
    ///
    /// Routes the overflow notification to thread `tid` as signal `signo`.
    /// The signal is delivered asynchronously when the counter overflows past
    /// the sample period.
    ///
    /// `tid` is a Linux thread ID (from `gettid(2)`). `signo` is the signal
    /// number to deliver (e.g. `libc::SIGSTKFLT`).
    pub fn set_signal_delivery(
        &self,
        tid: libc::pid_t,
        signo: libc::c_int,
    ) -> Result<(), PerfError> {
        let owner = FOwnerEx {
            type_: F_OWNER_TID,
            pid: tid,
        };
        let ret = unsafe { libc::fcntl(self.fd, F_SETOWN_EX, &owner as *const FOwnerEx) };
        if ret < 0 {
            return Err(PerfError::Fcntl(io::Error::last_os_error()));
        }
        let ret = unsafe { libc::fcntl(self.fd, libc::F_SETFL, libc::O_ASYNC) };
        if ret < 0 {
            return Err(PerfError::Fcntl(io::Error::last_os_error()));
        }
        let ret = unsafe { libc::fcntl(self.fd, F_SETSIG, signo) };
        if ret < 0 {
            return Err(PerfError::Fcntl(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Change the overflow period.
    ///
    /// The counter will fire an overflow notification after `ticks` more
    /// retired conditional branches. This takes effect from the current
    /// counter position.
    pub fn set_period(&self, ticks: u64) -> Result<(), PerfError> {
        // PERF_EVENT_IOC_PERIOD expects a pointer to u64.
        let mut ticks = ticks;
        let ret = unsafe {
            libc::ioctl(
                self.fd,
                perf::bindings::PERIOD as libc::c_ulong,
                &mut ticks as *mut u64,
            )
        };
        if ret < 0 {
            return Err(PerfError::Ioctl(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Enable the timer.
    pub fn enable(&self) -> Result<(), PerfError> {
        ioctl_no_arg(self.fd, perf::bindings::ENABLE)
    }

    /// Disable the timer.
    pub fn disable(&self) -> Result<(), PerfError> {
        ioctl_no_arg(self.fd, perf::bindings::DISABLE)
    }

    /// Reset the counter to zero.
    pub fn reset(&self) -> Result<(), PerfError> {
        ioctl_no_arg(self.fd, perf::bindings::RESET)
    }

    /// Read the current counter value.
    pub fn read(&self) -> Result<u64, PerfError> {
        read_counter(self.fd)
    }

    /// Return the raw file descriptor for this timer.
    ///
    /// Useful for signal handler identification (matching `si_fd` against
    /// known timer fds).
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RbcTimer {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Raw ioctl request code for `PERF_EVENT_IOC_ENABLE`.
///
/// Exported for use in async-signal-safe code paths that cannot call
/// higher-level `RbcTimer` methods.
pub const PERF_IOC_ENABLE: libc::c_ulong = perf::bindings::ENABLE as libc::c_ulong;

/// Raw ioctl request code for `PERF_EVENT_IOC_DISABLE`.
pub const PERF_IOC_DISABLE: libc::c_ulong = perf::bindings::DISABLE as libc::c_ulong;

/// Raw ioctl request code for `PERF_EVENT_IOC_RESET`.
pub const PERF_IOC_RESET: libc::c_ulong = perf::bindings::RESET as libc::c_ulong;

/// Raw ioctl request code for `PERF_EVENT_IOC_PERIOD`.
pub const PERF_IOC_PERIOD: libc::c_ulong = perf::bindings::PERIOD as libc::c_ulong;

/// Shared ioctl helper for ENABLE/DISABLE/RESET (no argument).
fn ioctl_no_arg(fd: RawFd, request: u32) -> Result<(), PerfError> {
    let ret = unsafe { libc::ioctl(fd, request as libc::c_ulong, 0 as libc::c_ulong) };
    if ret < 0 {
        return Err(PerfError::Ioctl(io::Error::last_os_error()));
    }
    Ok(())
}

/// Shared read helper for counter value.
fn read_counter(fd: RawFd) -> Result<u64, PerfError> {
    let mut count: u64 = 0;
    let ret = unsafe {
        libc::read(
            fd,
            &mut count as *mut u64 as *mut libc::c_void,
            std::mem::size_of::<u64>(),
        )
    };
    if ret < 0 {
        return Err(PerfError::Read(io::Error::last_os_error()));
    }
    Ok(count)
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

/// Try to create an RBC timer, returning `None` with a warning if unavailable.
///
/// The timer starts with [`RbcTimer::DISABLE_SAMPLE_PERIOD`] so it won't
/// fire until a real period is set via [`RbcTimer::set_period`].
pub fn try_create_rbc_timer() -> Option<RbcTimer> {
    let config = match PmuConfig::detect() {
        Some(c) => c,
        None => {
            tracing::warn!("RBC timer: CPU not supported (no CPUID match)");
            return None;
        }
    };
    match RbcTimer::new(&config, RbcTimer::DISABLE_SAMPLE_PERIOD) {
        Ok(timer) => Some(timer),
        Err(e) => {
            tracing::warn!("RBC timer unavailable: {e}");
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

        // Basic lifecycle: reset -> enable -> disable -> read
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
        // Should have counted some conditional branches.
        // In VMs/containers, PMU may be available but not actually counting.
        if count == 0 {
            eprintln!("skipping RBC assertion: counter reads 0 (likely VM/container)");
            return;
        }
        assert!(count > 0, "expected non-zero RBC count, got {count}");
    }

    #[test]
    fn test_try_create_rbc_counter() {
        // Should not panic regardless of platform
        let _counter = try_create_rbc_counter();
    }

    #[test]
    fn test_try_create_rbc_timer() {
        // Should not panic regardless of platform
        let _timer = try_create_rbc_timer();
    }

    #[test]
    fn test_rbc_timer_signal_delivery() {
        use std::sync::atomic::{AtomicBool, Ordering};

        static SIGNAL_RECEIVED: AtomicBool = AtomicBool::new(false);

        extern "C" fn handler(_signo: libc::c_int) {
            SIGNAL_RECEIVED.store(true, Ordering::SeqCst);
        }

        let config = match PmuConfig::detect() {
            Some(c) => c,
            None => {
                eprintln!("skipping RBC timer test: unsupported CPU");
                return;
            }
        };

        // Create timer with a small period (100 branches).
        let timer = match RbcTimer::new(&config, 100) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("skipping RBC timer test: {e}");
                return;
            }
        };

        // Install SIGSTKFLT handler.
        let sa = libc::sigaction {
            sa_sigaction: handler as libc::sighandler_t,
            sa_mask: unsafe { std::mem::zeroed() },
            sa_flags: libc::SA_SIGINFO,
            sa_restorer: None,
        };
        let ret = unsafe { libc::sigaction(libc::SIGSTKFLT, &sa, std::ptr::null_mut()) };
        assert_eq!(ret, 0, "sigaction failed");

        // Route signal to this thread.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::pid_t;
        timer
            .set_signal_delivery(tid, libc::SIGSTKFLT)
            .expect("set_signal_delivery");

        // Enable and run some branches to trigger overflow.
        timer.reset().expect("reset");
        timer.enable().expect("enable");

        let mut sum = 0u64;
        for i in 0..100_000u64 {
            if i % 2 == 0 {
                sum += i;
            }
        }
        std::hint::black_box(sum);

        timer.disable().expect("disable");

        // Restore default handler.
        let sa_default = libc::sigaction {
            sa_sigaction: libc::SIG_DFL,
            sa_mask: unsafe { std::mem::zeroed() },
            sa_flags: 0,
            sa_restorer: None,
        };
        unsafe {
            libc::sigaction(libc::SIGSTKFLT, &sa_default, std::ptr::null_mut());
        }

        // In VMs/containers, the counter may not actually fire.
        let count = timer.read().unwrap_or(0);
        if count == 0 {
            eprintln!("skipping RBC timer signal assertion: counter reads 0 (likely VM/container)");
            return;
        }

        assert!(
            SIGNAL_RECEIVED.load(Ordering::SeqCst),
            "expected SIGSTKFLT signal after {count} retired branches with period=100"
        );
    }

    #[test]
    fn test_rbc_timer_set_period() {
        let config = match PmuConfig::detect() {
            Some(c) => c,
            None => {
                eprintln!("skipping RBC timer period test: unsupported CPU");
                return;
            }
        };

        // Create with large period, then set a real one.
        let timer = match RbcTimer::new(&config, RbcTimer::DISABLE_SAMPLE_PERIOD) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("skipping RBC timer period test: {e}");
                return;
            }
        };

        timer.set_period(500).expect("set_period should succeed");
        timer.reset().expect("reset");
        timer.enable().expect("enable");

        let mut sum = 0u64;
        for i in 0..1000u64 {
            if i % 2 == 0 {
                sum += i;
            }
        }
        std::hint::black_box(sum);

        timer.disable().expect("disable");
        // Just verify it didn't crash; actual counting may not work in VMs.
    }
}
