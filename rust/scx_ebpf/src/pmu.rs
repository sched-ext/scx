//! BPF helper wrappers for reading hardware performance counters (PMU events).
//!
//! This module provides the eBPF-side primitives for reading perf event
//! counters that have been installed by userspace into a
//! `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
//!
//! # Architecture overview
//!
//! Hardware performance monitoring works as a cooperation between userspace
//! and eBPF:
//!
//! **Userspace** (the scheduler loader) is responsible for:
//! 1. Opening a perf event fd for each CPU via `perf_event_open(2)`
//! 2. Storing those fds in a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` BPF map
//!
//! **eBPF** (this module) is responsible for:
//! 1. Reading the counter values via `bpf_perf_event_read_value` (helper #55)
//! 2. Computing deltas between scheduling events to attribute counter
//!    values to individual tasks
//!
//! # Userspace integration (for future Rust scheduler loaders)
//!
//! The Rust userspace loader needs to perform the following setup before
//! attaching the scheduler:
//!
//! ```ignore
//! use perf_event_open_sys as sys;
//!
//! fn setup_perf_events(map: &aya::maps::PerfEventArray, nr_cpus: u32, config: u64) {
//!     for cpu in 0..nr_cpus {
//!         let mut attrs = sys::bindings::perf_event_attr::default();
//!         attrs.type_ = sys::bindings::PERF_TYPE_RAW;
//!         attrs.config = config;  // e.g., 0xC0 for instructions on x86
//!         attrs.size = core::mem::size_of::<sys::bindings::perf_event_attr>() as u32;
//!         attrs.set_disabled(0);
//!         attrs.set_inherit(0);
//!
//!         let fd = unsafe {
//!             sys::perf_event_open(&mut attrs, -1, cpu as i32, -1, 0)
//!         };
//!         assert!(fd >= 0, "perf_event_open failed");
//!
//!         // Store the fd in the BPF map keyed by CPU index.
//!         // The fd must remain open for the lifetime of the scheduler.
//!         map.update(&cpu.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
//!             .expect("failed to update perf event map");
//!     }
//! }
//! ```
//!
//! Common `perf_config` values (x86):
//! - `0xC0` — retired instructions
//! - `0x3C` — unhalted core cycles
//! - IPC can be derived from instructions / cycles
//!
//! # eBPF usage pattern
//!
//! The typical pattern in a struct_ops scheduler:
//!
//! ```ignore
//! use scx_ebpf::pmu::{PerfEventValue, perf_event_read_value, BPF_F_CURRENT_CPU};
//!
//! // In ops.running() — capture baseline when task starts:
//! let mut start_val = PerfEventValue::ZERO;
//! let ret = unsafe { perf_event_read_value(map_ptr, BPF_F_CURRENT_CPU, &mut start_val) };
//!
//! // In ops.stopping() — read current value, compute delta:
//! let mut end_val = PerfEventValue::ZERO;
//! let ret = unsafe { perf_event_read_value(map_ptr, BPF_F_CURRENT_CPU, &mut end_val) };
//! let delta = end_val.counter - start_val.counter;
//! ```

/// Flag value to read the perf event for the current CPU.
///
/// Equivalent to `BPF_F_CURRENT_CPU` in the kernel (0xFFFF_FFFF).
/// Pass this as the `index` argument to [`perf_event_read_value`]
/// to automatically select the counter for the CPU the BPF program
/// is currently executing on.
pub const BPF_F_CURRENT_CPU: u64 = 0xFFFF_FFFF;

/// Result of reading a perf event counter.
///
/// Matches the kernel's `struct bpf_perf_event_value` layout exactly.
/// All three fields are reported by the kernel:
///
/// - `counter`: the raw event count since the counter was enabled
/// - `enabled`: total time (ns) the counter was enabled
/// - `running`: total time (ns) the counter was actually counting
///
/// When `enabled != running`, the counter was multiplexed (time-shared
/// with other events). In that case, the true count can be estimated as:
/// `counter * enabled / running`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerfEventValue {
    /// Raw event count accumulated since the counter was enabled.
    pub counter: u64,
    /// Total time in nanoseconds the event was enabled.
    pub enabled: u64,
    /// Total time in nanoseconds the event was actually running
    /// (may be less than `enabled` if multiplexed).
    pub running: u64,
}

impl PerfEventValue {
    /// A zeroed value, suitable for initializing before a read.
    pub const ZERO: Self = Self {
        counter: 0,
        enabled: 0,
        running: 0,
    };

    /// Returns true if the counter was multiplexed (time-shared).
    ///
    /// When multiplexed, `running < enabled` and the raw `counter`
    /// value underestimates the true count. Use [`Self::scaled_counter`]
    /// to get an estimated true count.
    #[inline(always)]
    pub fn is_multiplexed(&self) -> bool {
        self.enabled != self.running
    }

    /// Returns an estimated true count, scaling for multiplexing.
    ///
    /// If the counter ran for the full enabled period, returns the raw
    /// counter value. If multiplexed, scales up proportionally.
    /// Returns 0 if `running` is 0 (counter never ran).
    #[inline(always)]
    pub fn scaled_counter(&self) -> u64 {
        if self.running == 0 {
            return 0;
        }
        if self.enabled == self.running {
            return self.counter;
        }
        // Scale: counter * (enabled / running)
        // Use u128 to avoid overflow on large counter values.
        ((self.counter as u128 * self.enabled as u128) / self.running as u128) as u64
    }
}

/// Read a perf event counter value from a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
///
/// This wraps BPF helper #55 (`bpf_perf_event_read_value`). The helper
/// reads the hardware performance counter associated with the given CPU
/// index from the perf event array map.
///
/// # Arguments
///
/// - `map`: Pointer to a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map. In Rust eBPF
///   programs, this is typically the address of a global map variable.
/// - `index`: CPU index to read, or [`BPF_F_CURRENT_CPU`] to read the
///   current CPU's counter.
/// - `val`: Output buffer for the counter value.
///
/// # Returns
///
/// 0 on success, negative errno on failure. Common errors:
/// - `-ENOENT`: No perf event fd installed for the given CPU index
/// - `-EINVAL`: Map is not a perf event array, or buffer size is wrong
///
/// # Safety
///
/// - `map` must point to a valid `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
/// - `val` must point to a valid, writable `PerfEventValue`.
/// - The perf event fd for the target CPU must have been installed by
///   userspace before this call.
///
/// # Example
///
/// ```ignore
/// let mut val = PerfEventValue::ZERO;
/// let ret = unsafe {
///     perf_event_read_value(&raw const MY_PERF_MAP as *const _, BPF_F_CURRENT_CPU, &mut val)
/// };
/// if ret == 0 {
///     // val.counter contains the event count
/// }
/// ```
#[inline(always)]
pub unsafe fn perf_event_read_value(
    map: *const core::ffi::c_void,
    index: u64,
    val: &mut PerfEventValue,
) -> i64 {
    let ret: i64;
    let buf = val as *mut PerfEventValue as u64;
    let size = core::mem::size_of::<PerfEventValue>() as u64;
    core::arch::asm!(
        "call 55",
        in("r1") map,
        in("r2") index,
        in("r3") buf,
        in("r4") size,
        lateout("r0") ret,
        lateout("r5") _,
    );
    ret
}

/// Output a perf event record to a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
///
/// This wraps BPF helper #25 (`bpf_perf_event_output`). It writes a
/// sample record that userspace can read via `perf_event_read` or `mmap`.
///
/// This is a different use case from [`perf_event_read_value`]: while
/// `perf_event_read_value` reads hardware counter snapshots,
/// `perf_event_output` sends arbitrary data records to userspace via
/// the perf ring buffer.
///
/// # Arguments
///
/// - `ctx`: BPF program context pointer (the first argument to the BPF
///   program entry point).
/// - `map`: Pointer to a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
/// - `flags`: Lower 32 bits are the CPU index (or [`BPF_F_CURRENT_CPU`]).
///   Upper 32 bits are flags (e.g., `BPF_F_INDEX_MASK`).
/// - `data`: Pointer to the data to output.
/// - `size`: Size of the data in bytes.
///
/// # Returns
///
/// 0 on success, negative errno on failure.
///
/// # Safety
///
/// - `ctx` must be a valid BPF program context pointer.
/// - `map` must point to a valid `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
/// - `data` must point to `size` bytes of readable memory.
#[inline(always)]
pub unsafe fn perf_event_output(
    ctx: *const core::ffi::c_void,
    map: *const core::ffi::c_void,
    flags: u64,
    data: *const core::ffi::c_void,
    size: u64,
) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "call 25",
        in("r1") ctx,
        in("r2") map,
        in("r3") flags,
        in("r4") data,
        in("r5") size,
        lateout("r0") ret,
    );
    ret
}
