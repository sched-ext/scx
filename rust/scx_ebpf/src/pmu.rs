//! BPF helper wrappers for reading hardware performance counters (PMU events).
//!
//! This module provides the eBPF-side primitives for reading perf event
//! counters that have been installed by userspace into a
//! `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
//!
//! # IMPORTANT: struct_ops limitation
//!
//! **`bpf_perf_event_read_value` (helper #55) is NOT available in
//! `BPF_PROG_TYPE_STRUCT_OPS` programs.** The kernel restricts this helper
//! to tracing program types (kprobe, tracepoint, fentry, tp_btf). This is
//! defined in `bpf_tracing_func_proto()` in `kernel/trace/bpf_trace.c`.
//! The struct_ops verifier_ops (`bpf_struct_ops_verifier_ops` in
//! `kernel/bpf/bpf_struct_ops.c`) has no `get_func_proto` callback, so
//! struct_ops programs only get the base helper set from `bpf_base_func_proto()`.
//!
//! Attempting to call helper #55 from a struct_ops program will cause the
//! BPF verifier to reject the program with:
//! `program of this type cannot use helper bpf_perf_event_read_value#55`
//!
//! The C sched_ext PMU library (scx/lib/pmu.bpf.c) has the same limitation.
//! Its solution architecture uses separate tracing BPF programs
//! (`SEC("?tp_btf/sched_switch")` and `SEC("?fentry/scx_tick")`) that CAN
//! call the helper, with counter data shared to struct_ops programs via a
//! BPF map. This pattern is not yet implemented in the Rust eBPF framework.
//!
//! These functions are usable from tracing-type BPF programs if you need
//! to read perf events from fentry/tracepoint/kprobe programs.
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
//! use core::mem::MaybeUninit;
//!
//! // In ops.running() — capture baseline when task starts:
//! let mut start_val = MaybeUninit::<PerfEventValue>::uninit();
//! let ret = unsafe { perf_event_read_value(map_ptr, BPF_F_CURRENT_CPU, start_val.as_mut_ptr()) };
//! let start_val = unsafe { start_val.assume_init() };
//!
//! // In ops.stopping() — read current value, compute delta:
//! let mut end_val = MaybeUninit::<PerfEventValue>::uninit();
//! let ret = unsafe { perf_event_read_value(map_ptr, BPF_F_CURRENT_CPU, end_val.as_mut_ptr()) };
//! let end_val = unsafe { end_val.assume_init() };
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
#[repr(C, align(8))]
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
/// # struct_ops limitation
///
/// **This helper is NOT available in `BPF_PROG_TYPE_STRUCT_OPS` programs.**
/// Calling it from a struct_ops callback will cause the BPF verifier to
/// reject the program. Only use this from tracing program types (kprobe,
/// tracepoint, fentry, tp_btf).
///
/// # Arguments
///
/// - `map`: Pointer to a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map. In Rust eBPF
///   programs, this is typically the address of a global map variable.
/// - `index`: CPU index to read, or [`BPF_F_CURRENT_CPU`] to read the
///   current CPU's counter.
/// - `val`: Output pointer for the counter value. A raw pointer is used
///   instead of `&mut` to allow callers to use `MaybeUninit`, avoiding
///   compiler-generated `memset` that the BPF verifier rejects due to
///   stack alignment issues.
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
/// - `val` must point to a valid, writable `PerfEventValue`-sized buffer.
/// - The perf event fd for the target CPU must have been installed by
///   userspace before this call.
///
/// # Example
///
/// ```ignore
/// let mut val = core::mem::MaybeUninit::<PerfEventValue>::uninit();
/// let ret = unsafe {
///     perf_event_read_value(
///         &raw const MY_PERF_MAP as *const _,
///         BPF_F_CURRENT_CPU,
///         val.as_mut_ptr(),
///     )
/// };
/// if ret == 0 {
///     let val = unsafe { val.assume_init() };
///     // val.counter contains the event count
/// }
/// ```
#[inline(always)]
pub unsafe fn perf_event_read_value(
    map: *const core::ffi::c_void,
    index: u64,
    val: *mut PerfEventValue,
) -> i64 {
    let ret: i64;
    let buf = val as u64;
    let size = core::mem::size_of::<PerfEventValue>() as u64;
    core::arch::asm!(
        "call 55",
        inlateout("r1") map => _,
        inlateout("r2") index => _,
        inlateout("r3") buf => _,
        inlateout("r4") size => _,
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
        inlateout("r1") ctx => _,
        inlateout("r2") map => _,
        inlateout("r3") flags => _,
        inlateout("r4") data => _,
        inlateout("r5") size => _,
        lateout("r0") ret,
    );
    ret
}
