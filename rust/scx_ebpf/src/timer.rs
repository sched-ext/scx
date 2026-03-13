//! BPF timer helpers for deferred scheduling operations.
//!
//! Provides wrappers around the kernel's `bpf_timer_*` BPF helpers, which
//! enable schedulers to defer work using kernel timers. This is useful for
//! batching CPU wakeups to reduce IPI overhead.
//!
//! # Architecture
//!
//! A BPF timer lives inside a BPF map value. The typical setup is:
//!
//! 1. Declare a `BPF_MAP_TYPE_ARRAY` map whose value type contains a [`BpfTimer`]
//! 2. Look up the map element to get a pointer to the [`BpfTimer`]
//! 3. Initialize it with [`timer_init`], associating it with its parent map
//! 4. Register a callback with [`timer_set_callback`]
//! 5. Arm the timer with [`timer_start`]
//!
//! The callback fires in soft-IRQ context and can re-arm the timer for
//! periodic execution.
//!
//! # Example (conceptual, requires maps support)
//!
//! ```ignore
//! use scx_ebpf::timer::{BpfTimer, CLOCK_MONOTONIC};
//!
//! // Map value type containing a timer:
//! #[repr(C)]
//! struct TimerData {
//!     timer: BpfTimer,
//! }
//!
//! // Timer callback — signature must be:
//! //   fn(map: *mut c_void, key: *mut i32, timer: *mut BpfTimer) -> i32
//! fn my_timer_cb(_map: *mut core::ffi::c_void, _key: *mut i32,
//!                timer: *mut BpfTimer) -> i32 {
//!     // Do deferred work here (e.g., kick idle CPUs)
//!     // ...
//!
//!     // Re-arm the timer for periodic execution:
//!     scx_ebpf::timer::timer_start(timer, 1_000_000, 0); // 1ms
//!     0
//! }
//!
//! // In scheduler init:
//! fn init_timer(timer: *mut BpfTimer, map: *mut core::ffi::c_void) {
//!     scx_ebpf::timer::timer_init(timer, map, CLOCK_MONOTONIC);
//!     scx_ebpf::timer::timer_set_callback(timer, my_timer_cb as u64);
//!     scx_ebpf::timer::timer_start(timer, 20_000_000, 0); // 20ms
//! }
//! ```

/// Opaque kernel `struct bpf_timer` — must live inside a BPF map value.
///
/// This is a 16-byte structure (two `u64`s) with 8-byte alignment,
/// matching the kernel's `struct bpf_timer { __u64 __opaque[2]; }`.
///
/// The timer must be initialized with [`timer_init`] before use.
/// The kernel manages the timer's internal state; BPF programs must
/// not read or write the opaque fields directly.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct BpfTimer {
    _opaque: [u64; 2],
}

impl BpfTimer {
    /// Create a zero-initialized `BpfTimer`.
    ///
    /// This is suitable for embedding in a map value struct. The timer
    /// is not usable until [`timer_init`] is called on it.
    pub const fn zeroed() -> Self {
        BpfTimer { _opaque: [0; 2] }
    }
}

// ── Clock ID constants ──────────────────────────────────────────────────

/// `CLOCK_MONOTONIC` — monotonic time since an unspecified starting point.
/// This is the most common clock for BPF timers.
pub const CLOCK_MONOTONIC: u64 = 1;

/// `CLOCK_REALTIME` — wall-clock time (subject to NTP adjustments).
pub const CLOCK_REALTIME: u64 = 0;

/// `CLOCK_BOOTTIME` — like `CLOCK_MONOTONIC` but includes time spent suspended.
pub const CLOCK_BOOTTIME: u64 = 7;

// ── Timer start flags ───────────────────────────────────────────────────

/// Interpret the `nsecs` argument to [`timer_start`] as an absolute
/// timestamp rather than a relative delay.
pub const BPF_F_TIMER_ABS: u64 = 1 << 0;

/// Pin the timer to the CPU of the caller. The callback will execute
/// on the same CPU that called [`timer_start`].
pub const BPF_F_TIMER_CPU_PIN: u64 = 1 << 1;

// ── BPF helper wrappers ─────────────────────────────────────────────────
//
// These use numeric `call N` instructions because bpf_timer_* are BPF
// helpers (not kfuncs). Helper numbers:
//   bpf_timer_init         = 169
//   bpf_timer_set_callback = 170
//   bpf_timer_start        = 171
//   bpf_timer_cancel       = 172

/// Initialize a BPF timer, associating it with its parent map and clock.
///
/// Must be called before [`timer_set_callback`] or [`timer_start`].
///
/// # Arguments
///
/// * `timer` — pointer to a [`BpfTimer`] inside a map value
/// * `map` — pointer to the BPF map that contains the timer. In BPF
///   programs this is typically `&map_variable` cast to a raw pointer.
/// * `flags` — clock ID in the low 4 bits (e.g., [`CLOCK_MONOTONIC`])
///
/// # Returns
///
/// `0` on success, negative errno on failure:
/// * `-EBUSY` if the timer is already initialized
/// * `-EINVAL` if invalid flags are passed
/// * `-EPERM` if the map has no user references
#[inline(always)]
pub fn timer_init(timer: *mut BpfTimer, map: *const core::ffi::c_void, flags: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call 169",
            in("r1") timer,
            in("r2") map,
            in("r3") flags,
            lateout("r0") ret,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}

/// Set the callback function for a BPF timer.
///
/// The callback will be invoked when the timer fires. It runs in
/// soft-IRQ context and has the following signature:
///
/// ```ignore
/// fn callback(map: *mut c_void, key: *mut i32, timer: *mut BpfTimer) -> i32
/// ```
///
/// # Arguments
///
/// * `timer` — pointer to an initialized [`BpfTimer`]
/// * `callback` — BPF function pointer to the callback. Pass the Rust
///   function cast to `u64`: `my_callback_fn as u64`
///
/// # Returns
///
/// `0` on success, negative errno on failure:
/// * `-EINVAL` if the timer was not initialized
/// * `-EPERM` if the map has no user references
#[inline(always)]
pub fn timer_set_callback(timer: *mut BpfTimer, callback: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call 170",
            in("r1") timer,
            in("r2") callback,
            lateout("r0") ret,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}

/// Start (arm) a BPF timer.
///
/// Sets the timer to fire after `nsecs` nanoseconds (relative to now),
/// or at an absolute time if [`BPF_F_TIMER_ABS`] is set in `flags`.
///
/// The configured callback will be invoked in soft-IRQ context. The
/// timer does not repeat automatically — call `timer_start` again
/// from the callback to create a periodic timer.
///
/// # Arguments
///
/// * `timer` — pointer to an initialized [`BpfTimer`] with a callback set
/// * `nsecs` — delay in nanoseconds (relative), or absolute timestamp
///   if `BPF_F_TIMER_ABS` is set
/// * `flags` — combination of [`BPF_F_TIMER_ABS`] and [`BPF_F_TIMER_CPU_PIN`],
///   or `0` for default (relative, any CPU)
///
/// # Returns
///
/// `0` on success, negative errno on failure.
#[inline(always)]
pub fn timer_start(timer: *mut BpfTimer, nsecs: u64, flags: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call 171",
            in("r1") timer,
            in("r2") nsecs,
            in("r3") flags,
            lateout("r0") ret,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}

/// Cancel a pending BPF timer.
///
/// If the timer callback is currently executing, this function will
/// wait for it to complete before returning.
///
/// # Arguments
///
/// * `timer` — pointer to an initialized [`BpfTimer`]
///
/// # Returns
///
/// `0` if the timer was successfully cancelled.
/// `1` if the timer was not active (already fired or never started).
/// Negative errno on failure.
#[inline(always)]
pub fn timer_cancel(timer: *mut BpfTimer) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call 172",
            in("r1") timer,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}
