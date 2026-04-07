//! Wrappers around kernel `bpf_cpumask_*` kfuncs.
//!
//! These kfuncs manipulate `struct bpf_cpumask`, which is a
//! reference-counted, mutable cpumask allocated by the kernel.
//!
//! # `bpf_cpumask` vs `cpumask`
//!
//! The kernel defines two cpumask types relevant to BPF:
//!
//! - **`struct cpumask`** (read-only): returned by sched_ext helpers
//!   like `scx_bpf_get_idle_cpumask()`. These are kernel-owned and
//!   must be released with `scx_bpf_put_cpumask()`. See [`kfuncs`]
//!   for those wrappers.
//!
//! - **`struct bpf_cpumask`** (mutable, refcounted): allocated by
//!   `bpf_cpumask_create()` and managed by the BPF program. These
//!   can be stored in maps as `__kptr` fields for persistent state
//!   across BPF program invocations. Release with
//!   `bpf_cpumask_release()`.
//!
//! A `*mut bpf_cpumask` can be cast to `*const cpumask` for use
//! with read-only APIs (this is the `cast_mask()` pattern in C code).
//!
//! # kptr storage pattern
//!
//! To persist a cpumask across BPF program invocations, store a
//! `bpf_cpumask __kptr *` in a map value. The kernel tracks the
//! reference and releases it when the map entry is deleted. In C:
//!
//! ```c
//! // In a map value struct:
//! struct bpf_cpumask __kptr *my_mask;
//!
//! // Initialization (typically in ops.init or a syscall prog):
//! struct bpf_cpumask *mask = bpf_cpumask_create();
//! mask = bpf_kptr_xchg(&my_mask, mask);
//! if (mask) bpf_cpumask_release(mask);  // release old value
//!
//! // Reading (under RCU):
//! bpf_rcu_read_lock();
//! struct bpf_cpumask *m = my_mask;
//! if (m) bpf_cpumask_set_cpu(cpu, m);
//! bpf_rcu_read_unlock();
//! ```
//!
//! # Example
//!
//! ```ignore
//! use scx_ebpf::cpumask;
//! use scx_ebpf::kfuncs;
//!
//! // Create a cpumask and populate it
//! let mask = cpumask::create();
//! if !mask.is_null() {
//!     cpumask::set_cpu(0, mask);
//!     cpumask::set_cpu(4, mask);
//!     assert!(!cpumask::empty(cpumask::cast(mask)));
//!     let first = cpumask::first(cpumask::cast(mask));
//!     cpumask::release(mask);
//! }
//! ```

use super::kfuncs::cpumask;

/// Mutable, reference-counted BPF cpumask.
///
/// This is the kernel's `struct bpf_cpumask`, which wraps `struct cpumask`
/// with a reference count. Allocated by [`create`] and freed by [`release`].
///
/// Can be cast to `*const cpumask` via [`cast`] for use with read-only
/// APIs like `kfuncs::get_idle_cpumask()` comparisons.
#[repr(C)]
pub struct bpf_cpumask {
    _opaque: u8,
}

// ── kfunc extern declarations ────────────────────────────────────────────

unsafe extern "C" {
    fn bpf_cpumask_create() -> *mut bpf_cpumask;
    fn bpf_cpumask_release(mask: *mut bpf_cpumask);
    fn bpf_cpumask_set_cpu(cpu: u32, mask: *mut bpf_cpumask);
    fn bpf_cpumask_clear_cpu(cpu: u32, mask: *mut bpf_cpumask);
    fn bpf_cpumask_test_cpu(cpu: u32, mask: *const cpumask) -> bool;
    fn bpf_cpumask_first(mask: *const cpumask) -> u32;
    fn bpf_cpumask_first_zero(mask: *const cpumask) -> u32;
    fn bpf_cpumask_empty(mask: *const cpumask) -> bool;
    fn bpf_cpumask_full(mask: *const cpumask) -> bool;
    fn bpf_cpumask_and(dst: *mut bpf_cpumask, src1: *const cpumask, src2: *const cpumask) -> bool;
    fn bpf_cpumask_or(dst: *mut bpf_cpumask, src1: *const cpumask, src2: *const cpumask);
    fn bpf_cpumask_copy(dst: *mut bpf_cpumask, src: *const cpumask);
    fn bpf_cpumask_setall(mask: *mut bpf_cpumask);
    fn bpf_cpumask_any_distribute(mask: *const cpumask) -> u32;
    fn bpf_cpumask_subset(src1: *const cpumask, src2: *const cpumask) -> bool;
    fn bpf_cpumask_weight(mask: *const cpumask) -> u32;
}

// ── Raw kfunc wrappers (unsafe) ──────────────────────────────────────────
//
// All public functions in this module are `unsafe` because they perform
// raw BPF kfunc calls that require a valid BPF program context.
// Prefer using [`BpfCtx`](crate::ctx::BpfCtx) for safe access.

/// Cast a mutable `bpf_cpumask` pointer to a read-only `cpumask` pointer.
///
/// This is the Rust equivalent of the C `cast_mask()` macro. The kernel's
/// `struct bpf_cpumask` embeds a `struct cpumask`, so this cast is valid.
///
/// Use this when passing a `bpf_cpumask` to APIs that take `*const cpumask`,
/// such as `kfuncs::select_cpu_and()` or the read-only cpumask kfuncs
/// in this module (`test_cpu`, `first`, `empty`, etc.).
#[inline(always)]
pub fn cast(mask: *const bpf_cpumask) -> *const cpumask {
    mask.cast()
}

/// Allocate a new BPF cpumask with all bits cleared.
///
/// Returns a pointer to the new mask, or null on allocation failure.
/// The caller owns the reference and must call [`release`] when done,
/// or transfer ownership to a map via `bpf_kptr_xchg`.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_create()`](crate::ctx::BpfCtx::cpumask_create) for safe access.
#[inline(always)]
pub unsafe fn create() -> *mut bpf_cpumask {
    let ret: *mut bpf_cpumask;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_create,
            lateout("r0") ret,
            lateout("r1") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}

/// Release a BPF cpumask reference.
///
/// After this call, the pointer is invalid and must not be used.
/// Only call this on masks obtained from [`create`] or `bpf_kptr_xchg`.
/// Do **not** call this on masks from `scx_bpf_get_idle_cpumask()` --
/// use `kfuncs::put_cpumask()` for those.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_release()`](crate::ctx::BpfCtx::cpumask_release) for safe access.
#[inline(always)]
pub unsafe fn release(mask: *mut bpf_cpumask) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_release,
            inlateout("r1") mask => _,
            lateout("r0") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Set the bit for `cpu` in the cpumask.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_set_cpu()`](crate::ctx::BpfCtx::cpumask_set_cpu) for safe access.
#[inline(always)]
pub unsafe fn set_cpu(cpu: u32, mask: *mut bpf_cpumask) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_set_cpu,
            inlateout("r1") (cpu as u64) => _,
            inlateout("r2") mask => _,
            lateout("r0") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Clear the bit for `cpu` in the cpumask.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_clear_cpu()`](crate::ctx::BpfCtx::cpumask_clear_cpu) for safe access.
#[inline(always)]
pub unsafe fn clear_cpu(cpu: u32, mask: *mut bpf_cpumask) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_clear_cpu,
            inlateout("r1") (cpu as u64) => _,
            inlateout("r2") mask => _,
            lateout("r0") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Test whether `cpu` is set in the cpumask.
///
/// Takes a `*const cpumask` (read-only). Use [`cast`] to convert a
/// `*const bpf_cpumask` to the required type.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_test_cpu()`](crate::ctx::BpfCtx::cpumask_test_cpu) for safe access.
#[inline(always)]
pub unsafe fn test_cpu(cpu: u32, mask: *const cpumask) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_test_cpu,
            inlateout("r1") (cpu as u64) => _,
            inlateout("r2") mask => _,
            lateout("r0") ret,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret != 0
}

/// Return the index of the first set bit, or `>= nr_cpu_ids` if empty.
///
/// Takes a `*const cpumask` (read-only). Use [`cast`] to convert a
/// `*const bpf_cpumask`.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_first()`](crate::ctx::BpfCtx::cpumask_first) for safe access.
#[inline(always)]
pub unsafe fn first(mask: *const cpumask) -> u32 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_first,
            inlateout("r1") mask => _,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as u32
}

/// Return the index of the first unset (zero) bit, or `>= nr_cpu_ids` if full.
///
/// Takes a `*const cpumask` (read-only). Use [`cast`] to convert a
/// `*const bpf_cpumask`.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_first_zero()`](crate::ctx::BpfCtx::cpumask_first_zero) for safe access.
#[inline(always)]
pub unsafe fn first_zero(mask: *const cpumask) -> u32 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_first_zero,
            inlateout("r1") mask => _,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as u32
}

/// Return true if no bits are set in the cpumask.
///
/// Takes a `*const cpumask` (read-only). Use [`cast`] to convert a
/// `*const bpf_cpumask`.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_empty()`](crate::ctx::BpfCtx::cpumask_empty) for safe access.
#[inline(always)]
pub unsafe fn empty(mask: *const cpumask) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_empty,
            inlateout("r1") mask => _,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret != 0
}

/// Return true if all possible CPU bits are set in the cpumask.
///
/// Takes a `*const cpumask` (read-only). Use [`cast`] to convert a
/// `*const bpf_cpumask`.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_full()`](crate::ctx::BpfCtx::cpumask_full) for safe access.
#[inline(always)]
pub unsafe fn full(mask: *const cpumask) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_full,
            inlateout("r1") mask => _,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret != 0
}

/// Compute `dst = src1 AND src2`. Returns true if the result is non-empty.
///
/// `dst` must be a mutable `bpf_cpumask`. `src1` and `src2` are read-only
/// `cpumask` pointers (use [`cast`] to convert `bpf_cpumask` pointers).
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_and()`](crate::ctx::BpfCtx::cpumask_and) for safe access.
#[inline(always)]
pub unsafe fn and(dst: *mut bpf_cpumask, src1: *const cpumask, src2: *const cpumask) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_and,
            inlateout("r1") dst => _,
            inlateout("r2") src1 => _,
            inlateout("r3") src2 => _,
            lateout("r0") ret,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret != 0
}

/// Compute `dst = src1 OR src2`.
///
/// `dst` must be a mutable `bpf_cpumask`. `src1` and `src2` are read-only
/// `cpumask` pointers (use [`cast`] to convert `bpf_cpumask` pointers).
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_or()`](crate::ctx::BpfCtx::cpumask_or) for safe access.
#[inline(always)]
pub unsafe fn or(dst: *mut bpf_cpumask, src1: *const cpumask, src2: *const cpumask) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_or,
            inlateout("r1") dst => _,
            inlateout("r2") src1 => _,
            inlateout("r3") src2 => _,
            lateout("r0") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Copy all bits from `src` into `dst`.
///
/// `dst` must be a mutable `bpf_cpumask`. `src` is a read-only `cpumask`
/// pointer (use [`cast`] to convert a `bpf_cpumask` pointer).
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_copy()`](crate::ctx::BpfCtx::cpumask_copy) for safe access.
#[inline(always)]
pub unsafe fn copy(dst: *mut bpf_cpumask, src: *const cpumask) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_copy,
            inlateout("r1") dst => _,
            inlateout("r2") src => _,
            lateout("r0") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Set all possible CPU bits in the cpumask.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::cpumask_setall()`](crate::ctx::BpfCtx::cpumask_setall) for safe access.
#[inline(always)]
pub unsafe fn setall(mask: *mut bpf_cpumask) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_setall,
            inlateout("r1") mask => _,
            lateout("r0") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Pick a pseudo-random set CPU from the cpumask, with distribution.
///
/// Returns a CPU index, or `>= nr_cpu_ids` if the mask is empty.
/// The kernel distributes selections across set bits to avoid
/// thundering-herd on a single CPU.
///
/// Takes a `*const cpumask` (read-only). Use [`cast`] to convert a
/// `*const bpf_cpumask`.
#[inline(always)]
pub fn any_distribute(mask: *const cpumask) -> u32 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_any_distribute,
            inlateout("r1") mask => _,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as u32
}

/// Test whether `src1` is a subset of `src2` (every bit set in `src1`
/// is also set in `src2`).
///
/// Both arguments are `*const cpumask` (read-only). Use [`cast`] to
/// convert `*const bpf_cpumask` pointers.
#[inline(always)]
pub fn subset(src1: *const cpumask, src2: *const cpumask) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_subset,
            inlateout("r1") src1 => _,
            inlateout("r2") src2 => _,
            lateout("r0") ret,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret != 0
}

/// Return the number of set bits (popcount) in the cpumask.
///
/// Takes a `*const cpumask` (read-only). Use [`cast`] to convert a
/// `*const bpf_cpumask`.
#[inline(always)]
pub fn weight(mask: *const cpumask) -> u32 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cpumask_weight,
            inlateout("r1") mask => _,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as u32
}
