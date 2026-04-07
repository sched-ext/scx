//! Wrappers around kernel cgroup kfuncs.
//!
//! These kfuncs manipulate `struct cgroup`, the kernel's control group
//! hierarchy. MITOSIS uses them for cgroup hierarchy traversal and
//! per-cgroup storage lookups.
//!
//! # Reference counting
//!
//! `bpf_cgroup_acquire` and `bpf_cgroup_from_id` return acquired
//! references that must be released with `bpf_cgroup_release`.
//! `bpf_cgroup_ancestor` also returns an acquired reference.
//!
//! # Example
//!
//! ```ignore
//! use scx_ebpf::cgroup;
//!
//! // Get the task's cgroup and look up its ancestor
//! let cgrp = cgroup::task_cgroup(p);
//! if !cgrp.is_null() {
//!     let ancestor = cgroup::ancestor(cgrp, 1);
//!     if !ancestor.is_null() {
//!         // ... use ancestor ...
//!         cgroup::release(ancestor);
//!     }
//! }
//! ```

/// Opaque kernel `struct cgroup` — used as a pointer target only.
#[repr(C)]
pub struct cgroup {
    _opaque: u8,
}

// ── kfunc extern declarations ────────────────────────────────────────────

unsafe extern "C" {
    fn bpf_cgroup_acquire(cgrp: *mut cgroup) -> *mut cgroup;
    fn bpf_cgroup_release(cgrp: *mut cgroup);
    fn bpf_cgroup_ancestor(cgrp: *mut cgroup, level: i32) -> *mut cgroup;
    fn bpf_cgroup_from_id(id: u64) -> *mut cgroup;
}

// ── Safe wrappers ────────────────────────────────────────────────────────

/// Acquire a reference to a cgroup.
///
/// Returns an acquired `cgroup` pointer that must be released with [`release`].
/// Returns null on failure.
#[inline(always)]
pub fn acquire(cgrp: *mut cgroup) -> *mut cgroup {
    let ret: *mut cgroup;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cgroup_acquire,
            inlateout("r1") cgrp => _,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}

/// Release a cgroup reference obtained from [`acquire`], [`ancestor`],
/// or [`from_id`].
///
/// After this call, the pointer is invalid and must not be used.
#[inline(always)]
pub fn release(cgrp: *mut cgroup) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cgroup_release,
            inlateout("r1") cgrp => _,
            lateout("r0") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Get an ancestor cgroup at the given hierarchy level.
///
/// `level` is the depth in the cgroup tree (0 = root).
/// Returns an acquired reference that must be released with [`release`].
/// Returns null if the level is invalid or the cgroup has no ancestor
/// at that level.
#[inline(always)]
pub fn ancestor(cgrp: *mut cgroup, level: i32) -> *mut cgroup {
    let ret: *mut cgroup;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cgroup_ancestor,
            inlateout("r1") cgrp => _,
            inlateout("r2") (level as i64) => _,
            lateout("r0") ret,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}

/// Look up a cgroup by its ID.
///
/// Returns an acquired reference that must be released with [`release`].
/// Returns null if no cgroup exists with the given ID.
#[inline(always)]
pub fn from_id(id: u64) -> *mut cgroup {
    let ret: *mut cgroup;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_cgroup_from_id,
            inlateout("r1") id => _,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}
