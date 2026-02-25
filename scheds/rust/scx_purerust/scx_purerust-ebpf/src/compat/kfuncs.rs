//! Safe wrappers around sched_ext BPF kfunc calls.
//!
//! HACK: The Rust BPF compiler does not emit proper kfunc call
//! instructions for `extern "C"` declarations — it generates a broken
//! `call -1; exit` sequence. We use inline assembly to manually set up
//! registers and emit the call instruction.
//!
//! When the Rust BPF compiler gains proper kfunc support, each wrapper
//! here becomes a plain `extern "C"` call with no inline asm.

use super::vmlinux::task_struct;

/// Default scheduling time slice (20ms in nanoseconds).
pub const SLICE_DFL: u64 = 20_000_000;

// ── kfunc extern declarations (used as sym targets in inline asm) ───────

unsafe extern "C" {
    fn scx_bpf_dsq_insert(p: *mut task_struct, dsq_id: u64, slice: u64, enq_flags: u64);
    fn scx_bpf_dsq_move_to_local(dsq_id: u64) -> bool;
    fn scx_bpf_create_dsq(dsq_id: u64, node: i32) -> i32;
}

// ── Safe wrappers ───────────────────────────────────────────────────────

/// Insert a task into a dispatch queue with a given time slice.
#[inline(always)]
pub fn dsq_insert(p: *mut task_struct, dsq_id: u64, slice: u64, enq_flags: u64) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_dsq_insert,
            in("r1") p,
            in("r2") dsq_id,
            in("r3") slice,
            in("r4") enq_flags,
            lateout("r0") _,
            lateout("r5") _,
        );
    }
}

/// Move one task from a dispatch queue to the local CPU's DSQ.
#[inline(always)]
pub fn dsq_move_to_local(dsq_id: u64) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_dsq_move_to_local,
            in("r1") dsq_id,
            lateout("r0") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Create a user dispatch queue. Returns 0 on success, negative errno on failure.
#[inline(always)]
pub fn create_dsq(dsq_id: u64, node: i32) -> i32 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_create_dsq,
            in("r1") dsq_id,
            in("r2") node as i64,
            lateout("r0") ret,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as i32
}
