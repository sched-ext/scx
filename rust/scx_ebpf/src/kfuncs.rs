//! Safe wrappers around sched_ext BPF kfunc calls.
//!
//! Uses inline assembly because the Rust BPF compiler does not emit
//! proper kfunc call instructions for `extern "C"` declarations.

use super::vmlinux::task_struct;

/// Opaque kernel `struct cpumask` — used as a pointer target only.
#[repr(C)]
pub struct cpumask {
    _opaque: u8,
}

/// Default scheduling time slice (20ms in nanoseconds).
pub const SLICE_DFL: u64 = 20_000_000;

// ── kfunc extern declarations (used as sym targets in inline asm) ───────

unsafe extern "C" {
    fn scx_bpf_dsq_insert(p: *mut task_struct, dsq_id: u64, slice: u64, enq_flags: u64);
    fn scx_bpf_dsq_insert_vtime(
        p: *mut task_struct,
        dsq_id: u64,
        slice: u64,
        vtime: u64,
        enq_flags: u64,
    );
    fn scx_bpf_dsq_move_to_local(dsq_id: u64) -> bool;
    fn scx_bpf_create_dsq(dsq_id: u64, node: i32) -> i32;
    fn scx_bpf_kick_cpu(cpu: i32, flags: u64);
    fn scx_bpf_dsq_nr_queued(dsq_id: u64) -> i32;
    fn scx_bpf_error_bstr(fmt: *const u8, data: *const u64, data_len: u32);
    fn scx_bpf_cpuperf_set(cpu: i32, perf: u32);
    fn scx_bpf_nr_cpu_ids() -> u32;
    fn scx_bpf_get_idle_cpumask() -> *const cpumask;
    fn scx_bpf_get_idle_smtmask() -> *const cpumask;
    fn scx_bpf_put_cpumask(mask: *const cpumask);
    fn scx_bpf_test_and_clear_cpu_idle(cpu: i32) -> bool;
    fn scx_bpf_task_running(p: *const task_struct) -> bool;
    fn scx_bpf_task_cpu(p: *const task_struct) -> i32;
    fn scx_bpf_cpu_curr(cpu: i32) -> *mut task_struct;
    fn scx_bpf_now() -> u64;
    fn scx_bpf_select_cpu_dfl(
        p: *mut task_struct,
        prev_cpu: i32,
        wake_flags: u64,
        is_idle: *mut bool,
    ) -> i32;
    fn scx_bpf_select_cpu_and(
        p: *mut task_struct,
        prev_cpu: i32,
        wake_flags: u64,
        cpus_allowed: *const cpumask,
        flags: u64,
    ) -> i32;
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

/// Insert a task into a dispatch queue with vtime-based ordering.
#[inline(always)]
pub fn dsq_insert_vtime(
    p: *mut task_struct,
    dsq_id: u64,
    slice: u64,
    vtime: u64,
    enq_flags: u64,
) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_dsq_insert_vtime,
            in("r1") p,
            in("r2") dsq_id,
            in("r3") slice,
            in("r4") vtime,
            in("r5") enq_flags,
            lateout("r0") _,
        );
    }
}

/// Move one task from a dispatch queue to the local CPU's DSQ.
#[inline(always)]
pub fn dsq_move_to_local(dsq_id: u64) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_dsq_move_to_local,
            in("r1") dsq_id,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret != 0
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

/// Kick a CPU, optionally only if idle (`SCX_KICK_IDLE = 1`).
#[inline(always)]
pub fn kick_cpu(cpu: i32, flags: u64) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_kick_cpu,
            in("r1") cpu as i64,
            in("r2") flags,
            lateout("r0") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Return the number of tasks queued on a DSQ.
#[inline(always)]
pub fn dsq_nr_queued(dsq_id: u64) -> i32 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_dsq_nr_queued,
            in("r1") dsq_id,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as i32
}

/// Report a fatal scheduler error (triggers scheduler exit).
///
/// `fmt` must be a null-terminated format string. `data` is the packed
/// argument array and `data_len` its size in bytes.
#[inline(always)]
pub fn error_bstr(fmt: *const u8, data: *const u64, data_len: u32) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_error_bstr,
            in("r1") fmt,
            in("r2") data,
            in("r3") data_len as u64,
            lateout("r0") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Report a fatal scheduler error with a simple static message (no args).
#[inline(always)]
pub fn error_msg(msg: &[u8]) {
    // Pass empty data array (data_len = 0).
    error_bstr(msg.as_ptr(), core::ptr::null(), 0);
}

/// Set the target CPU performance level (0 .. SCX_CPUPERF_ONE).
#[inline(always)]
pub fn cpuperf_set(cpu: i32, perf: u32) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_cpuperf_set,
            in("r1") cpu as i64,
            in("r2") perf as u64,
            lateout("r0") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Return the maximum number of CPU IDs on this system.
#[inline(always)]
pub fn nr_cpu_ids() -> u32 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_nr_cpu_ids,
            lateout("r0") ret,
            lateout("r1") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as u32
}

/// Get a read-only reference to the idle CPU mask. Must be released with `put_cpumask`.
#[inline(always)]
pub fn get_idle_cpumask() -> *const cpumask {
    let ret: *const cpumask;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_get_idle_cpumask,
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

/// Get a read-only reference to the idle SMT-sibling mask. Must be released with `put_cpumask`.
#[inline(always)]
pub fn get_idle_smtmask() -> *const cpumask {
    let ret: *const cpumask;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_get_idle_smtmask,
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

/// Release a cpumask reference obtained from `get_idle_cpumask` or `get_idle_smtmask`.
#[inline(always)]
pub fn put_cpumask(mask: *const cpumask) {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_put_cpumask,
            in("r1") mask,
            lateout("r0") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Atomically test and clear the idle bit for `cpu`. Returns true if the CPU was idle.
#[inline(always)]
pub fn test_and_clear_cpu_idle(cpu: i32) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_test_and_clear_cpu_idle,
            in("r1") cpu as i64,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret != 0
}

/// Return true if the task is currently running on a CPU.
#[inline(always)]
pub fn task_running(p: *const task_struct) -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_task_running,
            in("r1") p,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret != 0
}

/// Return the CPU a task is currently assigned to.
#[inline(always)]
pub fn task_cpu(p: *const task_struct) -> i32 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_task_cpu,
            in("r1") p,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as i32
}

/// Return the task_struct of the task currently running on `cpu`.
///
/// Must be called inside an RCU read-side critical section.
#[inline(always)]
pub fn cpu_curr(cpu: i32) -> *mut task_struct {
    let ret: *mut task_struct;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_cpu_curr,
            in("r1") cpu as i64,
            lateout("r0") ret,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret
}

/// Return the current scheduler clock value in nanoseconds.
#[inline(always)]
pub fn now() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_now,
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

/// Select the default idle CPU for a task. Returns the CPU and sets `*is_idle`.
#[inline(always)]
pub fn select_cpu_dfl(
    p: *mut task_struct,
    prev_cpu: i32,
    wake_flags: u64,
    is_idle: *mut bool,
) -> i32 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_select_cpu_dfl,
            in("r1") p,
            in("r2") prev_cpu as i64,
            in("r3") wake_flags,
            in("r4") is_idle,
            lateout("r0") ret,
            lateout("r5") _,
        );
    }
    ret as i32
}

/// Select an idle CPU intersected with an additional cpumask constraint.
///
/// `flags` can include `SCX_PICK_IDLE_CORE` (1) to prefer full-idle SMT cores.
#[inline(always)]
pub fn select_cpu_and(
    p: *mut task_struct,
    prev_cpu: i32,
    wake_flags: u64,
    cpus_allowed: *const cpumask,
    flags: u64,
) -> i32 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym scx_bpf_select_cpu_and,
            in("r1") p,
            in("r2") prev_cpu as i64,
            in("r3") wake_flags,
            in("r4") cpus_allowed,
            in("r5") flags,
            lateout("r0") ret,
        );
    }
    ret as i32
}
