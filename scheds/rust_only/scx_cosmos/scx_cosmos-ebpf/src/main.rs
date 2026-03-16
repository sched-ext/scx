//! scx_cosmos — a deadline + vruntime scheduler, ported from C to pure Rust.
//!
//! This is an incremental port of scx_cosmos. It implements:
//!
//! - `select_cpu`: uses `pick_idle_cpu` with SMT-aware idle scanning,
//!   `select_cpu_dfl` fallback, mm_affinity, busy-aware dispatch, and
//!   no_wake_sync support
//! - `enqueue`: three-tier — migration to idle CPU, local DSQ when not busy,
//!   vtime-ordered shared DSQ when busy (uses task_cpu + task_running kfuncs)
//! - `dispatch`: `dsq_move_to_local` + slice extension for prev task
//! - `running`: updates vtime_now + records per-task last_run_at via task storage,
//!   applies cpufreq performance level
//! - `stopping`: charges actual used time (via scx_bpf_now delta) to dsq_vtime,
//!   accumulates exec_runtime in per-task storage, updates per-CPU load for cpufreq
//! - `runnable`: resets exec_runtime, updates wakeup_freq via per-task storage
//! - `enable`: initializes task dsq_vtime to current vtime_now
//! - `init_task`: creates per-task context via BPF_MAP_TYPE_TASK_STORAGE
//! - `exit_task`: cleans up per-task storage when a task exits
//!
//! BPF map usage:
//! - `TASK_CTX`: per-task storage for exec_runtime, wakeup_freq, last_run_at
//! - `CPU_CTX`: per-CPU array for load tracking (last_update, perf_lvl)
//!
//! Userspace-configurable globals:
//! - `SLICE_NS`, `SLICE_LAG`: time slice and maximum runtime parameters
//! - `BUSY_THRESHOLD`, `CPU_UTIL`: system busy detection
//! - `NO_WAKE_SYNC`, `CPUFREQ_ENABLED`, `SMT_ENABLED`, `AVOID_SMT`: feature flags
//! - `MM_AFFINITY`: address space affinity for cache-friendly wakeups
//! - `NUMA_ENABLED`, `NR_NODES`, `CPU_TO_NODE`: NUMA-aware per-node DSQ routing
//!
//! Remaining gaps vs the full C implementation (see PORT_TODO comments):
//! - No PMU tracking
//! - No flat/preferred idle scan, no primary_cpumask
//! - Migration only tries prev_cpu (no full pick_idle_cpu scan in enqueue)

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use scx_ebpf::prelude::*;
use scx_ebpf::core_read;
use scx_ebpf::maps::{TaskStorage, PerCpuArray};
use scx_ebpf::kptr::{Kptr, kptr_xchg, rcu_read_lock, rcu_read_unlock};
use scx_ebpf::cpumask::{self, bpf_cpumask};

scx_ebpf::scx_ebpf_boilerplate!();

/// Generated vmlinux struct definitions with real field layouts.
mod vmlinux {
    include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
}

// ── Per-task context ────────────────────────────────────────────────────

/// Per-task context stored in BPF_MAP_TYPE_TASK_STORAGE.
///
/// Mirrors the C cosmos `struct task_ctx`:
/// - `exec_runtime`: accumulated CPU time since last sleep (for deadline calc)
/// - `wakeup_freq`: exponentially-smoothed wakeup frequency (for slice_lag scaling)
/// - `last_run_at`: timestamp when this task last started running
/// - `last_woke_at`: timestamp of last wakeup (for wakeup_freq calculation)
#[repr(C)]
#[derive(Copy, Clone)]
struct TaskCtx {
    exec_runtime: u64,
    wakeup_freq: u64,
    last_run_at: u64,
    last_woke_at: u64,
}

/// Per-CPU context stored in BPF_MAP_TYPE_PERCPU_ARRAY.
///
/// Tracks per-CPU scheduling state for load tracking and cpufreq scaling.
/// - `last_update`: timestamp of last scheduling update on this CPU
/// - `perf_lvl`: EWMA-smoothed CPU performance level [0..1024]
#[repr(C)]
#[derive(Copy, Clone)]
struct CpuCtx {
    last_update: u64,
    perf_lvl: u64,
}

// ── BPF map declarations ────────────────────────────────────────────────

/// Per-task storage map. Automatically freed when a task exits.
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
static TASK_CTX: TaskStorage<TaskCtx> = TaskStorage::new();

/// Per-CPU context array (1 entry, each CPU gets its own copy).
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
static CPU_CTX: PerCpuArray<CpuCtx, 1> = PerCpuArray::new();

// ── Constants ───────────────────────────────────────────────────────────

/// Shared DSQ used for deadline-mode scheduling when the system is saturated.
const SHARED_DSQ: u64 = 0;

/// Maximum number of CPUs supported (matches C cosmos MAX_CPUS).
const MAX_CPUS: usize = 1024;

/// Maximum number of NUMA nodes supported (matches C cosmos MAX_NODES).
const MAX_NODES: u32 = 1024;

/// SCX_TASK_QUEUED flag in scx entity flags.
const SCX_TASK_QUEUED: u32 = 1;

/// SCX_KICK_IDLE flag for kick_cpu.
const SCX_KICK_IDLE: u64 = 1;

/// SCX_WAKE_SYNC flag value (from kernel enum).
const SCX_WAKE_SYNC: u64 = 16;

/// Maximum CPU performance level (SCX_CPUPERF_ONE = 1024).
const SCX_CPUPERF_ONE: u64 = 1024;

/// Below this threshold, reduce cpufreq to half.
const CPUFREQ_LOW_THRESH: u64 = SCX_CPUPERF_ONE / 4;

/// Above this threshold, raise cpufreq to maximum.
const CPUFREQ_HIGH_THRESH: u64 = SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4;

/// PF_EXITING flag in task_struct.flags — task is in the process of exiting.
/// Used by is_wake_affine() to skip wakers that are exiting.
const PF_EXITING: u32 = 0x00000004;

// ── Userspace-configurable globals ──────────────────────────────────────
//
// These are `#[unsafe(no_mangle)] static mut` globals that userspace can
// set before loading the BPF program (via EbpfLoader::set_global) or
// update at runtime (via map operations on .bss/.data/.rodata).
//
// C reference uses `const volatile` for compile-time-set globals and
// `volatile` for runtime-updated globals.

/// Default time slice: 10us (matches C cosmos `slice_ns = 10000`).
#[unsafe(no_mangle)]
static mut SLICE_NS: u64 = 10_000;

/// Maximum runtime that can be charged to a task (bounds vruntime jumps).
#[unsafe(no_mangle)]
static mut SLICE_LAG: u64 = 20_000_000;

/// CPU utilization threshold for system busy detection [0..1024].
/// When `CPU_UTIL >= BUSY_THRESHOLD`, the system is considered busy.
/// C reference: `const volatile u64 busy_threshold`
#[unsafe(no_mangle)]
static mut BUSY_THRESHOLD: u64 = 75;

/// Current global CPU utilization [0..1024], set by userspace polling loop.
/// C reference: `volatile u64 cpu_util`
#[unsafe(no_mangle)]
static mut CPU_UTIL: u64 = 0;

/// When true, clear SCX_WAKE_SYNC from wake_flags in select_cpu.
/// C reference: `const volatile bool no_wake_sync`
#[unsafe(no_mangle)]
static mut NO_WAKE_SYNC: bool = false;

/// When true, enable cpufreq performance scaling in running/stopping.
/// C reference: `const volatile bool cpufreq_enabled = true`
#[unsafe(no_mangle)]
static mut CPUFREQ_ENABLED: bool = true;

/// When true, CPUs have SMT (hyperthreading) enabled.
/// C reference: `const volatile bool smt_enabled = true`
#[unsafe(no_mangle)]
static mut SMT_ENABLED: bool = true;

/// When true, try to avoid placing tasks on SMT siblings of busy cores.
/// C reference: `const volatile bool avoid_smt = true`
#[unsafe(no_mangle)]
static mut AVOID_SMT: bool = true;

/// When true, enable NUMA-aware per-node DSQ routing.
/// C reference: `const volatile bool numa_enabled`
#[unsafe(no_mangle)]
static mut NUMA_ENABLED: bool = false;

/// Number of NUMA nodes on this system, set by userspace.
/// C reference: `const volatile u32 nr_node_ids`
#[unsafe(no_mangle)]
static mut NR_NODES: u32 = 1;

/// CPU-to-NUMA-node mapping, populated by userspace via .bss.
/// C reference: `cpu_node_map` BPF hash map (we use a flat array instead).
/// Each entry maps a CPU index to its NUMA node ID.
#[unsafe(no_mangle)]
static mut CPU_TO_NODE: [u32; MAX_CPUS] = [0; MAX_CPUS];

// PORT_TODO: primary_cpumask and primary_all for preferred CPU domain
// C reference: `private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask`
// and `const volatile bool primary_all = true` control a subset of CPUs
// to prioritize. enable_primary_cpu() is a syscall program that sets bits.
//
// KPTR EXPERIMENT: Below is a prototype kptr global using the Kptr<T>
// wrapper. This compiles and generates the right runtime code, but the
// BPF verifier will reject bpf_kptr_xchg() calls because the Rust
// compiler does not emit BTF_KIND_TYPE_TAG "kptr" annotations.
//
// See kptr.rs module docs and the findings at the bottom of this file
// for details on the BTF gap and workaround strategies.

/// Primary cpumask kptr — prototype kptr storage.
///
/// In C: `private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask;`
///
/// NOTE: This is placed in `.data` (not `.bss`) because kptr globals in
/// C are typically in the `.data` section. The section matters because
/// the verifier resolves kptr locations relative to map values, and
/// `.data` / `.bss` are loaded as implicit BPF maps.
#[unsafe(no_mangle)]
static mut PRIMARY_CPUMASK: Kptr<bpf_cpumask> = Kptr::zeroed();

/// When true, primary domain includes all CPUs (primary_cpumask is empty/unused).
#[unsafe(no_mangle)]
static mut PRIMARY_ALL: bool = true;

// PORT_TODO: flat_idle_scan and preferred_idle_scan modes
// C reference: When flat_idle_scan or preferred_idle_scan is true, cosmos
// uses pick_idle_cpu_flat() which iterates CPUs in preferred order or
// round-robin to find idle cores. Requires preferred_cpus[] array and
// cpu_capacity[] array from userspace. These are large arrays (MAX_CPUS=1024
// entries) that need userspace to sort CPUs by capacity and populate.

/// When true, enable address space affinity in select_cpu.
/// Keeps wakee on the waker's CPU when they share the same mm (address space),
/// improving cache locality for tasks that share memory (e.g., threads).
/// C reference: `const volatile bool mm_affinity`
#[unsafe(no_mangle)]
static mut MM_AFFINITY: bool = false;

// PORT_TODO: PMU / perf event integration
// C reference: perf_config selects a hardware counter. scx_pmu_event_start/stop
// track per-task events. is_event_heavy() checks if a task exceeds
// perf_threshold. pick_least_busy_event_cpu() distributes event-heavy tasks.
// Requires BPF perf event support (scx_pmu_install/scx_pmu_read kfuncs).

// ── Global state ────────────────────────────────────────────────────────

/// Current global vruntime — tracks the most recent dsq_vtime seen.
static mut VTIME_NOW: u64 = 0;

/// Number of CPUs on this system, set in init().
static mut NR_CPU_IDS: u32 = 0;

// ── Helpers ─────────────────────────────────────────────────────────────

/// Write a u64 field in a kernel struct at a known compile-time offset.
#[inline(always)]
unsafe fn write_field_u64(base: *mut task_struct, offset: usize, val: u64) {
    let ptr = (base as *mut u8).add(offset) as *mut u64;
    core::ptr::write_volatile(ptr, val);
}

/// BPF helper #158: `bpf_get_current_task_btf() -> *mut task_struct`
///
/// Returns a pointer to the current task's task_struct with BTF type info.
/// Used to access the waker's task in select_cpu for mm_affinity.
#[inline(always)]
fn get_current_task_btf() -> *mut task_struct {
    let ret: *mut task_struct;
    unsafe {
        core::arch::asm!(
            "call 158",
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

/// BPF helper #8: `bpf_get_smp_processor_id() -> u32`
///
/// Returns the ID of the CPU on which the BPF program is currently running.
#[inline(always)]
fn get_smp_processor_id() -> i32 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call 8",
            lateout("r0") ret,
            lateout("r1") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    ret as i32
}

/// Check if the waker and wakee share the same address space.
///
/// Returns true when mm_affinity is enabled, the waker is not exiting,
/// and both tasks share the same mm_struct (same address space -- typically
/// threads of the same process). Used to keep the wakee on the waker's
/// CPU for cache locality.
///
/// C reference: `is_wake_affine(waker, wakee)`:
///   return mm_affinity &&
///       !(waker->flags & PF_EXITING) && wakee->mm && (wakee->mm == waker->mm);
#[inline(always)]
fn is_wake_affine(waker: *mut task_struct, wakee: *mut task_struct) -> bool {
    if !unsafe { MM_AFFINITY } {
        return false;
    }

    // Read waker->flags to check PF_EXITING.
    let waker_flags = if let Ok(f) = core_read!(vmlinux::task_struct, waker, flags) {
        f
    } else {
        return false;
    };
    if waker_flags & PF_EXITING != 0 {
        return false;
    }

    // Read wakee->mm (a pointer -- compare as u64 for address equality).
    let wakee_mm = if let Ok(mm) = core_read!(vmlinux::task_struct, wakee, mm) {
        mm as u64
    } else {
        return false;
    };
    if wakee_mm == 0 {
        return false;
    }

    // Read waker->mm.
    let waker_mm = if let Ok(mm) = core_read!(vmlinux::task_struct, waker, mm) {
        mm as u64
    } else {
        return false;
    };

    wakee_mm == waker_mm
}

/// Read the current slice_ns value (from userspace-configurable global).
#[inline(always)]
fn get_slice_ns() -> u64 {
    unsafe { SLICE_NS }
}

/// Read the current slice_lag value (from userspace-configurable global).
#[inline(always)]
fn get_slice_lag() -> u64 {
    unsafe { SLICE_LAG }
}

/// Compute a weight-scaled time slice: slice_ns * weight / 100.
/// This matches C cosmos `task_slice()` = `scale_by_task_weight(p, slice_ns)`.
#[inline(always)]
fn task_slice(weight: u64) -> u64 {
    let slice_ns = get_slice_ns();
    if weight > 0 { (slice_ns * weight) / 100 } else { slice_ns }
}

/// Read the task's scx.weight, defaulting to 100 (NICE 0).
#[inline(always)]
fn read_weight(p: *mut task_struct) -> u64 {
    if let Ok(w) = core_read!(vmlinux::task_struct, p, scx.weight) {
        w as u64
    } else {
        100
    }
}

/// Determine if the system is busy (saturated).
///
/// Uses userspace-provided CPU utilization when available (CPU_UTIL > 0),
/// falling back to DSQ queue depth when userspace hasn't set it yet.
/// C reference: `is_system_busy()` returns `cpu_util >= busy_threshold`.
#[inline(always)]
fn is_system_busy() -> bool {
    let cpu_util = unsafe { CPU_UTIL };
    if cpu_util > 0 {
        // Userspace has set CPU utilization — use threshold comparison.
        let threshold = unsafe { BUSY_THRESHOLD };
        cpu_util >= threshold
    } else {
        // Fallback: userspace hasn't set CPU_UTIL yet, approximate
        // by checking if the shared DSQ has queued tasks.
        kfuncs::dsq_nr_queued(SHARED_DSQ) > 0
    }
}

/// Return the DSQ ID for the given CPU.
///
/// When NUMA is enabled, each NUMA node gets its own DSQ (DSQ ID = node ID).
/// Tasks are routed to their node's DSQ to keep memory-local scheduling.
/// When NUMA is disabled, all CPUs share a single DSQ (SHARED_DSQ = 0).
///
/// C reference: `shared_dsq(cpu)` returns `cpu_node(cpu)` when numa_enabled.
#[inline(always)]
fn shared_dsq(cpu: i32) -> u64 {
    if unsafe { NUMA_ENABLED } {
        // Bounds-check for BPF verifier: cpu must be within array.
        let idx = cpu as u32 as usize;
        if idx < MAX_CPUS {
            unsafe { CPU_TO_NODE[idx] as u64 }
        } else {
            SHARED_DSQ
        }
    } else {
        SHARED_DSQ
    }
}

/// Exponential weighted moving average (EWMA).
///
/// Matches C cosmos `calc_avg()`:
///   new_avg = (old_val * 0.75) + (new_val * 0.25)
#[inline(always)]
fn calc_avg(old_val: u64, new_val: u64) -> u64 {
    (old_val - (old_val >> 2)) + (new_val >> 2)
}

/// Exponential moving average update for wakeup frequency tracking.
///
/// Computes `update_freq(old_freq, delta_t)` matching the C cosmos logic:
///   new_freq = (1024 * NSEC_PER_MSEC) / delta_t
///   smoothed = (old_freq + new_freq) / 2
///
/// Capped at 1024 to prevent overflow.
#[inline(always)]
fn update_freq(old_freq: u64, delta_ns: u64) -> u64 {
    // Avoid division by zero; if delta is tiny, cap at max frequency.
    if delta_ns == 0 {
        return 1024;
    }
    // 1024 * 1_000_000 = 1024 * NSEC_PER_MSEC
    let new_freq = (1024 * 1_000_000) / delta_ns;
    let smoothed = (old_freq + new_freq) / 2;
    if smoothed > 1024 { 1024 } else { smoothed }
}

// ── Cpufreq helpers ─────────────────────────────────────────────────────

/// Update the per-CPU load tracking and compute a new EWMA performance level.
///
/// Called from `on_stopping()` after computing the actual used time slice.
/// C reference: `update_cpu_load(p, slice)` computes perf_lvl as
///   MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE)
/// and smooths it with EWMA via calc_avg().
#[inline(always)]
fn update_cpu_load(slice: u64, now: u64) {
    if unsafe { !CPUFREQ_ENABLED } {
        return;
    }

    let cctx = CPU_CTX.get_ptr_mut(0);
    if cctx.is_null() {
        return;
    }
    let cctx = unsafe { &mut *cctx };

    let delta_t = now.wrapping_sub(cctx.last_update);
    if delta_t == 0 {
        return;
    }

    // Compute instantaneous performance level.
    let perf_lvl = {
        let raw = slice * SCX_CPUPERF_ONE / delta_t;
        if raw > SCX_CPUPERF_ONE { SCX_CPUPERF_ONE } else { raw }
    };

    // Smooth with EWMA.
    cctx.perf_lvl = calc_avg(cctx.perf_lvl, perf_lvl);
    cctx.last_update = now;
}

/// Apply the target cpufreq performance level to the current CPU.
///
/// Called from `on_running()` to set the CPU frequency based on recent load.
/// Uses hysteresis thresholds: below LOW -> half, above HIGH -> max,
/// between -> use the smoothed value.
/// C reference: `update_cpufreq(cpu)`.
#[inline(always)]
fn update_cpufreq(cpu: i32) {
    if unsafe { !CPUFREQ_ENABLED } {
        return;
    }

    let cctx = CPU_CTX.get_ptr_mut(0);
    if cctx.is_null() {
        return;
    }
    let perf_lvl_stored = unsafe { (*cctx).perf_lvl };

    // Apply hysteresis thresholds.
    let perf_lvl = if perf_lvl_stored >= CPUFREQ_HIGH_THRESH {
        SCX_CPUPERF_ONE
    } else if perf_lvl_stored <= CPUFREQ_LOW_THRESH {
        SCX_CPUPERF_ONE / 2
    } else {
        perf_lvl_stored
    };

    kfuncs::cpuperf_set(cpu, perf_lvl as u32);
}

// ── Idle CPU selection ──────────────────────────────────────────────────

/// Pick an idle CPU for a task, with SMT awareness.
///
/// Uses `#[inline(always)]` instead of `#[inline(never)]` because aya's
/// kfunc resolution does not yet handle BPF subprograms: after function
/// linking, subprogram instructions are appended to the main function
/// at new offsets, but `fixup_kfunc_calls()` still uses the original
/// section offsets to look up relocations, so kfunc calls in subprograms
/// get left as `imm=0` and the verifier rejects them with "invalid kernel
/// function call not eliminated". Once aya fixes this, switch to
/// `#[inline(never)]` for its own register scope.
///
/// Tries two strategies:
///
/// 1. **`select_cpu_dfl()`** — the kernel's default idle CPU picker.
///    Always tried first; this handles wake-affine, LLC locality, and
///    basic idle scanning.
///
/// 2. **SMT verification** — when `AVOID_SMT` is enabled and strategy 1
///    found an idle CPU, we check whether the entire physical core is
///    idle (both SMT siblings) using `get_idle_smtmask()`. If the found
///    CPU's core is not fully idle, we reject it and return -1 so the
///    caller falls back to non-idle dispatch.
///
/// Returns the idle CPU number (>= 0) if one was found, or a negative
/// value if no suitable idle CPU is available.
///
/// C reference: `pick_idle_cpu()` in `main.bpf.c` with a simplified
/// strategy set (no flat_idle_scan, no preferred_idle_scan, no hybrid
/// core migration, no primary cpumask filtering).
// PORT_TODO: Enhanced pick_idle_cpu() with primary cpumask filtering
// C reference: When primary_all is false and primary_cpumask is set,
// pick_idle_cpu() first tries scx_bpf_select_cpu_and() with the primary
// mask and SCX_PICK_IDLE_CORE, falling back to the full cpus_ptr.
// Requires kptr support for primary_cpumask.
//
// PORT_TODO: flat_idle_scan and preferred_idle_scan modes
// C reference: When flat_idle_scan or preferred_idle_scan is true, cosmos
// uses pick_idle_cpu_flat() which iterates CPUs in preferred order or
// round-robin to find idle cores. Requires preferred_cpus[] array and
// cpu_capacity[] array from userspace.
//
// PORT_TODO: Hybrid core wake-affine migration
// C reference: When primary_all and the waker's CPU is faster than the
// wakee's CPU (is_cpu_faster()), pick_idle_cpu() migrates prev_cpu to
// this_cpu to naturally move tasks to faster cores. Requires
// cpu_capacity[] array from userspace.
#[inline(always)]
fn pick_idle_cpu(p: *mut task_struct, prev_cpu: i32, wake_flags: u64) -> i32 {
    // Strategy 1: kernel's default idle CPU selection.
    let mut is_idle: bool = false;
    let cpu = kfuncs::select_cpu_dfl(p, prev_cpu, wake_flags, &mut is_idle);

    if !is_idle {
        // No idle CPU found — nothing more to try.
        return -1;
    }

    // Strategy 2: SMT-aware verification.
    // If avoid_smt is enabled, check whether the found CPU's physical
    // core is fully idle (both SMT siblings). If not, reject it to
    // avoid contention on the same core.
    //
    // The idle SMT mask has a bit set for each CPU whose SMT sibling(s)
    // are ALL idle. So if cpu is set in the smtmask, the entire core
    // is idle and it's a good pick.
    if unsafe { SMT_ENABLED } && unsafe { AVOID_SMT } {
        let smtmask = kfuncs::get_idle_smtmask();
        let core_idle = cpumask::test_cpu(cpu as u32, smtmask);
        kfuncs::put_cpumask(smtmask);

        if !core_idle {
            // The CPU is idle but its SMT sibling is busy. Reject it.
            // The caller can still dispatch locally (non-idle path)
            // or let enqueue() handle it.
            return -1;
        }
    }

    cpu
}

// ── Scheduler callbacks ─────────────────────────────────────────────────

/// select_cpu: find an idle CPU for the task.
///
/// Uses `pick_idle_cpu()` for idle CPU selection with:
/// - no_wake_sync: clears SCX_WAKE_SYNC from wake_flags when enabled.
/// - SMT awareness: when avoid_smt is enabled, prefers fully-idle cores
/// - mm_affinity: when enabled and waker/wakee share the same address space,
///   keeps the wakee on the waker's CPU for cache locality (non-busy only)
/// - If idle CPU found: dispatch directly to local DSQ (any saturation level)
/// - If no idle CPU and not busy: dispatch to local DSQ (round-robin)
/// - If no idle CPU and busy: do NOT dispatch, let enqueue() handle
///   deadline-mode dispatch to the shared DSQ
//
// PORT_TODO: PMU / perf event integration in select_cpu
// C reference: When perf_config is set, cosmos_select_cpu dispatches
// event-heavy tasks via pick_least_busy_event_cpu(). Requires BPF perf
// event support (scx_pmu kfuncs).
#[inline(always)]
pub fn on_select_cpu(p: *mut task_struct, prev_cpu: i32, wake_flags: u64) -> i32 {
    // Clear SCX_WAKE_SYNC if no_wake_sync is enabled.
    // C: if (no_wake_sync) wake_flags &= ~SCX_WAKE_SYNC;
    let effective_wake_flags = if unsafe { NO_WAKE_SYNC } {
        wake_flags & !SCX_WAKE_SYNC
    } else {
        wake_flags
    };

    let is_busy = is_system_busy();

    // mm_affinity: when the waker and wakee share the same address space
    // (same mm) and the waker is currently running on the same CPU as
    // prev_cpu, keep the wakee on prev_cpu for cache locality.
    //
    // This optimization only applies when the system is not saturated,
    // to avoid introducing too much unfairness.
    //
    // C reference: cosmos_select_cpu():
    //   if (is_wake_affine(current, p) && !is_busy) {
    //       if (this_cpu == prev_cpu) {
    //           scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);
    //           return this_cpu;
    //       }
    //   }
    if !is_busy {
        let current = get_current_task_btf();
        if !current.is_null() && is_wake_affine(current, p) {
            let this_cpu = get_smp_processor_id();
            if this_cpu == prev_cpu {
                let weight = read_weight(p);
                let slice = task_slice(weight);
                kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, 0);
                return this_cpu;
            }
        }
    }

    let cpu = pick_idle_cpu(p, prev_cpu, effective_wake_flags);
    let found_idle = cpu >= 0;

    // Dispatch to local DSQ when:
    // 1. An idle CPU was found (always dispatch, regardless of busy state), or
    // 2. No idle CPU but system is not busy (round-robin mode)
    //
    // When busy and no idle CPU, don't dispatch — let enqueue() handle
    // deadline-mode dispatch to the shared DSQ for fairness.
    // C: if (cpu >= 0 || !is_busy) dsq_insert(LOCAL, ...);
    if found_idle || !is_busy {
        let weight = read_weight(p);
        let slice = task_slice(weight);
        kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, 0);
    }

    // Return the idle CPU if found, otherwise prev_cpu.
    // C: return cpu >= 0 ? cpu : prev_cpu;
    if found_idle { cpu } else { prev_cpu }
}

/// enqueue: three-tier dispatch — migration, local round-robin, or shared DSQ.
///
/// Mirrors the C cosmos_enqueue() pattern:
///
/// 1. **Migration attempt** (wakeup path): If the task is not currently
///    running (i.e., this is a wakeup), try to find an idle CPU and
///    dispatch directly there via `SCX_DSQ_LOCAL_ON`. This avoids
///    waiting for dispatch() and gets the task running immediately.
///
/// 2. **Local round-robin** (low load): When the system is not busy,
///    dispatch to the local DSQ for simple round-robin scheduling.
///    If the task should migrate, kick prev_cpu to wake it.
///
/// 3. **Deadline mode** (high load): When the system is busy,
///    dispatch to the shared DSQ with vtime-based ordering for fairness.
///
/// If select_cpu already dispatched the task (via SCX_DSQ_LOCAL), this
/// callback is not invoked by the kernel.
///
/// ## Trusted pointer usage
///
/// The BPF verifier preserves PTR_TRUSTED in callee-saved registers (R6-R9)
/// across kfunc calls. The scx kfuncs (task_cpu, task_running, dsq_insert)
/// are KF_RCU, NOT KF_RELEASE, so they do not invalidate trusted pointers.
/// This means we can call multiple kfuncs on the same `p` safely.
///
/// To minimize register pressure (only R6-R9 available), we:
/// - Read struct fields (via core_read!) AFTER the kfunc calls, not before
/// - Use early-return branches to limit live variable scope
/// - Compute deadline values only in the branch that needs them
#[inline(always)]
pub fn on_enqueue(p: *mut task_struct, enq_flags: u64) {
    // ── Phase 1: kfunc calls ─────────────────────────────────────────
    // Call kfuncs first while register pressure is minimal.
    // p is in a callee-saved register; these KF_RCU kfuncs preserve it.
    let prev_cpu = kfuncs::task_cpu(p);
    let is_running = kfuncs::task_running(p);

    // ── Phase 2: migration attempt ───────────────────────────────────
    // C: if (task_should_migrate(p, enq_flags)) { ... }
    // task_should_migrate = !is_running (simplified; full version also
    // checks SCX_ENQ_CPU_SELECTED which isn't available yet).
    //
    // If the task is waking up (not running), try to find an idle CPU
    // and dispatch directly there for minimal latency.
    if !is_running {
        if kfuncs::test_and_clear_cpu_idle(prev_cpu) {
            // prev_cpu is idle — dispatch there directly.
            let weight = read_weight(p);
            let slice = task_slice(weight);
            kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL_ON | prev_cpu as u64, slice, enq_flags);
            // Kick the CPU to wake it up.
            kfuncs::kick_cpu(prev_cpu, SCX_KICK_IDLE);
            return;
        }
        // PORT_TODO: full pick_idle_cpu() scan across all CPUs
        // C reference: pick_idle_cpu(p, prev_cpu, -1, 0, true) tries
        // multiple strategies: primary cpumask, SMT-aware scan, etc.
        // For now we only try prev_cpu via test_and_clear_cpu_idle.
    }

    // ── Phase 3: local dispatch when not busy ────────────────────────
    // C: if (!is_system_busy()) { dsq_insert(LOCAL, ...); wakeup_cpu(); }
    if !is_system_busy() {
        let weight = read_weight(p);
        let slice = task_slice(weight);
        kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, enq_flags);
        // If the task should migrate (wakeup), kick prev_cpu.
        if !is_running {
            kfuncs::kick_cpu(prev_cpu, SCX_KICK_IDLE);
        }
        return;
    }

    // ── Phase 4: deadline mode to shared DSQ ─────────────────────────
    // Read struct fields now — we've finished all the kfunc calls that
    // need minimal register pressure.
    let vtime = if let Ok(v) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        v
    } else {
        unsafe { VTIME_NOW }
    };
    let weight = read_weight(p);
    let slice = task_slice(weight);

    // Compute deadline using exec_runtime from per-task storage.
    // C: task_dl() = dsq_vtime + scale_inverse(exec_runtime)
    // Tasks with more accumulated runtime get higher (later) deadlines,
    // prioritizing interactive tasks that sleep frequently.
    let (deadline, wakeup_freq) = if let Some(tctx) = TASK_CTX.get(p as *mut u8) {
        let tctx = unsafe { tctx.as_ref() };
        let er = tctx.exec_runtime;
        let wf = tctx.wakeup_freq;
        let dl = if weight > 0 {
            vtime.wrapping_add(er * 100 / weight)
        } else {
            vtime.wrapping_add(er)
        };
        (dl, wf)
    } else {
        (vtime, 0u64)
    };

    // Clamp vtime so tasks don't accumulate too much credit from sleeping.
    // C: vtime_min = vtime_now - scale_by_task_weight(p, slice_lag)
    let vtime_now = unsafe { VTIME_NOW };
    let slice_lag = get_slice_lag();

    // Scale slice_lag by wakeup frequency: tasks that wake up often get
    // more vtime credit (larger effective slice_lag).
    // C: wakeup_freq_lag = slice_lag + slice_lag * tctx->wakeup_freq / 1024
    let effective_lag = slice_lag + slice_lag * wakeup_freq / 1024;
    let vsleep_max = if weight > 0 { (effective_lag * weight) / 100 } else { effective_lag };
    let vtime_min = vtime_now.wrapping_sub(vsleep_max);
    let clamped_deadline = if deadline < vtime_min { vtime_min } else { deadline };

    // Write clamped vtime back if it changed.
    if clamped_deadline != vtime {
        let offset = core::mem::offset_of!(vmlinux::task_struct, scx.dsq_vtime);
        unsafe { write_field_u64(p, offset, clamped_deadline); }
    }

    kfuncs::dsq_insert_vtime(p, shared_dsq(prev_cpu), slice, clamped_deadline, enq_flags);

    // If the task should migrate (wakeup), kick prev_cpu.
    // C: if (task_should_migrate(p, enq_flags)) wakeup_cpu(prev_cpu);
    if !is_running {
        kfuncs::kick_cpu(prev_cpu, SCX_KICK_IDLE);
    }
}

/// dispatch: consume from the shared DSQ.
///
/// If the shared DSQ has a task, move it to the local CPU. Otherwise,
/// if the previous task is still queued (expired its slice but no
/// contention), extend its slice to avoid unnecessary context switches.
///
/// When NUMA is enabled, consumes from the per-node DSQ for this CPU's
/// NUMA node instead of the single global shared DSQ.
/// C reference: `scx_bpf_dsq_move_to_local(shared_dsq(cpu))`
#[inline(always)]
pub fn on_dispatch(cpu: i32, prev: *mut task_struct) {
    if kfuncs::dsq_move_to_local(shared_dsq(cpu)) {
        return;
    }

    // If the previous task's time slice expired but no other task is
    // waiting, let it continue with a fresh slice.
    // C: if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
    //        prev->scx.slice = task_slice(prev);
    if !prev.is_null() {
        // Read flags and weight together as a u64 to avoid the LLVM BPF
        // backend bug where consecutive bpf_probe_read_kernel calls with
        // the same size arg skip re-materializing r2.
        // scx.flags is at offset 816 (u32), scx.weight is at offset 820 (u32).
        // Reading 8 bytes at offset 816 gets both in one call.
        let base = prev as *const u8;
        let flags_offset = core::mem::offset_of!(vmlinux::task_struct, scx.flags);
        let src = unsafe { base.add(flags_offset) as *const u64 };
        if let Ok(flags_and_weight) = unsafe { scx_ebpf::helpers::probe_read_kernel(src) } {
            let flags = flags_and_weight as u32;
            let weight = (flags_and_weight >> 32) as u64;
            if flags & SCX_TASK_QUEUED != 0 {
                let slice = task_slice(weight);
                let offset = core::mem::offset_of!(vmlinux::task_struct, scx.slice);
                unsafe { write_field_u64(prev, offset, slice); }
            }
        }
    }
}

/// runnable: called when a task becomes runnable (wakeup or new fork).
///
/// Resets exec_runtime and updates wakeup frequency in per-task storage.
/// C reference: cosmos_runnable() does:
///   tctx->exec_runtime = 0;
///   delta_t = now - tctx->last_woke_at;
///   tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
///   tctx->wakeup_freq = MIN(tctx->wakeup_freq, 1024);
///   tctx->last_woke_at = now;
#[inline(always)]
pub fn on_runnable(p: *mut task_struct, _enq_flags: u64) {
    let now = kfuncs::now();
    if let Some(mut tctx) = TASK_CTX.get(p as *mut u8) {
        let tctx = unsafe { tctx.as_mut() };
        // Reset accumulated runtime — task just woke up.
        tctx.exec_runtime = 0;
        // Update wakeup frequency using time since last wakeup.
        let delta = now.wrapping_sub(tctx.last_woke_at);
        tctx.wakeup_freq = update_freq(tctx.wakeup_freq, delta);
        tctx.last_woke_at = now;
    }
}

/// running: update vtime_now, record run start time, and apply cpufreq.
///
/// Advances the global vruntime to track the most recent task's vtime.
/// Records the timestamp in per-task storage for accurate time-slice
/// charging in stopping(). Applies the per-CPU cpufreq performance level.
///
/// C reference: cosmos_running() calls update_cpufreq(scx_bpf_task_cpu(p)).
#[inline(always)]
pub fn on_running(p: *mut task_struct) {
    // Record run start time in per-task storage.
    // C: tctx->last_run_at = scx_bpf_now();
    let now = kfuncs::now();
    if let Some(mut tctx) = TASK_CTX.get(p as *mut u8) {
        unsafe { tctx.as_mut().last_run_at = now; }
    }

    // Update per-CPU context timestamp.
    let cctx = CPU_CTX.get_ptr_mut(0);
    if !cctx.is_null() {
        unsafe { (*cctx).last_update = now; }
    }

    // Update current system's vruntime.
    // C: if (time_before(vtime_now, p->scx.dsq_vtime))
    //        vtime_now = p->scx.dsq_vtime;
    if let Ok(dsq_vtime) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        unsafe {
            if VTIME_NOW < dsq_vtime {
                VTIME_NOW = dsq_vtime;
            }
        }
    }

    // Apply cpufreq performance level based on recent load.
    // C: update_cpufreq(scx_bpf_task_cpu(p));
    if unsafe { CPUFREQ_ENABLED } {
        let cpu = kfuncs::task_cpu(p);
        update_cpufreq(cpu);
    }
}

/// stopping: charge the actual used time slice, update dsq_vtime, and
/// update per-CPU load for cpufreq scaling.
///
/// Uses the per-task last_run_at timestamp to compute the real time delta,
/// capped at slice_ns. Advances dsq_vtime inversely proportional to
/// weight (higher weight = slower vtime advancement = more CPU time).
/// Also accumulates exec_runtime in per-task storage for deadline calculation.
///
/// C reference: cosmos_stopping() calls update_cpu_load(p, slice) which
/// computes perf_lvl = MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE)
/// and smooths it with EWMA.
// PORT_TODO: PMU counter update in stopping
// C reference: scx_pmu_event_stop(p) + update_counters(p, tctx, cpu)
// reads perf event delta and stores in per-task and per-CPU contexts.
// Requires scx_pmu_event_stop/scx_pmu_read kfuncs.
#[inline(always)]
pub fn on_stopping(p: *mut task_struct, _runnable: bool) {
    // Read ALL fields before writing.
    let old_vtime = if let Ok(v) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        v
    } else {
        return;
    };

    let weight = read_weight(p);
    let slice_ns = get_slice_ns();
    let slice_lag = get_slice_lag();

    // Compute actual time slice used from per-task last_run_at, and
    // update exec_runtime, all in a single TASK_CTX lookup to avoid
    // the LLVM BPF backend register clobber bug (see helpers.rs docs).
    // C: slice = MIN(scx_bpf_now() - tctx->last_run_at, slice_ns);
    // C: tctx->exec_runtime = MIN(tctx->exec_runtime + slice, slice_lag)
    let now = kfuncs::now();
    let slice = if let Some(mut tctx) = TASK_CTX.get(p as *mut u8) {
        let tctx = unsafe { tctx.as_mut() };
        let delta = now.wrapping_sub(tctx.last_run_at);
        let s = if delta < slice_ns { delta } else { slice_ns };
        // Update exec_runtime while we have the pointer.
        let new_runtime = tctx.exec_runtime + s;
        tctx.exec_runtime = if new_runtime > slice_lag { slice_lag } else { new_runtime };
        s
    } else {
        slice_ns
    };

    // C: p->scx.dsq_vtime += scale_by_task_weight_inverse(p, slice);
    // scale_by_task_weight_inverse(p, v) = v * 100 / weight
    let vtime_delta = if weight > 0 { slice * 100 / weight } else { slice };
    let new_vtime = old_vtime.wrapping_add(vtime_delta);

    let offset = core::mem::offset_of!(vmlinux::task_struct, scx.dsq_vtime);
    unsafe { write_field_u64(p, offset, new_vtime); }

    // Update per-CPU load for cpufreq scaling.
    // C: update_cpu_load(p, slice);
    update_cpu_load(slice, now);
}

/// enable: initialize a task's dsq_vtime to the current global vruntime.
///
/// Direct port of the C cosmos_enable callback.
#[inline(always)]
pub fn on_enable(p: *mut task_struct) {
    let vtime_now = unsafe { VTIME_NOW };
    let offset = core::mem::offset_of!(vmlinux::task_struct, scx.dsq_vtime);
    unsafe { write_field_u64(p, offset, vtime_now); }
}

/// init_task: create per-task context via BPF task storage.
///
/// C reference: cosmos_init_task creates per-task storage via
/// bpf_task_storage_get(&task_ctx_stor, ..., BPF_LOCAL_STORAGE_GET_F_CREATE).
#[inline(always)]
pub fn on_init_task(p: *mut task_struct, _args: *mut core::ffi::c_void) -> i32 {
    // Create per-task storage (zero-initialized by the kernel).
    if TASK_CTX.get_or_create(p as *mut u8).is_none() {
        return -12; // ENOMEM
    }
    0
}

/// exit_task: clean up per-task storage when a task exits.
///
/// Called by the kernel when a task is being destroyed. Deletes the
/// per-task context from the TASK_CTX storage map.
///
/// C reference: cosmos_exit_task() calls scx_pmu_task_fini(p).
/// We don't have PMU support yet, so we just clean up task storage.
// PORT_TODO: PMU per-task cleanup
// C reference: scx_pmu_task_fini(p) cleans up per-task perf event state.
// Requires scx_pmu_task_fini kfunc.
#[inline(always)]
pub fn on_exit_task(p: *mut task_struct, _args: *mut core::ffi::c_void) {
    // Clean up per-task storage.
    let _ = TASK_CTX.delete(p as *mut u8);
}

/// init: create DSQ(s) and record nr_cpu_ids.
///
/// When NUMA is enabled, creates one DSQ per NUMA node (DSQ ID = node ID).
/// Otherwise creates a single shared DSQ (DSQ 0).
/// C reference: `cosmos_init()` with `bpf_for(node, 0, nr_node_ids)`.
// PORT_TODO: PMU installation
// C reference: When perf_config is set, cosmos_init calls scx_pmu_install().

/// Initialize a kptr cpumask: create a new mask and atomically store it.
///
/// Mirrors the C `init_cpumask()` function:
/// ```c
/// static int init_cpumask(struct bpf_cpumask **p_cpumask) {
///     mask = bpf_cpumask_create();
///     mask = bpf_kptr_xchg(p_cpumask, mask);
///     if (mask) bpf_cpumask_release(mask);
/// }
/// ```
///
/// # KPTR EXPERIMENT NOTE
///
/// This function compiles correctly and generates proper BPF instructions
/// for `bpf_kptr_xchg` (helper #194) and the cpumask kfuncs. However,
/// the BPF verifier will reject it because the BTF for `PRIMARY_CPUMASK`
/// lacks the `BTF_KIND_TYPE_TAG "kptr"` annotation.
///
/// Expected verifier error (one of):
/// - `"arg#0 expected pointer to map value"` — verifier doesn't
///   recognize the global as containing a kptr
/// - `"R1 doesn't point to kptr"` — verifier found the map value
///   but the BTF type chain doesn't have TYPE_TAG "kptr"
#[inline(always)]
fn init_primary_cpumask() -> i32 {
    // Create a new cpumask with all bits cleared.
    let mask = cpumask::create();
    if mask.is_null() {
        return -12; // ENOMEM
    }

    // Atomically store the new mask in the kptr slot.
    // bpf_kptr_xchg returns the old value (should be null on first init).
    let old = unsafe { kptr_xchg(&raw mut PRIMARY_CPUMASK, mask) };
    if !old.is_null() {
        // Release the old mask if there was one (shouldn't happen on init).
        cpumask::release(old);
    }

    // Verify the exchange succeeded by reading back under RCU.
    rcu_read_lock();
    let stored = unsafe { Kptr::get(&raw const PRIMARY_CPUMASK) };
    let ok = !stored.is_null();
    rcu_read_unlock();

    if ok { 0 } else { -12 }
}

#[inline(always)]
pub fn on_init() -> i32 {
    // Record the number of CPUs for bounds checking.
    unsafe { NR_CPU_IDS = kfuncs::nr_cpu_ids(); }

    // Create per-node DSQs when NUMA is enabled, otherwise a single shared DSQ.
    // C: if (numa_enabled) { bpf_for(node, 0, nr_node_ids) create_dsq(node, node); }
    //    else { create_dsq(SHARED_DSQ, -1); }
    if unsafe { NUMA_ENABLED } {
        let nr_nodes = unsafe { NR_NODES };
        // Cap at MAX_NODES to satisfy BPF verifier's bounded loop requirement.
        let max = if nr_nodes < MAX_NODES { nr_nodes } else { MAX_NODES };
        let mut node: u32 = 0;
        while node < max {
            let err = kfuncs::create_dsq(node as u64, node as i32);
            if err != 0 {
                scx_ebpf::scx_bpf_error!("cosmos: failed to create node DSQ");
                return err;
            }
            node += 1;
        }
    } else {
        let err = kfuncs::create_dsq(SHARED_DSQ, -1);
        if err != 0 {
            scx_ebpf::scx_bpf_error!("cosmos: failed to create shared DSQ");
            return err;
        }
    }

    // KPTR EXPERIMENT: Initialize the primary cpumask kptr.
    // This will fail at the verifier until BTF patching is implemented.
    // To test compilation without verifier rejection, set
    // KPTR_EXPERIMENT_ENABLED to false.
    #[cfg(feature = "kptr_experiment")]
    {
        let err = init_primary_cpumask();
        if err != 0 {
            scx_ebpf::scx_bpf_error!("cosmos: failed to init primary cpumask");
            return err;
        }
    }

    0
}

/// exit: no-op for now.
// PORT_TODO: PMU cleanup and UEI_RECORD
// C reference: cosmos_exit() calls scx_pmu_uninstall() when perf_config
// is set, and UEI_RECORD(uei, ei) to save exit info for userspace.
#[inline(always)]
pub fn on_exit(_ei: *mut scx_exit_info) {}

// ── Registration ────────────────────────────────────────────────────────

scx_ebpf::scx_ops_define! {
    name: "cosmos",
    timeout_ms: 5000,
    select_cpu: on_select_cpu,
    enqueue: on_enqueue,
    dispatch: on_dispatch,
    runnable: on_runnable,
    running: on_running,
    stopping: on_stopping,
    enable: on_enable,
    init_task: on_init_task,
    exit_task: on_exit_task,
    init: on_init,
    exit: on_exit,
}

// ── KPTR EXPERIMENT FINDINGS ────────────────────────────────────────────
//
// This file prototypes kptr support for Rust BPF. Here are the findings:
//
// ## What works
//
// 1. The `Kptr<T>` wrapper compiles to the correct memory layout — a
//    single `*mut T` field, identical to C's `struct T __kptr *`.
//
// 2. The `kptr_xchg` inline asm wrapper correctly emits `call 194`
//    (BPF helper bpf_kptr_xchg) with the right register assignments.
//
// 3. The `rcu_read_lock` / `rcu_read_unlock` kfunc wrappers compile
//    correctly as kfunc calls (using `sym` references to extern fns).
//
// 4. The `bpf_cpumask_create` / `bpf_cpumask_release` kfuncs from
//    the cpumask module integrate cleanly with the kptr pattern.
//
// 5. The overall code structure matches the C pattern exactly:
//    create -> kptr_xchg -> release old -> rcu_read_lock -> access ->
//    rcu_read_unlock.
//
// ## What does NOT work (the BTF gap)
//
// The BPF verifier requires `BTF_KIND_TYPE_TAG` with value `"kptr"`
// in the BTF type chain for kptr globals. Specifically, for a variable
// like `primary_cpumask`, the BTF must contain:
//
//   VAR "PRIMARY_CPUMASK" -> PTR -> TYPE_TAG "kptr" -> STRUCT "bpf_cpumask"
//
// The Rust BPF compiler emits:
//
//   VAR "PRIMARY_CPUMASK" -> STRUCT "Kptr<bpf_cpumask>" -> PTR -> STRUCT "bpf_cpumask"
//
// Missing: the TYPE_TAG "kptr" between PTR and STRUCT.
//
// Without this tag, the verifier will reject bpf_kptr_xchg() with one
// of these errors:
//   - "arg#0 expected pointer to map value"
//   - "R1 doesn't point to kptr"
//
// ## Recommended fix: aya-core-postprocessor BTF patching
//
// The aya-core-postprocessor (which already patches BTF for CO-RE
// relocations) should be extended to:
//
// 1. Detect `Kptr<T>` types in DATASEC BTF entries by looking for
//    structs named "Kptr" with a single pointer field.
//
// 2. Inject a `BTF_KIND_TYPE_TAG` type with string "kptr".
//
// 3. Rewire the pointer's target: instead of PTR -> STRUCT T, make
//    it PTR -> TYPE_TAG "kptr" -> STRUCT T.
//
// 4. Optionally, collapse the Kptr wrapper struct so the DATASEC
//    entry becomes VAR -> PTR -> TYPE_TAG -> STRUCT (matching clang).
//
// This approach is clean because:
// - It reuses existing post-processor infrastructure
// - TYPE_TAG is a simple BTF type (kind + string, no complex data)
// - The Kptr<T> struct is a well-defined marker that won't collide
// - It can be driven by a sidecar annotation file or auto-detected
//
// ## Alternative: raw BTF injection via inline asm
//
// It is theoretically possible to emit raw BTF bytes into the `.BTF`
// section using `core::arch::global_asm!(".pushsection .BTF ...")`.
// However, this is extremely fragile because:
// - The injected bytes must mesh with compiler-generated BTF
// - BTF type IDs are assigned sequentially; inserting a type shifts
//   all subsequent IDs
// - The BTF header checksums and offsets must be updated
// - Any change to the program can break the hardcoded offsets
//
// This approach is not recommended for production use.
//
// ## Alternative: map-based storage instead of global kptr
//
// Instead of a global `static mut Kptr<T>`, store the cpumask pointer
// in a BPF array map value struct. This is how some C schedulers handle
// it (e.g., per-CPU context with kptr fields).
//
// However, this has the SAME fundamental BTF problem: the map value
// type's BTF must also contain TYPE_TAG "kptr" for the pointer field.
// The Rust compiler won't emit it for map value structs either.
//
// The map approach does work differently in one way: the verifier
// checks the map's BTF at map creation time, so the loader would
// need to patch the map value BTF before creating the map. This is
// actually the same loader-side patching approach, just applied to
// a map definition instead of a DATASEC entry.
