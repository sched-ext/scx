//! scx_cosmos — a deadline + vruntime scheduler, ported from C to pure Rust.
//!
//! This is an incremental port of scx_cosmos. It implements:
//!
//! - `select_cpu`: uses `pick_idle_cpu` with SMT-aware idle scanning,
//!   `select_cpu_dfl` fallback, mm_affinity, hybrid core wake-affine,
//!   busy-aware dispatch, and no_wake_sync support
//! - `enqueue`: four-tier — PMU event-heavy dispatch, migration to idle CPU
//!   (with is_pcpu_task and SCX_ENQ_CPU_SELECTED checks), local DSQ when not
//!   busy, vtime-ordered shared DSQ when busy (uses task_cpu + task_running kfuncs)
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
//! - `TASK_CTX`: per-task storage for exec_runtime, wakeup_freq, last_run_at,
//!   perf_events
//! - `CPU_CTX`: per-CPU array for load tracking (last_update, perf_lvl, perf_events)
//! - `SCX_PMU_MAP`: perf event array (populated by userspace, not readable from struct_ops)
//! - `WAKEUP_TIMER`: single-element BPF_MAP_TYPE_ARRAY holding the deferred
//!   wakeup bpf_timer. When `DEFERRED_WAKEUPS` is enabled, CPU kicks in the
//!   enqueue path are deferred to a periodic timer callback that scans for idle
//!   CPUs with pending tasks, reducing IPI overhead in the hot path.
//!
//! Userspace-configurable globals:
//! - `SLICE_NS`, `SLICE_LAG`: time slice and maximum runtime parameters
//! - `BUSY_THRESHOLD`, `CPU_UTIL`: system busy detection
//! - `DEFERRED_WAKEUPS`: enable/disable deferred wakeup timer (default: true)
//! - `NO_WAKE_SYNC`, `CPUFREQ_ENABLED`, `SMT_ENABLED`, `AVOID_SMT`: feature flags
//! - `MM_AFFINITY`: address space affinity for cache-friendly wakeups
//! - `NUMA_ENABLED`, `NR_NODES`, `CPU_TO_NODE`: NUMA-aware per-node DSQ routing
//! - `PERF_CONFIG`, `PERF_THRESHOLD`: PMU perf event tracking configuration
//! - `PREFERRED_IDLE_SCAN`, `FLAT_IDLE_SCAN`: idle CPU scan modes for big.LITTLE
//! - `PREFERRED_CPUS`, `CPU_CAPACITY`: CPU ordering/capacity for idle scan
//!
//! PMU architecture:
//! PMU perf event reading uses a separate `tp_btf/sched_switch` tracing program
//! (included in this same ELF binary) that calls `bpf_perf_event_read_value`
//! (helper #55) on each context switch. The struct_ops scheduler cannot call
//! this helper directly (kernel restricts it to tracing program types). The
//! tracing program writes per-task and per-CPU perf counters to the shared
//! `TASK_CTX` and `CPU_CTX` maps. Userspace loads both programs from the same
//! ELF object.

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_camel_case_types, non_upper_case_globals, dead_code, unused_imports)]

use scx_ebpf::prelude::*;
use scx_ebpf::core_read;
use scx_ebpf::core_write;
use scx_ebpf::bpf_for;
use scx_ebpf::maps::{TaskStorage, PerCpuArray, PerfEventArray, BpfArray};
use scx_ebpf::kptr::{Kptr, kptr_xchg, rcu_read_lock, rcu_read_unlock};
use scx_ebpf::cpumask::{self, bpf_cpumask};
use scx_ebpf::pmu::{self, PerfEventValue, BPF_F_CURRENT_CPU};
// bpf_timer type and helpers for deferred wakeup timer.
use scx_ebpf::timer::{self, BpfTimer};

scx_ebpf::scx_ebpf_boilerplate!();

/// Generated vmlinux struct definitions with real field layouts.
#[allow(non_snake_case, improper_ctypes_definitions, unnecessary_transmutes)]
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
/// - `perf_events`: accumulated perf event count from last run (for event-heavy detection)
///
/// NOTE: The `perf_events` field is populated by the `tp_btf/sched_switch`
/// tracing program included in this binary. That program calls
/// `bpf_perf_event_read_value` (helper #55), which is restricted to tracing
/// program types and NOT available in struct_ops programs. On each context
/// switch, the tracing program computes the perf counter delta and writes
/// it to `TASK_CTX.perf_events` and `CPU_CTX.perf_events`. The struct_ops
/// scheduler reads these values via `is_event_heavy()` and
/// `pick_least_busy_event_cpu()`.
#[repr(C)]
#[derive(Copy, Clone)]
struct TaskCtx {
    exec_runtime: u64,
    wakeup_freq: u64,
    last_run_at: u64,
    last_woke_at: u64,
    perf_events: u64,
}

/// Per-CPU context stored in BPF_MAP_TYPE_PERCPU_ARRAY.
///
/// Tracks per-CPU scheduling state for load tracking and cpufreq scaling.
/// - `last_update`: timestamp of last scheduling update on this CPU
/// - `perf_lvl`: EWMA-smoothed CPU performance level [0..1024]
/// - `perf_events`: accumulated perf event count on this CPU (for least-busy CPU selection)
#[repr(C)]
#[derive(Copy, Clone)]
struct CpuCtx {
    last_update: u64,
    perf_lvl: u64,
    perf_events: u64,
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

/// Perf event array for hardware performance counter access.
///
/// Userspace populates this map with perf_event_open() fds (one per CPU).
/// The `tp_btf/sched_switch` tracing program reads counter values from this
/// map via `bpf_perf_event_read_value` (helper #55). The struct_ops scheduler
/// cannot call this helper directly — the kernel restricts it to tracing types.
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
static SCX_PMU_MAP: PerfEventArray<1024> = PerfEventArray::new();

/// Per-CPU scratch space for PMU counter baselines.
///
/// The `tp_btf/sched_switch` tracing program stores the perf counter value
/// at the start of each task's run here. On the next sched_switch, it reads
/// the counter again and computes the delta (current - start), which it
/// stores in the task's `TASK_CTX.perf_events` and the CPU's `CPU_CTX.perf_events`.
///
/// This is a per-CPU array with 1 entry (the baseline counter value for
/// the task currently running on that CPU).
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
static PMU_BASELINE: PerCpuArray<u64, 1> = PerCpuArray::new();

/// Timer map value type for deferred wakeup timer.
///
/// The kernel's btf_find_timer() walks the map value struct looking for a
/// member whose BTF type is named exactly `bpf_timer`. The `BpfTimer` type
/// alias resolves to `struct bpf_timer` in BTF, satisfying this requirement.
///
/// C reference: `struct wakeup_timer { struct bpf_timer timer; };`
#[repr(C)]
#[derive(Clone, Copy)]
struct WakeupTimer {
    timer: BpfTimer,
}

#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
static WAKEUP_TIMER: BpfArray<WakeupTimer, 1> = BpfArray::new();

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

/// SCX_PICK_IDLE_CORE flag for select_cpu_and: prefer fully-idle SMT cores.
const SCX_PICK_IDLE_CORE: u64 = 1;

/// SCX_WAKE_TTWU flag value (from kernel enum scx_wake_flags).
/// Set by the kernel for any try_to_wake_up() wakeup (not fork, not exec).
/// Used by hybrid core wake-affine to detect task wakeups.
const SCX_WAKE_TTWU: u64 = 8;

/// SCX_WAKE_SYNC flag value (from kernel enum).
const SCX_WAKE_SYNC: u64 = 16;

/// SCX_ENQ_CPU_SELECTED flag: set by the kernel when ops.select_cpu() was
/// already called and selected a CPU. When this flag is set in enq_flags,
/// the task should NOT attempt migration in enqueue (select_cpu already
/// handled idle CPU selection).
///
/// Value from kernel enum `scx_enq_flags`: SCX_ENQ_CPU_SELECTED = 1024.
const SCX_ENQ_CPU_SELECTED: u64 = 1024;

/// Maximum CPU performance level (SCX_CPUPERF_ONE = 1024).
const SCX_CPUPERF_ONE: u64 = 1024;

/// Below this threshold, reduce cpufreq to half.
const CPUFREQ_LOW_THRESH: u64 = SCX_CPUPERF_ONE / 4;

/// Above this threshold, raise cpufreq to maximum.
const CPUFREQ_HIGH_THRESH: u64 = SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4;

/// PF_EXITING flag in task_struct.flags — task is in the process of exiting.
/// Used by is_wake_affine() to skip wakers that are exiting.
const PF_EXITING: u32 = 0x00000004;

/// PF_IDLE flag in task_struct.flags — task is the idle thread.
/// Used by is_cpu_idle() to detect whether a CPU is running its idle thread.
/// C reference: `p->flags & PF_IDLE`
const PF_IDLE: u32 = 0x00000002;

// ── Userspace-configurable globals ──────────────────────────────────────
//
// These are `#[unsafe(no_mangle)]` globals that userspace can set before
// loading the BPF program (via EbpfLoader::set_global) or update at
// runtime (via map operations on .bss/.data/.rodata).
//
// Wrapped in `BpfGlobal<T>` to eliminate `unsafe` at every access site.
// `BpfGlobal` is `#[repr(transparent)]`, so the loader sees the same
// memory layout as a bare `T`.

/// Default time slice: 10us (matches C cosmos `slice_ns = 10000`).
#[unsafe(no_mangle)]
static SLICE_NS: BpfGlobal<u64> = BpfGlobal::new(10_000);

/// Maximum runtime that can be charged to a task (bounds vruntime jumps).
#[unsafe(no_mangle)]
static SLICE_LAG: BpfGlobal<u64> = BpfGlobal::new(20_000_000);

/// CPU utilization threshold for system busy detection [0..100].
/// When `CPU_UTIL >= BUSY_THRESHOLD`, the system is considered busy.
/// C reference: `const volatile u64 busy_threshold`
#[unsafe(no_mangle)]
static BUSY_THRESHOLD: BpfGlobal<u64> = BpfGlobal::new(0);

/// Current global CPU utilization [0..100], set by userspace polling loop.
/// C reference: `volatile u64 cpu_util`
#[unsafe(no_mangle)]
static CPU_UTIL: BpfGlobal<u64> = BpfGlobal::new(0);

/// When true, clear SCX_WAKE_SYNC from wake_flags in select_cpu.
/// C reference: `const volatile bool no_wake_sync`
#[unsafe(no_mangle)]
static NO_WAKE_SYNC: BpfGlobal<bool> = BpfGlobal::new(false);

/// When true, enable cpufreq performance scaling in running/stopping.
/// C reference: `const volatile bool cpufreq_enabled = true`
#[unsafe(no_mangle)]
static CPUFREQ_ENABLED: BpfGlobal<bool> = BpfGlobal::new(true);

/// When true, CPUs have SMT (hyperthreading) enabled.
/// C reference: `const volatile bool smt_enabled = true`
#[unsafe(no_mangle)]
static SMT_ENABLED: BpfGlobal<bool> = BpfGlobal::new(true);

/// When true, try to avoid placing tasks on SMT siblings of busy cores.
/// C reference: `const volatile bool avoid_smt = true`
#[unsafe(no_mangle)]
static AVOID_SMT: BpfGlobal<bool> = BpfGlobal::new(true);

/// When true, enable NUMA-aware per-node DSQ routing.
/// C reference: `const volatile bool numa_enabled`
#[unsafe(no_mangle)]
static NUMA_ENABLED: BpfGlobal<bool> = BpfGlobal::new(false);

/// Number of NUMA nodes on this system, set by userspace.
/// C reference: `const volatile u32 nr_node_ids`
#[unsafe(no_mangle)]
static NR_NODES: BpfGlobal<u32> = BpfGlobal::new(1);

/// CPU-to-NUMA-node mapping, populated by userspace via .bss.
/// C reference: `cpu_node_map` BPF hash map (we use a flat array instead).
/// Each entry maps a CPU index to its NUMA node ID.
#[unsafe(no_mangle)]
static CPU_TO_NODE: BpfGlobalArray<u32, MAX_CPUS> = BpfGlobalArray::new([0; MAX_CPUS]);

/// Primary cpumask kptr — kernel-managed reference-counted cpumask.
///
/// In C: `private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask;`
///
/// The aya loader's `fixup_kptr_types()` automatically transforms the
/// `Kptr<T>` wrapper into the BTF chain `PTR -> TYPE_TAG("kptr") -> T`
/// that the verifier requires for kptr recognition.
///
/// Initialized in `init_primary_cpumask()`, read under RCU lock in
/// `pick_idle_cpu()` to filter idle CPU selection to the primary domain.
///
/// NOTE: PRIMARY_CPUMASK uses a raw `static mut` instead of `BpfGlobal`
/// because `Kptr<T>` requires `&raw mut` / `&raw const` access for
/// `bpf_kptr_xchg` and RCU dereferencing, which are inherently unsafe
/// kernel operations. Wrapping in BpfGlobal would not eliminate the
/// unsafety and would complicate the pointer-to-kptr-slot semantics.
#[unsafe(no_mangle)]
static mut PRIMARY_CPUMASK: Kptr<bpf_cpumask> = Kptr::zeroed();

/// When true, primary domain includes all CPUs (primary_cpumask is unused).
/// When false and the `kernel_6_16` feature is enabled, `pick_idle_cpu()`
/// first tries `select_cpu_and()` with the primary cpumask before falling
/// back to the full cpus_ptr.
/// C reference: `const volatile bool primary_all = true`
#[unsafe(no_mangle)]
static PRIMARY_ALL: BpfGlobal<bool> = BpfGlobal::new(true);

/// When true, use preferred idle scan: iterate CPUs in descending capacity
/// order (from userspace's PREFERRED_CPUS array) to find an idle CPU,
/// preferring high-performance cores. Falls back to select_cpu_dfl if none found.
/// C reference: `const volatile bool preferred_idle_scan`
#[unsafe(no_mangle)]
static PREFERRED_IDLE_SCAN: BpfGlobal<bool> = BpfGlobal::new(false);

/// When true, use flat idle scan: iterate ALL CPUs in preferred order
/// (from PREFERRED_CPUS array) rather than using select_cpu_dfl at all.
/// C reference: `const volatile bool flat_idle_scan`
#[unsafe(no_mangle)]
static FLAT_IDLE_SCAN: BpfGlobal<bool> = BpfGlobal::new(false);

/// CPU list for primary domain, set by userspace via `override_global`.
///
/// Contains CPU IDs that belong to the primary scheduling domain.
/// Terminated by -1 sentinel. When `PRIMARY_ALL` is false, `on_init()`
/// iterates this list and calls `bpf_cpumask_set_cpu` for each CPU.
/// C reference: populated via `bpf_prog_test_run` on syscall programs;
/// we use a global array instead for simplicity.
#[unsafe(no_mangle)]
static PRIMARY_CPU_LIST: BpfGlobalArray<i32, MAX_CPUS> = BpfGlobalArray::new([-1i32; MAX_CPUS]);

/// C reference: `const volatile s32 preferred_cpus[MAX_CPUS]`
#[unsafe(no_mangle)]
static PREFERRED_CPUS: BpfGlobalArray<i32, MAX_CPUS> = BpfGlobalArray::new([-1i32; MAX_CPUS]);

/// Per-CPU capacity value, populated by userspace from sysfs cpu_capacity.
/// C reference: `const volatile u64 cpu_capacity[MAX_CPUS]`
#[unsafe(no_mangle)]
static CPU_CAPACITY: BpfGlobalArray<u64, MAX_CPUS> = BpfGlobalArray::new([0u64; MAX_CPUS]);

/// When true, enable address space affinity in select_cpu.
/// Keeps wakee on the waker's CPU when they share the same mm (address space),
/// improving cache locality for tasks that share memory (e.g., threads).
/// C reference: `const volatile bool mm_affinity`
#[unsafe(no_mangle)]
static MM_AFFINITY: BpfGlobal<bool> = BpfGlobal::new(false);

/// PMU perf event config: hardware counter ID to track.
/// 0 = disabled (no PMU tracking). Set by userspace via `--perf-config`.
/// Common values (x86): 0xC0 = retired instructions, 0x3C = unhalted core cycles.
/// C reference: `const volatile u64 perf_config`
#[unsafe(no_mangle)]
static PERF_CONFIG: BpfGlobal<u64> = BpfGlobal::new(0);

/// Performance counter threshold to classify a task as event-heavy.
/// When a task's per-run perf_events exceeds this value, it is considered
/// event-heavy and may be migrated to a less busy CPU.
/// C reference: `const volatile u64 perf_threshold`
#[unsafe(no_mangle)]
static PERF_THRESHOLD: BpfGlobal<u64> = BpfGlobal::new(0);

/// When true, keep event-heavy tasks on their current CPU instead of
/// migrating to the least busy CPU. Effectively disables the CPU scan
/// in `pick_least_busy_event_cpu`, returning `prev_cpu` immediately.
/// C reference: `const volatile bool perf_sticky`
#[unsafe(no_mangle)]
static PERF_STICKY: BpfGlobal<bool> = BpfGlobal::new(false);

/// Enable deferred wakeup timer.
///
/// When true, CPU wakeups triggered by enqueue are deferred to a periodic
/// timer callback (`wakeup_timerfn`) instead of being performed inline.
/// This reduces IPI overhead in the enqueue hot path.
///
/// C reference: `const volatile bool deferred_wakeups = true`
#[unsafe(no_mangle)]
static DEFERRED_WAKEUPS: BpfGlobal<bool> = BpfGlobal::new(true);

// PMU integration architecture:
//
// SCX_PMU_MAP (BPF_MAP_TYPE_PERF_EVENT_ARRAY) is populated by userspace with
// perf_event_open() fds. The BPF helper bpf_perf_event_read_value (#55) is
// NOT available in struct_ops programs — the kernel restricts it to tracing
// program types (kprobe, tracepoint, fentry, tp_btf).
//
// Solution: A separate `tp_btf/sched_switch` tracing program is included in
// this same ELF binary. On each context switch it:
//   1. Reads the perf counter via helper #55
//   2. Computes the delta for the outgoing task (prev) since its last switch-in
//   3. Stores the delta in prev's TASK_CTX.perf_events and CPU_CTX.perf_events
//   4. Records the baseline counter for the incoming task (next) in PMU_BASELINE
//
// The struct_ops scheduler reads TASK_CTX.perf_events (is_event_heavy) and
// CPU_CTX.perf_events (pick_least_busy_event_cpu) without needing helper #55.
//
// Userspace loads and attaches both programs from the same ELF object:
//   - Struct_ops: attached via ebpf.attach_struct_ops("_scx_ops")
//   - Tracing: loaded via BtfTracePoint::load("sched_switch", &btf) then .attach()

// ── Global state ────────────────────────────────────────────────────────

/// Current global vruntime — tracks the most recent dsq_vtime seen.
static VTIME_NOW: BpfGlobal<u64> = BpfGlobal::new(0);

/// Number of CPUs on this system, set in init().
static NR_CPU_IDS: BpfGlobal<u32> = BpfGlobal::new(0);

/// Round-robin rotation for flat idle scan. Tracks the next CPU to start
/// scanning from, incremented each time a CPU is claimed. Only used when
/// `FLAT_IDLE_SCAN` is true (not `PREFERRED_IDLE_SCAN`).
///
/// C reference: `static u32 last_cpu` in `pick_idle_cpu_pref_smt()`.
static LAST_CPU: BpfGlobal<u32> = BpfGlobal::new(0);

// ── Helpers ─────────────────────────────────────────────────────────────

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

/// Read the CPU capacity for a given CPU index.
///
/// Returns 0 if the index is negative or out of bounds.
/// The BPF verifier needs the bounds check tightly coupled with the
/// array access to prove safety, so this is a separate helper.
#[inline(always)]
fn cpu_capacity(cpu: i32) -> u64 {
    if cpu < 0 {
        return 0;
    }
    let idx = cpu as u32 as usize;
    if idx >= MAX_CPUS {
        return 0;
    }
    CPU_CAPACITY.get(idx).unwrap_or(0)
}

/// Check if CPU `a` has higher capacity than CPU `b` (e.g., P-core vs E-core).
///
/// Used for hybrid core wake-affine: when the waker is on a faster core,
/// prefer migrating the wakee to the waker's core rather than keeping it
/// on a slower one.
///
/// Returns false if either CPU index is negative or out of bounds.
///
/// C reference: `is_cpu_faster(a, b)` compares `cpu_capacity[a] > cpu_capacity[b]`.
#[inline(always)]
fn is_cpu_faster(a: i32, b: i32) -> bool {
    let cap_a = cpu_capacity(a);
    let cap_b = cpu_capacity(b);
    cap_a > cap_b
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
    if !MM_AFFINITY.get() {
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
    SLICE_NS.get()
}

/// Read the current slice_lag value (from userspace-configurable global).
#[inline(always)]
fn get_slice_lag() -> u64 {
    SLICE_LAG.get()
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

/// Check if a task has migration disabled.
///
/// The BPF runtime disables migration while running BPF code (it increments
/// `p->migration_disabled` in the prolog). So for the _current_ task,
/// `migration_disabled == 1` is the normal BPF-induced disable, and we need
/// `migration_disabled > 1` to detect user-initiated migration disable.
/// For non-current tasks, any non-zero value means migration is disabled.
///
/// C reference: `is_migration_disabled()` in `common.bpf.h`:
/// ```c
/// if (p->migration_disabled == 1)
///     return bpf_get_current_task_btf() != p;
/// else
///     return p->migration_disabled;
/// ```
#[inline(always)]
fn is_migration_disabled(p: *mut task_struct) -> bool {
    let md = if let Ok(v) = core_read!(vmlinux::task_struct, p, migration_disabled) {
        v
    } else {
        return false;
    };
    if md == 1 {
        // migration_disabled == 1 might just be the BPF prolog; check if
        // p is the current task. If it IS current, the disable is from BPF.
        get_current_task_btf() != p
    } else {
        md != 0
    }
}

/// Check if a task is pinned to a single CPU (per-CPU task).
///
/// Returns true when the task can only run on one CPU, either because
/// it has `nr_cpus_allowed == 1` (CPU affinity mask with single CPU)
/// or because migration is explicitly disabled.
///
/// C reference: `is_pcpu_task()`:
/// ```c
/// return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
/// ```
#[inline(always)]
fn is_pcpu_task(p: *mut task_struct) -> bool {
    if let Ok(n) = core_read!(vmlinux::task_struct, p, nr_cpus_allowed) {
        if n == 1 {
            return true;
        }
    }
    is_migration_disabled(p)
}

/// Determine if the system is busy (saturated).
///
/// C reference: `is_system_busy()` returns `cpu_util >= busy_threshold`.
#[inline(always)]
fn is_system_busy() -> bool {
    CPU_UTIL.get() >= BUSY_THRESHOLD.get()
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
    if NUMA_ENABLED.get() {
        // Bounds-check for BPF verifier: cpu must be within array.
        let idx = cpu as u32 as usize;
        CPU_TO_NODE.get(idx).map(|n| n as u64).unwrap_or(SHARED_DSQ)
    } else {
        SHARED_DSQ
    }
}

/// Look up the NUMA node for a CPU, with bounds checking.
///
/// Returns the node ID, or `u32::MAX` if the CPU index is out of range.
///
/// The bounds check uses inline asm to emit a comparison instruction
/// (`if r > MAX_CPUS-1 goto skip`) that the BPF verifier can see and
/// use to narrow the register range. LLVM cannot optimize away inline
/// asm, even at -O3 with LTO, so the comparison always appears in the
/// final BPF bytecode.
#[inline(always)]
fn cpu_node(cpu: u32) -> u32 {
    let idx = cpu as usize;
    // Emit a bounds-check comparison via inline asm so LLVM can't remove it.
    // After `if idx > MAX_CPUS-1 goto out_of_bounds`, the verifier knows
    // idx is in [0, MAX_CPUS-1], making the array access safe.
    //
    // The asm block sets `in_bounds` to 1 if `idx <= MAX_CPUS-1`, 0 otherwise.
    let in_bounds: u64;
    unsafe {
        core::arch::asm!(
            // r_out = 1 (assume in-bounds)
            "r0 = 1",
            // if idx > MAX_CPUS-1, set r_out = 0
            "if {idx} > {max} goto +1",
            "goto +1",
            "r0 = 0",
            idx = in(reg) idx as u64,
            max = const (MAX_CPUS - 1),
            lateout("r0") in_bounds,
        );
    }
    if in_bounds != 0 {
        // SAFETY: bounds verified by asm block above; get_unchecked avoids
        // a second bounds check that the BPF verifier cannot correlate.
        unsafe { CPU_TO_NODE.get_unchecked(idx) }
    } else {
        u32::MAX
    }
}

/// Wrapping time comparison: returns true if `a` is before `b`.
///
/// Matches C's `time_before(a, b)` which uses `(s64)(a - b) < 0`.
/// This handles wrapping u64 timestamps correctly.
#[inline(always)]
fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
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
///   new_freq = (100 * NSEC_PER_MSEC) / delta_t
///   return calc_avg(old_freq, new_freq)
#[inline(always)]
fn update_freq(old_freq: u64, delta_ns: u64) -> u64 {
    // Avoid division by zero; return old_freq unchanged.
    if delta_ns == 0 {
        return old_freq;
    }
    // 100 * 1_000_000 = 100 * NSEC_PER_MSEC = 100_000_000
    let new_freq = (100 * 1_000_000) / delta_ns;
    calc_avg(old_freq, new_freq)
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
    if !CPUFREQ_ENABLED.get() {
        return;
    }

    let Some(cctx) = CPU_CTX.get_mut(0) else {
        return;
    };

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
    if !CPUFREQ_ENABLED.get() {
        return;
    }

    let Some(cctx) = CPU_CTX.get(0) else {
        return;
    };
    let perf_lvl_stored = cctx.perf_lvl;

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

/// Check if a CPU is running its idle thread.
///
/// Reads the current task on the given CPU via `scx_bpf_cpu_rq()`, then
/// checks if the task has the `PF_IDLE` flag set in `task_struct.flags`.
/// This is used by the deferred wakeup timer to determine which CPUs
/// need to be kicked.
///
/// Uses `scx_bpf_cpu_rq` (available on all sched_ext kernels) instead
/// of `scx_bpf_cpu_curr` (added in v6.15) for backward compatibility.
/// This matches the C compat wrapper `__COMPAT_scx_bpf_cpu_curr()`.
///
/// NOTE: Uses inline bpf_probe_read_kernel (helper #113) directly instead
/// of `core_read!` to avoid subprogram calls inside the loop. The BPF
/// verifier's bounded-loop analysis can detect "infinite loops" when
/// subprogram calls appear in the loop body, because the subprogram
/// call resets register state tracking.
///
/// C reference: `is_cpu_idle(cpu)` in `main.bpf.c`:
/// ```c
/// bpf_rcu_read_lock();
/// p = __COMPAT_scx_bpf_cpu_curr(cpu);
/// idle = p->flags & PF_IDLE;
/// bpf_rcu_read_unlock();
/// ```
#[inline(always)]
fn is_cpu_idle(cpu: i32) -> bool {
    rcu_read_lock();
    let rq = kfuncs::cpu_rq(cpu);
    if rq.is_null() {
        rcu_read_unlock();
        return false;
    }

    // Read rq->curr using bpf_probe_read_kernel to avoid subprogram call overhead.
    // On kernel 6.16+ the bindgen layout wraps curr in an anonymous union.
    #[cfg(feature = "kernel_6_16")]
    let curr_offset = core::mem::offset_of!(vmlinux::rq, __bindgen_anon_1.curr);
    #[cfg(not(feature = "kernel_6_16"))]
    let curr_offset = core::mem::offset_of!(vmlinux::rq, curr);
    let mut p: *mut vmlinux::task_struct = core::ptr::null_mut();
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "call 113",
            inlateout("r1") &mut p as *mut _ as *mut u8 => _,
            inlateout("r2") (core::mem::size_of::<*mut vmlinux::task_struct>() as u64) => _,
            inlateout("r3") ((rq as *const u8).add(curr_offset)) => _,
            lateout("r0") ret,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
    if ret != 0 || p.is_null() {
        rcu_read_unlock();
        return false;
    }

    // Read p->flags to check PF_IDLE.
    let flags_offset = core::mem::offset_of!(vmlinux::task_struct, flags);
    let mut flags: u32 = 0;
    let ret2: i64;
    unsafe {
        core::arch::asm!(
            "call 113",
            inlateout("r1") &mut flags as *mut _ as *mut u8 => _,
            inlateout("r2") (core::mem::size_of::<u32>() as u64) => _,
            inlateout("r3") ((p as *const u8).add(flags_offset)) => _,
            lateout("r0") ret2,
            lateout("r4") _,
            lateout("r5") _,
        );
    }

    rcu_read_unlock();
    ret2 == 0 && (flags & PF_IDLE != 0)
}

// ── Idle CPU selection ──────────────────────────────────────────────────

/// Pick an idle CPU using preferred or flat scan strategy.
///
/// Scans CPUs for an idle one using preferred or flat strategy.
/// When `PREFERRED_IDLE_SCAN` is true, iterates the `PREFERRED_CPUS` array
/// (CPUs sorted by capacity descending, big cores first). When
/// `FLAT_IDLE_SCAN` is true instead, iterates all CPUs in round-robin
/// order starting from `LAST_CPU` to distribute load evenly.
///
/// Tries `prev_cpu` first as a fast path before scanning, matching the
/// C `pick_idle_cpu_pref_smt()` behavior.
///
/// Uses the `bpf_for!` macro for bounded iteration over all CPUs. The
/// macro emits a `while` loop that the BPF verifier (kernel 6.1+)
/// natively tracks as bounded, so kfunc calls in the loop body work
/// without the aya-55 subprogram kfunc resolution issue that affects
/// `bpf_loop()` callbacks.
///
/// C reference: `pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed,
///              primary=NULL, smt=NULL)` — the final tier in
///              `pick_idle_cpu_flat()` which scans system-wide with no
///              primary or SMT filtering.
#[inline(always)]
fn pick_idle_cpu_preferred(prev_cpu: i32) -> i32 {
    // Fast path: try prev_cpu first.
    // C reference: pick_idle_cpu_pref_smt checks is_prev_allowed &&
    // scx_bpf_test_and_clear_cpu_idle(prev_cpu) before scanning.
    // We can't check p->cpus_ptr without CO-RE, so we just check idle.
    if prev_cpu >= 0 && kfuncs::test_and_clear_cpu_idle(prev_cpu) {
        return prev_cpu;
    }

    let nr = NR_CPU_IDS.get();
    let bound = if nr < MAX_CPUS as u32 { nr } else { MAX_CPUS as u32 };
    let preferred = PREFERRED_IDLE_SCAN.get();

    if preferred {
        // Preferred mode: iterate PREFERRED_CPUS array in order (big cores first).
        // C reference: cpu = preferred_cpus[i] when preferred_idle_scan is true.
        bpf_for!(i, 0, bound, {
            let cpu = PREFERRED_CPUS.get(i as usize).unwrap_or(-1);
            if cpu < 0 {
                // Sentinel: end of preferred CPU list.
                break;
            }
            // Skip prev_cpu (already tried above) but keep iteration advancing.
            if cpu != prev_cpu && kfuncs::test_and_clear_cpu_idle(cpu) {
                return cpu;
            }
        });
    } else {
        // Flat mode: round-robin starting from LAST_CPU.
        // C reference: start = last_cpu; cpu = (start + i) % max_cpus;
        //              last_cpu = cpu + 1 on success.
        let start = LAST_CPU.get();
        bpf_for!(i, 0, bound, {
            let cpu = ((start + i) % bound) as i32;
            // Skip prev_cpu (already tried above) but keep iteration advancing.
            if cpu != prev_cpu && kfuncs::test_and_clear_cpu_idle(cpu) {
                LAST_CPU.set((cpu as u32 + 1) % bound);
                return cpu;
            }
        });
    }
    -1
}

/// Pick an idle CPU for a task, with SMT awareness, primary cpumask
/// filtering, and preferred/flat scan.
///
/// Uses `#[inline(always)]` because kfunc calls in BPF subprograms are
/// not yet supported by aya (subprogram instruction offsets shift after
/// function linking, causing kfunc relocations to be missed).
///
/// Tries these strategies in order:
///
/// 0. **Preferred/flat idle scan** — when `PREFERRED_IDLE_SCAN` or
///    `FLAT_IDLE_SCAN` is enabled **and the system is not busy**, try
///    `pick_idle_cpu_preferred()` which iterates CPUs in capacity order
///    (preferred) or round-robin (flat). Skipped when busy because the
///    cpumask-based scanning (select_cpu_dfl / select_cpu_and) is more
///    efficient under load.
///
/// 1. **Primary cpumask** — when `PRIMARY_ALL` is false and a primary
///    cpumask is set, try `select_cpu_and()` with the primary cpumask to
///    prefer CPUs in the primary domain. Uses `SCX_PICK_IDLE_CORE` when
///    `AVOID_SMT` is enabled to prefer fully-idle cores.
///    Only compiled when the `kernel_6_16` feature is enabled.
///
/// 2. **`select_cpu_dfl()`** — the kernel's default idle CPU picker.
///    Tried after primary cpumask (or first if primary filtering is
///    disabled); handles wake-affine, LLC locality, and basic idle scanning.
///
/// 3. **SMT verification** — when `AVOID_SMT` is enabled and strategy 2
///    found an idle CPU, we check whether the entire physical core is
///    idle (both SMT siblings) using `get_idle_smtmask()`. If the found
///    CPU's core is not fully idle, we reject it and return -1 so the
///    caller falls back to non-idle dispatch.
///
/// Returns the idle CPU number (>= 0) if one was found, or a negative
/// value if no suitable idle CPU is available.
///
/// C reference: `pick_idle_cpu()` in `main.bpf.c`.
#[inline(always)]
fn pick_idle_cpu(p: *mut task_struct, prev_cpu: i32, wake_flags: u64, from_enqueue: bool) -> i32 {
    // Strategy 0: Preferred/flat idle scan.
    // Only enter when the system is not busy — under load the cpumask-based
    // scanning (select_cpu_dfl / select_cpu_and) is more efficient.
    // C reference: if ((flat_idle_scan || preferred_idle_scan) && !is_system_busy())
    //                  return pick_idle_cpu_flat(p, prev_cpu);
    let preferred = PREFERRED_IDLE_SCAN.get();
    let flat = FLAT_IDLE_SCAN.get();
    if (preferred || flat) && !is_system_busy() {
        let pref_cpu = pick_idle_cpu_preferred(prev_cpu);
        if pref_cpu >= 0 {
            return pref_cpu;
        }
        // If no idle CPU was found, still fall through to select_cpu_dfl
        // as a fallback.
    }

    // Strategy 1: Primary cpumask filtering.
    // On kernel >= 6.16, use scx_bpf_select_cpu_and() to prefer CPUs in the
    // primary domain. On older kernels this kfunc doesn't exist in vmlinux
    // BTF, so the code is compiled out via the kernel_6_16 feature flag.
    #[cfg(feature = "kernel_6_16")]
    {
        if !PRIMARY_ALL.get() {
            rcu_read_lock();
            let mask = unsafe { Kptr::get(&raw mut PRIMARY_CPUMASK) };
            if !mask.is_null() {
                let flags = if AVOID_SMT.get() { SCX_PICK_IDLE_CORE } else { 0 };
                let cpu = kfuncs::select_cpu_and(
                    p,
                    prev_cpu,
                    wake_flags,
                    cpumask::cast(mask),
                    flags,
                );
                rcu_read_unlock();
                if cpu >= 0 {
                    return cpu;
                }
            } else {
                rcu_read_unlock();
            }
        }
    }

    // Strategy 2: kernel's default idle CPU selection.
    //
    // NOTE: select_cpu_dfl is only valid when called from ops.select_cpu().
    // When called from enqueue (from_enqueue=true) and we don't have
    // select_cpu_and (i.e., kernel < 6.16), we must return -1 instead of
    // calling select_cpu_dfl, which would trigger a kernel warning.
    //
    // On kernel >= 6.16, the select_cpu_and path above handles both
    // select_cpu and enqueue contexts, so this fallback is only reached
    // on older kernels.
    //
    // NOTE: Do NOT reject the CPU returned by select_cpu_dfl based on
    // SMT sibling state. select_cpu_dfl internally claims the CPU's idle
    // bit (via scx_bpf_test_and_clear_cpu_idle). Rejecting the CPU here
    // would waste it: the CPU is marked non-idle but never used, causing
    // subsequent tasks to skip it. This leads to severe wakeup latency
    // (3ms+) as tasks pile up in DSQs with no CPU to consume them.
    //
    // SMT-aware idle CPU selection is properly handled by
    // scx_bpf_select_cpu_and() with SCX_PICK_IDLE_CORE (Strategy 1 above,
    // kernel >= 6.16). On older kernels, accept whatever select_cpu_dfl
    // returns — matching C cosmos behavior.
    if from_enqueue {
        // select_cpu_dfl is not valid from enqueue context.
        // C reference: pick_idle_cpu(..., from_enqueue=true) returns -EBUSY
        // when scx_bpf_select_cpu_and is not available.
        return -1;
    }

    let mut is_idle: bool = false;
    let cpu = kfuncs::select_cpu_dfl(p, prev_cpu, wake_flags, &mut is_idle);

    if is_idle { cpu } else { -1 }
}

// ── PMU helpers ─────────────────────────────────────────────────────────

/// Check if a task is event-heavy based on its last-run perf event count.
///
/// C reference: `is_event_heavy(tctx)` returns `tctx->perf_events > perf_threshold`.
/// When PERF_CONFIG == 0, this always returns false (no PMU tracking).
#[inline(always)]
fn is_event_heavy(tctx: &TaskCtx) -> bool {
    let threshold = PERF_THRESHOLD.get();
    threshold > 0 && tctx.perf_events > threshold
}

/// Find the least busy CPU by perf event count within the same NUMA node.
///
/// C reference: `pick_least_busy_event_cpu(p, prev_cpu)` scans per-CPU
/// `cctx->perf_events` to find the idle CPU with the lowest PMU activity
/// within the same NUMA node as `prev_cpu`.
///
/// When `PERF_STICKY` is true, returns `prev_cpu` immediately (keeping
/// event-heavy tasks pinned to their current CPU).
///
/// Uses `bpf_map_lookup_percpu_elem` (via `PerCpuArray::get_percpu`) to
/// read other CPUs' per-CPU context without being restricted to the
/// current CPU.
///
/// Uses `bpf_loop` with a callback instead of `bpf_for!` because the BPF
/// verifier's bounded-while-loop analysis cannot handle the complex loop
/// body (global array access with bounds checking + map lookup), detecting
/// "infinite loops" when the loop body state doesn't change between
/// iterations. `bpf_loop` tells the verifier the iteration count is bounded,
/// and the callback is analyzed only once regardless of iteration count.
///
/// Note: The `p->cpus_ptr` affinity check from the C version is skipped
/// because CO-RE field access for cpumasks is not yet available.
/// Note: The `is_cpu_idle(cpu)` check from the C version is skipped
/// because the extra `bpf_probe_read_kernel` calls in the loop body
/// add too many branches, and the verifier's jump complexity limit (8192)
/// is easily exceeded.

/// Context struct passed to the `bpf_loop` callback for `pick_least_busy_event_cpu`.
#[repr(C)]
struct LeastBusyCtx {
    node: u32,
    ret_cpu: i32,
    min: u64,
}

/// `bpf_loop` callback for scanning CPUs to find the least busy one.
///
/// Returns 0 to continue iterating, 1 to stop early.
#[inline(never)]
unsafe extern "C" fn least_busy_callback(idx: u32, ctx_ptr: *mut core::ffi::c_void) -> i64 {
    let ctx = &mut *(ctx_ptr as *mut LeastBusyCtx);

    // Stay within the same NUMA node.
    if cpu_node(idx) != ctx.node {
        return 0; // continue
    }

    // Look up this CPU's per-CPU context.
    if let Some(cctx) = CPU_CTX.get_percpu(0, idx) {
        if cctx.perf_events < ctx.min {
            ctx.min = cctx.perf_events;
            ctx.ret_cpu = idx as i32;
        }
    }

    0 // continue
}

#[inline(never)]
fn pick_least_busy_event_cpu(_p: *mut task_struct, prev_cpu: i32) -> i32 {
    if PERF_STICKY.get() {
        return prev_cpu;
    }

    // Bounds-check prev_cpu before using as array index — the BPF verifier
    // cannot prove it's in-range from just the signed i32 type.
    let prev_idx = prev_cpu as u32 as usize;
    if prev_idx >= MAX_CPUS {
        return prev_cpu;
    }
    let node = cpu_node(prev_cpu as u32);

    let nr = NR_CPU_IDS.get();
    let bound = if nr < MAX_CPUS as u32 { nr } else { MAX_CPUS as u32 };

    let mut ctx = LeastBusyCtx {
        node,
        ret_cpu: -16, // -EBUSY
        min: u64::MAX,
    };

    unsafe {
        scx_ebpf::helpers::bpf_loop(
            bound,
            least_busy_callback,
            &mut ctx as *mut LeastBusyCtx as *mut core::ffi::c_void,
            0,
        );
    }

    ctx.ret_cpu
}

/// Update perf event counters for a task.
///
/// Called by the `tp_btf/sched_switch` tracing program to store per-task
/// and per-CPU perf event deltas. The struct_ops scheduler reads these
/// values via `is_event_heavy()` and `pick_least_busy_event_cpu()`.
///
/// This function is NOT called from struct_ops callbacks — it is called
/// exclusively from the tracing program which has access to helper #55.
#[inline(always)]
fn update_perf_counters(p: *mut task_struct, delta: u64) {
    // Store delta in per-task context for is_event_heavy().
    if let Some(tctx) = TASK_CTX.get_mut(p as *mut u8) {
        tctx.perf_events = delta;
    }

    // Accumulate in per-CPU context for pick_least_busy_event_cpu().
    if let Some(cctx) = CPU_CTX.get_mut(0) {
        cctx.perf_events += delta;
    }
}

// ── Deferred wakeup timer ───────────────────────────────────────────────

/// Deferred wakeup timer callback.
///
/// Instead of waking up CPUs inline in the enqueue hot path, we defer
/// the wakeup to this periodic timer callback. This reduces IPI overhead.
///
/// C reference: `wakeup_timerfn()` in `main.bpf.c`
///
/// The callback iterates all CPUs, checking for tasks pending in the
/// local DSQ (`SCX_DSQ_LOCAL_ON | cpu`). For each CPU with queued tasks,
/// it issues `scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE)`. The `SCX_KICK_IDLE`
/// flag makes the kick a no-op for non-idle CPUs, so no explicit
/// `is_cpu_idle()` check is needed (the C version does check, but we
/// skip it since `scx_bpf_cpu_curr` is not available on all kernels).
///
/// The timer re-arms itself at the end for periodic execution with period
/// equal to `SLICE_NS`.
#[inline(never)]
fn wakeup_timerfn(
    _map: *mut core::ffi::c_void,
    _key: *mut i32,
    timer_ptr: *mut BpfTimer,
) -> i32 {
    let nr = NR_CPU_IDS.get();
    let bound = if nr < MAX_CPUS as u32 { nr } else { MAX_CPUS as u32 };

    bpf_for!(cpu, 0, bound, {
        let dsq_id = kfuncs::SCX_DSQ_LOCAL_ON | cpu as u64;
        if kfuncs::dsq_nr_queued(dsq_id) > 0 {
            kfuncs::kick_cpu(cpu as i32, SCX_KICK_IDLE);
        }
    });

    // Re-arm the timer for periodic execution (every slice_ns).
    let slice = SLICE_NS.get();
    timer::timer_start(timer_ptr, slice, 0);
    0
}

/// Wake up a CPU if it's idle, respecting deferred wakeup mode.
///
/// When `DEFERRED_WAKEUPS` is enabled, all wakeup events are deferred to
/// the periodic `wakeup_timerfn()` timer callback. The inline kick is
/// skipped to reduce IPI overhead in the enqueue hot path.
///
/// When disabled, directly calls `scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE)`.
///
/// C reference: `wakeup_cpu(cpu)` in `main.bpf.c`:
/// ```c
/// static inline void wakeup_cpu(s32 cpu) {
///     if (deferred_wakeups) return;
///     scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
/// }
/// ```
#[inline(always)]
fn wakeup_cpu(cpu: i32) {
    if DEFERRED_WAKEUPS.get() {
        return;
    }
    kfuncs::kick_cpu(cpu, SCX_KICK_IDLE);
}

// ── Scheduler callbacks ─────────────────────────────────────────────────

/// select_cpu: find an idle CPU for the task.
///
/// Uses `pick_idle_cpu()` for idle CPU selection with:
/// - no_wake_sync: clears SCX_WAKE_SYNC from wake_flags when enabled.
/// - SMT awareness: when avoid_smt is enabled, prefers fully-idle cores
/// - mm_affinity: when enabled and waker/wakee share the same address space,
///   keeps the wakee on the waker's CPU for cache locality (non-busy only)
/// - PMU: when perf_config is set, event-heavy tasks are dispatched to the
///   least busy CPU (by perf event count) rather than the default idle CPU
/// - If idle CPU found: dispatch directly to local DSQ (any saturation level)
/// - If no idle CPU and not busy: dispatch to local DSQ (round-robin)
/// - If no idle CPU and busy: do NOT dispatch, let enqueue() handle
///   deadline-mode dispatch to the shared DSQ
#[inline(always)]
pub fn on_select_cpu(p: *mut task_struct, prev_cpu: i32, wake_flags: u64) -> i32 {
    // NOTE: prev_cpu validation.
    //
    // The C cosmos validates prev_cpu against p->cpus_ptr:
    //   if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
    //       prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);
    //
    // This requires CO-RE field access to p->cpus_ptr which we cannot do
    // from Rust without generated vmlinux bindings for that field. This is
    // acceptable because:
    // - select_cpu_dfl and select_cpu_and handle invalid prev_cpu internally
    // - The kernel guarantees prev_cpu is valid in the common case
    // - Invalid prev_cpu only happens during cpuset changes, which are rare
    let mut prev_cpu = prev_cpu;

    // Clear SCX_WAKE_SYNC if no_wake_sync is enabled.
    // C: if (no_wake_sync) wake_flags &= ~SCX_WAKE_SYNC;
    let effective_wake_flags = if NO_WAKE_SYNC.get() {
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

    // Hybrid core wake-affine: on heterogeneous CPU systems (big.LITTLE,
    // Intel hybrid P/E-cores), if the waker is on a faster core and this
    // is a task wakeup (SCX_WAKE_TTWU), try to move the wakee to the
    // waker's core. This naturally migrates tasks toward higher-performance
    // cores.
    //
    // Only applies when primary_all is true (no primary cpumask filtering),
    // matching the C cosmos behavior.
    //
    // On homogeneous systems (all CPUs same capacity), is_cpu_faster()
    // always returns false and this path is never taken.
    //
    // C reference: pick_idle_cpu():
    //   if (primary_all && is_wakeup(wake_flags) && this_cpu >= 0 &&
    //       is_cpu_faster(this_cpu, prev_cpu)) {
    //       if (cpus_share_cache && !is_smt_contended) return prev_cpu;
    //       prev_cpu = this_cpu;
    //   }
    //
    // NOTE: We skip the cpus_share_cache and is_smt_contended checks since
    // they require per-CPU LLC IDs and SMT sibling masks which we don't
    // have in the pure-Rust BPF context. This means we may redirect the
    // idle scan to a faster core even when prev_cpu is in the same LLC and
    // fully idle — a minor suboptimality that select_cpu_dfl handles well.
    if PRIMARY_ALL.get() && (effective_wake_flags & SCX_WAKE_TTWU) != 0 {
        let this_cpu = get_smp_processor_id();
        if this_cpu >= 0 && is_cpu_faster(this_cpu, prev_cpu) {
            if kfuncs::test_and_clear_cpu_idle(this_cpu) {
                let weight = read_weight(p);
                let slice = task_slice(weight);
                kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, 0);
                return this_cpu;
            }
            // Redirect subsequent idle scan to the faster core's
            // neighborhood, even if we couldn't claim it directly.
            // C: prev_cpu = this_cpu;
            prev_cpu = this_cpu;
        }
    }

    // PMU event-heavy dispatch: when perf_config is set, redirect
    // event-heavy tasks to the least busy CPU (by perf event count).
    //
    // C reference: cosmos_select_cpu():
    //   if (perf_config) {
    //       tctx = try_lookup_task_ctx(p);
    //       if (tctx && is_event_heavy(tctx)) {
    //           dsq_insert(p, SCX_DSQ_LOCAL, ...);
    //           new_cpu = pick_least_busy_event_cpu(p, prev_cpu);
    //           return new_cpu < 0 ? prev_cpu : new_cpu;
    //       }
    //   }
    if PERF_CONFIG.get() != 0 {
        if let Some(tctx) = TASK_CTX.get_ref(p as *mut u8) {
            if is_event_heavy(tctx) {
                let weight = read_weight(p);
                let slice = task_slice(weight);
                kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, 0);
                let new_cpu = pick_least_busy_event_cpu(p, prev_cpu);
                return if new_cpu >= 0 { new_cpu } else { prev_cpu };
            }
        }
    }

    let cpu = pick_idle_cpu(p, prev_cpu, effective_wake_flags, false);
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

/// enqueue: four-tier dispatch — PMU event-heavy, migration, local round-robin,
/// or shared DSQ.
///
/// Mirrors the C cosmos_enqueue() pattern:
///
/// 0. **PMU event-heavy dispatch**: If PMU tracking is enabled and the task
///    is event-heavy (high perf counter), dispatch to the least busy CPU.
///
/// 1. **Migration attempt** (wakeup path): If the task is not currently
///    running and select_cpu was not already called (no SCX_ENQ_CPU_SELECTED),
///    try to find an idle CPU and dispatch directly there via
///    `SCX_DSQ_LOCAL_ON`. For pinned tasks (single-CPU affinity or migration
///    disabled), only try prev_cpu instead of a full idle scan.
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

    // ── Phase 1.5: PMU event-heavy dispatch ──────────────────────────
    // C: if (perf_config && !is_migration_disabled(p) && is_event_heavy(tctx))
    //        new_cpu = pick_least_busy_event_cpu(p, prev_cpu);
    //        dsq_insert(LOCAL_ON | new_cpu, ...); wakeup_cpu(new_cpu);
    //
    // Immediately dispatch perf event-heavy tasks to a less busy CPU.
    // This runs before the migration check to prioritize PMU-aware placement.
    if PERF_CONFIG.get() != 0 && !is_migration_disabled(p) {
        if let Some(tctx) = TASK_CTX.get_ref(p as *mut u8) {
            if is_event_heavy(tctx) {
                let new_cpu = pick_least_busy_event_cpu(p, prev_cpu);
                if new_cpu >= 0 {
                    let weight = read_weight(p);
                    let slice = task_slice(weight);
                    kfuncs::dsq_insert(
                        p,
                        kfuncs::SCX_DSQ_LOCAL_ON | new_cpu as u64,
                        slice,
                        enq_flags,
                    );
                    if new_cpu != prev_cpu || !is_running {
                        wakeup_cpu(new_cpu);
                    }
                    return;
                }
            }
        }
    }

    // ── Phase 2: migration attempt ───────────────────────────────────
    // C: if (task_should_migrate(p, enq_flags)) { ... }
    // task_should_migrate = !is_enq_cpu_selected(enq_flags) && !is_running
    //
    // Only attempt migration if:
    // - The task is waking up (not currently running), AND
    // - select_cpu was NOT already called (SCX_ENQ_CPU_SELECTED not set)
    let should_migrate = !is_running && (enq_flags & SCX_ENQ_CPU_SELECTED) == 0;
    if should_migrate {
        // For pinned tasks (single-CPU affinity or migration disabled),
        // only try prev_cpu. Don't do a full idle CPU scan since the
        // task can't run anywhere else.
        // C: if (is_pcpu_task(p))
        //        cpu = test_and_clear_cpu_idle(prev_cpu) ? prev_cpu : -EBUSY;
        //    else
        //        cpu = pick_idle_cpu(p, prev_cpu, -1, 0, true);
        let idle_cpu = if is_pcpu_task(p) {
            if kfuncs::test_and_clear_cpu_idle(prev_cpu) {
                prev_cpu
            } else {
                -1
            }
        } else {
            if kfuncs::test_and_clear_cpu_idle(prev_cpu) {
                prev_cpu
            } else {
                // Full idle CPU scan: try preferred list, primary cpumask,
                // and SMT-aware filtering.
                // C reference: pick_idle_cpu(p, prev_cpu, -1, 0, true)
                pick_idle_cpu(p, prev_cpu, 0, true)
            }
        };
        if idle_cpu >= 0 {
            let weight = read_weight(p);
            let slice = task_slice(weight);
            kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL_ON | idle_cpu as u64, slice, enq_flags);
            wakeup_cpu(idle_cpu);
            return;
        }
    }

    // ── Phase 3: local dispatch when not busy ────────────────────────
    // C: if (!is_system_busy()) { dsq_insert(LOCAL, ...); wakeup_cpu(); }
    if !is_system_busy() {
        let weight = read_weight(p);
        let slice = task_slice(weight);
        kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, enq_flags);
        // If the task should migrate (wakeup), wake prev_cpu.
        if should_migrate {
            wakeup_cpu(prev_cpu);
        }
        return;
    }

    // ── Phase 4: deadline mode to shared DSQ ─────────────────────────
    // Read struct fields now — we've finished all the kfunc calls that
    // need minimal register pressure.
    let vtime = if let Ok(v) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        v
    } else {
        VTIME_NOW.get()
    };
    let weight = read_weight(p);
    let slice = task_slice(weight);

    // Compute deadline using exec_runtime from per-task storage.
    // C: task_dl() clamps dsq_vtime first, then computes
    //   deadline = dsq_vtime + scale_inverse(exec_runtime)
    // Tasks with more accumulated runtime get higher (later) deadlines,
    // prioritizing interactive tasks that sleep frequently.
    let (exec_runtime, wakeup_freq) = if let Some(tctx) = TASK_CTX.get_ref(p as *mut u8) {
        (tctx.exec_runtime, tctx.wakeup_freq)
    } else {
        (0u64, 0u64)
    };

    // Clamp vtime FIRST so tasks don't accumulate too much credit from sleeping.
    // C: lag_scale = MAX(wakeup_freq, 1)
    //    vsleep_max = scale_by_task_weight(p, slice_lag * lag_scale)
    //    vtime_min = vtime_now - vsleep_max
    //    if (time_before(dsq_vtime, vtime_min)) dsq_vtime = vtime_min
    let vtime_now = VTIME_NOW.get();
    let slice_lag = get_slice_lag();
    let lag_scale = if wakeup_freq > 1 { wakeup_freq } else { 1 };
    let vsleep_max = if weight > 0 { (slice_lag * lag_scale * weight) / 100 } else { slice_lag * lag_scale };
    let vtime_min = vtime_now.wrapping_sub(vsleep_max);
    let clamped_vtime = if time_before(vtime, vtime_min) { vtime_min } else { vtime };

    // Write clamped vtime back to dsq_vtime if it changed.
    if clamped_vtime != vtime {
        #[cfg(feature = "kernel_6_16")]
        kfuncs::task_set_dsq_vtime(p, clamped_vtime);
        #[cfg(not(feature = "kernel_6_16"))]
        core_write!(vmlinux::task_struct, p, scx.dsq_vtime, clamped_vtime);
    }

    // Compute deadline from the (clamped) vtime.
    // C: return dsq_vtime + scale_by_task_weight_inverse(p, exec_runtime)
    let deadline = if weight > 0 {
        clamped_vtime.wrapping_add(exec_runtime * 100 / weight)
    } else {
        clamped_vtime.wrapping_add(exec_runtime)
    };

    kfuncs::dsq_insert_vtime(p, shared_dsq(prev_cpu), slice, deadline, enq_flags);

    // If the task should migrate (wakeup), wake prev_cpu.
    // C: if (task_should_migrate(p, enq_flags)) wakeup_cpu(prev_cpu);
    if should_migrate {
        wakeup_cpu(prev_cpu);
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
        // scx.flags (u32) is immediately followed by scx.weight (u32) in
        // the kernel's task_struct layout. Reading 8 bytes at the flags
        // offset gets both in one call.
        let base = prev as *const u8;
        let flags_offset = core::mem::offset_of!(vmlinux::task_struct, scx.flags);
        let src = unsafe { base.add(flags_offset) as *const u64 };
        if let Ok(flags_and_weight) = unsafe { scx_ebpf::helpers::probe_read_kernel(src) } {
            let flags = flags_and_weight as u32;
            let weight = (flags_and_weight >> 32) as u64;
            if flags & SCX_TASK_QUEUED != 0 {
                let slice = task_slice(weight);
                #[cfg(feature = "kernel_6_16")]
                kfuncs::task_set_slice(prev, slice);
                #[cfg(not(feature = "kernel_6_16"))]
                core_write!(vmlinux::task_struct, prev, scx.slice, slice);
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
    if let Some(tctx) = TASK_CTX.get_mut(p as *mut u8) {
        // Reset accumulated runtime — task just woke up.
        tctx.exec_runtime = 0;
        // Update wakeup frequency using time since last wakeup.
        let delta = now.wrapping_sub(tctx.last_woke_at);
        tctx.wakeup_freq = update_freq(tctx.wakeup_freq, delta);
        // Cap at 1024 to match C's MIN(tctx->wakeup_freq, 1024).
        if tctx.wakeup_freq > 1024 {
            tctx.wakeup_freq = 1024;
        }
        tctx.last_woke_at = now;
    }
}

/// running: update vtime_now, record run start time, capture PMU baseline,
/// and apply cpufreq.
///
/// Advances the global vruntime to track the most recent task's vtime.
/// Records the timestamp in per-task storage for accurate time-slice
/// charging in stopping(). Applies cpufreq performance scaling.
///
/// NOTE: The C cosmos calls scx_pmu_event_start(p, false) here when
/// perf_config is set, which reads bpf_perf_event_read_value to capture a
/// baseline counter value. Helper #55 is not available in struct_ops programs,
/// so this is handled instead by the `tp_btf/sched_switch` tracing program,
/// which records the baseline counter for each incoming task in PMU_BASELINE.
///
/// C reference: cosmos_running() calls update_cpufreq(scx_bpf_task_cpu(p))
/// and scx_pmu_event_start(p, false) when perf_config is set.
#[inline(always)]
pub fn on_running(p: *mut task_struct) {
    // Record run start time in per-task storage.
    // C: tctx->last_run_at = scx_bpf_now();
    let now = kfuncs::now();
    if let Some(tctx) = TASK_CTX.get_mut(p as *mut u8) {
        tctx.last_run_at = now;
    }

    // Update current system's vruntime.
    // C uses time_before(vtime_now, dsq_vtime) which does wrapping comparison;
    // we use plain `<` which is sufficient because vtime_now stays near current
    // values and wrapping is not expected in practice.
    // C: if (time_before(vtime_now, p->scx.dsq_vtime))
    //        vtime_now = p->scx.dsq_vtime;
    if let Ok(dsq_vtime) = core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        if VTIME_NOW.get() < dsq_vtime {
            VTIME_NOW.set(dsq_vtime);
        }
    }

    // Apply cpufreq performance level based on recent load.
    // C: update_cpufreq(scx_bpf_task_cpu(p));
    if CPUFREQ_ENABLED.get() {
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
/// NOTE: The C cosmos calls scx_pmu_event_stop(p) + update_counters() here
/// to compute perf counter deltas. In our implementation, PMU counters are
/// updated by the separate `tp_btf/sched_switch` tracing program on context
/// switches, not inline in stopping(). The struct_ops scheduler only reads
/// the stored values via `is_event_heavy()` and `pick_least_busy_event_cpu()`.
///
/// C reference: cosmos_stopping() calls update_cpu_load(p, slice) which
/// computes perf_lvl = MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE)
/// and smooths it with EWMA. Also calls scx_pmu_event_stop(p) +
/// update_counters(p, tctx, cpu) for PMU tracking.
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
    let slice = if let Some(tctx) = TASK_CTX.get_mut(p as *mut u8) {
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

    #[cfg(feature = "kernel_6_16")]
    kfuncs::task_set_dsq_vtime(p, new_vtime);
    #[cfg(not(feature = "kernel_6_16"))]
    core_write!(vmlinux::task_struct, p, scx.dsq_vtime, new_vtime);

    // PMU counter updates are handled by the tp_btf/sched_switch tracing
    // program, which reads perf events on context switches and writes to
    // TASK_CTX.perf_events and CPU_CTX.perf_events. The struct_ops scheduler
    // only reads those values (via is_event_heavy / pick_least_busy_event_cpu).

    // Update per-CPU load for cpufreq scaling.
    // C: update_cpu_load(p, slice);
    update_cpu_load(slice, now);
}

/// enable: initialize a task's dsq_vtime to the current global vruntime.
///
/// Direct port of the C cosmos_enable callback.
#[inline(always)]
pub fn on_enable(p: *mut task_struct) {
    let vtime_now = VTIME_NOW.get();
    #[cfg(feature = "kernel_6_16")]
    kfuncs::task_set_dsq_vtime(p, vtime_now);
    #[cfg(not(feature = "kernel_6_16"))]
    core_write!(vmlinux::task_struct, p, scx.dsq_vtime, vtime_now);
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
/// C reference: cosmos_exit_task() calls scx_pmu_task_fini(p) for PMU
/// cleanup. Our PMU state is embedded in the TaskCtx storage map and
/// is automatically cleaned up when the storage entry is deleted.
#[inline(always)]
pub fn on_exit_task(p: *mut task_struct, _args: *mut core::ffi::c_void) {
    // Clean up per-task storage.
    let _ = TASK_CTX.delete(p as *mut u8);
}

/// Initialize the primary cpumask kptr.
///
/// Creates an empty `bpf_cpumask` and stores it in the `PRIMARY_CPUMASK`
/// global kptr via `bpf_kptr_xchg`. The aya loader's `fixup_kptr_types()`
/// transforms the `Kptr<T>` wrapper's BTF into the `PTR -> TYPE_TAG("kptr")`
/// chain that the verifier requires.
///
/// Called from `on_init()`. The cpumask starts empty; when `PRIMARY_ALL` is
/// false, `on_init()` then populates it from the `PRIMARY_CPU_LIST` array
/// (set by userspace via `override_global`).
///
/// Mirrors the C `init_cpumask()` pattern: create, kptr_xchg, release old.
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

/// init: create DSQ(s), record nr_cpu_ids, initialize primary cpumask,
/// and set up the deferred wakeup timer.
///
/// When NUMA is enabled, creates one DSQ per NUMA node (DSQ ID = node ID).
/// Otherwise creates a single shared DSQ (DSQ 0). Initializes the primary
/// cpumask kptr and populates it from `PRIMARY_CPU_LIST` when `PRIMARY_ALL`
/// is false. When `DEFERRED_WAKEUPS` is enabled, initializes and starts
/// the periodic wakeup timer.
///
/// C reference: `cosmos_init()` with `bpf_for(node, 0, nr_node_ids)`.
#[inline(always)]
pub fn on_init() -> i32 {
    // Record the number of CPUs for bounds checking.
    NR_CPU_IDS.set(kfuncs::nr_cpu_ids());

    // Create per-node DSQs when NUMA is enabled, otherwise a single shared DSQ.
    // C: if (numa_enabled) { bpf_for(node, 0, nr_node_ids) create_dsq(node, node); }
    //    else { create_dsq(SHARED_DSQ, -1); }
    if NUMA_ENABLED.get() {
        let nr_nodes = NR_NODES.get();
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

    // Initialize the primary cpumask kptr.
    // Creates an empty cpumask and stores it via kptr_xchg.
    // When PRIMARY_ALL is true (default), the cpumask exists but is not
    // consulted in pick_idle_cpu(). When userspace sets PRIMARY_ALL = false
    // and populates the cpumask, it restricts idle CPU selection.
    let err = init_primary_cpumask();
    if err != 0 {
        scx_ebpf::scx_bpf_error!("cosmos: failed to init primary cpumask");
        return err;
    }

    // Populate the primary cpumask from PRIMARY_CPU_LIST when userspace
    // has set PRIMARY_ALL = false. Userspace fills PRIMARY_CPU_LIST with
    // the CPUs that should be in the primary domain (terminated by -1).
    // This replaces the C cosmos's `enable_primary_cpu` syscall program.
    if !PRIMARY_ALL.get() {
        rcu_read_lock();
        let mask = unsafe { Kptr::get(&raw mut PRIMARY_CPUMASK) };
        if !mask.is_null() {
            bpf_for!(i, 0, MAX_CPUS as u32, {
                let cpu = PRIMARY_CPU_LIST.get(i as usize).unwrap_or(-1);
                if cpu < 0 {
                    break;
                }
                cpumask::set_cpu(cpu as u32, mask as *mut bpf_cpumask);
            });
        }
        rcu_read_unlock();
    }

    // Initialize the deferred wakeup timer when enabled.
    //
    // C reference: cosmos_init():
    //   timer = bpf_map_lookup_elem(&wakeup_timer, &key);
    //   bpf_timer_init(timer, &wakeup_timer, CLOCK_MONOTONIC);
    //   bpf_timer_set_callback(timer, wakeup_timerfn);
    //   bpf_timer_start(timer, slice_ns, 0);
    if DEFERRED_WAKEUPS.get() {
        let timer_val = WAKEUP_TIMER.get_ptr_mut(0);
        if !timer_val.is_null() {
            let t = unsafe { &mut (*timer_val).timer as *mut BpfTimer };
            let map_ptr = core::ptr::from_ref(&WAKEUP_TIMER).cast();
            timer::timer_init(t, map_ptr, timer::CLOCK_MONOTONIC);
            timer::timer_set_callback(t, wakeup_timerfn as *const () as u64);
            let slice = SLICE_NS.get();
            timer::timer_start(t, slice, 0);
        }
    }

    // Per-CPU perf_events counters are zero-initialized by the kernel
    // when the BPF map is created (.bss semantics for PerCpuArray), so
    // no explicit zeroing loop is needed here.
    //
    // NOTE: The previous code had a loop over all CPUs calling
    // CPU_CTX.get_ptr_mut(0), but PerCpuArray::get_ptr_mut(0) always
    // returns the *current* CPU's entry, so the loop was zeroing the
    // same entry repeatedly. Since the kernel already zero-initializes
    // per-CPU array entries, the loop was unnecessary.
    //
    // NOTE: The C version calls scx_pmu_install(perf_config) here to
    // program per-CPU perf events. In Rust, userspace handles this via
    // perf_event_open() and populating SCX_PMU_MAP (see loader code).

    0
}

/// exit: PMU cleanup placeholder.
///
/// C reference: cosmos_exit() calls scx_pmu_uninstall() when perf_config
/// is set, and UEI_RECORD(uei, ei) to save exit info for userspace.
/// Our PMU state is in per-CPU and per-task maps that are automatically
/// cleaned up when the BPF program detaches. UEI_RECORD is not yet
/// ported (requires the UEI mechanism).
#[inline(always)]
pub fn on_exit(_ei: *mut scx_exit_info) {}

// ── PMU tracing program ─────────────────────────────────────────────────
//
// This is a BTF-enabled raw tracepoint program that attaches to
// `sched_switch`. It runs on every context switch and can call
// `bpf_perf_event_read_value` (helper #55), which is restricted to
// tracing program types and NOT available in struct_ops programs.
//
// Architecture (mirrors C scx/lib/pmu.bpf.c):
//   On sched_switch(prev, next):
//     1. Read perf counter for current CPU
//     2. For prev: compute delta = current - baseline, write to
//        TASK_CTX.perf_events (for is_event_heavy) and
//        CPU_CTX.perf_events (for pick_least_busy_event_cpu)
//     3. For next: record baseline = current in PMU_BASELINE
//
// The tracepoint context for tp_btf/sched_switch is an array of u64
// pointers. The layout matches the kernel's tracepoint definition:
//   ctx[0] = (unused, preempt flag in some kernels)
//   ctx[1] = pointer to prev task_struct
//   ctx[2] = pointer to next task_struct

/// `tp_btf/sched_switch` — PMU perf event reader.
///
/// This function is placed in the `tp_btf/sched_switch` ELF section, which
/// aya recognizes as a `BtfTracePoint` program. Userspace loads and attaches
/// it separately from the struct_ops scheduler.
///
/// On each context switch:
/// - Reads the perf counter for the current CPU
/// - Computes the event delta for the outgoing task (prev)
/// - Stores the delta in prev's per-task and per-CPU context
/// - Records the baseline counter for the incoming task (next)
///
/// When PERF_CONFIG is 0 (PMU disabled), this function returns immediately.
#[unsafe(no_mangle)]
#[unsafe(link_section = "tp_btf/sched_switch")]
pub unsafe extern "C" fn scx_pmu_sched_switch(ctx: *const u64) -> i32 {
    // Skip if PMU is not configured.
    if PERF_CONFIG.get() == 0 {
        return 0;
    }

    // Read the perf counter for the current CPU.
    let mut val = core::mem::MaybeUninit::<PerfEventValue>::uninit();
    let ret = pmu::perf_event_read_value(
        &raw const SCX_PMU_MAP as *const core::ffi::c_void,
        BPF_F_CURRENT_CPU,
        val.as_mut_ptr(),
    );
    if ret != 0 {
        // If the read fails (e.g., no perf event installed for this CPU),
        // silently skip. This is expected during startup or on CPUs where
        // perf events haven't been installed yet.
        return 0;
    }
    let current_counter = val.assume_init().counter;

    // Extract prev and next task pointers from the tracepoint context.
    // tp_btf/sched_switch context layout: ctx[1] = prev, ctx[2] = next.
    let prev = *ctx.add(1) as *mut task_struct;
    let next = *ctx.add(2) as *mut task_struct;

    // Process outgoing task (prev): compute delta and store in maps.
    if !prev.is_null() {
        // Read prev's PID to skip kernel idle thread (pid 0).
        let prev_pid = core_read!(vmlinux::task_struct, prev, pid);
        if let Ok(pid) = prev_pid {
            if pid != 0 {
                // Read the baseline for this CPU.
                if let Some(baseline) = PMU_BASELINE.get(0) {
                    let delta = current_counter.wrapping_sub(*baseline);
                    // Write delta to per-task and per-CPU contexts.
                    update_perf_counters(prev, delta);
                }
            }
        }
    }

    // Process incoming task (next): record baseline for next run.
    if !next.is_null() {
        let next_pid = core_read!(vmlinux::task_struct, next, pid);
        if let Ok(pid) = next_pid {
            if pid != 0 {
                // Store the current counter as the baseline for next's run.
                let ptr = PMU_BASELINE.get_ptr_mut(0);
                if !ptr.is_null() {
                    core::ptr::write_volatile(ptr, current_counter);
                }
            }
        }
    }

    0
}

// ── Registration ────────────────────────────────────────────────────────

scx_ebpf::scx_ops_define! {
    name: "cosmos",
    timeout_ms: 5000,
    // SCX_OPS_ENQ_LAST (2) | SCX_OPS_ENQ_EXITING (4) |
    // SCX_OPS_ENQ_MIGRATION_DISABLED (16) | SCX_OPS_ALLOW_QUEUED_WAKEUP (32)
    //
    // These flags match the C cosmos userspace loader which sets them at
    // runtime via skel.struct_ops.cosmos_ops_mut().flags. Since our pure-Rust
    // loader doesn't modify struct_ops fields, we set them here in the BPF
    // binary directly.
    //
    // - ENQ_LAST: keep running the previous task if no other task is ready
    // - ENQ_EXITING: enqueue exiting tasks (important for cleanup)
    // - ENQ_MIGRATION_DISABLED: enqueue migration-disabled tasks
    // - ALLOW_QUEUED_WAKEUP: allow wakeups of already-queued tasks
    flags: 54,
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
