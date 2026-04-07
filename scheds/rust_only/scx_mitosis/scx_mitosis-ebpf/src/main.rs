// SPDX-License-Identifier: GPL-2.0
//
// scx_mitosis — cell-based cgroup scheduler, ported from C to pure Rust.
//
// This is the eBPF side. Currently implements:
// - DSQ ID encoding (per-CPU + cell+LLC)
// - Core data structures (cell, task_ctx, cpu_ctx, cgrp_ctx)
// - Minimal scheduler skeleton (enqueue → global DSQ, dispatch, init/exit)

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_camel_case_types, non_upper_case_globals, dead_code, unused_imports)]

use scx_ebpf::prelude::*;
use scx_ebpf::core_read;
use scx_ebpf::core_write;
use scx_ebpf::maps::{TaskStorage, PerCpuArray, HashMap, BpfArray, CgrpStorage};
use scx_ebpf::helpers::BpfSpinLock;
use scx_ebpf::cgroup::cgroup;
use scx_ebpf::cpumask::{self, bpf_cpumask};
use scx_ebpf::kptr::{Kptr, kptr_xchg};
use scx_ebpf::timer::{self, BpfTimer};

mod vmlinux {
    include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
}

scx_ebpf::scx_ebpf_boilerplate!();

// FAKE_FLAT_CELL_LLC constant defined at line ~478 (=0, used when LLC
// awareness is disabled to flatten topology into one scheduling domain).

// ── Constants (matching C intf.h) ──────────────────────────────────────

const CACHELINE_SIZE: usize = 64;
const MAX_CPUS_SHIFT: u32 = 9;
const MAX_CPUS: u32 = 1 << MAX_CPUS_SHIFT;  // 512
const MAX_CPUS_U8: usize = (MAX_CPUS as usize) / 8; // 64
const MAX_CELLS: u32 = 256;
const MAX_LLCS: u32 = 16;
const MAX_CG_DEPTH: usize = 256;
const TIMER_INTERVAL_NS: u64 = 100_000_000;  // 100ms
const USAGE_HALF_LIFE: u64 = 100_000_000;     // 100ms
const DEBUG_EVENTS_BUF_SIZE: u32 = 4096;
const CPUMASK_LONG_ENTRIES: usize = 128;

/// Statistics indices, matching C enum cell_stat_idx.
#[repr(u32)]
#[derive(Clone, Copy)]
enum CellStat {
    Local = 0,
    CpuDsq = 1,
    CellDsq = 2,
    AffinityViolation = 3,
    Steal = 4,
}
const NR_CSTATS: usize = 5;

// ── DSQ ID encoding ───────────────────────────────────────────────────
//
// 64-bit layout (only low 32 bits used for user DSQs):
//
//   Per-CPU:    [31..28]=0x1  [27..0]=CPU#
//   Cell+LLC:   [31..28]=0x2  [27..16]=CELL#  [15..0]=LLC_ID
//
// Bit 63 set = built-in DSQ (LOCAL, GLOBAL, etc.)
//
// We use const fn constructors and explicit bit manipulation instead of
// C bitfield unions, which avoids compiler-defined layout issues.

const CPU_BITS: u32 = 28;
const LLC_BITS: u32 = 16;
const CELL_BITS: u32 = 12;
const TYPE_BITS: u32 = 4;
const TYPE_SHIFT: u32 = 28;  // bits [31..28]
const CELL_SHIFT: u32 = 16;  // bits [27..16] in cell+LLC layout

/// DSQ type enumeration.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum DsqType {
    None = 0,
    Cpu = 1,
    CellLlc = 2,
}

/// 64-bit DSQ ID. Thin wrapper around u64 for type safety.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct DsqId(u64);

/// Invalid DSQ ID sentinel (type=0, all zero).
const DSQ_INVALID: DsqId = DsqId(0);

impl DsqId {
    /// Construct a per-CPU DSQ ID.
    #[inline(always)]
    const fn cpu(cpu: u32) -> Self {
        DsqId(((DsqType::Cpu as u64) << TYPE_SHIFT) | (cpu as u64))
    }

    /// Construct a cell+LLC DSQ ID.
    #[inline(always)]
    const fn cell_llc(cell: u32, llc: u32) -> Self {
        DsqId(
            ((DsqType::CellLlc as u64) << TYPE_SHIFT)
                | ((cell as u64) << CELL_SHIFT)
                | (llc as u64),
        )
    }

    /// Extract the DSQ type from the low 32 bits.
    #[inline(always)]
    const fn dsq_type(self) -> u32 {
        ((self.0 >> TYPE_SHIFT) & 0xF) as u32
    }

    /// Is this the invalid sentinel?
    #[inline(always)]
    const fn is_invalid(self) -> bool {
        self.0 == 0
    }

    /// Is this a user-defined DSQ (not built-in, not invalid)?
    #[inline(always)]
    const fn is_user(self) -> bool {
        // Bit 63 clear (not built-in) and type != None
        (self.0 >> 63) == 0 && self.dsq_type() != DsqType::None as u32
    }

    /// Is this a per-CPU DSQ?
    #[inline(always)]
    const fn is_cpu(self) -> bool {
        self.is_user() && self.dsq_type() == DsqType::Cpu as u32
    }

    /// Is this a cell+LLC DSQ?
    #[inline(always)]
    const fn is_cell_llc(self) -> bool {
        self.is_user() && self.dsq_type() == DsqType::CellLlc as u32
    }

    /// Get the raw u64 value for passing to kfuncs.
    #[inline(always)]
    const fn raw(self) -> u64 {
        self.0
    }

    /// Extract CPU number from a per-CPU DSQ ID.
    /// Caller must ensure `is_cpu()` is true.
    #[inline(always)]
    const fn cpu_id(self) -> u32 {
        (self.0 & ((1 << CPU_BITS) - 1)) as u32
    }

    /// Extract cell number from a cell+LLC DSQ ID.
    /// Caller must ensure `is_cell_llc()` is true.
    #[inline(always)]
    const fn cell_id(self) -> u32 {
        ((self.0 >> CELL_SHIFT) & ((1 << CELL_BITS) - 1)) as u32
    }

    /// Extract LLC ID from a cell+LLC DSQ ID.
    /// Caller must ensure `is_cell_llc()` is true.
    #[inline(always)]
    const fn llc_id(self) -> u32 {
        (self.0 & ((1 << LLC_BITS) - 1)) as u32
    }
}

// ── Per-LLC data (cacheline-aligned) ──────────────────────────────────

/// Per-LLC data within a cell. Cacheline-aligned to prevent false
/// sharing when CPUs on different LLCs update concurrently.
///
/// Matches C `struct cell_llc`.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct CellLlc {
    vtime_now: u64,
    cpu_cnt: u32,
    // Padding to fill cacheline (64 - 12 = 52 bytes)
    _pad: [u8; 52],
}

const _: () = assert!(
    core::mem::size_of::<CellLlc>() == CACHELINE_SIZE,
    "CellLlc must be exactly one cache line"
);

impl CellLlc {
    const ZERO: Self = Self {
        vtime_now: 0,
        cpu_cnt: 0,
        _pad: [0; 52],
    };
}

// ── Cell struct ───────────────────────────────────────────────────────

/// Core scheduling cell. A cell is a group of CPUs + cgroups that are
/// scheduled together.
///
/// Matches C `struct cell`. The lock field is a BPF spin lock in the
/// kernel; userspace sees it as 4 bytes of padding (zeroed by kernel).
///
/// Layout: lock(4) + in_use(4) + cpu_cnt(4) + llc_present_cnt(4) +
///         pad_to_cacheline(48) + llcs[MAX_LLCS](64*16=1024)
///         = 64 + 1024 = 1088 bytes
#[repr(C)]
#[derive(Clone, Copy)]
struct Cell {
    /// BPF spin lock (4 bytes). Must be first field at offset 0.
    lock: BpfSpinLock,
    /// Whether this cell is currently in use.
    in_use: u32,
    /// Number of CPUs assigned to this cell.
    cpu_cnt: u32,
    /// Number of LLCs with at least one CPU in this cell.
    llc_present_cnt: u32,
    /// Padding to align llcs[] to cacheline boundary.
    _pad: [u8; 48],
    /// Per-LLC data, cacheline-aligned.
    llcs: [CellLlc; MAX_LLCS as usize],
}

const _: () = assert!(
    core::mem::size_of::<Cell>() == CACHELINE_SIZE + (CACHELINE_SIZE * MAX_LLCS as usize),
    "Cell size must match C layout: cacheline header + MAX_LLCS cachelines"
);

const _: () = assert!(
    core::mem::offset_of!(Cell, lock) == 0,
    "lock must be at offset 0"
);

const _: () = assert!(
    core::mem::offset_of!(Cell, in_use) == 4,
    "in_use must follow 4-byte lock"
);

impl Cell {
    const ZERO: Self = Self {
        lock: BpfSpinLock::new(),
        in_use: 0,
        cpu_cnt: 0,
        llc_present_cnt: 0,
        _pad: [0; 48],
        llcs: [CellLlc::ZERO; MAX_LLCS as usize],
    };
}

// ── Per-task context ──────────────────────────────────────────────────

/// Per-task context stored in BPF_MAP_TYPE_TASK_STORAGE.
///
/// Matches C `struct task_ctx`.
#[repr(C)]
#[derive(Clone, Copy)]
struct TaskCtx {
    /// Pointer to this task's cpumask (kptr, stored in task storage).
    /// PORT_TODO(aya-55): bpf_cpumask __kptr not yet supported in
    /// pure Rust BPF. Need kptr_xchg support in aya maps. For now,
    /// we track cpumask as a null pointer placeholder.
    cpumask_placeholder: u64,
    /// Timestamp when task started running (for runtime accounting).
    started_running_at: u64,
    /// Base vtime for this task's scheduling priority.
    basis_vtime: u64,
    /// Cell this task belongs to.
    cell: u32,
    /// DSQ this task is assigned to (per-CPU or cell+LLC).
    dsq: DsqId,
    /// Configuration sequence number (to detect stale config).
    configuration_seq: u32,
    /// Whether all CPUs in the cell are allowed for this task.
    all_cell_cpus_allowed: u32, // bool as u32 for BPF alignment
    /// Last known cgroup ID (for detecting cgroup moves).
    cgid: u64,
    /// Which LLC this task is assigned to (-1 = none).
    llc: i32,
    /// How many times this task has been stolen.
    steal_count: u32,
    /// Timestamp of last steal.
    last_stolen_at: u64,
}

impl TaskCtx {
    const ZERO: Self = Self {
        cpumask_placeholder: 0,
        started_running_at: 0,
        basis_vtime: 0,
        cell: 0,
        dsq: DSQ_INVALID,
        configuration_seq: 0,
        all_cell_cpus_allowed: 0,
        cgid: 0,
        llc: -1,
        steal_count: 0,
        last_stolen_at: 0,
    };
}

// ── Per-CPU context ───────────────────────────────────────────────────

/// Per-CPU context stored in BPF_MAP_TYPE_PERCPU_ARRAY.
///
/// Matches C `struct cpu_ctx`.
#[repr(C)]
#[derive(Clone, Copy)]
struct CpuCtx {
    /// Per-cell statistics counters.
    cstats: [[u64; NR_CSTATS]; MAX_CELLS as usize],
    /// Per-cell cycle counts.
    cell_cycles: [u64; MAX_CELLS as usize],
    /// Current vtime for this CPU.
    vtime_now: u64,
    /// Cell this CPU belongs to.
    cell: u32,
    /// LLC this CPU belongs to.
    llc: u32,
}

impl CpuCtx {
    const ZERO: Self = Self {
        cstats: [[0; NR_CSTATS]; MAX_CELLS as usize],
        cell_cycles: [0; MAX_CELLS as usize],
        vtime_now: 0,
        cell: 0,
        llc: 0,
    };
}

// ── Per-cgroup context ────────────────────────────────────────────────

/// Per-cgroup context stored in BPF_MAP_TYPE_CGRP_STORAGE.
///
/// Matches C `struct cgrp_ctx`.
#[repr(C)]
#[derive(Clone, Copy)]
struct CgrpCtx {
    /// Cell this cgroup is assigned to.
    cell: u32,
    /// Whether this cgroup owns its cell.
    cell_owner: u32, // bool as u32 for BPF alignment
}

impl CgrpCtx {
    const ZERO: Self = Self {
        cell: 0,
        cell_owner: 0,
    };
}

// ── Root cell constant ────────────────────────────────────────────────

const ROOT_CELL_ID: u32 = 0;

// ── LLC cpumask (fixed-size CPU bitmask for topology arrays) ─────────

/// Fixed-size CPU bitmask matching C `struct llc_cpumask` (intf.h:39-41).
/// Supports up to CPUMASK_LONG_ENTRIES * 64 = 8192 CPUs.
#[repr(C)]
#[derive(Clone, Copy)]
struct LlcCpumask {
    bits: [u64; CPUMASK_LONG_ENTRIES],
}

impl LlcCpumask {
    const ZERO: Self = Self {
        bits: [0; CPUMASK_LONG_ENTRIES],
    };
}

// ── Debug events ────────────────────────────────────────────────────

/// Debug event types matching C `enum debug_event_type` (intf.h:44-48).
#[repr(u32)]
#[derive(Clone, Copy)]
enum DebugEventType {
    CgroupInit = 0,
    InitTask = 1,
    CgroupExit = 2,
}

/// Debug event record matching C `struct debug_event` (intf.h:51-66).
///
/// In C this is a discriminated union. Here we flatten the union to the
/// largest variant (init_task: cgid + pid = 12 bytes) since the BPF
/// verifier needs a fixed-size type in the array map.
#[repr(C)]
#[derive(Clone, Copy)]
struct DebugEvent {
    timestamp: u64,
    event_type: u32,
    /// Union field 1: cgid (used by all event types).
    cgid: u64,
    /// Union field 2: pid (only used by InitTask).
    pid: u32,
    _pad: u32,
}

impl DebugEvent {
    const ZERO: Self = Self {
        timestamp: 0,
        event_type: 0,
        cgid: 0,
        pid: 0,
        _pad: 0,
    };
}

// PORT_TODO: cell_cpumask_wrapper uses placeholder u64 fields instead of
// bpf_cpumask __kptr. Blocked on kptr support in aya.
// See C source mitosis.bpf.c:321-328

// ── BPF maps ──────────────────────────────────────────────────────────

scx_ebpf::bpf_map!(TASK_CTX: TaskStorage<TaskCtx> = TaskStorage::new());
scx_ebpf::bpf_map!(CPU_CTX: PerCpuArray<CpuCtx, 1> = PerCpuArray::new());
scx_ebpf::bpf_map!(CELLS: BpfArray<Cell, { MAX_CELLS as usize }> = BpfArray::new());
scx_ebpf::bpf_map!(DEBUG_EVENTS: BpfArray<DebugEvent, { DEBUG_EVENTS_BUF_SIZE as usize }> = BpfArray::new());

scx_ebpf::bpf_map!(CGRP_CTX: CgrpStorage<CgrpCtx> = CgrpStorage::new());

/// Timer map value wrapper for the periodic reconfiguration timer.
///
/// The kernel requires the timer field to have BTF type name `bpf_timer`.
/// The `BpfTimer` type alias resolves to `struct bpf_timer` in BTF.
///
/// C reference: `struct update_timer { struct bpf_timer timer; };`
/// See C source mitosis.bpf.c:76-78
#[repr(C)]
#[derive(Clone, Copy)]
struct UpdateTimer {
    timer: BpfTimer,
}

scx_ebpf::bpf_map!(UPDATE_TIMER: BpfArray<UpdateTimer, 1> = BpfArray::new());

/// Per-cell cpumask storage with double-buffer for lock-free updates.
#[repr(C)]
struct CellCpumaskWrapper {
    cpumask: Kptr<bpf_cpumask>,
    tmp_cpumask: Kptr<bpf_cpumask>,
}

scx_ebpf::bpf_map!(CELL_CPUMASKS: BpfArray<CellCpumaskWrapper, { MAX_CELLS as usize }> = BpfArray::new());

// ── Globals ───────────────────────────────────────────────────────────

// Const volatile globals set by userspace before load (rodata section).
scx_ebpf::bpf_global!(NR_LLC: u32 = 1);
scx_ebpf::bpf_global!(ENABLE_LLC_AWARENESS: bool = false);
scx_ebpf::bpf_global!(ENABLE_WORK_STEALING: bool = false);
scx_ebpf::bpf_global!(SLICE_NS: u64 = 20_000_000); // 20ms default
scx_ebpf::bpf_global!(SMT_ENABLED: bool = true);
scx_ebpf::bpf_global!(NR_POSSIBLE_CPUS: u32 = 1);
scx_ebpf::bpf_global!(ROOT_CGID: u64 = 1);
scx_ebpf::bpf_global!(DEBUG_EVENTS_ENABLED: bool = false);
scx_ebpf::bpf_global!(EXITING_TASK_WORKAROUND_ENABLED: bool = true);
scx_ebpf::bpf_global!(CPU_CONTROLLER_DISABLED: bool = false);
scx_ebpf::bpf_global!(REJECT_MULTICPU_PINNING: bool = false);

// All-CPUs bitmask (one bit per CPU, supports up to 512 CPUs).
scx_ebpf::bpf_global_array!(ALL_CPUS: [u8; MAX_CPUS_U8] = [0u8; MAX_CPUS_U8]);

// LLC topology arrays, populated by userspace before load.
scx_ebpf::bpf_global_array!(CPU_TO_LLC: [u32; { MAX_CPUS as usize }] = [0u32; { MAX_CPUS as usize }]);
// PORT_TODO: LLC_TO_CPUS needs LlcCpumask which is large (128*8 = 1024 bytes per entry).
// bpf_global_array doesn't support custom struct values. Need a BpfArray map instead,
// or flatten to [u64; MAX_LLCS * CPUMASK_LONG_ENTRIES].
// See C source mitosis.bpf.c:54

// Mutable globals (bss section — writable at runtime).
// These use raw statics since bpf_global! generates const-section globals.
// In BPF, the linker places non-const statics in .bss which is mutable.
#[unsafe(no_mangle)]
static mut CONFIGURATION_SEQ: u32 = 0;
#[unsafe(no_mangle)]
static mut APPLIED_CONFIGURATION_SEQ: u32 = 0;
#[unsafe(no_mangle)]
static mut DEBUG_EVENT_POS: u32 = 0;

/// Global cpumask containing all possible CPUs. Built from ALL_CPUS[]
/// in init(). Read under RCU lock.
#[unsafe(no_mangle)]
static mut ALL_CPUMASK: Kptr<bpf_cpumask> = Kptr::zeroed();

/// When LLC awareness is disabled, use a single "fake" LLC index to flatten
/// the entire cell's topology into one scheduling domain.
const FAKE_FLAT_CELL_LLC: u32 = 0;

/// SCX_PICK_IDLE_CORE flag for pick_idle_cpu.
const SCX_PICK_IDLE_CORE: u64 = 1;

/// SCX_KICK_IDLE flag for kick_cpu.
const SCX_KICK_IDLE: u64 = 1;

/// SCX_ENQ_CPU_SELECTED flag — set when select_cpu already picked a CPU.
const SCX_ENQ_CPU_SELECTED: u64 = 1 << 52;

// PORT_TODO: Missing kptr globals — see C source mitosis.bpf.c:87-88
// - all_cpumask: bpf_cpumask __kptr — all-CPUs mask, needs kptr support in aya
// - root_cgrp: cgroup __kptr — acquired reference to root cgroup

// PORT_TODO: Missing UEI (User Exit Info) — see C source mitosis.bpf.c:90
// - UEI_DEFINE(uei) — enables structured exit reporting to userspace

/// Level-cell tracker: records the cell ID at each cgroup hierarchy level
/// during the pre-order cgroup tree walk in `update_timer_cb`.
/// Parents are visited before children, so `level_cells[level-1]` gives
/// the parent's cell when processing a child at `level`.
/// See C source mitosis.bpf.c:967.
#[unsafe(no_mangle)]
static mut LEVEL_CELLS: [u32; MAX_CG_DEPTH] = [0u32; MAX_CG_DEPTH];

// ── Helper functions ──────────────────────────────────────────────────

/// Look up a cell by index.
#[inline(always)]
fn lookup_cell(idx: u32) -> Option<&'static mut Cell> {
    CELLS.get_mut(idx)
}

/// Look up the per-task context from task storage.
#[inline(always)]
fn lookup_task_ctx(p: *mut task_struct) -> Option<&'static mut TaskCtx> {
    TASK_CTX.get_mut(p as *mut u8)
}

/// Look up CPU context. `cpu < 0` means current CPU.
#[inline(always)]
fn lookup_cpu_ctx(cpu: i32) -> Option<&'static mut CpuCtx> {
    if cpu < 0 {
        CPU_CTX.get_mut(0)
    } else {
        // PORT_TODO: Use PerCpuArray::get_percpu(0, cpu) for specific CPU.
        // Currently get_percpu returns Option<&V> (immutable). For now,
        // only current-CPU lookups are used correctly in the hot path.
        CPU_CTX.get_mut(0)
    }
}

/// Signed 64-bit time comparison (handles wrapping).
/// Returns true if `a` is before `b` in the vtime timeline.
#[inline(always)]
fn time_before(a: u64, b: u64) -> bool {
    (a as i64).wrapping_sub(b as i64) < 0
}

/// Returns true if `a` is after `b` in the vtime timeline.
#[inline(always)]
fn time_after(a: u64, b: u64) -> bool {
    (a as i64).wrapping_sub(b as i64) > 0
}

/// Advance CPU and cell DSQ vtime watermarks to keep in sync with task vtime.
///
/// Mirrors C advance_dsq_vtimes() — see mitosis.bpf.c:1231-1254.
#[inline(always)]
fn advance_dsq_vtimes(cell: &mut Cell, cctx: &mut CpuCtx, tctx: &TaskCtx, task_vtime: u64) {
    // Advance per-CPU vtime
    if time_before(cctx.vtime_now, task_vtime) {
        cctx.vtime_now = task_vtime;
    }

    if !ENABLE_LLC_AWARENESS.get() {
        // Advance the flat cell DSQ vtime
        if time_before(cell.llcs[FAKE_FLAT_CELL_LLC as usize].vtime_now, task_vtime) {
            cell.llcs[FAKE_FLAT_CELL_LLC as usize].vtime_now = task_vtime;
        }
        return;
    }

    // LLC-aware: advance the task's LLC vtime
    let llc = tctx.llc;
    if llc >= 0 && (llc as u32) < MAX_LLCS {
        if time_before(cell.llcs[llc as usize].vtime_now, task_vtime) {
            cell.llcs[llc as usize].vtime_now = task_vtime;
        }
    }
}

/// Look up a cgroup ancestor at the given hierarchy level.
/// Returns null on failure. Caller must release the returned reference.
/// See C source mitosis.bpf.c:102-114.
#[inline(always)]
fn lookup_cgrp_ancestor(cgrp: *mut cgroup, level: i32) -> *mut cgroup {
    let cg = scx_ebpf::cgroup::ancestor(cgrp, level);
    if cg.is_null() {
        scx_ebpf::scx_bpf_error!("mitosis: failed to get ancestor level");
    }
    cg
}

/// Look up cgrp_ctx for a cgroup (returns None if not found, no error).
/// See C source mitosis.bpf.c:123-132.
#[inline(always)]
fn lookup_cgrp_ctx_fallible(cgrp: *mut cgroup) -> Option<&'static mut CgrpCtx> {
    CGRP_CTX.get_mut(cgrp as *mut u8)
}

/// Look up cgrp_ctx for a cgroup (errors on failure).
/// See C source mitosis.bpf.c:134-143.
#[inline(always)]
fn lookup_cgrp_ctx(cgrp: *mut cgroup) -> Option<&'static mut CgrpCtx> {
    let cgc = CGRP_CTX.get_mut(cgrp as *mut u8);
    if cgc.is_none() {
        scx_ebpf::scx_bpf_error!("mitosis: cgrp_ctx lookup failed");
    }
    cgc
}

// PORT_TODO: Missing task_cgroup(p) — gets task's cgroup, handling cpu_controller_disabled
// mode (reads p->cgroups->dfl_cgrp under RCU). See C source mitosis.bpf.c:145-169
// For now, cgroup callbacks receive the cgroup directly from the kernel.

/// Allocate a free cell from the cell pool.
///
/// Uses the cell's BPF spin lock to atomically check and set `in_use`.
/// The C version uses `__sync_bool_compare_and_swap` (lock-free atomic CAS)
/// which maps to `BPF_ATOMIC | BPF_CMPXCHG`. We use spin_lock instead
/// because Rust BPF doesn't yet emit atomic CAS instructions.
///
/// See C source mitosis.bpf.c:219-235.
#[inline(always)]
fn allocate_cell() -> i32 {
    // Linear scan for a free cell
    let mut cell_idx: u32 = 0;
    while cell_idx < MAX_CELLS {
        if let Some(c) = lookup_cell(cell_idx) {
            // Acquire spin lock for atomic check-and-set of in_use.
            // PORT_TODO: Replace with BPF atomic CAS (__sync_bool_compare_and_swap)
            // once aya-ebpf supports emitting BPF_ATOMIC|BPF_CMPXCHG instructions.
            // The spin lock approach works but is heavier than the C version's
            // lock-free CAS. Note: spin_lock/unlock on map values has verifier
            // restrictions — we must not call most helpers while holding it.
            let lock_ptr = &c.lock as *const BpfSpinLock as *mut BpfSpinLock;
            scx_ebpf::helpers::spin_lock(lock_ptr);
            let was_free = c.in_use == 0;
            if was_free {
                c.in_use = 1;
            }
            scx_ebpf::helpers::spin_unlock(lock_ptr);

            if was_free {
                // zero_cell_vtimes AFTER releasing lock — it accesses the cell
                // but doesn't need the lock since no other CPU can claim this cell.
                zero_cell_vtimes(c);
                return cell_idx as i32;
            }
        }
        cell_idx += 1;
    }
    scx_ebpf::scx_bpf_error!("mitosis: no available cells to allocate");
    -1
}

/// Free a cell back to the pool.
/// See C source mitosis.bpf.c:237-251.
#[inline(always)]
fn free_cell(cell_idx: i32) -> i32 {
    if cell_idx < 0 || cell_idx >= MAX_CELLS as i32 {
        return -1;
    }
    if let Some(c) = lookup_cell(cell_idx as u32) {
        c.in_use = 0;
        0
    } else {
        -1
    }
}

/// Record a cgroup_init debug event. See C source mitosis.bpf.c:256-274.
#[inline(always)]
fn record_cgroup_init(cgid: u64) {
    if !DEBUG_EVENTS_ENABLED.get() {
        return;
    }
    let pos = unsafe {
        let p = DEBUG_EVENT_POS;
        DEBUG_EVENT_POS = p.wrapping_add(1);
        p
    };
    let idx = pos % DEBUG_EVENTS_BUF_SIZE;
    if let Some(event) = DEBUG_EVENTS.get_mut(idx) {
        event.timestamp = kfuncs::now();
        event.event_type = DebugEventType::CgroupInit as u32;
        event.cgid = cgid;
        event.pid = 0;
    }
}

/// Record an init_task debug event. See C source mitosis.bpf.c:276-295.
#[inline(always)]
fn record_init_task(cgid: u64, pid: u32) {
    if !DEBUG_EVENTS_ENABLED.get() {
        return;
    }
    let pos = unsafe {
        let p = DEBUG_EVENT_POS;
        DEBUG_EVENT_POS = p.wrapping_add(1);
        p
    };
    let idx = pos % DEBUG_EVENTS_BUF_SIZE;
    if let Some(event) = DEBUG_EVENTS.get_mut(idx) {
        event.timestamp = kfuncs::now();
        event.event_type = DebugEventType::InitTask as u32;
        event.cgid = cgid;
        event.pid = pid;
    }
}

/// Record a cgroup_exit debug event. See C source mitosis.bpf.c:297-315.
#[inline(always)]
fn record_cgroup_exit(cgid: u64) {
    if !DEBUG_EVENTS_ENABLED.get() {
        return;
    }
    let pos = unsafe {
        let p = DEBUG_EVENT_POS;
        DEBUG_EVENT_POS = p.wrapping_add(1);
        p
    };
    let idx = pos % DEBUG_EVENTS_BUF_SIZE;
    if let Some(event) = DEBUG_EVENTS.get_mut(idx) {
        event.timestamp = kfuncs::now();
        event.event_type = DebugEventType::CgroupExit as u32;
        event.cgid = cgid;
        event.pid = 0;
    }
}

/// Look up a cell's cpumask (RCU-protected kptr read).
/// Returns a raw pointer valid within the current RCU critical section.
/// Port of C lookup_cell_cpumask (mitosis.bpf.c:338-353).
#[inline(always)]
fn lookup_cell_cpumask(idx: u32) -> *const vmlinux::cpumask {
    let wrapper = CELL_CPUMASKS.get_ptr_mut(idx);
    if wrapper.is_null() {
        return core::ptr::null();
    }
    let w = unsafe { &*wrapper };
    let mask = unsafe { Kptr::get(&raw const w.cpumask) };
    if mask.is_null() {
        return core::ptr::null();
    }
    cpumask::cast(mask) as *const vmlinux::cpumask
}
/// Increment a per-cell statistic counter.
///
/// Mirrors C cstat_inc() — see mitosis.bpf.c:369-372.
/// Bounds-checks cell and stat indices to satisfy the BPF verifier.
#[inline(always)]
fn cstat_inc(idx: CellStat, cell: u32, cctx: &mut CpuCtx) {
    if (cell as usize) < MAX_CELLS as usize && (idx as usize) < NR_CSTATS {
        cctx.cstats[cell as usize][idx as usize] += 1;
    }
}

// PORT_TODO: Missing update_task_cpumask(p, tctx) — intersects cell cpumask with task
// affinity, handles per-CPU pinning vs cell-wide path vs LLC-aware path, sets tctx->dsq
// and p->scx.dsq_vtime. Blocked on cell cpumask kptrs. See C source mitosis.bpf.c:374-450

/// Update a task's cell assignment based on its cgroup's cell.
///
/// Port of C update_task_cell (mitosis.bpf.c:456-503):
/// - Reads cgrp_ctx->cell from the task's cgroup
/// - Handles exiting_task_workaround (dying cgroups → root cell)
/// - Syncs configuration_seq to prevent redundant refreshes
/// - Calls update_task_cpumask to recalculate DSQ assignment
///
/// PORT_TODO: `update_task_cpumask` is stubbed (needs cell cpumask kptrs).
/// Currently just assigns the cell and DSQ without cpumask intersection.
#[inline(always)]
fn update_task_cell(p: *mut task_struct, tctx: &mut TaskCtx, cgrp: *mut cgroup) {
    if cgrp.is_null() {
        return;
    }

    let cgrp_ctx = match lookup_cgrp_ctx_fallible(cgrp) {
        Some(ctx) => ctx,
        None => {
            // Dying cgroup with no storage — assign to root cell
            if EXITING_TASK_WORKAROUND_ENABLED.get() {
                tctx.cell = ROOT_CELL_ID;
                tctx.dsq = DsqId::cell_llc(ROOT_CELL_ID, FAKE_FLAT_CELL_LLC);
            }
            return;
        }
    };

    let cell = unsafe { core::ptr::read_volatile(&cgrp_ctx.cell) };
    tctx.cell = cell;

    // Sync configuration_seq to mark this task as up-to-date
    let cur_seq = unsafe { core::ptr::read_volatile(&raw const APPLIED_CONFIGURATION_SEQ) };
    tctx.configuration_seq = cur_seq;

    // Record cgroup ID for detecting cgroup moves when cpu_controller_disabled
    if let Ok(kn) = core_read!(vmlinux::cgroup, cgrp, kn) {
        if let Ok(id) = core_read!(vmlinux::kernfs_node, kn, id) {
            tctx.cgid = id;
        }
    }

    // PORT_TODO: update_task_cpumask(p, tctx) — intersect cell cpumask with task
    // affinity, set tctx->dsq properly. For now, assign to the cell's flat DSQ.
    let llc = if ENABLE_LLC_AWARENESS.get() {
        // Use task's current LLC or fallback to 0
        if tctx.llc >= 0 { tctx.llc as u32 } else { 0 }
    } else {
        FAKE_FLAT_CELL_LLC
    };
    tctx.dsq = DsqId::cell_llc(cell, llc);
}

/// Refresh a task's cell assignment by looking up its cgroup.
///
/// Port of C refresh_task_cell (mitosis.bpf.c:508-515).
///
/// PORT_TODO: Needs task_cgroup() helper (reading p->cgroups->dfl_cgrp
/// under RCU). For now, uses scx_bpf_task_cgroup kfunc which requires
/// the CPU controller to be enabled.
#[inline(always)]
fn refresh_task_cell(p: *mut task_struct, tctx: &mut TaskCtx) {
    let cgrp = kfuncs::task_cgroup(p);
    if !cgrp.is_null() {
        update_task_cell(p, tctx, cgrp);
    }
}

/// Check if a task's cell assignment needs refreshing and do so if stale.
///
/// Port of C maybe_refresh_cell (mitosis.bpf.c:547-571):
/// - Compares task's configuration_seq to applied_configuration_seq
/// - When they differ, refresh via cgroup lookup
/// - Also handles cpu_controller_disabled cgroup move detection (cgid change)
#[inline(always)]
fn maybe_refresh_cell(p: *mut task_struct, tctx: &mut TaskCtx) {
    let applied_seq = unsafe { core::ptr::read_volatile(&raw const APPLIED_CONFIGURATION_SEQ) };

    if tctx.configuration_seq != applied_seq {
        refresh_task_cell(p, tctx);
        return;
    }

    // When CPU controller is disabled, detect cgroup moves by checking
    // if the task's cgroup ID has changed since last refresh.
    if CPU_CONTROLLER_DISABLED.get() {
        let cgrp = kfuncs::task_cgroup(p);
        if !cgrp.is_null() {
            if let Ok(kn) = core_read!(vmlinux::cgroup, cgrp, kn) {
                if let Ok(id) = core_read!(vmlinux::kernfs_node, kn, id) {
                    if id != tctx.cgid {
                        update_task_cell(p, tctx, cgrp);
                    }
                }
            }
        }
    }
}

// PORT_TODO: Missing pick_idle_cpu(p, prev_cpu, cctx, tctx) — gets task cpumask and idle
// SMT mask, calls pick_idle_cpu_from. Blocked on cell cpumask kptrs. See C source mitosis.bpf.c:573-599

// ── Cpumask scratch allocation ────────────────────────────────────────

/// Scratch buffer for reading cgroup cpusets.
///
/// Port of C struct cpumask_entry (mitosis.bpf.c:847-850).
/// Used as per-CPU scratch space during cgroup tree walks.
#[repr(C)]
struct CpumaskEntry {
    /// The cpumask read from a cgroup's cpuset.
    cpumask: [u64; CPUMASK_LONG_ENTRIES],
    /// Whether this entry is currently in use (atomic CAS guard).
    used: u32,
    _pad: u32,
}

const MAX_CPUMASK_ENTRIES: u32 = 4;

scx_ebpf::bpf_map!(CGRP_INIT_PERCPU_CPUMASK: PerCpuArray<CpumaskEntry, { MAX_CPUMASK_ENTRIES as usize }> = PerCpuArray::new());

/// Allocate a scratch cpumask entry from the per-CPU pool.
///
/// Port of C allocate_cpumask_entry (mitosis.bpf.c:859-875).
/// Uses compare-and-swap on the `used` field for lock-free allocation.
///
/// PORT_TODO: Proper atomic CAS (__sync_bool_compare_and_swap) not available
/// in Rust BPF. Using volatile read + write which has a TOCTOU race but is
/// acceptable for scratch buffers in single-CPU contexts (timer callbacks).
#[inline(always)]
fn allocate_cpumask_entry() -> Option<&'static mut CpumaskEntry> {
    let mut idx: u32 = 0;
    while idx < MAX_CPUMASK_ENTRIES {
        if let Some(ent) = CGRP_INIT_PERCPU_CPUMASK.get_mut(idx) {
            let was_used = unsafe { core::ptr::read_volatile(&ent.used) };
            if was_used == 0 {
                unsafe { core::ptr::write_volatile(&mut ent.used, 1) };
                return Some(ent);
            }
        }
        idx += 1;
    }
    None
}

/// Free a scratch cpumask entry.
///
/// Port of C free_cpumask_entry (mitosis.bpf.c:877-884).
#[inline(always)]
fn free_cpumask_entry(entry: &mut CpumaskEntry) {
    unsafe { core::ptr::write_volatile(&mut entry.used, 0) };
}

/// Check if a cgroup has a non-trivial cpuset mask and read it.
///
/// Port of C get_cgroup_cpumask (mitosis.bpf.c:905-961).
///
/// Returns:
/// -  1 = cgroup has a cpuset with a CPU restriction (mask written to entry)
/// -  0 = no cpuset or cpuset covers all CPUs (no restriction)
/// - <0 = error
///
/// PORT_TODO(aya-33): This requires CO-RE introspection that isn't available
/// in pure Rust BPF:
/// - `cgrp->subsys[cpuset_cgrp_id]` — array index on kernel struct
/// - `container_of(css, struct cpuset, css)` — CO-RE container_of
/// - `bpf_core_type_matches(struct cpuset___cpumask_arr)` — type matching
/// - `bpf_core_read(&entry->cpumask, ..., &cpuset->cpus_allowed)` — flexible read
///
/// For now, this always returns 0 (no cpuset), meaning all cgroups get the
/// root cell. Cpuset-based cell allocation will require either:
/// 1. vmlinux bindgen with cpuset struct definition, or
/// 2. A helper BPF program written in C that exposes cpuset reads
#[inline(always)]
fn get_cgroup_cpumask(_cgrp: *mut cgroup, _entry: &mut CpumaskEntry) -> i32 {
    // PORT_TODO(aya-33): Implement cpuset introspection.
    // The C version reads cgrp->subsys[cpuset_cgrp_id]->cpuset->cpus_allowed
    // using bpf_core_type_matches to handle different kernel cpuset layouts.
    // Without CO-RE type matching in Rust BPF, we cannot safely read cpuset data.
    0 // No cpuset restriction detected
}

// ── Timer callback: cgroup walker / cell reconfiguration ──────────────

/// Periodic timer callback that walks the cgroup hierarchy and
/// reconfigures cell↔CPU assignments based on cpuset changes.
///
/// Port of C update_timer_cb (mitosis.bpf.c:972-1229).
///
/// This is the heart of MITOSIS's dynamic reconfiguration:
/// 1. Check if configuration_seq changed (someone bumped it)
/// 2. Walk cgroup tree (pre-order DFS)
/// 3. For each cgroup with a cpuset, allocate a cell and assign CPUs
/// 4. Root cell gets leftover CPUs
/// 5. Update applied_configuration_seq
///
/// PORT_TODO(bpf_for_each css): `bpf_for_each(css, pos, root_css,
/// BPF_CGROUP_ITER_DESCENDANTS_PRE)` is a C macro that expands to
/// `bpf_for_each_css_task` open-coded iterator. This has no Rust equivalent.
/// The cgroup walk is stubbed with a bounded loop and PORT_TODO.
///
/// PORT_TODO(kptr): Cell cpumask updates use bpf_kptr_xchg for lock-free
/// double-buffer swaps. Not available in aya.
#[inline(always)]
fn update_timer_cb() -> i32 {
    // ── Step 1: Check if configuration changed ────────────────────
    let local_configuration_seq = unsafe {
        core::ptr::read_volatile(&raw const CONFIGURATION_SEQ)
    };
    let applied_seq = unsafe {
        core::ptr::read_volatile(&raw const APPLIED_CONFIGURATION_SEQ)
    };
    if local_configuration_seq == applied_seq {
        return 0; // Nothing changed
    }

    // ── Step 2: Allocate scratch cpumask ──────────────────────────
    let entry = match allocate_cpumask_entry() {
        Some(e) => e as *mut CpumaskEntry,
        None => return 0,
    };

    // ── Step 3: Initialize root cell's cpumask to all CPUs ───────
    //
    // PORT_TODO(kptr): The C version does:
    //   root_bpf_cpumask = bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask, NULL);
    //   bpf_cpumask_copy(root_bpf_cpumask, all_cpumask);
    // We can't do kptr_xchg. Instead, we track CPU assignments via
    // cpu_ctx.cell and rebuild from there.

    // Reset all CPU assignments to root cell (cell 0)
    let nr_cpus = NR_POSSIBLE_CPUS.get();
    let mut cpu_idx: u32 = 0;
    while cpu_idx < nr_cpus && cpu_idx < MAX_CPUS {
        if let Some(cctx) = lookup_cpu_ctx(cpu_idx as i32) {
            cctx.cell = ROOT_CELL_ID;
        }
        cpu_idx += 1;
    }

    // Initialize level_cells[0] = root cell
    unsafe {
        core::ptr::write_volatile(&mut LEVEL_CELLS[0], ROOT_CELL_ID);
    }

    // ── Step 4: Walk cgroup tree (pre-order DFS) ─────────────────
    //
    // PORT_TODO(bpf_for_each css): The C version iterates the cgroup
    // hierarchy with:
    //   bpf_for_each(css, pos, root_css, BPF_CGROUP_ITER_DESCENDANTS_PRE)
    //
    // This is an open-coded iterator that the BPF verifier understands.
    // There is no Rust equivalent. When aya adds support for open-coded
    // iterators (or we use a C shim), this section should iterate all
    // descendant cgroups and:
    //
    // For each cgroup `cur_cgrp` at depth `level`:
    //   1. Look up cgrp_ctx (fallible — dying cgroups may lack storage)
    //   2. Call get_cgroup_cpumask(cur_cgrp, entry)
    //   3. If no cpuset (rc == 0):
    //      - Inherit parent's cell: cgrp_ctx.cell = level_cells[level - 1]
    //      - Record: level_cells[level] = cgrp_ctx.cell
    //   4. If cpuset found (rc == 1):
    //      - Allocate a cell if cgrp_ctx is not already a cell_owner
    //      - Copy cpuset mask to cell's cpumask (kptr_xchg double buffer)
    //      - For each CPU in cpuset: cpu_ctx.cell = cell_idx
    //      - Remove those CPUs from root cell's cpumask
    //      - If LLC-aware: recalc_cell_llc_counts
    //      - Record: level_cells[level] = cell_idx
    //      - Write cgrp_ctx.cell = cell_idx
    //
    // For now, without cgroup iteration, all cgroups stay in the root cell.
    // The configuration_seq mechanism still works — tasks will refresh
    // their cell assignment via maybe_refresh_cell → lookup cgrp_ctx.

    // ── Step 5: Assign leftover CPUs to root cell ────────────────
    //
    // After the cgroup walk, any CPUs not claimed by a cpuset-bearing
    // cgroup belong to the root cell. Since we reset all CPUs to root
    // in step 3 and the cgroup walk (step 4) is currently stubbed,
    // all CPUs remain in the root cell.
    //
    // PORT_TODO(kptr): The C version updates root cell's kptr cpumask:
    //   root_bpf_cpumask = bpf_kptr_xchg(&root_cell_cpumaskw->cpumask, root_bpf_cpumask);
    //   bpf_kptr_xchg(&root_cell_cpumaskw->tmp_cpumask, root_bpf_cpumask);

    // Update root cell CPU count
    if let Some(root_cell) = lookup_cell(ROOT_CELL_ID) {
        let mut count: u32 = 0;
        let mut cpu: u32 = 0;
        while cpu < nr_cpus && cpu < MAX_CPUS {
            if let Some(cctx) = lookup_cpu_ctx(cpu as i32) {
                if cctx.cell == ROOT_CELL_ID {
                    count += 1;
                }
            }
            cpu += 1;
        }
        root_cell.cpu_cnt = count;
    }

    // ── Step 6: Recalc LLC counts for root cell ──────────────────
    //
    // PORT_TODO(kptr): recalc_cell_llc_counts needs cell cpumask kptr.
    // Stubbed for now.

    // ── Step 7: Publish applied_configuration_seq ────────────────
    //
    // barrier() equivalent: volatile write ensures ordering.
    // Tasks checking maybe_refresh_cell will see the new seq and
    // re-read their cgrp_ctx.cell.
    unsafe {
        core::ptr::write_volatile(&raw mut APPLIED_CONFIGURATION_SEQ, local_configuration_seq);
    }

    // Free scratch cpumask
    unsafe { free_cpumask_entry(&mut *entry) };

    0
}

/// Validate configuration flags. See C source mitosis.bpf.c:1561-1579.
#[inline(always)]
fn validate_flags() -> i32 {
    let nr_llc = NR_LLC.get();
    if ENABLE_LLC_AWARENESS.get() && (nr_llc < 1 || nr_llc > MAX_LLCS) {
        return -22; // -EINVAL
    }
    if ENABLE_WORK_STEALING.get() && !ENABLE_LLC_AWARENESS.get() {
        return -22; // -EINVAL
    }
    0
}

/// Validate data populated by userspace. See C source mitosis.bpf.c:1581-1589.
#[inline(always)]
fn validate_userspace_data() -> i32 {
    if NR_POSSIBLE_CPUS.get() > MAX_CPUS {
        return -22; // -EINVAL
    }
    0
}

/// Zero vtime_now for all LLCs in a cell.
/// See C source llc_aware.bpf.h:191-202.
#[inline(always)]
fn zero_cell_vtimes(cell: &mut Cell) {
    if ENABLE_LLC_AWARENESS.get() {
        for i in 0..(MAX_LLCS as usize) {
            cell.llcs[i].vtime_now = 0;
        }
    } else {
        cell.llcs[FAKE_FLAT_CELL_LLC as usize].vtime_now = 0;
    }
}

/// Check if an LLC ID is valid.
/// See C source llc_aware.bpf.h:28-34.
#[inline(always)]
fn llc_is_valid(llc_id: u32) -> bool {
    llc_id != u32::MAX && llc_id < MAX_LLCS
}

/// Initialize task LLC fields.
/// See C source llc_aware.bpf.h:36-45.
#[inline(always)]
fn init_task_llc(tctx: &mut TaskCtx) {
    tctx.llc = -1; // LLC_INVALID = ~0u32 as i32
    if ENABLE_WORK_STEALING.get() {
        tctx.steal_count = 0;
        tctx.last_stolen_at = 0;
    }
}

/// BPF timer callback — invoked by the kernel timer subsystem.
///
/// Signature: `fn(map: *mut c_void, key: *mut i32, timer: *mut BpfTimer) -> i32`
/// Registered via `bpf_timer_set_callback` in `mitosis_init`.
/// Calls `update_timer_cb()` and re-arms the timer.
fn update_timer_fn(
    _map: *mut core::ffi::c_void,
    _key: *mut i32,
    timer_ptr: *mut BpfTimer,
) -> i32 {
    timer::timer_start(timer_ptr, TIMER_INTERVAL_NS, 0);
    update_timer_cb();
    0
}

// === LLC-aware helpers (from llc_aware.bpf.h) ===

/// Recompute per-LLC CPU counts within a cell.
///
/// Port of C recalc_cell_llc_counts (llc_aware.bpf.h:65-123).
/// Without cell cpumask kptrs, uses cpu_ctx.cell + CPU_TO_LLC to count.
#[inline(always)]
fn recalc_cell_llc_counts(cell_idx: u32) {
    let cell = match lookup_cell(cell_idx) {
        Some(c) => c,
        None => return,
    };

    let nr_llc = NR_LLC.get();
    let nr_cpus = NR_POSSIBLE_CPUS.get();
    let mut llc_cpu_cnt = [0u32; MAX_LLCS as usize];
    let mut total_cpus = 0u32;
    let mut llcs_present = 0u32;

    // PORT_TODO: The C version uses cell cpumask kptrs with bpf_cpumask_and.
    // Our fallback reads cpu_ctx.cell via get_percpu for each CPU.
    let mut cpu: u32 = 0;
    while cpu < nr_cpus && cpu < MAX_CPUS {
        if let Some(cctx) = CPU_CTX.get_percpu(0, cpu) {
            if cctx.cell == cell_idx {
                if let Some(llc) = CPU_TO_LLC.get(cpu as usize) {
                    if llc < nr_llc && llc < MAX_LLCS {
                        llc_cpu_cnt[llc as usize] += 1;
                        total_cpus += 1;
                    }
                }
            }
        }
        cpu += 1;
    }

    let mut i: u32 = 0;
    while i < nr_llc && i < MAX_LLCS {
        if llc_cpu_cnt[i as usize] > 0 {
            llcs_present += 1;
        }
        i += 1;
    }

    // Write LLC counts under spin lock to protect concurrent readers.
    let lock_ptr = &cell.lock as *const BpfSpinLock as *mut BpfSpinLock;
    scx_ebpf::helpers::spin_lock(lock_ptr);
    i = 0;
    while i < nr_llc && i < MAX_LLCS {
        cell.llcs[i as usize].cpu_cnt = llc_cpu_cnt[i as usize];
        i += 1;
    }
    cell.llc_present_cnt = llcs_present;
    cell.cpu_cnt = total_cpus;
    scx_ebpf::helpers::spin_unlock(lock_ptr);
}

/// Weighted random LLC selection for a task.
///
/// Port of C pick_llc_for_task (llc_aware.bpf.h:135-189).
/// P(LLC) proportional to number of CPUs in that LLC within the cell.
/// Returns LLC ID on success, -1 on error.
#[inline(always)]
fn pick_llc_for_task(cell_id: u32) -> i32 {
    let cell = match lookup_cell(cell_id) {
        Some(c) => c,
        None => return -1,
    };

    let nr_llc = NR_LLC.get();
    let mut llc_cpu_cnt = [0u32; MAX_LLCS as usize];
    let mut total_cpu_cnt = 0u32;

    // Read LLC cpu counts under spin lock for consistency.
    let lock_ptr = &cell.lock as *const BpfSpinLock as *mut BpfSpinLock;
    scx_ebpf::helpers::spin_lock(lock_ptr);
    let mut i: u32 = 0;
    while i < nr_llc && i < MAX_LLCS {
        llc_cpu_cnt[i as usize] = cell.llcs[i as usize].cpu_cnt;
        total_cpu_cnt += llc_cpu_cnt[i as usize];
        i += 1;
    }
    scx_ebpf::helpers::spin_unlock(lock_ptr);

    if total_cpu_cnt == 0 {
        return -1;
    }

    let target = scx_ebpf::helpers::get_prandom_u32() % total_cpu_cnt;
    let mut cur = 0u32;

    i = 0;
    while i < nr_llc && i < MAX_LLCS {
        cur += llc_cpu_cnt[i as usize];
        if target < cur {
            return i as i32;
        }
        i += 1;
    }

    -1
}

/// Detect and handle cross-LLC task migration (work stealing).
///
/// Port of C maybe_retag_stolen_task (llc_aware.bpf.h:211-231).
/// Called from running() when LLC-aware + work stealing is enabled.
#[inline(always)]
fn maybe_retag_stolen_task(
    _p: *mut task_struct,
    tctx: &mut TaskCtx,
    cctx: &CpuCtx,
) -> i32 {
    if tctx.llc as u32 == cctx.llc {
        return 0;
    }

    tctx.steal_count += 1;
    tctx.last_stolen_at = kfuncs::now();
    tctx.llc = cctx.llc as i32;
    tctx.dsq = DsqId::cell_llc(tctx.cell, cctx.llc);

    // Set vtime baseline from new LLC
    if let Some(cell) = lookup_cell(tctx.cell) {
        if (cctx.llc as usize) < MAX_LLCS as usize {
            tctx.basis_vtime = cell.llcs[cctx.llc as usize].vtime_now;
        }
    }

    // PORT_TODO: Full update_task_cpumask(p, tctx) to narrow cpumask by new LLC.
    // Blocked on cell cpumask kptrs. See C source llc_aware.bpf.h:230.
    0
}

/// Try stealing work from sibling LLC DSQs within the same cell.
///
/// Port of C try_stealing_work (llc_aware.bpf.h:240-301).
/// Returns true if a task was stolen, false otherwise.
#[inline(always)]
fn try_stealing_work(cell_idx: u32, local_llc: u32) -> bool {
    if !llc_is_valid(local_llc) {
        return false;
    }

    let nr_llc = NR_LLC.get();

    let cell_ptr = match lookup_cell(cell_idx) {
        Some(c) => c,
        None => return false,
    };

    let mut i: u32 = 1;
    while i < nr_llc && i < MAX_LLCS {
        let candidate_llc = (local_llc + i) % nr_llc;

        if candidate_llc >= MAX_LLCS {
            i += 1;
            continue;
        }

        // Skip if cell has no CPUs in this LLC
        if cell_ptr.llcs[candidate_llc as usize].cpu_cnt == 0 {
            i += 1;
            continue;
        }

        let candidate_dsq = DsqId::cell_llc(cell_idx, candidate_llc);
        if candidate_dsq.is_invalid() {
            return false;
        }

        // Skip if empty (fast path)
        if kfuncs::dsq_nr_queued(candidate_dsq.raw()) == 0 {
            i += 1;
            continue;
        }

        // Attempt the steal — retag happens in running() via maybe_retag_stolen_task
        if kfuncs::dsq_move_to_local(candidate_dsq.raw()) {
            return true;
        }

        i += 1;
    }

    false
}

// PORT_TODO: Missing update_task_llc_assignment(p, tctx) — picks new LLC, narrows cpumask
// by LLC, sets DSQ and vtime baseline. Blocked on cell cpumask kptrs.
// See C source llc_aware.bpf.h:303-349

// ── Scheduler callbacks ───────────────────────────────────────────────

/// select_cpu: Pick an idle CPU for a waking task.
///
/// Simplified port of C mitosis_select_cpu (mitosis.bpf.c:605-650).
/// Without cell cpumask kptrs, we can't do full cell-aware idle CPU
/// selection. Instead, use the default idle CPU selection and dispatch
/// directly to LOCAL when an idle CPU is found.
///
/// Full C version: refresh cell, pick idle from cell cpumask with SMT
/// awareness, handle per-CPU pinning, fall back to prev_cpu or
/// bpf_cpumask_any_distribute.
fn mitosis_select_cpu(p: *mut task_struct, prev_cpu: i32, _wake_flags: u64) -> i32 {
    // Refresh cell assignment if configuration_seq changed
    if let Some(tctx) = lookup_task_ctx(p) {
        maybe_refresh_cell(p, tctx);
    }

    // PORT_TODO: Full cell-aware idle CPU selection with pick_idle_cpu().
    // Blocked on cell cpumask kptrs. For now, use the default selection.

    // Without cell cpumasks, all tasks are all_cell_cpus_allowed and use
    // the cell+LLC DSQ. Try to find an idle CPU with the default helper.
    let mut is_idle = false;
    let cpu = kfuncs::select_cpu_dfl(p, prev_cpu, 0, &mut is_idle);
    if is_idle {
        let slice = SLICE_NS.get();
        kfuncs::dsq_insert(p, kfuncs::SCX_DSQ_LOCAL, slice, 0);
    }
    cpu
}

/// enqueue: Insert task into its cell's DSQ with vtime ordering.
///
/// Port of C mitosis_enqueue (mitosis.bpf.c:652-749):
/// - Refresh cell assignment via maybe_refresh_cell
/// - Determine target DSQ (per-CPU for pinned tasks, cell+LLC for cell tasks)
/// - Clamp vtime to [basis - slice, basis + 8192*slice] to prevent runaway
/// - Insert with vtime ordering via dsq_insert_vtime
/// - Kick idle CPU if we didn't get one from select_cpu
fn mitosis_enqueue(p: *mut task_struct, enq_flags: u64) {
    let tctx = match lookup_task_ctx(p) {
        Some(t) => t,
        None => return,
    };

    let slice = SLICE_NS.get();

    // Refresh cell assignment if configuration changed
    maybe_refresh_cell(p, tctx);

    // Read vtime AFTER any cell refresh (which might manipulate it)
    let mut vtime = match core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Determine target DSQ and basis_vtime.
    // Without cell cpumasks, all tasks use cell+LLC DSQ for their cell.
    let cell_idx = tctx.cell;

    let cell = match lookup_cell(cell_idx) {
        Some(c) => c,
        None => return,
    };

    let llc = if ENABLE_LLC_AWARENESS.get() {
        let l = tctx.llc;
        if l < 0 || l as u32 >= MAX_LLCS {
            FAKE_FLAT_CELL_LLC
        } else {
            l as u32
        }
    } else {
        FAKE_FLAT_CELL_LLC
    };

    let basis_vtime = cell.llcs[llc as usize].vtime_now;
    let dsq = DsqId::cell_llc(cell_idx, llc);

    tctx.basis_vtime = basis_vtime;

    // Upper vtime clamp: reject tasks with absurdly far-ahead vtime.
    // This catches bugs in vtime accounting that could starve other tasks.
    // Matches C: time_after(vtime, basis_vtime + 8192 * slice_ns) — mitosis.bpf.c:730
    if time_after(vtime, basis_vtime.wrapping_add(8192 * slice)) {
        scx_ebpf::scx_bpf_error!("mitosis: vtime too far ahead");
        // Clamp to prevent starvation.
        vtime = basis_vtime.wrapping_add(8192 * slice);
    }

    // Lower vtime clamp: cap accumulated idle budget to one slice.
    // Matches C: time_before(vtime, basis_vtime - slice_ns) — mitosis.bpf.c:738
    if time_before(vtime, basis_vtime.wrapping_sub(slice)) {
        vtime = basis_vtime.wrapping_sub(slice);
    }

    kfuncs::dsq_insert_vtime(p, dsq.raw(), slice, vtime, enq_flags);

    // If select_cpu didn't pick a CPU, try to kick an idle one
    if enq_flags & SCX_ENQ_CPU_SELECTED == 0 {
        // PORT_TODO: pick_idle_cpu from cell cpumask. For now just kick prev.
        let task_cpu = kfuncs::task_cpu(p);
        if kfuncs::test_and_clear_cpu_idle(task_cpu) {
            kfuncs::kick_cpu(task_cpu, SCX_KICK_IDLE);
        }
    }
}

/// dispatch: Pick the highest-priority task from this CPU's cell DSQs.
///
/// Port of C mitosis_dispatch (mitosis.bpf.c:751-824):
/// - Build cell+LLC DSQ and per-CPU DSQ IDs
/// - Peek both DSQs, dispatch from whichever has the lowest-vtime task
/// - If both empty and LLC-aware + work stealing enabled, try stealing
///   from sibling LLC DSQs within the same cell
fn mitosis_dispatch(cpu: i32, _prev: *mut task_struct) {
    let cctx = match lookup_cpu_ctx(-1) {
        Some(c) => c,
        None => return,
    };

    let cell_idx = cctx.cell;
    let llc = if ENABLE_LLC_AWARENESS.get() { cctx.llc } else { FAKE_FLAT_CELL_LLC };

    let cell_dsq = DsqId::cell_llc(cell_idx, llc);
    let cpu_dsq = DsqId::cpu(cpu as u32);

    if cell_dsq.is_invalid() || cpu_dsq.is_invalid() {
        return;
    }

    // Peek both DSQs to pick the task with the lowest vtime.
    // dsq_peek returns the head task without consuming it (kernel 6.19+).
    // On older kernels the __weak extern returns null — we fall back to
    // cell-first ordering.
    let cell_head = kfuncs::dsq_peek(cell_dsq.raw());
    let cpu_head = kfuncs::dsq_peek(cpu_dsq.raw());

    if !cell_head.is_null() && !cpu_head.is_null() {
        // Both DSQs have tasks — compare vtimes
        let cell_vtime = core_read!(vmlinux::task_struct, cell_head, scx.dsq_vtime)
            .unwrap_or(u64::MAX);
        let cpu_vtime = core_read!(vmlinux::task_struct, cpu_head, scx.dsq_vtime)
            .unwrap_or(u64::MAX);

        if time_before(cpu_vtime, cell_vtime) {
            kfuncs::dsq_move_to_local(cpu_dsq.raw());
            return;
        }
        kfuncs::dsq_move_to_local(cell_dsq.raw());
        return;
    }

    // Only one (or neither) has tasks — try cell first, then CPU
    if kfuncs::dsq_move_to_local(cell_dsq.raw()) {
        return;
    }
    if kfuncs::dsq_move_to_local(cpu_dsq.raw()) {
        return;
    }

    // Both local DSQs empty — try work stealing from sibling LLCs
    if ENABLE_LLC_AWARENESS.get() && ENABLE_WORK_STEALING.get() {
        if try_stealing_work(cell_idx, llc) {
            // Re-borrow cctx since lookup_cell in try_stealing_work may have
            // invalidated the previous reference in the verifier's view.
            if let Some(cctx) = lookup_cpu_ctx(-1) {
                cstat_inc(CellStat::Steal, cell_idx, cctx);
            }
        }
    }
}

/// running: Record task start time for runtime accounting.
///
/// Port of C mitosis_running (mitosis.bpf.c:1256-1272):
/// - Handle stolen task retag (LLC-aware + work stealing mode)
/// - Record scx_bpf_now() as started_running_at
fn mitosis_running(p: *mut task_struct) {
    let tctx = match lookup_task_ctx(p) {
        Some(t) => t,
        None => return,
    };

    // Detect cross-LLC migration (work stealing) and retag task
    if ENABLE_LLC_AWARENESS.get() && ENABLE_WORK_STEALING.get() {
        if let Some(cctx) = lookup_cpu_ctx(-1) {
            if maybe_retag_stolen_task(p, tctx, cctx) < 0 {
                return;
            }
        }
    }

    tctx.started_running_at = kfuncs::now();
}

/// stopping: Charge vtime and advance DSQ watermarks.
///
/// Port of C mitosis_stopping (mitosis.bpf.c:1273-1316):
/// - Compute used = now - started_running_at
/// - Charge vtime = used * 100 / weight (weight-proportional)
/// - Advance cell and CPU DSQ vtimes
/// - Track per-cell CPU cycles
fn mitosis_stopping(p: *mut task_struct, _runnable: bool) {
    let tctx = match lookup_task_ctx(p) {
        Some(t) => t,
        None => return,
    };
    let cctx = match lookup_cpu_ctx(-1) {
        Some(c) => c,
        None => return,
    };

    // Use CPU's cell (not task's cell) to match dispatch() logic.
    // Prevents starvation when a task is pinned outside its cell.
    let cidx = cctx.cell;
    let cell = match lookup_cell(cidx) {
        Some(c) => c,
        None => return,
    };

    let now = kfuncs::now();
    let used = now.wrapping_sub(tctx.started_running_at);
    tctx.started_running_at = now;

    // Read task weight via CO-RE
    let weight = match core_read!(vmlinux::task_struct, p, scx.weight) {
        Ok(w) if w > 0 => w as u64,
        _ => 100, // default weight
    };

    // Read current dsq_vtime
    let mut dsq_vtime = match core_read!(vmlinux::task_struct, p, scx.dsq_vtime) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Charge: scale by inverse of weight
    dsq_vtime = dsq_vtime.wrapping_add(used * 100 / weight);

    // Write back dsq_vtime
    scx_ebpf::core_write!(vmlinux::task_struct, p, scx.dsq_vtime, dsq_vtime);

    // Advance cell and CPU DSQ vtime watermarks
    advance_dsq_vtimes(cell, cctx, tctx, dsq_vtime);

    // Track per-cell CPU cycles
    if cidx < MAX_CELLS {
        cctx.cell_cycles[cidx as usize] = cctx.cell_cycles[cidx as usize].wrapping_add(used);
    }
}

/// set_cpumask: Called when a task's CPU affinity changes.
///
/// Port of C mitosis_set_cpumask (mitosis.bpf.c:1545-1559):
/// - Look up task context
/// - Re-intersect the task's allowed cpumask with its cell cpumask
///   via update_task_cpumask, which may change the task's DSQ assignment
///   (e.g., from cell-wide to per-CPU pinned or vice versa)
///
/// The `_cpumask` parameter is the new cpumask set by the kernel. The C
/// version doesn't use it directly — update_task_cpumask reads p->cpus_ptr
/// which is already updated by the time this callback fires.
fn mitosis_set_cpumask(p: *mut task_struct, _cpumask: *mut core::ffi::c_void) {
    let _tctx = match lookup_task_ctx(p) {
        Some(t) => t,
        None => return,
    };

    // PORT_TODO: Call update_task_cpumask(p, tctx) to re-intersect the task's
    // CPU affinity with its cell cpumask. This updates tctx->dsq (per-CPU vs
    // cell+LLC) and tctx->all_cell_cpus_allowed based on the new affinity.
    // Blocked on cell cpumask kptrs (cell_cpumasks map).
    // See C source mitosis.bpf.c:1545-1559
}

fn mitosis_init() -> i32 {
    // ── Step 1: Validate configuration ──────────────────────────────
    let ret = validate_flags();
    if ret != 0 {
        return ret;
    }
    let ret = validate_userspace_data();
    if ret != 0 {
        return ret;
    }

    // ── Steps 2+3: Acquire root cgroup, init its cgrp_ctx ──────────
    // See C source mitosis.bpf.c:1836-1859
    {
        let root_cgid = ROOT_CGID.get();
        let rootcg = scx_ebpf::cgroup::from_id(root_cgid);
        if rootcg.is_null() {
            scx_ebpf::scx_bpf_error!("mitosis: root cgroup not found");
            return -2; // -ENOENT
        }

        // Create cgrp_ctx for root cgroup — assigned to cell 0
        let init_val = CgrpCtx { cell: ROOT_CELL_ID, cell_owner: 0 };
        let cgc = CGRP_CTX.get_or_init(rootcg as *mut u8, &init_val);
        if cgc.is_none() {
            scx_ebpf::cgroup::release(rootcg);
            scx_ebpf::scx_bpf_error!("mitosis: cgrp_ctx init failed for root");
            return -2; // -ENOENT
        }

        scx_ebpf::cgroup::release(rootcg);
        // PORT_TODO(kptr): Store root_cgrp as kptr global for timer callback.
    }

    // PORT_TODO(step 4): Build all_cpumask from ALL_CPUS[] bitmap.
    // Requires bpf_cpumask_create() + bpf_cpumask_set_cpu() + kptr storage.
    // See C source mitosis.bpf.c:1862-1882

    // ── Step 5: Create per-CPU DSQs ─────────────────────────────────
    // Each online CPU gets its own DSQ for pinned tasks.
    // See C source mitosis.bpf.c:1884-1907
    let nr_cpus = NR_POSSIBLE_CPUS.get();
    let mut cpu: u32 = 0;
    while cpu < nr_cpus && cpu < MAX_CPUS {
        // Check if this CPU is in the ALL_CPUS bitmask
        let byte_idx = (cpu / 8) as usize;
        let bit_idx = (cpu % 8) as u8;
        if byte_idx < MAX_CPUS_U8 {
            if let Some(byte) = ALL_CPUS.get(byte_idx) {
                if byte & (1 << bit_idx) != 0 {
                    let cpu_dsq = DsqId::cpu(cpu);
                    let ret = kfuncs::create_dsq(cpu_dsq.raw(), -1);
                    if ret != 0 {
                        scx_ebpf::scx_bpf_error!("mitosis: failed to create CPU DSQ");
                        return ret;
                    }
                }
            }
        }
        cpu += 1;
    }

    // ── Step 6: Set cpu_ctx->llc from CPU_TO_LLC[] ──────────────────
    // See C source mitosis.bpf.c:1909-1931
    cpu = 0;
    while cpu < nr_cpus && cpu < MAX_CPUS {
        // PORT_TODO: Use PerCpuArray::get_percpu(0, cpu) for cross-CPU access.
        // For now, cpu_ctx->llc defaults to 0 which is correct when
        // LLC-awareness is disabled (single flat domain).
        // The userspace loader populates CPU_TO_LLC[] but we can't read
        // per-CPU array entries for other CPUs yet.
        cpu += 1;
    }

    // PORT_TODO(step 7): When cpu_controller_disabled, iterate all cgroups
    // via bpf_cgroup_iter and init cgrp_ctx for each.
    // See C source mitosis.bpf.c:1933-1952

    // ── Step 8: Create cell DSQs ────────────────────────────────────
    // Create DSQs for all cell+LLC combinations. Only cell 0 (root) is
    // active initially; the rest are created preemptively so they're
    // ready when cells are allocated dynamically.
    // See C source mitosis.bpf.c:1954-1976
    let nr_llc = if ENABLE_LLC_AWARENESS.get() { NR_LLC.get() } else { 1 };
    let mut cell: u32 = 0;
    while cell < MAX_CELLS {
        let mut llc: u32 = 0;
        while llc < nr_llc && llc < MAX_LLCS {
            let dsq = DsqId::cell_llc(cell, llc);
            let ret = kfuncs::create_dsq(dsq.raw(), -1);
            if ret != 0 {
                scx_ebpf::scx_bpf_error!("mitosis: failed to create cell+LLC DSQ");
                return ret;
            }
            llc += 1;
        }
        cell += 1;
    }

    // ── Step 9: Initialize cell_cpumasks (cpumask + tmp_cpumask kptrs) ──
    // Each cell gets two cpumasks: primary (used by scheduling paths) and
    // tmp (scratch for double-buffer swaps during reconfiguration).
    // Root cell (0) starts with all CPUs; others start empty.
    // See C source mitosis.bpf.c:1978-1992
    {
        let mut cell_i: u32 = 0;
        while cell_i < MAX_CELLS {
            let wrapper = CELL_CPUMASKS.get_ptr_mut(cell_i);
            if wrapper.is_null() {
                scx_ebpf::scx_bpf_error!("mitosis: cell_cpumasks lookup fail");
                return -2;
            }
            let w = unsafe { &mut *wrapper };

            // Create primary cpumask
            let mask = cpumask::create();
            if mask.is_null() {
                scx_ebpf::scx_bpf_error!("mitosis: cpumask create failed");
                return -12;
            }
            // Root cell starts with all CPUs enabled
            if cell_i == ROOT_CELL_ID {
                cpumask::setall(mask);
            }
            let old = unsafe { kptr_xchg(&raw mut w.cpumask, mask) };
            if !old.is_null() {
                cpumask::release(old);
            }

            // Create tmp cpumask (scratch for double-buffer swaps)
            let tmp = cpumask::create();
            if tmp.is_null() {
                scx_ebpf::scx_bpf_error!("mitosis: tmp cpumask create failed");
                return -12;
            }
            let old = unsafe { kptr_xchg(&raw mut w.tmp_cpumask, tmp) };
            if !old.is_null() {
                cpumask::release(old);
            }

            cell_i += 1;
        }
    }

    // PORT_TODO(step 10): Recalc LLC counts for root cell.
    // Requires cell cpumask kptrs.
    // See C source mitosis.bpf.c:1994-1998

    // ── Step 11: Mark cell 0 (root cell) as in_use ──────────────────
    // See C source mitosis.bpf.c:2000-2002
    if let Some(root_cell) = lookup_cell(ROOT_CELL_ID) {
        root_cell.in_use = 1;
        // All CPUs start in cell 0 (root cell). The cpu_cnt will be set
        // by the timer callback once cell cpumasks are implemented.
        root_cell.cpu_cnt = nr_cpus;
    } else {
        return -2; // -ENOENT
    }

    // ── Step 12: Setup and arm bpf_timer for periodic reconfiguration ──
    // Port of C mitosis.bpf.c:2004-2014
    {
        let timer_val = UPDATE_TIMER.get_ptr_mut(0);
        if !timer_val.is_null() {
            let t = unsafe { &mut (*timer_val).timer as *mut BpfTimer };
            let map_ptr = core::ptr::from_ref(&UPDATE_TIMER).cast();
            timer::timer_init(t, map_ptr, timer::CLOCK_BOOTTIME);
            timer::timer_set_callback(t, update_timer_fn as *const () as u64);
            let ret = timer::timer_start(t, TIMER_INTERVAL_NS, 0);
            if ret < 0 {
                return ret as i32;
            }
        }
    }

    0
}

fn mitosis_exit(_ei: *mut scx_exit_info) {
    // PORT_TODO: UEI_RECORD(uei, ei) — record exit info for userspace.
    // See C source mitosis.bpf.c:2015-2018
}

fn mitosis_init_task(p: *mut task_struct, _args: *mut core::ffi::c_void) -> i32 {
    // PORT_TODO: Full init_task — see C source mitosis.bpf.c:1629-1652
    // When cpu_controller_disabled: get task's actual cgroup via task_cgroup(),
    // call init_cgrp_ctx_with_ancestors to ensure hierarchy is initialized,
    // then call init_task_impl(p, cgrp).
    // Otherwise: call init_task_impl(p, args->cgroup).
    // init_task_impl creates bpf_cpumask kptr via bpf_kptr_xchg into tctx->cpumask,
    // initializes LLC fields, calls update_task_cell.
    let tctx = TASK_CTX.get_or_create(p as *mut u8);
    if tctx.is_none() {
        return -1;
    }
    0
}

fn mitosis_exit_task(p: *mut task_struct, _args: *mut core::ffi::c_void) {
    let _ = TASK_CTX.delete(p as *mut u8);
}

/// Initialize cgrp_ctx for a cgroup.
///
/// Port of C init_cgrp_ctx (mitosis.bpf.c:1347-1392):
/// - Creates cgrp_ctx in cgroup storage
/// - Root cgroup gets cell 0
/// - Non-root cgroups inherit parent's cell
/// - If cgroup has a cpuset, bumps configuration_seq so the timer
///   allocates a dedicated cell
///
/// PORT_TODO: get_cgroup_cpumask() check for cpusets is not yet
/// implemented (needs CO-RE reads of cpuset->cpus_allowed).
/// See C source mitosis.bpf.c:1365-1378.
#[inline(always)]
fn init_cgrp_ctx(cgrp: *mut cgroup) -> i32 {
    // Read cgrp->kn->id for debug events and root detection.
    let cgid = if let Ok(kn) = core_read!(vmlinux::cgroup, cgrp, kn) {
        core_read!(vmlinux::kernfs_node, kn, id).unwrap_or(0)
    } else {
        0u64
    };
    record_cgroup_init(cgid);

    // Create cgrp_ctx in cgroup storage
    let cgc = match CGRP_CTX.get_or_init(cgrp as *mut u8, &CgrpCtx::ZERO) {
        Some(c) => c,
        None => {
            scx_ebpf::scx_bpf_error!("mitosis: cgrp_ctx creation failed");
            return -2; // -ENOENT
        }
    };

    let root_cgid = ROOT_CGID.get();

    // Check if this is the root cgroup by comparing kn->id to ROOT_CGID.
    if cgid == root_cgid {
        cgc.cell = ROOT_CELL_ID;
        return 0;
    }

    // Initialize to parent's cell (for non-root cgroups)
    // PORT_TODO: Proper cgrp->level read via CO-RE. For now, try ancestor at
    // level (cgrp_level - 1). Since we can't read the level field, we try
    // looking up parent via ancestor(cgrp, cgrp->level - 1). Without the
    // level, we use a workaround: just inherit cell 0 (root cell) as default.
    // The timer callback will reassign cells based on cpusets.
    cgc.cell = ROOT_CELL_ID;
    cgc.cell_owner = 0;

    // PORT_TODO: Check cpuset with get_cgroup_cpumask(). If cpuset exists,
    // bump configuration_seq to trigger cell allocation in timer callback.
    // See C source mitosis.bpf.c:1365-1378.

    0
}

/// cgroup_init: Called when a cgroup is created.
///
/// Port of C mitosis_cgroup_init (mitosis.bpf.c:1436-1442).
fn mitosis_cgroup_init(cgrp: *mut core::ffi::c_void, _args: *mut core::ffi::c_void) -> i32 {
    if CPU_CONTROLLER_DISABLED.get() {
        return 0;
    }
    init_cgrp_ctx(cgrp as *mut cgroup)
}

/// cgroup_exit: Called when a cgroup is destroyed.
///
/// Port of C mitosis_cgroup_exit (mitosis.bpf.c:1444-1475):
/// - Looks up cgrp_ctx
/// - If this cgroup owned a cell, frees it
/// - Bumps configuration_seq to redistribute CPUs back to root cell
fn mitosis_cgroup_exit(cgrp: *mut core::ffi::c_void) {
    if CPU_CONTROLLER_DISABLED.get() {
        return;
    }

    let cgid = if let Ok(kn) = core_read!(vmlinux::cgroup, cgrp as *mut cgroup, kn) {
        core_read!(vmlinux::kernfs_node, kn, id).unwrap_or(0)
    } else {
        0u64
    };
    record_cgroup_exit(cgid);

    let cgc = match lookup_cgrp_ctx(cgrp as *mut cgroup) {
        Some(c) => c,
        None => {
            // If lookup fails, the cgroup doesn't have storage — not a cell owner
            return;
        }
    };

    if cgc.cell_owner != 0 {
        let _ret = free_cell(cgc.cell as i32);
        // Bump configuration_seq so the timer redistributes CPUs
        unsafe {
            CONFIGURATION_SEQ = CONFIGURATION_SEQ.wrapping_add(1);
        }
    }
}

/// cgroup_move: Called when a task is migrated between cgroups.
///
/// Port of C mitosis_cgroup_move (mitosis.bpf.c:1477-1489):
/// - Looks up the task's context
/// - Updates the task's cell assignment to match the destination cgroup
fn mitosis_cgroup_move(p: *mut task_struct, _from: *mut core::ffi::c_void, to: *mut core::ffi::c_void) {
    if CPU_CONTROLLER_DISABLED.get() {
        return;
    }

    let tctx = match lookup_task_ctx(p) {
        Some(t) => t,
        None => return,
    };

    // Look up the destination cgroup's cell assignment
    let cgc = match lookup_cgrp_ctx_fallible(to as *mut cgroup) {
        Some(c) => c,
        None => return,
    };

    // Update the task's cell to match the destination cgroup
    tctx.cell = cgc.cell;

    // PORT_TODO: Full update_task_cell(p, tctx, to) which also updates
    // cpumask, DSQ assignment, configuration_seq sync, and vtime baseline.
    // Blocked on cell cpumask kptrs. See C source mitosis.bpf.c:456-503.
    // For now, just update the cell ID — the task will get its full
    // assignment refreshed on next enqueue via maybe_refresh_cell.
}

/// dump: Called by the kernel to dump overall scheduler state.
///
/// Port of C mitosis_dump (mitosis.bpf.c:1690-1782):
/// Iterates all in-use cells, printing cpumask, vtime, and nr_queued
/// for each DSQ. Then per-CPU cell assignment and vtime.
///
/// PORT_TODO: scx_bpf_dump() is a variadic printf-like kfunc not yet
/// available in scx-ebpf. Until we add a wrapper, this is a no-op stub.
fn mitosis_dump(_dctx: *mut core::ffi::c_void) {
    // PORT_TODO: Add scx_bpf_dump() kfunc wrapper to scx-ebpf, then:
    // 1. Iterate CELLS[0..MAX_CELLS], for each in_use cell:
    //    - Print cell index, vtime_now, nr_queued for each LLC DSQ
    // 2. Iterate CPUs [0..nr_possible_cpus]:
    //    - Print CPU cell assignment, vtime_now, per-CPU DSQ nr_queued
    // 3. If debug_events_enabled, dump the debug event circular buffer
    // See C source mitosis.bpf.c:1690-1782
}

/// dump_task: Called by the kernel to dump per-task debug info.
///
/// Port of C mitosis_dump_task (mitosis.bpf.c:1784-1799):
/// Prints task's vtime, basis_vtime, cell, DSQ, all_cell_cpus_allowed.
///
/// PORT_TODO: scx_bpf_dump() not yet available. Same blocker as dump().
fn mitosis_dump_task(_dctx: *mut core::ffi::c_void, p: *mut task_struct) {
    // Read task context to validate it exists (verifier path coverage)
    let _tctx = lookup_task_ctx(p);
    // PORT_TODO: Once scx_bpf_dump() wrapper exists, print:
    // Task[pid] vtime=... basis_vtime=... cell=... dsq=... all_cpus=...
    // See C source mitosis.bpf.c:1784-1799
}

// ── Auxiliary BPF programs (fentry / tp_btf) ────────────────────────
//
// These are standalone BPF programs in separate ELF sections, loaded and
// attached independently from the struct_ops scheduler. They detect
// cpuset/cgroup changes and bump configuration_seq to trigger cell
// reconfiguration.
//
// The userspace loader must find these programs by section name and
// attach them via aya's FEntry/BtfTracePoint program types.

/// fentry/cpuset_write_resmask — detect cpuset.cpus modifications.
///
/// Port of C fentry_cpuset_write_resmask (mitosis.bpf.c:1316-1326).
///
/// When a cpuset.cpus file is written, the scheduler needs to know so it can
/// reconfigure cells to match the new CPU masks. We bump configuration_seq
/// so the timer callback (update_timer_cb) will re-walk the cgroup tree and
/// reassign CPUs.
///
/// The C version's arguments are:
///   (struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off, ssize_t retval)
/// We don't need to read them — just the fact that the function was called
/// is enough to know a cpuset changed.
#[unsafe(no_mangle)]
#[unsafe(link_section = "fentry/cpuset_write_resmask")]
pub fn fentry_cpuset_write_resmask(_ctx: *mut core::ffi::c_void) -> i32 {
    // Bump configuration_seq so the timer reconfigures cells.
    // Use volatile read-modify-write for cross-CPU visibility.
    // BPF programs are non-preemptible, so no TOCTOU race on a single CPU.
    // The C version uses __atomic_add_fetch which the BPF JIT compiles to
    // LOCK XADD — our volatile approach is correct but slightly weaker
    // (no atomic guarantee if two CPUs increment simultaneously, but the
    // result is still a changed value which triggers reconfiguration).
    unsafe {
        let cur = core::ptr::read_volatile(&raw const CONFIGURATION_SEQ);
        core::ptr::write_volatile(&raw mut CONFIGURATION_SEQ, cur.wrapping_add(1));
    }
    0
}

/// tp_btf/cgroup_mkdir — fallback cgroup creation tracking.
///
/// Port of C trace_cgroup_mkdir (mitosis.bpf.c:1495-1509).
///
/// When cpu_controller_disabled is true, the SCX cgroup_init callback
/// doesn't fire for new cgroups. This tracepoint catches cgroup creation
/// and initializes cgrp_ctx so the cgroup can participate in cell scheduling.
///
/// Arguments from tp_btf/cgroup_mkdir:
///   arg0: struct cgroup *cgrp
///   arg1: const char *cgrp_path
///
/// PORT_TODO: init_cgrp_ctx_with_ancestors() is not yet implemented.
/// It walks the cgroup hierarchy upward, ensuring all ancestors have
/// cgrp_ctx initialized. For now, we call init_cgrp_ctx() which only
/// initializes the immediate cgroup. See C source mitosis.bpf.c:1394-1434.
#[unsafe(no_mangle)]
#[unsafe(link_section = "tp_btf/cgroup_mkdir")]
pub fn tp_cgroup_mkdir(ctx: *mut u64) -> i32 {
    if !CPU_CONTROLLER_DISABLED.get() {
        return 0;
    }

    // arg0 = struct cgroup *cgrp
    let cgrp = unsafe { *ctx.add(0) } as *mut cgroup;
    if cgrp.is_null() {
        return 0;
    }

    // PORT_TODO: Use init_cgrp_ctx_with_ancestors(cgrp) to walk up the
    // hierarchy and ensure all ancestors have cgrp_ctx. For now, just
    // init this cgroup directly. This works if the parent was already
    // initialized (e.g., via a previous cgroup_mkdir or cgroup_init).
    let ret = init_cgrp_ctx(cgrp);
    if ret != 0 {
        scx_ebpf::scx_bpf_error!("mitosis: init_cgrp_ctx failed in cgroup_mkdir");
    }

    0
}

/// tp_btf/cgroup_rmdir — fallback cgroup removal tracking.
///
/// Port of C trace_cgroup_rmdir (mitosis.bpf.c:1511-1543).
///
/// When cpu_controller_disabled is true, the SCX cgroup_exit callback
/// doesn't fire. This tracepoint catches cgroup removal, frees any owned
/// cells, and bumps configuration_seq to redistribute CPUs.
///
/// Arguments from tp_btf/cgroup_rmdir:
///   arg0: struct cgroup *cgrp
///   arg1: const char *cgrp_path
#[unsafe(no_mangle)]
#[unsafe(link_section = "tp_btf/cgroup_rmdir")]
pub fn tp_cgroup_rmdir(ctx: *mut u64) -> i32 {
    if !CPU_CONTROLLER_DISABLED.get() {
        return 0;
    }

    // arg0 = struct cgroup *cgrp
    let cgrp = unsafe { *ctx.add(0) } as *mut cgroup;
    if cgrp.is_null() {
        return 0;
    }

    // Use fallible lookup since this tracepoint fires for ALL cgroups,
    // including ones that never had tasks or cgrp_ctx storage.
    let cgc = match lookup_cgrp_ctx_fallible(cgrp) {
        Some(c) => c,
        None => return 0,
    };

    let cgid = if let Ok(kn) = core_read!(vmlinux::cgroup, cgrp, kn) {
        core_read!(vmlinux::kernfs_node, kn, id).unwrap_or(0)
    } else {
        0u64
    };
    record_cgroup_exit(cgid);

    if cgc.cell_owner != 0 {
        let ret = free_cell(cgc.cell as i32);
        if ret != 0 {
            scx_ebpf::scx_bpf_error!("mitosis: failed to free cell in cgroup_rmdir");
        }

        // Bump configuration_seq so the timer redistributes the freed
        // cell's CPUs back to the root cell.
        unsafe {
            CONFIGURATION_SEQ = CONFIGURATION_SEQ.wrapping_add(1);
        }
    }

    0
}

// Also missing .flags for SCX_OPS_ALLOW_QUEUED_WAKEUP.
// See C source mitosis.bpf.c:2021-2037
scx_ebpf::scx_ops_define! {
    name: "mitosis",
    select_cpu: mitosis_select_cpu,
    enqueue: mitosis_enqueue,
    dispatch: mitosis_dispatch,
    running: mitosis_running,
    stopping: mitosis_stopping,
    set_cpumask: mitosis_set_cpumask,
    dump: mitosis_dump,
    dump_task: mitosis_dump_task,
    init: mitosis_init,
    exit: mitosis_exit,
    init_task: mitosis_init_task,
    exit_task: mitosis_exit_task,
    cgroup_init: mitosis_cgroup_init,
    cgroup_exit: mitosis_cgroup_exit,
    cgroup_move: mitosis_cgroup_move,
}
