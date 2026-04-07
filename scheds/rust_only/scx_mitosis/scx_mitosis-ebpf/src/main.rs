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
use scx_ebpf::maps::{TaskStorage, PerCpuArray, HashMap, BpfArray};
use scx_ebpf::helpers::BpfSpinLock;
use scx_ebpf::cgroup::cgroup;
use scx_ebpf::cpumask::bpf_cpumask;

mod vmlinux {
    include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
}

scx_ebpf::scx_ebpf_boilerplate!();

// PORT_TODO: FAKE_FLAT_CELL_LLC constant (=0) used when LLC awareness is
// disabled to flatten topology into a single scheduling domain.
// — see C source mitosis.bpf.c:27

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

// PORT_TODO: Missing struct cell_cpumask_wrapper — holds kptr cpumask + tmp_cpumask
// for double-buffered cpumask updates. Blocked on kptr support in aya.
// See C source mitosis.bpf.c:321-328

// PORT_TODO: Missing struct cpumask_entry — per-CPU scratch buffer for reading
// cgroup cpusets. See C source mitosis.bpf.c:847-850

// ── BPF maps ──────────────────────────────────────────────────────────

scx_ebpf::bpf_map!(TASK_CTX: TaskStorage<TaskCtx> = TaskStorage::new());
scx_ebpf::bpf_map!(CPU_CTX: PerCpuArray<CpuCtx, 1> = PerCpuArray::new());
scx_ebpf::bpf_map!(CELLS: BpfArray<Cell, { MAX_CELLS as usize }> = BpfArray::new());
scx_ebpf::bpf_map!(DEBUG_EVENTS: BpfArray<DebugEvent, { DEBUG_EVENTS_BUF_SIZE as usize }> = BpfArray::new());

// PORT_TODO: CGRP_CTX needs BPF_MAP_TYPE_CGRP_STORAGE which is tracked
// by mitosis-cgroup-storage-map task. For now we skip cgroup storage.

// PORT_TODO: Missing update_timer map (BPF_MAP_TYPE_ARRAY, max_entries=1)
// — holds bpf_timer for periodic cell reconfiguration. Blocked on
// bpf_timer support in aya. See C source mitosis.bpf.c:76-85

// PORT_TODO: Missing cell_cpumasks map (BPF_MAP_TYPE_ARRAY, max_entries=MAX_CELLS)
// — stores cell_cpumask_wrapper { cpumask: bpf_cpumask __kptr, tmp_cpumask: bpf_cpumask __kptr }
// — needs kptr support in aya maps. See C source mitosis.bpf.c:321-336

// PORT_TODO: Missing cgrp_init_percpu_cpumask map (BPF_MAP_TYPE_PERCPU_ARRAY, max_entries=4)
// — per-CPU scratch space for reading cgroup cpusets during init.
// — See C source mitosis.bpf.c:852-857

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

// PORT_TODO: Missing level_cells: [u32; MAX_CG_DEPTH] mutable global
// — tracks ancestor cell IDs during cgroup tree walk in update_timer_cb.
// See C source mitosis.bpf.c:967

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

// PORT_TODO: Missing lookup_cgrp_ancestor(cgrp, level) — wraps bpf_cgroup_ancestor.
// — See C source mitosis.bpf.c:102-114

// PORT_TODO: Missing lookup_cgrp_ctx_fallible(cgrp) / lookup_cgrp_ctx(cgrp)
// — wraps bpf_cgrp_storage_get on cgrp_ctxs map. Blocked on cgrp storage map.
// — See C source mitosis.bpf.c:123-143

// PORT_TODO: Missing task_cgroup(p) — gets task's cgroup, handling cpu_controller_disabled
// mode (reads p->cgroups->dfl_cgrp under RCU). See C source mitosis.bpf.c:145-169

// PORT_TODO: Missing allocate_cell() / free_cell() — atomic cell pool management using
// __sync_bool_compare_and_swap on cell.in_use. See C source mitosis.bpf.c:219-251

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

// PORT_TODO: Missing lookup_cell_cpumask(idx) — reads cell_cpumask_wrapper.cpumask kptr.
// Blocked on cell_cpumasks map + kptr support. See C source mitosis.bpf.c:338-353

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

// PORT_TODO: Missing update_task_cell(p, tctx, cg) — reads cgrp_ctx to get cell assignment,
// handles exiting_task_workaround, syncs configuration_seq. See C source mitosis.bpf.c:456-503

// PORT_TODO: Missing refresh_task_cell(p, tctx) — gets task's cgroup and calls
// update_task_cell. See C source mitosis.bpf.c:508-515

// PORT_TODO: Missing maybe_refresh_cell(p, tctx) — checks configuration_seq staleness and
// cpu_controller_disabled cgroup move detection. See C source mitosis.bpf.c:547-571

// PORT_TODO: Missing pick_idle_cpu(p, prev_cpu, cctx, tctx) — gets task cpumask and idle
// SMT mask, calls pick_idle_cpu_from. Blocked on cell cpumask kptrs. See C source mitosis.bpf.c:573-599

// PORT_TODO: Missing allocate_cpumask_entry() / free_cpumask_entry() — per-CPU scratch
// cpumask allocation for cgroup init. See C source mitosis.bpf.c:859-884

// PORT_TODO: Missing update_timer_cb() — periodic timer callback that walks cgroup tree,
// allocates cells, assigns CPUs, updates cell cpumasks via kptr_xchg, recalcs LLC counts.
// This is the core reconfiguration logic (~250 lines). See C source mitosis.bpf.c:972-1229

// PORT_TODO: Missing init_task_impl(p, cgrp) — full task init: creates cpumask kptr,
// initializes LLC fields, calls update_task_cell. See C source mitosis.bpf.c:1591-1627

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

// === LLC-aware helpers (from llc_aware.bpf.h) ===

// PORT_TODO: Missing recalc_cell_llc_counts(cell_idx, explicit_mask) — recomputes per-LLC
// CPU counts within a cell, using bpf_cpumask_and + bpf_cpumask_weight under spin lock.
// Blocked on cell cpumask kptrs. See C source llc_aware.bpf.h:65-123

// PORT_TODO: Missing pick_llc_for_task(cell_id) — weighted random LLC selection using
// bpf_get_prandom_u32, proportional to per-LLC CPU count.
// See C source llc_aware.bpf.h:135-189

// PORT_TODO: Missing maybe_retag_stolen_task(p, tctx, cctx) — detects cross-LLC migration
// (work stealing), updates steal accounting, reassigns LLC. See C source llc_aware.bpf.h:211-231

// PORT_TODO: Missing try_stealing_work(cell, local_llc) — scans sibling (cell,LLC) DSQs
// for stealable tasks, calls scx_bpf_dsq_move_to_local. See C source llc_aware.bpf.h:240-301

// PORT_TODO: Missing update_task_llc_assignment(p, tctx) — picks new LLC, narrows cpumask
// by LLC, sets DSQ and vtime baseline. See C source llc_aware.bpf.h:303-349

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
    // PORT_TODO: maybe_refresh_cell(p, tctx) — refresh cell assignment if
    // configuration_seq changed. Blocked on cgroup storage.

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
/// - Refresh cell assignment (PORT_TODO: blocked on cgroup storage)
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

    // PORT_TODO: maybe_refresh_cell(p, tctx) — refresh cell if stale.
    // Blocked on cgroup storage.

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

    // Clamp vtime: cap accumulated idle budget to one slice
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
/// Port of C mitosis_dispatch (mitosis.bpf.c:751-817):
/// - Build cell+LLC DSQ and per-CPU DSQ IDs
/// - Try cell+LLC DSQ first, then per-CPU DSQ
/// - PORT_TODO: peek both DSQs, pick lowest vtime (needs dsq_peek on 6.19+)
/// - PORT_TODO: work stealing from sibling LLCs when both DSQs empty
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

    // Try cell+LLC DSQ first (higher priority — vtime-ordered shared queue)
    if kfuncs::dsq_move_to_local(cell_dsq.raw()) {
        return;
    }

    // Then per-CPU DSQ (for pinned tasks)
    if kfuncs::dsq_move_to_local(cpu_dsq.raw()) {
        return;
    }

    // PORT_TODO: work stealing when both DSQs are empty.
    // Requires try_stealing_work(cell, llc) — see llc_aware.bpf.h:240-301.
}

/// running: Record task start time for runtime accounting.
///
/// Port of C mitosis_running (mitosis.bpf.c:1256-1272):
/// - Record scx_bpf_now() as started_running_at
/// - PORT_TODO: Handle stolen task retag (LLC-aware mode)
fn mitosis_running(p: *mut task_struct) {
    let tctx = match lookup_task_ctx(p) {
        Some(t) => t,
        None => return,
    };

    // PORT_TODO: maybe_retag_stolen_task(p, tctx, cctx) for LLC-aware mode.
    // Blocked on cell cpumask kptrs + update_task_cpumask.

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

fn mitosis_init() -> i32 {
    // PORT_TODO: Full init implementation — see C source mitosis.bpf.c:1801-2013
    // Must:
    // 1. validate_flags() and validate_userspace_data()
    // 2. Acquire root cgroup (bpf_cgroup_from_id), store as kptr
    // 3. Initialize cgrp_ctx for root cgroup
    // 4. Build all_cpumask from all_cpus[] bitmap
    // 5. Create per-CPU DSQs (scx_bpf_create_dsq for each online CPU)
    // 6. Set cpu_ctx->llc from cpu_to_llc[] array
    // 7. When cpu_controller_disabled: iterate all cgroups and init cgrp_ctx
    // 8. Create per-cell DSQs (cell+LLC combinations)
    // 9. Initialize cell_cpumasks (cpumask + tmp_cpumask kptrs)
    // 10. Recalc LLC counts for root cell
    // 11. Mark cell 0 as in_use
    // 12. Setup and arm bpf_timer for periodic reconfiguration
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

// PORT_TODO: Missing cgroup_init callback — see C source mitosis.bpf.c:1436-1442
// Calls init_cgrp_ctx(cgrp) to create cgrp_ctx in cgrp storage, assign to
// parent's cell, and bump configuration_seq if cgroup has a cpuset.

// PORT_TODO: Missing cgroup_exit callback — see C source mitosis.bpf.c:1444-1475
// Frees cell if cgrp_ctx->cell_owner, bumps configuration_seq to trigger
// CPU redistribution.

// PORT_TODO: Missing cgroup_move callback — see C source mitosis.bpf.c:1477-1489
// Calls update_task_cell(p, tctx, to) to reassign task to new cgroup's cell.

// PORT_TODO: Missing dump callback — see C source mitosis.bpf.c:1690-1782
// Dumps all in-use cells with cpumasks, vtime, nr_queued for each DSQ.
// Dumps per-CPU cell assignment and vtime. If debug_events_enabled, dumps
// the circular debug event buffer.

// PORT_TODO: Missing dump_task callback — see C source mitosis.bpf.c:1784-1799
// Dumps per-task vtime, basis_vtime, cell, DSQ, all_cell_cpus_allowed, cpumask.

// PORT_TODO: Missing fentry/cpuset_write_resmask program — see C source mitosis.bpf.c:1316-1326
// fentry hook that bumps configuration_seq when a cpuset.cpus file is written,
// triggering the timer to reconfigure cells.

// PORT_TODO: Missing tp_btf/cgroup_mkdir tracepoint — see C source mitosis.bpf.c:1496-1509
// When cpu_controller_disabled, initializes cgrp_ctx for new cgroups since
// SCX cgroup callbacks don't fire.

// PORT_TODO: Missing tp_btf/cgroup_rmdir tracepoint — see C source mitosis.bpf.c:1511-1543
// When cpu_controller_disabled, handles cgroup removal — frees owned cells,
// bumps configuration_seq.

// PORT_TODO: scx_ops_define is missing callbacks that the C version registers:
// set_cpumask, cgroup_init, cgroup_exit, cgroup_move, dump, dump_task.
// Also missing .flags for SCX_OPS_ALLOW_QUEUED_WAKEUP.
// See C source mitosis.bpf.c:2021-2037
scx_ebpf::scx_ops_define! {
    name: "mitosis",
    select_cpu: mitosis_select_cpu,
    enqueue: mitosis_enqueue,
    dispatch: mitosis_dispatch,
    running: mitosis_running,
    stopping: mitosis_stopping,
    init: mitosis_init,
    exit: mitosis_exit,
    init_task: mitosis_init_task,
    exit_task: mitosis_exit_task,
}
