//! BPF map types for pure-Rust sched_ext schedulers.
//!
//! This module provides BPF map declarations and helper wrappers for use
//! in eBPF programs. Maps are declared as `#[link_section = ".maps"]`
//! statics with BTF-compatible `#[repr(C)]` layout that the aya loader
//! recognizes.
//!
//! # Supported map types
//!
//! - [`HashMap`] — generic key-value hash map (`BPF_MAP_TYPE_HASH`)
//! - [`BpfArray`] — indexed array (`BPF_MAP_TYPE_ARRAY`), used for timer maps
//! - [`PerCpuArray`] — per-CPU indexed array (`BPF_MAP_TYPE_PERCPU_ARRAY`)
//! - [`PerfEventArray`] — perf event array for hardware counter access (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`)
//! - [`TaskStorage`] — per-task local storage (`BPF_MAP_TYPE_TASK_STORAGE`)
//!
//! # Usage
//!
//! Maps must be declared as `#[unsafe(no_mangle)]` statics with
//! `#[unsafe(link_section = ".maps")]`:
//!
//! ```ignore
//! use scx_ebpf::maps::{HashMap, PerCpuArray, TaskStorage};
//!
//! #[unsafe(link_section = ".maps")]
//! #[unsafe(no_mangle)]
//! static TASK_CTX: TaskStorage<TaskCtx> = TaskStorage::new();
//!
//! #[unsafe(link_section = ".maps")]
//! #[unsafe(no_mangle)]
//! static CPU_CTX: PerCpuArray<CpuCtx, 1> = PerCpuArray::new();
//!
//! #[unsafe(link_section = ".maps")]
//! #[unsafe(no_mangle)]
//! static GPU_NODE: HashMap<u32, u32, 64> = HashMap::new();
//! ```

use core::marker::PhantomData;
use core::ptr::NonNull;

// ── BPF map type constants ──────────────────────────────────────────────

/// `BPF_MAP_TYPE_HASH` = 1
const MAP_TYPE_HASH: usize = 1;
/// `BPF_MAP_TYPE_ARRAY` = 2
#[allow(dead_code)]
const MAP_TYPE_ARRAY: usize = 2;
/// `BPF_MAP_TYPE_PERF_EVENT_ARRAY` = 4
const MAP_TYPE_PERF_EVENT_ARRAY: usize = 4;
/// `BPF_MAP_TYPE_PERCPU_ARRAY` = 6
const MAP_TYPE_PERCPU_ARRAY: usize = 6;
/// `BPF_MAP_TYPE_TASK_STORAGE` = 29
const MAP_TYPE_TASK_STORAGE: usize = 29;

/// `BPF_F_NO_PREALLOC` = 1
const BPF_F_NO_PREALLOC: usize = 1;

/// `BPF_LOCAL_STORAGE_GET_F_CREATE` = 1
pub const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

// ── BPF helper wrappers (inline asm) ────────────────────────────────────
//
// These call BPF helpers by number using `call N` in inline asm, matching
// the pattern used throughout scx-ebpf for kfunc calls.

/// BPF helper #1: `bpf_map_lookup_elem(map, key) -> *mut value`
#[inline(always)]
unsafe fn bpf_map_lookup_elem(map: *const u8, key: *const u8) -> *mut u8 {
    let ret: *mut u8;
    core::arch::asm!(
        "call 1",
        inlateout("r1") map => _,
        inlateout("r2") key => _,
        lateout("r0") ret,
        lateout("r3") _,
        lateout("r4") _,
        lateout("r5") _,
    );
    ret
}

/// BPF helper #2: `bpf_map_update_elem(map, key, value, flags) -> int`
#[inline(always)]
unsafe fn bpf_map_update_elem(
    map: *const u8,
    key: *const u8,
    value: *const u8,
    flags: u64,
) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "call 2",
        inlateout("r1") map => _,
        inlateout("r2") key => _,
        inlateout("r3") value => _,
        inlateout("r4") flags => _,
        lateout("r0") ret,
        lateout("r5") _,
    );
    ret
}

/// BPF helper #3: `bpf_map_delete_elem(map, key) -> int`
#[inline(always)]
unsafe fn bpf_map_delete_elem(map: *const u8, key: *const u8) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "call 3",
        inlateout("r1") map => _,
        inlateout("r2") key => _,
        lateout("r0") ret,
        lateout("r3") _,
        lateout("r4") _,
        lateout("r5") _,
    );
    ret
}

/// BPF helper #156: `bpf_task_storage_get(map, task, value, flags) -> *mut value`
#[inline(always)]
unsafe fn bpf_task_storage_get(
    map: *const u8,
    task: *mut u8,
    value: *mut u8,
    flags: u64,
) -> *mut u8 {
    let ret: *mut u8;
    core::arch::asm!(
        "call 156",
        inlateout("r1") map => _,
        inlateout("r2") task => _,
        inlateout("r3") value => _,
        inlateout("r4") flags => _,
        lateout("r0") ret,
        lateout("r5") _,
    );
    ret
}

/// BPF helper #195: `bpf_map_lookup_percpu_elem(map, key, cpu) -> *mut value`
///
/// Looks up a per-CPU map element for a specific CPU (not just the current CPU).
/// Available since kernel 5.19. Returns null if the key or CPU is invalid.
#[inline(always)]
unsafe fn bpf_map_lookup_percpu_elem(map: *const u8, key: *const u8, cpu: u32) -> *mut u8 {
    let ret: *mut u8;
    core::arch::asm!(
        "call 195",
        inlateout("r1") map => _,
        inlateout("r2") key => _,
        inlateout("r3") cpu => _,
        lateout("r0") ret,
        lateout("r4") _,
        lateout("r5") _,
    );
    ret
}

/// BPF helper #157: `bpf_task_storage_delete(map, task) -> int`
#[inline(always)]
unsafe fn bpf_task_storage_delete(map: *const u8, task: *mut u8) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "call 157",
        inlateout("r1") map => _,
        inlateout("r2") task => _,
        lateout("r0") ret,
        lateout("r3") _,
        lateout("r4") _,
        lateout("r5") _,
    );
    ret
}

// ── BTF map definition structs ──────────────────────────────────────────
//
// The BTF encoding uses pointer-to-sized-array trick:
//   `*const [i32; N]` encodes the integer N in BTF via the array size.
// The pointer fields are never dereferenced — they exist purely for
// BTF type information that the loader reads.
//
// The `key` and `value` fields use `*const K` / `*const V` so the
// loader can determine the key/value types from BTF.

// ── HashMap ─────────────────────────────────────────────────────────────

/// A BTF-compatible BPF hash map (`BPF_MAP_TYPE_HASH`).
///
/// Provides key-value storage with O(1) lookups. Declare as a
/// `#[unsafe(link_section = ".maps")]` static.
///
/// # Type Parameters
///
/// - `K` — key type (must be `Copy`)
/// - `V` — value type (must be `Copy`)
/// - `MAX_ENTRIES` — maximum number of entries
///
/// # Example
///
/// ```ignore
/// #[unsafe(link_section = ".maps")]
/// #[unsafe(no_mangle)]
/// static GPU_NODE_MAP: HashMap<u32, u32, 64> = HashMap::new();
///
/// // In a BPF program:
/// let node = gpu_node_map.get(&gpu_id);
/// ```
#[repr(C)]
pub struct HashMap<K, V, const MAX_ENTRIES: usize> {
    r#type: *const [i32; MAP_TYPE_HASH],
    key: *const K,
    value: *const V,
    max_entries: *const [i32; MAX_ENTRIES],
    _kv: PhantomData<(K, V)>,
}

unsafe impl<K, V, const N: usize> Sync for HashMap<K, V, N> {}

impl<K, V, const MAX_ENTRIES: usize> HashMap<K, V, MAX_ENTRIES> {
    /// Create a new hash map definition.
    pub const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
            _kv: PhantomData,
        }
    }

    /// Look up a value by key. Returns `None` if the key is not found.
    #[inline(always)]
    pub fn get(&self, key: &K) -> Option<&V> {
        let ptr = self.get_ptr_mut(key);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    /// Returns a mutable reference to the value for `key`.
    ///
    /// The reference is valid for the duration of the current BPF program
    /// invocation, provided no other mutable reference to the same map
    /// entry is held.
    ///
    /// # Safety note
    ///
    /// This is safe under BPF's execution model (single-threaded,
    /// non-preemptible) but the returned reference has an implicit lifetime
    /// tied to BPF verifier state, not Rust's borrow checker. Do not hold
    /// references across BPF helper/kfunc calls.
    #[inline(always)]
    pub fn get_mut(&self, key: &K) -> Option<&mut V> {
        let ptr = self.get_ptr_mut(key);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &mut *ptr })
        }
    }

    /// Look up a value by key, returning a mutable pointer.
    #[inline(always)]
    pub fn get_ptr_mut(&self, key: &K) -> *mut V {
        unsafe {
            bpf_map_lookup_elem(
                core::ptr::from_ref(self).cast(),
                core::ptr::from_ref(key).cast(),
            )
            .cast()
        }
    }

    /// Insert or update a key-value pair. `flags` is typically 0 (`BPF_ANY`).
    #[inline(always)]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_update_elem(
                core::ptr::from_ref(self).cast(),
                core::ptr::from_ref(key).cast(),
                core::ptr::from_ref(value).cast(),
                flags,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }

    /// Delete an entry by key.
    #[inline(always)]
    pub fn delete(&self, key: &K) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_delete_elem(
                core::ptr::from_ref(self).cast(),
                core::ptr::from_ref(key).cast(),
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}

// ── BpfArray ────────────────────────────────────────────────────────────

/// A BTF-compatible BPF array map (`BPF_MAP_TYPE_ARRAY`).
///
/// A simple, non-per-CPU indexed array with a fixed number of entries.
/// Unlike [`PerCpuArray`], all CPUs share the same data.
///
/// This is the map type required for `BpfTimer` storage — the kernel
/// manages timer lifecycle through the map, so the timer must live in
/// a regular (non-per-CPU) array value.
///
/// # Type Parameters
///
/// - `V` — value type (must be `Copy`)
/// - `MAX_ENTRIES` — number of array entries
///
/// # Example
///
/// ```ignore
/// use scx_ebpf::timer::BpfTimer;
///
/// #[repr(C)]
/// #[derive(Clone, Copy)]
/// struct WakeupTimer {
///     timer: BpfTimer,
/// }
///
/// #[unsafe(link_section = ".maps")]
/// #[unsafe(no_mangle)]
/// static WAKEUP_TIMER: BpfArray<WakeupTimer, 1> = BpfArray::new();
/// ```
#[repr(C)]
pub struct BpfArray<V, const MAX_ENTRIES: usize> {
    r#type: *const [i32; MAP_TYPE_ARRAY],
    key: *const u32,
    value: *const V,
    max_entries: *const [i32; MAX_ENTRIES],
    _v: PhantomData<V>,
}

unsafe impl<V, const N: usize> Sync for BpfArray<V, N> {}

impl<V, const MAX_ENTRIES: usize> BpfArray<V, MAX_ENTRIES> {
    /// Create a new array map definition.
    pub const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
            _v: PhantomData,
        }
    }

    /// Look up an element at `index`. Returns `None` if the index is out of bounds.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&V> {
        let ptr = self.get_ptr_mut(index);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    /// Returns a mutable reference to the element at `index`.
    ///
    /// The reference is valid for the duration of the current BPF program
    /// invocation, provided no other mutable reference to the same map
    /// entry is held.
    ///
    /// # Safety note
    ///
    /// This is safe under BPF's execution model (single-threaded,
    /// non-preemptible) but the returned reference has an implicit lifetime
    /// tied to BPF verifier state, not Rust's borrow checker. Do not hold
    /// references across BPF helper/kfunc calls.
    #[inline(always)]
    pub fn get_mut(&self, index: u32) -> Option<&mut V> {
        let ptr = self.get_ptr_mut(index);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &mut *ptr })
        }
    }

    /// Look up an element at `index`, returning a mutable pointer.
    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> *mut V {
        unsafe {
            bpf_map_lookup_elem(
                core::ptr::from_ref(self).cast(),
                core::ptr::from_ref(&index).cast(),
            )
            .cast()
        }
    }

    /// Set the element at `index`.
    #[inline(always)]
    pub fn set(&self, index: u32, value: &V, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_update_elem(
                core::ptr::from_ref(self).cast(),
                core::ptr::from_ref(&index).cast(),
                core::ptr::from_ref(value).cast(),
                flags,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}

// ── PerCpuArray ─────────────────────────────────────────────────────────

/// A BTF-compatible per-CPU array map (`BPF_MAP_TYPE_PERCPU_ARRAY`).
///
/// Each CPU gets its own copy of each array element, providing
/// lock-free per-CPU storage. Indexed by `u32`.
///
/// # Type Parameters
///
/// - `V` — value type (must be `Copy`)
/// - `MAX_ENTRIES` — number of array entries
///
/// # Example
///
/// ```ignore
/// #[unsafe(link_section = ".maps")]
/// #[unsafe(no_mangle)]
/// static CPU_CTX: PerCpuArray<CpuCtx, 1> = PerCpuArray::new();
///
/// // In a BPF program — gets this CPU's element:
/// if let Some(ctx) = cpu_ctx.get(0) { ... }
/// ```
#[repr(C)]
pub struct PerCpuArray<V, const MAX_ENTRIES: usize> {
    r#type: *const [i32; MAP_TYPE_PERCPU_ARRAY],
    key: *const u32,
    value: *const V,
    max_entries: *const [i32; MAX_ENTRIES],
    _v: PhantomData<V>,
}

unsafe impl<V, const N: usize> Sync for PerCpuArray<V, N> {}

impl<V, const MAX_ENTRIES: usize> PerCpuArray<V, MAX_ENTRIES> {
    /// Create a new per-CPU array definition.
    pub const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
            _v: PhantomData,
        }
    }

    /// Look up the current CPU's element at `index`.
    #[inline(always)]
    pub fn get(&self, index: u32) -> Option<&V> {
        let ptr = self.get_ptr_mut(index);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*ptr })
        }
    }

    /// Returns a mutable reference to the current CPU's element at `index`.
    ///
    /// The reference is valid for the duration of the current BPF program
    /// invocation, provided no other mutable reference to the same map
    /// entry is held.
    ///
    /// # Safety note
    ///
    /// This is safe under BPF's execution model (single-threaded,
    /// non-preemptible) but the returned reference has an implicit lifetime
    /// tied to BPF verifier state, not Rust's borrow checker. Do not hold
    /// references across BPF helper/kfunc calls.
    #[inline(always)]
    pub fn get_mut(&self, index: u32) -> Option<&mut V> {
        let ptr = self.get_ptr_mut(index);
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &mut *ptr })
        }
    }

    /// Look up the current CPU's element, returning a mutable pointer.
    #[inline(always)]
    pub fn get_ptr_mut(&self, index: u32) -> *mut V {
        unsafe {
            bpf_map_lookup_elem(
                core::ptr::from_ref(self).cast(),
                core::ptr::from_ref(&index).cast(),
            )
            .cast()
        }
    }

    /// Look up a specific CPU's element at `index`.
    ///
    /// Unlike [`get`] / [`get_ptr_mut`] which return the *current* CPU's
    /// element, this method returns the element for an arbitrary CPU by
    /// calling BPF helper #195 (`bpf_map_lookup_percpu_elem`).
    /// Available since kernel 5.19.
    ///
    /// Returns `None` if the `index` or `cpu` is out of range.
    #[inline(always)]
    pub fn get_percpu(&self, index: u32, cpu: u32) -> Option<&V> {
        let ptr = unsafe {
            bpf_map_lookup_percpu_elem(
                core::ptr::from_ref(self).cast(),
                core::ptr::from_ref(&index).cast(),
                cpu,
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*(ptr as *const V) })
        }
    }

    /// Set the current CPU's element at `index`.
    #[inline(always)]
    pub fn set(&self, index: u32, value: &V, flags: u64) -> Result<(), i64> {
        let ret = unsafe {
            bpf_map_update_elem(
                core::ptr::from_ref(self).cast(),
                core::ptr::from_ref(&index).cast(),
                core::ptr::from_ref(value).cast(),
                flags,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}

// ── PerfEventArray ──────────────────────────────────────────────────────

/// A BTF-compatible perf event array map (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`).
///
/// This map is used as a bridge between userspace and eBPF for hardware
/// performance counter access. Userspace opens perf events via
/// `perf_event_open(2)` and stores the resulting fds in this map
/// (one per CPU). eBPF programs then read counter values via
/// `bpf_perf_event_read_value()` (helper #55).
///
/// Key and value are both `u32`: the key is the CPU index, and the
/// value is the perf event fd (set by userspace).
///
/// This map type does not support lookup/update from eBPF — it is
/// populated exclusively by userspace and consumed by the perf read helper.
///
/// # Type Parameters
///
/// - `MAX_ENTRIES` — maximum number of entries (typically >= nr_cpus)
///
/// # Example
///
/// ```ignore
/// #[unsafe(link_section = ".maps")]
/// #[unsafe(no_mangle)]
/// static SCX_PMU_MAP: PerfEventArray<1024> = PerfEventArray::new();
///
/// // In a BPF program — read the current CPU's perf counter:
/// let mut val = PerfEventValue::ZERO;
/// let ret = unsafe {
///     pmu::perf_event_read_value(
///         &raw const SCX_PMU_MAP as *const _,
///         BPF_F_CURRENT_CPU,
///         &mut val,
///     )
/// };
/// ```
#[repr(C)]
pub struct PerfEventArray<const MAX_ENTRIES: usize> {
    r#type: *const [i32; MAP_TYPE_PERF_EVENT_ARRAY],
    key: *const u32,
    value: *const u32,
    max_entries: *const [i32; MAX_ENTRIES],
}

unsafe impl<const N: usize> Sync for PerfEventArray<N> {}

impl<const MAX_ENTRIES: usize> PerfEventArray<MAX_ENTRIES> {
    /// Create a new perf event array definition.
    pub const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
        }
    }
}

// ── TaskStorage ─────────────────────────────────────────────────────────

/// A BTF-compatible per-task local storage map (`BPF_MAP_TYPE_TASK_STORAGE`).
///
/// Provides per-task storage that is automatically freed when the task
/// exits. Uses `BPF_F_NO_PREALLOC` and `max_entries = 0` as required
/// by the kernel for task storage maps.
///
/// # Type Parameters
///
/// - `V` — value type stored per task (must be `Copy` + zero-initializable)
///
/// # Example
///
/// ```ignore
/// #[repr(C)]
/// #[derive(Copy, Clone)]
/// struct TaskCtx {
///     exec_runtime: u64,
///     last_run_at: u64,
/// }
///
/// #[unsafe(link_section = ".maps")]
/// #[unsafe(no_mangle)]
/// static TASK_CTX: TaskStorage<TaskCtx> = TaskStorage::new();
///
/// // Get or create per-task context:
/// let tctx = task_ctx.get_or_create(p);
/// ```
#[repr(C)]
pub struct TaskStorage<V> {
    r#type: *const [i32; MAP_TYPE_TASK_STORAGE],
    key: *const i32,
    value: *const V,
    max_entries: *const [i32; 0],
    map_flags: *const [i32; BPF_F_NO_PREALLOC],
    _v: PhantomData<V>,
}

unsafe impl<V> Sync for TaskStorage<V> {}

impl<V> TaskStorage<V> {
    /// Create a new task storage map definition.
    pub const fn new() -> Self {
        Self {
            r#type: core::ptr::null(),
            key: core::ptr::null(),
            value: core::ptr::null(),
            max_entries: core::ptr::null(),
            map_flags: core::ptr::null(),
            _v: PhantomData,
        }
    }

    /// Get the per-task storage for a task, returning `None` if not yet created.
    ///
    /// `task` must be a valid `task_struct` pointer (e.g., from a sched_ext callback).
    #[inline(always)]
    pub fn get(&self, task: *mut u8) -> Option<NonNull<V>> {
        let ptr = unsafe {
            bpf_task_storage_get(
                core::ptr::from_ref(self).cast(),
                task,
                core::ptr::null_mut(),
                0,
            )
        };
        NonNull::new(ptr.cast())
    }

    /// Returns a reference to the per-task storage value.
    ///
    /// The reference is valid for the duration of the current BPF program
    /// invocation, provided no other mutable reference to the same map
    /// entry is held.
    ///
    /// # Safety note
    ///
    /// This is safe under BPF's execution model (single-threaded,
    /// non-preemptible) but the returned reference has an implicit lifetime
    /// tied to BPF verifier state, not Rust's borrow checker. Do not hold
    /// references across BPF helper/kfunc calls.
    ///
    /// `task` must be a valid `task_struct` pointer.
    #[inline(always)]
    pub fn get_ref(&self, task: *mut u8) -> Option<&V> {
        let ptr = unsafe {
            bpf_task_storage_get(
                core::ptr::from_ref(self).cast(),
                task,
                core::ptr::null_mut(),
                0,
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*(ptr as *const V) })
        }
    }

    /// Returns a mutable reference to the per-task storage value.
    ///
    /// The reference is valid for the duration of the current BPF program
    /// invocation, provided no other mutable reference to the same map
    /// entry is held.
    ///
    /// # Safety note
    ///
    /// This is safe under BPF's execution model (single-threaded,
    /// non-preemptible) but the returned reference has an implicit lifetime
    /// tied to BPF verifier state, not Rust's borrow checker. Do not hold
    /// references across BPF helper/kfunc calls.
    ///
    /// `task` must be a valid `task_struct` pointer.
    #[inline(always)]
    pub fn get_mut(&self, task: *mut u8) -> Option<&mut V> {
        let ptr = unsafe {
            bpf_task_storage_get(
                core::ptr::from_ref(self).cast(),
                task,
                core::ptr::null_mut(),
                0,
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &mut *(ptr as *mut V) })
        }
    }

    /// Get or create the per-task storage for a task.
    ///
    /// If storage does not yet exist for this task, it is zero-initialized
    /// and created (using `BPF_LOCAL_STORAGE_GET_F_CREATE`).
    ///
    /// `task` must be a valid `task_struct` pointer.
    #[inline(always)]
    pub fn get_or_create(&self, task: *mut u8) -> Option<NonNull<V>> {
        let ptr = unsafe {
            bpf_task_storage_get(
                core::ptr::from_ref(self).cast(),
                task,
                core::ptr::null_mut(),
                BPF_LOCAL_STORAGE_GET_F_CREATE,
            )
        };
        NonNull::new(ptr.cast())
    }

    /// Delete the per-task storage for a task.
    ///
    /// `task` must be a valid `task_struct` pointer.
    #[inline(always)]
    pub fn delete(&self, task: *mut u8) -> Result<(), i64> {
        let ret = unsafe {
            bpf_task_storage_delete(
                core::ptr::from_ref(self).cast(),
                task,
            )
        };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}
