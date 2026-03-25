//! Safe BPF execution context using Rust's borrow checker.
//!
//! [`BpfCtx`] is the unified safe context for BPF schedulers. All map
//! operations and BPF helper/kfunc calls go through this single type.
//!
//! # Design: The Borrow Split
//!
//! Map lookups take `&self` (shared borrow) and return references tied
//! to that borrow. Helper/kfunc calls that may invalidate map pointers
//! take `&mut self` (exclusive borrow). Rust's borrow checker prevents
//! holding map references across `&mut self` calls, which mirrors the
//! BPF verifier's pointer invalidation semantics exactly.
//!
//! ```ignore
//! fn on_enqueue(ctx: &mut BpfCtx, p: *mut task_struct) {
//!     // Multiple map lookups can coexist (&self borrows)
//!     let tctx = ctx.task_storage_get(&TASK_CTX, p as _).unwrap();
//!     let cctx = ctx.percpu_array_get(&CPU_CTX, 0).unwrap();
//!     let weight = tctx.exec_runtime + cctx.load;
//!     drop(tctx);  // must drop before helper call
//!     drop(cctx);
//!
//!     // Helper calls require &mut self — compiler enforces the drop
//!     ctx.dsq_insert(p, SHARED_DSQ, weight * 10, 0);
//! }
//! ```
//!
//! # Safety model
//!
//! This API catches the most common class of BPF safety errors (using
//! a map pointer after a helper call that invalidates it) at compile
//! time. It does NOT address all possible safety concerns:
//!
//! - **Global variable access**: Handled separately by [`BpfGlobal<T>`]
//! - **Kernel struct field access**: Handled by [`core_read!`] / [`core_write!`]
//! - **RCU lock pairing**: Not enforced (could add `RcuGuard` RAII later)
//! - **Kptr lifecycle**: `kptr_xchg` and RCU dereference need manual care
//! - **Timer callback validity**: Function pointers must be valid BPF subprograms
//! - **`bpf_loop` callback safety**: Callback function pointer must be valid
//!
//! # Mutable map access
//!
//! Methods like `task_storage_get_mut` return `&mut V` through `&self`.
//! This is technically unsound under strict Rust aliasing rules, but is
//! safe under BPF's execution model: BPF runs single-threaded per-CPU
//! with preemption disabled, and the BPF verifier tracks pointer
//! validity independently. We use internal `unsafe` with documentation
//! explaining why it is correct in this context.
//!
//! # `&self` vs `&mut self` classification
//!
//! **`&self` (read-only, don't invalidate map pointers):**
//! - `now()` — reads scheduler clock
//! - `nr_cpu_ids()` — returns a constant
//! - `task_running()` — reads task state
//! - `task_cpu()` — reads task state
//! - `dsq_nr_queued()` — reads queue depth
//! - `get_smp_processor_id()` — reads current CPU
//! - `get_current_task_btf()` — reads current task pointer
//! - cpumask queries: `test_cpu`, `first`, `first_zero`, `empty`, `full`
//!
//! **`&mut self` (may invalidate map pointers):**
//! - `dsq_insert()` / `dsq_insert_vtime()` — modifies scheduling state
//! - `dsq_move_to_local()` — modifies scheduling state
//! - `kick_cpu()` — sends IPI, may trigger reschedule
//! - `test_and_clear_cpu_idle()` — modifies idle state
//! - `select_cpu_dfl()` / `select_cpu_and()` — calls into kernel scheduler
//! - `create_dsq()` — creates kernel resource
//! - `cpuperf_set()` — sets CPU performance (conservative: &mut self)
//! - `error_bstr()` — triggers error path
//! - cpumask mutations: `create`, `release`, `set_cpu`, `clear_cpu`,
//!   `and`, `or`, `copy`, `setall`
//! - RCU: `rcu_read_lock`, `rcu_read_unlock`
//! - kptr: `kptr_xchg`
//! - timers: all timer ops
//! - `bpf_loop` — calls callback
//! - `probe_read_kernel` — reads kernel memory
//! - map mutations: `hash_insert`, `hash_delete`, `task_storage_delete`

use crate::cpumask::bpf_cpumask;
use crate::kfuncs::cpumask;
use crate::kptr::Kptr;
use crate::maps;
use crate::pmu::PerfEventValue;
use crate::timer::BpfTimer;
use crate::vmlinux::{rq, task_struct};

/// Safe BPF execution context.
///
/// Uses Rust's borrow checker to enforce that map references are not
/// held across BPF helper/kfunc calls. Map lookups take `&self`;
/// helper calls take `&mut self`. The borrow checker prevents
/// simultaneous shared and exclusive borrows, catching use-after-
/// invalidation errors at compile time.
///
/// `BpfCtx` is a zero-sized type (ZST) — it compiles away completely,
/// producing no additional BPF instructions.
///
/// # Construction
///
/// `BpfCtx` should only be constructed at BPF program entry points.
/// The `scx_ops_define!` macro will create it and pass `&mut BpfCtx`
/// to user-defined callbacks. Manual construction is available via
/// `BpfCtx::new()` (pub(crate) visibility).
///
/// # Example
///
/// ```ignore
/// fn on_enqueue(ctx: &mut BpfCtx, p: *mut task_struct, enq_flags: u64) {
///     // Phase 1: Read from maps (shared borrows of ctx)
///     let (vtime, dsq) = {
///         let tctx = ctx.task_storage_get(&TASK_CTX, p as _).unwrap();
///         (tctx.vtime, tctx.dsq_id)
///     }; // tctx dropped, shared borrow released
///
///     // Phase 2: Call helpers (exclusive borrow of ctx)
///     ctx.dsq_insert_vtime(p, dsq, 20_000_000, vtime, enq_flags);
/// }
/// ```
pub struct BpfCtx {
    _private: (),
}

impl BpfCtx {
    /// Create a new `BpfCtx`.
    ///
    /// Should only be called at BPF program entry points (e.g., in the
    /// trampoline generated by `scx_ops_define!`).
    #[inline(always)]
    pub fn new() -> Self {
        Self { _private: () }
    }

    // =====================================================================
    // Map accessors (&self) — multiple lookups can coexist
    // =====================================================================

    // ── TaskStorage ──────────────────────────────────────────────────────

    /// Look up per-task storage, returning an immutable reference.
    ///
    /// The returned reference borrows `&self`, preventing any `&mut self`
    /// helper call until the reference is dropped.
    ///
    /// `task` must be a valid `task_struct` pointer (cast to `*mut u8`).
    #[inline(always)]
    pub fn task_storage_get<'a, V>(
        &'a self,
        map: &'a maps::TaskStorage<V>,
        task: *mut u8,
    ) -> Option<&'a V> {
        map.get_ref(task)
    }

    /// Look up per-task storage, returning a mutable reference.
    ///
    /// Returns `&mut V` through `&self` — this is safe under BPF's
    /// single-threaded per-CPU execution model. The borrow checker still
    /// prevents holding this across helper calls.
    ///
    /// `task` must be a valid `task_struct` pointer (cast to `*mut u8`).
    #[inline(always)]
    pub fn task_storage_get_mut<'a, V>(
        &'a self,
        map: &'a maps::TaskStorage<V>,
        task: *mut u8,
    ) -> Option<&'a mut V> {
        // SAFETY: BPF is single-threaded per CPU with preemption disabled.
        // Returning &mut V from &self is safe because there is no concurrent
        // access to the same map entry on this CPU. The lifetime tie to
        // &'a self prevents use across helper calls.
        map.get_mut(task)
    }

    /// Get or create per-task storage, returning a mutable reference.
    ///
    /// If storage does not exist for this task, it is zero-initialized
    /// and created (using `BPF_LOCAL_STORAGE_GET_F_CREATE`).
    ///
    /// `task` must be a valid `task_struct` pointer (cast to `*mut u8`).
    #[inline(always)]
    pub fn task_storage_get_or_create<'a, V>(
        &'a self,
        map: &'a maps::TaskStorage<V>,
        task: *mut u8,
    ) -> Option<&'a mut V> {
        // SAFETY: Same justification as task_storage_get_mut.
        map.get_or_create(task)
            .map(|nn| unsafe { &mut *nn.as_ptr() })
    }

    // ── PerCpuArray ──────────────────────────────────────────────────────

    /// Look up the current CPU's element in a per-CPU array.
    #[inline(always)]
    pub fn percpu_array_get<'a, V, const N: usize>(
        &'a self,
        map: &'a maps::PerCpuArray<V, N>,
        index: u32,
    ) -> Option<&'a V> {
        map.get(index)
    }

    /// Look up the current CPU's element, returning a mutable reference.
    ///
    /// Safe under BPF's per-CPU execution model (each CPU has its own
    /// copy of per-CPU array elements).
    #[inline(always)]
    pub fn percpu_array_get_mut<'a, V, const N: usize>(
        &'a self,
        map: &'a maps::PerCpuArray<V, N>,
        index: u32,
    ) -> Option<&'a mut V> {
        map.get_mut(index)
    }

    /// Look up a specific CPU's element in a per-CPU array.
    ///
    /// Unlike `percpu_array_get` which returns the current CPU's element,
    /// this returns the element for an arbitrary CPU. Available since
    /// kernel 5.19.
    #[inline(always)]
    pub fn percpu_array_get_cpu<'a, V, const N: usize>(
        &'a self,
        map: &'a maps::PerCpuArray<V, N>,
        index: u32,
        cpu: u32,
    ) -> Option<&'a V> {
        map.get_percpu(index, cpu)
    }

    // ── HashMap ──────────────────────────────────────────────────────────

    /// Look up a value in a hash map.
    #[inline(always)]
    pub fn hash_get<'a, K, V, const N: usize>(
        &'a self,
        map: &'a maps::HashMap<K, V, N>,
        key: &K,
    ) -> Option<&'a V> {
        map.get(key)
    }

    /// Look up a mutable value in a hash map.
    ///
    /// Note: hash maps are shared across CPUs, so concurrent writes to
    /// the same key from different CPUs are racy. This is inherent to
    /// BPF hash maps (same in C). For per-CPU data, use `PerCpuArray`.
    #[inline(always)]
    pub fn hash_get_mut<'a, K, V, const N: usize>(
        &'a self,
        map: &'a maps::HashMap<K, V, N>,
        key: &K,
    ) -> Option<&'a mut V> {
        map.get_mut(key)
    }

    // ── BpfArray ─────────────────────────────────────────────────────────

    /// Look up an element in a BPF array.
    #[inline(always)]
    pub fn array_get<'a, V, const N: usize>(
        &'a self,
        map: &'a maps::BpfArray<V, N>,
        index: u32,
    ) -> Option<&'a V> {
        map.get(index)
    }

    /// Look up a mutable element in a BPF array.
    #[inline(always)]
    pub fn array_get_mut<'a, V, const N: usize>(
        &'a self,
        map: &'a maps::BpfArray<V, N>,
        index: u32,
    ) -> Option<&'a mut V> {
        map.get_mut(index)
    }

    // =====================================================================
    // Read-only helpers (&self) — don't invalidate map pointers
    // =====================================================================

    /// Return the current scheduler clock value in nanoseconds.
    #[inline(always)]
    pub fn now(&self) -> u64 {
        crate::kfuncs::now()
    }

    /// Return the maximum number of CPU IDs on this system.
    #[inline(always)]
    pub fn nr_cpu_ids(&self) -> u32 {
        crate::kfuncs::nr_cpu_ids()
    }

    /// Return true if the task is currently running on a CPU.
    #[inline(always)]
    pub fn task_running(&self, p: *const task_struct) -> bool {
        crate::kfuncs::task_running(p)
    }

    /// Return the CPU a task is currently assigned to.
    #[inline(always)]
    pub fn task_cpu(&self, p: *const task_struct) -> i32 {
        crate::kfuncs::task_cpu(p)
    }

    /// Return the number of tasks queued on a DSQ.
    #[inline(always)]
    pub fn dsq_nr_queued(&self, dsq_id: u64) -> i32 {
        crate::kfuncs::dsq_nr_queued(dsq_id)
    }

    /// Return the ID of the CPU the BPF program is currently executing on.
    #[inline(always)]
    pub fn get_smp_processor_id(&self) -> i32 {
        crate::helpers::get_smp_processor_id()
    }

    /// Return a BTF-typed pointer to the current task's `task_struct`.
    #[inline(always)]
    pub fn get_current_task_btf(&self) -> *mut u8 {
        crate::helpers::get_current_task_btf()
    }

    // ── Read-only cpumask queries ────────────────────────────────────────

    /// Test whether `cpu` is set in a cpumask.
    #[inline(always)]
    pub fn cpumask_test_cpu(&self, cpu: u32, mask: *const cpumask) -> bool {
        crate::cpumask::test_cpu(cpu, mask)
    }

    /// Return the index of the first set bit in a cpumask.
    #[inline(always)]
    pub fn cpumask_first(&self, mask: *const cpumask) -> u32 {
        crate::cpumask::first(mask)
    }

    /// Return the index of the first unset bit in a cpumask.
    #[inline(always)]
    pub fn cpumask_first_zero(&self, mask: *const cpumask) -> u32 {
        crate::cpumask::first_zero(mask)
    }

    /// Return true if no bits are set in the cpumask.
    #[inline(always)]
    pub fn cpumask_empty(&self, mask: *const cpumask) -> bool {
        crate::cpumask::empty(mask)
    }

    /// Return true if all possible CPU bits are set.
    #[inline(always)]
    pub fn cpumask_full(&self, mask: *const cpumask) -> bool {
        crate::cpumask::full(mask)
    }

    // =====================================================================
    // Mutating helpers (&mut self) — invalidate all map pointers
    // =====================================================================

    // ── DSQ operations ───────────────────────────────────────────────────

    /// Insert a task into a dispatch queue with a given time slice.
    #[inline(always)]
    pub fn dsq_insert(
        &mut self,
        p: *mut task_struct,
        dsq_id: u64,
        slice: u64,
        enq_flags: u64,
    ) {
        crate::kfuncs::dsq_insert(p, dsq_id, slice, enq_flags);
    }

    /// Insert a task into a dispatch queue with vtime-based ordering.
    #[inline(always)]
    pub fn dsq_insert_vtime(
        &mut self,
        p: *mut task_struct,
        dsq_id: u64,
        slice: u64,
        vtime: u64,
        enq_flags: u64,
    ) {
        crate::kfuncs::dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
    }

    /// Move one task from a dispatch queue to the local CPU's DSQ.
    #[inline(always)]
    pub fn dsq_move_to_local(&mut self, dsq_id: u64) -> bool {
        crate::kfuncs::dsq_move_to_local(dsq_id)
    }

    /// Create a user dispatch queue. Returns 0 on success, negative errno on failure.
    #[inline(always)]
    pub fn create_dsq(&mut self, dsq_id: u64, node: i32) -> i32 {
        crate::kfuncs::create_dsq(dsq_id, node)
    }

    // ── CPU operations ───────────────────────────────────────────────────

    /// Kick a CPU, optionally only if idle (`SCX_KICK_IDLE = 1`).
    #[inline(always)]
    pub fn kick_cpu(&mut self, cpu: i32, flags: u64) {
        crate::kfuncs::kick_cpu(cpu, flags);
    }

    /// Atomically test and clear the idle bit for `cpu`.
    /// Returns true if the CPU was idle.
    #[inline(always)]
    pub fn test_and_clear_cpu_idle(&mut self, cpu: i32) -> bool {
        crate::kfuncs::test_and_clear_cpu_idle(cpu)
    }

    /// Select the default idle CPU for a task.
    /// Returns the CPU and sets `*is_idle`.
    #[inline(always)]
    pub fn select_cpu_dfl(
        &mut self,
        p: *mut task_struct,
        prev_cpu: i32,
        wake_flags: u64,
        is_idle: *mut bool,
    ) -> i32 {
        crate::kfuncs::select_cpu_dfl(p, prev_cpu, wake_flags, is_idle)
    }

    /// Select an idle CPU intersected with an additional cpumask constraint.
    #[inline(always)]
    pub fn select_cpu_and(
        &mut self,
        p: *mut task_struct,
        prev_cpu: i32,
        wake_flags: u64,
        cpus_allowed: *const cpumask,
        flags: u64,
    ) -> i32 {
        crate::kfuncs::select_cpu_and(p, prev_cpu, wake_flags, cpus_allowed, flags)
    }

    /// Set the target CPU performance level (0 .. SCX_CPUPERF_ONE).
    ///
    /// Classified as `&mut self` conservatively. While this doesn't directly
    /// invalidate map pointers, it modifies kernel state.
    #[inline(always)]
    pub fn cpuperf_set(&mut self, cpu: i32, perf: u32) {
        crate::kfuncs::cpuperf_set(cpu, perf);
    }

    /// Return the task_struct of the task currently running on `cpu`.
    ///
    /// Requires kernel >= 6.15. Must be called inside an RCU read-side
    /// critical section.
    #[inline(always)]
    pub fn cpu_curr(&mut self, cpu: i32) -> *mut task_struct {
        crate::kfuncs::cpu_curr(cpu)
    }

    /// Return the `struct rq` for the given CPU.
    #[inline(always)]
    pub fn cpu_rq(&mut self, cpu: i32) -> *mut rq {
        crate::kfuncs::cpu_rq(cpu)
    }

    /// Get a read-only reference to the idle CPU mask.
    /// Must be released with [`put_cpumask`](Self::put_cpumask).
    #[inline(always)]
    pub fn get_idle_cpumask(&mut self) -> *const cpumask {
        crate::kfuncs::get_idle_cpumask()
    }

    /// Get a read-only reference to the idle SMT-sibling mask.
    /// Must be released with [`put_cpumask`](Self::put_cpumask).
    #[inline(always)]
    pub fn get_idle_smtmask(&mut self) -> *const cpumask {
        crate::kfuncs::get_idle_smtmask()
    }

    /// Release a cpumask reference obtained from `get_idle_cpumask`
    /// or `get_idle_smtmask`.
    #[inline(always)]
    pub fn put_cpumask(&mut self, mask: *const cpumask) {
        crate::kfuncs::put_cpumask(mask);
    }

    // ── Error reporting ──────────────────────────────────────────────────

    /// Report a fatal scheduler error (triggers scheduler exit).
    #[inline(always)]
    pub fn error_bstr(&mut self, fmt: *const u8, data: *const u64, data_len: u32) {
        crate::kfuncs::error_bstr(fmt, data, data_len);
    }

    // ── Kernel 6.16 kfuncs ───────────────────────────────────────────────

    /// Set a task's `dsq_vtime` (kernel >= 6.16).
    #[cfg(feature = "kernel_6_16")]
    #[inline(always)]
    pub fn task_set_dsq_vtime(&mut self, p: *mut task_struct, vtime: u64) -> bool {
        crate::kfuncs::task_set_dsq_vtime(p, vtime)
    }

    /// Set a task's scheduling `slice` (kernel >= 6.16).
    #[cfg(feature = "kernel_6_16")]
    #[inline(always)]
    pub fn task_set_slice(&mut self, p: *mut task_struct, slice: u64) -> bool {
        crate::kfuncs::task_set_slice(p, slice)
    }

    // ── Cpumask mutations ────────────────────────────────────────────────

    /// Allocate a new BPF cpumask with all bits cleared.
    #[inline(always)]
    pub fn cpumask_create(&mut self) -> *mut bpf_cpumask {
        crate::cpumask::create()
    }

    /// Release a BPF cpumask reference.
    #[inline(always)]
    pub fn cpumask_release(&mut self, mask: *mut bpf_cpumask) {
        crate::cpumask::release(mask);
    }

    /// Set the bit for `cpu` in a BPF cpumask.
    #[inline(always)]
    pub fn cpumask_set_cpu(&mut self, cpu: u32, mask: *mut bpf_cpumask) {
        crate::cpumask::set_cpu(cpu, mask);
    }

    /// Clear the bit for `cpu` in a BPF cpumask.
    #[inline(always)]
    pub fn cpumask_clear_cpu(&mut self, cpu: u32, mask: *mut bpf_cpumask) {
        crate::cpumask::clear_cpu(cpu, mask);
    }

    /// Compute `dst = src1 AND src2`. Returns true if result is non-empty.
    #[inline(always)]
    pub fn cpumask_and(
        &mut self,
        dst: *mut bpf_cpumask,
        src1: *const cpumask,
        src2: *const cpumask,
    ) -> bool {
        crate::cpumask::and(dst, src1, src2)
    }

    /// Compute `dst = src1 OR src2`.
    #[inline(always)]
    pub fn cpumask_or(
        &mut self,
        dst: *mut bpf_cpumask,
        src1: *const cpumask,
        src2: *const cpumask,
    ) {
        crate::cpumask::or(dst, src1, src2);
    }

    /// Copy all bits from `src` into `dst`.
    #[inline(always)]
    pub fn cpumask_copy(&mut self, dst: *mut bpf_cpumask, src: *const cpumask) {
        crate::cpumask::copy(dst, src);
    }

    /// Set all possible CPU bits in a cpumask.
    #[inline(always)]
    pub fn cpumask_setall(&mut self, mask: *mut bpf_cpumask) {
        crate::cpumask::setall(mask);
    }

    /// Cast a mutable `bpf_cpumask` pointer to a read-only `cpumask` pointer.
    #[inline(always)]
    pub fn cpumask_cast(&self, mask: *const bpf_cpumask) -> *const cpumask {
        crate::cpumask::cast(mask)
    }

    // ── RCU ──────────────────────────────────────────────────────────────

    /// Enter an RCU read-side critical section.
    #[inline(always)]
    pub fn rcu_read_lock(&mut self) {
        crate::kptr::rcu_read_lock();
    }

    /// Exit an RCU read-side critical section.
    #[inline(always)]
    pub fn rcu_read_unlock(&mut self) {
        crate::kptr::rcu_read_unlock();
    }

    // ── Kptr ─────────────────────────────────────────────────────────────

    /// Atomically exchange a kptr value. Returns the old pointer.
    ///
    /// # Safety
    ///
    /// - `kptr` must point to a valid kptr storage location with proper
    ///   BTF_KIND_TYPE_TAG "kptr" annotation.
    /// - `new` must be a valid owned reference or null.
    /// - The caller takes ownership of the returned old pointer.
    #[inline(always)]
    pub unsafe fn kptr_xchg<T>(&mut self, kptr: *mut Kptr<T>, new: *mut T) -> *mut T {
        crate::kptr::kptr_xchg(kptr, new)
    }

    /// Read a kptr value under RCU protection.
    ///
    /// # Safety
    ///
    /// - `this` must point to a valid `Kptr<T>`.
    /// - Must be called inside an RCU read-side critical section.
    #[inline(always)]
    pub unsafe fn kptr_get<T>(&self, this: *const Kptr<T>) -> *mut T {
        Kptr::get(this)
    }

    // ── Timers ───────────────────────────────────────────────────────────

    /// Initialize a BPF timer, associating it with its parent map and clock.
    #[inline(always)]
    pub fn timer_init(
        &mut self,
        timer: *mut BpfTimer,
        map: *const core::ffi::c_void,
        flags: u64,
    ) -> i64 {
        crate::timer::timer_init(timer, map, flags)
    }

    /// Set the callback function for a BPF timer.
    #[inline(always)]
    pub fn timer_set_callback(&mut self, timer: *mut BpfTimer, callback: u64) -> i64 {
        crate::timer::timer_set_callback(timer, callback)
    }

    /// Start (arm) a BPF timer.
    #[inline(always)]
    pub fn timer_start(&mut self, timer: *mut BpfTimer, nsecs: u64, flags: u64) -> i64 {
        crate::timer::timer_start(timer, nsecs, flags)
    }

    /// Cancel a pending BPF timer.
    #[inline(always)]
    pub fn timer_cancel(&mut self, timer: *mut BpfTimer) -> i64 {
        crate::timer::timer_cancel(timer)
    }

    // ── Map mutation operations ──────────────────────────────────────────

    /// Insert or update a key-value pair in a hash map.
    #[inline(always)]
    pub fn hash_insert<K, V, const N: usize>(
        &mut self,
        map: &maps::HashMap<K, V, N>,
        key: &K,
        value: &V,
        flags: u64,
    ) -> Result<(), i64> {
        map.insert(key, value, flags)
    }

    /// Delete an entry from a hash map.
    #[inline(always)]
    pub fn hash_delete<K, V, const N: usize>(
        &mut self,
        map: &maps::HashMap<K, V, N>,
        key: &K,
    ) -> Result<(), i64> {
        map.delete(key)
    }

    /// Set an element in a BPF array.
    #[inline(always)]
    pub fn array_set<V, const N: usize>(
        &mut self,
        map: &maps::BpfArray<V, N>,
        index: u32,
        value: &V,
        flags: u64,
    ) -> Result<(), i64> {
        map.set(index, value, flags)
    }

    /// Set the current CPU's element in a per-CPU array.
    #[inline(always)]
    pub fn percpu_array_set<V, const N: usize>(
        &mut self,
        map: &maps::PerCpuArray<V, N>,
        index: u32,
        value: &V,
        flags: u64,
    ) -> Result<(), i64> {
        map.set(index, value, flags)
    }

    /// Delete per-task storage for a task.
    #[inline(always)]
    pub fn task_storage_delete<V>(
        &mut self,
        map: &maps::TaskStorage<V>,
        task: *mut u8,
    ) -> Result<(), i64> {
        map.delete(task)
    }

    // ── bpf_loop ─────────────────────────────────────────────────────────

    /// Call a callback function for up to `nr_loops` iterations.
    ///
    /// The callback must be a named `#[inline(never)]` function (not a
    /// closure) for BPF subprogram emission.
    ///
    /// # Safety
    ///
    /// - `callback_fn` must be a valid BPF subprogram function pointer.
    /// - `callback_ctx` must point to valid memory for the callback's use.
    #[inline(always)]
    pub unsafe fn bpf_loop(
        &mut self,
        nr_loops: u32,
        callback_fn: unsafe extern "C" fn(u32, *mut core::ffi::c_void) -> i64,
        callback_ctx: *mut core::ffi::c_void,
        flags: u64,
    ) -> i64 {
        crate::helpers::bpf_loop(nr_loops, callback_fn, callback_ctx, flags)
    }

    // ── Kernel memory access ─────────────────────────────────────────────

    /// Read a value from kernel memory.
    ///
    /// # Safety
    ///
    /// `src` must point to valid kernel memory of type `T`.
    #[inline(always)]
    pub unsafe fn probe_read_kernel<T: Copy>(&mut self, src: *const T) -> Result<T, i64> {
        crate::helpers::probe_read_kernel(src)
    }

    // ── PMU / perf events ────────────────────────────────────────────────

    /// Read a perf event counter value.
    ///
    /// NOTE: Not available in struct_ops programs. Only usable from
    /// tracing program types (kprobe, tracepoint, fentry, tp_btf).
    ///
    /// # Safety
    ///
    /// - `map` must point to a valid `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
    /// - `val` must point to a valid `PerfEventValue` buffer.
    #[inline(always)]
    pub unsafe fn perf_event_read_value(
        &mut self,
        map: *const core::ffi::c_void,
        index: u64,
        val: *mut PerfEventValue,
    ) -> i64 {
        crate::pmu::perf_event_read_value(map, index, val)
    }

    /// Output a perf event record to userspace.
    ///
    /// # Safety
    ///
    /// - `ctx` must be a valid BPF program context pointer.
    /// - `map` must point to a valid `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
    /// - `data` must point to `size` bytes of readable memory.
    #[inline(always)]
    pub unsafe fn perf_event_output(
        &mut self,
        ctx: *const core::ffi::c_void,
        map: *const core::ffi::c_void,
        flags: u64,
        data: *const core::ffi::c_void,
        size: u64,
    ) -> i64 {
        crate::pmu::perf_event_output(ctx, map, flags, data, size)
    }
}
