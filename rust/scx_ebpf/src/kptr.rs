//! BPF kptr (kernel pointer) support for Rust BPF programs.
//!
//! In C BPF, a kptr is declared with the `__kptr` attribute:
//! ```c
//! private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask;
//! ```
//!
//! The `__kptr` annotation causes clang to emit a `BTF_KIND_TYPE_TAG` with
//! value `"kptr"` on the pointer type. The BPF verifier reads this tag
//! to enable reference tracking: it knows the pointer holds a kernel-managed,
//! reference-counted object and enforces proper acquire/release semantics.
//!
//! # The BTF problem
//!
//! The Rust BPF compiler (rustc targeting bpfel-unknown-none) does **not**
//! emit `BTF_KIND_TYPE_TAG` annotations. Without this tag, the verifier
//! treats kptr globals as ordinary pointers and rejects `bpf_kptr_xchg()`
//! calls with errors like:
//!
//! ```text
//! arg#0 expected pointer to map value
//! ```
//!
//! or
//!
//! ```text
//! R1 doesn't point to kptr
//! ```
//!
//! The verifier specifically looks for `BTF_KIND_TYPE_TAG "kptr"` in the
//! map value's BTF when validating `bpf_kptr_xchg()`. Without it, the
//! pointer is not recognized as a kptr at all.
//!
//! # Workaround strategies
//!
//! Since the Rust compiler cannot produce the needed BTF encoding, there
//! are several possible workarounds:
//!
//! 1. **Loader-side BTF patching** (recommended): The aya loader or
//!    `aya-core-postprocessor` can inject `BTF_KIND_TYPE_TAG "kptr"` into
//!    the program's BTF before loading. This is analogous to how CO-RE
//!    relocations are post-processed.
//!
//! 2. **Inline asm `.BTF` section injection**: Emit raw BTF bytes via
//!    `core::arch::global_asm!` into the `.BTF` section. This is fragile
//!    because it must match the compiler-generated BTF layout exactly.
//!
//! 3. **Map-based storage**: Instead of a global kptr, store the pointer
//!    in a BPF array map value. The verifier checks the map value's BTF
//!    for `TYPE_TAG "kptr"` annotations, so this has the same fundamental
//!    BTF problem.
//!
//! # What this module provides
//!
//! This module provides the runtime primitives that would be needed once
//! the BTF problem is solved:
//!
//! - [`Kptr<T>`]: A `#[repr(C)]` wrapper for kptr-annotated pointers
//! - [`kptr_xchg`]: Wrapper around BPF helper #194 (`bpf_kptr_xchg`)
//! - [`rcu_read_lock`] / [`rcu_read_unlock`]: RCU critical section helpers
//!
//! # Example (will work once BTF patching is implemented)
//!
//! ```ignore
//! use scx_ebpf::kptr::{Kptr, kptr_xchg, rcu_read_lock, rcu_read_unlock};
//! use scx_ebpf::cpumask::{self, bpf_cpumask};
//!
//! // Global kptr storage (needs BTF_KIND_TYPE_TAG "kptr" annotation)
//! #[unsafe(no_mangle)]
//! static mut PRIMARY_CPUMASK: Kptr<bpf_cpumask> = Kptr::zeroed();
//!
//! // Initialize in ops.init:
//! fn init_primary_cpumask() -> i32 {
//!     let mask = cpumask::create();
//!     if mask.is_null() {
//!         return -12; // ENOMEM
//!     }
//!     unsafe {
//!         let old = kptr_xchg(&raw mut PRIMARY_CPUMASK, mask);
//!         if !old.is_null() {
//!             cpumask::release(old);
//!         }
//!     }
//!     0
//! }
//!
//! // Read under RCU protection:
//! fn read_primary_cpumask() {
//!     rcu_read_lock();
//!     let mask = unsafe { Kptr::get(&raw const PRIMARY_CPUMASK) };
//!     if !mask.is_null() {
//!         let ro = cpumask::cast(mask);
//!         // ... use the cpumask ...
//!     }
//!     rcu_read_unlock();
//! }
//! ```

/// A kernel-managed reference-counted pointer (BPF kptr).
///
/// In C BPF, declared as `struct T __kptr *name`. The BPF verifier tracks
/// references through this pointer and ensures proper acquire/release
/// semantics.
///
/// # BTF encoding requirement
///
/// For the verifier to recognize this as a kptr, the BTF for this type
/// must include a `BTF_KIND_TYPE_TAG` with value `"kptr"` wrapping the
/// pointer type. The type chain should look like:
///
/// ```text
/// VAR "PRIMARY_CPUMASK" -> PTR -> TYPE_TAG "kptr" -> STRUCT "bpf_cpumask"
/// ```
///
/// The Rust BPF compiler does not emit `TYPE_TAG`, so this must be
/// injected by a post-processor or loader.
///
/// # Memory layout
///
/// `Kptr<T>` is `#[repr(C)]` with a single `*mut T` field, so it has
/// the same layout as a raw pointer. This means a `static mut Kptr<T>`
/// in `.data` or `.bss` is laid out identically to the C equivalent
/// `struct T __kptr *`.
#[repr(C)]
pub struct Kptr<T> {
    ptr: *mut T,
}

/// Safety: Kptr is used in BPF global statics which must be Sync.
/// Access is inherently single-threaded in BPF (per-CPU execution with
/// preemption disabled), and kptr_xchg provides atomic exchange.
unsafe impl<T> Sync for Kptr<T> {}

impl<T> Kptr<T> {
    /// Create a zeroed (null) kptr. Used for static initialization.
    pub const fn zeroed() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
        }
    }

    /// Read the raw pointer value.
    ///
    /// # Safety
    ///
    /// - `this` must point to a valid `Kptr<T>` (e.g., obtained via
    ///   `&raw const GLOBAL_KPTR`)
    /// - The returned pointer is only valid within an RCU read-side
    ///   critical section (between `rcu_read_lock()` and `rcu_read_unlock()`).
    ///   The kernel guarantees the referenced object won't be freed while
    ///   RCU read lock is held.
    #[inline(always)]
    pub unsafe fn get(this: *const Self) -> *mut T {
        // Use volatile read to prevent the compiler from caching/eliding
        // the load. The kptr value can change due to bpf_kptr_xchg from
        // another BPF program invocation.
        core::ptr::read_volatile(&raw const (*this).ptr)
    }

}

// ── bpf_kptr_xchg (BPF helper #194) ────────────────────────────────────

/// Atomically exchange a kptr value. Returns the old pointer.
///
/// This is a wrapper around BPF helper #194 (`bpf_kptr_xchg`).
///
/// The caller is responsible for releasing the returned old pointer
/// (if non-null) using the appropriate release function (e.g.,
/// `bpf_cpumask_release()` for cpumasks).
///
/// # Arguments
///
/// - `kptr`: Raw pointer to the kptr storage location. Obtain via
///   `&raw mut GLOBAL_KPTR` to avoid creating a mutable reference
///   to a static mut.
/// - `new`: The new pointer value to store
///
/// # Returns
///
/// The old pointer value that was in the kptr slot. May be null if
/// the slot was previously empty.
///
/// # Safety
///
/// - `kptr` must point to a valid kptr storage location (a global or
///   map value field with proper BTF_KIND_TYPE_TAG "kptr" annotation)
/// - `new` must be a valid owned reference obtained from a creation
///   function (e.g., `bpf_cpumask_create()`) or null
/// - The caller takes ownership of the returned old pointer and must
///   release it
#[inline(always)]
pub unsafe fn kptr_xchg<T>(kptr: *mut Kptr<T>, new: *mut T) -> *mut T {
    let ret: *mut T;
    core::arch::asm!(
        "call 194",
        inlateout("r1") kptr => _,
        inlateout("r2") new => _,
        lateout("r0") ret,
        lateout("r3") _,
        lateout("r4") _,
        lateout("r5") _,
    );
    ret
}

// ── RCU read lock/unlock (BPF kfuncs) ───────────────────────────────────

// Kfunc extern declarations used as sym targets in inline asm.
unsafe extern "C" {
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

/// Enter an RCU read-side critical section.
///
/// While the RCU read lock is held, kernel objects referenced through
/// kptrs are guaranteed not to be freed. This is required for safe
/// access to kptr values.
///
/// Must be paired with a call to [`rcu_read_unlock`]. BPF programs
/// must not sleep or call blocking helpers between lock and unlock.
///
/// # Example
///
/// ```ignore
/// rcu_read_lock();
/// let mask = unsafe { Kptr::get(&raw const PRIMARY_CPUMASK) };
/// if !mask.is_null() {
///     cpumask::set_cpu(0, mask);
/// }
/// rcu_read_unlock();
/// ```
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::rcu_read_lock()`](crate::ctx::BpfCtx::rcu_read_lock) for safe access.
#[inline(always)]
pub unsafe fn rcu_read_lock() {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_rcu_read_lock,
            lateout("r0") _,
            lateout("r1") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

/// Exit an RCU read-side critical section.
///
/// Must be paired with a preceding [`rcu_read_lock`] call. After this
/// call, kptr-referenced objects may be freed by the kernel, so any
/// pointers obtained via `Kptr::get()` become invalid.
///
/// # Safety
/// Caller must ensure this is called from a valid BPF program context.
/// Prefer using [`BpfCtx::rcu_read_unlock()`](crate::ctx::BpfCtx::rcu_read_unlock) for safe access.
#[inline(always)]
pub unsafe fn rcu_read_unlock() {
    unsafe {
        core::arch::asm!(
            "call {func}",
            func = sym bpf_rcu_read_unlock,
            lateout("r0") _,
            lateout("r1") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
            lateout("r5") _,
        );
    }
}

// ── BTF annotation notes ────────────────────────────────────────────────
//
// For reference, here is the BTF type chain that clang emits for:
//   `private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask;`
//
// The DATASEC entry for the variable looks like:
//
//   [N] DATASEC '.data' size=8
//       type_id=M vlen=1
//       [M] VAR 'primary_cpumask' type_id=P linkage=static
//       [P] PTR '(anon)' type_id=T
//       [T] TYPE_TAG 'kptr' type_id=S
//       [S] STRUCT 'bpf_cpumask' size=...
//
// The TYPE_TAG 'kptr' (BTF kind 18, introduced in kernel 5.17) is the
// critical piece. It signals to the verifier that:
// 1. This pointer holds a kernel-managed reference
// 2. bpf_kptr_xchg() is valid on this location
// 3. The kernel should clean up the reference on program unload
//
// The `private(COSMOS)` part maps to DECL_TAG with value "cosmos"
// attached to the DATASEC, which creates a "privacy scope" for the
// variable. Multiple kptrs with the same DECL_TAG value share the
// same scope. This is less critical for correctness -- the verifier
// works without it.
//
// POST-PROCESSOR APPROACH:
//
// The aya-core-postprocessor can add TYPE_TAG "kptr" to the BTF by:
// 1. Finding VAR entries in DATASEC for variables of type Kptr<T>
// 2. The VAR will reference a STRUCT type (Kptr) with a single PTR field
// 3. Insert a new TYPE_TAG type with string "kptr" pointing to the
//    inner struct T
// 4. Modify the PTR to point to the TYPE_TAG instead of directly to T
// 5. Optionally "unwrap" the Kptr struct so the DATASEC entry's type
//    chain is PTR -> TYPE_TAG -> STRUCT (matching clang output)
//
// This is viable because:
// - The post-processor already modifies BTF for CO-RE relocations
// - TYPE_TAG is a simple type that just wraps another type with a string
// - The Kptr<T> struct is a known pattern that can be detected
//
// A sidecar annotation file (like the CO-RE TOML) could specify which
// globals need kptr annotation:
//
//   [[kptr]]
//   variable = "PRIMARY_CPUMASK"
//   section = ".data"
