//! Helpers for BPF programs: kernel reads/writes and bounded iteration.
//!
//! Provides:
//! - [`bpf_for!`] / [`bpf_repeat!`] -- bounded loop macros for ergonomic iteration
//! - [`bpf_loop`] -- raw BPF helper #181 wrapper for callback-based iteration
//! - [`core_read!`] -- portable kernel struct field read via CO-RE
//! - [`core_write!`] -- portable kernel struct field write via CO-RE
//! - [`probe_read_kernel`] -- raw kernel memory reads
//!
//! ## Bounded iteration
//!
//! [`bpf_for!`] provides `for`-loop-like syntax for bounded BPF iteration:
//!
//! ```ignore
//! bpf_for!(i, 0, nr_cpus, {
//!     let cpu = unsafe { PREFERRED_CPUS[i as usize] };
//!     if cpu < 0 { break; }
//!     if kfuncs::test_and_clear_cpu_idle(cpu) {
//!         found_cpu = cpu;
//!         break;
//!     }
//! });
//! ```
//!
//! The macro emits a `while` loop with a verifier-provable bound. On
//! kernel 6.1+, the BPF verifier natively handles bounded `while` loops,
//! so no callback subprogram is needed. This means:
//! - The loop body runs **inline** -- kfunc calls, local variable access,
//!   `break`, and `return` all work naturally.
//! - No context struct or `#[inline(never)]` callback function required.
//! - No aya-55 kfunc-in-subprogram issues.
//!
//! For callback-based iteration (e.g., pre-6.1 kernels), use [`bpf_loop`]
//! directly with a named `#[inline(never)]` callback function.
//!
//! ## CO-RE field access
//!
//! [`core_read!`] and [`core_write!`] compute field offsets at compile
//! time using the vmlinux-generated struct definitions, then read/write
//! the value using `bpf_probe_read_kernel` or `write_volatile`.
//!
//! On the build kernel, the offsets are correct without any loader
//! patching. For cross-kernel portability, the `aya-core-postprocessor`
//! tool scans the compiled ELF for matching BPF instructions (ALU ADD
//! for reads, STX MEM for writes) and generates CO-RE relocation
//! records in `.BTF.ext`. The loader then patches field offsets at
//! load time.

/// BPF helper: read `len` bytes from kernel address `src` into `dst`.
///
/// This is BPF helper #113 (`bpf_probe_read_kernel`).
///
/// # LLVM BPF backend register clobber bug
///
/// BPF calling convention requires all r1-r5 to be clobbered by helper
/// calls. However, the LLVM BPF backend has a bug where it fails to
/// re-materialize argument registers (r1-r3) between consecutive inlined
/// helper calls when the arguments happen to have the same value.
///
/// For example, two back-to-back `bpf_probe_read_kernel` calls both
/// reading 4 bytes would share `r2 = 4`, and LLVM may skip emitting the
/// second `r2 = 4` instruction because it believes r2 still holds 4 from
/// the first call -- even though the BPF helper clobbered it.
///
/// Workarounds:
/// 1. Ensure consecutive reads have different sizes (e.g., read a u64
///    instead of two u32s by combining adjacent fields)
/// 2. Use `core_read!` calls that naturally read different-sized types
/// 3. The `#[inline(never)]` annotation is intended to force separate
///    subprogram calls, but LLVM may still inline the function via LTO
#[inline(never)]
unsafe fn bpf_probe_read_kernel_raw(dst: *mut u8, len: u32, src: *const u8) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "call 113",
        inlateout("r1") dst => _,
        inlateout("r2") (len as u64) => _,
        inlateout("r3") src => _,
        lateout("r0") ret,
        lateout("r4") _,
        lateout("r5") _,
    );
    ret
}

/// Reads a value of type `T` from kernel memory at `src`.
///
/// Returns `Ok(value)` on success, `Err(errno)` on failure.
#[inline(always)]
pub unsafe fn probe_read_kernel<T: Copy>(src: *const T) -> Result<T, i64> {
    let mut val = core::mem::MaybeUninit::<T>::uninit();
    let ret = unsafe {
        bpf_probe_read_kernel_raw(
            val.as_mut_ptr().cast(),
            core::mem::size_of::<T>() as u32,
            src.cast(),
        )
    };
    if ret == 0 {
        Ok(unsafe { val.assume_init() })
    } else {
        Err(ret)
    }
}

/// BPF helper: call `callback_fn(index, ctx)` for `nr_loops` iterations.
///
/// This is BPF helper #181 (`bpf_loop`), available since Linux 5.17.
/// The callback receives the current iteration index (0..nr_loops) and the
/// user-provided context pointer. Return 0 from the callback to continue,
/// 1 to break early.
///
/// Unlike a regular bounded `while` loop, the BPF verifier only analyzes the
/// callback body once regardless of `nr_loops`, making this efficient for
/// large iteration counts (e.g., iterating all CPUs on a 1024-CPU system).
///
/// `flags` must be 0.
///
/// # BPF subprogram requirement
///
/// The callback MUST be a named `#[inline(never)]` function (not a closure),
/// so that LLVM emits it as a separate BPF subprogram. The `bpf_loop` helper
/// calls the subprogram by BPF function pointer.
///
/// # Kfunc limitation (aya-55)
///
/// Due to aya bug aya-55, kfunc calls inside `#[inline(never)]` subprograms
/// are not resolved correctly (their `imm` field stays 0). If the callback
/// needs kfunc calls, use inline asm with `call {func}` / `sym` to emit the
/// kfunc call directly — OR restructure to avoid kfuncs in the callback
/// (e.g., communicate via a global variable / context struct).
///
/// # Returns
///
/// The number of iterations performed (0 on error).
#[inline(always)]
pub unsafe fn bpf_loop(
    nr_loops: u32,
    callback_fn: unsafe extern "C" fn(u32, *mut core::ffi::c_void) -> i64,
    ctx: *mut core::ffi::c_void,
    flags: u64,
) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "call 181",
        inlateout("r1") (nr_loops as u64) => _,
        inlateout("r2") callback_fn => _,
        inlateout("r3") ctx => _,
        inlateout("r4") flags => _,
        lateout("r0") ret,
        lateout("r5") _,
    );
    ret
}

/// Bounded iteration over a `start..end` range, like C's `bpf_for()`.
///
/// Expands to a `while` loop with a verifier-provable bound. The BPF
/// verifier on kernel 6.1+ natively tracks bounded `while` loops, so no
/// callback subprogram (and thus no aya-55 kfunc issues) is needed.
///
/// The loop variable is bound as a `u32`. Use `as usize` for array
/// indexing, `as i32` for signed APIs.
///
/// `break` exits the loop. `return` exits the **enclosing function**.
///
/// # Comparison with `bpf_loop`
///
/// | Feature              | `bpf_for!`        | `bpf_loop()`            |
/// |----------------------|-------------------|-------------------------|
/// | Kfunc calls in body  | Yes               | No (aya-55)             |
/// | `break` / `return`   | Natural           | Return 1 / not possible |
/// | Local variable access| Natural           | Via context struct      |
/// | Verifier cost        | Proportional to N | Constant (1 analysis)   |
/// | Min kernel version   | 6.1               | 5.17                    |
///
/// For very large iteration counts (>100K) where verifier analysis time
/// matters, prefer `bpf_loop()` with a named callback. For typical
/// scheduler loops (scanning CPUs, DSQs, NUMA nodes), `bpf_for!` is
/// simpler and more ergonomic.
///
/// # Syntax
///
/// ```ignore
/// bpf_for!(var, start, end, { body });
/// ```
///
/// Equivalent to C: `bpf_for(var, start, end) { body }`
///
/// # Examples
///
/// ```ignore
/// // Scan all CPUs for an idle one:
/// let mut found_cpu: i32 = -1;
/// bpf_for!(i, 0, nr_cpus, {
///     let cpu = unsafe { PREFERRED_CPUS[i as usize] };
///     if cpu < 0 { break; }
///     if kfuncs::test_and_clear_cpu_idle(cpu) {
///         found_cpu = cpu;
///         break;
///     }
/// });
///
/// // Create per-node dispatch queues:
/// bpf_for!(node, 0, nr_nodes, {
///     kfuncs::create_dsq(node as u64, node as i32);
/// });
/// ```
#[macro_export]
macro_rules! bpf_for {
    ($var:ident, $start:expr, $end:expr, $body:block) => {{
        let __bpf_for_end: u32 = $end;
        let mut $var: u32 = $start;
        while $var < __bpf_for_end {
            $body
            $var += 1;
        }
    }};
}

/// Bounded repetition without an index variable, like C's `bpf_repeat()`.
///
/// Executes `$body` up to `$count` times. Use `break` to exit early.
///
/// # Example
///
/// ```ignore
/// bpf_repeat!(100, {
///     if try_something() {
///         break;
///     }
/// });
/// ```
#[macro_export]
macro_rules! bpf_repeat {
    ($count:expr , $body:block) => {{
        let __bpf_repeat_end: u32 = $count;
        let mut __bpf_repeat_i: u32 = 0;
        while __bpf_repeat_i < __bpf_repeat_end {
            $body
            __bpf_repeat_i += 1;
        }
    }};
}

/// BPF helper #158: `bpf_get_current_task_btf() -> *mut task_struct`
///
/// Returns a BTF-typed pointer to the current task's `task_struct`.
/// Used to access the current task in BPF programs (e.g., to compare
/// the waker with the wakee for mm_affinity).
///
/// The return type is a raw pointer so callers can cast to their own
/// vmlinux `task_struct` type.
#[inline(always)]
pub fn get_current_task_btf() -> *mut u8 {
    let ret: *mut u8;
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
/// Returns the ID of the CPU on which the BPF program is currently
/// executing. The result is always valid and in-range for the current
/// system.
#[inline(always)]
pub fn get_smp_processor_id() -> i32 {
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

/// Maximum size of a CO-RE marker record in bytes.
///
/// Layout: tag(1) + name_len(1) + name(N) + path_len(1) + path(M).
/// 128 bytes is generous for any reasonable struct name + field path.
pub const CORE_RELO_MARKER_MAX: usize = 128;

/// Tag byte marking the start of a CO-RE relocation marker.
pub const CORE_RELO_TAG: u8 = 0xAC;

/// Result of building a CO-RE marker at compile time.
///
/// Contains the fixed-size buffer and the actual length of valid data.
pub struct CoreReloMarkerData {
    pub buf: [u8; CORE_RELO_MARKER_MAX],
    pub len: usize,
}

/// Extracts the last path segment from a stringified type path.
///
/// `stringify!(vmlinux::task_struct)` produces `"vmlinux :: task_struct"`.
/// This function returns the byte range for `"task_struct"` (skipping
/// spaces around `::` separators).
///
/// Returns `(start, end)` indices into the input byte slice.
pub const fn last_path_segment(s: &[u8]) -> (usize, usize) {
    // Walk backwards to find the last `:`
    let len = s.len();
    let mut last_colon = len; // "no colon found"
    let mut i = len;
    while i > 0 {
        i -= 1;
        if s[i] == b':' {
            last_colon = i;
            break;
        }
    }

    if last_colon == len {
        // No `::` -- strip leading/trailing spaces from the whole string
        let start = skip_spaces_forward(s, 0);
        let end = skip_spaces_backward(s, len);
        return (start, end);
    }

    // Start after the last `:`, skip spaces
    let start = skip_spaces_forward(s, last_colon + 1);
    let end = skip_spaces_backward(s, len);
    (start, end)
}

/// Removes spaces from a stringified field path.
///
/// `stringify!(scx.dsq_vtime)` produces `"scx . dsq_vtime"`.
/// This function copies the bytes without spaces into `dst` and
/// returns the number of bytes written.
pub const fn strip_spaces(src: &[u8], dst: &mut [u8]) -> usize {
    let mut out = 0;
    let mut i = 0;
    while i < src.len() {
        if src[i] != b' ' {
            dst[out] = src[i];
            out += 1;
        }
        i += 1;
    }
    out
}

const fn skip_spaces_forward(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && s[i] == b' ' {
        i += 1;
    }
    i
}

const fn skip_spaces_backward(s: &[u8], mut i: usize) -> usize {
    while i > 0 && s[i - 1] == b' ' {
        i -= 1;
    }
    i
}

/// Builds a CO-RE marker record at compile time.
///
/// The marker format (matching `marker_parser.rs`):
///   - 1 byte:  tag `0xAC`
///   - 1 byte:  struct name length (N)
///   - N bytes: struct name (UTF-8)
///   - 1 byte:  field path length (M)
///   - M bytes: field path (dot-separated, UTF-8)
pub const fn build_core_relo_marker(
    type_str: &[u8],      // e.g. b"vmlinux :: task_struct"
    field_str: &[u8],     // e.g. b"scx . dsq_vtime"
) -> CoreReloMarkerData {
    let mut buf = [0u8; CORE_RELO_MARKER_MAX];

    // Extract struct name (last path segment, e.g., "task_struct")
    let (seg_start, seg_end) = last_path_segment(type_str);
    let name_len = seg_end - seg_start;

    // Strip spaces from field path
    // First compute stripped length, then copy
    let mut field_buf = [0u8; CORE_RELO_MARKER_MAX];
    let field_len = strip_spaces(field_str, &mut field_buf);

    // Build the marker
    let mut pos = 0;

    // Tag
    buf[pos] = CORE_RELO_TAG;
    pos += 1;

    // Struct name length
    buf[pos] = name_len as u8;
    pos += 1;

    // Struct name bytes
    let mut i = 0;
    while i < name_len {
        buf[pos] = type_str[seg_start + i];
        pos += 1;
        i += 1;
    }

    // Field path length
    buf[pos] = field_len as u8;
    pos += 1;

    // Field path bytes
    i = 0;
    while i < field_len {
        buf[pos] = field_buf[i];
        pos += 1;
        i += 1;
    }

    CoreReloMarkerData { buf, len: pos }
}

/// Write a value to a kernel struct field using compile-time offsets.
///
/// Uses `core::ptr::write_volatile` to write the value at the computed
/// field offset. The offset is determined at compile time from the
/// vmlinux-generated struct definitions via `offset_of!`.
///
/// # CO-RE portability
///
/// This macro emits a marker record into an `.aya.core_relo` ELF section
/// that the `aya-core-postprocessor` tool reads. The post-processor
/// generates `bpf_core_relo` records in `.BTF.ext` so that aya's
/// `relocate_btf()` can patch the `off` field at load time.
///
/// # Arguments
///
/// - `$struct_ty`: The vmlinux-generated struct type (e.g., `vmlinux::task_struct`)
/// - `$ptr`: A mutable pointer to the kernel struct
/// - `$($field).+`: The field path (e.g., `scx.dsq_vtime`)
/// - `$val`: The value to write (must match the field type)
///
/// # Example
///
/// ```ignore
/// // Write dsq_vtime:
/// core_write!(vmlinux::task_struct, p, scx.dsq_vtime, new_vtime);
///
/// // Write slice:
/// core_write!(vmlinux::task_struct, p, scx.slice, slice_ns);
/// ```
#[macro_export]
macro_rules! core_write {
    ($struct_ty:ty, $ptr:expr, $($field:ident).+, $val:expr) => {{
        // Emit CO-RE marker for postprocessor discovery.
        const _: () = {
            const __MARKER: $crate::helpers::CoreReloMarkerData =
                $crate::helpers::build_core_relo_marker(
                    stringify!($struct_ty).as_bytes(),
                    stringify!($($field).+).as_bytes(),
                );

            #[unsafe(link_section = ".aya.core_relo")]
            #[used]
            static __CORE_RELO: [u8; __MARKER.len] = {
                let mut out = [0u8; __MARKER.len];
                let mut i = 0;
                while i < __MARKER.len {
                    out[i] = __MARKER.buf[i];
                    i += 1;
                }
                out
            };
        };

        let base = $ptr as *mut u8;
        let offset = core::mem::offset_of!($struct_ty, $($field).+);
        let field_ptr = unsafe { base.add(offset) } as *mut _;
        // write_volatile: the pointer type is inferred from $val,
        // ensuring the correct store width (e.g. STX_MEM_DW for u64).
        unsafe { core::ptr::write_volatile(field_ptr, $val) }
    }};
}

/// Read a field from a kernel struct pointer using compile-time offsets.
///
/// Uses `bpf_probe_read_kernel` to safely read the field value. The
/// offset is computed at compile time from the vmlinux-generated struct
/// definitions, so it is correct for the kernel the program was built on.
///
/// The struct type and field path determine both the offset and the
/// return type via type inference.
///
/// # CO-RE portability
///
/// This macro emits a marker record into an `.aya.core_relo` ELF section
/// that the `aya-core-postprocessor` tool reads. The post-processor
/// generates `bpf_core_relo` records in `.BTF.ext` so that aya's
/// `relocate_btf()` can patch the field offsets for different kernels.
///
/// The marker encodes:
///   - The struct type name (e.g. "task_struct")
///   - The field path (e.g. "scx.dsq_vtime")
///
/// # Arguments
///
/// - `$struct_ty`: The vmlinux-generated struct type (e.g., `vmlinux::task_struct`)
/// - `$ptr`: A pointer to the kernel struct (any pointer type, cast internally)
/// - `$($field).+`: The field path (e.g., `scx.dsq_vtime`)
///
/// # Returns
///
/// `Result<FieldType, i64>` -- the field value or a BPF error code.
///
/// # Example
///
/// ```ignore
/// mod vmlinux { include!(concat!(env!("OUT_DIR"), "/vmlinux.rs")); }
///
/// // Read a nested field:
/// let vtime: u64 = core_read!(vmlinux::task_struct, p, scx.dsq_vtime)?;
///
/// // Read a simple field:
/// let pid: i32 = core_read!(vmlinux::task_struct, p, pid)?;
/// ```
#[macro_export]
macro_rules! core_read {
    ($struct_ty:ty, $ptr:expr, $($field:ident).+) => {{
        // Emit CO-RE marker for postprocessor discovery.
        const _: () = {
            const __MARKER: $crate::helpers::CoreReloMarkerData =
                $crate::helpers::build_core_relo_marker(
                    stringify!($struct_ty).as_bytes(),
                    stringify!($($field).+).as_bytes(),
                );

            #[unsafe(link_section = ".aya.core_relo")]
            #[used]
            static __CORE_RELO: [u8; __MARKER.len] = {
                let mut out = [0u8; __MARKER.len];
                let mut i = 0;
                while i < __MARKER.len {
                    out[i] = __MARKER.buf[i];
                    i += 1;
                }
                out
            };
        };

        // Compute the field pointer using offset_of and raw pointer arithmetic.
        let base = $ptr as *const u8;
        let offset = core::mem::offset_of!($struct_ty, $($field).+);

        // Use a null pointer to infer the field type, then read from the real address
        let typed_field_ptr = unsafe {
            &raw const (*(base as *const $struct_ty)).$($field).+
        };
        // typed_field_ptr points to the right offset with the right type
        unsafe { $crate::helpers::probe_read_kernel(typed_field_ptr) }
    }};
}
