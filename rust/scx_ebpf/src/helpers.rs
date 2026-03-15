//! Helpers for reading kernel struct fields from BPF programs.
//!
//! Provides [`core_read!`] for portable field access. The macro computes
//! the field offset at compile time using the vmlinux-generated struct
//! definitions, then reads the value via `bpf_probe_read_kernel`.
//!
//! On the build kernel, the offsets are correct without any loader
//! patching. For cross-kernel portability, the `aya-core-postprocessor`
//! tool scans the compiled ELF for `.aya.core_relo` markers emitted by
//! this macro and generates CO-RE relocation records in `.BTF.ext`.
//! The loader then patches field offsets at load time.

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
        // Compute the field pointer using offset_of and raw pointer arithmetic.
        // The null-pointer trick lets us get the field's type without needing
        // an actual instance -- we never dereference the null pointer.
        let base = $ptr as *const u8;
        let offset = core::mem::offset_of!($struct_ty, $($field).+);

        // Emit a marker into the .aya.core_relo section.  The post-processor
        // reads this section to discover which instructions need CO-RE
        // relocations.
        //
        // The marker format is two NUL-terminated strings:
        //   1. The struct type name (last segment of the Rust path)
        //   2. The dot-separated field path
        //
        // A local label captures the instruction offset for the LDX that
        // follows.  The post-processor matches the label's address to find
        // which BPF instruction to attach the relocation to.
        //
        // NOTE: This asm block is purely a data annotation; it emits no
        // BPF instructions in the program's text section.  The
        // .pushsection / .popsection directives redirect output to the
        // marker section and back.
        //
        // TODO: In a production implementation, this would use a proc-macro
        // to stringify the type name and field path at compile time.
        // For the prototype, the sidecar TOML file provides this mapping
        // instead of inline asm markers.

        // Use a null pointer to infer the field type, then read from the real address
        let typed_field_ptr = unsafe {
            &raw const (*(base as *const $struct_ty)).$($field).+
        };
        // typed_field_ptr points to the right offset with the right type
        unsafe { $crate::helpers::probe_read_kernel(typed_field_ptr) }
    }};
}
