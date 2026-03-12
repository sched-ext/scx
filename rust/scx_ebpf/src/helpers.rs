//! Helpers for reading kernel struct fields from BPF programs.
//!
//! Provides [`core_read!`] for portable field access. The macro computes
//! the field offset at compile time using the vmlinux-generated struct
//! definitions, then reads the value via `bpf_probe_read_kernel`.
//!
//! On the build kernel, the offsets are correct without any loader
//! patching. For cross-kernel portability, a future post-processor
//! could emit CO-RE relocation records that the loader patches.

/// BPF helper: read `len` bytes from kernel address `src` into `dst`.
///
/// This is BPF helper #113 (`bpf_probe_read_kernel`).
#[inline(always)]
unsafe fn bpf_probe_read_kernel_raw(dst: *mut u8, len: u32, src: *const u8) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "call 113",
        in("r1") dst,
        in("r2") len as u64,
        in("r3") src,
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
/// # Arguments
///
/// - `$struct_ty`: The vmlinux-generated struct type (e.g., `vmlinux::task_struct`)
/// - `$ptr`: A pointer to the kernel struct (any pointer type, cast internally)
/// - `$($field).+`: The field path (e.g., `scx.dsq_vtime`)
///
/// # Returns
///
/// `Result<FieldType, i64>` — the field value or a BPF error code.
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
        // an actual instance — we never dereference the null pointer.
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
