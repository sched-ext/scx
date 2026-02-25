//! Compatibility shims for Rust BPF struct_ops.
//!
//! Everything in this module works around limitations in the current Rust
//! BPF toolchain. When aya gains native struct_ops support, this entire
//! module should be replaced by:
//!
//! - Auto-generated vmlinux types (aya-gen or equivalent)
//! - Native kfunc call support (no inline asm)
//! - Procedural macros for struct_ops callback registration
//!
//! Until then, this module provides:
//!
//! - [`vmlinux`]: Opaque kernel type stubs
//! - [`kfuncs`]: Safe wrappers around BPF kfunc calls (hides inline asm)
//! - [`struct_ops`]: `sched_ext_ops` definition, callback trampolines, ops map

pub mod kfuncs;
pub mod struct_ops;
pub mod vmlinux;

// ── GPL license (required for BPF) ──────────────────────────────────────

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static _license: [u8; 4] = *b"GPL\0";

// ── Panic handler (required for no_std) ─────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
