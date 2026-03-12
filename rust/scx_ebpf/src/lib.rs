//! Shared eBPF-side support for pure-Rust sched_ext schedulers.
//!
//! This crate provides the boilerplate needed to build a sched_ext
//! scheduler in pure Rust eBPF:
//!
//! - [`ops`]: `sched_ext_ops` struct definition matching kernel BTF
//! - [`kfuncs`]: Safe wrappers around `scx_bpf_*` kernel functions
//! - [`vmlinux`]: Opaque kernel type stubs
//! - [`scx_ops_define!`]: Proc macro to register callbacks and generate trampolines
//!
//! # Example
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//! use scx_ebpf::prelude::*;
//!
//! fn my_enqueue(p: *mut core::ffi::c_void, enq_flags: u64) {
//!     kfuncs::dsq_insert(p as _, 0, kfuncs::SLICE_DFL, enq_flags);
//! }
//!
//! fn my_init() -> i32 { kfuncs::create_dsq(0, -1) }
//! fn my_exit(_ei: *mut core::ffi::c_void) {}
//!
//! scx_ebpf::scx_ops_define! {
//!     name: "my_sched",
//!     enqueue: my_enqueue,
//!     init: my_init,
//!     exit: my_exit,
//! }
//! ```

#![no_std]
#![feature(asm_experimental_arch)]

pub mod helpers;
pub mod kfuncs;
pub mod ops;
pub mod vmlinux;

/// Proc macro for registering sched_ext callbacks and generating trampolines.
pub use scx_ebpf_derive::scx_ops_define;

/// Re-exports for convenient glob import.
pub mod prelude {
    pub use crate::kfuncs;
    pub use crate::ops::{DEFAULT_OPS, sched_ext_ops};
    pub use crate::vmlinux::{scx_exit_info, task_struct};
}

/// Emits the GPL license section and panic handler required by all BPF programs.
///
/// Call this once in your eBPF binary's `main.rs`.
#[macro_export]
macro_rules! scx_ebpf_boilerplate {
    () => {
        #[unsafe(link_section = "license")]
        #[unsafe(no_mangle)]
        static _license: [u8; 4] = *b"GPL\0";

        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo) -> ! {
            unsafe { core::hint::unreachable_unchecked() }
        }
    };
}
