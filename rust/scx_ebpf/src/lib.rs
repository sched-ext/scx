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
pub mod maps;
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

/// Report a fatal scheduler error with a static message.
///
/// This macro copies the string to a stack-allocated buffer before passing
/// it to `scx_bpf_error_bstr`. This is necessary because BPF string
/// literals live in `.rodata` maps which are read-only, and the kernel
/// verifier forbids passing read-only map pointers to kfuncs that expect
/// writable `char *` parameters.
///
/// The C equivalent uses `static char ___fmt[] = fmt;` in the
/// `scx_bpf_bstr_preamble` macro to place the string in `.data` (writable).
///
/// We write the format string to the stack using inline asm to avoid the
/// compiler generating `memset`/`memcpy` intrinsics whose alignment
/// handling the BPF verifier cannot track.
///
/// # Example
///
/// ```ignore
/// scx_bpf_error!("cosmos: failed to create shared DSQ");
/// ```
#[macro_export]
macro_rules! scx_bpf_error {
    ($msg:expr) => {{
        // Encode the message as a 64-byte stack buffer using inline asm.
        // This avoids memset/memcpy intrinsics that confuse the BPF verifier.
        const __MSG_BYTES: &[u8] = concat!($msg, "\0").as_bytes();

        // Pack the message into u64 words at compile time.
        const fn pack_word(bytes: &[u8], word_idx: usize) -> u64 {
            let start = word_idx * 8;
            let mut val: u64 = 0;
            let mut i = 0usize;
            while i < 8 {
                if start + i < bytes.len() {
                    val |= (bytes[start + i] as u64) << (i * 8);
                }
                i += 1;
            }
            val
        }

        // Pack up to 8 words (64 bytes). Truncate messages > 63 chars.
        const W0: u64 = pack_word(__MSG_BYTES, 0);
        const W1: u64 = pack_word(__MSG_BYTES, 1);
        const W2: u64 = pack_word(__MSG_BYTES, 2);
        const W3: u64 = pack_word(__MSG_BYTES, 3);
        const W4: u64 = pack_word(__MSG_BYTES, 4);
        const W5: u64 = pack_word(__MSG_BYTES, 5);
        const W6: u64 = pack_word(__MSG_BYTES, 6);
        const W7: u64 = pack_word(__MSG_BYTES, 7);

        // Write the packed words to the stack and call error_bstr,
        // all via inline asm to prevent the compiler from generating
        // memset/memcpy.
        unsafe {
            core::arch::asm!(
                // Write 8 words (64 bytes) to the stack at fp-72..fp-8
                // (fp-8 is data[0], the rest is the format string)
                "*(u64 *)(r10 - 72) = r1",
                "*(u64 *)(r10 - 64) = r2",
                "*(u64 *)(r10 - 56) = r3",
                "*(u64 *)(r10 - 48) = r4",
                "*(u64 *)(r10 - 40) = r5",
                // We ran out of input registers (BPF has r1-r5 for args).
                // Write the remaining words using r0 as a temp.
                "r0 = {w5}",
                "*(u64 *)(r10 - 32) = r0",
                "r0 = {w6}",
                "*(u64 *)(r10 - 24) = r0",
                "r0 = {w7}",
                "*(u64 *)(r10 - 16) = r0",
                // data[0] = 0 at fp-8
                "r0 = 0",
                "*(u64 *)(r10 - 8) = r0",
                // Set up the call: r1 = fmt (fp-72), r2 = data (fp-8), r3 = 8
                "r1 = r10",
                "r1 += -72",
                "r2 = r10",
                "r2 += -8",
                "r3 = 8",
                "call {error_fn}",
                in("r1") W0,
                in("r2") W1,
                in("r3") W2,
                in("r4") W3,
                in("r5") W4,
                w5 = in(reg) W5,
                w6 = in(reg) W6,
                w7 = in(reg) W7,
                error_fn = sym $crate::kfuncs::__raw::scx_bpf_error_bstr,
                lateout("r0") _,
                lateout("r1") _,
                lateout("r2") _,
                lateout("r3") _,
                lateout("r4") _,
                lateout("r5") _,
            );
        }
    }};
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
