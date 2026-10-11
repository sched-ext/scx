# scx_rustsched_build

Build script support for a Rust BPF sched_ext scheduler. The scheduler's
build.rs fills a `Spec`, the BPF crate's manifest and name, the kfunc
catalog, the ksyms it reads and the object variants, and calls `build()`,
or calls `build_default()` when it uses nothing beyond the runtime's.
That builds the crate for the BPF target with the toolchain that builds
the scheduler, or the rustup toolchain `BPF_RUST_TOOLCHAIN` names, adds
to each object's BTF what the Rust toolchain does not emit (the kfunc
prototypes, the ksyms and an `arg:trusted` tag on every task parameter of
a global function), and weakens the symbols a kernel may lack.

The BPF target has no prebuilt `core`, so it is built from `rust-src`,
and `bpf-linker` reads the compiler's LLVM bitcode, so it must be built
against the same LLVM. A distribution builds both against its own. The
build uses unstable features, build-std among them, which it enables
with `RUSTC_BOOTSTRAP=1`, so a stable compiler does. On a host without
the toolchain the objects are left empty and the scheduler refuses to
start, so that workspace builds do not need it.
