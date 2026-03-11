//! Opaque kernel type stubs.
//!
//! HACK: These are placeholder definitions for kernel structs. Each
//! contains a dummy scalar field because the BPF verifier's kfunc CO-RE
//! validation requires struct types with at least one resolvable field.
//!
//! With proper vmlinux BTF bindings (like aya-gen), these would be
//! auto-generated with full field layouts.

#[repr(C)]
pub struct task_struct {
    _opaque: i32,
}

#[repr(C)]
pub struct scx_exit_info {
    _opaque: i32,
}
