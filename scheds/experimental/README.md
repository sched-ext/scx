RUST SCHEDULERS
===============

# Introduction

This directory contains schedulers with user space `Rust` components.

The README in each scheduler directory provides background information and
describes the types of workloads or scenarios they are designed to handle.
For more details on any of these schedulers, please refer to the header
comments in their `main.rs` or `*.bpf.c` files.

> ⚠️ **Warning**
>
> The schedulers in this directory are experimental and may be incomplete,
> unstable, or contain bugs. They are primarily intended for development,
> testing, and experimentation.
>
> Running these schedulers on production systems is **not recommended**.
> Use at your own risk.

# Schedulers

- [scx_flow](scx_flow/README.md)
- [scx_rlfifo](scx_rlfifo/README.md)
- [scx_rake](scx_rake/README.md): scx_cake's policy written in Rust BPF, with owner queues, per-LLC wake pools and seats
- [scx_reevdf](scx_reevdf/README.md): EEVDF cid-form scheduler written in Rust BPF, a port of scx_eevdf
- [scx_rburst](scx_rburst/README.md): EEVDF-style scheduler with virtual-time borrowing, whose requests follow the CPU burst, written in Rust BPF
- [scx_rlocal](scx_rlocal/README.md): per-CPU queues with stealing inside the LLC, written in Rust BPF, with typed per-CID state
- [scx_rvtime](scx_rvtime/README.md): weighted vtime scheduler written in Rust BPF, with typed per-task state
