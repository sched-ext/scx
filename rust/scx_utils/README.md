# Utility collection for sched_ext schedulers

[sched_ext](https://github.com/sched-ext/scx) is a Linux kernel feature
which enables implementing kernel thread schedulers in BPF and dynamically
loading them.

This crate is a collection of utilities for sched_ext scheduler
implementations which use Rust for userspace component. This enables
implementing hot paths in BPF while offloading colder and more complex
operations to userspace Rust code which can be significantly more convenient
and powerful.

Please see [documentation](https://docs.rs/scx_utils/latest/scx_utils/) for
more details.
