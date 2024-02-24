# Framework to implement sched_ext schedulers running in user-space

[sched_ext](https://github.com/sched-ext/scx) is a Linux kernel feature
which enables implementing kernel thread schedulers in BPF and dynamically
loading them.

Thie crate provides a generic framework that allows to implement sched_ext
schedulers that are running in user-space.
