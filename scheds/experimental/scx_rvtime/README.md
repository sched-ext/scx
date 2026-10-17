# scx_rvtime

A weighted virtual time scheduler on `scx_rustsched`, the runtime for
schedulers whose BPF program is written in Rust. It is what scx_simple is in
C, and the smallest example of a scheduler that keeps state of its own: a
global, and a typed state per task in the arena.

## Overview

Every task waits in one queue ordered by virtual time. A task's virtual
time advances with the time it ran, scaled inversely by its weight, so a
task with a higher weight gets more of the CPU. A task that slept comes
back a little behind the queue, so that it runs soon without starving the
rest. A waking task that finds an idle CPU in its LLC goes straight to it.

The scheduler is `bpf/src/main.rs`. The loader,
`src/main.rs`, is its options and one macro, and `build.rs` builds the BPF
side.

## Build and run

Building needs Rust with `rust-src`, a `bpf-linker` built against the same
LLVM as the Rust compiler, `llvm-objcopy` and `llvm-nm`. Without them the
build warns and the binary refuses to start. Running needs a kernel with
`sched_ext_ops_cid` and BPF arenas.

```sh
cargo build --release -p scx_rvtime
sudo target/release/scx_rvtime
```

`--help` lists the options. `rust/scx_rustsched/README.md` describes how to
write a scheduler on the runtime.
