# scx_rlocal

A scheduler with one queue per CPU on `scx_rustsched`, the runtime for
schedulers whose BPF program is written in Rust. It is the example of a
scheduler that works over the topology: a typed state per CID, a loop over
the CIDs of an LLC, and a function the verifier checks once.

## Overview

A task waits on the queue of the CPU it was placed on, ordered by weighted
virtual time, so it tends to run where its cache is. The queues are in
the arena, not kernel DSQs, so any CPU can look into any of them. Each
queue keeps its own virtual time, and a task that arrives from another
queue is placed close to where the new one is.

A waking task looks for an idle CPU in the LLC of its last one: a core
that is idle as a whole first, then any idle CPU. A CPU whose queue is
empty takes a task from another queue of its LLC, and an enqueue wakes an
idle CPU of the LLC to do so. Nothing moves a task between two CPUs that
both stay busy.

The scheduler is `bpf/src/main.rs`.

## Build and run

Building needs Rust with `rust-src`, a `bpf-linker` built against the same
LLVM as the Rust compiler, `llvm-objcopy` and `llvm-nm`. Without them the
build warns and the binary refuses to start. Running needs a kernel with
`sched_ext_ops_cid` and BPF arenas.

```sh
cargo build --release -p scx_rlocal
sudo target/release/scx_rlocal
```

`--help` lists the options.
