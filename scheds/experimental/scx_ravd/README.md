# scx_ravd

scx_ravd, scx Rust LAVD, is a port of `scx_lavd` to Rust: the
Latency-criticality Aware Virtual Deadline scheduler with both its BPF
program and its userspace loader written in Rust. There is no BPF C source,
no generated skeleton and no Aya dependency; the build uses bpf-linker. It
runs on the Rust BPF runtime under `rust/`, `scx_rustsched` and its loader,
as `scx_reevdf` does for `scx_eevdf`.

## Overview

LAVD measures how latency-critical a task is from how it behaves. A task
that waits often (it consumes events), wakes others often (it produces
them) and runs briefly is in the middle of a task chain, and delaying it
delays the chain. That criticality sets the task's virtual deadline, the
tighter the more critical, and the task with the earliest deadline runs
next. Its time slice is sized so that every runnable task runs within a
targeted latency, and boosted for tasks that need longer. A task that has
had more than its fair share of CPU time is penalized in its deadline, and
an urgent task that finds no idle CPU takes one from a less urgent task.

CPUs are grouped in compute domains, one per LLC and core type, which
share a queue ordered by deadline. A periodic balancer turns underloaded
domains into stealers and overloaded ones into stealees. On a machine of
big and little cores, performance-critical tasks go to the big cores, in
proportion to the big cores' share of the capacity, and each CPU's
frequency follows its utilization.

The BPF program, `bpf/src/`, file by file after lavd's:

| File | What it does | scx_lavd |
| --- | --- | --- |
| `main.rs` | The sched_ext callbacks, the time slice, the logical clock and the runtime accounting | `main.bpf.c` |
| `lat_cri.rs` | Latency and performance criticality, the greedy penalty, the virtual deadline | `lat_cri.bpf.c` |
| `math.rs` | The arithmetic of all of the above as plain functions, which the host tests run | |
| `sys_stat.rs` | The statistics a 10 ms timer collects, and the system's time slice | `sys_stat.bpf.c` |
| `preempt.rs` | Kick-based preemption by the power of two random choices, slice shrinking | `preempt.bpf.c` |
| `idle.rs` | Where a task runs: its sticky domain, idle cores, the sync waker, neighbors | `idle.bpf.c` |
| `balance.rs` | Stealers and stealees, and what a CPU runs next | `balance.bpf.c` |
| `power.rs` | The big-core threshold and the CPU performance target | `power.bpf.c` |
| `cpdom.rs` | Compute domains, built from the CID topology | `init_cpdoms()`, `cpu_order.rs` |
| `taskctx.rs`, `cpuctx.rs` | The per-task and per-CID contexts in the arena | `lavd.bpf.h` |
| `util.rs`, `lavd.rs` | Helpers, constants and flags | `util.bpf.c`, `lavd.bpf.h` |

`tests/math.rs` checks `math.rs` on the host against values worked out from
lavd's C, and `tests/smoke.sh` loads the scheduler in a VM, runs work under
it and stops it.

## Differences from scx_lavd

The policy is lavd's, with lavd's constants and lavd's names. What the
port changes:

- **The cid form.** CPUs are CIDs, contiguous per core, LLC and node. A
  compute domain is the CIDs of one LLC in one capacity tier; the CID
  topology replaces the neighbor lists lavd's user space computes, by
  distance: the same LLC, the same node, the rest.
- **Queues in the arena.** A domain's queue is an `Edq::User`, a CID's own
  queue an `Edq::Cid`, scx_rustsched's queues in the arena. There are at
  most 64 domains.
- **Invariant time** is capacity-invariant only. lavd reads the PELT clock,
  which also scales by frequency; the runtime does not read it.
- **Runtime** is what the kernel accounts, `se.sum_exec_runtime`.
- **The virtual deadline** is kept in the task context: the runtime keeps
  the slot's address where lavd keeps it, `p->scx.dsq_vtime`.
- **A forked task** starts from the context of the task that forks it,
  which is its parent, as lavd copies the parent's.

What it leaves out, for later ports:

- Core compaction, the power profiles and autopilot: every CPU is active
  and the big-core threshold is the balanced one.
- Futex and lock boosting, which need tracing programs the runtime does not
  build, and the boosts for a wakeup from a hardirq or softirq or of
  ksoftirqd.
- The split of a domain's queue into steady and turbulent CPUs, which needs
  IRQ and steal time from the PELT clock.
- The default fast load balancer, which budgets migrations by the queued
  load of each task: this is the balancer lavd runs with `--no-fast-lb`.
- The warm-CPU wait, cgroup `cpu.max`, the introspection ring buffer with
  `--monitor-sched-samples`, and schedutil's rate limit.
- CPU hotplug: the kernel ejects the scheduler when a CPU comes or goes.

## Build and run

Building needs Rust with `rust-src`, a `bpf-linker` that reads the
compiler's bitcode, `llvm-objcopy` and `llvm-nm`, see
`rust/scx_rustsched/README.md`. Running needs a kernel with
`sched_ext_ops_cid` and BPF arenas.

```
cargo build --release -p scx_ravd
sudo target/release/scx_ravd --verify   # load and stop: does the verifier take it?
sudo target/release/scx_ravd
cargo test -p scx_ravd                  # the arithmetic, on the host
sudo bash tests/smoke.sh target/release/scx_ravd   # in a VM: load, run work, stop
```

The options are lavd's names for what is ported: `--slice-min-us`,
`--slice-max-us`, `--pinned-slice-us`, `--preempt-shift`,
`--lb-local-dsq-util-pct`, `--no-preemption`, `--no-wake-sync`,
`--no-slice-boost`, `--no-freq-scaling` and `--per-cpu-dsq`.

`--stats <interval>` prints, beside the scheduler, what the statistics timer
collects, under lavd's metric names, and `--monitor <interval>` prints it
from another process; `--help-stats` describes each metric.

## Status

Experimental. The port builds and its arithmetic is tested on the host; its
verifier acceptance and its behavior against scx_lavd are to be measured.
