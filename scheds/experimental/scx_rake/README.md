# scx_rake

[scx_cake](../../rust/scx_cake)'s scheduling policy on `scx_rustsched`, the
runtime for schedulers whose BPF program is written in Rust. It has no BPF C
source and no generated skeleton. scx_cake applies ideas of the CAKE queue
manager to CPU scheduling: serve waiting tasks promptly without moving them
away from their cache, and classify tasks by their own history rather than
by name.

## Overview

A task's history decides where it goes. From its runtime, voluntary
switches, total wait and age the policy derives its mean burst and mean
wait, and from those:

- a **stage**, a task whose mean burst is at least 64 us, takes a **seat**
  on the CID it blocks on, which other wakeups pass over while anything
  else is idle and which it takes back from a stranger when it wakes;
- a task that **waits longer than it runs** is never preempted for a
  wakeup and, when it wakes, comes back with a deeper virtual-time floor;
- the **slice** is twice the mean burst, capped by half the mean cycle and
  1.5 ms, and floored at one handoff, 1464 ns.

Three kinds of queue:

| Queue | Purpose |
| --- | --- |
| A CID's local DSQ | Work admitted to that CID: a claimed idle CID, a preempted occupant, a handoff |
| A CID's own queue, an `Edq::Cid` | Continuations, warm on their CID, which the LLC steals from |
| An LLC's pool, an `Edq::User` | Wakeups that wait longer than a turn, collisions and forced requeues, served by every CID of the LLC |

All three are ordered by virtual time, which a task is charged in
ops.stopping() from the runtime the kernel accounted, scaled by a
fixed-point reciprocal of its weight. A global frontier, advanced in 65 us
grains, bounds how far behind a waking task's key can be.

A dispatch takes an offer from another LLC first, then the earlier of its
own queue's head and its pool's head, the pool needing a slice of lead,
then steals from its LLC from the next CID on, then from other LLCs whose
head is a whole slice behind the frontier or whose pool went unserved for
24 ms.

See [scx_cake's DESIGN.md](../../rust/scx_cake/DESIGN.md) for the policy in
full: scx_rake follows it with every `g8x` construct on, as the current
scx_cake source does.

## Where scx_cake's code went

| scx_cake, cake.bpf.c | scx_rake |
| --- | --- |
| The inline arithmetic and intf.h's constants | `bpf/src/policy.rs`, checked on the host by `tests/policy.rs` |
| `cake_select_cpu()`, `cake_claim_warm()`, `cake_select_undecided()` | `place::select_cid()` |
| `cake_enqueue()`, `cake_enqueue_wake()`, `cake_wake_place()` | `place::enqueue()` |
| `cake_dispatch_search()`, `cake_ring_walk()`, `cake_llc_pool_rescue()` | `serve::search()`, `serve::steal()`, `serve::rescue()` |
| `cake_offer_remote()`, `cake_take_remote()` | `serve::offer_remote()`, `serve::take_offer()` |
| `cake_seat_update()`, `cake_seat_retire()` | `bpf/src/seat.rs` |
| `cake_running()`, `cake_stopping()`, `cake_frontier_candidate()` | `running()`, `stopping()`, `frontier_candidate()` in `bpf/src/main.rs` |
| `scx_bpf_cpu_curr()` | `Cid::curr()` |
| `p->se.sum_exec_runtime`, `nvcsw`, `sched_info`, `start_time` | `Task::sum_exec_runtime()`, `nvcsw()`, `sched_info()`, `start_time()` |

## What is different

What the runtime makes unnecessary:

- The pool's pending-insert token, the may-hold-work mark, the bitmask of
  non-empty CPU queues and the pool tag in a slice's low bits exist in
  scx_cake because a kernel DSQ insert lands after its op returns. An insert
  in the runtime's queues is there when it returns: counts are exact, and
  the runtime's queued bits are the mask.
- The per-CPU spin lock of a seat is one word per CID, changed by compare
  and exchange, see `seat.rs`.
- The idle words and their snapshots are the runtime's idle tracking. A
  claim is `idle::pick()` or `Cid::claim()`: a whole idle core first, the
  task's own core first, and a second pick when the first lands on another
  task's held seat.

What is changed:

- A task is charged the runtime since its own last charge, not since its
  CPU's last ops.running(), which the kernel can skip.
- The adaptive slice keeps its low bits, which scx_cake gives to the pool
  tag: its floor is 1464 ns, as DESIGN.md states, not 1440 ns.

What the runtime cannot express yet, and is left out:

- Interrupt-aware placement: the IRQ and softirq tracepoints, the sampled
  interrupt load, the tick look-ahead and the cpuidle depth. The runtime
  attaches struct_ops callbacks only.
- ops.cpu_release(): a task with IMMED that a higher class preempts comes
  back through ops.enqueue() as a requeue, which goes to the pool, but a
  continuation left on a CID's own queue waits for a steal.
- The preferred die of a stage on a multi-LLC host, which scx_cake's
  loader keeps current, and its capacity ranks: the runtime ranks idle CIDs
  itself.
- The probe instrumentation.

## Build and run

Building needs Rust with `rust-src`, a `bpf-linker` built against the same
LLVM as the Rust compiler, `llvm-objcopy` and `llvm-nm`. Without them the
build warns and the binary refuses to start. Running needs a kernel with
`sched_ext_ops_cid` and BPF arenas.

```sh
cargo build --release -p scx_rake
sudo target/release/scx_rake --verify   # load the object and stop
sudo target/release/scx_rake
```

`--single-pool` keeps one wake pool for the machine, scx_cake's `g89=0`.
`cargo test -p scx_rake` runs the policy's tests on the host.
`rust/scx_rustsched/README.md` describes how to write a scheduler on the
runtime.
