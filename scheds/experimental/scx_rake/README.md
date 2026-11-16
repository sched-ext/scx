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
  1.5 ms, and floored at one handoff, 1464 ns;
- a thread that keeps a **fifth of a CPU** busy owns a core as its
  **home**, one home per core, and returns to it on every wakeup, see
  `bpf/src/home.rs`.

Three kinds of queue:

| Queue | Purpose |
| --- | --- |
| A CID's local DSQ | Work admitted to that CID: a claimed idle CID, a preempted occupant, a handoff |
| A CID's own queue, an `Edq::Cid` | Continuations, warm on their CID, which the LLC steals from |
| An LLC's pool, an `Edq::User` | Wakeups that wait longer than a turn, collisions and forced requeues, served by every CID of the LLC |

All three are ordered by virtual time, which a task is charged in
ops.stopping() from the runtime the kernel accounted, scaled by a
fixed-point reciprocal of its weight, and the charge is capped so that no
task leads the frontier by more than the grant cap at its weight. A global
frontier, advanced in 65 us grains at between a sixteenth of the wall
clock's pace and its full pace, bounds how far behind a waking task's key can be, and a forced requeue is
keyed at most 2.25 ms behind it.

A dispatch takes an offer from another LLC first, then the earlier of its
own queue's head and its pool's head, the pool needing a slice of lead,
then steals from its LLC from the next CID on, then from other LLCs whose
head is a whole slice behind the frontier or whose pool went unserved for
24 ms.

See [scx_cake's DESIGN.md](../../rust/scx_cake/DESIGN.md) for the policy in
full: scx_rake follows scx_cake 1.4.0 with every `g8x` construct on, as its
source does, including the charge ceiling and frontier band (G98), the
exact starvation test (G105), the pinned wake lane and ops.yield(), exiting
tasks through ops.enqueue() and fixed homes.

## Where scx_cake's code went

| scx_cake, cake.bpf.c | scx_rake |
| --- | --- |
| The inline arithmetic and intf.h's constants | `bpf/src/policy.rs`, checked on the host by `tests/policy.rs` |
| `cake_select_cpu()`, `cake_claim_warm()`, `cake_select_undecided()` | `place::select_cid()` |
| `cake_enqueue()`, `cake_enqueue_wake()`, `cake_wake_place()` | `place::enqueue()` |
| `cake_dispatch_search()`, `cake_ring_walk()`, `cake_llc_pool_rescue()` | `serve::search()`, `serve::steal()`, `serve::rescue()` |
| `cake_offer_remote()`, `cake_take_remote()` | `serve::offer_remote()`, `serve::take_offer()` |
| `cake_seat_update()`, `cake_seat_retire()` | `bpf/src/seat.rs`, its transitions in `bpf/src/seat_word.rs`, checked by `tests/seat.rs` |
| `cake_running()`, `cake_stopping()`, `cake_frontier_candidate()` | `running()`, `stopping()`, `frontier_candidate()` in `bpf/src/main.rs` |
| `cake_frontier_step()`, the charge ceiling | `frontier_advance()` in `bpf/src/main.rs`, `policy::charge()` and `policy::frontier_step()` |
| `cake_yield()` | `serve::yield_task()` |
| `cake_home_sample()`, `cake_home_drop()`, `cake_home_cpu()` | `bpf/src/home.rs` |
| `scx_bpf_cpu_curr()` | `Cid::curr()`, a `CurrTask` that cannot outlive the callback |
| `cake_system_serial()`, the idle census | `update_idle()` and the count in the first CID of each LLC |
| `p->se.sum_exec_runtime`, `nvcsw`, `sched_info`, `start_time` | `Task::sum_exec_runtime()`, `nvcsw()`, `sched_info()`, `start_time()` |

## What is different

What the runtime makes unnecessary:

- The pool's pending-insert token, the may-hold-work mark, the bitmask of
  non-empty CPU queues and the pool tag in a slice's low bits exist in
  scx_cake because a kernel DSQ insert lands after its op returns. An insert
  in the runtime's queues is there when it returns: counts are exact, and
  the runtime's queued bits are the mask.
- The per-CPU spin lock of a seat is one word per CID, changed by compare
  and exchange, see `seat.rs`. `tests/seat.rs` walks every interleaving of
  the word's two writers: each change applies whole, a late release never
  undoes a later hold, and a release loses at most two exchanges and any
  other change one, so the bounded retries never run out. A release that
  did run out would keep the task's record of its seat and try again.
- The idle words and their snapshots are the runtime's idle tracking, as
  is scx_cake 1.4.0's private idle word with its claim tokens. A claim is
  `idle::pick()` or `Cid::claim()`: a whole idle core first, the task's own
  core first, and a second pick when the first lands on another task's
  held seat.
- scx_cake's 64-entry home table, hashed by pid, and its word of owned
  cores need a host whose CPUs fit one 64-bit word. scx_rake keeps a home
  as one word in the slot of each core's first CID, so homes work on any
  host.

What is changed:

- A task is charged the runtime since its own last charge, not since its
  CPU's last ops.running(), which the kernel can skip.
- The adaptive slice keeps its low bits, which scx_cake gives to the pool
  tag: its floor is 1464 ns, as DESIGN.md states, not 1440 ns.
- The serial handoff counts the LLC's idle CIDs with a census that
  ops.update_idle() keeps: CIDs physically idle, the occupancy scx_cake
  counts on wide hosts. On hosts whose CPUs fit one word scx_cake 1.4.0
  counts the CIDs free to claim, its idle word less its claims, since it
  dropped the separate `cake_idle_nr`: a CID a wakeup just claimed still
  counts here until it runs, so a burst of claims can read an LLC as serial
  a moment longer. `tests/policy.rs` models the difference. A count past
  the LLC's size allows no handoff and is counted in the dump.
- A home's core is chosen by the runtime's capacity tier, then its packing
  tier, where scx_cake ranks CPUs by its own rank tiers.
- Whether a task can move is `Task::pinned()`, which counts disabled
  migration, where scx_cake tests the size of the affinity mask.

What the runtime cannot express yet, and is left out:

- Interrupt-aware placement: the IRQ and softirq tracepoints, the sampled
  interrupt load, the tick look-ahead, the cpuidle depth, and scx_cake
  1.4.0's wake signals and hardirq accounting. The runtime attaches
  struct_ops callbacks only.
- ops.cpu_release(): a task with IMMED that a higher class preempts comes
  back through ops.enqueue() as a requeue, which goes to the pool, but a
  continuation left on a CID's own queue waits for a steal. scx_rake sets
  `SCX_OPS_ENQ_EXITING` as scx_cake 1.4.0 does, but without
  ops.cpu_release() it cannot tell the requeue limit that kernel 7.3 puts
  on a scheduler apart from any other requeue.
- The preferred die of a stage on a multi-LLC host, which scx_cake's
  loader keeps current, and its capacity ranks: the runtime ranks idle CIDs
  itself.
- The probe instrumentation.

## Build and run

Building needs Rust with `rust-src`, a `bpf-linker` built against the same
LLVM as the Rust compiler, `llvm-objcopy` and `llvm-nm`. Without them the
build warns and the binary refuses to start. Running needs a kernel with
`sched_ext_ops_cid` and BPF arenas.

The watchdog fires after 5 s without a run, as in scx_cake 1.4.0.

```sh
cargo build --release -p scx_rake
sudo target/release/scx_rake --verify   # load the object and stop
sudo target/release/scx_rake
```

`--single-pool` keeps one wake pool for the machine, which also turns off
the offers and rescues between LLCs' pools and the worker's anchor at its
waker. It follows the one-pool mode scx_cake's documentation calls `g89=0`,
which its current source no longer has as a switch, so the two are not
known to behave alike beyond that.

`cargo test -p scx_rake` runs the policy's and the seats' tests on the
host, as CI does.
`rust/scx_rustsched/README.md` describes how to write a scheduler on the
runtime.
