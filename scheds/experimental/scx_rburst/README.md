# scx_rburst

An EEVDF-style scheduler with virtual-time borrowing, on `scx_rustsched`,
the runtime for schedulers whose BPF program is written in Rust. It picks by
virtual deadline among the eligible tasks, as EEVDF does, but models the
time a task requests on its CPU burst, the time it runs from one sleep to
the next, and a waking task borrows virtual time.

It is also the example of a scheduler that queues tasks itself: queues in
the arena ordered by deadline, an eligibility check at the pick, and a
task state that follows the task from one queue to another.

## Overview

Each CPU has a queue and a virtual clock. The clock is where a task would
be had it received exactly its share of the CPU, so a task behind the
clock is owed service and one ahead of it has had more than its share. A
CPU runs the task with the earliest virtual deadline among those that are
not ahead of the clock, and the task whose slice ends keeps the CPU while
none queued comes before it.

A task's deadline is its virtual time plus what it asks for, which is how
long it runs between two sleeps. A task that works for a moment and sleeps
again asks for little, so its deadline comes early, and when it wakes
beside a task that asks for more it takes the CPU from it. That keeps such
tasks responsive beside tasks that never sleep, without taking anything
off anyone's virtual time.

Tasks are placed as the kernel's fair class places them, in outline. A
waking task looks for an idle CPU near its last one, and a forked task
looks further. Where the kernel ranks the CPUs, as on a hybrid machine,
the better ones are preferred.

Two simple load balancers move tasks after that, both toward idle CPUs:

- A pull balancer in `ops.dispatch()`. A CPU whose queue is empty steals
  a task from the closest queue that has one: in its LLC, then its node,
  then anywhere.
- An active balancer at the tick, for tasks that never sleep and so are
  never placed again. A CPU running one moves it to a whole idle core
  when its SMT sibling is busy, or to an idle CPU of a better rank, in
  its LLC.

Neither compares loads, so nothing moves a task between two CPUs that
both stay busy.

A waking task is also placed ahead of the tasks that stayed runnable,
after the [Borrowed Virtual Time
scheduler](https://dl.acm.org/doi/10.1145/319151.319169) of Duda and
Cheriton, and queued on a CPU where it can preempt. It is also credited
part of the run it interrupts, so that tasks that wake often get up to
twice their share beside tasks that never sleep. This lowers the wakeup
latency of tasks that sleep beside tasks that never do, and keeps a
pipeline of threads that barely sleep, such as a browser rendering frames,
running beside CPU hogs, at the expense of the latter.
`--no-vtime-borrowing` turns it off.

Where the kernel supports proxy execution, a task that blocks on a mutex
stays queued, and when its turn comes the mutex owner runs in its place.
`--no-proxy-exec` turns it off.

It does not follow the kernel's fair class in the rest, such as the
protection of a running task's slice, load tracking or cgroups.

The scheduler is `bpf/src/main.rs`. Its comments
describe each rule where it is implemented.

## Build and run

Building needs Rust with `rust-src`, a `bpf-linker` built against the same
LLVM as the Rust compiler, `llvm-objcopy` and `llvm-nm`. Without them the
build warns and the binary refuses to start. Running needs a kernel with
`sched_ext_ops_cid` and BPF arenas.

```sh
cargo build --release -p scx_rburst
sudo target/release/scx_rburst
```

`--help` lists the options: the slice, the bounds of the policy, and a
switch for each rule above.

`--stats <interval>` prints what the scheduler does at each interval: how
wakeups are placed, preemptions, steals and moves at the tick, the cost of each callback and
the depth of the queues. `--monitor <interval>` prints the same from
another process.
