# scx_bpfland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_bpfland` is an EEVDF-like scheduler (Earliest Eligible Virtual Deadline
First) with one deadline-ordered queue per CPU. It adds two things to the EEVDF
model: each task's request is sized from how long it actually runs between two
sleeps, and a waking task can borrow virtual time. Together they keep
interactive workloads responsive while CPU-intensive tasks run beside them.

The BPF part makes all the scheduling decisions. A small Rust part loads it,
reads the CPU topology, and reports statistics.

## Design

### Virtual time and eligibility

Each CPU has a virtual clock. While a task runs there, the clock advances by
the elapsed time divided by the total weight of the tasks runnable on that CPU.
It is the virtual time a task would have reached had it received exactly its
share. A task's own virtual time advances by the time it ran divided by its
weight, so a higher-priority (heavier) task advances more slowly.

The distance between the clock and a task's virtual time is the task's lag. A
task behind the clock is owed service and is eligible to run. A task ahead of
it has had more than its share and waits until the clock catches up.

A task keeps its lag across a sleep: it wakes as far from the clock as it was
when it went to sleep, so sleeping neither earns service nor forgives what the
task ran beyond its share. A task that moves to another CPU keeps its lag too,
restated against the new CPU's clock. The lag is bounded in both directions,
and a change of weight rescales it, as in the kernel's EEVDF.

### Deadlines

A task's virtual deadline is its virtual time plus its request, scaled by its
weight. The request is how long the task runs between two sleeps: the larger of
its current burst and a running average of its past bursts, kept between an
eighth of a slice and a full slice. A new task asks for a full slice until it
has shown that it sleeps.

Each CPU runs the eligible task with the earliest deadline. A task that works
for a moment and sleeps again asks for little and gets an early deadline, so it
runs soon. A task that computes without a pause asks for a whole slice and
waits behind it. The task whose slice ends takes part in the same pick: it is
charged for what it ran and keeps the CPU while it is still eligible and no
queued task has an earlier deadline, which avoids needless context switches.

A waking task preempts the running one when it is eligible, asks for less, and
has an earlier deadline. A CPU is also left alone for a short while after a
task starts running on it, so that a burst of wakeups cannot switch it at every
wakeup.

### Virtual-time borrowing

In plain EEVDF, a task that used up its share before it slept wakes at the
clock or ahead of it, and waits for the tasks that stayed runnable, although it
would only run for a moment and sleep again. Frame pipelines, audio and other
interactive threads behave like that, and they lose against CPU hogs.

`scx_bpfland` lets a waking task borrow virtual time, an idea from the Borrowed
Virtual Time scheduler (Duda and Cheriton, SOSP '99) applied at wakeup only:

- The waking task is placed at least a fixed credit behind the clock. This
  makes it eligible, with a deadline ahead of the tasks that never sleep. What
  it then runs is charged as usual.
- A task that wakes on a busy CPU is also credited part of the run it
  interrupts: for that stretch, the clock advances as if the waking task had
  been runnable too. The credit is capped, so every task keeps at least half
  its share.
- A waking task that finds no idle CPU is queued on a CPU it can take, one
  whose running task asks for more than it does, rather than on its last CPU,
  where a task like itself often runs. This search only runs while some CPU is
  running a task that does not sleep.

Borrowing takes CPU time from the tasks that never sleep. It can be turned off,
which makes the scheduler a plain EEVDF one.

### Per-CPU queues

Each CPU has its own queue, an EDQ (an earliest-deadline queue kept in a BPF
arena). An EDQ keeps tasks in deadline order and finds the first eligible one,
which the kernel's built-in DSQs cannot do. When a CPU needs work, it moves that
task from its EDQ to its local DSQ, which the kernel runs from.

A queued task stays in the scheduler's custody until a CPU dispatches it or the
kernel takes it back. Tasks that wake on an idle CPU skip the queues and go
straight to that CPU's local DSQ.

Per-CPU queues keep the hot path local: enqueue and dispatch mostly touch the
current CPU's queue. A one-bit-per-CPU hint tells other CPUs which queues hold
tasks, so a CPU looking for work only looks at queues worth a look.

### Task placement

The primary domain orders or narrows the CPUs that placement uses. As a
preference, the fastest cores first, the slowest first, the ones that boost
highest first, one that follows the power profile, or one thread of each core
before its SMT siblings, it only changes the order in which the CPUs are tried:
tasks still spill onto every CPU when the preferred ones are busy. As an
explicit list of CPUs, it keeps tasks on those CPUs, queued there when they are
busy rather than spilled elsewhere. Affinity remains authoritative: tasks whose
affinity excludes the list, and migration-disabled tasks, run outside it.

A waking task looks for an idle CPU in the LLC of the CPU it last ran on, where
its cache is: a core that is idle as a whole first, then any idle CPU, its last
CPU first either way. A forked task has no cache to keep warm, so with nothing
idle in the LLC it starts on an idle CPU of the node or of the machine.

On hybrid CPUs, placement prefers the faster cores by default: work packs on
them and spills over to the others as those fill up. A task that sleeps often
keeps its last CPU when that one is idle, whatever its type: it has just gone
idle, while a CPU idle for longer may be in a deep idle state that takes long
to leave. The ranking comes from the kernel's core priorities where it ranks
the cores (asymmetric packing, as on x86 processors with performance and
efficiency cores), and otherwise from the capacity the kernel gives each CPU,
as on Arm systems with big and little cores.

### Load balancing

Two balancers move tasks toward idle CPUs, and neither compares loads:

- **Pull balancing at dispatch:** a CPU whose queue is empty steals the first
  task it may run from the closest queue that holds one: in its LLC, then in
  its node, then anywhere. A task put back at the end of its slice or after a
  preemption also kicks an idle CPU that can come and take it.
- **Active balancing at the tick:** a task that never sleeps is never placed
  again, so its CPU moves it when a better CPU is idle in the LLC. That is a
  whole idle core while an SMT sibling is busy, or an idle core of a better
  rank on a hybrid CPU.

When neither local work nor stealing selects another task, the previous
runnable task keeps the CPU even if it is ahead of the virtual clock.

On a hybrid CPU with more CPU-bound tasks than fast cores, no fast core ever
goes idle, so the tasks that started on the slow cores stay there. A
workload that splits its work evenly among its threads then waits for them.
Optional tier rotation fixes that: once a task has run on slower cores for a
set time, it swaps places with a task that has run on a fast core of its LLC
for as long without sleeping, so that CPU-bound tasks take turns on the fast
cores. Tasks that sleep more often, such as render threads waiting for a
frame, keep their fast cores. It is off by default.

## Typical Use Case

Interactive and latency-sensitive workloads running alongside CPU-intensive
background work: gaming, live streaming, video playback and rendering,
real-time audio, and desktop use during builds or batch jobs.

In that setting, the kernel's default EEVDF scheduler gives the interactive
threads no more than their weight's share, so they are slowed down as soon as
the CPUs fill up with work that never sleeps. `scx_bpfland` keeps them running
at their pace:

- Requests come from how tasks behave, so short-burst tasks get early deadlines
  without being configured or reniced.
- Virtual-time borrowing puts waking tasks ahead of the CPU hogs, and the hogs
  absorb the cost.
- Wakeup preemption is limited to the cases where it pays off: a shorter
  request and an earlier deadline, with a minimum run time between two
  preemptions.
- On hybrid CPUs, placement prefers the faster cores.

With the CPUs not saturated, it aims to match the default scheduler on
throughput and tail latency.

## Production Ready?

The scheduler has been redesigned around the EEVDF model described above. The
new design has seen less testing than the one it replaces, so please report
regressions against the default scheduler.
