# scx_mlfq

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_mlfq is a Multilevel Feedback Queue scheduler. Tasks are classified into three queues, Q1 for interactive tasks, Q2 for tasks the scheduler cannot classify yet, and Q3 for CPU-bound tasks. Each queue is a vtime-ordered dispatch queue. The virtual deadline of a task, computed as its virtual runtime plus its slice divided by its weight, is used as the insertion key, so the kernel dispatch queue rbtree serves the task with the earliest virtual deadline first, in the style of EEVDF.

Classification relies on an EMA interactivity gauge that climbs while a task runs and decays while it sleeps. The gauge maps onto the queues with hysteresis, so short-sleeping tasks promote to a higher queue, CPU consumers that run for a sustained window without sleeping demote to a lower queue, and an aging pass elevates tasks that have been queued in Q2 or Q3 for more than a second, which prevents starvation. A wakeup preempts the task running on its previous CPU when it belongs to a higher queue; same-queue wakeups are served by virtual-time order at dispatch, so a running task is not displaced mid-slice by a task of its own priority. Slices are 1 ms for Q1, 2 ms for Q2, and 4 ms for Q3, and dispatch serves Q1 up to a quota of four, then Q2 up to a quota of eight, then Q3, within a bounded batch. Each dispatch slot takes the earliest virtual deadline among the CPU's own queues and the remote CPUs' same-queue queues, migrating a remote task only when it is at least one of its virtual slices ahead of the local head, and a CPU whose queues are empty keeps its running task with a fresh slice instead of idling with runnable work. Wakeups from a short sleep, up to 32 ms (the 60 Hz frame cadence), or from I/O get a rate-limited promotion to Q1, granted at most once per task every two milliseconds, so a bursty consumer of CPU such as a video decoder stays in Q1 for its whole burst.

Placement is cache and capacity aware. Wakeups prefer the previous CPU when it is idle, then an idle CPU in the waker's LLC. On hybrid systems such as Intel P/E cores and ARM big.LITTLE, interactive tasks additionally prefer idle big cores and never stick to an efficiency core. Through the sched_ext cpuperf API the scheduler raises the schedutil performance target to its maximum for interactive tasks; other tasks leave the frequency to the kernel's governor.

The scheduler is deliberately knob-free. Every scheduling constant is a compile-time value and no command-line option changes the scheduling behavior, so there is nothing to misconfigure and no mode to get wrong.

## Typical Use Cases

- Gaming and other latency-sensitive applications. Interactive tasks wake from short sleeps or I/O, promote to Q1, preempt lower-priority tasks, run at the maximum performance target, and prefer idle big cores on hybrid systems, so wakeup latency stays low.
- General desktop use. The desktop session stays responsive while background work such as software updates, file indexing, or compilation is demoted to Q3 and no longer competes with interactive tasks.
- Mixed workloads on laptops and desktops. CPU-bound jobs keep throughput with larger slices while the aging pass periodically elevates tasks that wait in the lower queues, so no task is left behind.

## Limitations

- The EEVDF substrate is approximated where BPF cannot express the kernel's exact machinery. Eligibility is enforced at placement with DELAY_ZERO semantics instead of an augmented-tree walk, only the local CPU's running task is folded into the weighted average, and the aggregate math is s64-only. Each approximation is documented in the code.
- The queues are per-CPU user dispatch queues. A CPU serves the earliest-eligible task across its own queues and the remote CPUs' same-queue queues, migrating a remote task only when it is at least one of its virtual slices ahead of the local head, so NUMA locality comes from wakeup placement while idle CPUs pull clearly-owed tasks from wherever they sit.
- sched_ext cannot schedule RT and DL tasks: the kernel resolves them to the rt and dl classes before sched_ext, so this scheduler handles SCHED_NORMAL, SCHED_BATCH and SCHED_IDLE tasks only.

## Status

The scheduler passes the project's CI stress simulation, including the
affinity-pinned stressor variant, and has been exercised under full CPU
load and in regular desktop use without stalls. As an experimental
scheduler its approximations are documented under Limitations, and
real-time and deadline tasks are scheduled by the kernel classes and
bypass the scheduler entirely.
