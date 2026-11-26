# scx_lertick

scx_lertick is an experimental Linux sched_ext scheduler that learns
choices from measured wait costs in BPF and predicts CPU bursts to guide
time slices.

## Measured results

In the default-mode rc27 comparison on an ARM64 VM, Lertick led EEVDF
on 12 of 22 measures, tied on nine, and trailed on one. The comparison
uses medians over three rounds per scheduler, with workloads allowed
on four or eight vCPUs. The win and loss cutoff is 5%.

- With the four CPUs assigned to schbench busy, wakeup p99 was 21%
  lower. From the start of processing to completion, request p99 was
  42.9 ms versus 41.4 ms. Median requests per second were 222 versus
  242, about 8% lower.
- With eight CPUs available, perf bench sched pipe took 1.25 us per
  operation versus 19.26 us under EEVDF in this VM.

An earlier rc15 ablation used one fixed policy for wakeup preemption,
queue placement, and tick yielding together. Keeping learned slices,
that policy lowered the stress-ng rate by 65% for futex and 77% for
mq, measured in bogo ops/s. Using only a fixed base slice lowered them
by 2.5% and 3.2%, respectively. Some lighter workloads matched or
favored the tested fixed choices.

## Policy

Lertick uses measured wait and run intervals as feedback at sched_ext
decision points. Per-program feedback guides wakeup preemption, CPU
or LLC queue placement, and tick yielding. After a task migrates,
feedback still targets the deciding CPU's table. Other sched_ext
schedulers can use this path as a reference for their own policies.
Burst prediction, training, and feedback run in BPF.

The burst model uses a recent burst estimate, average burst length,
sleep duration, and queue depth. It can use the last burst started
by the same waker when that estimate has been more accurate. Tasks
with the same executable device, inode, and name can start from a
shared model. Kernel threads are grouped by name.

The base slice is 2 ms, with a default range of 0.5 to 3 ms.
Runnable load can shorten slices. The fixed option uses a fixed
base slice subject to the same load caps. Learned decisions for
preemption, placement, and yielding remain active.

Queues use weighted virtual time and a deadline offset. The
scheduler charges measured runtime using nice and cgroup weights.
The main queues are per CPU and per LLC. An idle CPU can try other
CPUs' queues and checks up to 16 candidates for affinity per CPU queue
it steals from. Eligible work farther down a queue can wait for
another scheduling opportunity.

A dispatch-driven guard tries to move tasks that have waited more
than a second to the local queue of an allowed CPU. It can fall back
to the LLC queue for a movable task if it cannot pick a target CPU.
Each pass moves at most 64 tasks and checks the wait time of up to
1,024 entries. The runnable weight can retain one sleeping task per
CPU across a short handoff, saving shared counter updates.

Hybrid placement scales burst estimates by CPU capacity. SMT
placement can move long running work to a whole idle core. Handover
skips exiting tasks before claiming a destination CPU because the
kernel can requeue them locally without calling `enqueue()`.

Use `--cpu-capacity` or `--smt-siblings` to declare a topology for
testing. Use `--no-asym-rotate` or `--no-smt-balance` to disable the
respective handover. Use `--no-pred-move` to base the handover
decision on the fixed slice.

## Validation and limitations

Validation used an ARM64 VM with Linux 7.0.0-43-generic and one LLC.
The default-mode comparisons and full validation were run on rc27.
In diagnostics with simulated hybrid and SMT topology, rc27 logged
handovers still pending when tasks left sched_ext. The rc28 diagnostics
logged none. The rc28 scheduler stayed active through smoke runs in
both modes.

An early rc27 mixed stress run hit the watchdog during hackbench.
Later rc27 reruns completed without fallback. The cause remains
unconfirmed. Bare metal, multiple LLCs, runtime CPU hotplug, and
other kernels need validation.

In the rc27 single CPU stress test, a probe went at most about 2.1 s
between runs when launching 1,100 workers on one CPU. An earlier
EEVDF baseline measured 3.3 to 4.0 s. Some overloaded runs took 74
to 80 s for the full stress script to finish, versus about 37 s in
typical runs.

With 2,200 tasks bound to two CPUs, the longest observed gap between
probe runs was 3.5 s on rc27 and 0.8 s on EEVDF. The probe first ran
after as much as 4.1 s in the 1,100 task case on rc27.

The shared virtual clock can give loose cgroup weight ratios to tasks
pinned to a CPU with different load from the rest. While the root has
only one active child cgroup, changing that child's cpu.weight does
not change its share against tasks directly in the root cgroup.
Threaded cgroups are not weighted specially. The scheduler does not
enforce cgroup cpu.max or honor cgroup cpu.idle.

Use the CPU controller on cgroup v2. The scheduler requires
CONFIG_CGROUPS and CONFIG_CGROUP_SCHED for its cgroup callbacks.

The scheduler does not account for energy use. On SMT cores with
more than two threads, it checks one sibling. The choice tables take
160 KiB per possible CPU. A learned choice can be slow to respond
when the cost of its other option drops.

For hybrid or SMT handover, check for the kernel's SCX_ENQ_LAST local
queue stall fix in 7a9df7667963 or its backport. For Linux core
scheduling, check for the dispatch kfunc fix in 3dd52416e44a or its
backport.
