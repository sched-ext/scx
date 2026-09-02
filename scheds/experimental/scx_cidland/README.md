# scx_cidland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_cidland` is a **cid-form** scheduler, that is a scheduler implementing
`struct sched_ext_ops_cid` instead of the usual `struct sched_ext_ops`, and it
uses cids to drive every placement decision.

A cid (topological CPU ID) is an alternative way to address a CPU: instead of
the raw CPU number, each CPU gets an id from a dense space that is ordered by
topology, so that the CPUs of a core, of an LLC and of a NUMA node always
occupy **contiguous** ranges of that space.

This turns a topology domain into a `(base, len)` slice, so questions that
normally require cpumasks and per-CPU topology lookups become plain range scans:

 - "is this core fully idle?" -> are all the bits in `[core_base, core_base +
   core_nr)` set?
 - "is there an idle CPU in my LLC?" -> scan `[llc_base, llc_base + llc_nr)`

Task affinities are handled in cid space too: the cid form reports them through
`ops.set_cmask()` as a **cmask**, the cid-space counterpart of a cpumask, which
`scx_cidland` copies into its per-task `allowed` bitmap (primed in
`ops.init_task()` from the task's cpumask). Checking whether a task can run on a
candidate cid is then a bit test, with no cid to CPU translation in the pick
loop.

`scx_cidland` keeps its own bitmap of idle cids and idle state is tracked via
`ops.update_idle()`). On wakeup, it looks for an idle cid in this order:

 1. the cid the task last ran on, if its whole core is idle,
 2. any fully idle core in the LLC the task last ran on,
 3. the cid the task last ran on,
 4. any idle cid in the LLC the task last ran on,
 5. any idle cid in the system.

If an idle cid is found the task is dispatched directly to it, otherwise it is
queued to a single shared DSQ, that is consumed by the first cid that runs out
of work.

That shared queue is ordered by a virtual deadline (`task_dl()`, the same logic
used by `scx_cosmos`):

```
deadline = vruntime + burst_vruntime
```

`vruntime` is the task's total runtime inversely scaled by its weight, which
provides fairness, while `burst_vruntime` only accounts for the runtime since
the task last went to sleep, which prioritizes tasks that sleep frequently and
run in short bursts, typically the latency critical ones. The vruntime credit a
task can build up while sleeping is capped at `--slice-lag-us`, scaled by the
task's weight and by its wakeup frequency, so that tasks sleeping for very long
intervals don't get an unbounded priority boost over CPU intensive ones.

The per-cid core and LLC ranges are built once in `ops.init()` from
`scx_bpf_cid_topo()`, walking the cid space backwards: since the cids of a
domain are contiguous, seeing the highest cid of a domain first is enough to
derive the length of the whole range.

## Requirements

A kernel with cid-form `sched_ext` support, that is one exporting
`struct sched_ext_ops_cid`:

```shell
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep sched_ext_ops_cid
```

Note that cid-form schedulers are also required to provide a BPF arena (the
kernel allocates the per-task cmasks from it), hence the `lib/arena_map.h`
include. The per-cid topology table lives in that arena as well: arena pointers
are not range tracked by the verifier, so a cid that is known to be in range can
index the table directly.

## Typical Use Case

Multi-core or multi-LLC systems where placement should follow the machine
topology: tasks are kept on a fully idle core when there is one, then within the
LLC they last ran on, and they only move further away when nothing closer is
idle.

The deadline ordering favors tasks that sleep frequently and run in short bursts
over CPU intensive ones, so interactive workloads keep responding while the
machine is busy.

## Production Ready?

No. It requires a kernel with cid-form `sched_ext` support, which is still under
development.
