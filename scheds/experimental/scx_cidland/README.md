# scx_cidland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

Topology-aware scheduler that preserves task-to-CPU locality, built on EEVDF
concepts.

`scx_cidland` is a **cid-form** scheduler: instead of raw CPU numbers it
addresses CPUs by their cid (topological CPU ID), an id from a dense space
ordered by topology, so that the CPUs of a core, of an LLC and of a NUMA node
always occupy **contiguous** ranges of that space.

That turns a topology domain into a `(base, len)` slice, so every question the
idle search and the work pulling ask is a range of a bitmap:

 - "is this core fully idle?" -> are all the bits in `[core_base, core_base +
   core_nr)` set?
 - "is there an idle CPU in my LLC?" -> scan `[llc_base, llc_base + llc_nr)`

no cpumask allocation and no per-CPU topology lookup in the hot path. All the
state sized by the machine lives in a BPF arena allocated at start, so no limit
on the number of CPUs, cores, LLCs, nodes or capacity tiers is built in.

### What it takes from EEVDF

The placement and the fairness rules are the ones the kernel's own scheduler
uses, translated to cid space:

 - **Virtual deadline.** Tasks that can't be placed on an idle CPU are queued
   by `vd_i = ve_i + r_i / w_i`, EEVDF's `update_deadline()`, with a request
   size `r_i` that is the same for everybody, like `sysctl_sched_base_slice`:
   the weight buys an earlier deadline, not a longer slice.

 - **Per-runqueue reference.** Each CPU keeps `V = \Sum (w_i * v_i) / \Sum w_i`
   over the tasks queued on it, EEVDF's `avg_vruntime()`, kept incrementally,
   so the queues of different CPUs stay comparable.

 - **Lag.** How far a task is from the reference is taken when it stops being
   runnable and restored when it comes back or migrates, the way
   `update_entity_lag()` and `place_entity()` do, so a sleeper gets back what
   it was owed and no more, and a migration keeps its fairness.

 - **Runtime accounting.** The service consumed is charged as wall-clock time
   inversely scaled by the weight, `update_curr()` with `calc_delta_fair()`;
   the CPU capacity is used to balance the load, never to discount the
   vruntime.

 - **Idle search.** A fully idle core is preferred over a thread with a busy
   sibling, `select_idle_core()` before `select_idle_cpu()`, and within that
   the previous CPU, then its LLC, then its node, the order
   `select_idle_sibling()` applies. A synchronous wakeup can stack the wakee on
   the waker's CPU, `wake_affine_idle()`, but only after the idle search has
   come up empty. A new task with nowhere idle to go is placed on the shortest
   queue, `find_idlest_cpu()`.

 - **Load balancing.** A CPU that runs out of work pulls from the other queues
   of its node, walking its own LLC first the way the idle balancer walks the
   domains bottom up, and leaves alone a task that ran a moment ago,
   `task_hot()` with `sysctl_sched_migration_cost`. A busy CPU samples a couple
   of remote queues once per slice, the way the balancer runs on the tick, and
   only takes from a queue that is clearly deeper than its own, the equivalent
   of `imbalance_pct`.

 - **Asymmetric capacity.** On systems with CPUs of different capacity (e.g.
   P-cores and E-cores), idle CPUs are handed out in capacity order and idle
   faster CPUs pull work up from the slower ones, the way asym packing does,
   but only onto a fully idle faster core, which is what
   `asym_smt_can_pull_tasks()` refuses to give up.

Time slices are fixed (1 ms by default) and a task that runs out of its slice
with nothing waiting on its CPU keeps running there.

## Requirements

A kernel with cid-form `sched_ext` support.

## Typical Use Case

General-purpose scheduler: it should adapt itself both to server workloads and
to desktop workloads.

## Production Ready?

No. It requires a kernel with cid-form `sched_ext` support, which is still
under development.
