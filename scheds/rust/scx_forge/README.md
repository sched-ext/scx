# scx_forge

This is a base scheduler for [`sched_ext`](https://github.com/sched-ext/scx/tree/main), intended to be customized and optimized in place by AI systems through [`scx_forge_agent`](../../../tools/scx_forge_agent). It is kept buildable and runnable so policy changes can be validated quickly, but it is not intended to be used as a production scheduler unchanged. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_forge` is an AI-oriented base scheduler. It provides a complete
sched_ext Rust crate, BPF program, CLI, stats plumbing, and topology setup whose
policy is meant to be evolved in place by the agent.

Default policy:

- `select_cpu()` is primarily a wakeup placement hint, and may directly dispatch
  to a terminal DSQ when there is a clear fast-path reason, such as an idle CPU.
  It should not own global queueing or selection policy.
- `enqueue()` admits runnable tasks that were not consumed by a `select_cpu()`
  direct-dispatch fast path, including migration-disabled and
  affinity-constrained tasks that skipped wakeup placement. By default, it
  enqueues those tasks only to per-CPU DSQs.
- `dispatch()` is the primary selection point and pulls from per-CPU DSQs,
  stealing from other CPU DSQs when their earliest runnable task can run on the
  dispatching CPU.
- Per-LLC, per-NUMA-node, and global DSQs are supported. The default policy
  uses CPU-local queueing with work stealing across per-CPU DSQs.
- Queue ordering uses a DSQ queue key derived from task-local weighted virtual
  runtime. Deadline and FIFO queueing is also supported optionally.
- Runtime budget is a fixed slice by default.

## Typical Use Case

`scx_forge` is meant to be customized and optimized through
[`scx_forge_agent`](../../../tools/scx_forge_agent), the LLM-driven optimizer.

The agent edits this crate's policy in place, then builds, runs, and scores each
change with its bundled validation harness. The agent's `SKILL.md` documents how
to translate Rust-like policy specs into BPF helpers while preserving sched_ext
callback constraints.

## Validate / Iterate

`scx_forge` is scored and improved by
[`scx_forge_agent`](../../../tools/scx_forge_agent), which owns the closed-loop
validation harness and spec. The agent edits the policy, builds, attaches the
scheduler, runs a workload, extracts one metric, and keeps or reverts the change
based on whether it improved beyond run-to-run noise. See that tool's
`README.md` and `SKILL.md` for the workflow and the spec format.

## Production Ready?

No. `scx_forge` is a starting-point scheduler for AI-driven policy development.
