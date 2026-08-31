# scx_nitosis

An experimental fork of `scx_mitosis` being converted to the cid form of
sched_ext ops with all state in a BPF arena, with the goal of becoming a root
scheduler that other schedulers can plug into (sub-scheduling), one per cell.
Requires kernel sched_ext/for-7.3 once the conversion lands.

A cgroup-aware scheduler that isolates workloads into *cells*. The eventual goal is to enable overcomitting workloads on datacenter servers.

## How it works

The direct children of the cgroup passed via `--cell-parent-cgroup` each get
their own *cell*, except for names excluded with `--cell-exclude`, which remain
in cell 0. Each cell owns a dedicated CPU set with a shared dispatch queue.
Tasks within a cell are scheduled using weighted vtime. CPU-pinned tasks
(typically system threads) use per-CPU queues. Cell and CPU tasks compete for
dispatch based on their vtime.

On multi-LLC systems, LLC-awareness keeps tasks on cache-sharing CPUs. In this case, the single cell queue is split into multiple queues, one per LLC.

## Usage

```bash
# Basic
scx_nitosis --cell-parent-cgroup /workloads

# With LLC-awareness
scx_nitosis --cell-parent-cgroup /workloads --enable-llc-awareness
```
