# scx_mitosis

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
scx_mitosis --cell-parent-cgroup /workloads

# With LLC-awareness
scx_mitosis --cell-parent-cgroup /workloads --enable-llc-awareness
```
