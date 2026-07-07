# scx_mitosis

A cgroup-aware scheduler that isolates workloads into *cells*. The eventual goal is to enable overcomitting workloads on datacenter servers.

## How it works

The direct children of the cgroup passed via `--cell-parent-cgroup` each get
their own *cell*, except for names excluded with `--cell-exclude`, which remain
in cell 0. Each cell owns a dedicated CPU set with one dispatch queue per LLC.
Tasks within a cell are scheduled using weighted vtime and kept on
cache-sharing CPUs when possible. CPU-pinned tasks (typically system threads)
use per-CPU queues. Cell and CPU tasks compete for dispatch based on their
vtime.

## Usage

```bash
scx_mitosis --cell-parent-cgroup /workloads
```
