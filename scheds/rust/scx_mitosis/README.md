# scx_mitosis

A cgroup-aware scheduler that isolates workloads into *cells*. The eventual goal is to enable overcomitting workloads on datacenter servers.

## How it works

Cgroups that restrict their parent's cpuset get their own *cell*—a dedicated CPU set with a shared dispatch queue. Tasks within a cell are scheduled using weighted vtime. CPU-pinned tasks (typically system threads) use per-CPU queues. Cell and CPU tasks compete for dispatch based on their vtime.

On multi-LLC systems, LLC-awareness keeps tasks on cache-sharing CPUs, with optional work stealing to prevent idle cores. In this case, the single cell queue is split into multiple queues, one per LLC.

## Usage

```bash
# Basic
scx_mitosis

# With LLC-awareness and work stealing
scx_mitosis --enable-llc-awareness --enable-work-stealing
```
