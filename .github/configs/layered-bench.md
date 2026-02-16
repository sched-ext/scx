# layered-bench.json — Benchmark Config for scx_layered

Single config used across all CI benchmarks, designed for regression detection.
The config JSON is printed in benchmark logs so Claude can cross-reference it
with layered source code (see `LayerSpec`, `LayerKind`, `LayerGrowthAlgo` structs).

## Layer → Benchmark Mapping

### `latency` layer (Open)
**Benchmarks:** schbench, schbench-split, schbench-pipe
**Match:** `CommPrefix`/`PcommPrefix` = `schbench`

Features exercised:
- `Open` layer kind — tasks can run on any CPU, no confinement
- `growth_algo: Sticky` — CPUs stay with the layer once assigned
- `preempt: true` — layer can preempt lower-priority work
- `prev_over_idle_core: true` — prefer previous CPU over idle cores (cache reuse)
- Low `min_exec_us` (100) and short `slice_us` (5000) — tight latency bounds

### `compute` layer (Confined)
**Benchmarks:** sysbench-threads, sysbench-cpu, stress-ng-switch, stress-ng-cache, stress-ng-affinity
**Match:** `CommPrefix`/`PcommPrefix` = `sysbench` or `stress-ng`

Features exercised:
- `Confined` layer kind — tasks restricted to layer's CPU set
- `growth_algo: Topo` — grow CPU set following topology (fill cores/LLCs)
- `util_range: [0.7, 0.9]` — target high utilization before growing
- `cpus_range_frac: [0.3, 0.9]` — bounded CPU allocation range
- `xllc_mig_min_us: 500` — cross-LLC migration minimum threshold
- High `min_exec_us` (500) and long `slice_us` (20000) — throughput-oriented

### `sync` layer (Grouped)
**Benchmarks:** epoll-single, epoll-multiq, futex-lock-pi
**Match:** `CommPrefix`/`PcommPrefix` = `perf`

Features exercised:
- `Grouped` layer kind — tasks share CPUs with topological locality
- `growth_algo: Linear` — grow CPU set linearly
- `skip_remote_node: true` — NUMA-aware, avoids remote node scheduling
- `xllc_mig_min_us: 200` — lower cross-LLC migration threshold (sync patterns)
- Moderate `slice_us` (10000) — balance between latency and throughput

### `rest` layer (Grouped, catch-all)
**Benchmarks:** none directly — catches system services, shells, monitoring
**Match:** `[[]]` (matches everything not caught above)

Features exercised:
- `Grouped` layer kind with default settings
- `util_range: [0.5, 0.6]` — conservative utilization target
- No explicit growth algo, slice, or migration settings (uses defaults)
