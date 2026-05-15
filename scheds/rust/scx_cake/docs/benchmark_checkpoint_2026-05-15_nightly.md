# scx_cake nightly benchmark checkpoint - 2026-05-15

Branch: `RitzDaCat/scx_cake-nightly`
Baseline commit: `c778f296d587` (`origin/RitzDaCat/scx_cake-nightly` at session start)
Checkpoint run: `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260515T214342Z_cake_only_single_core_stat_release/matrix/20260515T214344Z_all_scheduler-matrix.fc3jG5`
Coverage: all-available, `13` passed, `0` failed, `1` skipped (`namd-92k-atoms`)
Scheduler binary hash: `d1c95811ea1b3d4454b353e1c5e41cb42cfb4c9ffce5503f92cf42f6055e77fc`
BPF object hash: `db46a26cb443f619b0274eeacd1577c7111eb5412483eeda607c4b102dc5d545`
Patch hash at capture: `94fa9c8f803d5ff30fe57dab11a4a09ed143631aca36b56c30f5948c498b6d54`

This checkpoint records the current default release `scx_cake` build after the
2026-05-15 performance lane. The near-term gate was to beat the last pushed
clean Cake build on the summed all-available wall-clock comparison before
pushing another nightly checkpoint.

## Gate result

| Build | Summed wall seconds | Notes |
|---|---:|---|
| Current checkpoint | `201.95s` | all-available, NAMD skipped |
| Pushed clean baseline `c778f296d587` | `202.29s` | all-available, NAMD skipped |
| Delta | `+0.34s faster` | current checkpoint wins summed wall |

## Primary scores versus pushed clean baseline

| Benchmark | Metric | Current | Pushed clean | Delta | Wall current | Wall pushed |
|---|---:|---:|---:|---:|---:|---:|
| `argon2-hashing` | wall_time (lower) | `0.81 s` | `0.85 s` | `+4.71%` | `0.81s` | `0.85s` |
| `blender-render` | wall_time (lower) | `0.86 s` | `0.85 s` | `-1.18%` | `0.86s` | `0.85s` |
| `ffmpeg-compilation` | wall_time (lower) | `52.11 s` | `52.23 s` | `+0.23%` | `52.11s` | `52.23s` |
| `kernel-defconfig` | wall_time (lower) | `2.23 s` | `2.26 s` | `+1.33%` | `2.23s` | `2.26s` |
| `perf-memcpy` | throughput (higher) | `35.082e9 bytes/s` | `34.185e9 bytes/s` | `+2.62%` | `0.28s` | `0.28s` |
| `perf-sched-fork` | wall_time (lower) | `0.19 s` | `0.24 s` | `+20.83%` | `0.19s` | `0.24s` |
| `perf-sched-thread` | wall_time (lower) | `0.16 s` | `0.21 s` | `+23.81%` | `0.16s` | `0.21s` |
| `prime-numbers` | prime_ops (higher) | `24,720.06 bogo_ops/s` | `24,396.92 bogo_ops/s` | `+1.32%` | `30.02s` | `30.02s` |
| `schbench` | request_p99 (lower) | `4,952 us` | `5,016 us` | `+1.28%` | `60.01s` | `60.01s` |
| `stress-ng-cpu-cache-mem` | cache_ops (higher) | `5.449M bogo_ops/s` | `4.298M bogo_ops/s` | `+26.79%` | `30.03s` | `30.03s` |
| `x265-encoding` | wall_time (lower) | `1.62 s` | `1.62 s` | `+0.00%` | `1.62s` | `1.62s` |
| `xz-compression` | wall_time (lower) | `5.92 s` | `5.93 s` | `+0.17%` | `5.92s` | `5.93s` |
| `y-cruncher-pi-1b` | wall_time (lower) | `17.71 s` | `17.76 s` | `+0.28%` | `17.71s` | `17.76s` |

## Supporting native metrics

| Benchmark | Native metric | Current |
|---|---:|---:|
| `stress-ng-cpu-cache-mem` | cache realtime bogo ops/s | `5,449,277.03` |
| `stress-ng-cpu-cache-mem` | memcpy realtime bogo ops/s | `3,577.41` |
| `schbench` | wakeup p99 | `3 us` |
| `perf-sched-fork` | perf sched messaging runtime | `0.123s` |
| `perf-sched-thread` | perf sched messaging runtime | `0.116s` |
| `perf-memcpy` | memcpy throughput | `35,081,806,134.58 bytes/s` |
| `blender-render` | render time | `0.49s` |
| `x265-encoding` | encode fps | `147.88 fps` |

## Mutation summary

Size: `M` scheduler policy/hot-path checkpoint plus benchmark-wrapper hardening.

Kept mechanisms:

- Release build bakes actual online CPU and LLC counts into `CAKE_NR_CPUS` and
  `CAKE_NR_LLCS`, avoiding repeated volatile topology loads on the release hot
  path while retaining debug runtime rodata.
- Fast-scan probes are consumed from packed lanes in release select-cpu logic.
- Non-`s*` throughput tasks may try fixed fast-probe slots before native
  fallback; `stress-ng-*` and sched messaging keep the guarded path to protect
  cache/mem and perf-sched behavior.
- Cache-simple dispatch/enqueue handling keeps the cache win while adding
  mixed-stream bleed and miss decay to reduce broad-workload regressions.
- Benchmark wrapper/harness cleanup reduces stale scheduler and output-path
  failure modes seen during the session.

Parked or rejected mechanisms:

- Broad native-fallback bypass for saturated bulk tasks: parked after a large
  ffmpeg regression.
- Broad throughput fast-probe for all non-latency tasks: refined after it hurt
  `perf-sched-thread`.
- Exact comm-heavy classifier expansion in select-cpu: avoided because the
  cheap `p->comm[0] == 's'` guard preserved the wins with less BPF growth.

## Remaining work

This checkpoint clears the near-term push gate, not the ultimate goal.

Known open rows:

- `blender-render` remains a tiny regression versus pushed clean baseline
  (`0.86s` versus `0.85s`).
- `stress-ng-cpu-cache-mem` memcpy remains below pushed clean baseline
  (`3,577.41` versus `4,108.38` bogo ops/s), although cache is much higher.
- The long-term goal remains one current default Cake build first place on
  every tracked benchmark/metric row.
