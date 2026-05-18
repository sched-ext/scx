# scx_cake nightly checkpoint: S160/S172 champion

Date: 2026-05-18
Branch: `RitzDaCat/scx_cake-nightly`
Previous GitHub nightly base: `b1b51d71698b`
Checkpoint candidate: S160/S172 champion
Release BPF object SHA256:
`9df312119f3b899f2e32607562e919665244513f1507d8072b98e16a81f31e59`
Release BPF object size: `119112` bytes

## Decision

Promote S160/S172 to the nightly branch as the current working checkpoint.

The checkpoint gate is the current Cake goal: every benchmark receives equal
weight, wallclock is reported separately, and noisy/historical one-off rows do
not override a same-window controlled comparison. On the 2026-05-18 same-window
3x comparison, S160/S172 beat the previous GitHub nightly overall:

- Equal-weight median score: `1.01196` (`+1.20%`).
- Median primary wall rows: `82.73s -> 82.22s` (`-0.62%` faster).
- Strongest gains: `stress-ng-cpu-cache-mem`, `argon2-hashing`,
  `kernel-defconfig`, `x265-encoding`, and `ffmpeg-compilation`.
- Small regressions remained on `prime-numbers`, `perf-memcpy`, `schbench`, and
  `xz-compression`; none were large enough to outweigh the equal-weight win.

Later same-day experiments (`combined service-token + inline clamp` and
`inline clamp only`) did not beat S160/S172 and were not promoted.

## Benchmark artifacts

### Previous GitHub nightly, 3 runs

1. `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T165812Z_all_wide/matrix/20260518T165812Z_all_scheduler-matrix.bQ4JH4/analysis_metrics.tsv`
2. `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T170549Z_all_wide/matrix/20260518T170549Z_all_scheduler-matrix.fsP2m5/analysis_metrics.tsv`
3. `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T171324Z_all_wide/matrix/20260518T171324Z_all_scheduler-matrix.tHOlXp/analysis_metrics.tsv`

### S160/S172 champion, 3 runs

1. `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T172101Z_all_wide/matrix/20260518T172101Z_all_scheduler-matrix.GeNi78/analysis_metrics.tsv`
2. `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T172827Z_all_wide/matrix/20260518T172827Z_all_scheduler-matrix.TyAKEg/analysis_metrics.tsv`
3. `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T173554Z_all_wide/matrix/20260518T173554Z_all_scheduler-matrix.8c3MlY/analysis_metrics.tsv`

## Median 3x results by benchmark

| Benchmark | Previous nightly median | S160/S172 median | S160/S172 delta |
|---|---:|---:|---:|
| `argon2-hashing` wall_time, lower | `0.86 s` | `0.82 s` | `+4.88%` |
| `blender-render` wall_time, lower | `0.86 s` | `0.86 s` | `+0.00%` |
| `ffmpeg-compilation` wall_time, lower | `53.13 s` | `52.67 s` | `+0.87%` |
| `kernel-defconfig` wall_time, lower | `2.29 s` | `2.25 s` | `+1.78%` |
| `perf-memcpy` throughput, higher | `3.50784e10 bytes/s` | `3.49450e10 bytes/s` | `-0.38%` |
| `perf-sched-fork` wall_time, lower | `0.19 s` | `0.19 s` | `+0.00%` |
| `perf-sched-thread` wall_time, lower | `0.17 s` | `0.17 s` | `+0.00%` |
| `prime-numbers` prime_ops, higher | `24752.9 bogo_ops/s` | `24475.4 bogo_ops/s` | `-1.12%` |
| `schbench` request_p99, lower | `5000 us` | `5016 us` | `-0.32%` |
| `stress-ng-cpu-cache-mem` cache_ops, higher | `5.28372e6 bogo_ops/s` | `5.75020e6 bogo_ops/s` | `+8.83%` |
| `x265-encoding` wall_time, lower | `1.64 s` | `1.62 s` | `+1.23%` |
| `xz-compression` wall_time, lower | `5.92 s` | `5.94 s` | `-0.34%` |
| `y-cruncher-pi-1b` wall_time, lower | `17.71 s` | `17.69 s` | `+0.11%` |

## Non-promoted follow-up variants

### Combined service-token + inline clamp

- Full run:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T221302Z_all_wide/matrix/20260518T221302Z_all_scheduler-matrix.PBUhD5/analysis_metrics.tsv`
- Compared against same-day S160 control:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T222039Z_all_wide/matrix/20260518T222039Z_all_scheduler-matrix.XUPUgP/analysis_metrics.tsv`
- Equal-weight score: `0.998445` (`-0.16%`).
- Summed wall: `203.24s -> 203.02s` (`-0.11%` faster).
- Decision: protected finding, not promoted. It improved wallclock and several
  rows but regressed `perf-sched-fork`, `perf-sched-thread`, `argon2-hashing`,
  and slightly `stress-ng-cpu-cache-mem`.

### Inline clamp only

- Full run:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T232916Z_all_wide/matrix/20260518T232916Z_all_scheduler-matrix.MZ08Au/analysis_metrics.tsv`
- Compared against same-day S160 control:
  `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/full/20260518T222039Z_all_wide/matrix/20260518T222039Z_all_scheduler-matrix.XUPUgP/analysis_metrics.tsv`
- Equal-weight score: `0.985425` (`-1.46%`).
- Summed wall: `203.24s -> 203.41s` (`+0.08%` slower).
- Decision: rejected and restored. It helped several throughput-ish rows but
  regressed `blender-render` by `-16.19%`, `kernel-defconfig` by `-9.84%`, and
  `perf-sched-fork` by `-5.00%`.

## Next work

Continue refinement from S160/S172, not from the failed inline-only branch.
The most promising protected finding is the combined service-token + inline
shape, but it should be treated as a regression-repair/blending problem rather
than a direct base. Future work should preserve the S160/S172 behavior and
target the shared `perf-sched-fork` regression first.
