# Scheduler Benchmark Report
Generated on: Thu Apr  2 05:25:17 AM IST 2026

## 1. Throughput & Efficiency

| Scheduler | Sysbench (Events/s) | Cache Misses (%) | Kernel Compile (s) |
|-----------|---------------------|------------------|--------------------|
| scx_rlfifo | 12826.26 | 15.98 | 105.49 |
| scx_rusty | 12772.64 | 20.40 | 102.98 |
| scx_rustland | 12776.90 | 15.91 | 107.63 |
| scx_rdtai | 12658.75 | 18.92 | 107.45 |

## 2. Wakeup Latencies (Schbench)

| Scheduler | 50.0th (us) | 90.0th (us) | 99.0th (us) | 99.9th (us) |
|-----------|-------------|-------------|-------------|-------------|
| scx_rlfifo | 973 | 1005 | 1934 | 2014 |
| scx_rusty | 365 | 1258 | 3132 | 6824 |
| scx_rustland | 859 | 1630 | 2316 | 2996 |
| scx_rdtai | 210 | 4488 | 9744 | 16928 |

## 3. Request Latencies (Schbench)

| Scheduler | 50.0th (us) | 90.0th (us) | 99.0th (us) | 99.9th (us) |
|-----------|-------------|-------------|-------------|-------------|
| scx_rlfifo | 10736 | 20704 | 36032 | 52288 |
| scx_rusty | 10256 | 22560 | 42688 | 64320 |
| scx_rustland | 9872 | 16544 | 30496 | 45248 |
| scx_rdtai | 8944 | 11376 | 17888 | 26528 |
