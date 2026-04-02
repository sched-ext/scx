# Scheduler Benchmark Report (Deep Analysis)
Generated on: Thu Apr  2 08:21:29 AM IST 2026

## 1. Throughput & Execution Efficiency
*Higher Events/s and IPC is better. Lower Cache Misses and Compile Time is better.*

| Scheduler | Sysbench (Events/s) | IPC (instr/cycle) | Cache Misses (%) | Kernel Compile (s) | Hackbench (s) |
|-----------|----------------------|-------------------|------------------|--------------------|---------------|
| scx_rlfifo | 13067.02 | 0.83 | 13.45 | 107.02 | 0.730 |
| scx_rusty | 12799.96 | 0.87 | 18.29 | 107.33 | 1.043 |
| scx_rustland | 12775.35 | 0.87 | 15.14 | 106.13 | 0.719 |
| scx_rdtai | 12842.66 | 0.87 | 20.71 | 106.42 | 1.127 |

## 2. Wakeup Latencies (Schbench)
*Time from thread wake to execution. Lower is better (microseconds).*

| Scheduler | 50.0th (us) | 90.0th (us) | 99.0th (us) | 99.9th (us) |
|-----------|-------------|-------------|-------------|-------------|
| scx_rlfifo | 965 | 1007 | 1990 | 2018 |
| scx_rusty | 486 | 1550 | 4200 | 7816 |
| scx_rustland | 851 | 1662 | 2412 | 3148 |
| scx_rdtai | 221 | 4084 | 7960 | 12304 |

## 3. Request Latencies (Schbench)
*Time from request start to completion. Lower is better (microseconds).*

| Scheduler | 50.0th (us) | 90.0th (us) | 99.0th (us) | 99.9th (us) |
|-----------|-------------|-------------|-------------|-------------|
| scx_rlfifo | 10288 | 19296 | 33344 | 48192 |
| scx_rusty | 10320 | 21920 | 41664 | 64704 |
| scx_rustland | 9968 | 16480 | 30304 | 45248 |
| scx_rdtai | 9136 | 11344 | 16272 | 20960 |
