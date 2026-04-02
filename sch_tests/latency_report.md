# Latency & Complex Workload Benchmark Report
Generated on: Thu Apr  2 09:09:25 AM IST 2026

## 1. IPC & Messaging (Hackbench)
*Lower is better (seconds)*

| Scheduler | Run 1 (s) | Run 2 (Recorded) (s) |
|-----------|-----------|----------------------|
| scx_rlfifo | 0.664 | 0.667 |
| scx_rusty | 0.923 | 0.971 |
| scx_rustland | 0.636 | 0.634 |
| scx_rdtai | 0.992 | 0.953 |

## 2. Key-Value Store Latency (Redis)
*Lower is better (milliseconds at percentiles)*

| Scheduler | GET P50 | GET P95 | GET P99 | SET P50 | SET P95 | SET P99 |
|-----------|---------|---------|---------|---------|---------|---------|
| scx_rlfifo | 0.079 | 0.191 | 0.319 | 0.079 | 0.215 | 0.327 |
| scx_rusty | 0.223 | 0.303 | 0.311 | 0.151 | 0.199 | 0.207 |
| scx_rustland | 0.079 | 0.175 | 0.287 | 0.079 | 0.111 | 0.279 |
| scx_rdtai | 0.215 | 0.295 | 0.303 | 0.223 | 0.303 | 0.311 |

## 3. HFT Real-Time Jitter (Cyclictest)
*Wakeup latency under stress (microseconds). Lower is better.*

| Scheduler | Avg | P50 | P90 | P99 | Max |
|-----------|-----|-----|-----|-----|-----|
| scx_rlfifo | -nan | 000001 | 000011 | 000012 |  |
| scx_rusty | -nan | 000001 | 000011 | 000012 |  |
| scx_rustland | -nan | 000001 | 000011 | 000012 |  |
| scx_rdtai | -nan | 000001 | 000011 | 000012 |  |

## 4. Local Network Throughput (iperf3)
*Higher is better (Gbps)*

| Scheduler | Throughput (Gbps) |
|-----------|-------------------| 
| scx_rlfifo | 97.40916294257974 |
| scx_rusty | 78.23299809316066 |
| scx_rustland | 103.01202468086322 |
| scx_rdtai | 121.24479154566043 |
