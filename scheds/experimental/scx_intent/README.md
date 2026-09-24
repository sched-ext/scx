# scx_intent

An intent-based preemptive CPU scheduler for Linux built with `sched_ext` and `scx_rustland_core`.

## Origin & Architectural Foundation

`scx_intent` ports the 5-class intent-based scheduling architecture from the [Exploidus Operating System](https://github.com/rahadbhuiya/Exploidus) (`kernel/proc/scheduler.c`) into the Linux kernel ecosystem.

In modern desktop and server environments, treating every task as an abstract nice/vruntime value often introduces latency spikes for interactive workloads under heavy compilation or batch compute. `scx_intent` classifies tasks into five explicit runtime intent tiers and allocates dynamic execution slices tuned for each workload pattern:

### 1. The 5 Intent Tiers & Dispatch Priority

| Intent Tier | Target Workloads | Execution Slice | Dispatch Precedence |
|-------------|------------------|-----------------|---------------------|
| **Audit / Security** (`INTENT_AUDIT`) | Security auditing (`auditd`, `cnsl`), kernel monitoring | 10 ms | Highest (Rank 1) |
| **Interactive** (`INTENT_INTERACTIVE`) | Compositors (Wayland, Hyprland, Xorg), audio (`pipewire`, `pulse`), UI input | 4 ms | Rank 2 |
| **I/O** (`INTENT_IO`) | Storage daemons, database flushes, blocked I/O awakenings | 5 ms | Rank 3 |
| **Network** (`INTENT_NETWORK`) | Network stack handlers, socket processing (`sshd`, web servers) | 8 ms | Rank 4 |
| **Compute** (`INTENT_COMPUTE`) | Compilers (`gcc`, `rustc`, `clang`), batch rendering, mathematical tasks | 20 ms | Rank 5 |

### 2. Dispatch Mechanism & Starvation Prevention

- **Strict Precedence with Fair Drain**: In each scheduling cycle, higher-priority intent queues are drained first (`Audit -> Interactive -> IO -> Network -> Compute`).
- **Cache-Friendly Compute Slices**: Compute tasks receive a generous 20 ms time slice to maximize CPU L1/L2 cache residency and instructions-per-cycle (IPC).
- **Anti-Starvation Watchdog**: An anti-starvation counter guarantees that compute and background jobs are periodically serviced even under continuous interactive or I/O pressure.

## Usage

Build and run `scx_intent` with release optimizations:

```bash
cargo run --release --package scx_intent
```

## Authors & Acknowledgments

- **Rahad Bhuiya** <rahadbhuiya2021@gmail.com> — Author of `scx_intent` and the [Exploidus Operating System](https://github.com/rahadbhuiya/Exploidus).
