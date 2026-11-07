# scx_intent

An intent-based preemptive CPU scheduler for Linux built natively with `sched_ext` and in-kernel BPF.

## Origin & Architectural Foundation

`scx_intent` ports the 5-class intent-based scheduling architecture from the [Exploidus Operating System](https://github.com/rahadbhuiya/Exploidus) (`kernel/proc/scheduler.c`) into the Linux kernel ecosystem.

Rather than relying on userspace round-trips or generic vruntime curves, `scx_intent` runs entirely inside the Linux kernel via eBPF struct_ops and manages 5 dedicated BPF Dispatch Queues (DSQs). Workloads are classified by runtime intent and assigned explicit execution slices:

### 1. The 5 Intent Tiers & Dedicated DSQs

| Intent Tier | Target Workloads | DSQ ID | Execution Slice | Dispatch Precedence |
|-------------|------------------|--------|-----------------|---------------------|
| **Audit / Security** (`INTENT_AUDIT`) | Security auditing (`auditd`, `falco`, `apparmor`), kernel monitoring | `DSQ_AUDIT` (0) | 10 ms | Highest (Rank 1) |
| **Interactive** (`INTENT_INTERACTIVE`) | UI compositors (Wayland, Hyprland, Xorg), audio (`pipewire`, `pulse`), shells | `DSQ_INTERACTIVE` (1) | 4 ms | Rank 2 |
| **I/O** (`INTENT_IO`) | Storage engines, database flushes, blocked I/O awakenings | `DSQ_IO` (2) | 5 ms | Rank 3 |
| **Network** (`INTENT_NETWORK`) | Socket handlers, ingress packet filters (`sshd`, web servers) | `DSQ_NETWORK` (3) | 8 ms | Rank 4 |
| **Compute** (`INTENT_COMPUTE`) | Compilers (`gcc`, `rustc`, `clang`), batch rendering, mathematical tasks | `DSQ_COMPUTE` (4) | 20 ms | Rank 5 |

### 2. In-Kernel BPF Dispatching & Multi-Tier Anti-Starvation

- **In-Kernel Classification**: Tasks are classified at `ops.enqueue` inside BPF and directly routed to their dedicated DSQ, eliminating userspace context-switch overhead.
- **Priority Drain**: Each scheduling pass prioritizes higher tiers (`Audit -> Interactive -> IO -> Network -> Compute`).
- **Comprehensive Multi-Tier Anti-Starvation**: When higher tiers consume CPU time under saturation, lower tiers (`Compute`, `Network`, `IO`, `Interactive`) track starve cycles. When a tier's starvation counter reaches the configured threshold (default: 32), it is granted an immediate priority dispatch slot, ensuring no tier is starved.

## Usage

Build and run `scx_intent` with release optimizations:

```bash
# Run with default desktop preset
cargo run --release --package scx_intent

# Run with gaming preset (prioritizing Proton, Steam, Gamescope, Wayland)
cargo run --release --package scx_intent -- --preset gaming

# Run with custom user-defined JSON configuration file
cargo run --release --package scx_intent -- --config intent.example.json
```

Command-line options:

```bash
scx_intent --help
```

## Authors & Acknowledgments

- **Rahad Bhuiya** <rahadbhuiya2021@gmail.com>: Author of `scx_intent` and the [Exploidus Operating System](https://github.com/rahadbhuiya/Exploidus).
