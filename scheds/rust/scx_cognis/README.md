# scx_cognis

`scx_cognis` is a BPF-first `sched_ext` scheduler aimed at desktops, workstations, and general-purpose servers.

Cognis keeps the normal scheduling path in BPF. Rust remains in the process as a control plane for loading, topology export, stats, restart handling, the optional TUI, and a narrow compatibility fallback when work intentionally crosses into userspace.

> [!NOTE]
> This in-tree README is intentionally shorter than the standalone [galpt/scx_cognis](https://github.com/galpt/scx_cognis) README. For fuller benchmark notes, standalone install scripts, and additional operational details, see the main Cognis repository.

## Table of Contents

- [Overview](#overview)
- [Typical Use Cases](#typical-use-cases)
- [Profiles](#profiles)
- [Production Ready?](#production-ready)
- [Build and Run](#build-and-run)
- [Observability](#observability)
- [Design Notes](#design-notes)
- [Limitations](#limitations)
- [License](#license)
- [Inspirations and References](#inspirations-and-references)

## Overview

Cognis uses a BPF queue hierarchy and tries to keep normal scheduling decisions out of userspace:

- common path hierarchy: `CPU local DSQ -> LLC DSQ -> node DSQ -> shared DSQ`
- dispatch ordering: deadline-oriented with bounded wake credit
- remote balancing: cross-LLC and cross-node steals before the final shared spill path
- default CLI mode: `desktop`
- alternate CLI mode: `server`
- watchdog-triggered `sched_ext` exits are treated as non-restartable failures so Cognis fails open to the kernel scheduler instead of immediately re-executing itself

The BPF policy lives in [src/bpf/main.bpf.c](src/bpf/main.bpf.c). The Rust control plane lives in [src/main.rs](src/main.rs) and [src/bpf.rs](src/bpf.rs).

## Typical Use Cases

- desktop systems where wake responsiveness and locality matter
- workstations that alternate between interactive and sustained CPU load
- general-purpose servers that still want a BPF-first scheduler, but with broader spill behavior than the desktop profile

## Profiles

Both profiles use the same hierarchy. `desktop` is tuned for faster wake responsiveness and longer locality retention, while `server` reaches broader spill tiers sooner and favors steadier throughput under saturation.

| Profile | Default slice ceiling | Default min slice | Saturated-path bias |
|:--|:--|:--|:--|
| `desktop` | `1000 µs` | `250 µs` | favors local, LLC, and nearby-domain retention before broader spill |
| `server` | `8000 µs` | `1000 µs` | uses the same hierarchy but reaches node/shared spill sooner |

## Production Ready?

Conditionally.

For a validated target machine and workload mix, Cognis is intended to be usable as a production scheduler: the normal path stays in BPF, the Rust fallback is meant to be exceptional, and the default profile is tuned for desktop responsiveness.

However, Cognis does not claim to be universally production-ready across all kernels, topologies, desktop stacks, and server fleets without workload-specific validation.

## Build and Run

Build from the root of the `sched-ext/scx` repository:

```bash
cargo build --release -p scx_cognis
```

Run with the default desktop profile:

```bash
sudo ./target/release/scx_cognis
```

Run explicitly in desktop or server mode:

```bash
sudo ./target/release/scx_cognis --mode desktop
sudo ./target/release/scx_cognis --mode server
```

Only one `sched_ext` scheduler instance should be active at a time.

Selected options:

| Option | Current behavior |
|:--|:--|
| `--mode <desktop\|server>` | Selects the active BPF profile |
| `-s, --slice-us <N>` | Overrides the profile slice ceiling in microseconds |
| `-S, --slice-us-min <N>` | Overrides the profile minimum slice in microseconds |
| `-l, --percpu-local` | Forces explicit per-CPU dispatch for userspace-fallback tasks |
| `-p, --partial` | Only manages tasks already using `SCHED_EXT` |
| `-v, --verbose` | Enables verbose output |
| `-t, --tui` | Launches the TUI dashboard |
| `--stats <secs>` | Runs the scheduler and periodic stats output together |
| `--monitor <secs>` | Monitor-only mode; does not launch a scheduler |
| `--help-stats` | Prints descriptions for exported statistics |
| `-V, --version` | Prints the Cognis version and `scx_rustland_core` version |

## Observability

Cognis exports stats, a monitor view, and an optional TUI.

```bash
sudo ./target/release/scx_cognis --stats 1
sudo ./target/release/scx_cognis --monitor 1
sudo ./target/release/scx_cognis --tui
```

> [!IMPORTANT]
> - The common case is meant to avoid a Rust round-trip.
> - `nr_queued`, `nr_scheduled`, and `nr_user_dispatches` are compatibility-fallback signals. If they keep rising under a workload, work is escaping the intended BPF fast path.
> - `nr_local_dispatches`, `nr_llc_dispatches`, `nr_node_dispatches`, `nr_shared_dispatches`, `nr_xllc_steals`, and `nr_xnode_steals` describe how saturated work is moving through the BPF hierarchy.
> - The monitor's `base` slice is the profile ceiling. The fallback `assigned` slice is not a direct view of every live BPF dispatch slice.
> - The TUI and monitor are observability tools, not the scheduling engine itself.

> [!NOTE]
> The TUI is intended for diagnostics, not unattended long-running use.

## Design Notes

- BPF owns the normal scheduling path and makes the placement and deadline decisions that matter on the fast path.
- Rust exports topology, loads the scheduler, reports exits, drives observability, and keeps a compatibility fallback available.
- The Rust-side scheduler tables are fixed-capacity and allocated once at startup rather than grown on demand on the hot path.
- The BPF side uses bounded queue domains and per-task local state.
- `desktop` and `server` share the same hierarchy so the server profile remains a first-class mode rather than a neglected side path.
- Watchdog / runnable-task-stall exits fail open to the kernel scheduler instead of being treated as restartable runtime exits.

## Limitations

- Cognis is BPF-first, but not a pure BPF-only scheduler with no Rust companion.
- Production readiness still depends on machine-specific validation under the target desktop or server workload mix.
- The monitor exposes fallback slice state more directly than live BPF per-task slice state.
- The current mitigation for watchdog-triggered `sched_ext` exits is fail-open behavior, not a claim that the entire stall class has been eliminated.

## License

GPL-2.0-only

## Inspirations and References

These references informed Cognis' design and evaluation mindset, especially around deadline ordering, bounded wake credit, locality-aware hierarchy design, BPF-owned hot paths, and disable/fallback handling. They are inspirations and reference points, not a claim that Cognis automatically reproduces each cited paper's or project's published results.

### Papers

1. Linux kernel documentation. (n.d.). *EEVDF Scheduler*. https://docs.kernel.org/scheduler/sched-eevdf.html
2. Duda, K. J., & Cheriton, D. R. (1999). *Borrowed-virtual-time (BVT) scheduling: Supporting latency-sensitive threads in a general-purpose scheduler*. Proceedings of the 17th ACM Symposium on Operating Systems Principles. https://web.stanford.edu/class/cs240/old/sp2014/readings/duda99borrowed.pdf
3. Agrawal, K., & Sukha, J. (2011). *Hierarchical scheduling for multicores with multilevel cache hierarchies*. Washington University in St. Louis, Department of Computer Science and Engineering. https://openscholarship.wustl.edu/cse_research/66/
4. Wang, J., Trach, B., Fu, M., Behrens, D., Schwender, J., Liu, Y., Lei, J., Vafeiadis, V., Härtig, H., & Chen, H. (2023). *BWoS: Formally verified block-based work stealing for parallel processing*. 17th USENIX Symposium on Operating Systems Design and Implementation (OSDI 23). Used here as a steal-policy and hierarchy reference point rather than as a Linux CPU-scheduler blueprint. https://www.usenix.org/conference/osdi23/presentation/wang-jiawei

### Reference Schedulers

1. sched-ext maintainers. (n.d.). *scx_bpfland* [Software]. GitHub. https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_bpfland
2. sched-ext maintainers. (n.d.). *scx_beerland* [Software]. GitHub. https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_beerland
3. sched-ext maintainers. (n.d.). *scx_lavd* [Software]. GitHub. https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_lavd
4. sched-ext maintainers. (n.d.). *scx_cake* [Software]. GitHub. https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_cake
5. sched-ext maintainers. (n.d.). *scx_layered* [Software]. GitHub. Referenced directly in Cognis' disable-path comments and fallback handling pattern. https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_layered
6. sched-ext maintainers. (n.d.). *scx_rustland_core* [Software]. GitHub. Cognis still uses this crate as its userspace scaffold rather than reimplementing the loader/control-plane substrate from scratch. https://github.com/sched-ext/scx/tree/main/rust/scx_rustland_core
