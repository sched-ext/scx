# scx_cognis

`scx_cognis` is a BPF-first `sched_ext` scheduler aimed at desktops, workstations, and general-purpose servers.

Cognis keeps the normal scheduling path in BPF. Rust remains in the process as a control plane for loading, topology export, stats, restart handling, the optional TUI, and a narrow compatibility fallback when work intentionally crosses into userspace.

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

The BPF policy lives in [src/bpf/main.bpf.c](src/bpf/main.bpf.c). The Rust control plane lives in [src/main.rs](src/main.rs) and [src/bpf.rs](src/bpf.rs).

## Typical Use Cases

- desktop systems where wake responsiveness and locality matter
- workstations that alternate between interactive and sustained CPU load
- general-purpose servers that still want a BPF-first scheduler, but with broader spill behavior than the desktop profile

## Profiles

Both profiles use the same hierarchy. `desktop` is tuned for faster wake responsiveness and longer locality retention, while `server` reaches broader spill tiers sooner and favors steadier throughput under saturation.

| Profile | Default slice ceiling | Default min slice | Saturated-path bias |
|:--|:--|:--|:--|
| `desktop` | `1000 us` | `250 us` | favors local, LLC, and nearby-domain retention before broader spill |
| `server` | `8000 us` | `1000 us` | uses the same hierarchy but reaches node/shared spill sooner |

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

## Limitations

- Cognis is BPF-first, but not a pure BPF-only scheduler with no Rust companion.
- Production readiness still depends on machine-specific validation under the target desktop or server workload mix.
- The monitor exposes fallback slice state more directly than live BPF per-task slice state.

## License

GPL-2.0-only

## Inspirations and References

- Caprita, R., Wong, C., & Zwaenepoel, W. (2005). Group ratio round-robin: O(1) proportional share scheduling for uniprocessor and multiprocessor systems. *USENIX Annual Technical Conference*. https://www.usenix.org/event/usenix05/tech/general/full_papers/caprita/caprita.pdf
- Chandra, R., Fink, S., & Vahdat, A. (2000). The case for surplus fair scheduling. *OSDI 2000*. https://www.usenix.org/events/osdi2000/full_papers/chandra/chandra.pdf
- Duda, K. J., & Cheriton, D. R. (1999). Borrowed-virtual-time (BVT) scheduling: Supporting latency-sensitive threads in a general-purpose scheduler. *SOSP 1999*. https://web.stanford.edu/class/cs240/old/sp2014/readings/duda99borrowed.pdf
- Linux kernel documentation. (n.d.). *EEVDF Scheduler*. https://docs.kernel.org/scheduler/sched-eevdf.html
- sched-ext maintainers and contributors. (n.d.). `scx_beerland`, `scx_bpfland`, `scx_cake`, `scx_cosmos`, `scx_lavd`, `scx_pandemonium`, and `scx_rustland` in the `sched-ext/scx` repository. https://github.com/sched-ext/scx
