# scx_timely v2

This is the experimental v2 branch of `scx_timely`, a TIMELY-inspired `sched_ext` CPU scheduler built on [`scx_bpfland`](https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_bpfland).

For the full documentation, benchmarks, and production-ready v1.1.0, see the [`main`](https://github.com/galpt/scx_timely) branch.

## What's New in v2

v2 introduces **pressure-aware load-balancing** inspired by [Swift](https://research.google/pubs/swift-delay-is-simple-and-effective-for-congestion-control-in-the-datacenter/) and [Shenango](https://www.usenix.org/conference/nsdi19/presentation/ousterhout):

- **Expand/Contract Mode**: The scheduler switches between locality-first and balance-first behavior based on sustained delay pressure
- **Global Pressure Tracking**: System-wide saturation signal drives policy decisions
- **Hysteresis**: Prevents oscillation between modes (expand at 75%, contract at 50% by default on desktop)

The core principle (per [TIMELY](https://research.google/pubs/timely-rtt-based-congestion-control-for-the-datacenter/)): **delay stays the main control signal**

## v2 Code Changes

For line-by-line diff against v1 (for reviewer reference), see [docs/design-vs-bpfland.md](docs/design-vs-bpfland.md).

For implementation details, see [docs/v2-pressure-mode-note.md](docs/v2-pressure-mode-note.md).

## Build and Install

```bash
sudo sh install.sh --build-from-source --force
```

## Modes

All modes (`desktop`, `powersave`, `server`) now benefit from v2 expand/contract behavior with mode-specific thresholds.

## Inspirations and References

1. `sched-ext` maintainers. *scx_bpfland* [Software]. https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_bpfland
2. Mittal, R., Lam, V. T., Dukkipati, N., et al. (2015). *TIMELY: RTT-based congestion control for the datacenter.* https://research.google.com/pubs/timely-rtt-based-congestion-control-for-the-datacenter/
3. Kabbani, A., et al. (2020). *Swift: Delay is Simple and Effective for Congestion Control in the Datacenter.* https://research.google.com/pubs/swift-delay-is-simple-and-effective-for-congestion-control-in-the-datacenter/
4. Ousterhout, A., et al. (2019). *Shenango: Achieving High CPU Efficiency for Latency-sensitive Datacenter Workloads.* https://www.usenix.org/conference/nsdi19/presentation/ousterhout
