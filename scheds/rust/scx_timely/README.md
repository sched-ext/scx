# scx_timely

`scx_timely` is a `sched_ext` CPU scheduler built on top of [`scx_bpfland`](../scx_bpfland/README.md).

Its goal is to adapt the TIMELY paper's delay-driven feedback idea to CPU scheduling while keeping the inherited `bpfland` base small, understandable, and close to upstream behavior.

> [!IMPORTANT]
> `scx_timely` is still experimental. It should be read as a `bpfland`-based TIMELY adaptation, not as a literal transport-layer port of the paper.

## Overview

- `bpfland`-based scheduler with a narrower TIMELY-inspired control layer
- explicit Timely-style `Tlow` / `Thigh` delay regions
- queue-delay and delay-gradient feedback
- additive increase, multiplicative decrease, and HAI-style faster recovery
- built-in `desktop`, `powersave`, and `server` presets
- CLI overrides for the main Timely controller knobs
- local benchmark helpers for `mini`, `cachyos`, and `cachyos-quick`

## Modes

- `desktop`: the most validated profile so far and the main interactive preset
- `powersave`: more conservative behavior around delay growth, throttling, and recovery
- `server`: tuned around wider placement and more server-oriented policy knobs

All three modes use the same controller structure, but with different default thresholds and policy settings.

## Typical Use Cases

`scx_timely` is aimed at people who want a scheduler that reacts to measured queue pressure instead of staying locked into one fixed policy.

Typical use cases:

- gaming and mixed desktop workloads
- low-latency creative work such as audio editing or monitoring
- development machines doing local builds while staying responsive
- heavier background work where interactive feel still matters

If you want the safest public recommendation today, the more established upstream schedulers are still the better default pick.

## TIMELY Mapping

This project follows TIMELY's control ideas, but adapts them to CPU scheduling:

- RTT -> task queue delay
- send-rate control -> per-task slice gain
- `Tlow` / `Thigh` -> low/high queue-delay thresholds
- additive increase / multiplicative decrease -> slice-gain updates
- HAI -> faster recovery after several consecutive favorable samples

So the design is TIMELY-shaped, but not a word-for-word transport-layer port.

## Building and Running

Build from the workspace root:

```bash
cargo build --release -p scx_timely
```

Run it:

```bash
sudo ./target/release/scx_timely --mode desktop
```

Other presets:

```bash
sudo ./target/release/scx_timely --mode powersave
sudo ./target/release/scx_timely --mode server
```

## Status

- `desktop`: the most validated profile so far
- `powersave`: calmer and usable enough for now, but still experimental
- `server`: first repeated local checks landed in a healthy range

These are not production-readiness claims. They are only the current state of the profile tuning work.

## Notes

- The controller is intentionally narrow and keeps most of the inherited `bpfland` fast path intact.
- This in-tree README is intentionally shorter than the standalone [`galpt/scx_timely`](https://github.com/galpt/scx_timely) README. For standalone install scripts, local benchmark helpers, and extra tuning notes, see the standalone repository.

## References

1. Mittal, R., Lam, V. T., Dukkipati, N., et al. (2015). *TIMELY: RTT-based congestion control for the datacenter.* https://research.google/pubs/timely-rtt-based-congestion-control-for-the-datacenter/
2. `sched-ext` maintainers. *scx_bpfland* [Software]. https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_bpfland
