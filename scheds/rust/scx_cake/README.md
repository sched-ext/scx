# scx_cake

A Linux `sched_ext` CPU scheduler for gaming responsiveness and general use.

Cake keeps runnable tasks from waiting needlessly while preserving cache
locality and fair CPU service. Decisions use task activity and hardware
topology, never game names or profiles. The name comes from the CAKE network
queue manager.

This README describes this checkout; an installed package may differ
(`scx_cake --version`, `scx_cake --help`).

## Build and run

Requirements:

- A kernel with `CONFIG_SCHED_CLASS_EXT=y`, BPF and BTF
  ([kernel configuration](../../../kernel.config)).
- The repository's [Rust toolchain](../../../rust-toolchain.toml), Clang with
  BPF support and the libraries in the [build instructions](../../../README.md#build--install).
- Permission to load the scheduler (your scheduler service or administrator).

From the scx repository root:

```sh
cargo build --locked --release -p scx_cake
./target/release/scx_cake --version          # inspect, no attach
./target/release/scx_cake --print-topology   # inspect, no attach
./target/release/scx_cake                    # run the default policy
```

`cake build` (`./scheds/rust/scx_cake/cake build`) produces the same release
binary. `cat /sys/kernel/sched_ext/root/ops` shows the active scheduler; Cake's
name starts with `cake`. Ctrl+C detaches and returns to the kernel default.
Cake requests a five-second runnable-stall watchdog: a recovery mechanism, not a
latency guarantee.

## Stock kernel or custom patch

Cake runs on any supported kernel. Features from the experimental cake kernel
patch ([full signals patch](docs/research/jit-bitops-prototype/0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch))
are detected at startup on the running machine, never at build time; without
them Cake falls back automatically.

| Feature | Needs | Without it |
|---|---|---|
| Cached rq clock in `ops.running` | Stock ≥ 6.14 | `scx_bpf_now()` |
| Native CTZ/POPCNT | Custom patch, x86 BMI1/POPCNT | Portable builtins |
| `--kernel-signals` (input/fence wake, IRQ time) | Custom patch | Reports unavailable, runs normally |
| Direct DSQ index | Custom patch (kernel side, no Cake change) | Hash lookup |

Measured results and verdicts: [STATE.md](./STATE.md) pattern ledger.

## Command-line flags

Everything except the inspection flags is for testing; the default policy needs
no flags.

| Flag | Default | Behaviour |
|---|---|---|
| `-h`, `--help` | — | Print flags and toggles, exit |
| `-V`, `--version` | — | Print version and binary SHA-256, exit |
| `--print-topology` | — | Print topology and core preferences, exit |
| `-v`, `--verbose` | Off | libbpf output, startup detail, IRQ diagnostics, exit counts |
| `--inspect-bpf NEW_DIR` | Off | Load the BPF, dump instructions, exit without attaching |
| `--toggle NAME=0\|1` | — | Override a toggle (below); repeatable, last wins |
| `--handoff-ns NS` | — | Override the handoff threshold |
| `--native-bitops` | Auto | Require native CTZ/POPCNT; fail if unavailable |
| `--portable-bitops` | Off | Force portable CTZ/POPCNT |
| `--native-ring` | Off | CTZ queue scan on single-LLC hosts |
| `--native-hist` | Off | Native CLZ for probe histograms; only with `probe=1` |
| `--kernel-signals off\|observe\|on` | Off | `observe` counts signals; `on` uses them for placement |
| `--signal-report NEW.csv` | Off | Save signal counters at exit; needs `observe` or `on` |

Unknown options, such as old `--profile gaming` or `-p powersave` arguments
from `scx_loader`, are ignored with a warning and **Cake still starts** with the
remaining options. Invalid toggle specifications are ignored the same way.

## Toggles

| Name | Default | Controls |
|---|---|---|
| `probe` | `0` | Extra placement and delay diagnostics, reported at exit |

`-v` and `probe` are independent. Toggles are read at startup.

## How scheduling works

An **LLC** is a last-level cache shared by a group of CPUs; a **DSQ** is a
`sched_ext` dispatch queue. Cake has one owner queue per CPU and one wake pool
per LLC.

| Situation | Usual behaviour |
|---|---|
| A wake claims an eligible idle CPU | Insert directly on that CPU |
| A wake's mean wait exceeds twice its mean burst | Use its LLC wake pool |
| A task uses up its slice | Return it to its owner queue |
| A CPU needs work | Remote offers, own queue, wake pool, then other queues |

Placement weighs cache warmth, whole idle cores, SMT interference, platform
capacity hints and interrupt load (sampled IRQ share, active handlers, tick
look-ahead). A **seat** links a CPU to a pipeline-stage task; it is a
preference, not a reservation.

Virtual runtime orders service by CPU time and nice weight. The adaptive slice
uses lifetime runtime, age and voluntary switches, with a **1,464 ns floor** and
**1.5 ms cap**; some paths use a fixed **3 ms** slice. Details:
[DESIGN.md](./DESIGN.md).

## Limits

- Narrow claim, seat and per-LLC pool paths need present CPU IDs in 0–63; wider
  spans use the kernel idle picker and one pool.
- At most 16 LLC pools; more LLCs collapse to one.
- CPU-ID span limit 1,024 (possible CPUs included).
- A fixed **24 ms** starvation fallback lets dispatch favour an unserved pool
  ([DESIGN.md](./DESIGN.md#starvation-fallback-24-ms)).

## Tests and bug reports

```sh
cargo test --locked -p scx_cake
```

The tests do not attach the scheduler; the verifier-load test is ignored by
default and needs BPF permissions. For a bug report include the version or
commit, kernel version, CPU, launch arguments and scheduler and kernel logs.

## Source

| File | Purpose |
|---|---|
| [src/main.rs](./src/main.rs) | Loader: flags, topology, attach, IRQ monitoring |
| [src/bpf/cake.bpf.c](./src/bpf/cake.bpf.c) | Scheduling policy |
| [src/bpf/intf.h](./src/bpf/intf.h) | Shared constants and limits |
| [DESIGN.md](./DESIGN.md) | Policy and known limits |
| [STATE.md](./STATE.md) | Current status, pattern ledger, owed work |
| [docs/README.md](./docs/README.md) | Documentation map |
| [bench/README.md](./bench/README.md) | Bench tools |

License: GPL-2.0-only.
