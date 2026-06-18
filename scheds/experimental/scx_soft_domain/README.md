# scx_soft_domain

`scx_soft_domain` is a Rust scheduler for [`sched_ext`](https://github.com/sched-ext/scx/tree/main) that favors LLC and NUMA locality by keeping tasks on local domain CPUs.

## Overview

The scheduler reduces cross-node and cross-cache traffic by selecting CPUs based on underlying hardware topology and task affinity. It is intended for environments where memory locality and interference reduction are important.

## Features

- LLC-aware CPU selection
- NUMA node affinity preservation
- Per-task command filtering
- Lightweight BPF-based policy for `sched_ext`

## Building

```bash
cargo build -p scx_soft_domain
cargo build --release -p scx_soft_domain
```

## Running

For debug builds:

```bash
./target/debug/scx_soft_domain [options]
```

For release builds:

```bash
./target/release/scx_soft_domain [options]
```

## Options

- `-l <node>`: restrict scheduling to the specified NUMA node
- `-P <comm>`: only schedule tasks whose command name matches `comm`
- `-v`: increase verbose logging; repeat for more detail
- `-V`: print scheduler version and exit
- `--help`: show scheduler and libbpf options

> Note: the scheduler currently does not expose interactive debug output or runtime statistics printing beyond internal CPU load tracking.

## Requirements

- Linux with `sched_ext` support
- `libbpf` and the Rust `libbpf-rs` bindings
- root privileges to load the BPF scheduler

## License

GPL-2.0-only
