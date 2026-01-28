# CLAUDE.md - AI Assistant Guide for sched_ext/scx

This document provides guidance for AI assistants working with the sched_ext schedulers repository.

## Project Overview

**sched_ext** is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. This repository contains:
- Various scheduler implementations (both example and production-ready)
- Shared libraries and utilities
- Development and monitoring tools

The project is primarily developed by Meta and Google, with sched_ext being fully upstreamed in Linux kernel 6.12+.

## Repository Structure

```
scx/
├── scheds/                 # Scheduler implementations
│   ├── c/                  # C schedulers (examples, synced with kernel tree)
│   │   ├── scx_simple      # Minimal global vtime/FIFO scheduler
│   │   ├── scx_central     # Central CPU scheduling decisions
│   │   ├── scx_flatcg      # Flattened cgroup hierarchy
│   │   ├── scx_nest        # Warm core scheduling (single socket)
│   │   ├── scx_pair        # Sibling scheduler for L1TF mitigation
│   │   ├── scx_qmap        # Weighted FIFO example
│   │   ├── scx_prev        # Prioritizes previous CPU
│   │   └── scx_userland    # User space scheduling decisions
│   ├── rust/               # Rust schedulers (production-capable)
│   │   ├── scx_bpfland     # General-purpose with topology awareness
│   │   ├── scx_rusty       # Load balancing with user space component
│   │   ├── scx_lavd        # Latency-aware virtual deadline
│   │   ├── scx_layered     # Layer-based scheduling policies
│   │   ├── scx_flash       # Fast, lightweight scheduler
│   │   ├── scx_cosmos      # Cosmos scheduler
│   │   ├── scx_p2dq        # Two-level dispatch queue
│   │   ├── scx_rustland    # User space Rust scheduling
│   │   ├── scx_mitosis     # Cell-based scheduling
│   │   ├── scx_tickless    # Tickless scheduling
│   │   ├── scx_chaos       # Chaos testing scheduler
│   │   ├── scx_wd40        # WD40 scheduler
│   │   └── scx_rlfifo      # Round-robin FIFO
│   ├── include/            # Shared BPF and C headers
│   └── vmlinux/            # Generated vmlinux headers
├── rust/                   # Rust support libraries
│   ├── scx_utils/          # Core utilities for Rust schedulers
│   ├── scx_stats/          # Statistics framework
│   ├── scx_rustland_core/  # Core for user space scheduling
│   ├── scx_arena/          # Arena allocator
│   └── scx_bpf_compat/     # BPF compatibility layer
├── lib/                    # Shared BPF libraries
│   ├── sdt_alloc.bpf.c     # SDT allocator
│   ├── topology.bpf.c      # Topology helpers
│   ├── ravg.bpf.c          # Running average
│   ├── rbtree.bpf.c        # Red-black tree
│   └── scxtest/            # Unit testing framework
├── tools/                  # Development tools
│   ├── scxtop/             # Top-like monitoring tool
│   ├── scxcash/            # Caching utility
│   ├── vmlinux_docify/     # Kernel documentation generator
│   └── xtask/              # Build task runner
├── scripts/                # Utility scripts (bpftrace, ftrace, etc.)
└── services/               # systemd service files
```

## Build System

### Building Rust Schedulers (Primary)

```bash
# Build all Rust schedulers
cargo build --release

# Build specific scheduler
cargo build --release -p scx_rusty

# Available build profiles:
# - release: Thin LTO (default production)
# - release-tiny: Stripped, optimized for size
# - release-fast: No LTO, faster compilation
cargo build --profile=release-tiny -p scx_flash
```

### Building C Schedulers

```bash
# Build all C schedulers (output in build/scheds/c/)
make all

# Build specific C scheduler
make scx_simple

# Install to custom directory
make install INSTALL_DIR=~/bin
```

### Dependencies

- **clang**: >=16 required, >=17 recommended (for BPF compilation)
- **libbpf**: >=1.2.2 required, >=1.3 recommended
- **bpftool**: Usually in `linux-tools-common`
- **Rust**: >=1.82 (stable channel, see `rust-toolchain.toml`)
- **libelf, libz, libzstd**: For linking

### Environment Variables

```bash
BPF_CLANG=clang-17 cargo build --release  # Specify clang version
BPF_CFLAGS="-O2 -g"                        # Override BPF compiler flags
```

## Code Conventions

### Rust Code

- Use `cargo fmt` for formatting (edition 2021)
- Stable Rust toolchain with `rustfmt` and `clippy` components
- Run `cargo test` for unit tests (includes BPF unit tests)

### C/BPF Code

- Follow kernel coding style (`.clang-format` provided)
- Run `clang-format` on C/BPF files
- 80 column limit
- BPF files use `.bpf.c` extension
- Test files use `.test.bpf.c` extension

### Pre-commit Hook

The repository includes a pre-commit hook (`.githooks/pre-commit`) that:
1. Runs `cargo fmt --all`
2. Runs `clang-format` on scx_mitosis BPF files

To enable: `git config core.hooksPath .githooks`

## Testing

### Unit Tests

```bash
# Run all tests
cargo test

# Run tests for specific scheduler
cargo test -p scx_flash
```

### BPF Unit Tests

BPF unit tests follow a specific pattern:
1. Create `main.test.bpf.c` alongside `main.bpf.c`
2. Include the main file and use `SCX_TEST()` macro
3. Register in `rust/scx_bpf_unittests/build.rs`

See `UNIT_TESTING_GUIDE.md` for details.

### Integration Tests

CI runs integration tests using `virtme-ng` with pinned kernels. Tests include:
- Scheduler loading/unloading
- Stress tests with `stress-ng`
- Per-scheduler flag variations

## Key Concepts

### Scheduler Architecture

1. **BPF Component** (`*.bpf.c`): Kernel-space scheduling logic
   - Implements `sched_ext_ops` callbacks
   - Uses dispatch queues (DSQs) for task management
   - Runs in kernel context with BPF safety guarantees

2. **User Space Component** (`main.rs` or `*.c`):
   - Loads BPF program
   - Handles configuration and statistics
   - May implement load balancing (e.g., scx_rusty)

### Dispatch Queues (DSQs)

- `SCX_DSQ_GLOBAL`: Global FIFO queue
- `SCX_DSQ_LOCAL`: Per-CPU local queue
- Custom DSQs can be created with `scx_bpf_create_dsq()`

### Core Callbacks

- `ops.select_cpu()`: CPU selection hint + wake idle CPU
- `ops.enqueue()`: Task enqueue decision
- `ops.dispatch()`: Populate local DSQ when empty

## Common Tasks

### Adding a New Rust Scheduler

1. Create directory under `scheds/rust/scx_<name>/`
2. Add to workspace in root `Cargo.toml`
3. Use `scx_utils` for common functionality
4. Implement BPF component in `src/bpf/`
5. Add README.md documenting the scheduler

### Debugging

```bash
# Enable Rust backtraces
sudo env RUST_BACKTRACE=1 ./target/debug/scx_flash

# Enable debug logging
sudo env RUST_LOG=debug ./target/debug/scx_flash

# List loaded BPF programs
sudo bpftool struct_ops list

# View scheduler state
cat /sys/kernel/sched_ext/state
cat /sys/kernel/sched_ext/*/ops
```

### Monitoring

```bash
# Use built-in monitoring
scx_bpfland --monitor 0.5

# Use scxtop tool
cargo build --release -p scxtop
sudo ./target/release/scxtop
```

## Important Files

- `Cargo.toml`: Workspace configuration and build profiles
- `rust-toolchain.toml`: Rust version (stable with rustfmt, clippy)
- `kernel-versions.json`: Pinned kernel versions for CI
- `.clang-format`: C/BPF formatting rules
- `meson.build`/`meson.options`: Alternative build system (legacy)

## CI/CD

The project uses GitHub Actions with:
- **bpf-next-test.yml**: Tests against BPF-next kernel
- **stable.yml**: Tests against stable kernel (scheduled)
- **integration-tests.yml**: Full scheduler integration tests
- **build-kernels.yml**: Kernel build caching

Tests run on self-hosted runners with Nix for reproducibility.

## Useful Tools for Development

- **bpftool**: BPF program/map inspection
- **retsnoop**: Kernel function tracing
- **bpftrace**: High-level BPF tracing
- **bpftop**: BPF program overhead monitoring
- **veristat**: BPF verifier statistics
- **stress-ng**: Synthetic load generation
- **turbostat**: CPU frequency/power monitoring
- **Perfetto**: Trace visualization (use `scripts/sched_ftrace.py`)

## Resources

- [Kernel sched_ext documentation](https://docs.kernel.org/scheduler/sched-ext.html)
- [eBPF documentation](https://ebpf-docs.dylanreimerink.nl/)
- [scx_utils rustdocs](https://sched-ext.github.io/scx/)
- [Discord community](https://discord.gg/b2J8DrWa7t)
- [Mailing list](mailto:sched-ext@lists.linux.dev)

## Notes for AI Assistants

1. **Prefer editing existing files** over creating new ones
2. **Run `cargo fmt`** after Rust changes
3. **Run `clang-format`** after C/BPF changes
4. **Check scheduler README** before modifying scheduler code
5. **BPF code has strict constraints** - verifier limits, no unbounded loops
6. **Test changes** with `cargo test` before committing
7. **Kernel compatibility** - changes may need to work across kernel versions
8. **Safety is paramount** - BPF provides safety guarantees, don't circumvent them
