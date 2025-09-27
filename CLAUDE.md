# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains `sched_ext` schedulers and tools. `sched_ext` is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. The repository contains various scheduler implementations in both C and Rust, along with support utilities.

## Build Commands

### C Schedulers
```bash
make all                          # Build all C schedulers
make install INSTALL_DIR=~/bin    # Install to custom directory
make clean                        # Clean build artifacts
```

Individual scheduler targets:
- Available C schedulers: `scx_simple`, `scx_qmap`, `scx_central`, `scx_userland`, `scx_nest`, `scx_flatcg`, `scx_pair`, `scx_prev`, `scx_sdt`

### Rust Schedulers
```bash
cargo build --release                 # Build all Rust schedulers
cargo build --release -p scx_rusty    # Build specific scheduler
cargo fmt                            # Format Rust code (required for PRs)
cargo test                           # Run unit tests including BPF tests
```

### Binary Locations
- **C schedulers**: `build/scheds/c/scx_simple`
- **Rust schedulers**: `target/release/scx_rusty`

### Environment Variables for BPF Compilation
- `BPF_CLANG`: The clang command to use (Default: `clang`)
- `BPF_CFLAGS`: Override all compiler flags for BPF compilation
- `BPFTOOL`: The bpftool command to use (Default: `bpftool`) - C schedulers only
- `CC`: The C compiler to use (Default: `cc`) - C schedulers only

Example:
```bash
BPF_CLANG=clang-17 make all
BPF_CLANG=clang-17 cargo build --release
```

## Testing

### Unit Tests
Run `cargo test` to execute all unit tests, including BPF unit tests for both C and Rust schedulers. The test driver code is written in Rust regardless of scheduler language.

### BPF Unit Testing
- BPF tests are created by adding a `*.test.bpf.c` file alongside the main BPF code
- Include the main BPF file and use `SCX_TEST()` macro to define tests
- Add test files to `rust/scx_bpf_unittests/build.rs` to enable building and running

## Architecture

### Directory Structure
```
scx/
├── scheds/               # Scheduler implementations
│   ├── include/          # Shared BPF and user C include files including vmlinux.h
│   ├── c/                # C schedulers (userspace code in C)
│   ├── rust/             # Rust schedulers (userspace code in Rust)
│   └── vmlinux/          # vmlinux.h and architecture-specific headers
├── rust/                 # Rust support code and libraries
│   ├── scx_utils/        # Common utility library for Rust schedulers
│   ├── scx_stats/        # Statistics framework
│   ├── scx_rustland_core/# Core library for userspace schedulers
│   └── ...               # Other support crates
├── tools/                # Utilities and tools
│   ├── scxtop/           # top-like tool for sched_ext events
│   ├── scxctl/           # Control tool for schedulers
│   └── ...
└── lib/                  # C support libraries
```

### Scheduler Types
- **C Schedulers**: BPF program + C userspace component
- **Rust Schedulers**: BPF program + Rust userspace component using scx_utils and related crates

### Statistics and Monitoring
Schedulers use `scx_stats` framework. To view scheduler statistics:
```bash
scx_SCHEDNAME --monitor $INTERVAL  # Monitor mode
scx_SCHEDNAME --stats $INTERVAL    # Direct statistics
```

## Dependencies

### Required
- `clang`: >=16 required, >=17 recommended
- `libbpf`: >=1.2.2 required, >=1.3 recommended
- `bpftool`: Usually in `linux-tools-common` package
- `libelf`, `libz`, `libzstd`: For linking against libbpf
- `pkg-config`: For finding system libraries
- `Rust` toolchain: >=1.82

### Kernel Requirements
The kernel must have:
- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_JIT=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_JIT_ALWAYS_ON=y`
- `CONFIG_BPF_JIT_DEFAULT_ON=y`
- `CONFIG_SCHED_CLASS_EXT=y`

See `kernel.config` for complete kernel configuration requirements.

## Development Notes

### Code Formatting
- Rust code must pass `cargo fmt` (uses nightly toolchain pinned in `rust-toolchain.toml`)
- This is enforced in CI and will fail PRs if not followed

### Build Systems
- **Primary**: Use `make` for C schedulers and `cargo` for Rust schedulers
- **Deprecated**: Meson builds are deprecated and will be removed

### BPF Development
- All BPF programs use common includes from `scheds/include/`
- BPF compilation flags are standardized across both build systems
- Use environment variables to customize BPF compilation (clang version, flags, etc.)

### Rust Crate Structure
The repository uses a Cargo workspace with multiple crates:
- Scheduler crates in `scheds/rust/`
- Support libraries in `rust/`
- Tools in `tools/`

### Testing BPF Code
- BPF unit tests can be created for both C and Rust schedulers
- Tests are driven by Rust code regardless of scheduler language
- Use `SCX_TEST()` macro and `scx_test_assert()` in BPF test files
- See `scheds/rust/scx_p2dq/src/bpf/main.test.bpf.c` for canonical example