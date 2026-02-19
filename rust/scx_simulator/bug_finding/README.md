# Bug Finding Infrastructure

This directory contains stress testing infrastructure for finding bugs in sched_ext
schedulers through randomized simulation.

## Overview

Unlike regression testing (`cargo test`, `./validate.sh`), bug finding:

- Runs for extended periods (potentially unbounded until Ctrl-C)
- Keeps all CPU cores busy searching for bugs
- Uses randomization to explore the search space
- Goal is to find scheduler stalls or crashes

## Running Stress Tests

### Quick Start

```bash
# Run stress tests on all cores until Ctrl-C or bug found
./bug_finding/stress.sh

# Run with specific number of parallel jobs
./bug_finding/stress.sh --jobs 4

# Run a single iteration (useful for debugging)
./bug_finding/stress.sh --once

# Run with verbose output
./bug_finding/stress.sh --verbose
```

### Test Parameters

The stress tests use:
- **2 second watchdog timeout**: Catches stalls quickly
- **4 seconds simulation duration**: Enough time for bugs to manifest
- **Random seeds**: Different seed per parallel run
- **BPF error detection**: Enabled to catch `scx_bpf_error()` calls

## Stress Test Scenarios

The stress tests exercise various workload patterns:

1. **Random task counts**: 1-32 tasks
2. **Random CPU counts**: 1-16 CPUs
3. **Random nice values**: -20 to +19
4. **Mixed workloads**: CPU-bound, I/O-bound, ping-pong, wake chains
5. **CPU affinity**: Random pinning patterns
6. **Hotplug events**: Random CPU offline/online

## Interpreting Results

When a bug is found, the script prints:

```
!!! BUG FOUND !!!
Scheduler: lavd
Seed: 12345
Exit: ErrorStall { pid: Pid(5), runnable_for_ns: 2000000000 }
```

Use the seed to reproduce:

```bash
cargo test -p scx_simulator stress_scenario -- --seed 12345
```

## Methodology

### Search Space Exploration

Each stress test iteration:
1. Generates a random scenario configuration
2. Runs simulation with detect_bpf_errors() and short watchdog
3. Checks for errors (stalls, BPF errors, crashes)
4. On success, moves to next seed

### Coverage Goals

The stress testing aims to exercise:
- DSQ operations under contention
- Vtime ordering edge cases
- CPU selection with affinity constraints
- Task wake chains and dependencies
- Scheduler internal state machine transitions

## Adding New Scenarios

Edit `crates/scx_simulator/tests/stress.rs` to add new stress patterns.
Each scenario should:

1. Use `.detect_bpf_errors()` to catch BPF errors
2. Use `.watchdog_timeout_ns(Some(2_000_000_000))` for 2s watchdog
3. Use `.duration_ms(4000)` for 4s simulation
4. Vary parameters with the provided seed
