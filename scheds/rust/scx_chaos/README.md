<img src="logo.png" alt="scx_chaos" width="60%">

A general purpose `sched_ext` scheduler designed to amplify race conditions for testing and debugging.

## Overview

`scx_chaos` is a specialized scheduler that intentionally introduces various forms of latency and performance degradation to help expose race conditions and timing-dependent bugs in applications. Unlike traditional schedulers that aim for optimal performance, `scx_chaos` is designed to stress-test applications by introducing controlled chaos into the scheduling process.

**WARNING**: This scheduler is experimental and should not be used in production environments. It is specifically designed to degrade performance and may cause system instability.

## Features

The scheduler supports several "chaos traits" that can be enabled individually or in combination, with more to come:

### Random Delays

- Introduces random delays in task scheduling
- Configurable frequency, minimum, and maximum delay times
- Helps expose timing-dependent race conditions

### CPU Frequency Scaling

- Randomly scales CPU frequency for processes
- Configurable frequency range and application probability
- Tests application behavior under varying CPU performance

### Performance Degradation

- Applies configurable performance degradation to processes
- Uses a fractional degradation system
- Simulates resource contention scenarios

### Kprobe-based Delays

- **WARNING**: These delays are the most likely to break your system
- Attaches to kernel functions via kprobes
- Introduces delays when specific kernel functions are called
- Useful for testing specific kernel code paths

## Usage

### Basic Usage

Run without chaos features (baseline performance):

```bash
sudo scx_chaos
```

### Random Delays

```bash
sudo scx_chaos --random-delay-frequency 0.1 --random-delay-min-us 100 --random-delay-max-us 1000
```

### CPU Frequency Scaling

```bash
sudo scx_chaos --cpufreq-frequency 0.2 --cpufreq-min 400000 --cpufreq-max 2000000
```

### Performance Degradation

```bash
sudo scx_chaos --degradation-frequency 0.15 --degradation-frac7 64
```

### Kprobe Delays

```bash
sudo scx_chaos --kprobes-for-random-delays schedule do_exit --kprobe-random-delay-frequency 0.05 --kprobe-random-delay-min-us 50 --kprobe-random-delay-max-us 500
```

### Testing Specific Applications

Run a specific command under the chaos scheduler:

```bash
sudo scx_chaos [chaos-options] -- ./your-application --app-args
```

The scheduler will automatically detach when the application exits.

### Process Targeting

Focus chaos on a specific process and its children:

```bash
sudo scx_chaos --pid 1234 [chaos-options]
```

### Monitoring

Enable statistics monitoring:

```bash
sudo scx_chaos --stats 1.0 [chaos-options]  # Update every 1 second
```

Run in monitoring mode only (no scheduler):

```bash
sudo scx_chaos --monitor 2.0
```

### Repeat Testing

Automatically restart applications for continuous testing:

```bash
# Restart on failure
sudo scx_chaos --repeat-failure [chaos-options] -- ./test-app

# Restart on success
sudo scx_chaos --repeat-success [chaos-options] -- ./test-app
```

## Command Line Options

> **Note:** For the most up-to-date and complete CLI documentation, run `scx_chaos --help`. This includes all chaos-specific options as well as the full set of p2dq performance tuning options.

### Random Delays

- `--random-delay-frequency <FLOAT>`: Probability of applying random delays (0.0-1.0)
- `--random-delay-min-us <MICROSECONDS>`: Minimum delay time
- `--random-delay-max-us <MICROSECONDS>`: Maximum delay time

### CPU Frequency

- `--cpufreq-frequency <FLOAT>`: Probability of applying frequency scaling
- `--cpufreq-min <FREQ>`: Minimum CPU frequency
- `--cpufreq-max <FREQ>`: Maximum CPU frequency

### Performance Degradation

- `--degradation-frequency <FLOAT>`: Probability of applying degradation
- `--degradation-frac7 <0-128>`: Degradation fraction (7-bit scale)

### Kprobe Delays

- `--kprobes-for-random-delays <FUNCTION_NAMES>`: Kernel functions to probe
- `--kprobe-random-delay-frequency <FLOAT>`: Probability of kprobe delays
- `--kprobe-random-delay-min-us <MICROSECONDS>`: Minimum kprobe delay
- `--kprobe-random-delay-max-us <MICROSECONDS>`: Maximum kprobe delay

### General Options

- `--verbose`, `-v`: Increase verbosity (can be repeated)
- `--stats <SECONDS>`: Enable statistics with update interval
- `--monitor <SECONDS>`: Run in monitoring mode only
- `--ppid-targeting`: Focus on target process and children (default: true)
- `--repeat-failure`: Restart application on failure
- `--repeat-success`: Restart application on success
- `--pid <PID>`: Monitor specific process ID
- `--version`: Print version and exit

## Requirements

- Root privileges (required for `sched_ext` and kprobe operations)
- Modern Linux kernel with `sched_ext` support, chaos has very limited backward compatibility

## Use Cases

- **Race Condition Detection**: Expose timing-dependent bugs in multithreaded applications
- **Performance Testing**: Test application behavior under varying system performance
- **Stress Testing**: Validate application robustness under adverse conditions
- **Kernel Development**: Test kernel code paths with artificial delays
- **CI/CD Integration**: Automated testing with controlled chaos injection

## Statistics

The scheduler provides various statistics including:

- Random delay applications
- CPU frequency scaling events
- Performance degradation applications
- Kprobe delay triggers
- Process targeting exclusions

## Implementation Details

`scx_chaos` is built on the `sched_ext` framework and uses the `scx_p2dq` scheduler as its base. It implements chaos traits through BPF programs that intercept scheduling decisions and apply configured disruptions based on probability distributions.
