# scx_mlfq

scx_mlfq is a user-defined scheduler for Linux, written in Rust with a BPF core, that runs inside [`sched_ext`](https://github.com/sched-ext/scx/tree/main). It is a multilevel feedback queue built on EEVDF-style virtual time, and it is deliberately knob-free.


## Overview

Tasks are classified into three per-CPU queues, Q1 for interactive tasks, Q2 for unclassified tasks and Q3 for CPU-bound tasks, with 1/2/4 ms slices served in virtual-deadline order within a bounded dispatch batch. Classification is driven by a regression tree that predicts the next CPU burst from recent task behavior, trained in user space on the machine's own samples and republished every minute, with the EMA gauge as the fallback until the first model is published. A task that recently submitted GPU work is also treated as interactive, so a renderer that sleeps on a fence is not demoted to Q3.

The scheduler also implements wakeup boosts, run-out demotion, aging, a guaranteed Q3 share of every dispatch batch, cache-aware stealing and the placement sequence, and the details live in the code comments of the named files. The classification and boost rules are in `src/bpf/classify.bpf.c` and `src/bpf/enqueue.bpf.c`, the steal tiers in `src/bpf/dispatch.bpf.c`, the placement steps in `src/bpf/select_cpu.bpf.c`. Every placement clamps a task's lag to within one lag bound of its queue's virtual clock. This per-queue bounded-lag guarantee is documented in `src/bpf/intf.h`.

## Typical Use Cases

- Gaming and other latency-sensitive applications. Interactive tasks wake from short sleeps or I/O, promote to Q1, preempt lower-priority tasks, run at the maximum performance target, and prefer idle big cores on hybrid systems, so wakeup latency stays low.
- General desktop use. The desktop session stays responsive while background work such as software updates, file indexing, or compilation is demoted to Q3 and no longer competes with interactive tasks.
- Mixed workloads on laptops and desktops. CPU-bound jobs keep throughput with larger slices while the aging pass re-classifies tasks that wait in the lower queues for more than a second.

## Production Ready?

Yes


## Configuration

The scheduler is deliberately knob-free. The scheduling constants are compile-time values in `src/bpf/intf.h`, and no command-line option changes the scheduling behavior. The runtime footprint depends only on the reporting options, which are `--stats`, `--monitor` and `--no-webui`. The adaptive band tuning behind the compile-time constant `adapt_enabled` ships enabled. The wakeup-latency gauge reads the machine's average wakeup latency, and the wakeup-rate gauge and the band shift are live, with no command-line or configuration exposure. At startup a topology banner reports the CPU count, the big-core split, the LLC domains, the SMT state and whether one LLC domain is strictly the largest. The run also holds a 10 us PM QoS constraint on `/dev/cpu_dma_latency`, the maximum tolerated idle-exit latency.


## Web UI

A dashboard is served on the loopback address, port 50005, with a unix-socket fallback. It shows a plain-language Summary built from the live gauges, a compact per-CPU grid and the System counters, with no authentication, since the loopback address is the trust boundary. `--no-webui` disables it.

The loader's network sandbox is a seccomp filter the scheduler inherits and cannot lift in place. When the TCP bind is denied, the dashboard serves via the unix socket and the scheduler writes a per-boot runtime drop-in under `/run` that lifts the sandbox for the next start, removing it on exit. `/run` is tmpfs, so an unclean exit self-heals. The full mechanics live in the `src/webui.rs` comments.


## Real-time Core Avoidance

Realtime tasks take a CPU over when they become runnable, since the kernel resolves them to their own classes before sched_ext. The scheduler detects every takeover on the context switch, drains the DSQs of the taken-over CPU, and skips occupied cores in placement. The drain uses the 7.1 queue-DSQ re-enqueue path. If a scheduling callback stalls for longer than the 30 s watchdog, the scheduler exits and the kernel reverts to CFS. The details live in `src/bpf/rtdl.bpf.c`.


## Measuring Wakeup Latency

To measure the wakeup latency the scheduler delivers with cyclictest, pin the measurement threads to dedicated CPUs with `-a`, use the monotonic clock (`-c 0`), a realtime priority (`-p 99`), and the performance governor, and move the device IRQs off the measured CPUs. For percentiles, run schbench with two message threads (`-m 2`) on an otherwise quiet machine. `clock_nanosleep` passes the task's timer slack to the timer as an expiry range, so the kernel may defer the wakeup by up to the slack, 50 us by default. The measured value therefore includes the deferral, the interrupt path and the scheduler's wakeup latency, so cyclictest reports a conservative upper bound on the scheduler's contribution, not the scheduler's latency alone.


## Limitations

- The bounded-lag guarantee is per-queue. Cross-queue lag conservation is absent.
- The queues are per-CPU user dispatch queues, so locality comes from placement while idle CPUs steal owed tasks from wherever they sit.
- The runnable gauges cover tracked tasks only and are advisory.
- The largest-LLC bias trades clock speed for cache capacity, is Q1-only and non-exclusive, and is off on single-LLC and equal-size machines.
- The topology is snapshotted at attach, so a CPU hotplug needs a restart.
- sched_ext cannot schedule RT and DL tasks: the kernel resolves them to the rt and dl classes before sched_ext, so this scheduler handles SCHED_NORMAL, SCHED_BATCH and SCHED_IDLE tasks only.
- GPU submitter awareness is optional and self pruning. The amdgpu and gpu_scheduler tracepoints are used when they exist, otherwise the feature stays at zero.
- Requires Linux 7.1 or newer. The queue-DSQ re-enqueue and the `SCX_ENQ_IMMED` wakeup fast-path require 7.1; older kernels are not supported.

