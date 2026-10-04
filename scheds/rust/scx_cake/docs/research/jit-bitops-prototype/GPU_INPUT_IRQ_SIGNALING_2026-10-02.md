# GPU, input and IRQ signaling implementation — 2026-10-02

The research implementation is built and has passed the ordinary-kernel VM
contract and Cake activation checks. It carries input/fence wake causes through
existing kernel wakeups and exposes completed IRQ time to Cake. It has **no
measured hardware or game-performance result**, and the new policy defaults off.

## Current game-test defaults

An ordinary release invocation automatically detects native CTZ/POPCNT. It
leaves division-free arithmetic, native queue scanning, native histograms and
the new kernel signals off. The user's startup report confirms those settings:

```text
Kernel signals requested=Off available=false enabled=false policy=false counters=false
Native CTZ true
Native POPCNT true
Division-free false (CLZ/MULHI portable)
```

`available` checks the BTF `SCX_OPS_WAKE_SIGNAL` enum value and both v1 kfuncs,
even when requested mode is off. False means the complete interface was not
detected; it is independent of native scalar support. Rebuilding Cake does not
add this interface to the running kernel. `Task state Native kernel support`
reports a separate existing feature.

| Invocation option | Supported kernel | Unsupported kernel |
|---|---|---|
| No option / `--kernel-signals off` | Existing policy, signal tracking disabled | Existing policy |
| `--kernel-signals observe` | Track causes and IRQ samples; existing placement policy | Explicit warning and existing policy |
| `--kernel-signals on` | Experimental placement policy; counters off unless a report is requested | Explicit warning and existing policy |
| `--signal-report NEW.csv` | Save aggregate counters and histograms at exit | Report marks signals disabled |

A report requires requested mode `observe` or `on`, refuses to overwrite an
existing file, and adds instrumentation to an otherwise counter-free `on` run.
Even with a supporting kernel, policy activation requires `--kernel-signals on`.
The previous native-bitops Helldivers test needs no new flag or kernel build.

## Single inclusive kernel patch

Use [0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch](0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch)
on **fresh CachyOS 7.2.8-1 sources**, replacing earlier custom Cake patch entries.
It includes scalar operations, unary fastcall, precise verifier return bounds,
typed DSQ comparison, direct DSQ indexing and the signaling implementation.
Keep the distribution's normal patches and desktop configuration. The kernel
source version must match; do not force rejected hunks or stack the old Cake
bundle with this one.

SHA256: `081d13aa37735b023c7109ce450b68a4e9ded155f83f347a6ea77fbb3468718e`.
The [validation manifest](KERNEL_SIGNAL_BUNDLE_VALIDATION_2026-10-02.json)
records all 21 changed files. Application to independently extracted pristine
files passed with zero fuzz/offsets, byte equality to the recovered candidate,
and a reverse application check. The software fence and VGEM test modifications
are excluded. Full native scalar specialization still has the separate Cake
build requirements documented in the [earlier bundle guide](KERNEL_FULL_BUNDLE_2026-10-02.md).

No host kernel was installed or booted by this work. Testing the new policy on
hardware requires building and booting the new kernel, then choosing the mode
explicitly. The current default startup remains suitable for the user's prior
settings comparison.

## Data path and freshness

| Producer / reader | Implementation | Meaning and lifetime |
|---|---|---|
| evdev packet readiness | `drivers/input/evdev.c` | Type input wakes at the existing nonempty SYN_REPORT client wake |
| dma_fence direct wait | `drivers/dma-buf/dma-fence.c` | Fence completion wakes a blocked waiter |
| sync_file readiness | `drivers/dma-buf/sync_file.c` | Completion propagates through poll/epoll |
| DRM syncobj wait / completion eventfd | `drivers/gpu/drm/drm_syncobj.c` | Completion is typed; availability/materialization stays untyped |
| Waitqueue / epoll / eventfd forwarding | `kernel/sched/wait.c`, `fs/eventpoll.c`, `fs/eventfd.c` | Carry the cause through direct and nested wakeups |
| Accepted blocked wake | `kernel/sched/core.c` | Publish before remote wake queueing or CPU selection |
| Task reader | `scx_bpf_task_wake_signal_v1(p)` | Packed MONOTONIC timestamp and input/fence bits, cleared after `ops.running` |
| IRQ reader | `scx_bpf_cpu_irq_ns_v1(cpu)` | Existing cumulative completed hard/soft IRQ time; unknown is `U64_MAX` |

The task token is an atomic 64-bit value, with two low cause bits and timestamp
rounded down by at most 3 ns. An accepted untyped blocked wake clears the cause.
Failed, already-runnable and current-task wake paths do not create a new token.
This measures accepted blocked wake to `ops.running`, not device arrival to
photon or hardware interrupt to runnable. A scheduler opt-in static key avoids
the new metadata timestamp/write when disabled; the forwarding wrappers still
exist in the patched kernel.

The IRQ reader makes bounded reads of existing accounting, with online,
configuration and runtime checks. It takes no remote runqueue lock and queries
no device. It requires 64-bit IRQ time accounting for a known result. Completed
accounting excludes `ksoftirqd` task runtime and does not describe an interrupt
still in progress.

Cake's [signal helper](../../../src/bpf/wake-signals.bpf.h) uses a 2,000,000 ns
freshness limit. Each CPU samples IRQ totals at most once per 250,000 ns while
its running callbacks occur. Intervals above 4,000,000 ns, counter resets,
impossible deltas and missing counters discard pressure. More than 12.5% IRQ
time in a valid interval marks recent pressure. The pressure cache is published
as one packed timestamp/state word; stale observations do not reject a CPU.
These are experimental thresholds, not established optimal settings.

With policy on, a fresh typed wake bypasses serial co-location and avoids
mistaking the interrupted thread for a serial userspace waker. Fresh IRQ
pressure supplements Cake's existing IRQ checks. Idle claims, affinity,
queue/vtime ordering and fairness mechanisms remain in use; this does not add
runtime credits, deadline donation or GPU command submission.

The [kfunc documentation](https://docs.kernel.org/bpf/kfuncs.html) describes the
kernel/BPF interface constraints. The [dma-buf documentation](https://docs.kernel.org/driver-api/dma-buf.html)
describes fence and synchronization semantics; a generic fence can represent
software or non-display work and is not proof of frame presentation.

## Coverage limits

- This does not update urgency for already-running/runnable tasks, merge all
  pending causes, or construct a dependency graph.
- Deferred epoll rescans, `wake_q`, io_uring-specific/deferred paths,
  fasync/SIGIO, private driver waits, futex/NTSYNC and userspace relays do not
  all preserve the typed cause.
- NVIDIA private waits need not use these generic fence/syncobj paths. No
  firmware utilization query, GPU hardware timestamp or direct device control
  was added.
- The earlier live snapshot found KWin main/input/display threads under RR
  priority 1, outside Cake. No RT policy was changed. Input payloads are not
  recorded.
- Comparing off versus on on the same patched kernel cannot measure forwarding
  wrapper overhead relative to an unpatched kernel.

See the [pipeline investigation](GAMING_SIGNAL_PIPELINE_2026-10-02.md) and
[clock/freshness investigation](SIGNAL_FRESHNESS_CLOCKS_2026-10-02.md) for the
source locations and distinctions that motivated these boundaries.

## Validation and retained evidence

Before the user's `cargo clean`, the LLVM kernel build and release Cake build
completed. Cake unit/CLI tests, formatting and debug/release package Clippy
passed. The workspace's existing unrelated manifest-key warning remained.
The clean deleted the original build trees, images and unit/Clippy logs; the
following VM receipts and serial logs survived outside Cargo's target tree:

| Receipt | Result and scope |
|---|---|
| [production-load](../../../../../../../scx_cake_bench/runs/cake_wake_signals_20261002/production-load/result.json) | Production kernel without fixtures: off/observe/on load, activate and restore |
| [old-kernel-fallback-v2](../../../../../../../scx_cake_bench/runs/cake_wake_signals_20261002/old-kernel-fallback-v2/result.json) | Kernel without v1 signals: all three requested modes load, activate, fall back and restore |
| [contract-v7](../../../../../../../scx_cake_bench/runs/cake_wake_signals_20261002/contract-v7/result.json) | 20-case minimal scheduler contract, then the workload under Cake off/observe/on; clean detach |

The final contract covers read/poll/epoll/nested-epoll input and fence paths
with pinned and unpinned waiters, syncobj direct wait, completion eventfd,
availability eventfd and ordinary eventfd. It checks token timing/lifetime,
clearing after running, later untyped wakes, duplicate fence signals, empty
input reports and invalid-CPU IRQ queries. The final receipts recorded no
BUG/Oops/WARNING/panic lines and ended with the scheduler disabled.

| Cake contract counters | Observe | On with report |
|---|---:|---:|
| Input-tagged running callbacks | 8 | 8 |
| Fence-tagged running callbacks | 10 | 10 |
| IRQ samples | 335 | 335 |
| Unknown IRQ samples | 0 | 0 |
| Clock errors | 0 | 0 |

These counts validate signal delivery. TCG timings are not hardware latency
measurements. The uninstrumented `on` variant passed verifier loading; its
separate sustained runtime/performance run remains pending. Earlier failed
harness attempts are retained: custom DSQ setup, a test ioctl collision and
waiting for the actual syncobj sleep were corrected before `contract-v7`.

Additional IRQ-disabled output reached the success marker, but its post-run
artifact check was interrupted by cleanup and has no valid receipt. Count it
as diagnostic output only. The instruction-disabled CPU, four-CPU and clean
debug/KASAN/lockdep matrix remain pending. Prior baseline debug issues are
documented in the [DSQ report](DSQ_DIRECT_INDEX_2026-10-02.md); they are not
claimed fixed here. Kernel checkpatch on the packaged patch reports zero
errors, one warning and three checks, including one signal declaration
alignment check and inherited scalar-selftest style findings.

## Recovery and rerun inputs

The complete kernel source was recovered at
`/home/ritz/Documents/Repo/scx/target_signals_20261002/linux`, outside Cargo's
`target/`. The inclusive patch was reconstructed from fresh matching source
plus the retained [ordered edits](signal-tests/kernel-edits.json), with
formatting-only differences from the built implementation. This reconstruction
has clean application/byte-comparison evidence, not a second kernel build.
Older reports' `target/` image and build-log links may now be unavailable.

The retained [test directory](signal-tests/) contains the software fence
fixture, minimal BPF scheduler, userspace cases and VM init. The fixture and
VGEM SYNCOBJ/SYNCOBJ_TIMELINE feature additions are for isolated test kernels
only. The runner hashes its kernel/initramfs before and after the run and fails
closed if artifacts disappear or change.

For future reruns, prepare the desired kernel image, matching `vmlinux.h`, a
release Cake binary and a guest-compatible runtime root. That root must contain
the loader under `lib64`, plus libc, libelf, zlib, zstd, libgcc, libm, libbpf,
their link inputs and startup objects under `usr/lib`. The host runtime may
require instructions absent from the feature-disabled guest; do not assume
that rebuilding only the test executables makes its libraries portable.

```sh
python3 scheds/rust/scx_cake/docs/research/jit-bitops-prototype/signal-tests/build-vm.py \
  target_signals_20261002 --runtime-root /path/to/compatible/runtime
python3 scheds/rust/scx_cake/docs/research/jit-bitops-prototype/signal-tests/run-vm.py \
  target_signals_20261002 fresh-contract-run
```

The original full kernel configs were lost to cleanup, so these inputs must be
recreated; this is retained test source, not a preserved bit-for-bit build kit.
No further builds or benchmarks were started during the user's Helldivers test.
The remaining performance gate is a controlled hardware comparison of existing
policy, observation overhead and the experimental policy, with callback costs,
wake-to-run tails and game frame times reported separately.
