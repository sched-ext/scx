# Direct DSQ index: implementation and simulation — 2026-10-02

The proposed kernel-owned lookup cache is implemented in an isolated kernel.
Six ordinary-kernel validation configurations and all 20 slots in a five-block
simulation passed. **A physical-hardware speedup is not established.** Debug
kernels expose two failures also observed on the baseline, so a clean debug
gate remains open. The host kernel, system package, Cake source and repo release
executable were not changed by this experiment.

This follows the [caching review](CACHE_HOTPATH_REVIEW_2026-10-02.md).

## Implementation

Each scheduler gets an optional 2048-entry array of RCU queue pointers: 16 KiB
on x86-64. IDs below 2048 use an indexed pointer read. Larger IDs and schedulers
without an allocated table retain the existing typed hash lookup. All queues
remain in the hash for lifecycle tracking. Allocation failure is nonfatal.

Creation publishes the pointer after successful hash insertion. Destruction
clears it after successful hash removal. A per-scheduler raw spinlock serializes
these rare updates so destruction cannot erase a newly recreated mapping.
Readers use existing lifetime protection and RCU; the fast lookup adds no
refcount, hit counter, shared write or time-based freshness check. The table
is freed during teardown and allocation-error unwind.

Only the ID-to-object mapping is retained. Queue counts, heads and contents are
read live, preserving the existing nonempty-destruction guard and deferred RCU
freeing. `array_index_nospec()` protects the indexed lookup. Scheduler association
checks and queue-object coherence costs remain.

The boot parameter `sched_ext.dsq_direct=0` selects hash-only operation in the
same candidate image. `/sys/kernel/sched_ext/root/dsq_direct_entries` reports
2048 when allocated, or 0 otherwise. These controls permit explicit path checks
without writes on each lookup.

Cake needs no new BPF API or source changes. Its custom IDs on this 16-thread,
one-LLC host are covered by the table: IDs 0–15 and 1026 occupy three 64-byte
table lines. That is software lookup coverage, **not a measured L1 hit rate**.
The queue objects themselves still change across cores. The design removes
hash work; it does not remove all shared-memory traffic.

## Patches and exact build

- [Complete kernel bundle](KERNEL_FULL_BUNDLE_2026-10-02.md) combines scalar
  instructions, fastcall, verifier bounds and these DSQ changes into one
  replacement patch for fresh CachyOS 7.2.8-1 sources.
- [Direct-index increment](0005-sched-ext-direct-dsq-index-cachyos-7.2.8.patch)
  applies after the [typed comparator](0004-sched-ext-typed-dsq-compare-cachyos-7.2.8.patch).
- [Direct index including typed fallback](0005-sched-ext-direct-dsq-index-with-typed-fallback-cachyos-7.2.8.patch)
  is the alternative for the retained source without that comparator. Do not
  apply both alternatives. Neither file is a complete scalar-instruction bundle.
- Both patches applied with zero fuzz to their recorded source bases and
  reproduced the two built kernel source files byte for byte. Checkpatch with
  `--strict --no-signoff` found zero errors, warnings or checks. These research
  patches have no submission sign-off; the normal submission check flags that
  missing trailer. Kernel and guest harness builds passed.
- Candidate workspace: `target/cake_dsq_index_20261002T201929Z/` in the scx repo.
  Baseline: `target/cake_deep_research_20261002T101516Z/`, already carrying the
  scalar fastcall/bounds and typed-comparison experiments. These are retained
  VM sources, not a claim about the exact installed host kernel source.
- Ordinary candidate kernel SHA-256:
  `2c785c1a6fc0c30197ff6410a3ff414c9a941011a588eab7837439621d73aacf`.
- Unchanged Cake release SHA-256:
  `059f78b352ef5c796754691ecd38dbbf0c896b10c2d0a85a383f1609fed94fef`.

The prototype is not installed or promoted to a production default. The
candidate kernel enables the index by default only within this experiment.
The existing automatic-native-bitops release behavior remains unchanged.

## What the actual assembly shows

The indexed path is inlined, while the hash fallback is deliberately outlined.
For a valid low ID it avoids calling the hashing function and its four register
save/restore pairs. It still executes bounds checks, loads the table address,
tests it, applies the speculation mask and reads the indexed pointer. The
enclosing kfunc's call overhead and saves remain.

| Compiled body | Baseline bytes / static instructions | Candidate bytes / static instructions |
|---|---:|---:|
| Hash lookup function | 297 / 91 | 297 / 91 |
| `scx_bpf_dsq_peek` | 220 / 56 | 264 / 66 |
| `scx_bpf_dsq_nr_queued` | 474 / 104 | 522 / 116 |

These counts include all branches in each body. The callers grow because they
now contain a direct branch and a fallback, even though a successful direct
lookup avoids executing the hash function. Static size is not dynamic instruction
count or latency. Disassembly is retained as `final-lookup.asm` and
`baseline-lookup.asm` in the candidate workspace.

## Ordinary-kernel correctness results

| Configuration | Result |
|---|---|
| Candidate, 2 vCPUs | Pass |
| Candidate, 16 vCPUs with SMT topology | Pass |
| Candidate, 2 vCPUs, direct allocation disabled | Pass |
| Candidate, 2 vCPUs, scalar CPU features disabled | Pass |
| Candidate, 4 vCPUs across two sockets / two reported LLC domains | Pass |
| Baseline typed-hash kernel, 2 vCPUs | Pass |

Across these six configurations: **393,216 concurrent lifecycle iterations**,
12 test-scheduler activations, 12 Cake inspection loads and 12 Cake
activation/workload/restoration checks passed, without kernel splats. Each
concurrent iteration attempts create, reads the queue count, then destroys;
the iteration count is not a count of successful creations. Expected duplicate
and missing results during races are accepted.

Each test-scheduler activation additionally performs 1025 sequential assertions
covering missing, duplicate, destroy/recreate and boundary IDs: 0, 1, 1026,
2047, 2048, 65536, 2^32 and 2^63−1; creation with the built-in flag is rejected.
Real scheduling queues at IDs 7 and 4096 exercise insert, count, peek and move.
Each guest repeats lifecycle activation/teardown and tests ordinary automatic
native bitops plus forced portable Cake.

The later simulation harness also checks scheduler identity and the actual
index allocation via sysfs. The six matrix receipts use the earlier retained
initramfs; both initramfs hashes and all results are recorded in the manifest.
Minimal guests lack `sha256sum` and emit a loader diagnostic; executable identity
is established externally by the initramfs manifest. QEMU also warns about its
synthetic AMD SMT model. Neither warning is a kernel splat.

## Debug findings: gate remains open

KASAN, lockdep, PROVE_RCU and DEBUG_ATOMIC_SLEEP images were built for both
baseline and candidate. Workload assertions passed, but the runner correctly
marked the affected boots failed:

1. The candidate reported a possible lock cycle between `p->pi_lock` and a
   workqueue pool lock. **The unchanged baseline reproduced the same cycle**
   in `baseline-kasan-poc-on-retry`. The trace goes through
   `select_task_rq_fair()` → `poc_check_skip_fallback()` → `schedule_work()`
   (`kernel/sched/poc_selector.c:1530`) during scheduler teardown. The new
   DSQ index lock is absent. This establishes that the cycle predates this
   index patch; it does not dismiss the warning as harmless.
2. Separate candidate and baseline boots reported an early KASAN
   wild-memory-access from `do_raw_spin_lock()` → `handle_edge_irq()` during
   `identify_boot_cpu()`, before guest init or scheduler activation. Its root
   cause is unresolved. Disabling the POC selector inside the candidate guest
   does not address a failure that occurs before init; those runs still fail.

Failed logs are retained alongside successful logs. No debug pass is claimed.
Resolving these baseline issues or establishing a clean equivalent debug setup
is required before promoting the kernel experiment. No host sysctl was changed.

## Five-block fixed-work simulation

QEMU TCG executed the actual ordinary candidate kernel and unchanged release
Cake. The two arms differ only in whether direct table allocation is enabled.
Five alternating ABBA/BAAB blocks give 20 boots, ten per arm. All slots verified
the chosen path, finished their work, matched per-worker checksums and restored
the guest to `sched_ext=disabled`.

Each slot uses two vCPUs and four pinned workers: two compute/sleep workers on
CPU 0 and two compute/yield workers on CPU 1. Each worker performs 160 iterations
of 20,000 xorshift steps. Total: **12,800 synthetic iterations and 256 million
work steps**. These are not rendered game frames, despite the harness's `frames`
field name.

| Block | Hash wall time (ms) | Direct wall time (ms) | Direct − hash (ns) | Change |
|---|---:|---:|---:|---:|
| 1 | 182.420547 | 182.295580 | -124,966.0 | -0.069% |
| 2 | 181.905816 | 179.528749 | -2,377,067.5 | -1.307% |
| 3 | 182.391890 | 181.358923 | -1,032,967.5 | -0.566% |
| 4 | 182.842593 | 182.665727 | -176,866.0 | -0.097% |
| 5 | 179.205892 | 182.704679 | +3,498,787.5 | +1.952% |

Average wall time: hash **181.753348 ms**, direct **181.710732 ms**;
difference **-42,615.9 ns (-0.023%)**.
The paired bootstrap 95% interval spans **-1,486,606.9 to +1,867,685.8 ns**.

Mean per-slot maximum deadline lateness: hash **1.818387 ms** versus
direct **1.226178 ms**, difference **-592,209.1 ns**.
Its bootstrap interval is [-967,404.5, -7,023.6] ns.
Four blocks improve and block 5 regresses on both metrics. This emulated
deadline observation is recorded for completeness, not accepted as a latency win.

TCG has no faithful model of this host's cache latency or coherence. The
`wake_late_max_ns` field measures iteration completion lateness against an
absolute sleep deadline, including computation overruns. It is not scheduler
wake-to-run latency, input latency, frame time or lookup time. Five blocks are
a small diagnostic sample; the bootstrap intervals describe these observations
only. The wall-clock result is inconclusive, and the emulated deadline result
cannot establish a physical-hardware latency win.

## Evidence and remaining work

[Validation manifest](dsq-index-data/validation.json),
[simulation CSV](dsq-index-data/simulation.csv),
[simulation analysis](dsq-index-data/simulation.json), and
[test source/reproduction notes](dsq-index-tests/README.md) are retained here.
Raw serial logs and per-run receipts are under the sibling
`scx_cake_bench/runs/cake_dsq_index_20261002T201929Z/` directory.
The manifest includes failed debug runs and source/binary hashes.

Actual allocator fault injection, simultaneous nested-scheduler namespace
isolation, nonempty-destroy rejection tests, long-duration stress and CPU hotplug
are not covered by this matrix. Disabling allocation exercises the NULL-table
fallback but does not force the allocator to fail.

After the debug gate is clean, the next performance gate is matched hardware
A/B testing through the maintained harness: lookup/callback ns, BPF CPU time,
throughput, wake-to-run tails and actual game frame data. Keep path/hit diagnostics
separate from release timing. Measure L1/LLC misses and shared-line behavior;
do not infer a hit rate from the table fitting in cache or translate the prior
warm-load primitive cost directly into a scheduler saving.
