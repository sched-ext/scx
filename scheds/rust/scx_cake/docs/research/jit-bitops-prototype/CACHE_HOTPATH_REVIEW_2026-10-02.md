# Cake caching and hot-path lookup review — 2026-10-02

Follow-up: [the direct index is now implemented and simulated](DSQ_DIRECT_INDEX_2026-10-02.md)
in an isolated kernel. The proposal below preserves its original evidence level;
the follow-up records build, correctness, timing limits and unresolved debug gates.

## Finding and evidence level

The strongest new caching candidate is a **kernel-owned direct index from DSQ
ID to queue object**, while continuing to read the queue's current count and
head. Cake creates a small, stable set of queues, but count, peek and move each
resolve their IDs again. This can remove repeated hashing without adding a
cache update on every task enqueue/dequeue.

This is a source review and experiment proposal, not a measured speedup. No
scheduler code, kernel, release executable or running scheduler was changed.
The user's system CachyOS package remains outside this work.

Sources inspected:

- Working-tree Cake on HEAD `8fc5ec9b105198286f7c9f7c53e2bf40308c3a4a`;
  the dirty source, not HEAD alone, defines this review.
- `src/bpf/cake.bpf.c` SHA-256:
  `9c12e59b99c96071b14f4c5f987932382cc4e8815bd84743d38f03c0cc148f60`.
- Retained 7.2.8 kernel candidate at
  `target/cake_deep_research_20261002T101516Z/linux/`, relative to the scx
  repository root. Its `kernel/sched/ext/ext.c` SHA-256:
  `732f895a46a2cd0c98a58b7aa3e839f952c2fdcf22662fd5c56388ecbc6fed54`.
  This is the earlier VM candidate, not proof of the exact installed host source.
- Official kernel documentation and upstream source linked below, accessed
  October 2, 2026. Exact local implementation takes precedence for this review.

## What is already cached

Source anchors below refer to [cake.bpf.c](../../../src/bpf/cake.bpf.c), unless
otherwise specified. These are existing mechanisms, not proposed changes.

| Data/work | Existing mechanism | Validity and avoided work |
|---|---|---|
| Topology and CPU preference | Loader-filled LLC masks, sibling IDs and steal order, around lines 1001–1058 | Precomputed for the scheduler instance; avoids rediscovering topology during selection. Topology changes require the existing lifecycle handling. |
| Nice-weight scaling | Reciprocal table and multiply/shift, around lines 1084–1112 | Small fixed weight domain; no repeated general division for ordinary vtime charging. Separate experimental dynamic division replacement is still disabled. |
| Idle/whole-core mask addresses | `cake_mask_cpu`, `cake_mask_smt`, lines 1194–1221; populated in `cake_init` | Caches the addresses of kernel-owned masks and reads their live words. Does not persist a supposedly current idle bitset. Avoids repeated get/put calls. |
| Selection inputs | `cake_pick_idle_clean`, line 2146 | Reuses idle/core/seat/noise snapshots and one clock reading within a search. Each chosen CPU still needs an authoritative idle claim. |
| Queue presence | `qmask`, pool pending accounting, `cake_dispatch_search`, line 2838 | A clear owner mark and zero pool token can avoid count and peek entirely, under the documented producer/consumer protocol. Remote marks remain hints. |
| Running-task accounting | Per-CPU `cake_run_slot`; `cake_running`, line 3229 | Retains starting runtime, timestamp and grant; stopping charges the runtime difference. Remote observations have separate consistency rules. |
| Pool service timestamp | `cake_wake_idle_refresh`, line 2730 | Compares the existing per-CPU run stamp before reading a new clock or writing a shared line. Freshness checking already avoids frequent writes. |
| Task-age time base | `cake_task_age`, line 403 | Reuses an initialization-time jiffies offset and coarse tick duration, with a precise-clock fallback. This approximation is restricted to lifetime calculations, not deadlines. |
| Seat ownership | `cake_seat_holders`, line 1617; `cake_running` | A conservative hashed holder census skips task-storage lookup for non-holders. Collisions cause extra lookups, not permission to skip necessary work. |
| IRQ preference | Averaged IRQ masks plus live per-CPU IRQ depth | Averaged load is an advisory preference. Live handler depth remains a separate read; an old average cannot establish that a CPU is currently outside an IRQ. |

Three additional caches already exist **inside the kernel**:

1. **DSQ head:** insertion/removal maintains `dsq->first_task`.
   `scx_bpf_dsq_peek()` resolves the queue, then reads that pointer under RCU.
   It is already a lockless head observation, not a list walk or a fresh
   spinlock acquisition. The head can change before a later operation; a peek
   does not reserve the task. See the inspected candidate's `ext.c:1605`,
   `1681`, `9816`, and
   [upstream implementation](https://code.googlesource.com/linux/torvalds/linux/+/a8934c2c6dfd72901cf3cc0de28e85eb902a61a4/kernel/sched/ext/ext.c).
2. **Task storage:** `bpf_task_storage_get()` requests a cached lookup.
   `bpf_local_storage_lookup()` first indexes
   `local_storage->cache[smap->cache_idx]`, checks the map identity and returns
   on a hit. Only a miss searches the task's storage list. See candidate
   `kernel/bpf/bpf_task_storage.c:168` and
   `include/linux/bpf_local_storage.h:144`. Adding a BPF hash cache around this
   operation could duplicate an existing faster cache.
3. **Runqueue clock:** `scx_bpf_now()` checks `SCX_RQ_CLK_VALID` and reads
   `rq->scx.clock` when valid; otherwise it calls `sched_clock_cpu()` for a
   fresh value. Cake uses it through `cake_now_rq()`. This is already a
   cheap validation followed by cache reuse, with validity controlled by
   the kernel's runqueue protocol. See candidate `ext.c:10539`. Repeated
   calls can return the same value within the valid period; Cake keeps
   this clock family separate from its monotonic-clock readings.

## Ranked opportunities

### 1. Direct DSQ index in the kernel

`find_user_dsq()` currently calls `rhashtable_lookup()`. Cake's owner DSQs use
CPU IDs; LLC pools use IDs 1026–1041. See
[intf.h](../../../src/bpf/intf.h), lines 75–81, and `cake_init`.
Cake creates these queues during initialization; no Cake runtime destroy call
was found in this review.

A per-scheduler table for IDs below 2048 would occupy **16 KiB of pointers on
a 64-bit kernel** and cover Cake's current ID layout. Arbitrary IDs retain
the hash path. Allocation can be conditional rather than charging every
scheduler instance that memory.

Current access:

```text
DSQ ID -> hash/bucket/key lookup -> DSQ object -> current count/head
```

Candidate access:

```text
DSQ ID -> bounds check + indexed pointer -> DSQ object -> current count/head
```

This caches the relatively stable **identity mapping**, not mutable scheduling
facts. Maintenance belongs to create/destroy, not every enqueue. Ordinary
reads need no timestamp-age test if publication and removal are correct.

Required design work:

- Keep each scheduler instance's namespace separate, including nested schedulers.
- Publish fully initialized objects; handle insertion/allocation failure.
- Serialize writers and remove the index entry on successful destruction.
  Destroy/recreate of the same ID must not let an old destroy clear a new entry.
- Preserve the existing dead-queue checks, reader lifetime and deferred freeing.
  Shutdown must clean up both indexes consistently.
- Preserve missing-ID errors, arbitrary-ID fallback and current move semantics.

RCU can protect an object's lifetime while readers access it; it does not make
queue contents immutable or replace writer synchronization.
[Kernel RCU documentation](https://docs.kernel.org/RCU/whatisRCU.html).

An internal index is a smaller initial interface change than exporting raw
queue pointers to BPF. A per-CPU last-queue cache is another possibility, but
adds scheduler/ID/lifetime validation and can miss as CPUs alternate queues.
It needs a demonstrated advantage over the direct table.

### 2. Resolve once for related queue observations

When owner and pool queues are both nonempty, `cake_dispatch_search()` can
perform two counts, two peeks and one successful move: **five user-DSQ
resolutions**. A count/head API that resolves each queue once could reduce
this case to three resolutions, including the move.

That is a call-path count, not a 40% callback or FPS improvement. Empty and
single-queue paths already avoid unnecessary peeks; an API must preserve that
advantage. Count and head from two lockless reads are not an atomic snapshot.
The move must still flush pending dispatches and perform its normal locking,
affinity and migration checks.

A callback-scoped checked handle could permit further reuse, but requires
verifier and lifetime design. Keep this separate from the internal-index
experiment so that its incremental value is measurable. The scheduling API
contract remains the starting point, including deferred dispatch behavior.
[sched_ext documentation](https://docs.kernel.org/scheduler/sched-ext.html).

### 3. Avoid redundant computation within one Cake decision

Prefer register/local reuse over introducing a persistent map. For example,
some selection paths evaluate `cake_starved_turn()` before falling through to
`cake_select_undecided()`, which evaluates it again. Check whether its inputs
remain stable across that particular path before sharing the result.

This is a small candidate, not an obvious win: keeping values live across
kfunc calls can add BPF spills. Several larger opportunities are already
taken: admission shares runtime/age calculations, idle selection reads the
clock once per search, and exceptional frontier scans share a timestamp.

Persistent caching of slices or classification is less attractive. Their
inputs include changing runtime, switch counts, delay and task age; task age
advances even while a task sleeps. Checking multiple keys and updating storage
may cost more than the arithmetic being replaced.

### 4. Reduce shared cache-line writes where the protocol permits

Cake already separates many per-CPU slots with 128-byte strides and avoids
unconditional queue-mark/service-stamp writes. The remaining shared pool,
seat and frontier state deserves profiling for cache-line transfer cost.
Independent CPUs writing the same line can outweigh savings from removing
several arithmetic instructions.

Distinguish false sharing between independent fields from true sharing of a
counter that all CPUs actually need. More padding only helps the first case
and increases footprint. Measure ownership/contended accesses before changing
layout or introducing another globally updated summary.
[Kernel false-sharing guide](https://kernel.org/doc/html/latest/kernel-hacking/false-sharing.html).

### 5. Cache a dynamic divisor's reciprocal only if reuse is high

The earlier division-free implementation paid reciprocal setup repeatedly.
Caching a reciprocal keyed by the exact normalized divisor, such as `nvcsw | 1`,
could amortize that setup if several uses share the divisor. This differs from
the already precomputed nice-weight table.

It is a low-priority hypothesis: establish uses per unchanged divisor first,
then account for lookup, state writes and invalidation. The five-repeat
[performance summary](PERFORMANCE_SUMMARY_2026-10-02.md) still shows +5.81%
aggregate BPF CPU for the tested division-free variant. This proposal does
not overturn that result or justify enabling it.

## Freshness and break-even

"Less than X microseconds old" is not sufficient for a scheduling decision
that depends on a concurrent event. An idle search can fail, another CPU can
become idle, and a later enqueue must still consider that CPU. Likewise, a
queue can acquire work immediately after an empty observation.

Use the validity mechanism appropriate to the data:

- Stable topology/identity: lifecycle-owned initialization and invalidation.
- One decision's input: local snapshot, with an authoritative action where needed.
- Queue-empty proof: producer/consumer ordering under the relevant locks or
  atomic protocol; a missed update can strand work.
- Policy preference: explicitly tolerate approximation and retain a progress path.
- Object pointer: correct lifetime protection as well as identity validation.

Do not cache idle-search failures across selection and enqueue, persist task
head pointers in Cake globals, or remove the fresh re-peek after failed moves
at `cake_dispatch_search` line 2989. Current code deliberately rechecks there.

For a rough cost model, let `R` be the original operation, `H` the cache
lookup plus validation, `h` the hit fraction, `F` the miss-fill cost and `U`
the amortized update/coherence cost per read:

```text
expected cached cost = H + (1 - h) * (R + F) + U
```

Caching pays only when this is below `R`. Include the cost transferred to
enqueue/running/stopping callbacks, not just the faster dispatch read.
Even a 100% hit rate can lose if validation and shared writes are expensive.

## Follow-up: change frequency, hit rates and cross-core cost

Read-only host inspection on October 2 found CPUs 0–15, eight physical cores,
one shared LLC, 64-byte cache lines, 48 KiB L1 data cache per core, 1 MiB L2
per core and 96 MiB shared L3. Sources: `lscpu -e` and CPU0 cache sysfs files.
This does not establish a measured cache-hit rate.

### How static is each opportunity?

| Candidate data | What changes it | Consequence for caching |
|---|---|---|
| DSQ ID → object pointer | Queue creation/destruction and scheduler teardown/restart | Cake creates queues only in `cake_init` and has no explicit destroy call. Normal steady-state mapping update rate is zero. A generic kernel implementation must still support other schedulers' dynamic queues. |
| Queue count | Each queue insertion/removal | Frequently mutable; keep reading the kernel's current counter. A second maintained copy adds writes and ordering obligations. |
| Queue head | Insertion of a new first task or removal of the current head | Potentially changes between two calls. Kernel already maintains it. Use only under its existing snapshot/lifetime contract. |
| Count/head lookup reuse | Resolve again on each applicable callback | Reuse the queue identity within the operation; do not extend the lifetime of old observations. Shared cache entries are unnecessary for a local temporary. |
| Task arithmetic inputs | Runtime accounting, voluntary switches, delay accounting, passage of time | Local common-expression reuse may help. Persistent classification/slice caches require several keys and are less compelling. |
| Reciprocal of `nvcsw \| 1` | When the normalized voluntary-switch count changes | The key can survive involuntary preemptions and adjacent counts such as 2/3. Blocking-heavy tasks offer less reuse than compute-heavy tasks. Actual reuse needs a census. |
| Shared pool/frontier/idle summaries | Scheduling, progress, idle claims and releases | These are actively written state. Investigate writer frequency and ownership rather than assume they are read-only. |

Candidate kernel anchors: queue count updates at `ext.c:1388` and `1426`,
head updates at `1605` and `1681`, creation at `9439` and destruction at
`4891`. `kernel/sched/core.c:7161–7187,7268` distinguishes voluntary and
involuntary switch accounting. These are event-based change descriptions;
this review did not record runtime events per second.

### Two different meanings of a hit

**Software coverage:** with all successfully created Cake custom queues
populated into an index covering IDs below 2048, valid steady-state custom-DSQ
lookups have **100% table coverage by construction**. This is not an empirical
percentage. Built-in local DSQs already use a separate path and are outside
this denominator. No demand-fill warm-up, eviction policy or per-hit update
is needed for the proposed direct index.

**CPU cache residency:** an indexed read can still miss L1 and be served by L2,
L3 or memory. The actual percentages are unknown. Source inspection cannot
justify a 99% L1-hit claim.

On this host Cake creates 16 owner queues and one pool, IDs 0–15 and 1026.
With a 64-byte-aligned pointer table, their entries occupy just **three cache
lines, 192 bytes**, despite the full array occupying 16 KiB. A CPU repeatedly
accessing its owner queue and the pool needs two of those lines. The small
working set makes frequent warm hits plausible, but game data, interrupts,
SMT contention, migration and idle/cache state can evict them.

For fused observations, the useful metric is the fraction of callbacks taking
the both-nonempty path and how many lookups they avoid; no persistent software
cache hit rate applies. For a reciprocal cache, if a task has `R` uses per
unchanged key, an ideal one-entry cache has `(R - 1) / R` hits: 50% for two
uses, 90% for ten. Those are examples, not observed Cake rates; overhead still
has to break even at the measured reuse rate.

### Retrieval cost: measured anchors versus estimates

Retained September 27 userspace microbenchmarks on this machine give these
warm-cache anchors, not kernel helper prices:

| Operation | Recorded time | Limit |
|---|---:|---|
| Dependent L1 pointer-chase load | 0.754 ns | `runs/isa_map_20260927/run2.txt`; small ring entirely warm |
| Stored pointer followed by dereference sequence | 1.784 ns | `var1.txt` and `var2.txt`; includes dependency-forming arithmetic, not just two bare loads |
| Current user-DSQ hash lookup | Not isolated in these measurements | The old cost ladder's 30–60 ns is an estimate, not a measured baseline |
| Proposed direct-index lookup | Not implemented/measured | A few nanoseconds is a plausible warm lookup target; not a prediction for the entire helper or a worst-case bound |

Raw files are under `/home/ritz/Documents/Repo/scx_cake_bench/`:

- [Pointer chase](../../../../../../../scx_cake_bench/runs/isa_map_20260927/run2.txt),
  SHA-256 `1f6cfe30f7e97aef81043d51d7a646d5361570d6b9810ee7200a0967dab85bbe`.
- [Pointer sequence run 1](../../../../../../../scx_cake_bench/runs/isa_map_20260927/var1.txt),
  SHA-256 `0b899df5cef939381c9c384cfc2360607149d494ca5fb44a4a2b781ffb365194`.
- [Pointer sequence run 2](../../../../../../../scx_cake_bench/runs/isa_map_20260927/var2.txt),
  SHA-256 `d71452e2cbc0590ef53f016828271a6e17169f5651e19464c4b160478bd1a8cf`.

These microbenchmarks select the best of repeated runs and derive their cycle
columns from an add-chain calibration. They are historical local timing
anchors, not fresh PMU measurements or confidence intervals. In `varbench.c`,
the separate cross-core reader uses `v & 0`, so its supposed dependency is
optimized away; its ns/read numbers are not individual cache-transfer latency.
They are deliberately not used as latency estimates here.

The current hash table is also served by hardware caches. The proposed saving
comes from removing hash arithmetic, bucket/node traversal and key checks,
not from turning every current memory access into an L1 access. Calls,
scheduler association checks, lifetime protection and access to the mutable
queue object remain. Do not subtract the raw-load time from the old estimated
hash price and report the difference as a scheduler win.

### Is the index read-only across cores?

**The index would be effectively read-only during ordinary Cake scheduling.**
Multiple cores may retain shared copies of its cache lines without repeatedly
invalidating each other. Read-only sharing still has compulsory fills and
capacity/SMT costs, but not the write-driven ownership traffic of a shared
counter. Keep per-hit counters, recency markers and frequently written control
fields off the index's lines; none is necessary for this design.

**The pointed-to queue objects are not read-only.** Their counts, heads, links
and locks change during scheduling. The new index cannot eliminate that
coherence cost. Existing hash metadata is also largely read-only between
queue lifecycle events, so removing all current cross-core traffic is not the
hypothesis. See the [kernel false-sharing guide](https://kernel.org/doc/html/latest/kernel-hacking/false-sharing.html).

RCU publication/removal and the existing destruction rules can protect rare
mapping changes without adding a shared refcount increment to every lookup.
This still requires a complete lifecycle implementation, not merely storing a
raw pointer. See [RCU](https://docs.kernel.org/RCU/whatisRCU.html).

The next measurement should separate table coverage, hardware miss rates,
lookup ns and whole-callback/game outcomes. Use per-CPU diagnostic counters
where needed and disable them for the ordinary release timing comparison.

## What the existing numbers support, and the next experiment

The [corrected historical profile](DEEP_RESEARCH_2026-10-02.md) attributed
`find_user_dsq` self samples to 2.340%, 5.488% and 13.102% of the respective
Cake-name sample denominators. Those archived kernels/builds differ from the
current release; the symbol resolver is approximate. This supports prioritizing
lookup work, not predicting an FPS increase or a current callback saving.

The older operation-cost audit contains estimates and older source assumptions.
In particular, a new cache should not be justified by claiming the inspected
peek takes a queue lock or that Cake reads the clock on every picker retry.
Both costs are already avoided in the inspected code.

The smallest useful next experiment is the kernel direct index alone, with
unchanged Cake policy and release flags:

1. Check create/destroy/recreate, invalid IDs, fallback IDs, allocation failure,
   scheduler teardown and concurrent readers in an isolated kernel.
2. Inspect the actual compiled lookup and verify Cake loading/liveness in a VM.
   VM/static evidence establishes correctness and implementation shape only.
3. Through the maintained harness, compare lookup/callback ns, total BPF CPU,
   wake-to-run/frame tails, throughput and noise at matched load. Keep diagnostic
   counters separate from normal release performance runs.
4. Follow with real-game frame measurements. Retain the change only on measured
   benefit without a progress/fairness regression; reverting the kernel experiment
   should require no Cake policy rollback.

The likely value comes from reducing repeated memory lookup and ownership
traffic. CTZ/POPCNT can help scan cached summaries, but cannot make a stale
summary correct or remove the cost of maintaining it.
