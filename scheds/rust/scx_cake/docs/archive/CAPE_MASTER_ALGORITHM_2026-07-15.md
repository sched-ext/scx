# CAPE: the master replacement shape

Date: 2026-07-15 (America/Chicago)

Status: **executable exact law plus normalized integer, verifier-shaped
single-domain SMP custody, lifecycle, and ER/IR/EB/IB source reference
implemented; sched_ext behavior unchanged; compilation, verifier load, and
performance unproven**.

## Outcome

The corpus does not support another fixed Cake knob or learned workload mode.
Every broad historical candidate reverses sign somewhere. The next complete
shape is **CAPE — Custody-Aware Proportional Eligibility**:

> Admit service by an explicit bounded lag ledger, order eligible requests by
> virtual deadline, and decide CPU custody separately. Locality may break an
> ordering tie; it may not manufacture eligibility or bypass an older eligible
> claim.

CAPE keeps the part Cake repeatedly wins with — cheap event-driven placement,
local continuation custody, wake discoverability, and topology-aware stealing —
while adding the service law that current Cake lacks. It is intended first as a
sched_ext challenger and, only after clean wins, as the policy for a complete
Linux fair-scheduler replacement.

## Exact evidence boundary

- Scheduler tree: `/home/ritz/Documents/Repo/scx`
  - branch: `codex/scx-cake-nightly-perf-review-20260709`
  - HEAD: `555c387a9a9fb96fb87563cb4623455386e4529a`
  - current scheduler diff SHA-256: `0bc2bd900e4efdb37f1f7448fafa401bad52e1847cb62e70511f2c736ed8f689`
  - `cake.bpf.c` SHA-256: `5e87d4e88c518792dab9b89905b326226fe74f39dad6cab415c30c67946bd1aa`
  - `intf.h` SHA-256: `b735fc4ce596c198d1ba0024603ec278d42f4444814fe722cbe792571e27b863`
- Running kernel: `7.1.3-2-cachyos`
  - sched_ext state: `disabled`, enable sequence `0`
  - live BTF SHA-256: `ee6f910c4ee269869533c14b0ba04b08a8166fdafacd0d28fadaa568d641508a`
  - `CONFIG_IRQ_TIME_ACCOUNTING=y`, `CONFIG_HAVE_SCHED_AVG_IRQ=y`
- Rootless live IRQ sample:
  - capture: `/home/ritz/Documents/Repo/scx_cake_bench_assets/runs/irq_audit/2026-07-15_070355_native-desktop-codex-active-20260715T0705/irq_audit.json`
  - JSON SHA-256: `944422f069c96ec6842cce0dfb9fb085030d710607951770a2bdfb3c2c1fdb71`
  - 10.008 seconds, 1,806.3 hard IRQ/s, 3,705.2 softIRQ/s
  - IRQ 46 `xhci_hcd`: 1,190.1/s on CPU 5; IRQ 115 `nvidia`:
    518.8/s on CPU 13; CPUs 5 and 13 are SMT siblings
- Reference Linux source: `v7.2-rc1-10-g4a50a141f05a`
- Global loss map:
  - generation: `lm1-35f7105576f0aca9d79b3503`
  - basis SHA-256: `35f7105576f0aca9d79b350396979ee02731a7c32643e886b5fdbc5adb3bf999`
  - JSON SHA-256: `a7a061b324722991a339b2383e2a95456dc7919cabfc5f964d2cec64d1eb3f72`

The map is directional only: zero promotion-eligible effects, zero trusted
counterexamples, zero trusted game comparisons, and no current-H1 performance
result. CAPE is a falsifiable design selected from this evidence, not a score
claim.

## What the complete corpus says

### Historical EEVDF gaps

| field | best historical Cake gap | governing mechanism |
|---|---:|---|
| stress-ng-futex | -15.0% | handoff custody, eligibility, wake lock cost |
| x265 | -5.0% | continuation warmth, migration, hot-path overhead |
| stress-ng-memcpy | -1.2% | streaming bandwidth, reconsideration/cache cost |
| perf-memcpy | -0.9% | scheduler overhead and memory interference |
| ffmpeg compile | -0.5% | short-task placement and callback overhead |
| kernel-defconfig / prime | missing official rows | evidence completion |

The historical frontier also contains large Cake wins in cache, pipe,
fork/thread, and saturated schbench. A replacement must retain those wins; it
cannot trade them away to repair futex or x265.

### Cross-candidate constraints

- 65 broad candidates cover at least seven benchmarks.
- All 65 reverse sign; none has a non-negative worst field.
- Best provisional minimax point is S09 at `-1.2345679%` worst case.
- Cache operations versus mixed memcpy is the strongest repeated opposition:
  Pearson `r=-0.740158`, `n=116` candidates.
- S09's useful mechanism is removal of shared scoreboard atomics.
- S11's useful mechanism is conditional, latency-gated idle search rather than
  permanent deep scanning.
- S203c shows that code layout alone can move most fields and still lose mixed
  memcpy. Scheduler instruction/helper cost is part of the policy result.

Therefore adaptability must come from current mathematical scheduling state,
not from selecting a benchmark regime. A fixed turn length moves along the
cache/streaming frontier; it does not eliminate that frontier.

## The missing separation in current Cake

Current Cake has one weighted `p->scx.dsq_vtime`, a shared maximum-like
frontier, per-CPU vtime queues, a global wake queue, and state-derived custody
rules. This is a useful service-age order, but it is not EEVDF:

1. it has no explicit service virtual-time contract;
2. it has no explicit eligible/ineligible split;
3. it has no separate virtual request deadline;
4. direct local insertion can become terminal before ordinary queue order;
5. locality and wake hysteresis partly stand in for missing eligibility.

Linux EEVDF explicitly maintains lag, admits only lag-nonnegative entities,
then chooses the earliest virtual deadline. CAPE retains this two-stage
service discipline while replacing Linux's placement/custody behavior with the
state-derived Cake mechanisms that have evidence.

## CAPE service law

For task `i` in service domain `c`, the selected CAPE candidate uses a
monotonic service clock:

```text
w_i       proportional weight
q_i       real request budget
V_c       monotonic service virtual time for the domain
ve_i      virtual eligibility time
vd_i      virtual deadline = ve_i + q_i / w_i
vlag_i    V_c - ve_i

eligible(i,c) := ve_i <= V_c
pick(c)       := arg min (vd_i, arrival_sequence_i)
                 over eligible compatible tasks
```

While a task runs for `u_i` with runnable domain weight `W_c`, advance:

```text
V_c' = V_c + u_i / W_c
```

Join, block, wake, and weight-change events do not translate peer `V_c`. This
is a deliberate CAPE policy distinction, not a claim of exact dynamic Linux
EEVDF equivalence.

The first sched_ext experiment keeps `q_i` fixed. Explicit kernel/user request
size is a later input; predicted burst, executable identity, benchmark labels,
and hidden task classes are not.

Runtime advances virtual service continuously, but a partial dispatch does not
silently issue a new request. After task `i` uses `u_i` service:

```text
ve_i' = ve_i + u_i / w_i

if ve_i' < vd_i:             # request still has service remaining
    vd_i' = vd_i
else:                        # request exhausted
    vd_i' = ve_i' + q_i / w_i
```

This distinction is required for preemption inside a request. Renewing
`vd_i` after every partial run would continuously push a preempted task's
deadline into the future and manufacture jitter.

### Block, wake, and reweight lifecycle

There are now two executable clock contracts, and they must not be conflated:

1. The **Linux-compatible weighted-average reference** preserves a zero active
   weighted-lag sum. Removing or adding a nonzero-lag task translates `V_c`;
   wake placement therefore needs the `(W+w_i)/W` compensation below.
2. The **CAPE monotonic candidate** advances `V_c` only with service. A sleeper
   owns a private bounded debt/credit token; lifecycle changes do not rewrite
   peers' clock or eligibility.

The original EEVDF report defines the base fluid virtual clock as the monotonic
integral `dV/dt = 1/sum(active weights)`, then separately defines a dynamic
Strategy 1 that translates `V` on nonzero-lag join/leave to redistribute that
lag. The report explicitly says compensation across activity periods has no
simple fairness answer. CAPE chooses not to transfer a sleeper's old debt or
credit into unrelated current peers. This choice still needs benchmark,
latency, and fairness falsification.

On blocking dequeue, retain bounded signed virtual lag rather than an absolute
deadline from an old competition:

```text
saved_vlag_i = clamp(V_c - ve_i, -lag_bound_i, +lag_bound_i)
```

In the Linux-compatible reference, removing the request changes the active
weighted-average virtual clock. On wake, let `W` be the already-runnable weight
and `w_i` the waking weight. To make the task's lag *after insertion* equal
`saved_vlag_i`, compensate for the task's own effect on that average:

```text
placement_vlag_i = saved_vlag_i * (W + w_i) / W
ve_i_preinsert   = V_c - placement_vlag_i
vd_i             = ve_i_preinsert + q_i / w_i   # fresh request after sleep
```

In the CAPE monotonic candidate no peer-clock translation occurs, so no wake
inflation is needed:

```text
V_c'       = V_c
ve_i       = V_c - saved_vlag_i
vd_i       = ve_i + q_i / w_i       # fresh request after sleep
```

When `W == 0`, place the only runnable task at zero lag and run it; CAPE never
idles a sole runnable task to enforce virtual debt. Delayed-dequeue or lag
decay for long sleepers is a separate intervention. It is not selected or
bundled into the first service-order candidate.

On a weight change from `w_i` to `w_i'`, preserve weighted lag and remaining
real request budget:

```text
(V_c - ve_i) * w_i = (V_c - ve_i') * w_i'
vd_i' - ve_i'      = remaining_real_request_i / w_i'
```

The exact-arithmetic v3 model remains the Linux-compatible lifecycle reference.
The v4 model adds the distinct monotonic CAPE contract, proves that lifecycle
events cannot move its clock backward or make an untouched READY peer
ineligible, and retains weighted steady-state service. Neither model is a
runtime, verifier, futex, or game-performance claim.

On non-sleep migration from service domain `a` to `b`, preserve bounded lag
and the remaining real request rather than copying incomparable absolute
timestamps:

```text
remaining_i = max(0, (vd_i - ve_i) * w_i)
vlag_i      = clamp(V_a - ve_i, -lag_bound_i, +lag_bound_i)
ve_i'       = V_b - vlag_i
vd_i'       = ve_i' + remaining_i / w_i
```

Sleep cannot erase negative debt or mint unlimited positive credit while a
competition exists. Preserve bounded lag at the service boundary. The exact
decay rule remains a separate intervention and must not be bundled with the
first service-order candidate.

If runnable work exists but no request is eligible, advance `V_c` to the
smallest compatible `ve_i` and run it. CAPE never idles merely to enforce a
virtual timestamp.

## Custody law

Eligibility says **whether** a task may receive service. Custody says **where
it waits**. These are separate decisions.

1. A runnable continuation stays with its last service domain for cache warmth.
2. A newly woken task must remain discoverable by the first compatible CPU that
   opens capacity.
3. An idle CPU may pull; a busy CPU does not push work merely to improve a
   topology score.
4. Same-core/LLC/CCD/V-Cache locality is an exact-deadline tie-break in CAPE v1.
5. The final escape is unrestricted across every compatible CPU, preserving
   work conservation.
6. RT/DL service plus IRQ/softIRQ stolen time discounts usable capacity. A CPU
   with an empty fair queue but sustained IRQ pressure is not idle-equivalent,
   and an SMT core's capacity includes pressure on both siblings.

The first BPF implementation should retain current Cake's local-continuation
and wake-discovery behavior until the service law is independently measured.
Changing queue representation and custody in one candidate would make any
result unattributable.

## IRQ-aware custody without workload identity

The reference Linux fair scheduler already models this distinction. Its
`rq->avg_irq.util_avg` feeds `cpu_util_irq()` and `scale_irq_capacity()`;
`scale_rt_capacity()` discounts RT, DL, and IRQ utilization before load
balancing. By contrast, the reference sched_ext default selector
`scx_select_cpu_dfl()` searches idle CPUs and topology but does not rank those
idle choices by IRQ capacity. This is a plausible missing input, not proof that
it caused any Cake loss.

The live 10-second sample found a repeatable-looking experiment candidate:
USB xHCI IRQ 46 and NVIDIA IRQ 115 delivered a combined 1,706.9 interrupts/s
to the two threads of SMT core `[5,13]`. The xHCI controller currently hosts a
GoXLR and Logitech USB receiver. Device activity is expected; the question is
whether treating that core as fully idle distorts placement during a benchmark
or game. No device, executable, IRQ number, or CPU number may enter CAPE policy.

The running kernel exposes `cpu_irqtime` in BTF, and the local scx common BPF
header already provides `scx_clock_irq(cpu)`. The first intervention is
shadow-only: sample the selected target's IRQ-time delta and record whether the
choice landed on a pressure-heavy logical CPU or sibling group, while leaving
the placement decision projection byte-for-byte unchanged. Pair it with a
semantic-neutral helper/state cost control. Only if current-boot A/A shows a
stable, inexpensive signal and the shadow value predicts tail harm should one
placement surface apply a dynamic per-CPU capacity discount.

The I0 source implementation now has three compile-time modes:

- mode `0` is the release default and removes the map, helper, calls, and
  observer-argument evaluation;
- mode `1` is the cost control and executes the complete BPF observation path
  but refuses to interpret pressure in userspace;
- mode `2` executes the identical BPF path and computes target/sibling IRQ
  utilization only at detach.

The per-CPU array is keyed by Cake's already-final selected target, so each
callback CPU writes a private shard without atomics. All five `select_cpu`
returns are observed after the existing choice is complete. Stripping the two
observer blocks, five calls, and their call-only braces reconstructs the exact
pre-I0 BPF source SHA256
`586fed77250fbea4888cbf6642f2fd35bd77506b213f2247806490d2a77612cd`.
This is source-contract proof of policy neutrality, not runtime proof: the I0
variant has not yet been built, verifier-loaded, or benchmarked under the
current execution quarantine.

RT/DL capacity needs a different read path. The kernel calls `select_cpu`
without a locked target runqueue, and `get_current_rq(cpu)` explicitly requires
that CPU's `rq` lock. Therefore placement must never dereference a selected
target's `rq->avg_rt`, `avg_dl`, or `avg_irq` directly. The lock-correct future
shape is an owner-CPU publication from `dispatch` before idle entry, where the
local runqueue is locked and RT/DL switch-boundary PELT updates are visible.
Publish timestamp plus RT, DL, and IRQ/steal utilization as one coherent `u64`;
placement may read it remotely only with an explicit wrap-safe freshness test.
Stale or ambiguous snapshots provide no capacity value.

That owner publisher remains an offline design, not part of I0. It must not be
stacked into the IRQ observer until the mode-0/mode-1/mode-2 build, verifier,
smoke, and cost-control ladder has bounded I0 overhead.

That behavior arm must remain work-conserving, decay stale pressure, combine
SMT sibling pressure, and fall back across every compatible CPU. It must be
tested against an equal-cost control with throughput, frame-time tails, game
lows, audio xruns, and network latency/loss guardrails. IRQ affinity mutation is
an OS experiment outside the scheduler and requires its own native/Cake A/B; the
scheduler must never rewrite affinity.

## Ordered admission and preemption

Terminal direct dispatch is permitted only when all of these hold:

```text
target is kernel-idle
wake request is eligible in the target service domain
no visible compatible eligible claim has an earlier (vd, sequence)
target is not owned by RT/DL
```

Otherwise the wake enters ordinary CAPE ordering. A qmark may prefilter the
exact head check; it is not proof of emptiness or permission by itself.

Preemption uses the same law:

```text
preempt current only if wake is eligible
and wake.vd is earlier than current.vd
and the current request's minimal switch-protection interval has expired
```

The protection interval is an overhead bound, not a priority boost. No learned
preemption or pressure-selected mode enters CAPE v1.

## Efficient sched_ext representation

The exact reference representation uses two priority phases per service domain:

| queue | membership | `dsq_vtime` key |
|---|---|---|
| `FUTURE[c]` | `ve_i > V_c` | `ve_i` |
| `READY[c]` | `ve_i <= V_c` | `vd_i` |

For fixed `q_i` and known `w_i`, either key reconstructs the other:

```text
vd_i = ve_i + q_i / w_i
ve_i = vd_i - q_i / w_i
```

This matters because sched_ext exposes only one priority key in
`p->scx.dsq_vtime`. An iterator move can promote a future head into the ready
queue while replacing its key with the deadline. The model proves this scalar
encoding lossless.

The v4 selector does not promote every newly eligible task. Let `R` be the
READY head deadline and `F` the FUTURE head eligibility. Because every request
has positive virtual length, every remaining FUTURE deadline satisfies
`vd > ve >= F`. Selection repeats:

```text
if READY empty and F > V: advance V to F             # work conservation
if FUTURE empty or F > V: dispatch READY head
if READY exists and R <= F: dispatch READY head      # exact lower-bound proof
otherwise: move FUTURE head to READY and rekey ve -> vd
```

This returns the same task as an exhaustive earliest-deadline scan while often
leaving eligible FUTURE tasks unpromoted. A hard iteration/promotion budget is
not permission to dispatch a stale READY head: if the lower-bound proof has not
terminated, the operation must fail closed and retry through a safe path. The
executable counterexample has a stale head deadline `90` after one promotion
while an unexamined eligible FUTURE task has deadline `3`.

The local sched_ext source contract supports snapshot DSQ iteration, membership
revalidation on move, and replacement of `dsq_vtime` during a move. The running
kernel BTF exposes the iterator, move, move-vtime, set-vtime, peek, and queue
count kfunc types. That proves API shape only. It does **not** prove verifier
acceptance, a bounded JIT path, safe concurrency across callbacks, or that
promotion, migration rebasing, and wake discovery are cheap enough in BPF.

The exact representation has one unresolved algorithmic defect: although each
request is promoted at most once, one selection can still encounter an
unbounded eligibility avalanche. A hard promotion cap is safe only by returning
no task; repeated fail-closed retries can then violate practical work
conservation. `peek` followed by `move_to_local` is also not an atomic exact-task
operation: the peeked head may block before the move consumes it. An exact S1
would have to move the iterator-selected task and retry on membership failure.

### CAPE-Q grouped approximation candidate

Linux already carries a production solution to the analogous packet-scheduler
problem: Quick Fair Queueing Plus groups requests by maximum request length over
weight, rounds group timestamps, and represents eligible/ineligible plus
blocked/ready state in four machine-word bitmaps. The local `sch_qfq.c` has 25
bounded groups, 32 slots per group, the `ER/IR/EB/IB` state sets, and a monotonic
service virtual clock. It is network-scheduler source evidence, not proof that a
CPU port is correct.

For a fixed maximum real request `qmax_i`, raw Linux fair weight `w_i`, nice-0
normalization `N = 1024`, and minimum virtual slot `sigma_0`, the CAPE-Q
offline model uses:

```text
vq_i      = qmax_i * N / w_i
g_i       = ceil(log2(vq_i / sigma_0))
sigma_i   = sigma_0 * 2^g_i
rounded_S = floor(ve_i / sigma_i) * sigma_i
group_F   = rounded_S + 2 * sigma_i
```

Groups occupy exactly one of `ER`, `IR`, `EB`, or `IB`. Selection uses the
lowest-index eligible-ready group and its first rounded-start slot. Advancing
`V` can flip group bits without moving every task, so the model performs zero
task promotions.

With Cake's fixed 3 ms request and a 256 ns minimum virtual slot, the 40 raw
Linux nice weights map into group indices 8 through 20. SCHED_IDLE uses raw
weight 3 and maps to group 22. The complete policy geometry is therefore 14
physical group DSQs in a 23-bit bitmap span: `[8..20, 22]`. Nice 0 is exactly
3 ms in virtual time, nice -20 is about 34.61 us, nice +19 is 204.8 ms, and
SCHED_IDLE is 1.024 s. Every rounded slot is at least its corresponding virtual
request and less than twice it. The public sched_ext `[1, 10000]` weight is not
used for this geometry because its cgroup conversion collapses distinct nice
weights and loses Linux's 1024 baseline. In 800
saturated 1:3-weight requests, the reference delivered exactly 25%/75% service
and bounded service lag below one request, while reporting 400 selections that
differed from the exact eligible-deadline oracle. That disagreement is the
trade: CAPE-Q targets bounded proportional service and constant-size group
selection, not exact EEVDF order.

The incremental reference maintains the state directly. Each task owns exact
CAPE `ve/vd/remaining` timestamps plus separate approximate QFQ timestamps and
direct slot membership. Each group owns a fixed 32-slot ring. Four bounded
bitmaps hold `ER/IR/EB/IB`; active weight and queued count are incrementally
maintained. Policy selection and lifecycle maintenance use direct task/slot
operations plus bitmap masks. A separate audit oracle scans all tasks and
groups after every event and rejects any mismatch; those scans are reported
but excluded from candidate cost.

CPU lifecycle exposed three packet-QFQ assumptions that must not be hidden:

1. **Wake credit:** QFQ's constant-time activation proof assumes a newly
   backlogged flow starts at or after current `V`; CAPE may restore positive
   sleeper credit before `V`. Keep exact credit in `ve/vd`, but normalize the
   approximate QFQ start into the current group epoch.
2. **Preemptive requeue:** packet QFQ keeps an aggregate in service while it
   consumes a budget. A preempted CPU request re-enters shared ordering and can
   otherwise create a new blocker from an old epoch. Normalize only its
   approximate timestamp pair before reinsertion.
3. **Future/GBT repair:** QFQ's XOR/FLS bulk eligibility transition assumes
   every ineligible group occupies its next virtual-time slot. Sleep debt and
   reweighting can place a CPU claim multiple epochs ahead. Pull only the
   approximate pair into the next representable epoch; preserve exact debt in
   the oracle.

Every repair is counted. In the bound deterministic 1,000-event lifecycle
stress, 770 dispatches, 125 blocks, 103 wakes, and 58 reweights completed with
the incremental state equal to full reconstruction after every event. The
largest policy event used 24 bitmap-word operations, 4 FFS operations, 6 slot
operations, 3 direct task operations, and 6 direct group operations. It used
zero policy task scans and zero policy group scans. The run recorded 17 credit,
14 requeue, and 1 future/GBT normalizations; no eligible-front clamp or ring
backshift. It also reported 470 exact-order disagreements and 405 approximate-
early selections. Those are approximation diagnostics, not wins.

A separate 512-task same-group adversary kept selection policy work unchanged:
zero task/group scans; the exhaustive audit oracle alone scanned 512 tasks.
This proves the configured offline representation's cost shape, not Python
dictionary worst-case behavior or BPF verifier/JIT cost.

The integer representation is now bounded offline. A 32-slot ring plus two
guard distances at the largest group-22 slot spans at most 36,507,222,016 ns,
far below the signed-u64 half range of 2^63 ns, so ordering uses Linux's
`time_before64()` modular signed-distance law. A 32-bit reciprocal table for
`1024 / weight` has at most 1 ns floor error for a 3 ms request. Even the
SCHED_IDLE reciprocal product fits u64; the one-shot fast path is bounded to
12,582,912 ns and longer runtime is split into bounded chunks. This proves the
offline integer law, not verifier acceptance or generated BPF cost.

The sched_ext custody mapping is now source-resolved. CAPE-Q does **not** need
one DSQ per slot and does not need BPF-side arbitrary removal. Use one custom
priority DSQ per QFQ group, keyed by `rounded_S`. The DSQ's head is the earliest
rounded-start slot; the kernel rbtree inserts equal keys to the right, so its
in-order list retains FIFO insertion order inside a slot. For Cake's current
geometry S1 therefore needs 14 custom DSQs, not `64 * 32 = 2048` or even
`14 * 32 = 448`. The 448 figure is only the bounded auxiliary counter array:
14 groups times 32 slot counts, plus four group bitmaps and one direct
membership record per task.

The local sched_ext source establishes two different custody-exit orders:

1. **Regular selected dispatch:** the core removes the priority-DSQ head and
   inserts it into a local DSQ before invoking `ops.dequeue()`.
2. **Sleep, property change, or core-sched execution:** `ops.dequeue()` runs
   while the task is still physically linked, and the core unlinks it
   afterwards under the task's rq lock. Core move/revalidation and
   `holding_cpu` resolve a concurrent move/dequeue race.

Direct insertion is a three-stage transaction with fail-stop semantics:

1. call `scx_bpf_dsq_insert_vtime()` with no BPF lock held; on the direct
   enqueue path the kfunc records `ddsp_dsq_id`, flags, and vtime but does not
   physically insert;
2. after the kfunc succeeds, publish direct auxiliary membership under the
   CAPE-Q BPF lock and return from `ops.enqueue()`;
3. the core consumes the recorded verdict and physically inserts into the
   custom PRIQ after the callback returns.

The verifier permits only a narrow allowlist of calls while a BPF spinlock is
held, so the sched_ext kfunc must precede the auxiliary lock. Intermediate
state may contain an auxiliary phantom. A root insertion failure is not a
recoverable transaction: sched_ext claims exit, sets `aborting`, ignores
enqueue/dispatch in bypass, cycles queued work into global FIFO, and guarantees
forward progress. CAPE-Q must stop policy immediately; it must never roll back
partial state and continue. This law requires a flat, exclusive root scheduler:
under sub-schedulers, an insert of a task not owned by the caller is explicitly
counted and ignored rather than universally fail-stop.

The reverse-order dequeue path marks the rq-locked task withdrawn before
unpublishing it. Dispatch uses a snapshot DSQ iterator in priority order, skips
withdrawn entries, and moves the first serviceable task directly to LOCAL with
`scx_bpf_dsq_move()`. The iterator can move a later task; the physical PRIQ head
therefore cannot strand progress. Both scanned entries and failed move attempts
consume a fixed policy budget. If auxiliary work remains when the budget is
exhausted, the root scheduler aborts into bypass instead of retrying. This is a
bounded offline policy model; the kernel's older `move_to_local` internal retry
loop and arbitrary repeated iterator moves have no kernel-provided constant
bound and are not treated as proof.

Completed transitions require exact equality between physical custom
membership and direct auxiliary state. `SCX_ENQ_REENQ` records the new direct
insertion, transfers auxiliary membership, and reinserts without closing its
custody epoch; terminal LOCAL/GLOBAL dispatch never enters the epoch.
`scx_bpf_dsq_nr_queued()` is an unlocked, path-dependent observation and is not
the exact occupancy oracle.

### Verifier-shaped single-domain SMP contract

The first correctness candidate now has a concrete map, lock, and race shape.
It deliberately represents **one service domain**; it is the S1 proof vehicle,
not the final scalable S2 topology. The proposed BPF layout is:

- one `BPF_MAP_TYPE_ARRAY` element containing one top-level
  `struct bpf_spin_lock` at offset 0;
- a 64-byte serialized hot header, 14 dense group records, 448 u32 slot
  counters, and 448 one-byte empty-scan retry counters;
- total domain value size `2752` bytes;
- one 32-byte `BPF_MAP_TYPE_TASK_STORAGE` value per task containing a packed
  membership/epoch/fraction word plus a state-dependent start, exact remaining
  real request, and rounded-start or runtime-baseline scalar;
- no spinlock in task storage;
- sparse mathematical groups `[8..20, 22]` mapped monotonically to dense BPF
  group IDs `[0..13]`, preserving service order while reducing the hot bitmap
  from 23 bits to 14.

Every domain critical section is scalar-only. Map/task lookups, DSQ iterator
creation/progression, `scx_bpf_dsq_insert_vtime()`, and
`scx_bpf_dsq_move()` all occur with no BPF lock held. This follows the local
verifier contract: only one spinlock may be active and ordinary helpers,
subprograms, and sched_ext kfuncs are rejected while it is held.

The enqueue publication sequence is:

1. record the direct PRIQ insertion verdict outside the lock;
2. lock once to publish the task's packed membership, slot count/masks, and
   domain mutation sequence, then unlock and return from `ops.enqueue()`;
3. let the core physically commit the recorded insertion.

The short interval between steps 2 and 3 is unavoidable because sched_ext has
no callback after the core's direct-insert commit. An empty dispatch snapshot
therefore is not immediately corruption. The S1 model gives a fresh unchanged
slot up to eight bounded publication-gap retries; a concurrent enqueue/dequeue
changes the domain sequence and makes the old dispatch snapshot stale instead.
Eight is a provisional fail-stop bound to falsify under verifier/runtime load,
not a proven latency constant. Repeated unchanged auxiliary work with no
physical candidate aborts without retrying indefinitely.

Dispatch uses this sequence:

1. lock briefly to snapshot the exact selected dense group, slot, rounded key,
   and mutation sequence, then unlock;
2. open a snapshot iterator over that group's physical PRIQ;
3. read the task's packed membership and `p->scx.dsq_vtime` locklessly as
   advisory validation;
4. call `scx_bpf_dsq_move()` outside the lock;
5. on success, rely on the core's synchronous physical move plus nested
   `ops.dequeue()` to take the lock once and unpublish exactly once.

No BPF owner, reservation, lease, or cross-CPU inbox is needed for **physical**
single-winner arbitration. Two CPUs may validate the same task. The kernel
rechecks that it is still on the iterator's DSQ and was queued before iterator
creation; one move wins, the other returns false, and the winning nested
dequeue changes the domain sequence. A dequeue/re-enqueue increments the
packed membership epoch and physical insertion sequence, so an old probe cannot
move the new custody instance. That kernel authority is not CAPE-Q policy
linearization: it does not prove that the moved task was still the selected ER
claim when a concurrent callback changed `ER/IR/EB/IB`.

The separate dispatch-linearization model now fixes the abstract law. Under the
domain lock, a winner must be revalidated against the current ER group, slot,
key, membership epoch, and domain sequence, then removed from logical policy
state and marked `RESERVED`. That logical removal is the selection
linearization point. Only then may the lock be released and the physical move
attempted. A successful move's synchronous nested `dequeue()` converts the
reservation into dispatched-service custody. A concurrent external dequeue or
`SCX_ENQ_REENQ` cancels the reservation and advances the physical generation,
so the old iterator move returns false. If the task remains the same stable
reservation yet the kernel move still fails, S1 must fail-stop rather than try
to reconstruct an old QFQ front after concurrent mutations. Two CPUs can reserve
concurrently because each lock acquisition observes the prior logical removal.
The adversarial model passes all eight witnesses. The quarantined BPF source now
encodes the reservation bit, packed in-flight/service counters, logical QFQ
removal, nested-dequeue closure, reenqueue cancellation, and stable-move
fail-stop. Static source binding is green; compile, verifier, and runtime
authority remain absent.

Affinity exposes a representation lower bound, not merely a missing loop. For
any fixed iterator budget `B`, place `B` tasks incompatible with CPU `c` ahead
of one compatible task in the same shared group DSQ. A bounded walk inspects the
prefix and returns empty while compatible work remains at position `B + 1`.
The executable witness holds for every positive tested budget, including the
current 64-task limit. Therefore one shared PRIQ per group plus a finite scan
cannot prove CPU-compatible work conservation. Raising the limit only moves the
counterexample; using the kernel's internally unbounded consume walk hides the
livelock risk already documented in local `ext.c`.

S2 now has an exact offline visibility shape. Decompose each task's effective
CPU mask into the maximal disjoint nodes of a laminar topology tree. Publish one
ordered **visibility ticket** at every node in that canonical cover. For any
allowed CPU, exactly one cover node lies on its leaf-to-root path; a disallowed
CPU sees none. Dispatch therefore compares one queue head per topology level
and cannot be defeated by an incompatible task prefix. On the current
16-logical-CPU, 8-core, one-LLC host the path contains at most three heads.

This is not flat per-CPU duplication. Full-LLC affinity and an SMT-sibling pair
each need one ticket instead of 16 and two respectively. The deliberately hard
one-thread-per-core mask still needs eight leaf tickets; the update cost is the
canonical-cover fanout and is not hidden. A single-owner restricted queue is
rejected as the exact fallback: if its owner is busy while another allowed CPU
is idle, compatible work is stranded even though every owner-queue entry is
owner-compatible.

Tickets duplicate visibility, not task custody. The task remains in the core's
single sched_ext `QUEUED` state with one task-storage cookie and epoch. A
serialized reservation removes every cover ticket and commits the logical
winner once. Local `ext.c` permits `ops.dispatch()` to name an arbitrary owned
task, captures its queue sequence, and claims `QUEUED -> DISPATCHING` with a
kernel CAS. The proposed handoff buffers that exact task into an otherwise empty
per-CPU staging DSQ and immediately calls `scx_bpf_dsq_move_to_local()`. The
flush plus single-entry consume gives an affinity-checked physical receipt; the
terminal local insertion synchronously closes BPF custody through
`ops.dequeue()`. An unchanged reservation plus failed staging move is fail-stop,
while dequeue/reenqueue or affinity-epoch change invalidates the old ticket.

The executable S2 model passes all 11 adversarial witnesses and a deterministic
10,000-step trace with zero compatible-candidate or lag-translation errors. It
performed 18,358 exact ticket insertions and removals, 2,199 reservations, 121
deliberately invalidated handoffs, and 1,376 service-domain lag translations;
maximum observed cover fanout was eight and every CPU probe stayed within three
heads. The local source contract is 9/9. These are representation and kernel-API
proofs only. The ordered ticket container, eager concurrent deletion with no
unbounded stale prefix, and the composition of global CAPE-Q group eligibility
with constrained per-CPU service remain unencoded and unverified.

The executable shape binds 20/20 local verifier/sched_ext/scx source clauses
and passes 10/10 adversarial witnesses. A separate deterministic 2,000-step
mixed lifecycle ran 1,003 enqueues, 332 external dequeues, 382 single-CPU
dispatches, and 283 two-CPU races; every race had exactly one losing move and
all 2,000 full counter/mask reconstructions passed. These are Python state-
machine and source-contract results. They do not prove that an emitted BPF
program verifies, that the provisional retry bound is safe under preemption,
or that one serialized domain is fast enough.

The bound custody model checks 34 local source clauses and all 11 required
running-kernel BTF function types. A deterministic 500-step real nice-weight
tandem used 14 group DSQs and 448 auxiliary counters, matched the incremental
slot head on every dispatch, and recorded zero hidden-serviceable states. It
also exercised regular dispatch, queued sleep, wake, property reweight,
repeated reenqueue, running block, terminal direct dispatch, equal-key FIFO,
and arbitrary core-sched execution. The last case is an external ordering
override and must be counted, not misreported as a CAPE-Q selection.

This is still not a selected BPF implementation. The integer/wrap, lock order,
withdrawn-head progress, root fail-stop, and single-domain SMP arbitration laws
now have executable offline contracts. Verifier acceptance, exact generated
instruction/JIT and lock-contention cost, safe multi-domain sharding and
migration, flat-root deployment proof, core-sched override impact, and the
latency/fairness cost of the three epoch normalizations remain unresolved.
The exact FUTURE/READY and exhaustive models stay as oracles. CAPE-Q advances
only if its approximation beats the exact representation's scheduler cost
without losing latency tails, jitter, throughput, gaming lows, or starvation
bounds.

### Source-bound integer lifecycle encoding

The sched_ext callback lifecycle now has a separate executable representation
contract. The exact local source binds these orders:

- `runnable()` occurs before the enqueue transfer, but either callback may
  occur without the other;
- a selected/custom task is physically removed before its nested custody
  `dequeue()`, while sleep/property exits invoke `dequeue()` before physical
  unlink;
- `running()` follows core-sched custody removal and the runtime start stamp;
- both `stopping(false)` and `stopping(true)` observe `sum_exec_runtime` after
  `update_curr_scx()`; the runnable stop precedes any reenqueue;
- `quiescent()` precedes queued-state clear and distinguishes sleep from an
  administrative migration/property pause; and
- a scheduling-property change dequeues/quiesces before `set_weight()` and
  restores runnable state afterwards, with the new kernel weight already
  visible to the callback.

The representation still fits the same maps. Domain header offset 44 is a Q32
fraction of virtual time, offset 48 is integer `V`, and offset 56 is bounded
active raw weight. The packed task word retains 2 lifecycle bits, 4 dense-group
bits, 5 slot bits, a 32-bit publication epoch, and a 17-bit state-dependent
fraction, leaving four high bits reserved. The group/slot bits carry a raw
priority index plus valid/sleep flags whenever the task is not published. A
published task stores its priority index in the otherwise-zero low eight bits
of the task-storage copy of its 256 ns-aligned key; the physical DSQ key remains
untagged.

The 17-bit fraction represents eligibility while active/published/running and
signed-lag fraction while quiescent. Together with the domain Q32 fraction,
this preserves sleeper credit while `V` advances and preserves weighted lag
through `set_weight()`. The second task scalar stores exact remaining real
nanoseconds in every state, so repeated affinity, migration, or nice changes
cannot accumulate request credit through virtual-to-real round trips. The
third scalar stores the physical key while published and
`p->se.sum_exec_runtime` while running.

The source contract passes 14/14 clauses; the encoding/lifecycle tests pass
21/21. A deterministic 2,000-transition stress covers wake, partial stop,
queued sleep, temporary pause, reweight, repeated enqueue, and uncoupled
dequeue/quiescent paths with zero policy task scans, zero policy group scans,
zero remaining-real-service pause error, and at most 12 scalar operations per
callback. Q32 domain and Q17 task division each truncate below one fractional
unit per service event. Positive credit that would predate non-wrapping S1
timestamp zero is explicitly counted and clamped; wrap-aware production
rebasing remains unresolved.

This remains offline evidence. The lifecycle callbacks, Q32/Q17 fractions,
active-weight arithmetic, exact remaining service, service-custody counter,
and partial-stop requeue are now translated into the quarantined C candidate.
The current 41-level raw nice plus SCHED_IDLE table still does not prove
continuous cgroup-weight semantics.

### Source-only S1 custody translation

The first BPF translation now exists at
`scheds/rust/scx_cake/experimental/cape_qfq_s1/cape_qfq_s1.bpf.c`. It is a
quarantined, unreferenced source candidate: `build.rs`, Cargo, the production
Cake BPF include graph, and the running scheduler do not consume it. The source
materializes the 2,752-byte domain ARRAY, 32-byte task storage, packed custody
epoch, 14 group PRIQ DSQs, insert-before-publication transaction, nine
scalar-only lock regions, bounded iterator/move/retry budgets, kernel-authority
move, nested dequeue unpublication, all four QFQ group states, Q32/Q17
lifecycle arithmetic, and dispatch-to-running service custody.

The paired static gate in bench-assets passes 58/58 conformance clauses and 43
source-gate tests. It rejects sched_ext or BPF-to-BPF calls under the
lock, control-flow escape from a critical section, missing lock markers,
direct-insert reordering, build-graph references, missing dequeue registration,
unbounded scans, unbounded/corrupt dispatch masks and heads, misclassifying a
physical but CPU-incompatible key as a publication gap, layout drift, and a
false policy-complete claim. A separate C-shaped transition oracle executes
40,064 boundary, randomized classification/unblock, and service-custody cases
with zero mismatches. It caught and corrected an eight-bit-early eligibility
promotion caused by initially omitting the 256 ns minimum-slot shift.

This source is deliberately **not** a complete or selected CAPE-Q scheduler.
Its selector now chooses the lowest eligible-ready dense group and encodes the
constant-work ER/IR/EB/IB transitions. Task-linear logical reservation is proved
offline and encoded in the quarantined source, including cancellation paths and
stable-move fail-stop. CPU-affinity work conservation is disproved for the
finite-scan/single-shared-DSQ representation. The S2 canonical topology-cover
index now proves exact compatible visibility offline with a topology-depth
candidate bound, but its ordered ticket storage and staging handoff are not
encoded in this S1 source. Continuous cgroup weights,
`exit_task` teardown, and wrap-aware timestamp rebasing also remain open.
`CAPEQ_POLICY_COMPLETE`, compile authority, verifier-load authority, runtime
authority, score authority, and promotion authority remain false. Only after
those source gates close and an independently attributable receipt-producing
builder exists may verifier compilation/load be attempted.

The production target must avoid a global atomic virtual-time line. Use local
service-domain aggregates and explicit lag translation on migration. Any task
storage is limited to correctness state such as domain/phase/preserved lag; no
learned history is admitted.

## Current frontier correctness finding

`cake_running()` currently does a racy shared read/check/write:

```c
if (time_before(cake.frontier.word, task_vtime))
        cake.frontier.word = task_vtime;
```

An exact interleaving can regress it: both CPUs read `100`, the `120` runner
writes, then the `110` runner writes, leaving `110`. That changes sleeper
credit, wake classification, and overflow aging. The new reference test makes
the lost update executable.

Do not silently replace this with a locked atomic max in the active scheduler.
S09 shows that shared atomic traffic itself can move benchmark scores. First
test a behavior-neutral observer or remove the shared frontier through CAPE's
per-domain virtual time. Correctness and cacheline cost must be measured as two
separate arms.

## Why the shape addresses all target dimensions

| target | CAPE mechanism |
|---|---|
| adaptability | eligibility, deadline, queue state, topology, and measured RT/DL/IRQ capacity at the current event |
| efficiency | per-domain state, sparse exact checks, decayed IRQ sampling, no learned maps, no normal-path global atomic |
| latency | earliest deadline among tasks actually owed service, placed away from measured stolen capacity when alternatives exist |
| jitter | bounded request/protection, deterministic order, decayed pressure, no oscillating workload modes |
| throughput | local continuations, tie-only locality, pull migration, fixed first-stage request, and no capacity reservation |
| gaming | latency law protects wake chains; custody protects render/cache warmth and avoids measured IRQ collision; promotion requires frametime tails and lows |
| fairness | explicit bounded private lag plus proportional steady-state virtual service; dynamic join/leave policy remains falsifiable |
| starvation | future-to-ready eligibility progression plus work-conserving V advance |

## Full Linux scheduler mapping

The eventual kernel patch is not a sched_ext wrapper. It needs a complete
SCHED_NORMAL/BATCH/IDLE implementation with:

- a CAPE runqueue containing eligible-deadline and future-eligibility trees;
- lag preservation across enqueue, dequeue, sleep, weight change, and migration;
- CAPE wake placement and ordered admission;
- capacity-aware pull balancing and RT/DL/IRQ capacity discounting;
- cgroup hierarchy/bandwidth, uclamp, PELT/capacity, NUMA, SMT/core scheduling,
  PSI, hotplug, throttling, and proxy-execution accounting;
- task request/latency API compatibility and safe default behavior;
- tracepoints, schedstats, lockdep, KCSAN, and scheduler invariant tests.

The existing fair.c PELT, `avg_irq`, and capacity accounting can remain kernel
infrastructure during the port, but the winning CAPE pick/admission/custody law
must consume that capacity consistently and be independently implemented and
bisected. A port is not authorized by a sched_ext average win; it requires no
accepted regression across the complete promotion matrix.

## Implementation ladder

1. **R0 complete:** executable exact-arithmetic service, admission, migration,
   capacity, dual lifecycle clocks, lazy FUTURE/READY selection, fail-closed
   promotion budget, incremental CAPE-Q partial/block/wake/reweight state,
   fixed-ring cost accounting, normalization counters, source-ordered
   one-PRIQ-per-group custody, repeated-enqueue/property/core-sched lifecycle,
   randomized tandem reconstruction checks, a 2752-byte one-lock domain plus
   32-byte lockless task-membership shape, Q32 domain/Q17 task lifecycle
   arithmetic with exact remaining-real-service preservation, 10 physical-move
   SMP witnesses, eight task-linear reservation/affinity witnesses, a finite-
   scan work-conservation counterexample, 11 exact topology-cover/staging
   witnesses, a 10,000-step S2 affinity/lag trace, and two separate 2,000-step
   mixed lifecycle reconstructions; no scheduling behavior.
2. **H1 first:** obtain clean current-kernel C1/H1 performance proof. Do not
   stack CAPE onto an unmeasured ordered-admission change.
3. **I0 IRQ shadow:** record selected-target and SMT-sibling IRQ-time pressure
   without changing placement; compare against a semantic-neutral helper/state
   cost control. Keep this separate from H1 and CAPE behavior.
4. **S0 CAPE shadow:** compute the exact CAPE oracle plus incremental CAPE-Q
   group/bitmap decisions without changing service; pair with a semantic-
   neutral state/helper-cost control and report every order disagreement,
   approximate-early selection, and epoch normalization.
5. **S1 single-domain:** once execution quarantine is lifted, compile and
   verifier-check task-linear reservation, then compare exact future/ready DSQs
   against bounded CAPE-Q groups for pinned one-CPU test tasks;
   prove work conservation, weights, service-lag bounds, normalization
   frequency/error, no stalls, legal removal, two-CPU arbitration,
   publication-gap bounds, domain-lock cost, and verifier/JIT shape.
6. **S2 multi-domain and compatibility visibility:** verifier-shape the selected
   canonical topology-cover ticket index and single-entry per-CPU staging
   handoff; require eager exact ticket removal, no stale-prefix escape, at most
   topology-depth candidate heads, exact compatible-work discovery, preserved
   signed lag and remaining service, and unchanged Golden custody. Compare its
   measured cover-fanout cost against flat per-CPU tickets and the rejected
   single-owner baseline. Do not combine a slice or IRQ-placement experiment in
   this arm.
7. **S3 custody:** compare retained global wake discovery against a sharded or
   pull-visible inbox only after S2 service order is proven.
8. **I1 IRQ capacity:** only after I0 plus A/A, test one dynamic capacity-discount
   decision surface against an equal-cost no-placement control; never hardcode
   devices, IRQs, processes, or CPUs.
9. **Promotion:** ambient/wake/cache/IRQ pressure controls, all official and
   extended tests, concurrent blends, scaling, then exact-identity game ABBA.
10. **Kernel port:** implement the proven law in a separate Linux patch series,
   then repeat correctness, benchmark, game, soak, and rollback gates.

## Falsification gates

Reject or redesign CAPE if any of these survive clean repetition:

- task/aggregate state loses fork/thread or futex before policy acts;
- future promotion can strand compatible runnable work;
- a verifier-bounded promotion path can dispatch without completing the exact
  lower-bound proof, or adversarial promotion depth is too costly;
- CAPE-Q needs task-linear group transitions, exceeds its claimed service-lag
  bound, starves a flow, or its approximate order regresses latency/jitter/game
  tails more than its scheduler-cost reduction recovers;
- CAPE-Q's wake-credit, preemptive-requeue, or future/GBT normalization is
  frequent enough to erase exact sleeper debt, create bursty early service, or
  dominate the scheduler-cost saving;
- the verifier rejects the ARRAY lock, task-storage lookup, iterator, packed
  membership, or nested-dequeue shape on the exact target kernel;
- normal enqueue can exhaust the provisional publication-gap retry bound, or
  a stale snapshot can trigger a false fail-stop;
- the S1 domain lock causes throughput loss, wake-tail inflation, or jitter
  before policy benefits can act, or S2 sharding cannot preserve lag and
  membership across migration;
- the monotonic private-lag policy causes persistent dynamic fairness or
  interactive sleeper exploitation that bounded lag cannot control;
- exact eligibility requires a shared atomic hot line;
- locality bypasses a strictly earlier eligible deadline;
- migration cannot preserve bounded lag across domains;
- cache improves only by losing mixed memcpy or vice versa;
- latency improves only by losing throughput, energy, or game tails;
- RT/DL activity can strand fair work or invalidate capacity selection;
- IRQ pressure is unavailable, stale, too expensive to sample, or cannot beat
  an equal-cost control across clean repetitions;
- an IRQ-aware result depends on this host's current device, IRQ, or CPU
  identity rather than a general capacity signal;
- avoiding IRQ pressure regresses work conservation, throughput, audio, network,
  or game frame tails;
- a win requires executable names, benchmark labels, or learned priority;
- any accepted official, extended, scaling, blend, or game field regresses.

## Primary research anchors

- Stoica and Abdel-Wahab, *Earliest Eligible Virtual Deadline First* (1995):
  https://people.eecs.berkeley.edu/~istoica/papers/eevdf-tr-95.pdf
- Linux EEVDF documentation and exact local `fair.c` implementation:
  https://docs.kernel.org/scheduler/sched-eevdf.html
- Checconi, Rizzo, and Valente, *QFQ: Efficient Packet Scheduling with Tight
  Guarantees* (and the exact local `net/sched/sch_qfq.c` implementation):
  https://docenti.ing.unipi.it/l.rizzo/papers/20120309-qfq.pdf
- sched_ext scheduling cycle, DSQs, direct dispatch, and custody:
  https://docs.kernel.org/scheduler/sched-ext.html
- ghOSt (SOSP 2021), for policy/control-plane separation and experimentability:
  https://mast.stanford.edu/pubs/ghost_fast_flexible_user_space_delegation_of_linux_scheduling/
- Shenango (NSDI 2019), for rapid state-driven capacity reallocation and the
  latency/efficiency objective rather than permanent core reservation:
  https://www.usenix.org/conference/nsdi19/presentation/ousterhout

These papers inform mechanisms. The local kernel source, exact BPF contracts,
and this machine's controlled benchmark/game evidence remain promotion truth.
