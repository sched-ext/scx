# Maintaining scx_mavd

scx_mavd follows scx_lavd's policy and source organization. Its fork
baseline is 1ad3bb7ef8c1 ("Merge pull request #3789 from
sched-ext/cosmos-primary-overload"). The reference sources are
[scx_lavd](../../rust/scx_lavd). This file records mavd's representation
choices and the obligations when porting a lavd change.

The conversion is under validation. A successful build or source review does
not establish verifier acceptance, behavioral equivalence or performance
equivalence. CPU contexts, task data, domains, masks and runtime policy
state now have arena storage.

## Shared bandwidth storage

Both lavd and mavd use the arena conversion of lib/cgroup_bw.bpf.c. Private
configuration, counters, free-list heads, deferred-destroy slots and cgroup-ID
work arrays share one arena allocation. A native pointer names the state. The
allocation retains the initial zeros, alignment and atomic publication
operations of the original objects.

Hierarchy traversal uses arena scratch indexed by the executing Linux CPU,
with space for the kernel's scx_bpf_nr_cpu_ids() span, including possible
CPUs not yet present in sysfs. Allocate it before starting either timer and
retain the state until arena teardown, including partial initialization
failure. Direct page allocation avoids the static allocator's per-allocation
size limit on large machines. Every traversal clears its own slot. This
preserves the original per-CPU scratch's concurrency assumptions. It does
not make nested use on the same CPU safe.

Keep the append capacity and hierarchy-depth checks. The cgroup list is
bounded by CBW_NR_CGRP_MAX; the throttled list contains at most one entry per
visited cgroup. Published counts therefore bound the direct array accesses
that replace MEMBER_VPTR(). Keep the timer/dispatch acquire and CAS ordering
when porting changes. Timer anchors and kernel association maps remain native.

## CPU identities

Keep existing policy identifiers such as cpu_id and suggested_cpu_id where
practical, but interpret scheduler-owned CPU fields as CIDs. The exceptions
below are Linux CPU IDs. Do not infer units from a variable's spelling.

| Value | Units |
| --- | --- |
| task_ctx CPU fields, including pinned_cpu_id and queued_on_cpu_id | CID, or the field's existing negative error |
| cpu_ctx.cpu_id and core_cid | CID |
| cpu_ctx.raw_cpu | Linux CPU ID |
| Runtime policy, affinity, domain and idle mask bits | CID |
| Runtime preference-table entries | CID |
| Preference-table positions and raw nr_cpu_ids span | Lavd's original positions and Linux CPU ID span |
| CpuOrder.cpu_adx, input capacity/sibling arrays and domain seed bitmap | Linux CPU ID |
| rq clocks, cpufreq per-CPU data and hardware pressure indices | Linux CPU ID |
| Introspection CPU fields and messages labeled CPU | Linux CPU ID |
| Compute-domain IDs and user-created virtual LLCs | Lavd policy domain, independent of kernel CID topology |

Convert raw topology input only in scheduler initialization, after the
kernel publishes the CID mapping. Keep preference positions, raw-span
affinity classification and virtual LLC membership. Kernel topology provides
SMT core ranges for idle tracking. It does not replace lavd's compute-domain
definitions.

Seed online membership by copying scx_bpf_online_cmask() into mavd's mutable
online_cmask during root ops.init(), where CPU hotplug is excluded. The
kernel seeds the borrowed mask from cpu_active_mask and updates it at the
beginning of each SCX hotplug notification, before BPF callbacks. Keep
maintaining mavd's private copy through its online/offline callbacks. The
borrowed mask remains readable through ops.exit() and must not be modified
or freed.

This getter replaces the direct __cpu_online_mask reference that failed
libbpf symbol resolution. It preserves lavd's initial membership except for
a CPU caught inside a hotplug transition at init: one that is online but not
yet active is excluded until its online notification arrives. The physical
online count can differ during transitions and must not be used to infer
members.

The per-core DSQ is named by the core's first cid from the kernel's cid
topology, where lavd used the sibling with the lower Linux CPU ID; only the
internal id of the core's DSQ differs. New tasks' zero-valued CPU history is
translated from raw CPU 0. Empty-affinity fallback checks the raw first-bit
result before translation. Load balancing takes the lowest cid on equal
per-CPU queue loads.

Per-CPU DSQ identifiers encode CIDs internally. Treat a raw dump of a DSQ
number as an internal identifier, not a Linux CPU number. Translate task/CPU
labels at the reporting boundary.

## CPU-context storage

CPU contexts occupy one cacheline-aligned arena array indexed by CID.
Allocate it for all possible CIDs after validating the count, before mask
and CPU initialization. Arena allocation supplies zeroed pages, preserving
the native map's initial state. Keep the structure's field offsets and
isolated queue-load cacheline when porting lavd changes.

The array belongs to the loaded BPF object. It is not freed at scheduler
exit, because auxiliary programs and timers can still execute. Context
lookup retains scx_bpf_cid_to_cpu() validation. With CONFIG_EXT_SUB_SCHED=y
and program association, that check resolves the calling scheduler's
instance. With the option disabled, it resolves the current root, so an old
auxiliary program can pass the check against a replacement scheduler. Detach
auxiliary links before replacing the scheduler. Mapped arena memory alone
does not establish scheduler availability.

The current-CPU lookup now returns NULL before the mapping and array exist,
or when CID resolution fails. The task-data lookup can still use its
uncached path. Initialization, attach/detach and auxiliary-hook tests must
cover these boundaries. Allocation failure is reported from scheduler
initialization, instead of native CPU-map creation during object loading.

Both select and enqueue supply pick_idle_cpu() with a checked context for
the executing CPU. Mask preparation reuses that pointer: the array is
allocated once and retained throughout the callback. Preserve this caller
contract when importing picker changes from lavd. Repeating the lookup adds
CID and scheduler-association checks without changing the selected slot.
Auxiliary entry paths still require the association validation described
above.

Task callbacks may execute on a different CPU from their task. Reuse a
checked task-CPU context for the executing CPU's cache only when its raw_cpu
matches bpf_get_smp_processor_id(). Otherwise resolve the executing context
normally. Dispatch uses the corresponding CID equality check. Idle
notifications pass their checked context through to the mask update. These
pointers remain within the non-migrating callback. Keep shared getter
validation: bandwidth and statistics timers also reach context lookups,
outside these callback-specific reuse contracts.

Scheduling entry points use get_cpu_ctx_ops() for the executing CID, their
protected subject task's CID or a direct dispatch/idle CID argument. The
kernel invokes these non-sleepable callbacks only after CPU-array
initialization and drains them before invalidating scheduler association or
CID tables. Direct indexing therefore removes repeated range, allocation and
association checks. The helper is restricted to select, enqueue, dequeue,
runnable, dispatch, running, tick, stopping, quiescent and idle
notification, including their current-context reuse helper. Preserve
target-versus-executing CPU selection. Picker results, cached candidates,
initialization, hotplug, exit, dump, timers and auxiliary hooks retain the
general checked lookup. A new caller must establish the same lifetime and ID
contract.

Runnable and dequeue use the executing CPU's context for their subject-task
cache. Dequeue can run on a dispatch rq without holding the subject's rq
lock: the SCX_OPSS_DISPATCHING ownership handoff blocks racing task dequeue
until the callback finishes. Preserve that serialization when changing cache
callers.

Dispatch passes its executing context to consume_prev() while retaining the
target context for scheduling decisions. Select, enqueue and dispatch reuse
the initialized target's core_cid for the CPU DSQ and load-accounting
identifiers.

CPU accounting stages each arena-resident running average through the stack:
ravg_from_arena(), the native ravg_accumulate(), ravg_to_arena() and a read
of the temporary. Each average has one writer context, the CPU's own running
and stopping callbacks for utilization and the statistics timer for IRQ
steal, so the copy-back overwrites nothing concurrent. Neither the library
nor the caller serializes readers against the writer. Validate statistics
under hotplug.

## Userspace-seeded arena globals

The arena exists only after load, so userspace cannot seed arena globals
through the BSS image the way lavd seeds its options. Every arena global
userspace writes or reads is listed in struct mavd_uptrs, and
mavd_publish_uptrs() stores their addresses there after load. main.rs seeds
the domain contexts, the preference table and the options through those
addresses between load and attach, and reads statistics through them as
approximate snapshots. A ported lavd change that adds a userspace-written
global either keeps it in rodata or BSS, or adds it to both the struct and
the publishing program.

## Userspace configuration bindings

lavd carried a redundant weak is_autopilot_on definition in sys_stat.bpf.c
alongside the strong definition in util.bpf.c. Their linked BTF and ELF
offsets differed, so the Rust skeleton and the BPF callback addressed
different bytes. lavd removed the redundant definition upstream and mavd
inherits the single binding through the fork. Results from before the fix
retain their original binary identities and coverage.

## Statistics sampling

Both schedulers collect and reset per-CPU scheduling and classification
counters separately. Aggregate publication and userspace copying also lack a
consistent-snapshot protocol. The six count-derived percentages, PERF-CR%,
LAT-CR%, X-MIG%, BIG%, PC/BIG% and LC/BIG%, therefore lack an unconditional
upper bound of 100%. Moving storage to the arena does not establish that
bound.

For lifecycle smoke coverage, require finite, nonnegative count ratios and
preserve every overshoot with its complete row, sequence and timestamp.
Validate hook execution, worker progress and scheduler events separately.
Retain the power-mode percentage anomaly checks and investigate any
violations. This does not accept statistics correctness or explain an
individual outlier. Compare statistics in matched runs and collect causal
evidence before attributing a discrepancy. Do not clamp the reported values.

To validate a displayed row's arithmetic, capture the exact numerators,
denominators and result values used to format that row. Preserve separate reads
where the existing calculation makes them. An independent reread of BPF state is
not the same input. Check the source arithmetic and formatting, retaining
nonfinite and out-of-range results explicitly. Matching these operands explains
the displayed calculation, not which concurrent updates produced the operands or
whether counts are complete.

## Futex tracing

lavd reads fexit return values with bpf_get_func_ret() and mavd inherits the
hooks. The kernel added arguments to futex_wake() and futex_unlock_pi(). The
previous positional declarations still attached but read an argument as the
return value.

All seven traced targets return int. Interpret the helper's u64 output as
s32 before applying the original success predicates. These fexit hooks
guarantee that the helper writes the return value and returns zero, so no
helper-status branch is needed. The syscall tracepoint implementation
retains its existing policy.

When importing lavd changes, retain argument-free declarations for hooks
that only use the return value. Check any newly used arguments or changed
return types against the target BTF. Function-name availability alone does
not validate a positional tracing declaration.

## Task context lifetime

mavd inherits lavd's task lifetime correction. Auxiliary futex and exec hooks,
runnable's waker, dispatch candidates and DSQ load sampling use
find_task_ctx(), a quiet lookup that neither reads nor fills the per-CPU task
cache. These non-sleepable readers keep the lookup and every use in the
callback's RCU read-side critical section.

The sleepable init_task() allocates outside an explicit RCU read-side
critical section, then protects the parent lookup and the inheritance copy
inside one. exit_task() frees task storage with scx_task_free_rcu() after
load accounting and bandwidth cancellation. Cached own-task lookups stay in
scheduler callbacks, which fill the cache with preemption disabled. A task
reference alone does not pin the arena allocation.

The controlled lavd detach test observed cached pointers after their
task-data associations were removed. It did not establish subsequent
dereference, reuse or corruption. The correction protects allocation
lifetime, not completion of initialization or coherent reads of mutable
fields. Bandwidth queue ownership still needs its separate validation.

The shared library's RCU grace period and its userspace driver are
prerequisites. Keep the driver alive until producers have stopped and the
final drain has completed. Validate pre-attach, active, detach and
post-detach hooks, concurrent parent exit, task churn and DSQ readers.
Source review and a build alone do not close these runtime obligations.

## Task utilization averages

Task averages use a private native temporary before publishing their final
fields. Task initialization copies parent history without the parent's rq
lock, so direct arena accumulation would expose intermediate stores absent
from lavd's copyback. The shared task helper preserves lavd's publication
and estimate ordering when a task sleeps. The inherited byte copy remains
unsynchronized and does not promise a coherent snapshot.

## Masks and ownership

The distribute helpers share the arena rotor that the shared arena init
allocates: one cacheline-separated slot per cid holding the last selected
cid, indexed by the executing cid. The slot starts at zero, a scan starts
from the previous cid plus one, and the slot is updated only after a valid
pick. The advisory non-atomic updates retain the native rotor's concurrency
semantics. Picks from a CPU outside the cid space fall back to the first
matching cid.

All current mavd cmasks cover the complete possible-CID range with base
zero. Embedded masks reserve storage for the configured maximum through
TRAILING_OVERLAP(); the scratch pool holds one mask per slot sized from
nr_cids. Initialize each mask's geometry before use and keep that geometry
immutable. Possible but offline affinity bits remain represented.

Task initialization only sets the owned mask's geometry. The kernel delivers
the initial affinity through ops.set_cmask() right after ops.enable(),
before ops.set_weight() and the first enqueue, and never calls it before
enable(), so set_cmask() alone copies its borrowed argument into that
storage and derives the affinity flags. Selection and enqueue can use it
under their task-affinity serialization. Permanent pinning, effective
single-CPU affinity and transient migration disable remain distinct
predicates.

A copied task mask is insufficient for asynchronous BTQ readers. Kernel
affinity can change before the mask callback updates the copy. BTQ placement
therefore tests live p->cpus_ptr and preserves the lowest-raw-CPU fallback.
Dispatch also uses live affinity snapshots because kernel queue operations
can drop locks before invoking the callback. Snapshots can age under
concurrent affinity changes, just as the baseline live reads could.

Scratch masks belong to the executing CPU. A dispatch callback can target a
different CPU during core scheduling. Its target cpu_ctx must not supply
scratch that the target CPU might also use. The previous-task and DSQ-task
dispatch paths use the executing CPU's context.

cmask operations mutate their first operand. Preserve aliasing when
translating a three-argument cpumask operation. Copy only when the
destination is distinct from the necessary source. The latency-critical
steady/turbulent split uses subtraction of the steady subset from the
eligible set, corresponding to lavd's XOR with that subset.

## Idle tracking

The arena idle picker retains lavd's selection scopes and branch order.
Within a scope, try a fully idle SMT core before a partially idle core.
SCX_PICK_IDLE_CORE forbids the partial-core fallback. Clear the entire
core's SMT-idle range before the single-CID claim, including when another
picker wins the claim.

Each CPU context carries its core's first cid and size from the kernel's cid
topology, fixed at init. Full-core eligibility tests and publication
include only currently online members. An offlined sibling must not prevent
the remaining idle CPU from becoming a full-core candidate. The custom
online mask follows ops.cid_online/offline(), so it can change earlier than
the kernel's physical sibling masks during hotplug. Full-core publication
follows SCX-active membership. Exact transient mask identity is not
asserted. Hotplug validation must cover those transitions under load.

An idle claim can be abandoned without an intervening busy transition, and
the kernel reports no idle notification for it. Mavd restores the claim at
the end of ops.dispatch() when nothing was consumed and there is no previous
task to keep running.

The shared cgroup bandwidth wake callback uses the same claim mechanism and
kicks the selected CID. Loading with bandwidth control enabled does not
prove quota throttling and unthrottling work. Exercise those transitions
explicitly.

Auxiliary programs and timers can outlive ops.exit(). A positive
scx_bpf_this_cid() or scx_bpf_task_cid() only establishes that a global
mapping exists. Context lookup follows the configuration-dependent
validation described above. An unavailable CPU context is a terminal claim
result for the picker invocation, not another lost claim to retry. Preserve
that distinction to avoid spinning on stale idle bits after scheduler exit.

## Differences requiring validation

CPU-context pages currently use NUMA_NO_NODE. Their physical placement can
differ from the native per-CPU map allocation. Measure locality and
remote-memory effects on multi-node hardware, together with lookup and
running-average costs.

CID distribution follows the shared per-cid cmask rotor in CID order. Lavd's
builtin cpumask rotor traverses Linux CPU IDs. Repeated choices still spread
across eligible CPUs, but exact CPU sequences can differ. Mavd's rotor also
belongs to the loaded BPF object, whereas the builtin rotor is kernel state.
Preserve lavd's explicit preference order rather than replacing it with a
first-set-bit choice. Equal-load ties in the most-loaded DSQ pick go to the
lowest cid, where lavd's scan order gave them to the lowest CPU. Measure the
resulting distribution and performance.

The BPF idle-claim retry uses can_loop, whose may_goto termination can
return busy under sustained contention. The kernel builtin retries until it
finds an empty eligible set or wins a claim. This is a termination
constraint on the BPF implementation. It must not drop the task: lavd's
existing fallback placement still runs. Stress contention and measure
whether fallback frequency changes.

Executing-CPU scratch in remote-core dispatch removes the source-visible
possibility of two CPUs sharing the target's temporary mask. This differs
from the inherited helper's scratch argument and is required by the storage
ownership rule. It has not been demonstrated by a runtime race reproducer.

CID task writes use the kernel setters instead of direct slice or
virtual-time stores, as required by the CID verifier. A remote slice request
made without the target's rq lock is applied at the kernel's next slice
consideration. Victim selection, the comparison with the old slice and the
winning CAS remain lavd's policy. Application timing differs from a direct
store and requires preemption-latency validation. With
CONFIG_EXT_SUB_SCHED=y, the setter checks that the task belongs to the
resolved scheduler. With that option disabled, the ownership check is a
stub.

The scheduler requires a CID-capable kernel. The old CPU-release callback is
replaced by the existing sched_switch reenqueue hook. These are interface
requirements, not intentional policy changes.

## Arena cleanup invariants

init_cpdoms() is the sole writer of nr_cpdoms and bounds it by
LAVD_CPDOM_MAX_NR. Complete scans below that count index cpdom_ctxs
directly. get_cpdom_ctx() still validates IDs from task history and neighbor
selection, where an out-of-range value affects the fallback. The neighbor
table stores unsigned bytes, so testing a retrieved ID for negativity adds
no protection.

init_cid_masks() validates nr_cids and installs all global and per-CPU masks
before CPU initialization, timers or scheduling use them. Their pages remain
allocated with the arena map. RCU sections that only protected the old kptr
masks are unnecessary. CPU-context availability checks remain necessary for
auxiliary programs, and the picker still uses NULL for empty active and overflow
sets.

The picker keeps its mask-preparation guards and Boolean return paths because
removing them together exceeds the verifier's processed-instruction limit.
Restoring that group allows the full program to load. An individual check's
contribution has not been isolated. Reevaluate the group when changing its mask
loops.

The loader validates nr_cpu_ids against LAVD_CPU_ID_MAX. Preference-position
loops bounded by nr_cpu_ids need no duplicate capacity check. Keep checks
before indexing native seed arrays and checks for invalid preference
entries. CPU max_capacity is an immutable copy of cpu_capacity[raw_cpu],
initialized before statistics and scheduling. Invariant-time conversion uses
that arena field directly.

When importing a lavd change, distinguish these storage guarantees from its
scheduling conditions. Do not restore native-map checks around fixed arena
state, or remove policy checks merely because arena faults are recoverable.
Keep actual stack boundaries, task lifetimes, atomic mask operations and CPU
online publication ordering. This cleanup intends no scheduling-policy
change.

## Loops

The conversion's own scans use bpf_arena_for() from lib/arena_loop.h: mask,
context, preference-table and domain-bitmap initialization, the sibling
scans in update_idle_cid(), and the per-cid statistics and power-mode scans
whose bound became nr_cids. Loop counters are u32 or narrower, as the macro
requires. Scans that lavd wrote over nr_cpdoms, the preference table and its
retry counts keep bpf_for() at this point.

can_loop in bpf_arena_for() and cmask_for_each() bounds verifier state, not
valid traversal. Every scan is bounded by the immutable cid, CPU or domain
count, far below the may_goto budget, so complete scans finish.

The Clang 22.1.8 BPF v3 build rejected the attempted 32-bit relaxed atomic
loads. The local view requests repeated reads without changing the field
declaration or adding ordering or synchronization with writers. Emitted
AS1-to-AS0 casts mark PTR_TO_ARENA, including in this tree's READ_ONCE()
expansion.

## Picker stack

The select and enqueue programs reach the idle scan six frames deep:
pick_idle_cpu(), migrate_to_neighbor(), pick_idle_cpu_at_cpdom(),
pick_idle_cid() and the distributed scan. The verifier sums every frame on
that chain, rounded up to 16 bytes, against its 512-byte limit. With the
boundaries below the chain measures 512 from the select program; without
them it measured 528 to 608 and the select program was rejected.

Three boundaries hold. The four mask preparation helpers in pick_idle_cpu()
stay out of line, which keeps its frame at 136 bytes instead of 152. The
domain intersection in pick_idle_cpu_at_cpdom() runs through an out-of-line
helper, which keeps that frame at 8 bytes instead of 88. pick_idle_cid()
runs the distributed scan through an out-of-line wrapper, so the scan's
96-byte frame returns before the claim's frame is pushed. Sticky-domain
selection is a plain static function. When porting idle-selection changes,
re-measure the chain from the emitted object: the deepest r10 offset in each
function, rounded to 16, summed along the call chains from both programs.
Another compiler can change the frames.

## Mask traversal

Domain statistics, initialization, affinity classification and load
balancing use cmask_for_each(). The macro bounds the arena next-set scan
with can_loop: a traversal yields at most nr_cids set bits, far below the
may_goto budget, so complete scans finish. An ordinary loop around the arena
scan failed verifier loop detection in statistics collection. The macro
evaluates the mask expression more than once, so keep it free of side
effects.

Arena-resident types are spelled out as struct with the __arena qualifier
rather than aliased. A typedef of the kernel's struct scx_cmask made a field
access in the traversal macro relocate against the alias, which the kernel
BTF has no match for, and ops.set_cmask() failed to load.

## Porting a lavd change

1. Record the lavd source revision and retain its original patch separately.
   Compare corresponding files and functions before translating identifiers.
2. Identify every input, output, index, mask and helper's units. Keep policy
   thresholds, equations, accounting updates, branch order and options
   unless an API constraint requires a documented difference.
3. Apply storage and API translation at the existing boundaries. Check
   callback ownership, auxiliary-hook lifetime, live affinity and scratch
   ownership before choosing an arena pointer.
4. Review each conversion checkpoint against its immediate predecessor.
   Inspect generated BPF code for large copies and variable indices. The
   compiler has previously miscompiled a large aligned copy in this work.
   Source-level memcpy equivalence is insufficient.
5. Add every new branch or interface to the validation matrix. Record any
   divergence with its reason, evidence, expected effect and a test that
   exercises it. Do not treat an untested difference as equivalent.

Keep policy source files parallel to lavd so future changes can be compared
by function.

## Validation obligations

Choose affected cases and the required confidence for the change at hand.
The wider coverage inventory includes affinity and migration disable, SMT
on/off, initially offline CPUs, hotplug, remote core scheduling, RT/DL
takeover, cgroup quota wakeups, preemption, statistics, power profiles and
attach/detach. It is not a mandatory matrix for every port. Compare matching
options and topology inputs. Require positive workload progress and clean
kernel, setup and detach observations. Record source, binary and kernel
identities once per batch.

The smoke test saves events-after-attach.log after complete attachment and
events.log after the workers finish, before detaching. Their difference
covers the whole root scheduler during that interval, including the test
harness and other tasks. Kernel event reads aggregate per-CPU counters
without stopping scheduling, so these are approximate snapshots.

Use a separate debug kernel for functional and stress tests. Run all
performance measurements and pilots on bare metal, including load-time
measurements. Both schedulers must use the same separately built performance
kernel, with lockdep, KASAN, KCSAN and expensive memory debugging disabled.
Audit the resolved configuration and verify the running kernel and boot
options. A requested config fragment alone is insufficient.

Choose paired sample counts and precision for the requested assessment. A
small descriptive comparison that reuses earlier results is acceptable when
the change does not warrant a full statistical run. Report inconclusive
results and unmeasured cases explicitly. VM validation does not establish
performance on bare metal, hybrid/ARM systems or actual games.
