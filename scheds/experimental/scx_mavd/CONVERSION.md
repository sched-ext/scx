# Maintaining scx_mavd

scx_mavd is scx_lavd converted to the cid form of sched_ext, with every
piece of scheduler-owned state in a BPF arena. It follows lavd's policy and
source organization file for file. The fork baseline is 0ed245e2d0a3
("scx_lavd: Drop the unused conv_wall_to_invr() and get_cpuperf_cap()"), and
the reference sources are [scx_lavd](../../rust/scx_lavd). This file records
the goals of the fork, the representation choices, the verifier constraints
that shaped the code and how to measure them, the known issues, and the
procedure for porting a lavd change.

The conversion is under validation. A successful build or source review does
not establish verifier acceptance, behavioral equivalence or performance
equivalence.

## Goals

The standing task once the conversion lands is to track lavd's development
while keeping the properties the conversion established. Every lavd change
is ported or recorded as deliberately omitted, following "Porting a lavd
change", and a port preserves all of the following.

- Policy parity. mavd makes the same scheduling decisions as lavd from the
  same inputs: the same thresholds, equations, accounting, branch order and
  options. Differences exist only where the cid form or arena storage forces
  them, and each is listed under "Differences requiring validation" with its
  reason.
- Source parity. Policy files keep lavd's relative paths, function layout
  and identifiers wherever they let the two be compared function by
  function. Only what holds a different thing is renamed, as the cid-valued
  fields and the cmask globals are.
- Everything in the arena. Every piece of scheduler-owned state lives in
  arena memory owned by the loaded object, and userspace reaches arena
  globals only through the published pointer struct. No scheduler state goes
  back into BPF maps, per-CPU maps or kptrs. The native objects that remain
  are the kernel's own or transport: timer anchors, the task-to-data
  association, the bandwidth library's kernel maps, the introspection ring
  buffer and the allocator library's RCU doorbell ring buffer.
- The cid form. Scheduler-owned CPU fields hold cids, masks are cmasks over
  the cid space, and the kernel's cid kfuncs replace the CPU ones. Linux CPU
  IDs appear only at the boundaries listed under "CPU identities".
- Checks dropped only for the verifier. A range or NULL test that lavd
  carries because the verifier demands it for native maps and kptrs is not
  restored around fixed arena state, and no new defensive test is added
  without a concrete failure it prevents. A test that encodes scheduling
  policy or a runtime condition stays. "Arena cleanup invariants" lists what
  was dropped and what was kept.
- Verifier limits within bounds, measured. The picker's two hot helpers are
  global functions verified once per program, every numeric scan is
  bpf_arena_for(), and no function carries an inlining annotation for stack
  budgeting alone. A port that touches the picker or the scheduling
  callbacks re-measures the stack chains with tools/stack-chains.py and the
  verifier, and the instruction counts, as described under "Verifier
  constraints", and records the results there.
- Validated, not assumed. Each port carries the evidence listed under
  "Validation obligations" for the cases it affects, and unmeasured cases
  are reported as such.

## Shared bandwidth storage

Both lavd and mavd use the arena conversion of lib/cgroup_bw.bpf.c. Private
configuration, counters, free-list heads, deferred-destroy slots and
cgroup-ID work arrays share one arena allocation. A native pointer names the
state. The allocation retains the initial zeros, alignment and atomic
publication operations of the original objects.

Hierarchy traversal uses arena scratch indexed by the executing Linux CPU,
with space for the kernel's scx_bpf_nr_cpu_ids() span, including possible
CPUs not yet present in sysfs. Allocate it before starting either timer and
retain the state until arena teardown, including partial initialization
failure. Direct page allocation avoids the static allocator's per-allocation
size limit on large machines. Every traversal clears its own slot. This
preserves the original per-CPU scratch's concurrency assumptions. It does
not make nested use on the same CPU safe.

Keep the append capacity and hierarchy-depth checks. The cgroup list is
bounded by CBW_NR_CGRP_MAX; the throttled list contains at most one entry
per visited cgroup. Published counts therefore bound the direct array
accesses that replace MEMBER_VPTR(). Keep the timer/dispatch acquire and CAS
ordering when porting changes. Timer anchors and kernel association maps
remain native.

## CPU identities

Scheduler-owned CPU fields of the task and CPU contexts are named cid or
*_cid. The exceptions below are Linux CPU IDs. Locals named cpu in converted
functions still hold cids, so do not infer units from a local's spelling.

| Value | Units |
| --- | --- |
| task_ctx cid fields | CID, or the field's existing negative error |
| cpu_ctx.cid and core_cid | CID |
| cpu_ctx.kernel_cpu | Linux CPU ID |
| Runtime policy, affinity, domain and idle mask bits | CID |
| Runtime preference-table entries | CID |
| Preference-table positions and raw nr_cpu_ids span | Lavd's original positions and Linux CPU ID span |
| CpuOrder.cpu_adx, the capacity, big and turbo tables and the domain seed bitmap | Linux CPU ID |
| rq clocks, cpufreq per-CPU data and hardware pressure indices | Linux CPU ID |
| Introspection CPU fields and messages labeled CPU | Linux CPU ID |
| Compute-domain IDs and user-created virtual LLCs | Lavd policy domain, independent of kernel CID topology |

Convert raw topology input only in scheduler initialization, after the
kernel publishes the CID mapping. Keep preference positions and virtual LLC
membership. Affinity classification compares the allowed mask's weight with
the cid count. Kernel topology provides SMT core ranges for idle tracking.
It does not replace lavd's compute-domain definitions.

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
translated from raw CPU 0. An empty allowed mask makes the first-cid
fallback return the mask end, which the context lookup rejects as lavd's
rejected nr_cpu_ids. Load balancing takes the lowest cid on equal per-CPU
queue loads.

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

CPU accounting updates its arena-resident running averages with the
library's ravg_accumulate_arena() and ravg_read_arena(), in the same
two-call form as lavd's native updates. Each average has one writer context,
the CPU's own running and stopping callbacks for utilization and the
statistics timer for IRQ steal, so the library's staged copy overwrites
nothing concurrent. Neither the library nor the caller serializes readers
against the writer. Validate statistics under hotplug.

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
Treat a percentage over 100 as an anomaly to investigate, never one to
clamp. This does not accept statistics correctness or explain an individual
outlier. Compare statistics in matched runs and collect causal evidence
before attributing a discrepancy. Do not clamp the reported values.

To validate a displayed row's arithmetic, capture the exact numerators,
denominators and result values used to format that row. Preserve separate
reads where the existing calculation makes them. An independent reread of
BPF state is not the same input. Check the source arithmetic and formatting,
retaining nonfinite and out-of-range results explicitly. Matching these
operands explains the displayed calculation, not which concurrent updates
produced the operands or whether counts are complete.

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

mavd inherits lavd's task lifetime correction. Auxiliary futex and exec
hooks, runnable's waker, dispatch candidates and DSQ load sampling use
find_task_ctx(), a quiet lookup that neither reads nor fills the per-CPU
task cache. These non-sleepable readers keep the lookup and every use in the
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

Task averages use the same library arena operations as lavd, and the
conversion does not touch them. Task initialization copies parent history
without the parent's rq lock; that inherited byte copy remains
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

Every affinity test reads that copy, the BTQ reenqueue and dispatch
included; mavd reads p->cpus_ptr nowhere. An asynchronous reader such as the
BTQ drain can see the copy lag an affinity change, but the change dequeues
and re-enqueues the task under its rq lock, and the kernel discards a
dispatch whose task was dequeued or re-enqueued since the decision, so a
stale test is never acted on. A DSQ candidate without a task context is
skipped in dispatch, where lavd fell back to the kernel mask.

Scratch masks belong to the executing CPU. A dispatch callback can target a
different CPU during core scheduling. Its target cpu_ctx must not supply
scratch that the target CPU might also use. The previous-task and DSQ-task
dispatch paths use the executing CPU's context.

The library's cmask_and(), cmask_or() and cmask_andnot() take a destination
and two sources, the destination may alias either source, and each returns
whether the destination is non-empty afterwards, so lavd's copy, operate and
test sequences become one call. The latency-critical steady/turbulent split
uses subtraction of the steady subset from the eligible set, corresponding
to lavd's XOR with that subset.

## Idle tracking

The arena idle picker retains lavd's selection scopes and branch order.
Within a scope, try a fully idle SMT core before a partially idle core.
SCX_PICK_IDLE_CORE forbids the partial-core fallback. Clear the entire
core's SMT-idle range before the single-CID claim, including when another
picker wins the claim.

Each CPU context carries its core's first cid and cid count from the
kernel's cid topology, fixed at init. Full-core eligibility tests and
publication include only currently online members. An offlined sibling must
not prevent the remaining idle CPU from becoming a full-core candidate. The
custom online mask follows ops.cid_online/offline(), so it can change
earlier than the kernel's physical sibling masks during hotplug. Full-core
publication follows SCX-active membership. Exact transient mask identity is
not asserted. Hotplug validation must cover those transitions under load.

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

Most of lavd's range and NULL tests on these tables and masks exist for the
verifier, which needs bounded array indices and NULL-tested kptr and map
lookups. It does not check arena accesses, so a test is dropped wherever the
value is always valid.

init_cpdoms() is the sole writer of nr_cpdoms and bounds it by
LAVD_CPDOM_MAX_NR, and userspace rejects more domains than that.
get_cpdom_ctx() and get_cpdom_mask() index cpdom_ctxs without a range test,
and scans below that count, lookups by a context's cpdom_id and
neighbor-table entries use the result without testing it. The two values
that can fall outside the domain range are guarded by their callers:
unaccount_queued_load() tests queued_in_cpdom_id for the not-queued value
before the lookup, and the picker exits on a sticky domain of -ENOENT before
its lookups.

init_cid_masks() validates nr_cids and installs all global and per-CPU masks
before CPU initialization, timers or scheduling use them. Their pages remain
allocated with the arena map, so no mask pointer is NULL-tested after init
and no RCU section remains for them. get_cpu_ctx_id() keeps its tests, a cid
outside the table, a missing array and a cid that no longer maps to a CPU,
for the mask-end value an empty allowed copy yields and for callers that can
run without the scheduler attached. Its result is tested only there and
where the id can be a sentinel: timers and the helpers they share with the
callbacks, auxiliary hooks, exit_task, the enqueue paths that reject an
empty allowed copy, and raw picker results. The scheduling callbacks do not
test its result for the cids the kernel hands them. The picker uses NULL for
empty active and overflow sets.

The picker's mask-preparation helpers return nothing. Their only failure
paths were the NULL guards that went with the fixed arena masks, so the
callers' fallbacks went with them.

The loader validates nr_cpu_ids against LAVD_CPU_ID_MAX. Preference-position
loops bounded by nr_cpu_ids need no duplicate capacity check. Keep the
checks for invalid preference entries. CPU max_capacity is an immutable copy
of cpu_capacity[kernel_cpu], initialized before statistics and scheduling.

When importing a lavd change, distinguish these storage guarantees from its
scheduling conditions. Do not restore native-map checks around fixed arena
state, or remove policy checks merely because arena faults are recoverable.
Keep task lifetimes, atomic mask operations and CPU online publication
ordering. This cleanup intends no scheduling-policy change.

## Loops

Every bpf_for() scan became bpf_arena_for() from lib/arena_loop.h, and the
loops that were plain C stay plain C. Loop counters are u32 or narrower, as
the macro requires.

can_loop in bpf_arena_for() and cmask_for_each() bounds verifier state, not
valid traversal. Every scan is bounded by the immutable cid, CPU or domain
count, far below the may_goto budget, so complete scans finish.

The Clang 22.1.8 BPF v3 build rejected the attempted 32-bit relaxed atomic
loads. The local view requests repeated reads without changing the field
declaration or adding ordering or synchronization with writers. Emitted
AS1-to-AS0 casts mark PTR_TO_ARENA, including in this tree's READ_ONCE()
expansion.

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

## Verifier constraints

Two verifier limits shaped the picker and the callbacks: the combined stack
limit and the instruction budget. This section records what they are, the
measurements behind the current code and how to repeat them.

The measurement kernel is sched_ext/for-next f6e1fb3c45b3 ("Merge branch
'for-7.4' into for-next") plus "bpf: Keep generic __uninit kfunc arguments
live". bpf-next has fc670d4b6c31 ("bpf: Fix generic __uninit kfunc output
buffers") for the same problem. The compiler is clang 22.1.8 with libbpf
1.7.0, and the programs were loaded in a 16-CPU QEMU guest with two threads
per core. Another compiler or kernel can change every number below, so
re-measure rather than reason from them.

The scheduler requires clang 22 or newer, and no code accommodates an older
compiler. Clang 19 through 21 compile the memset that zeroes the
arena-resident sys_stat_ctx in sys_stat.bpf.c into stores through the raw
arena address, without the address-space cast that clang 22 emits, and the
verifier rejects init, cid_online and cid_offline, the programs that reach
it, with an invalid scalar memory access.

### The combined stack limit

check_max_stack_depth() walks every call chain of a program, adds each
subprog's stack depth rounded up to 16 bytes under the JIT, and rejects the
program when a chain exceeds MAX_BPF_STACK, 512 bytes:

    combined stack size of 5 calls is 528. Too large

A subprog's depth is the deepest stack access the verifier saw in it.
Scratch whose lifetime ended before a deeper call still counts: the frame is
a per-subprog maximum, not a per-path one. Global functions are on the chain
like static ones.

### The deepest chains

The idle picker runs from both ops.select_cid() and ops.enqueue(). The
three-operand cmask operations it calls, cmask_and(), cmask_or() and
cmask_andnot(), are global functions with a frame of their own, while the
scans and bit tests stay inline in their callers. The deepest chain from
either program is the picker's own, six frames down to the idle claim:

    lavd_enqueue            160 -> 160
    pick_idle_cpu           104 -> 112
    migrate_to_neighbor     112 -> 112
    pick_idle_cpu_at_cpdom   16 ->  16
    pick_idle_cid            96 ->  96
    claim_idle_cid           48 ->  48
                                   544

The left column is the deepest r10 offset in the emitted object, the right
one the rounded frame the verifier adds. From lavd_select_cid(), whose frame
is 128, the same chain models at 512. The chain that ends in the domain
intersection's cmask_and() frame instead of the claim is 32 bytes shorter,
and the preemption victim search, lavd_enqueue() to
try_find_and_kick_victim_cpu() to cmask_and(), is 480. The verifier's own
`stack depth` line at log level 4 reports 496 for lavd_enqueue() and 464 for
lavd_select_cid(), 48 under the model on both.

### The current layout

The picker keeps lavd's helper layout: the mask preparation helpers are
`static __always_inline`, the overflow-set extension is written inline in
pick_idle_cpu() as in lavd while its candidate search
find_cpu_for_ovrflw_extend() stays a plain static function that clang keeps
as a frame of its own, the domain intersection is a plain cmask_and() call,
and the distributed scan is inlined into pick_idle_cid().

Sticky-domain selection is a global function with its own frame off the
deepest chain. The pick context carries no copies of the active and overflow
masks: in lavd the context holds the two kptrs, read once under the RCU lock
and NULL-checked, and in mavd they are arena globals fixed at init and read
where used.

The extension anchors on the LLC of the previous cid and translates cids to
CPUs for the library topology lookup. Its candidate pool is the task's
allowed copy intersected with mavd's online copy.

### How the layout got here

lavd declares its mask preparation helpers `static __always_inline` and most
other picker helpers plain `static`, and mavd keeps that. During the
conversion the cmask operations were inlined arena word loops whose scratch
landed in the helpers' callers, and with every helper inlined the verifier
rejected lavd_select_cid with the message quoted above: five frames, 528
bytes.

clang inlined the plain static helpers as well at the optimization level
used, so `__noinline` was the only way to keep a frame boundary, and the
picker carried four of them for a while: the mask preparation helpers, the
overflow-set extension, the domain intersection and the distributed scan,
each out of line. With them the chain stood at 512.

It dropped to 416 when the sticky-domain search became a global function:
clang had inlined it into pick_idle_cpu(), whose frame went from 144 to 48
once the search's scratch got a frame of its own, off the deepest chain. The
pick context also carried lavd's copies of the active and overflow masks,
and dropping the two pointers made both root frames 16 bytes smaller.

When the library's three-operand cmask operations became global functions
the word loops left their callers. The boundaries were then measured one at
a time and all together, every variant loaded, and they were removed.
Besides lavd's own on pick_idle_cpu(), only the two global functions keep
`__noinline`, so that clang cannot inline them at their call sites and undo
the once-per-program verification.

### Model versus verifier

tools/stack-chains.py reads `llvm-objdump -dr` output, takes each function's
deepest r10 offset, rounds it to 16, resolves call edges from relocations
and relative calls, and prints the deepest chains from a root. From the
repository root:

    python3 scheds/experimental/scx_mavd/tools/stack-chains.py \
        target/debug/build/scx_mavd-*/out/bpf.bpf.o \
        lavd_select_cid lavd_enqueue

The script's own docstring explains its output. The total is an upper bound:
the verifier charges a subprog only for the accesses it verifies, so code it
never reaches does not count. Every rejection seen during the conversion
modeled over 512, at 528 and 544, but a 528 model has both loaded and been
rejected depending on what the verifier reached, and the current code models
at 544 from lavd_enqueue() and 512 from lavd_select_cid() and loads, with
the verifier reporting 496 and 464. A model over the limit therefore names a
chain to measure, and the verifier's `stack depth` line decides.

### The instruction budget

The verifier checks a static subprogram again on every caller path, with the
caller's full register state. lavd's picker helpers are static, and in lavd
their bodies are cpumask kfuncs, one instruction each. In the cid form the
same bodies became arena word loops, inlined at the time, cheap per visit
but visited thousands of times through the picker's paths, and select_cid
exceeded the one-million-instruction budget:

    BPF program is too large. Processed 1000001 insn

Of the verified instructions, 81 percent were word loops in cid.bpf.h.
Dropping a NULL test after a lookup that can still return NULL costs more,
not less: the verifier then carries the NULL state through the rest of the
function.

A global function is verified once, with opaque arguments. Making the two
helpers under the most paths global, pick_idle_cpu_at_cpdom() and
find_sticky_cpu_and_cpdom(), took select_cid from over the one-million
budget to 73k verified instructions and enqueue to 102k. The eight other
picker helpers were measured as globals too and saved under five percent of
the instructions together.

The price of a global function is that the pick context can hold no kernel
pointers: the callee reads them as scalars, and the call marks the caller's
copy as written, so the task pointer travels as a separate argument. The
pointer arguments of a global function carry `__arg_arena` for arena
pointers and `__arg_trusted` for kernel pointers such as the task, so that
the callee is verified with the argument's type instead of a scalar.
Pointers into the caller's stack, the pick context and the out-parameters of
the two picker globals, carry `__arg_nonnull`, so the callee is verified
against the pointed-to struct without a NULL branch.

libbpf's `__hidden` does the opposite of what its name suggests here: it
marks a subprogram static for the verifier, and it is the declaration for a
function called across files that should stay static.

A program is associated with the arena map by the relocation of an arena
global it references directly, and a program or subprogram that only
receives or loads arena pointers still needs the map for its address-space
casts, so such a function references it explicitly with `asm volatile("" ::
"r"(&arena))`.

The six scans that an earlier attempt had to leave on `bpf_for()`, part of
the twenty the conversion moved, cost under six thousand instructions in
total once the picker helpers were global. The library's three-operand cmask
operations are global functions too, so the picker's mask intersections are
verified once per program instead of at every call site: on the same mavd
code they took select_cid from 88k to 70k verified instructions and enqueue
from 105k to 89k, and returning the picker to lavd's inline helpers cost 4k
and 3k of that back. Verified instructions per program with the current
code:

    lavd_select_cid      74,546
    lavd_enqueue         91,512
    lavd_dispatch       719,743
    lavd_init_task      168,388
    lavd_init            46,246

Dispatch rose from 473k to 720k when the cleanup dropped the tests on
lookups that can still return NULL, the effect above, and the last result
tests in the callbacks did not move it. An experiment that replaced the
lookups themselves with direct array indexing in the callbacks brought it to
436k. It was not kept, because it replaced the helpers.

### Re-measuring

1. Boot a kernel with the cid-form sched_ext API and the `__uninit` liveness
   fix.
2. `cargo build -p scx_mavd` from the repository root. The BPF object is
   target/debug/build/scx_mavd-*/out/bpf.bpf.o.
3. Run the model as above from the repository root, then load
   target/debug/scx_mavd. A rejected load prints the verifier log on stdout.
4. To watch the chains move, add `__noinline` to one of the picker's static
   helpers in src/bpf/idle.bpf.c, or drop it from a global function there,
   and repeat. The build tracks the BPF sources.
5. For per-program instruction counts and the verifier's own stack maxima,
   set the verifier log level to 4 on every program before loading,
   `bpf_program__set_log_level()` in libbpf or `set_log_level(4)` on each
   program of the opened skeleton in main.rs, and run the scheduler with
   `--log-level trace`: libbpf then prints each program's verifier log,
   ending in a `processed N insns` line and a `stack depth` line. Level 2
   with a caller-provided log buffer gives the full trace, whose `@
   file:line` annotations give a per-line histogram of where the budget
   goes.
6. Record the new chains and counts in this section.

## Known issues

These were observed during a functional and stress campaign on a KASAN and
lockdep build of the kernel above, on bare metal: a 24-thread desktop and a
192-CPU two-socket server. None is fixed.

- A task pinned to a CPU in its offline sequence can sit in that CPU's
  per-core DSQ until the sched_ext watchdog unloads the scheduler with a
  runnable task stall, ksoftirqd of the offlining CPU 30 to 45 seconds old
  in the exit dump while the CPU idles. An offline/online cycle of CPU pairs
  under load reproduced it on the desktop with mavd and with upstream lavd
  alike, so it is inherited. The kernel calls ops.cid_offline() from the
  deactivate step, long before the CPU stops running, and whatever is
  enqueued for that CPU afterwards still has to be dispatched. The 192-CPU
  server did not reproduce it in 19 cycles.
- Under a 50-minute autopilot soak with cpu.max quota churn on the 192-CPU
  server, the cgroup bandwidth library's ATQ spinlock timed out in
  scx_atq_pop() from the dispatch reenqueue: the timed may_goto budget of
  arena_spin_lock_slowpath() expired with 35 timeout reports from 33 CPUs,
  the library treats that as fatal, and the scheduler exited about 17
  minutes after attaching. Whether lavd hits it is untested beyond a
  five-minute run that passed.
- One scheduler load on the 192-CPU debug kernel spent 17 minutes in the
  verifier, sampled stacks inside do_check_common(), against 45 to 90
  seconds for every other load of the same binary. Cause unknown.
- The bandwidth test, in the mavd-tests patch on the maintainer's quilt-mavd
  branch with the other functional drivers, parses the library's state dump
  and predates the library's rewrite: the dump format and dump scope
  changed, and its trace-buffer sizing assumptions no longer hold.

## Porting a lavd change

The last lavd commit accounted for is the fork baseline named at the top of
this file. Move that line with every port. To see what moved, compare from
it to the current tree, and read the shared library and headers together
with lavd's own files, because lavd's arena conversion, the cmask operations
and the bandwidth code live there:

```sh
git log --oneline BASELINE..main -- scheds/rust/scx_lavd lib \
    scheds/include rust/scx_utils rust/scx_cargo
git diff BASELINE..main -- scheds/rust/scx_lavd
```

1. Record the selected lavd commit, its subject and the original incoming
   patches. Compare corresponding files and functions before translating
   identifiers.
2. Identify every input, output, index, mask and helper's units. Keep policy
   thresholds, equations, accounting updates, branch order and options
   unless an API constraint requires a documented difference.
3. Apply storage and API translation at the existing boundaries. Check
   callback ownership, auxiliary-hook lifetime, live affinity and scratch
   ownership before choosing an arena pointer. Keep policy changes separate
   from representation cleanup.
4. Review each port against the tree before it, including all changed
   callers, callback contracts, CPU units, masks, options and reporting
   fields. Inspect generated BPF code for large copies and variable indices.
   The compiler has previously miscompiled a large aligned copy in this
   work. Source-level memcpy equivalence is insufficient.
5. Build both schedulers, load mavd, and re-measure the stack chains and
   instruction counts when the picker or the callbacks changed. Add every
   new branch or interface to the coverage inventory under "Validation
   obligations". Record any divergence with its reason, evidence, expected
   effect and a test that exercises it. Do not treat an untested difference
   as equivalent.
6. Record the port in its patch description: the lavd commit and subject,
   the changed functions, each translation or deviation with its reason, and
   the build, review and functional evidence. A skipped lavd change needs
   the same record. Then update the baseline line.

To confirm the fork is still lavd plus the conversion, extract lavd at the
ported commit and diff it against mavd:

```sh
mkdir -p /tmp/lavd
git archive BASELINE scheds/rust/scx_lavd | tar -x -C /tmp/lavd
diff -r --no-dereference /tmp/lavd/scheds/rust/scx_lavd \
    scheds/experimental/scx_mavd
```

Beyond the conversion itself the differences are the crate name, description
and `publish = false` in Cargo.toml, the README, build.rs naming the shared
library sources by relative path instead of through the src/bpf/lib symlink,
adding cid.bpf.c and dropping the library's cpumask.bpf.c, whose helpers
nothing in the scheduler references, LICENSE as a regular file, the
scheduler name in main.rs, the ops name in main.bpf.c and the introspection
comm filter in introspec.bpf.c, cpu_order.rs without the sibling field and
table that the kernel's cid topology replaces, this file and tools/.
Everything else in that diff must be explained by a section of this file.

## Validation obligations

Choose affected cases and the required confidence for the change at hand.
The wider coverage inventory includes affinity and migration disable, SMT
on/off, initially offline CPUs, hotplug, remote core scheduling, RT/DL
takeover, cgroup quota wakeups, preemption, statistics, power profiles and
attach/detach. It is not a mandatory matrix for every port. Compare matching
options and topology inputs. Require positive workload progress and clean
kernel, setup and detach observations. Record source, binary and kernel
identities once per batch.

The functional drivers used so far, smoke, affinity, bandwidth and
lifecycle, live in the mavd-tests patch on the maintainer's quilt-mavd
branch, commented out of its series file and not in this tree. The patch
adds scheds/experimental/scx_mavd/tests/ with its own README.md and also
edits lock.bpf.c and main.bpf.c, so applying it on a moved tree means
reworking those hunks.

Whatever runs, a passing case shows the scheduler attached with the expected
ops name on the expected kernel, workers running under sched_ext and making
progress, a clean detach with the sched_ext state back to disabled, and a
kernel log with no warning, stall or error. Check the positive markers, not
only an empty grep.

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

## Open questions

- Whether the per-subprog maximum is the intended accounting, or whether
  scratch that is dead before a call could be excluded, which would make
  frame boundaries kept only for stack budgeting unnecessary in general.
- Whether `__noinline` is the recommended way to shape the combined stack,
  or an attribute or libbpf convention exists for it.
- Whether a global function's memory argument could be declared read-only,
  so that a context holding kernel pointers could be shared with it instead
  of splitting the pointers out as separate arguments.
