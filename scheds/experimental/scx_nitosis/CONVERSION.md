# Maintaining scx_nitosis

scx_nitosis is scx_mitosis converted to the cid form of sched_ext, with the
scheduler's state in a BPF arena, toward a root scheduler that hosts other
schedulers as sub-schedulers, one per cell. It follows mitosis's policy and
source organization file for file. The fork baseline is 1e9d241b0716
("scx_mitosis: Make the test scripts robust on real machines"), which
d064518875fe ("scx_nitosis: Re-fork from current scx_mitosis") copied under
the new name, and the reference sources are
[scx_mitosis](../../rust/scx_mitosis). This file records the goals of the
fork, the features it removed, the representation choices, the verifier
constraints that shaped the code, and the procedure for syncing with
mitosis.

The last sync, on 2026-10-28, covered main through ba5f4dc84c1e ("Merge pull
request #3948 from sched-ext/scxcli-view").

The conversion is under validation. A successful build or source review does
not establish verifier acceptance, behavioral equivalence or performance
equivalence.

## Goals

The standing task is to track mitosis's development while keeping the
properties the conversion established. Every mitosis commit is ported or
listed under "Skipped mitosis commits", following "Syncing with mitosis",
and a port preserves all of the following.

- Policy parity. nitosis makes the same scheduling decisions as mitosis from
  the same inputs: cell assignment, the vtime accounting of the cell, LLC
  and per-cid queues, the idle pick order, borrowing, draining, stealing and
  slice shrinking. Differences exist only where the cid form, arena storage
  or the removed features force them, or where they are kept by choice, and
  each is listed under "Differences requiring validation" with its reason.
- Source parity. Files keep mitosis's relative paths, function layout and
  identifiers wherever they let the two be compared function by function,
  down to the mitosis_ prefixes, the MitosisTopology type and the "mitosis"
  ops name. Only what holds a different thing is renamed, as the cid-valued
  fields, the DSQ helpers and the callbacks the cid form renames are.
- Scheduler state in the arena. Cells, per-cid, task and cgroup contexts,
  the topology snapshot, and the idle and cell masks are arena memory of the
  loaded object. In BSS stay the userspace-written configuration, the
  sequence counters, the arena pointers, the cgroup allocator's ready flag
  and the sub_cap_busy and sub_cap_pending flags. Native elsewhere are the
  cell mask allocator and its RCU state, the root cgroup kptr, the
  configuration walk's level_cells scratch, the read-only options, and the
  library's task and cgroup storage maps and RCU doorbell ring buffer.
- The cid form. Scheduler-owned CPU fields hold cids, masks are cmasks over
  the cid space, and the kernel's cid kfuncs replace the CPU ones. Linux CPU
  IDs appear only at the boundaries listed under "CPU identities".
- Checks dropped only for the verifier. A range or NULL test that mitosis
  carries because the verifier demands it for native maps and kptrs is not
  restored around fixed arena state, and no new defensive test is added
  without a concrete failure it prevents. A test that encodes scheduling
  policy or a runtime condition stays. "Arena cleanup invariants" lists what
  was dropped and what was kept.
- Verifier limits within bounds, measured. A port that touches the pick
  paths or the scheduling callbacks re-measures the stack chains as
  described under "Verifier constraints" and records the results there.
- Validated, not assumed. Each port carries the evidence listed under
  "Validation obligations" for the cases it affects, and unmeasured cases
  are reported as such.

## Removed features

Two mitosis features were removed ahead of the conversion rather than
converted. c0207bfc7176 ("scx_nitosis: Strip the subcell scheme ahead of the
cid conversion") removed subcells: the subcell and LLC DSQ encoding, the
per-subcell scheduling state and cpumasks, two-level borrowing, and the
userspace subcell assignment. Subcell domains are defined by userspace and
have no cid-range contiguity, so the range-based cid machinery does not
apply to them. That commit's message lists the mitosis commits it reverts,
for the port back. e4789702e05b ("scx_nitosis: Drop --virt-llc") removed
virtual LLC partitioning, which rode on the userspace LLC tables that the
cid topology replaced.

Both can return through an override of the cid mapping, which restores the
userspace-driven topology they need. Until then, a mitosis change to subcell
code is ported in its cell form where it has one, and a change that exists
only for subcells or virtual LLCs is proposed for skipping.

## Arena library

build.rs links the library's arena allocator, per-task and per-cgroup
storage, bitmap, cpumask and topology objects, rbtree and atq, which
arena_init() calls, and common.bpf.c, which provides the qnodes the arena
spinlock needs. ArenaLib::setup() initializes the arenas and the library
topology after load, sizes the per-task storage for cacheline-aligned
task_ctx elements, and starts the library's BPF stream watcher and RCU
reclaim threads. arena_init() sizes the bitmap allocator from the nr_cpu_ids
rodata that main.rs sets and fails without it, and allocates the rotor of
the cmask distribute helpers.

## CPU identities

Scheduler-owned CPU fields hold cids. Locals named cpu in converted code can
hold cids too, so do not infer units from a name. The exceptions below are
Linux CPU IDs.

| Value | Units |
| --- | --- |
| task_ctx allowed and effective masks | CID |
| cpu_ctx array index and the cid in a per-cid DSQ id | CID |
| cpu_ctx.cpu | Linux CPU ID |
| Cell, borrowable, idle and idle-core mask bits | CID |
| cell_config cpumasks and borrowable cpumasks | Linux CPU ID |
| Topology snapshot entries and ranges | CID |
| LLC, core and shard indices | Kernel cid topology indices |
| Userspace cell CPU sets, cpu_to_llc and statistics | Linux CPU ID |
| Dump rows | CID, including the rows labeled CPU without LLC awareness |

apply_cell_cmasks() translates the userspace configuration cpu by cpu with
scx_bpf_cpu_to_cid() and drops cpus without topology. Userspace translates
cpu_ctx entries back through cpu_ctx.cpu when it rebuilds the cell CPU sets.
Per-cid DSQ ids encode cids, so treat a raw DSQ number as an internal
identifier.

## Topology snapshot

ops.init() snapshots the kernel's cid topology into the arena-resident
struct mitosis_topo: each cid's entry, the cid range of every LLC, shard and
core, and the shard range of every LLC. cids are dense and topology ordered,
so every unit is a contiguous range, and topology lookups become range
checks and windowed cmask scans. This replaces mitosis's userspace-fed LLC
tables, per-LLC cpumasks and cached task and LLC intersection masks, and the
LLC count comes from the snapshot instead of userspace.

Possible but offline cpus get tail cids without core, LLC or node indices.
They stay out of the LLC and core tables, of topo_cids and of every cell
mask. They do take shard slots, but ops.update_idle() never marks them idle,
so the pick scans skip them. LLC awareness requires LLC topology, and a
topology with more LLCs than MAX_LLCS fails ops.init(). 97a471eee9e7
("scx_nitosis: Raise MAX_LLCS to 64") raised that cap from mitosis's 16 to
the limit of the per-cell u64 LLC bitmaps. SMT is sampled once from the
snapshot. mitosis's smt_enabled option was never set by userspace and stayed
true.

nitosis defines no ops.cid_online() or ops.cid_offline(), so the kernel
exits the scheduler with a restart code on every hotplug transition and
main.rs loads it again. The snapshot therefore stays accurate for the
lifetime of a loaded instance.

## Arena storage

The cells array holds MAX_CELLS entries in one allocation straight from
bpf_arena_alloc_pages() in ops.init(), since it exceeds what the static
allocator serves in one request. Per-cid contexts occupy one arena array
indexed by cid, with each entry cacheline aligned because the percpu map
they replace kept each CPU's copy apart. Userspace reads that array through
the arena's user address from the pointer and count published in BSS, racing
updates the same as the percpu map reads did. The topology snapshot,
topo_cids and the per-shard idle masks are allocated the same way. None of
them is freed while the object is loaded.

## Cell masks

bpf_cpumask kptrs cannot live in the arena, so cell and borrowable masks are
cid cmasks, kept in whole-configuration generations of MAX_CELLS masks each.
apply_cell_config() builds a fresh generation, publishes it in cell_masks
with one xchg, and frees the previous one through scx_urcu behind a grace
period, so a loaded generation is complete and stays valid to the end of the
reader's RCU section. This keeps the rule of mitosis's double-buffered kptr
slots that readers see only complete masks. Two syscall programs, which the
library's RCU thread finds by name, run the reclaim.

A cell that the new configuration drops or gives no cpus reads as an empty
mask, where mitosis kept the old mask. A task in such a cell takes the
pinned path instead of riding a cell DSQ no cid serves, until the next
configuration refreshes it. The first generation, published in ops.init(),
gives every cell all cids with topology until userspace pushes the first
configuration after attach.

## Task context lifetime

task_ctx lives in the arena through the library's sdt_task allocator, so
that arena data can point at per-task state. It is RCU protected and freed
with scx_task_free_rcu() from ops.exit_task(), which covers every departure.
A failed ops.init_task() gets no ops.exit_task() and frees the ctx
synchronously, since nothing has seen it. ops.init_task() is sleepable for
the arena page mapping, and init_task_impl() takes the RCU lock itself for
the p->cpus_ptr read and the cell assignment.

Lookups of a task the caller has not pinned use the quiet __scx_task_data():
the drain path's rescue of the head of an LLC DSQ and slice shrinking's peek
at a waiter. A failed lookup there means the task is gone and is skipped
quietly, where mitosis reported an error.

## Cgroup context

cgrp_ctx lives in the arena through the library's sdt_cgroup allocator. The
cgroup storage entry holds the arena reference, and the ctx is freed from an
fentry on bpf_cgrp_storage_free(), after nothing can reference the cgroup,
so a ctx pointer stays valid as long as the cgroup pointer it came from. The
cid form renames the cgroup callbacks to ops.cpuctl_init(),
ops.cpuctl_exit() and ops.cpuctl_move().

Tracepoints attach before the struct_ops, so a cgroup mkdir can fire before
ops.init() has initialized the cgroup allocator. tp_cgroup_mkdir() skips
until cgrp_alloc_ready is set, and the ctx is then created by ops.init()'s
cgroup walk or by the first task initialized in the cgroup, inheriting the
parent's cell. ops.init() creates the root ctx before it sets the flag,
because a racing mkdir's ancestor walk needs it.

## Masks and ownership

Task affinity is two arena cmasks in task_ctx, overlaid on fixed
MAX_CPUS-capacity storage because scx_cmask ends in a flex array. allowed is
the task's affinity, and effective is allowed and the cell's mask, which the
scheduling decisions use. ops.set_cmask() copies the kernel's mask into
allowed trimmed against topo_cids, and ops.init_task() seeds allowed from
p->cpus_ptr the same way. That seed is the only p->cpus_ptr read left.

The trim removes the possible but offline cpus that p->cpus_ptr can carry,
so a pinned pick cannot land on an offline cpu's tail cid, whose DSQ nothing
dispatches. It also makes the pinned classification count only usable cpus.
A task affined to one online and some offline cpus is pinned, where mitosis
counted the offline bits, and reject_multicpu_pinning no longer fires on
affinities whose only multiplicity came from offline cpus.

A sleeping task whose cpus all went offline has an empty allowed mask until
its next wakeup rewrites the affinity. update_task_cmask() parks it
unassigned instead of failing, which would abort the scheduler when it
happens in ops.init_task(). Only ops.select_cid() can see the parked state
before the rewrite, and it returns prev_cid. An enqueue that sees it is a
bug and fails on the invalid DSQ.

## Idle tracking

The cid form has no builtin idle tracking or picking. ops.update_idle()
maintains one windowed idle cmask per topology shard, and pickers claim a
cid with a test-and-clear, the analog of scx_bpf_test_and_clear_cpu_idle().
A claimed cid that is given no task stays idle without an ops.update_idle()
transition, so ops.dispatch() sets its bit again when it dispatches nothing
and the idle task is current, as the builtin idle tracking does. Shards are
LLC aligned, so transitions and claim contention stay local.

A claim and the arrival of the claimed task are separate steps: the remote
wakeup lands later on the select path, and the deferred dispatch to the
local DSQ waits for the cid's rq lock on the enqueue path. The cid's
dispatch can run in between, find its local DSQ empty and set the bit again,
so a second picker can claim the cid and two tasks land on it, the second
waiting behind the first. The builtin idle tracking has the same window in
its pick_task_idle() re-set, so this matches mitosis rather than regressing
from it.

A scan starts at prev's shard, or at a pseudo-random shard without a usable
prev, rotates through the shards of its window, and picks within a shard
with cmask_any_and_distribute(), whose per-cid rotor mirrors
bpf_cpumask_any_and_distribute(). A claim is retried at most
IDLE_PICK_RETRIES times per shard.

With SMT, a second set of per-shard masks mirrors the builtin idle-core
tracking. A core's cid range is set when every sibling is idle and cleared
on any busy transition, racy but self-correcting. A claim clears the claimed
core's range whether or not it wins, as the builtin does. The pick order
within one window matches mitosis's: prev in a wholly idle core, an
idle-core scan, a partially idle prev, then any idle cid. An LLC-aware task
exhausts its LLC's window before the full range.

## LLC draining

The drain bits in llcs_to_drain are maintained with cmpxchg loops, which
error out if they fail to make progress. The JIT rejects the fetching OR and
AND atomics that clang emits on arena memory unless it has the lowering the
shared cmask bit helpers probe for, and these loops do not use that probe.
They return early without a write when the bit is already in the target
state, which drops the full barrier the unconditional atomics implied. The
enqueue side's queue count increment and the drainer's CAS-and-recheck are
full barriers on their own, so either the drainer sees the queued work or
the enqueuer sees the LLC without cpus, and no wakeup is lost.

## Hosting sub-schedulers

A sub-scheduler attaches to a cgroup that owns a cell and takes over exactly
that cell. ops.sub_attach() returns -EINVAL for a cgroup that owns no cell.
struct cell records the owner cgroup in owner_cgid, kept while a detaching
sub still holds the cell, and the attached sub's cgroup id in sub_cgid, 0
when none. ops.sub_attach(), ops.sub_detach() and the record phases of
apply_cell_config() write both under the arena spinlock cells_lock, and the
owner changes only while sub_cgid is zero. Readers load the one word and
take no lock.

The sub holds SCX_CAP_ENQ, SCX_CAP_PREEMPT, SCX_CAP_PERF and
SCX_CAP_ENQ_IMMED on the cell's primary cids, and SCX_CAP_ENQ_IMMED alone on
its borrowable cids with --enable-borrowing. sub_cap_sync() brings every
delegated cell's caps in line with the published cell masks, as deltas
against scx_bpf_sub_caps(), every revoke before any grant so that no moving
cid is held with SCX_CAP_ENQ by two subs.

apply_cell_config() and ops.sub_attach() both call sub_cap_sync() and the
kernel does not serialize them, so the sub_cap_busy and sub_cap_pending
flags keep the pass to one runner without losing a request. The pass makes
up to eight kfunc calls per delegated cell, two caps queries and up to two
grants or revokes per half, and none without subs. It runs outside
cells_lock.

The kernel drops a sub's caps when it detaches, and ops.sub_detach() clears
sub_cgid, which hands the cell back to the cell manager. Userspace keeps a
destroyed cgroup's cell id in CellManager's detaching_cells until it sees
sub_cgid clear, and the release triggers an apply that clears the owner.

ops.dispatch() on a delegated cid serves the root's own queues first,
because the per-cid DSQ holds tasks that can run nowhere else and a task on
its way into the sub stays the root's until the kernel re-homes it. It then
offers the cid to the sub with scx_bpf_sub_dispatch(), and it skips the
sibling-LLC steal. The root always sets SCX_OPS_TID_TO_TASK, because the
kernel rejects a sub that sets it unless the root has it too.

A sub's tasks never pass through ops.stopping(), so
ops.sub_cid_sched_updated() charges a delegated cell's cpu time per cid, in
sub_ns under the per-cid sub_lock, and the sub_charge_cids() syscall program
charges every open interval before each userspace sample, taking every cid's
sub_lock with irqsave. The clock it uses is listed under "Differences
requiring validation".

sub_q_pct and the Sub column of the per-cell dispatch breakdown, next to
Local, CPU, Cell and Borrow, are the share of the cell's queue decisions
that were dispatches handed to a sub, counted by CSTAT_SUB_DISPATCH. The
denominator is every queue decision, mostly enqueue placements.

With sub_cgid 0 everywhere the delegation changes no scheduling decision.
Its cost without a sub is unmeasured. The kernel calls
ops.sub_cid_sched_updated() on every switch of a cid between a root task and
idle or another class, because the root implements the op and the kernel
notifies on every change of the cid's scheduler, and each call takes the
cid's sub_lock. sub_charge_cids() takes every cid's sub_lock with irqsave
before each sample, every apply runs sub_cap_sync()'s scan over MAX_CELLS
cells, and SCX_OPS_TID_TO_TASK is set.

The delegated cells' accounting is to be reworked to cut its cost, together
with the clock mix under "Differences requiring validation".

Every load, hosting or not, needs a kernel with ops.sub_cid_sched_updated(),
the requirement the README states. The op is always set, and the loader
clears only sub_attach and sub_detach on an older kernel.

## Differences requiring validation

A scan starts at prev's shard when prev is in the window. Shards are LLC
aligned, so even with LLC awareness off a scan prefers idle cids in prev's
LLC. mitosis calls the builtin scx_bpf_pick_idle_cpu(), which scans the
whole mask from a rotor after mitosis's own prev test. nitosis keeps the
prev-shard start by choice.

The sequences differ beyond that. cid order is not cpu order, the per-cid
rotor of cmask_any_and_distribute() picks within a shard, and the builtin's
rotor is kernel state while nitosis's belongs to the loaded object. A claim
is retried at most IDLE_PICK_RETRIES times per shard, the bound of the BPF
loop, where the builtin retries until the set is empty. Measure the
resulting distribution.

Borrowed placements are inserted with SCX_ENQ_IMMED, since 259b14637e74
("scx_nitosis: Insert borrowed placements with SCX_ENQ_IMMED"), where
mitosis inserts them with no flags. A sub holds only SCX_CAP_ENQ_IMMED on
its cell's borrowable cids, so the root's own cells borrow under the same
idle-only rule. A borrowed task that misses the idle window goes back
through enqueue to be placed again, where in mitosis it waits on the
borrowed cid's local DSQ. CSTAT_BORROW_BOUNCE, the Bounce column and
borrow_bounce_pct count the bounces.

Cell masks skip offline cpus, where mitosis kept their bits. CellManager
assigns only topology.span, so no configuration names an offline cpu. Tail
cids keep cpu_ctx.cell 0, as mitosis's per-cpu map does, and the cpu-to-cell
reporting comes out the same.

MAX_LLCS is 64, where mitosis's is 16. mitosis's topology.rs refuses to
start on a machine with more than 16 LLCs, LLC awareness or not. nitosis
runs there, and ops.init() fails beyond 64. On 16 LLCs or fewer the behavior
is the same.

Per-cid contexts use NUMA_NO_NODE arena pages. Their placement can differ
from the percpu map's, so measure locality effects on multi-node hardware.

running_ns comes from scx_clock_task(), which leaves out IRQ and steal time.
A delegated cell's sub_ns, charged by ops.sub_cid_sched_updated() and by the
sub_charge_cids() syscall program, stays on scx_bpf_now(). scx_clock_task()
reads the rq clock and needs the cid's rq lock, which sub_charge_cids() does
not hold when it charges every cid remotely. The cell's utilization
therefore adds a clock that counts IRQ and steal time to one that leaves
them out. It is to be fixed together with the sub accounting.

## Arena cleanup invariants

The cells array and the per-cid contexts are indexed directly. mitosis's
lookup_cell() range check and cstat_add()'s MEMBER_VPTR() are gone: every
cell index is bounded by MAX_CELLS by construction and every cid by the
snapshot. An out-of-range arena access does not return NULL. One that
reaches an unmapped page is reported on the program's stream, and the
library's stream watcher exits the scheduler on it. One that stays inside
mapped arena memory silently hits the neighboring allocation. The
abort-on-bad-index reports went with the checks.

Checks on values from userspace or the kernel stay: the DSQ id constructors'
range tests, the cell_config decode through MEMBER_VPTR(), the num_cells and
assignment count bounds in apply_cell_config(), and the task and cgroup ctx
lookups. When importing a mitosis change, do not restore native-map checks
around fixed arena state, and do not remove policy checks merely because
arena faults are recoverable.

## Loops

Most scans are still bpf_for(). f0afcfd10238 ("scx_nitosis: avoid aggregate
copy into arena CID topology") converted the topology walk in ops.init() to
bpf_arena_for(), and the shared cmask helpers use it internally. The
remaining scans have not been converted, see "Open items".

## Verifier constraints

A program that only dereferences arena pointers handed to it never loads the
arena map and is rejected at the first address-space cast.
MITOSIS_TOUCH_ARENA() at the top of every such program gives it the
reference.

init_cgrp_ctx() is a global function, because its arena accesses verify
expensively and inlining them into tp_cgroup_mkdir()'s ancestor loop
exceeded the instruction limit. The idle pick phases are __noinline subprogs
because inlining them into every caller exceeded the combined stack limit
once LLC awareness stacked a second pick level into ops.select_cid().
sub_cap_sync_cell() is one too, so that the two halves of the cap pass share
a single copy of its cmask bodies.

The ops.init() topology walk fills each entry field by field, because clang
20 derived the destination of the aggregate copy before the arena
address-space cast and the verifier saw the stores go through a scalar.
scx_cargo refuses to build cid-form schedulers with clang before 22 unless
SCX_ALLOW_OLD_CLANG is set.

scx_mavd's stack model reads any object. On the object built from this tree,
the deepest chain is:

    mitosis_enqueue       144
    update_task_cell       64
    update_task_cmask     144
    cmask_and             112
                          464

Each number is the rounded frame the verifier adds for the subprog. The same
chain ending in set_task_llc() instead of cmask_and() also models at 464.
ops.select_cid() models at 400 through the same helpers from a frame of 80,
and ops.dispatch() at 480, its frame of 304 over pick_idle_cid_cores() at
176.

The verifier's own stack depths and per-program instruction counts below are
from the SCX_ARENA_SCALAR object and have not been re-taken on the object
built with the __arena tags. They were measured on 2026-10-28 on sched_ext
for-next a96c41fea8da (7.3.0-rc5, lockdep) in a vng VM with 16 cpus as 8
cores x 2 threads, a debug build, every program loaded at verifier log level
4.

One run used the default options and one every BPF rodata option:
--enable-llc-awareness, --enable-borrowing, --enable-slice-shrinking,
--dynamic-affinity-cpu-selection, --use-lockless-peek and
--reject-multicpu-pinning, with exiting-task-workaround on by default in
both. Processed instructions, with the verifier's stack depth in
parentheses:

    select_cid   27,229 (368)   79,358 (368)
    enqueue      27,123 (416)  123,149 (416)
    dispatch      1,047 (176)   32,833 (272)
    running         111 (80)     1,692 (160)
    init_task    32,063 (336)   34,351 (336)
    init         56,404 (336)   56,184 (336)

The BPF options are rodata, so the verifier prunes the disabled paths and
the default counts are the lower ones, except for init, whose default count
is not lower than the all-on one. The verifier's stack depths sat at or
under that object's model, dispatch at 272 against its modeled 432, because
the model is an upper bound.

To re-measure, build scx_nitosis and run the model from the repository root:

```sh
python3 scheds/experimental/scx_mavd/tools/stack-chains.py \
    target/debug/build/scx_nitosis-*/out/bpf.bpf.o \
    mitosis_select_cid mitosis_enqueue mitosis_dispatch
```

Then set the verifier log level to 4 on every program, set_log_level(4) on
each program of the opened skeleton in main.rs, and run the scheduler with
--log-level trace. libbpf prints each program's verifier log, which gives
"stack depth max N", then one line per subprog, and ends with "processed N
insns". Record the results here.

## Known issues

tp_cgroup_mkdir() reads cgrp_alloc_ready with READ_ONCE() and ops.init()
sets it with WRITE_ONCE() before its cgroup walk, with no barrier on either
side. A mkdir that links its cgroup and then reads the flag, racing an init
that sets the flag and then walks, is a store-buffering pattern: on any CPU
that lets a load pass an earlier store, x86 included, both sides could miss
the new cgroup, which would then have no ctx and make a later task move
into it fail in update_task_cell(). This is memory-model reasoning, not an
observed failure, and the gate predates the conversion. The port of
929f6c3708d8 ("scx_mitosis: Always use tracepoints for cgroup tracking")
makes it apply to every load.

Since the port of 37905edcf7e3 ("scx_mitosis: Charge running time when
dispatch extends a solo task's slice"), ops.dispatch() charges the
dispatched cid's context and ops.running() and ops.stopping() the task's
cid. Under core scheduling, where dispatch runs for an SMT sibling, and
under a remote sched_change, where stopping() and running() run from another
cpu, a cid's cstats are incremented from another cpu while the cid's own
ops.select_cid() and ops.enqueue() increment them through cur_cpu_ctx()
without its rq lock.

cstat_add() is a plain +=, so increments can be lost. This affects
statistics only, and mitosis has had the same race since 37905edcf7e3.

## Syncing with mitosis

nitosis follows mitosis commit by commit. The top of this file records the
last sync: its date and the main commit it covered, LAST in the commands
below. A sync first brings main up to upstream and works on a branch from
it. List the commits since LAST that touch mitosis or the shared code both
schedulers build on, oldest first:

```sh
git log --reverse --no-merges --abbrev=12 --format='%h %s' LAST..main -- \
    scheds/rust/scx_mitosis scheds/experimental/scx_nitosis lib \
    scheds/include rust/scx_utils rust/scx_cargo rust/scx_arena \
    rust/scx_stats
```

Handle each listed commit as follows.

- Changes to shared files that nitosis builds reach it through the shared
  tree. Read them for changes to anything this file documents, such as build
  flags, library helpers or the measurement environment, and update the
  affected section. A change to a shared file that only mitosis builds is
  handled like a mitosis change.
- A mitosis change that the same commit also made to nitosis, as a
  dependency bump does, is already ported. So is one that an earlier nitosis
  commit already carries, which the record commit's message names.
- A mitosis change that does not apply to nitosis, such as one to code the
  cid form replaced or to a removed feature, is proposed for skipping. Once
  the maintainer confirms the skip, list it under "Skipped mitosis commits"
  as sha12 ("subject") with the reason.
- A commit made straight to nitosis is read for what it changes in this
  file, and its sections are updated.
- Every other mitosis change is ported as below.

Before porting anything, present the plan: every listed commit, how it will
be handled, and for each proposed skip what the commit does and why it
should not be ported. Port only after the maintainer confirms the plan. No
commit is skipped without that confirmation.

git cherry-pick cannot port a commit here. nitosis is a copy of mitosis
rather than a rename, so the pick would apply to mitosis's files again.
Apply the mitosis part of the commit to nitosis with a three-way fallback
instead. The touched nitosis files must be clean, and the result is staged.
Where the change touches code the conversion rewrote, it leaves conflict
markers between nitosis's code and mitosis's result:

```sh
git show --format= SHA -- scheds/rust/scx_mitosis | \
    git apply -3 -p4 --directory=scheds/experimental/scx_nitosis
```

Resolve the conflicts and translate the change to the cid form and arena
storage.

1. Compare corresponding files and functions before translating identifiers.
2. Identify every input, output, index, mask and helper's units. Keep policy
   thresholds, equations, accounting updates, branch order and options
   unless an API constraint requires a documented difference.
3. Apply storage and API translation at the existing boundaries. Check
   callback ownership, task and cgroup ctx lifetime, the allowed and
   effective masks and the cell mask generations before choosing an arena
   pointer. Keep policy changes separate from representation cleanup.
4. Review each port against the tree before it, including all changed
   callers, callback contracts, CPU units, masks, options and reporting
   fields. Inspect generated BPF code for large copies and variable indices.
   The compiler has previously miscompiled a large aligned copy in this
   work. Source-level memcpy equivalence is insufficient.
5. Build both schedulers, load nitosis when a kernel with the cid form is at
   hand, and re-measure the stack chains and instruction counts when the
   pick paths or the callbacks changed. Add every new branch or interface to
   the coverage inventory under "Validation obligations". Record any
   divergence with its reason, evidence, expected effect and a test that
   exercises it. Do not treat an untested difference as equivalent.

Commit each port with mitosis's author, date and message, the subject's
scx_mitosis prefix replaced by scx_nitosis. The sed below handles only a
leading "scx_mitosis:". Edit other subject forms by hand.

```sh
git log -1 --format=%B SHA | sed '1s/^scx_mitosis:/scx_nitosis:/' > MSG
# append the cherry-pick line and the port notes to MSG
git commit --author="$(git log -1 --format='%an <%ae>' SHA)" \
    --date="$(git log -1 --format=%aD SHA)" -F MSG
```

After mitosis's message come the line git cherry-pick -x writes, "(cherry
picked from commit FULL_SHA)", where FULL_SHA is the originating mitosis
commit on main, and then the port notes. The line makes every ported commit
point to the mitosis commit it came from. The notes cover every conflict and
how it was resolved, every modification the conversion required with its
reason, and the build, review and functional evidence. A port that applied
cleanly and needed no modification says so. A port that changes something
this file documents updates that section in the same commit.

After the last port, build both schedulers, load nitosis when a kernel with
the cid form is at hand, and run the fork check below. Then record the sync
in one commit to this file: the new date and main commit at the top, every
skipped commit, and the sections the shared commits affect. The record
commit's message also names each mitosis commit an earlier nitosis commit
already carries. A sync that finds nothing to port still records itself.

To confirm the fork is still mitosis plus the conversion, extract mitosis
from the sync branch, whose mitosis matches the main commit it covers, and
diff it against nitosis:

```sh
M=$(mktemp -d)
git archive HEAD scheds/rust/scx_mitosis | tar -x -C $M
diff -r --no-dereference $M/scheds/rust/scx_mitosis \
    scheds/experimental/scx_nitosis
```

Beyond the conversion and the removed features, the differences are the
crate name, the description, the scx_arena dependency and the veristat
opt-out in Cargo.toml, the README, build.rs linking the arena library, the
src/bpf/lib symlink, the scheduler name in main.rs and in the test scripts,
the ktstr tests and the undefok_flags.rs tests, this file, and mitosis's
config mode, config.rs with CellSource, --cell-config and
--reconfiguration-interval-s, which "Skipped mitosis commits" covers.
Everything else in that diff must be explained by a section of this file.

## Skipped mitosis commits

Each mitosis commit a sync did not port, as sha12 ("subject"), with its
reason.

The sync of 2026-10-28 skipped twelve commits that change only the subcell
scheme, which "Removed features" covers, and seven that add the cell config
mode. The maintainer decided to skip config mode. It mainly carries subcell
layouts, and its pattern-based cell selection, which is cell level, is
deferred until it can return with subcells through the cid topology
override.

Subcell only:

- 0eff90309443 ("scx_mitosis: Hoist subcell assignment out of the cell
  manager borrows"): moves only the subcell step out of the cell manager
  borrow. nitosis's blocks already return just the cell and CPU assignments.
- 4cca986266c3 ("scx_mitosis: Pre-create DSQs for every subcell slot from
  init"): subcell DSQs. nitosis already creates every cell and LLC DSQ in
  init.
- 4e0d30a2d1d2 ("scx_mitosis: Always share idle CPUs among sibling
  subcells"): the sibling-subcell idle step and the subcell borrowable
  masks, a no-op with one subcell per cell.
- 50d881b411d2 ("scx_mitosis: Share a cell smaller than its subcell count"):
  the subcell split only.
- 76c0eff7b39f ("scx_mitosis: Plumb subcell match rules through to BPF"):
  subcell match rules.
- 5a831d79da59 ("scx_mitosis: Match tasks into configured subcells"):
  subcell comm matching.
- 9b89bf9211fc ("scx_mitosis: Tag CPUs with their subcell when applying
  configured subcells"): nitosis has no apply_configured_cell_subcells(),
  and the cell-level vtime advance on a retag is already in it.
- 101a57f15fc4 ("scx_mitosis: Account running and queued time per subcell"):
  per-subcell accounting slots, read only by the subcell stats and weights.
- 2837168fbb58 ("scx_mitosis: Estimate each task's CPU demand per subcell"):
  per-task demand charged to subcell slots only.
- 56c52ab98ef1 ("scx_mitosis: Export per-subcell demand stats"):
  SubcellMetrics only.
- 2c1c39e9fa5f ("scx_mitosis: Weight subcell partitions by demand"): subcell
  split weights only.
- 3e41326dd28c ("scx_mitosis: Allocate subcells in LLC chunks"): called only
  from the subcell split.

The cell config mode:

- 90d2af23d31a ("scx_mitosis: Factor out the requested-minimum displacement
  check")
- e41f0a58f323 ("scx_mitosis: Add cell manager helpers for externally
  resolved cells")
- 31342deb513f ("scx_mitosis: Wrap the cell manager in a CellSource enum")
- 5dc0ae77f511 ("scx_mitosis: Add the cell config parser")
- f15afcaaa50f ("scx_mitosis: Resolve configured cells from the cgroup
  tree")
- f0bf0e15866e ("scx_mitosis: Skip cgroups that vanish during the cell
  resolve walk")
- 67c8aa0557f2 ("scx_mitosis: Add --cell-config mode")

## Validation obligations

Every update to nitosis tests the sub-scheduler scenarios below. They are
the main thing to test and come before the root-only suites.

nitosis runs as the root with its cells under a parent cgroup and with
--enable-borrowing, so that the IMMED-only grants on borrowable cids are
exercised. A sub attaches to a cell's cgroup by path, `--cgroup PATH` for
scx_mavd, the sub used so far, and any sub that attaches with a cgroup path
works. The kernel needs the sub-scheduler interface, CONFIG_EXT_SUB_SCHED,
and lockdep, since most sub-scheduler bugs show up as lockdep reports.

- An attach to a cgroup that owns no cell is refused. The kernel reports the
  sub disabled with "parent rejected (-22)".
- An attach to a cell, then load inside the delegated cell, in another cell
  and in the root cell. nitosis's stats show the delegated cell's dispatches
  going to the sub, sub_q_pct 100 for that cell.
- Cell churn with a sub attached: a new cell under load.
- A detach under load, with the cell returning to nitosis, and a reattach
  under load.
- Two subs at once on two cells.
- A cell's cgroup removed under its attached sub. The kernel unregisters the
  sub, and a later new cell reuses the id only after that.
- The root exiting under attached subs. Each sub exits with "parent exiting"
  and sched_ext ends disabled.

A passing sub scenario shows each sub's attach and exit reason in the kernel
log, the expected per-cell sub_q_pct, progress in every workload, the
surviving subs still running after another sub or cell goes away, and a
kernel log with no warning, lockdep report or stall.

Choose affected cases and the required confidence for the change at hand.
The root-only coverage inventory includes cell isolation, dynamic cell
creation and destruction, cell exclusion, borrowing, demand rebalancing,
cpuset changes, LLC awareness with draining and stealing, pinned tasks and
dynamic affinity selection, slice shrinking, SMT on and off, possible but
offline cpus, hotplug restarts, cgroup tracking with the CPU controller
enabled and disabled, and attach and detach. It is not a mandatory matrix
for every port. Record source, binary and kernel identities once per batch.

The functional drivers are mitosis's, renamed, and they cover root mode
only. The scripts under test/ run a built scheduler binary, SCHEDULER_BIN,
against test cgroups and need root and cgroup v2, and test_cell_isolation.sh
needs stress-ng. tests/ holds the ktstr tests behind the ktstr-tests
feature. All of them need a kernel with the cid form of sched_ext. The tree
has no driver for the sub scenarios yet.

Whatever runs, a passing case shows the scheduler attached on the expected
kernel, workers running under sched_ext and making progress, a clean detach
with the sched_ext state back to disabled, and a kernel log with no warning,
stall or error. Check the positive markers, not only an empty grep.

Use a separate debug kernel for functional and stress tests. Run all
performance measurements on bare metal, with both schedulers on the same
separately built performance kernel with lockdep, KASAN, KCSAN and expensive
memory debugging disabled. Audit the resolved configuration and verify the
running kernel and boot options. Report inconclusive results and unmeasured
cases explicitly. VM validation does not establish performance on bare
metal.

## Open items

- Converting the remaining bpf_for() scans to bpf_arena_for(), as the other
  cid-form code does.
- Whether the drain-bit loops should take the fetching atomics when the
  loader's probe finds the JIT lowers them, as the shared cmask bit helpers
  do.
- Whether idle tracking should move onto the shared cid idle helpers in
  scheds/include/lib/cid_idle.h, which arrived after the conversion.
- Bringing back the subcell scheme and virtual LLCs through a cid topology
  override.
