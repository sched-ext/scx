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

The last sync, on 2026-10-05, covered main through 63f2014925f7
("scx_mitosis: Retry the other DSQ when the chosen head got away").

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
  or the removed features force them, and each is listed under "Differences
  requiring validation" with its reason.
- Source parity. Files keep mitosis's relative paths, function layout and
  identifiers wherever they let the two be compared function by function,
  down to the mitosis_ prefixes, the MitosisTopology type and the "mitosis"
  ops name. Only what holds a different thing is renamed, as the cid-valued
  fields, the DSQ helpers and the callbacks the cid form renames are.
- Scheduler state in the arena. Cells, per-cid contexts, task and cgroup
  contexts, the topology snapshot, and the idle and cell masks are arena
  memory owned by the loaded object. The native objects that remain are the
  userspace-written configuration, the sequence counters, the arena pointers
  and the cgroup allocator's ready flag in BSS, the cell mask allocator and
  its RCU state, the root cgroup kptr, the level_cells scratch of the
  configuration's cgroup walk, the read-only options, and the library's task
  and cgroup storage maps and RCU doorbell ring buffer.
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
Shards are LLC aligned, so transitions and claim contention stay local. A
scan starts at prev's shard, or at a pseudo-random shard without a usable
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

## Differences requiring validation

The builtin idle picker restored the idle bit of a cpu that was claimed and
kicked but never given a task. In nitosis a claimed but unused cid stays
busy until it next runs a task and goes idle again. Measure whether idle
cpus go unused under wakeup bursts.

Scan order within and across shards differs from the builtin picker's, so
repeated choices spread across eligible cids but in different sequences. The
distribute rotor belongs to the loaded object, where the builtin's is kernel
state. Measure the resulting distribution.

Cell masks and the cpu-to-cell reporting skip offline cpus, where mitosis
kept their bits. A configuration that names offline cpus contributes nothing
for them.

Per-cid contexts use NUMA_NO_NODE arena pages. Their placement can differ
from the percpu map's, so measure locality effects on multi-node hardware.

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
scx_arena_subprog_init() in ops.dispatch(), ops.dump(), tp_cgroup_mkdir()
and apply_cell_config(), and MITOSIS_TOUCH_ARENA() in ops.update_idle(),
give those programs the reference.

init_cgrp_ctx() is a global function, because its arena accesses verify
expensively and inlining them into tp_cgroup_mkdir()'s ancestor loop
exceeded the instruction limit. The idle pick phases are __noinline subprogs
because inlining them into every caller exceeded the combined stack limit
once LLC awareness stacked a second pick level into ops.select_cid().

The ops.init() topology walk fills each entry field by field, because clang
20 derived the destination of the aggregate copy before the arena
address-space cast and the verifier saw the stores go through a scalar.
scx_cargo refuses to build cid-form schedulers with clang before 22 unless
SCX_ALLOW_OLD_CLANG is set.

scx_mavd's stack model reads any object. On the object built from this tree
at the last sync, the deepest chain is:

    mitosis_enqueue     144 -> 144
    update_task_cell     56 ->  64
    update_task_cmask   136 -> 144
    cmask_and           112 -> 112
                               464

The left column is the deepest r10 offset in the object, the right one the
rounded frame the verifier adds. The same chain ending in set_task_llc()
instead of cmask_and() also models at 464. ops.select_cid() models at 400
through the same helpers, and ops.dispatch() at 448 through the idle pick
phases. The verifier's own stack depths and the per-program instruction
counts have not been measured. To re-measure, build scx_nitosis and run the
model from the repository root:

```sh
python3 scheds/experimental/scx_mavd/tools/stack-chains.py \
    target/debug/build/scx_nitosis-*/out/bpf.bpf.o \
    mitosis_select_cid mitosis_enqueue mitosis_dispatch
```

Then load the scheduler with the verifier log level at 4 on every program
for the verifier's stack depth and processed-instruction lines, as
"Re-measuring" in scx_mavd's CONVERSION.md describes, and record the results
here.

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
the ktstr tests and the undefok_flags.rs tests, and this file. Everything
else in that diff must be explained by a section of this file.

## Skipped mitosis commits

Each mitosis commit a sync did not port, as sha12 ("subject"), with its
reason.

None yet.

## Validation obligations

Choose affected cases and the required confidence for the change at hand.
The wider coverage inventory includes cell isolation, dynamic cell creation
and destruction, cell exclusion, borrowing, demand rebalancing, cpuset
changes, LLC awareness with draining and stealing, pinned tasks and dynamic
affinity selection, slice shrinking, SMT on and off, possible but offline
cpus, hotplug restarts, cgroup tracking with the CPU controller enabled and
disabled, and attach and detach. It is not a mandatory matrix for every
port. Record source, binary and kernel identities once per batch.

The functional drivers are mitosis's, renamed. The scripts under test/ run a
built scheduler binary, SCHEDULER_BIN, against test cgroups and need root
and cgroup v2, and test_cell_isolation.sh needs stress-ng. tests/ holds the
ktstr tests behind the ktstr-tests feature. All of them need a kernel with
the cid form of sched_ext.

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
- Restoring the idle bit of an abandoned claim, which the builtin idle
  picker did.
- Whether idle tracking should move onto the shared cid idle helpers in
  scheds/include/lib/cid_idle.h, which arrived after the conversion.
- Bringing back the subcell scheme and virtual LLCs through a cid topology
  override.
