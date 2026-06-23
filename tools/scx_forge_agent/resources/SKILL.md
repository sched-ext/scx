---
name: scx-sched-policy
description: Modify a sched_ext Rust+BPF scheduler crate (under scheds/rust/<name>) in place. Use when AI agents need to customize, tune, validate, or iterate on a scx scheduler, including BPF policy callbacks, Rust control-plane setup, topology and DSQ maps, stats, and CLI options.
---

# scx_ext Scheduler Policy

Modify the target scheduler crate (the `scheds/rust/<name>` crate named by the
spec's `[scheduler].package`) directly to implement and tune sched_ext
scheduling policy. Edit the existing crate in place rather than copying it to a
new scheduler; treat the current policy as a scaffold to evolve, not as
production policy to preserve unchanged. You are told which scheduler you operate
on; read that crate's files before editing.

## Start Here

Read these files in the target crate before editing:

- `README.md`: scheduler purpose, user-facing options, and current policy summary.
- `Cargo.toml`: package name, dependencies, and workspace-facing metadata.
- `src/main.rs`: Rust control plane, CLI options, topology setup, BPF rodata/map
  initialization, struct_ops attach, stats server, and shutdown handling.
- `src/bpf/main.bpf.c`: core sched_ext policy and BPF maps.
- `src/bpf/intf.h`: C structs/constants shared with Rust through generated bindings.
- `src/stats.rs`: stats schema, formatting, JSON export, and monitor loop.
- `build.rs`: BPF skeleton and interface generation through `scx_cargo::BpfBuilder`.
- `https://www.kernel.org/doc/Documentation/scheduler/sched-ext.rst`: upstream
  sched_ext semantics, especially Dispatch Queues, Scheduling Cycle, task
  custody / `dequeue`, Task Lifecycle, status events, module parameters, and ABI
  instability.

(Some schedulers add extra modules or BPF files - e.g. a `tuner.rs`,
`load_balance.rs`, or supplementary `*.bpf.c` - so list the crate's `src/` and
`src/bpf/` directories and read whatever the policy actually uses.)

## Plan Phase

Before editing, turn the user's spec into a concrete plan:

- Restate the scheduling goal in one or two sentences (what should be optimized
  or guaranteed, and for which kind of workload).
- Read the scheduler's BPF callbacks (`select_cpu`, `enqueue`, `dispatch`,
  `running/stopping`, etc.) and identify the helper functions they delegate to, as
  these define the scheduler's policy seams. Map the goal to the specific seams
  it touches (queue ordering, wakeup placement, time-slice / charging, dispatch
  pull domains). Prefer preserving callback lifecycle semantics, but do not
  limit yourself to a numeric tweak when the objective calls for a larger
  scheduling change. A coherent redesign may touch multiple helpers, maps, and
  Rust-populated knobs if they implement one policy idea.
- If the spec defines "good" as a measurable number, capture that as a
  validation spec up front (see "Iterate To A Metric") so the same definition
  drives every iteration.

## Customize The Scheduler In Place

Work directly in the target crate; do not copy it to a new crate or rename the
package, the binary, or its `struct_ops` symbols. The crate already builds and
attaches, so keep the scaffolding intact and change only the policy:

1. Keep the package name, the binary name, the scheduler-name constant in
   `src/main.rs`, the `SCX_OPS_DEFINE(<ops>, ...)` `struct_ops` symbol, the
   callback function names, the `scx_ops_open!`/`scx_ops_load!`/`scx_ops_attach!`
   macro uses, and the `.name = "..."` ops name unchanged - whatever they are
   for this scheduler - so existing tooling, sysfs paths, stats, and the
   validation harness keep working. Discover these identifiers by reading
   `src/main.rs` and `src/bpf/main.bpf.c`; do not assume names from another
   scheduler.
2. Leave `build.rs` and its relative paths to `rust/scx_cargo` unchanged; the
   crate stays in its existing directory.
3. Make policy changes in `src/bpf/main.bpf.c` (and the matching Rust knobs),
   keeping each change focused on one coherent policy idea and the crate
   buildable. That idea may span multiple seams, such as queue ordering plus
   dispatch pull domains, or idle-CPU selection plus topology state.

## sched_ext Semantics

Only `ops.name` is mandatory in `struct sched_ext_ops`; other callbacks are
optional, but preserve the callbacks needed by the scheduler's state machine.
Use the current lifecycle model from
`https://www.kernel.org/doc/Documentation/scheduler/sched-ext.rst` when
deciding which callback owns each piece of policy state:

1. `init_task` runs when a task is created and can allocate task-local state.
2. `enable` admits the task into BPF scheduling and should initialize
   scheduler-visible task state such as `dsq_vtime`.
3. While the task remains in `SCHED_EXT`, wakeups for migratable tasks may call
   `select_cpu` first. `ops.select_cpu()` is not invoked for migration-disabled
   tasks (`is_migration_disabled(p)`) or per-CPU tasks
   (`p->nr_cpus_allowed == 1`); those paths reach `enqueue` without CPU
   selection. Treat the selected CPU as an optimization hint and idle-wakeup
   mechanism, not as a binding placement decision; the core ignores unusable CPU
   selections and may pick a fallback.
4. `runnable` runs when the task becomes ready to run (task wakeup).
5. While runnable, a task that is not in a DSQ can be passed to `enqueue`, which
   can insert it into a DSQ or keep it queued using BPF data structures.
6. Property changes can occur while a task is queued or running. If a queued
   task is in BPF scheduler custody, the core calls `dequeue`, then `quiescent`,
   then the relevant property callback, then `runnable` again.
7. When a CPU needs work, it consumes its local DSQ first, then the global DSQ,
   then calls `dispatch` so the scheduler can move or insert work into the local
   DSQ.
8. If a task leaves BPF custody through dispatch to a terminal DSQ, `dequeue` is
   called. If it was direct-dispatched to a local DSQ from `enqueue`, `dispatch`
   and `dequeue` are skipped.
9. `running` runs when the task starts executing on its assigned CPU.
10. While the task remains runnable and has slice left, `tick` may run every
    `1/HZ` seconds. If the slice reaches zero, `dispatch` may refill
    `task->scx.slice`.
11. `stopping` runs when the task stops using the CPU because its slice expires,
    it waits, it is preempted by a higher-priority scheduling class, or another
    transition removes it from the CPU.
12. `quiescent` runs when the task releases its CPU and is no longer runnable.
13. `disable` removes the task from BPF scheduling, and `exit_task` runs when
    the task is destroyed.

Identify which callbacks the target scheduler implements by reading
`src/bpf/main.bpf.c` and its `SCX_OPS_DEFINE(...)` block. Add callbacks such as
`tick`, `exit_task`, or additional property callbacks only when the scheduler
gains state that must be updated at those lifecycle points. If the scheduler
creates user DSQs, tasks inserted there enter BPF custody and need `dequeue`
accounting when they leave those DSQs.

Task custody rules:

- A task enters BPF scheduler custody when it is dispatched to a user-created
  DSQ or stored in BPF scheduler data structures. This normally happens from
  `enqueue`.

- Dispatching to a user DSQ from `select_cpu` has the same custody effect as
  dispatching from `enqueue`, but storing tasks in BPF-internal structures from
  `select_cpu` is discouraged and does not suppress `enqueue`.

- Dispatching to terminal DSQs, meaning `SCX_DSQ_LOCAL`,
  `SCX_DSQ_LOCAL_ON | cpu`, or `SCX_DSQ_GLOBAL`, does not put the task in BPF
  custody and does not trigger `dequeue`.

- When a task leaves BPF custody, `dequeue` is called exactly once. Regular
  dispatch to a terminal DSQ has no special flag; core-sched execution uses
  `SCX_DEQ_CORE_SCHED_EXEC`; scheduling property changes use
  `SCX_DEQ_SCHED_CHANGE`.

- `enqueue` can be called multiple times without an intervening `dequeue`, for
  example around `scx_bpf_dsq_reenq()`, while the task remains in custody.

- After a task has left BPF custody, later property changes do not trigger
  `dequeue` for that queued instance.

DSQ rules to preserve:

- A CPU always executes from its local DSQ. Non-local work must be moved or
  inserted into the target local DSQ before it runs.

- Do not rely on `select_cpu` for pinned work: migration-disabled tasks and
  per-CPU tasks skip `ops.select_cpu()`, so their placement and direct-dispatch
  handling must be done in `enqueue`.

- A common, safe pattern is to keep `select_cpu` as a pure wakeup placement
  hint: it returns a CPU and does not necessarily insert the task into a DSQ, so
  all tasks stay visible to `enqueue()` before any direct placement
  optimization. Check whether the target scheduler follows this pattern before
  relying on it.

- `select_cpu` may directly insert with `scx_bpf_dsq_insert()` or
  `scx_bpf_dsq_insert_vtime()` only when the scheduler explicitly chooses that
  fast path. If the target is `SCX_DSQ_LOCAL`, insertion skips `enqueue` and
  resolves to the local DSQ of the CPU returned by `select_cpu`. Dispatching to a
  user-created DSQ from `select_cpu` has custody semantics; storing tasks in
  BPF-internal structures from `select_cpu` does not suppress `enqueue` and is
  discouraged. When using this fast path, document why tasks that skip
  `select_cpu()` cannot be starved.

- `enqueue` may insert into `SCX_DSQ_GLOBAL`, `SCX_DSQ_LOCAL`,
  `SCX_DSQ_LOCAL_ON | cpu`, or a custom DSQ ID below `2^63`; alternatively, it
  may retain the task in BPF-managed queues for later dispatch. Tasks inserted
  to `SCX_DSQ_LOCAL` or `SCX_DSQ_LOCAL_ON | cpu` are processed before tasks
  inserted into `SCX_DSQ_GLOBAL`, which are processed before tasks in
  BPF-managed DSQs. Tasks in `SCX_DSQ_GLOBAL` can be consumed by any CPU. When
  creating custom user DSQs, keep IDs small and above the CPU-ID range: use IDs
  greater than `MAX_CPUS`, not high-bit or very large values, because built-in
  DSQs use reserved high-bit encodings.

- A scheduler's DSQ topology is a policy choice: read the BPF file to learn it.
  For example, a scheduler may create one user DSQ per possible CPU (using the
  CPU ID as the DSQ ID) and have `dispatch()` scan those per-CPU DSQs, stealing
  an eligible task from another CPU's DSQ when the task's affinity allows it.
  Others use a single shared DSQ, per-LLC DSQs, or per-domain DSQs - match the
  policy you are editing.

- DSQs work in a push/pop fahion: `enqueue()` is the push side for tasks that
  should be selected later, it inserts tasks into the chosen DSQ with the queue
  ordering key; `dispatch` is the pop side: it consumes tasks from a DSQ with
  `scx_bpf_dsq_move_to_local()`. The core calls `dispatch` when a CPU becomes
  available for more work, for example after the current task blocks, yields,
  exits, or exhausts its assigned time slice. Because dispatch runs at this
  CPU-available boundary, it is also the natural place to perform load balancing
  by pulling from local, sibling, LLC, node, domain, or shared DSQs according to
  the policy. If an experiment switches from per-CPU DSQs to per-LLC, per-node,
  per-domain, or shared DSQs, update both `enqueue` and `dispatch` in the same
  edit so DSQ IDs, ordering semantics, dispatch pull domains, and affinity
  checks match.

- Inserting a task into a terminal local DSQ with `SCX_DSQ_LOCAL` or
  `SCX_DSQ_LOCAL_ON | cpu` makes the core implicitly wake the resolved target
  CPU. Do not also call `scx_bpf_kick_cpu()` for the same placement; that is a
  redundant kick. Use explicit kicks when the task is left in a user-created DSQ
  or BPF-owned queue that the target CPU might not otherwise observe, or when
  the policy intentionally wants a preemption/idle kick that terminal local-DSQ
  insertion does not cover. For idle-only nudges, `SCX_KICK_IDLE` is normally the
  right flag.

- `dispatch` should populate the dispatching CPU's local DSQ: use
  `scx_bpf_dsq_move_to_local(dsq_id, 0)` to move the first task from `dsq_id`
  to the CPU's local DSQ.

- In `dispatch`, `scx_bpf_dsq_insert()` schedules insertions rather than
  performing them immediately, with up to `ops.dispatch_max_batch` pending
  tasks. `scx_bpf_dsq_move_to_local()` flushes pending insertions before
  attempting the move.

- Use `scx_bpf_dsq_insert()` for FIFO insertion. Use
  `scx_bpf_dsq_insert_vtime()` for priority-queue ordering. Built-in DSQs such
  as `SCX_DSQ_LOCAL` and `SCX_DSQ_GLOBAL` do not support vtime insertion.

- `scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags)` internally
  updates `p->scx.dsq_vtime` to the `vtime` argument and `p->scx.slice` to the
  `slice` argument. If policy also needs an accumulated vruntime separate from
  the queue key, keep it in task-local state instead of assuming
  `p->scx.dsq_vtime` still contains the old value.

- `scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags)` internally updates
  `p->scx.slice` to the `slice` argument.

- If all tasks are immediately inserted into built-in DSQs from `select_cpu` or
  `enqueue`, `dispatch` can often remain simple because the core drains
  local/global DSQs automatically.

sched_ext can be unloaded, or aborted automatically on internal errors or
runnable-task stalls; tasks then revert to the fair class.

## Implement Policy

Make policy changes primarily in `src/bpf/main.bpf.c`:

- `select_cpu`: implement wakeup placement hints and, when there is a clear
  reason, terminal-DSQ direct-dispatch fast paths such as dispatching immediately
  to an idle CPU. Preserve affinity checks with `p->cpus_ptr`. Remember that
  this callback is skipped for migration-disabled tasks
  (`is_migration_disabled(p)`) and per-CPU tasks (`p->nr_cpus_allowed == 1`), so
  put required handling for those tasks in `enqueue`. Do not implement global
  queueing or global selection policy here.
- `enqueue`: admit every runnable task that reaches BPF. Reuse the scheduler's
  own helpers - a direct-dispatch fast path as an idle-CPU optimization, and its
  DSQ-selection / queue-ordering helpers for tasks that should be selected from
  `dispatch()`. When `enqueue()` directly inserts into a terminal local DSQ,
  rely on the core's implicit target-CPU wakeup instead of calling
  `scx_bpf_kick_cpu()` for the same task. For user DSQs, keep this insertion
  path paired with the matching consumption path in `dispatch()`; changing only
  one side of the push/pop pair can leave runnable tasks stranded in queues that
  dispatch no longer reads.
- `dispatch`: implement the primary selection decision. A CPU should pull from
  the scheduler's chosen source DSQ with `scx_bpf_dsq_move_to_local(dsq_id, 0)`
  or explicitly refill the previous task through the scheduler's time-slice
  helpers. Treat this as a load-balancing point: the dispatching CPU is asking
  for runnable work, so this is where the scheduler can choose whether to keep
  locality or pull eligible work from another queue/domain.
- `dequeue`: add this when the scheduler keeps per-task state while tasks are in
  user DSQs or BPF-owned queues and must clean up or account for custody exit,
  property changes, or core-sched execution.
- `running` and `stopping`: update per-task timestamps, vruntime, accounting,
  and policy state.
- `runnable`, `quiescent`, `enable`, `disable`, `init_task`, and `exit_task`:
  initialize, pause, or tear down task-local state at lifecycle boundaries when
  the policy needs it.
- `init`: create DSQs and initialize BPF-side topology or policy metadata.
- `exit`: record `UserExitInfo` with `UEI_RECORD`.

Reuse the scheduler's existing structures as anchors instead of inventing new
ones. Before editing, grep `src/bpf/main.bpf.c` (and `intf.h`) for the crate's
own equivalents of:

- per-task state storage (a task-local storage map) and per-CPU state storage
  (per-CPU context, e.g. SMT sibling masks).
- Rust-populated topology lookups (e.g., a CPU-to-LLC map).
- the helpers each callback delegates to for DSQ selection / dispatch pull
  domains, the DSQ-ID scheme, idle-CPU placement, and queue ordering (FIFO vs
  weighted virtual-time, including any CFS-style sleep-lag preservation and
  wakeup rebasing).
- the time-slice / runtime-charging helpers.
- `const volatile` rodata knobs (e.g. a slice length, `smt_enabled`,
  `numa_enabled`) and the matching `rodata_data` assignments in Rust.
- the existing BPF counters exported through Rust stats - follow their pattern
  when adding a new counter.

## Wire Rust And BPF Together

When adding a BPF tunable, declare it as `const volatile` in
`src/bpf/main.bpf.c` and set it in `src/main.rs` through
`skel.maps.rodata_data.as_mut().unwrap()` before `scx_ops_load!`.

`const volatile` globals in the BPF program are almost always initialized from
Rust (through that same rodata path) before the skeleton is loaded - the BPF
side only reads them. The initializer in `src/bpf/main.bpf.c` is often just a
fallback or generated-field default; once Rust writes `rodata_data.<field>`,
that Rust value is what the running scheduler sees.

Do not treat a BPF-only `const volatile` initializer edit as a scheduler
optimization. It may compile and produce a diff, but if Rust assigns the field
before load, the runtime policy is unchanged. Before editing any existing
`const volatile`, grep `src/main.rs` for both the symbol name and
`rodata_data`, then update the Rust-side source of truth in the same edit:

- Rename or retype a `const volatile` in `src/bpf/main.bpf.c` -> update the
  corresponding `rodata_data` field assignment in `src/main.rs` (the field name
  and type are generated from the BPF declaration, so a mismatch is a build
  error, and a stale value silently defeats the change).
- Change the value of an existing tunable -> update the Rust default, CLI option,
  computed value, or `rodata_data` assignment that feeds it. Changing only the
  BPF initializer is valid only after verifying Rust never assigns that field.
- Change the meaning, units, or default of a tunable (e.g. ns vs us, a new
  scaling) -> update the Rust value that feeds it and any CLI option / validation
  that computes it, so BPF and Rust agree on the same units.
- Add a new `const volatile` -> it defaults to 0 in BPF unless Rust sets it;
  always wire the Rust assignment, or the policy runs with a zeroed knob.

When adding or changing BPF maps:

- Define the map in `src/bpf/main.bpf.c`.
- Populate host-derived data from `Scheduler::init()` after the skeleton is
  opened or loaded and before attach.
- Keep topology-derived logic in Rust when it is easier or safer than computing
  it in BPF.

When sharing structs or syscall test-run inputs between Rust and BPF:

- Add the C definition to `src/bpf/intf.h`.
- Use the generated Rust binding from `src/bpf_intf.rs`.
- Follow the crate's existing pattern for BPF syscall programs invoked with
  `ProgramInput` (e.g. an `enable_sibling_cpu`-style setup program), if it has one.

When adding CLI options:

- Extend `Opts` in `src/main.rs`.
- Validate and normalize user input in Rust.
- Pass only compact, verifier-friendly values into BPF rodata or maps.
- Update `README.md` examples and option descriptions.

When changing scheduler flags:

- Set flags in `Scheduler::init()` with `scx_utils::compat` constants where
  possible.
- Keep `SCX_OPS_ENQ_EXITING`, `SCX_OPS_ENQ_MIGRATION_DISABLED`, and related skip
  flags aligned with how much special-case handling the BPF policy implements.
- Use `SCX_OPS_SWITCH_PARTIAL` only when the scheduler should manage explicit
  `SCHED_EXT` tasks instead of all normal-class tasks.

When adding stats:

- Add BPF counters or state in `src/bpf/main.bpf.c`.
- Read them in `Scheduler::get_metrics()`.
- Extend `Metrics` in `src/stats.rs`, including `#[stat(desc = "...")]`,
  `format()`, and `delta()`.
- Check `--help-stats`, `--stats <interval>`, and `--monitor <interval>`
  behavior.

## BPF Safety Rules

Keep BPF verifier constraints central while designing:

- Check all map and task-storage lookups for null before dereferencing.
- Treat every `bpf_map_lookup_elem()` and task-storage lookup result as
  independently nullable. The verifier does not infer that a key read from one
  map exists in another map, even if Rust initialization populated both maps.
  Never write `lookup_foo(key)->field`. Bind the result to a pointer, check it
  for null, then dereference it only on the checked path.
- Bound loops with verifier-visible limits, such as `bpf_for(...)` over known
  counts.
- Release cpumasks obtained from `sched_ext` helpers with the matching put helper.
- Use RCU sections when reading kptr cpumasks, following the crate's existing
  RCU cpumask examples (e.g., an SMT-sibling lookup).
- Prefer small integer IDs and precomputed arrays/maps over dynamic BPF-side
  discovery.
- Keep hot-path helper calls minimal in `select_cpu`, `enqueue`, and `dispatch`.
- Return explicit errors from `init` when DSQ or metadata setup fails, and call
  `scx_bpf_error()` with useful context.
- Treat `sched_ext` callback, constant, and `scx_bpf_*` helper APIs as
  kernel-version-specific. Prefer the repo's existing compat wrappers and
  current local examples over stale external snippets.

## Validate

Run focused validation after each meaningful change:

```bash
cargo fmt -p <package_name>
cargo build -p <package_name>
```

On a `sched_ext`-capable kernel, smoke-test manually:

```bash
sudo ./target/debug/<binary_name> --help
sudo ./target/debug/<binary_name> --stats 1
sudo ./target/debug/<binary_name> --monitor 1
cat /sys/kernel/sched_ext/state
cat /sys/kernel/sched_ext/root/ops
cat /sys/kernel/sched_ext/<sched_name>/events
```

(`<sched_name>` is the scheduler's `.name` ops value - read it from the
`SCX_OPS_DEFINE(...)` block or `cat /sys/kernel/sched_ext/root/ops`.)

Use `--debug` for BPF `bpf_printk()` output and `--verbose` for libbpf details
when diagnosing attach, verifier, topology, or dispatch behavior.

Use `sched_ext` event counters as policy diagnostics:

- `SCX_EV_SELECT_CPU_FALLBACK`: `select_cpu` returned an unusable CPU.
- `SCX_EV_DISPATCH_LOCAL_DSQ_OFFLINE`: a local-DSQ dispatch was redirected
  because the target CPU went offline.
- `SCX_EV_ENQ_SKIP_EXITING` and `SCX_EV_ENQ_SKIP_MIGRATION_DISABLED`: exiting or
  migration-disabled task handling is relying on core bypass behavior.
- `SCX_EV_REENQ_LOCAL_REPEAT`: recurring counts suggest incorrect
  `SCX_ENQ_REENQ` handling.
- `SCX_EV_REFILL_SLICE_DFL`: the core refilled a task slice with
  `SCX_SLICE_DFL`, often indicating the policy did not refill it.
- `SCX_EV_INSERT_NOT_OWNED`: the scheduler attempted to insert a task it no
  longer owns.

For system-level checks, inspect `/sys/kernel/sched_ext/enable_seq`, or grep
`ext.enabled` in `/proc/<pid>/sched`.

Bypass-mode module parameters under `/sys/module/sched_ext/parameters/` are
debugging knobs; avoid baking them into the scheduler.

## Iterate To A Metric

When the user defines "good" as a measurable quantity, close the loop: edit the
policy, build, run the candidate under a real workload, read back one metric,
and repeat. The validation harness is built into the agent (it runs in
process; there is no separate script):

- The harness builds the candidate (`cargo build`), refuses to run if a
  scheduler is already attached, launches it on the host as root, drives a
  workload, verifies `/sys/kernel/sched_ext/state` is still `enabled`, extracts
  one metric, always tears the scheduler down (verifying the state returns to
  `disabled`), optionally records a small `trace-cmd` sched profile
  (`sched:sched_wakeup`, `sched:sched_wakeup_new`, `sched:sched_switch`,
  `sched:sched_migrate_task`) while the workload runs, and produces a single
  JSON verdict. It needs root: run as root, with passwordless sudo, or set
  `SCX_SUDO_PASSWORD_FILE` to a file containing the sudo password.
- `tools/scx_forge_agent/spec.toml` documents the spec: `[scheduler]` (package -
  which `scheds/rust/<name>` crate to optimize - plus profile), `[system]`
  (`sudo_passwd_file` for host sudo integration), `[ai]` (`base_url`, `model`,
  and optional `coding_base_url` / `coding_model`; each base-URL is an
  OpenAI-compatible URL or one of the agent-CLI keywords
  claude/codex/opencode/cursor-agent,
  and the planner/coder can use different backends. API keys come from
  `$SCX_FORGE_API_KEY` / `$SCX_FORGE_CODING_API_KEY`),
  `[tracing]` (`enable_tracing`, `trace_events` passed to trace-cmd record, plus
  `max_trace_size` capping the recorded trace.dat, e.g. `256M`),
  `[workload]` (`command`, `duration` in seconds, repeated measurement
  count `runs`), and `[goal]` (a plain-language `prompt`, `direction`, and
  `accept_threshold_stddev`; the reported metric name is always `score`).

The workload command is the only metric source. It must run the workload and
print exactly one numeric metric value; any extraction or aggregation belongs in
the command itself.

Agent loop (driven by the controller, not by you):

1. Read the specified `spec.toml` from the user's definition of "good". Confirm
   the workload and metric actually reflect the goal before optimizing.
2. The planner/reasoner role chooses one targeted scheduling-policy experiment,
   using read-only target-crate and scheduler-reference tools.
3. The coding role applies that experiment as one focused policy edit, often in
   `src/bpf/main.bpf.c` plus matching Rust-side rodata/CLI plumbing when needed.
4. `cargo build -p <package>` as a cheap gate; fix verifier/compile errors first.
5. The harness builds, attaches, checks that the scheduler stayed enabled during
   measurement, and measures the candidate, yielding a JSON verdict. If the
   scheduler exits `sched_ext` during measurement (`stage = "runtime"`), the
   controller gives the coding role a bounded runtime-fix loop with the verdict
   JSON and scheduler log tail before reverting the round. The same runtime-fix
   path is used if the workload cannot emit a parseable metric
   (`stage = "metric"`), because that often means the candidate disrupted the
   workload. Read `metric.value` (vs the previous best value), normalized
   `improvement`, the `scheduler_log_tail` (the scheduler stats deltas), and
   `sched_trace` if present (summary counts plus top switch/wakeup/migration
   tasks and CPUs from trace-cmd, not raw trace data) to understand *why* the
   number moved. Improvement is always measured against the starting (round 0)
   scheduler, never the default kernel scheduler.
6. Keep a short running log of (change -> metric value) so the search is
   auditable. The controller can append a completed run to a state file with
   `--save <path>` and load that memory into future prompts with
   `--resume <path>` as factual context.
7. Repeat from step 2 until the user's target is met, or the iteration budget is
   exhausted. Stop and report if `stage` is `build`, `attach`, or `metric` (the
   candidate did not build, attach, or produce a measurable result).

Change one thing per iteration. Scheduler metrics are noisy: use the spec's
`runs`/`stddev` to tell a real improvement from variance, and do not chase a gain
smaller than the stddev.

## Common Verifier Errors

When `cargo build` fails inside the BPF program, the fix is usually one of:

- "math between ... pointer and register" / unbounded access: add an explicit
  `if (idx >= BOUND) return;` before indexing, so the bound is verifier-visible.
- "Unreleased reference" on a cpumask: every `scx_bpf_get_*_cpumask()` needs the
  matching put helper on all paths, inside the same RCU section.
- "invalid mem access 'map_value_or_null'" / "invalid mem access 'scalar'" /
  null deref: a map or task-storage lookup result was dereferenced before a
  null check.
- "back-edge" / "infinite loop detected": replace open-coded loops with
  `bpf_for(i, 0, n)` over a known-bound `n`.
- "dereference of modified ctx ptr" or helper-arg type errors: confirm the
  `scx_bpf_*` signature against the current repo headers, not external snippets;
  these APIs are kernel-version-specific (see "BPF Safety Rules").

## Implementation Discipline

- Keep the scheduler buildable at each step; when adding advanced policy, make
  the first version verifier-friendly and measurable before adding extra polish.
- Preserve existing shutdown, `UserExitInfo`, restart, and stats-server plumbing
  unless the policy has a concrete reason to diverge.
- Keep policy-specific names, docs, CLI flags, and stats internally consistent.
- Avoid broad Rust or BPF refactors while implementing scheduling behavior.
- Update docs and validation commands in the final response so the next agent or
  maintainer can reproduce the result.
