# scx_reevdf

scx_reevdf, scx Rust EEVDF, is a port of `scx_eevdf` to Rust: a
virtual-deadline sched_ext scheduler with both its BPF program and userspace
loader written in Rust. The loader uses libbpf-rs and its bundled C libbpf.
There is no BPF C source, generated C skeleton, or Aya dependency. The build
uses the bpf-linker tool maintained by the Aya project.

## Overview

What is here is the scheduling policy. The plumbing any Rust BPF scheduler
needs lives in the runtime crates under `rust/`: `scx_rustsched` (the arena,
the task slots, the queues, the idle CIDs, the kfuncs and the struct_ops
map), `scx_rustsched_loader` (loading and attaching, and the CPU capacity
and packing tiers), `scx_rustsched_build` (the BPF build) and
`scx_rustsched_abi` (the configuration table both sides share).

The BPF program, `bpf/src/`:

| File | What it does |
| --- | --- |
| `main.rs` | The sched_ext callbacks and the `#[scheduler]` block that registers them |
| `preempt.rs` | The pick: whether a wakee preempts the running task, `wakeup_preempt_fair()`, and whether the running task keeps the CPU |
| `accounting.rs` | The policy's arithmetic as plain functions, which the host tests run as they are |
| `taskctx.rs` | The per-task context kept in the arena, and its accessors |
| `pack.rs` | A CID's pack: the weighted average vruntime tasks are placed and tested against, and what the CID is running |
| `idle.rs` | Where a waking or forked task goes, `select_task_rq_fair()` |
| `newidle.rs` | The idle pull: a CID out of work takes a queued task from a neighbour, `sched_balance_newidle()` |
| `balance.rs` | Periodic balance: moves queued tasks between CIDs that stay busy, `sched_balance_domains()` |
| `balance_state.rs` | Where the balancers keep the state worth watching and a reader for it, which the loader builds too |
| `active.rs` | Active balance: moves a running task, which fair.c does with a stopper thread |
| `load.rs` | Load tracking: how much a task runs and how loaded a CID is |
| `pressure.rs` | The capacity a CID loses to higher scheduling classes, IRQs and steal time |
| `cgroup.rs` | Group scheduling: cpu.weight and cpu.idle |
| `bandwidth.rs` | cpu.max |
| `hrtick.rs` | A timer per CID that ends a request between two ticks |
| `features.rs` | The switches that turn one fair.c rule off at a time |
| `debug.rs` | What the scheduler adds per task to the kernel's debug dump |

The loader, `src/`:

| File | What it does |
| --- | --- |
| `main.rs` | The options, what they ask of the runtime, and the metrics |
| `balance.rs` | Reads the balancers' per-CID state from the arena for the statistics |
| `stats.rs` | `--stats` and `--monitor` |

`build.rs` describes the BPF crate to `scx_rustsched_build`. `tests/` has
the host test `cargo test` runs, `accounting.rs` for the policy, and the
scripts to run in a VM: `smoke.sh`, which uses `fairness.py` and `yield.py`,
and `arena.sh`.

Design below is the short version of how it works. The detail is at the
top of each file.

## Design

scx_reevdf follows fair.c rule by rule, as `scx_eevdf` does, on sched_ext's
cid form. Each rule can be turned off by an option of its own, to compare
it against what it replaced (see Run). The ideas the code is built on:

- **A pack per CID.** The tasks queued on a CID and the one running there
  form its pack. The pack's reference is their weighted average vruntime,
  maintained incrementally as tasks join, leave and are charged. A task is
  eligible when its vruntime is not ahead of the reference, and its lag,
  the distance between the two, travels with it from pack to pack. There
  is no global virtual time: a vruntime means something only within a
  pack.
- **One eligible deadline queue per CID.** A task waits in an EDQ, a tree
  ordered by virtual deadline that finds the first eligible task in one
  descent. The pick is the eligible task with the earliest deadline among
  the queue and the running task, as in `pick_eevdf()`.
- **Queued tasks stay in BPF custody.** Nothing waits in a DSQ: a task is
  inserted into a local DSQ only when it is about to run. Any CID can
  therefore look at and take another's queued tasks, which needs a
  protocol for who may move a task on while the kernel can take it back.
- **Three ways work moves between CIDs.** A CID that runs out of work
  pulls a queued task from a neighbour. A periodic balance moves queued
  tasks between CIDs that stay busy. An active balance moves a running
  task, which fair.c does with a stopper thread and this does with a
  handover across callbacks.
- **Placement by topology.** A wakeup looks for an idle CID around its
  target as `select_task_rq_fair()` does: the core, the cluster, the LLC,
  and optionally the node and the machine. The idle state is kept per
  shard of an LLC, so that CPUs far apart do not contend on it.
- **Shared state lives in the arena.** The per-task contexts and the
  per-CID tables are in a BPF arena, reachable from any CPU, and what
  another CPU may change is updated with atomics rather than under a
  remote lock.
- **Groups without group runqueues.** A cgroup's task joins its CID's pack
  beside every other task, at a weight scaled by its group's share at
  every level, fair.c's single-runqueue design. cpu.max holds a group's
  tasks back in a backlog of its own.
- **What sched_ext does not tell.** The capacity a CPU loses to higher
  scheduling classes, IRQs and steal time is inferred, and virtual time is
  charged in the CPU's task clock, so that a task is not billed for the
  interrupts that land on its CPU.

The detail of each is at the top of the file that implements it, see the
tables above, and each callback in `bpf/src/main.rs` says what it does.
How a Rust BPF program is kept within the toolchain's and the verifier's
rules is in `rust/scx_rustsched/README.md`.

## Where fair.c's logic is

The port follows fair.c rule by rule, and the comments name the fair.c
function each piece of code follows. To find where a rule is implemented,
or to check the port against a change in fair.c, search `bpf/src/` for the
function's name. The table says where to start.

| In fair.c | Here |
| --- | --- |
| `pick_eevdf()`, `entity_eligible()`, `update_curr()`, `update_deadline()`, `set_protect_slice()`, `update_protect_slice()` (RUN_TO_PARITY, PREEMPT_SHORT) | `preempt.rs`, `accounting.rs`, with the callbacks in `main.rs` |
| `wakeup_preempt_fair()` | `preempt.rs` |
| `place_entity()`, `entity_lag()` (PLACE_LAG, PLACE_REL_DEADLINE) | `pack.rs`, `accounting.rs` |
| `dequeue_entity()`, `requeue_delayed_entity()`, `ttwu_runnable()` (DELAY_DEQUEUE) | `pack.rs`, `main.rs` |
| `reweight_entity()`, `reweight_eevdf()`, `update_cfs_group()` | `pack.rs`, `cgroup.rs` |
| `task_tick_fair()`, `entity_tick()`, `yield_task_fair()`, `set_next_task_fair()` | `main.rs` |
| `hrtick_start_fair()`, `hrtick_update()` (HRTICK) | `hrtick.rs` |
| `select_task_rq_fair()`, `wake_affine()`, `wake_wide()`, `select_idle_sibling()`, `select_idle_core()`, `select_idle_smt()`, `select_idle_cpu()`, `select_idle_capacity()`, `find_idlest_cpu()` | `idle.rs` |
| `update_idle_cpu_scan()` (SIS_UTIL) | `balance.rs`, `idle.rs` |
| `sched_balance_newidle()`, `task_hot()`, `update_newidle_cost()`, `rd->overloaded` | `newidle.rs` |
| `sched_balance_domains()`, `should_we_balance()`, `update_sd_lb_stats()`, `detach_tasks()`, `can_migrate_task()` | `balance.rs` |
| Active balance, `update_misfit_status()`, `nohz_balancer_kick()`, asymmetric packing and capacity | `active.rs` |
| Load tracking, what PELT is for (kept with running averages), and `util_est` | `load.rs` |
| Capacity lost to other classes, IRQs and steal time | `pressure.rs` |
| Proxy execution: a donor stays on its runqueue, `can_migrate_task()` refuses `task_is_blocked()` | `main.rs` (enqueue), `balance.rs`, `active.rs` |
| Group scheduling: `__calc_prop_weight()`, `enqueue_hierarchy()`, `dequeue_hierarchy()`, `sched_group_set_idle()` | `cgroup.rs` |
| CFS bandwidth: `tg_set_cfs_bandwidth()`, `__refill_cfs_bandwidth_runtime()`, `dequeue_throttled_task()` | `bandwidth.rs` |
| `sched_feat()` switches and their options | `features.rs` |

`accounting.rs` holds the arithmetic of these rules as plain functions,
which the host tests in `tests/accounting.rs` run as they are: a change to
a formula of fair.c goes there first.

## Build

scx_reevdf is a member of the scx Cargo workspace, and a plain `cargo build`
from the top of the tree builds it. Its BPF side, `bpf/`, is a Cargo
workspace of its own, which `build.rs` builds for the BPF target through
`scx_rustsched_build`. On a host without the toolchain below, as in CI, the
build warns and leaves the BPF objects empty, so that the rest of the
workspace still builds, and the scheduler refuses to start.

Prerequisites:

- Rust with `rust-src`, the same toolchain for userspace and BPF.
- `bpf-linker` on `PATH`, built against the same LLVM as the Rust
  compiler. See the [bpf-linker installation
  instructions](https://github.com/aya-rs/bpf-linker#installation).
- `llvm-objcopy`, `llvm-nm` and the usual libbpf build dependencies (C
  compiler, pkg-config, libelf and zlib development files).

```sh
cargo build --release --locked -p scx_reevdf
```

rust/scx_rustsched_build describes the build and its environment variables.

## Run

A kernel with cid-form `sched_ext_ops_cid` support, BPF arenas and kernel
BTF is required. Run initial experiments in a VM. From the top of the scx
tree:

```sh
sudo target/release/scx_reevdf --verify
sudo target/release/scx_reevdf --duration 10
sudo target/release/scx_reevdf
```

`--verify` loads and verifies the programs without attaching the
scheduler. `--help` lists the options. As in `scx_eevdf`, each rule of
fair.c the port follows can be turned off by an option of its own, such as
`--no-run-to-parity` or `--no-place-lag`, to compare it against what it
replaced.

`--stats <interval>` prints what each sched_ext callback costs, the state
of the queues and of the balancers, and `--monitor <interval>` prints the
same from another process for a scheduler already running. `--help-stats`
describes the figures.

## Validation

`cargo test -p scx_reevdf` runs the host tests of the policy's arithmetic.
The runtime's data structures are tested in scx_rustsched_loader.

`tests/smoke.sh` and `tests/arena.sh` take the path of the binary and run
as root in a disposable VM with no scheduler attached. The first checks
loading, attaching, detaching and that weights are honored. The second
checks the task contexts' pool under fork and exit churn and its growth.
For example, from an already-built kernel tree:

```sh
vng --cpus 2 --memory 1G --user root -- bash \
    /path/to/scx/scheds/experimental/scx_reevdf/tests/smoke.sh \
    /path/to/scx/target/release/scx_reevdf
```
