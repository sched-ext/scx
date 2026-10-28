# scx_rustsched

A framework for sched_ext schedulers whose BPF program is written in Rust.
A scheduler is an `impl` block of typed callbacks over tasks and CPUs:

```rust
#![no_std]
#![no_main]

use scx::prelude::*;
use scx_rustsched as scx;

#[scx::scheduler(name = "simple", flags = ENQ_LAST)]
impl Simple {
    fn select_cid(task: &Task, prev: Cid, _flags: WakeFlags) -> Cid {
        idle::pick(task, prev, Scope::Llc, Kind::AnyCpu).unwrap_or(prev)
    }

    fn enqueue(task: &Task, flags: EnqFlags) {
        dsq::insert(task, Dsq::Global, SLICE_DFL, flags);
    }
}
```

That is a whole scheduler. The framework emits the BPF entry points and
the struct_ops map, tracks the idle CPUs, and keeps what the verifier and
the toolchain need out of sight. The schedulers written in it have no
`unsafe`.

| Scheduler | What it shows |
| --- | --- |
| [scx_rvtime](../../scheds/experimental/scx_rvtime) | Weighted vtime: a queue of its own, a global, a state per task in the arena |
| [scx_rlocal](../../scheds/experimental/scx_rlocal) | Per-CPU queues with stealing: a state per CID, topology loops, a global function |
| [scx_rburst](../../scheds/experimental/scx_rburst) | EEVDF-style, with virtual-time borrowing and requests sized by the CPU burst: queues ordered by deadline, eligibility, a state that follows the task |
| [scx_reevdf](../../scheds/experimental/scx_reevdf) | A full EEVDF scheduler: the callbacks through `#[scheduler]`, the policy on the layers under the framework |
| [scx_rake](../../scheds/experimental/scx_rake) | scx_cake's policy, all in the typed API: per-CID queues and per-LLC pools, the task a CID runs, seats changed by compare and exchange |

## Writing a scheduler

A scheduler is a directory with a loader crate, which is a member of the
scx workspace, and a BPF crate in `bpf/`, which is not:

| File | Content |
| --- | --- |
| `Cargo.toml` | Depends on `scx_rustsched_loader`, build-depends on `scx_rustsched_build` |
| `build.rs` | `fn main() { scx_rustsched_build::build_default(); }` |
| `src/main.rs` | The options and `scx_rustsched_loader::main!("description", Opts);` |
| `bpf/Cargo.toml` | The BPF crate: depends on `scx_rustsched`, a `[workspace]` of its own |
| `bpf/Cargo.lock` | Checked in: the BPF build runs with `--locked` |
| `bpf/src/main.rs` | The scheduler |

Copy scx_rvtime, rename the two packages, and add the directory to `members`
and its `bpf/` to `exclude` in the root `Cargo.toml`. When `scx_rustsched`
gains a dependency, run `cargo update --offline -w` in `bpf/`.

Building needs Rust with `rust-src`, a `bpf-linker` built against the
same LLVM as the Rust compiler, `llvm-objcopy` and `llvm-nm`. Without
them the build warns and the binary refuses to start, so a workspace
build never needs them. Running needs a kernel with
`sched_ext_ops_cid` and BPF arenas. The loader takes `--verify` to load the
object and stop, which is the check to run after every change: a scheduler
that compiles can still be refused by the verifier.

### Callbacks

`#[scx::scheduler(name = "...")]` goes on an `impl` block whose functions
are named after the callbacks. Define the ones the policy needs. Each
takes the kernel's arguments in the kernel's order, may leave trailing
ones out, and declares each with the type it wants.

| Callback | Arguments | Returns |
| --- | --- | --- |
| `init` | | `Result<(), Error>` or nothing |
| `exit` | `&ExitInfo` | |
| `init_task` | `&Task`, `&InitTaskArgs` (is it a fork?) | `Result<(), Error>` or nothing |
| `exit_task` | `&Task` | |
| `enable`, `disable` | `&Task` | |
| `select_cid` | `&Task`, `Cid` (previous), `WakeFlags` | `Cid` |
| `enqueue` | `&Task`, `EnqFlags` | |
| `dequeue` | `&Task`, `DeqFlags` | |
| `dispatch` | `Cid`, `Option<&Task>` (previous) | |
| `runnable` | `&Task`, `EnqFlags` | |
| `running`, `tick` | `&Task` | |
| `stopping` | `&Task`, `bool` (still runnable) | |
| `quiescent` | `&Task`, `DeqFlags` | |
| `yield_task` | `&Task`, `Option<&Task>` (yielded to) | `bool` |
| `core_sched_before` | `&Task`, `&Task` | `bool` |
| `set_weight` | `&Task`, `u32` | |
| `set_cmask` | `&Task`, `Cmask` (the CIDs it may now use) | |
| `update_idle` | `Cid`, `bool` (idle) | |
| `cid_online`, `cid_offline` | `Cid` | |
| `dump` | `&DumpCtx` | |
| `dump_cid` | `&DumpCtx`, `Cid`, `bool` (idle) | |
| `dump_task` | `&DumpCtx`, `&Task` | |
| `cgroup_init` | `&Cgroup`, `&CgroupArgs` | `Result<(), Error>` or nothing |
| `cgroup_exit` | `&Cgroup` | |
| `cgroup_prep_move` | `&Task`, `&Cgroup` (from), `&Cgroup` (to) | `Result<(), Error>` or nothing |
| `cgroup_move`, `cgroup_cancel_move` | `&Task`, `&Cgroup` (from), `&Cgroup` (to) | |
| `cgroup_set_weight` | `&Cgroup`, `u32` | |
| `cgroup_set_bandwidth` | `&Cgroup`, `u64` period, quota and burst, in microseconds | |
| `cgroup_set_idle` | `&Cgroup`, `bool` | |

`yield_task` is ops.yield(), `yield` being a keyword in Rust. The cgroup
callbacks keep the cgroup_* names on every kernel: the build registers
them under the cpuctl_* names too, and the loader picks the set the
running kernel has. Defining `cid_online` or `cid_offline` means the
scheduler handles CPU hotplug. Without them the kernel ejects it when a
CPU comes or goes.

The `Cmask` of `set_cmask` is the task's new affinity: `mask.test(cid)`,
or `mask.word(index)` for 64 CIDs at a time. The kernel reuses its memory
once the callback returns, so a scheduler copies out what it keeps.

What a scheduler keeps per cgroup goes in cgroup storage, declared with
`scx::cgroup_state!(Type, map_name)` and reached with `cgroup.state()` and
`cgroup.state_or_create()`. A cgroup the kernel did not hand to the
callback, `task.cgroup()`, `cgroup.ancestor(level)` or
`Cgroup::from_id(id)`, is a `CgroupGuard`, which gives its reference back
when it goes out of scope.

The dump callbacks add the scheduler's lines to the kernel's debug dump
with `scx::dump!("vtime=%llu", value)`.

The attribute also takes `flags`, an expression over the names of
`ops::flags` (`ENQ_LAST`, `ENQ_EXITING`, ...), `timeout_ms` (the
watchdog timeout, 5 s by default, which `--timeout-ms` replaces at run
time), `dump_len` (the size of the debug dump, 32768 bytes by default),
and the state types below.

A `Cid` is a CPU in the kernel's topology order, where the CPUs of a core,
an LLC and a node are contiguous. The runtime keeps the idle state in
ops.init(), ops.update_idle() and ops.dispatch() whether the scheduler
defines them or not, and records the exit for the loader in ops.exit()
before the scheduler's own.

A scheduler that wants the idle state in its own hands passes
`idle_tracking = false` and calls `cid_idle::init()`, `update()` and
`rearm()` from those three callbacks itself, where it can skip the re-arm
on the dispatch paths it knows leave the CID busy.

### What the callbacks call

| | |
| --- | --- |
| `dsq::insert(task, dsq, slice, flags)` | Queue a task FIFO on `Dsq::Local`, `Dsq::LocalOn(cid)` or `Dsq::Global`, the kernel's queues. See [Queues in the arena](#queues-in-the-arena) for the scheduler's own |
| `dsq::nr_queued(dsq)` | How many tasks a queue holds |
| `idle::pick(task, anchor, scope, kind)` | Claim an idle CID in the anchor's `Scope::Core`, `Cluster`, `Llc`, `Node` or `Anywhere`, a whole idle core with `Kind::FullCore` or any CPU with `Kind::AnyCpu` |
| `flags.cid_selected()` | In `enqueue`: did `select_cid` run for this enqueue, which it does not for a wakeup queued to the task's CPU (`ALLOW_QUEUED_WAKEUP`) |
| `flags.last()` | In `enqueue`: is the task the last one of a CPU going idle, which the `ENQ_LAST` flag asks for |
| `idle::test(cid)`, `idle::scope_same(anchor, a, b)`, `idle::smt()` | Is a CID idle; do two scopes hold the same CIDs; does the machine have SMT |
| `task.weight()`, `task.scale_inverse(value)` | The task's weight, 1024 at nice 0, and a value scaled inversely by it |
| `task.cid()`, `task.allowed_on(cid)`, `task.pinned()` | Where the task is and may run |
| `task.slice()`, `task.set_slice(ns)`, `task.pid()`, `task.queued()`, `task.exiting()` | |
| `task.sum_exec_runtime()`, `task.nvcsw()`, `task.sched_info()`, `task.start_time()` | The task's history: runtime, voluntary switches, total wait and run count (None without CONFIG_SCHED_INFO), creation time in the clock of `helpers::ktime_get_ns()` |
| `task.kthread()`, `task.idle_task()` | Is it a kernel thread; is it a CPU's idle task |
| `Cid::current()`, `Cid::count()`, `cid.kick(flags)` | The CID the callback runs on, how many there are, and making one reschedule |
| `cid.curr()` | The task a CID runs now, read without its lock, as a `CurrTask`: a `Task` that cannot be kept past the callback |
| `Cid::from_cpu(cpu)`, `Cid::nr_cpus()`, `cid.set_perf(perf)` | The CID of a CPU by the kernel's number, how many CPU numbers there are, and telling the frequency governor how busy the CID is |
| `cid.is_idle()`, `cid.is_core_idle()`, `a.same_core(b)`, `a.same_llc(b)`, `cid.llc_span()`, `cid.cpu()`, `cid.capacity()` | What the topology and the idle tracking know of a CID |
| `Task::from_tid(tid)`, `Task::current()` | A task found by the id `task.tid()` gave, and the one this CPU was running: valid until the callback returns |
| `scx::timer_map!(pub name: Type, entries: N, callback: fire)`, `Type::init(key)`, `Type::start(key, ns)` | Timers: `fire(key, &Timer)` runs when one goes off, and can arm it again with `timer.start(ns)` |
| `Cid::all()`, `cid.scope(scope)` | Loops over every CID, and over a CID's core, LLC or node |
| `time::now()`, `time::before(a, b)` | The clock, and the comparison of times that wrap |

### State

Callbacks run on every CPU at once, so nothing they share is handed out as
`&mut`. A `Var<T>` is read with `get()` and written with `set()` or
`update()` through a shared reference, each one load or store, as
READ_ONCE() and WRITE_ONCE() are in C. `add()` and `fetch_add()` are the
atomic ones.

```rust
static VTIME_NOW: Var<u64> = Var::new(0);
```

`scx::shared!` declares a static in a section of its own, which a loader
finds by that name and which shares its cache lines with nothing else:

```rust
scx::shared! {
    pub static NR_QUEUED in ".data.queued": Var<u64> = Var::new(0);
}
```

What a scheduler keeps per task and per CID lives in the arena, the
memory every CPU of the scheduler shares. The arena is read and written
through loads and stores that leave no pointer behind, so a structure
there is a handle rather than a reference, and each field is a method
that returns something with `get()`, `set()` and `update()`:

```rust
scx::arena_struct! {
    struct TaskCtx {
        vtime: u64,
        lag: i64,
        queued: bool,
    }
}

impl scx::slots::TaskSlot for TaskCtx {}

scx::arena_struct! {
    struct CidCtx {
        nr_running: u64,
    }
}

#[scx::scheduler(name = "example", task_slot = TaskCtx, cid_slot = CidCtx)]
impl Example {
    fn running(task: &Task) {
        let Some(ctx) = task.slot::<TaskCtx>() else {
            return;
        };
        ctx.vtime().update(|vtime| vtime + 1);
        if let Some(here) = task.cid().slot::<CidCtx>() {
            here.nr_running().update(|count| count + 1);
        }
    }
}
```

A field is `u64`, `i64`, `u32`, `i32`, `bool`, an array of two to eight
`u64`, a running average (`Ravg`), or `Option` of another `arena_struct!`,
which holds that structure's address and 0 for `None`. `Words<N>` is a
region something else lays out: `field().address()` hands it on, and
`field().view::<T>()` reads it as another structure that fits in it. None
of it is `unsafe`: an arena access cannot fault or leave the arena,
whatever the address.

Structures that one allocation lays out back to back, such as one per CID,
are an `arena::Array<T>`, whose `get(index)` is `None` past the end:

```rust
let queues = Array::<Queue>::from_address(base, u64::from(Cid::count()));
if let Some(queue) = queues.get(u64::from(cid.index())) {
    queue.load().add(weight);
}
```

`task_slot = TaskCtx` gives every task a slot from a pool, zeroed, in
ops.init_task(), and takes it back after the scheduler's ops.exit_task().
`task.slot()` is `None` only for a task the scheduler was never given.
`TaskSlot` has `reset()` to override, for a slot that does not start as
zeroes. The slot's address is kept in the task itself, in the field the
kernel would order a DSQ by vtime with, so a lookup is one load.

`cid_slot = CidCtx` gives every CID a `CidCtx`, zeroed in ops.init(),
which `cid.slot()` returns from any CPU. It is `None` only for a number
that is not a CID. A scheduler with several per-CID tables declares each
with `scx::cid_slot!(Type, HEADER in ".data.name")` and allocates them
from its ops.init() with `cid_table::init_slots()`. A `u64` field several
CPUs update has `add()`, `fetch_add()`, `compare_exchange()` and
`release()`.

### Queues in the arena

A `Dsq` is a queue of the kernel's: the local ones and the global one. An
`Edq` is a queue of the scheduler's own, in the arena, used as the
kernel's user DSQs are: filled in `enqueue` and moved to a CPU in
`dispatch`.
`Edq::User(id)` is a queue that belongs to no CPU, and `Edq::Cid(cid)` the
queue of a CID, of which there is one per CID from the start.

```rust
const SHARED: Edq = Edq::User(0);

#[scx::scheduler(name = "...", task_slot = TaskCtx)]
impl Sched {
    fn init() -> Result<(), Error> {
        dsq::create(SHARED)
    }

    fn enqueue(task: &Task, flags: EnqFlags) {
        let Some(ctx) = task.slot::<TaskCtx>() else { return };
        dsq::insert_vtime(task, SHARED, SLICE_NS.get(), ctx.vtime().get(), flags);
    }

    fn dispatch(cid: Cid, _prev: Option<&Task>) {
        dsq::move_to_local(SHARED, cid);
    }
}
```

| Call | What it does |
| --- | --- |
| `dsq::create(edq)` | Check the id of an `Edq::User` queue, from `init`: it is below `dsq::USER_MAX` |
| `dsq::insert(task, edq, slice, flags)` | Queue the task behind what is there |
| `dsq::insert_vtime(task, edq, slice, vtime, flags)` | Queue the task in the order of `vtime`, the lowest first |
| `dsq::insert_deadline(task, edq, slice, vtime, deadline, flags)` | Queue the task in the order of `deadline`, with the virtual time it is eligible from |
| `dsq::move_to_local(edq, cid)` | Move the first task that may run on `cid` to its local DSQ, from `dispatch`, with the CID `dispatch` was called for |
| `dsq::move_to_local_eligible(edq, cid, vtime_now)` | The same with eligibility: the first task whose virtual time is not past `vtime_now`, or the first if there is none |
| `dsq::move_to_local_with(edq, cid, vtime_now, requeue)` | Either of the two, with a hint that the task that was running goes back on this queue, which then is not marked empty in between |
| `dsq::peek(edq, vtime_now)` | The deadline of the task such a move would take, and the shortest slice queued, without taking anything |
| `dsq::move_to_local_scan(edq, cid, &mut cursor, skip)` | Take from the queue of another CID, passing over the tasks whose slot `skip` returns true for, from where `cursor` stopped last time |
| `dsq::peek_next(edq, &mut cursor)` | Hold the next task of a queue: `Next::Task(held)` has `slot()`, `task()`, `is_queued()`, `key()` and `move_to_local(cid)`, and lets go when dropped |
| `dsq::queued(cid, scope)` | Loop over the CIDs of a scope whose queue has something in it |
| `dsq::queued_test(cid)`, `dsq::queued_check(cid)` | The bit that says a CID has something queued, and a second look at it after taking a task some other way |
| `Backlog::at(address)`, `park(task, key, slice)`, `pop()` | A queue tasks wait in without running from it, such as a cgroup out of bandwidth: `pop()` gives a held task to `unpark()` and queue again |
| `dsq::dequeue(task, flags)` | Take a task back in the scheduler's own `dequeue`, with `TaskSlot::OWN_DEQUEUE`: true if it was parked |
| `dsq::inspect(task, edq)` | What the queues know of a task, for a debug dump |
| `dsq::nr_queued(edq)`, `cid.has_queued()`, `cid.nr_queued()` | What a queue holds |

The framework keeps the node a task is queued by in the task's slot,
which every task has whether the scheduler names a `task_slot` or not.
Being in the arena is what lets any CPU look into any queue, and take
from the queue of another CID with `dsq::move_to_local(Edq::Cid(peer), cid)`.

A queued task is in the scheduler's custody, which the framework handles:
it takes the task back when the kernel changes a property of it, and asks
for the `TID_TO_TASK` flag, because a CPU that takes a task finds it by id.
A task that cannot be queued goes to a kernel DSQ, the local one of the
CID for an `Edq::Cid` queue and `Dsq::Global` otherwise, and the ordered
inserts then return false.

An `Edq::Cid` queue is mostly taken by its own CPU, and is where these
queues pay. Every CPU takes the lock of an `Edq::User` queue, so one queue
for a whole machine does not scale.

### Tunables

The scheduler's tunables are the options of its loader, written once, in
the loader's `src/main.rs`, as in any other scheduler:

```rust
#[derive(clap::Args)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "5000")]
    slice_us: u64,

    /// Do not let a CPU with an empty queue take from the other queues.
    #[clap(long)]
    no_steal: bool,
}
```

`scx::opts!();` in the scheduler reads that structure and declares a tunable
for each field that is an integer or a `bool`: `SLICE_NS` and `NO_STEAL`
here, with the option's type, documentation and default. `SLICE_NS.get()`
reads one, and `scx_rustsched_loader` sets it from the option,
`--slice-us 1000`. They are constants once the scheduler is loaded.

A time is in nanoseconds in the scheduler, whatever the option takes: a
field named `_us` or `_ms` gives the tunable named `_NS`, and the default
and what the loader is given are converted. A field marked
`#[opts(no_bpf)]` is an option of the loader alone, and gets no tunable.

`scx::params!` declares a tunable no option gives as it stands:

```rust
scx::params! {
    /// The CPUs to run tasks on first, a bit each.
    PRIMARY_CPUS: [u64; 4] = [0; 4];
}
```

An array is read with `PRIMARY_CPUS.at(index)`. The loader sets such a
tunable with a function of its own, from an option of another type, such
as a list of CPUs. See scx_rustsched_loader's README.

### Global functions

A callback and everything it calls is one program, and the verifier walks
every path through it. A loop, or a search called from several places, is
what to put behind `#[scx::global]`: the verifier then checks its body
once and treats each call as opaque.

```rust
#[scx::global]
fn steal(cid: Cid) -> bool {
    for peer in dsq::queued(cid, Scope::Llc) {
        if peer != cid && dsq::move_to_local(Edq::Cid(peer), cid) {
            return true;
        }
    }
    false
}
```

It takes up to five parameters and returns one value: `Cid`, `&Task`,
integers, `bool`, the flags types, and the handle of an `arena_struct!`,
which is passed as its address.

### What differs from other Rust

- There is no allocator and no standard library: `#![no_std]`, `core` only.
- A panic cannot be compiled to BPF. Divide with `checked_div()`, index
  with `get()`, and leave out `unwrap()` and `expect()`.
- Loop with `Cid::all()`, `cid.scope()` or `loops::range(start, end)`,
  which the verifier can bound. It walks every iteration of a plain
  `for i in 0..n`, which only a small constant `n` survives.
- Take one `Option` at a time, `let Some(a) = ... else { return };` for
  each. The verifier has refused a match on a tuple of two.
- Return a CID that may be none as `OptCid`, not `Option<Cid>`, and
  turn it into an `Option` where it is used, `search().get()`. An
  `Option<Cid>` is two registers, and the verifier has refused the copy
  of a `None` where two paths meet, whose CID half nothing wrote.
- Keep closures small enough to be inlined.

## Layers

The framework above is `sched`, `dsq`, `idle`, `var`, `arena`, `param` and
`time`. Under it is the core every scheduler links: the struct_ops map
(`ops`), the kfuncs and helpers (`kfuncs`, `helpers`, `timer`), the
configuration table (`config`), task fields (`task`), the arena (`pool`,
`mem`, `loops`), the per-CID tables and the idle tracking (`cid_table`,
`cids`, `cid_idle`, `cid_ranges`, `tiers`, `topology`), and `edq`, `slab`,
`ravg`, `clock` and `uei`. A scheduler can call into the core directly
where the framework does not reach yet, at the price of `unsafe`.

`queue` is the eligible deadline queues behind `Edq::Cid` and `Edq::User`
with the custody of the tasks in them, and `slots` the pool of per-task
arena slots their nodes live in. Schedulers reach both through `dsq`.

The crate is `#![no_std]`, built for the BPF target by the scheduler's build
script through `scx_rustsched_build`, and it is not a member of the scx
workspace. `scx_rustsched_macros` has the attributes, `scx_rustsched_abi` is
what the crate shares with the loader, and `scx_rustsched_loader` is the
loader side.

## Conventions

What the runtime's own code does, and why, to be accepted by the toolchain
and the verifier. A scheduler written in the framework does not have to
know any of it.

**No CO-RE.** The Rust toolchain emits no relocation records, so the
kernel's types stay opaque and the loader resolves each field's offset from
the running kernel's BTF into the frozen `.rodata.config` map, see
`scx_rustsched_abi`. The verifier then sees every access at a constant
offset.

**struct_ops.** The source declares only the `sched_ext_ops_cid` members a
scheduler uses. libbpf maps them by name into the running kernel's
structure, so the local structure deliberately matches neither its size
nor its layout. Each entry point receives a pointer to an array of 64-bit
argument slots. The initializer casts its address to the kernel's callback
type so that the BTF describes a function pointer, which libbpf and the
kernel consume and nothing calls through.

**kfuncs.** The toolchain emits no BTF for extern declarations, and
bpf-linker internalizes a declaration it is not told to export and discards
its arguments. The kfuncs are declared once, in the catalog `kfuncs.rs`,
which this crate expands into the extern declarations and
`scx_rustsched_build` into the prototypes and `.ksyms` entries it adds to
the BTF, and into the linker's export list. Adding a kfunc is one line
there.

**Arena access.** Every program that touches the arena references the
arena map once, `pool::touch()`, at the callback's entry. Loads, stores and
atomics go through `mem`, which casts and accesses in one block of assembly
and leaves no cast pointer in a register. The verifier turns 64-bit
arithmetic it sees on an arena pointer into 32-bit arithmetic, so an
instruction reached with a stale pointer on one path and with numbers on
another would truncate the numbers, and kernels since "bpf: Prevent
variable arena/non-arena register contents" refuse such a program.

**Atomics.** The BPF target has no standard atomic methods. Updates of map
values use the unstable atomic intrinsics, and arena updates the accessors
of `mem`. A compare and exchange is tested by comparing the returned value
with the expected one: rustc 1.98 emits invalid bitcode for a branch on
the success flag. The arena takes only the non-fetching bitwise atomics.

An atomic whose result is used is never Relaxed. LLVM 21 to 23 lower a
relaxed add or sub, and a relaxed 32-bit and, or or xor, to the
non-fetching `lock` instruction even when the result is used, and the
result is then the operand, not the old value. On BPF v3 they do so
without a diagnostic. llvm/llvm-project#210371 fixes it, first in LLVM 24.
A BPF fetching atomic has no ordering field, so any stronger ordering emits
the same `atomic_fetch_add` a correct relaxed one would.

An atomic whose result is discarded is Relaxed, as in `Var::add()` and
`pool::add()`. It is then the `lock` instruction, which the arm64 JIT
emits as `stadd` and not the fully ordered `ldaddal` of a fetching one.

**Arithmetic.** BPF v3 has no signed division, so signed quotients divide
magnitudes, and every divisor is checked so that no panic path reaches the
object.

**Global functions.** A function called for every CID of a domain is a
global BPF function (`#[no_mangle] extern "C"`, named `rust_*`), which the
verifier checks once rather than in every caller's state: as static
functions they took a callback past a million instructions. A global
function may take a kernel pointer only with an `arg:trusted` declaration
tag, which Rust cannot express, so `scx_rustsched_build` adds the tag to the
BTF for every task parameter of a global function. A scheduler writes its
own as `#[scx::global] fn name(...)`, over `Task`, `Cid` and scalars, and
calls it as written. Closures must stay inlined: an outlined one gets an
unnamed environment parameter, which the kernel's BTF check rejects.

**Loops.** A loop is `for index in loops::range(start, end)`, scx's
bpf_arena_for(): a counted loop bounded by may_goto, with no kfunc call per
iteration. Its step is read from a global, and a loop that walks ranges
takes its next start from the ranges, so that the verifier sees no counter
it must track exactly.
