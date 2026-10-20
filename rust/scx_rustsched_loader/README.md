# scx_rustsched_loader

Loading and running a Rust BPF sched_ext scheduler from user space: the
configuration table's kernel entries resolved from the running kernel's BTF,
the struct_ops map the kernel can take, the map sizes set before the load,
the attach, the exit record, the arena statistics, the per-callback profiler
and the sampler of the per-CID queues, which reads them from the arena
through scx_rustsched's `edq.rs`. `tiers` reads the CPU capacities and the
kernel's asymmetric packing priorities and hands them to the BPF program per
CPU.

`main!` is a scheduler's whole `main()`: it parses the command line,
loads and attaches the scheduler, and runs it until Ctrl-C, the end of
`--duration`, or the kernel ejects it. Every scheduler gets `--verify`,
`--exit-dump-len`, `--timeout-ms` (the watchdog timeout, in place of the
scheduler's own), `--version` and libbpf's options from it. What a
scheduler adds is its options and what it implements of `Scheduler`.

## Options and tunables

`Opts` is a `clap::Args` structure, written as in any other scheduler,
and each of its fields sets the tunable of the same name. The BPF side
declares those from the same structure, with `scx_rustsched::opts!()`:

```rust
#[derive(clap::Args)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "5000")]
    slice_us: u64,
}

impl scx_rustsched_loader::Scheduler for Opts {}

scx_rustsched_loader::main!("description", Opts);
```

`--slice-us 1000` then sets `SLICE_NS`, to 1000000: an option in
microseconds or milliseconds, named `_us` or `_ms`, sets the tunable in
nanoseconds. The default the scheduler starts with is the one in `Opts`.

An option that is not the tunable's value as it stands has a name of its
own, and `Scheduler::settings()` sets the tunable from it, which the BPF
side declares with `scx_rustsched::params!`. A list of CPUs that the
scheduler takes as a mask, an array tunable, is one:

```rust
#[derive(clap::Args)]
struct Opts {
    /// CPUs to run tasks on first, as a list.
    #[clap(short = 'm', long, default_value = "")]
    primary_domain: String,
}

impl Scheduler for Opts {
    fn settings(&self, params: &mut Params) -> Result<()> {
        params.set("primary_cpus", &mask_of(&self.primary_domain)?)
    }
}
```

`Params::set()` takes values of the tunable's own type: one for an integer
or a bool, and for an array at most as many as it has elements, the rest
of which become zero. `settings()` sees only what the names leave over:
every other option is set before it runs.

An option that only the loader uses, such as one that says how to read
the CPU capacities, is marked `#[opts(no_bpf)]`, on a structure that also
derives `scx_rustsched_loader::Opts`. `opts!()` then declares no tunable for
it:

```rust
#[derive(clap::Args, scx_rustsched_loader::Opts)]
struct Opts {
    /// Treat every CPU as having the same capacity.
    #[opts(no_bpf)]
    #[clap(long)]
    uniform_capacity: bool,
}
```

`settings()` also chooses the ops flags the scheduler is loaded with,
starting from the ones `#[scheduler(flags = ...)]` declares. A flag the
kernel may lack is added there, from `compat`, which reads 0 for it on
such a kernel, and the BPF side asks `scx_rustsched::ops::enabled()` what it
got:

```rust
fn settings(&self, params: &mut Params) -> Result<()> {
    if !self.no_proxy_exec {
        params.add_flags(*compat::SCX_OPS_ENQ_BLOCKED);
    }
    Ok(())
}
```

Every tunable has to be set, by an option of its name or by
`settings()`. A scheduler with one that nothing sets does not start,
which is what a misspelled option comes to.

## Statistics

A scheduler has no statistics unless it provides them. `--stats`,
`--monitor` and `--help-stats` are every scheduler's options, and they
work for the one whose `Scheduler::stats()` returns its two callbacks:

```rust
impl Scheduler for Opts {
    fn stats(&self) -> Option<Stats> {
        Some(Stats::new(
            server_data,                           // describes Metrics
            |object| metrics(object),              // reads one sample
            |metrics, interval| show(&metrics),    // prints one sample
        ))
    }
}
```

The first callback reads the scheduler's metrics, a structure of its own
that scx_stats can serve, from the running object when a client asks. The
second prints what a client received, with `--stats` beside the scheduler
and with `--monitor` from another process.

`Stats::idle()` adds a third, called about ten times a second while
nobody asks, for what is kept only for a client, such as the callback
profiler's accounting, to be dropped.

`OpsProfiler`, `QueueSampler`, `arena_usage()` and `ArenaView` are there
for a scheduler's metrics to use.

## Startup and exit

What a scheduler prints when it starts and stops is its own. The loader
calls `Scheduler::attached()` once the scheduler is attached and its init
has run, and `Scheduler::stopped()` when it was unregistered without an
error. Each prints one line by default. `Attached` has a method for each
thing the loader knows about the run, such as `nr_cpus()`, `tick_ns()`,
`ops_flags()`, `tiers()` and `arena_usage()`, and `object()` to read what
the scheduler's init computed:

```rust
impl Scheduler for Opts {
    fn attached(&self, attached: &Attached<'_>) {
        info!("{} on {} CPUs, flags {:#x}", attached.name(),
              attached.nr_cpus().unwrap_or(0), attached.ops_flags());
    }
}
```

An error exit is reported by the loader, with the kernel's debug dump.
Every line goes through the logger the loader sets up, at info level, with
the time.

## The runtime's options

`Scheduler::runtime()` returns what the scheduler asks of the runtime, a
mask of `config::runtime`'s bits, and `Scheduler::capacity()` how the
CPUs' capacities and packing ranks are read.
