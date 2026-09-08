# scx_cake

A Linux `sched_ext` CPU scheduler focused on gaming responsiveness and general-purpose use.

Cake tries to keep runnable tasks from waiting unnecessarily while preserving
cache locality and fair CPU service. Its name comes from the CAKE network queue
manager. Scheduling decisions use task activity and hardware topology, not game
names or application profiles.

This README describes the source in this checkout. An installed package may
differ: check `scx_cake --version` and `scx_cake --help`.

[Build and run](#build-and-run) · [Flags](#command-line-flags) ·
[Toggles](#toggle-settings) · [Design](#how-scheduling-works) ·
[Limits](#hardware-support-and-limits) · [Source](#source-and-further-reading)

## Build and run

Requirements:

- A Linux kernel with `CONFIG_SCHED_CLASS_EXT=y`, BPF support and kernel BTF.
  See the repository's [kernel configuration](../../../kernel.config).
  Compatibility wrappers handle supported API differences; a kernel version
  or distribution name alone does not establish that this build will load.
- The repository's [Rust toolchain](../../../rust-toolchain.toml), Clang with
  BPF support, and the system libraries listed in the
  [build instructions](../../../README.md#build--install).
- Permission to load and attach the scheduler, provided by your scheduler
  service or system administrator. The commands below do not grant permissions.

From the scx repository root:

```sh
cargo build --locked --release -p scx_cake

# Inspect the binary and host without starting the scheduler.
./target/release/scx_cake --version
./target/release/scx_cake --help
./target/release/scx_cake --print-topology

# Start with the default policy, once permissions are provisioned.
./target/release/scx_cake
```

You can also select Cake through your distribution's scheduler service.
The default policy needs no profile or toggle options.

While running, `cat /sys/kernel/sched_ext/root/ops` identifies the active
scheduler; Cake's name starts with `cake`. Press Ctrl+C to stop a foreground
instance. Detaching returns scheduling to the kernel's default scheduler.
Check service logs, terminal output and the kernel log for startup or exit
errors. Cake requests a five-second runnable-stall watchdog; it is a recovery
mechanism, not a latency guarantee.

## Command-line flags

| Flag | Default | Behavior |
|---|---|---|
| `-h`, `--help` | Off | Print supported flags and toggle defaults, then exit |
| `-V`, `--version` | Off | Print the version, then exit |
| `--print-topology` | Off | Print discovered core topology, capacity and preferred-core information, then exit without attaching |
| `-v`, `--verbose` | Off | Enable verbose libbpf output, startup details, IRQ diagnostics and exit event counts |
| `--toggle NAME=0\|1` | No overrides | Override a setting from the table below; repeat the option for multiple settings |

`--version` takes precedence over `--print-topology`. These inspection modes
do not apply or validate toggle specifications. In particular,
`--print-topology --toggle llcsplit=1` still prints the real host topology.

### Obsolete and invalid options

Unknown options from an old `scx_loader` configuration or another launcher
are ignored with a warning. Their associated values are discarded, and valid
options still apply. If no valid override remains, Cake uses its defaults.

Examples of ignored legacy arguments:

- `--profile gaming`
- `--profile=performance`
- `-p powersave`
- `-pperformance`

In `-vpperformance`, `-v` still enables verbose output and the obsolete
`-pperformance` suffix is ignored. None of these profile names selects a policy.

Invalid toggle specifications are warned about and ignored during scheduler
startup. They do not undo earlier valid overrides. Missing values for supported
options, such as a bare `--toggle`, remain errors. `--help` exits before logging;
version and topology output can be accompanied by unknown-option warnings.

## Toggle settings

Names are case-sensitive. Values must be exactly `0` (off) or `1` (on).
Settings are read at startup; changing them requires restarting Cake.
Repeated valid assignments are processed in order, so the last one wins.

| Name | Default | What it controls |
|---|---|---|
| `g85` | `1` | Seat rules that protect a pipeline-stage task's association with a CPU |
| `g86` | `1` | Retry idle-CPU claims and allow eligible kernel-thread wakes to use a shared pool |
| `g87` | `1` | Base wakeup protection and pinned-wake preemption margins on the waiting task's own slice |
| `g89` | `1` | Use per-cache wake pools and cache-local routing; `0` selects one shared pool and disables this routing policy |
| `probe` | `0` | Collect additional BPF placement and delay diagnostics, reported at exit |
| `llcsplit` | `0` | Testing only: split the host's cores into two synthetic cache domains, keeping SMT siblings together |

`-v` and `probe` are independent: verbose logging does not enable probe
instrumentation. Neither is needed for normal scheduling. `llcsplit` changes
the topology supplied to the scheduling policy; it does not reproduce physical
inter-cache costs. Hardware fallbacks still apply. There is no `g88` toggle.

With launch permissions already provisioned:

```sh
# Log details with the default scheduling policy.
./target/release/scx_cake -v

# Collect additional diagnostics.
./target/release/scx_cake --toggle probe=1

# Compare one shared wake pool with the default per-cache policy.
./target/release/scx_cake --toggle g89=0
```

## How scheduling works

An **LLC** is a last-level cache shared by a group of CPUs. A **DSQ** is a
dispatch queue managed through `sched_ext`.

Cake uses CPU-owner queues and shared wake queues. With the default policy
and supported topology, each LLC has a wake queue. Wider layouts can fall
back to one shared wake queue.

| Situation | Usual behavior |
|---|---|
| A task wakes and Cake claims an eligible idle CPU | Admit the task directly to that CPU |
| An eligible wake's estimated mean wait exceeds twice its mean CPU burst | Normally use its LLC's shared wake queue so nearby CPUs can serve it |
| A task uses up its slice | Return it to its owner queue, preserving locality |
| A CPU needs work | Check remote offers, its owner queue and its wake pool, then other eligible queues |

Affinity restrictions, pinned tasks, serial handoffs and forced requeues add
exceptions. These are common paths, not unconditional routing rules.

Placement considers cache warmth, whole idle cores, SMT interference and
platform capacity/preferred-core hints. A **seat** associates a CPU with a
pipeline-stage task; it is not an exclusive reservation or a CPU-affinity change.
Task storage retains placement history.

Cake also prefers CPUs with less interrupt work. It samples interrupt-time
shares, tracks active interrupt handlers, and uses tick look-ahead when the
required information is available. Noisy CPUs remain usable when suitable
cleaner CPUs are unavailable.

### CPU time and fairness

Virtual runtime orders service using consumed CPU time and nice-level weights.
The adaptive task-slice calculation uses lifetime runtime, task age and voluntary
switch count. It has a fixed **1,464 ns floor** and **1.5 ms cap**. Some paths,
including local kernel-thread wake admission, use the fixed **3 ms** slice instead.

The startup handoff probe does not set the adaptive slice floor. It supplies
diagnostic data and, when usable, a timing horizon for tick look-ahead.
Cake does not sample a display or game frame clock.

See [DESIGN.md](./DESIGN.md) for the policy details and construct names.

## Hardware support and limits

Topology is discovered at startup; it is not baked in from the build machine.

- Present CPU IDs must fit in 0–63 for the narrow claim, seat and per-LLC pool
  paths. A wider present-ID span uses the kernel idle picker and one wake pool.
- At most 16 LLC wake pools are represented. More LLCs collapse to one pool.
- The compiled CPU-ID span limit is 1,024, including possible CPUs. This is
  an ID-space limit, not just the number of online CPUs.
- Missing or incomplete capacity/preference data retains fallback placement.
  Advertised maximum frequency is reported, not treated as a speed measurement.

Known limits include overflow in lifetime wait/run comparison products, delayed
cross-LLC service when advisory queue information is stale, and serial-handoff
eligibility based on CPU-ID span rather than online CPU count. A fixed **24 ms**
starvation fallback lets dispatch favor an unserved pool. This is a policy
constant, not a deliberate task delay or a guaranteed maximum wait; its current
tuning is not established by these docs. See
[DESIGN.md](./DESIGN.md#starvation-fallback-24-ms).

Performance depends on the workload, topology and kernel. Historical benchmark
or game results do not establish the performance of every later build.

## Verification and bug reports

Run the portable regression tests from the repository root:

```sh
cargo test --locked -p scx_cake
```

The ordinary tests do not activate the scheduler. The optional verifier-load
test is ignored by default and requires appropriate kernel support and BPF
permissions. Passing these tests does not prove live scheduling performance.

For a bug report, include the version or commit, kernel version, CPU/topology,
exact launch arguments, and relevant scheduler and kernel logs.

## Source and further reading

| File | Purpose |
|---|---|
| [src/main.rs](./src/main.rs) | Flags, toggle defaults, topology setup, attach/restart and IRQ monitoring |
| [src/bpf/cake.bpf.c](./src/bpf/cake.bpf.c) | Scheduling policy, task state, queues and service accounting |
| [src/bpf/intf.h](./src/bpf/intf.h) | Shared constants and topology limits |
| [src/core_performance.rs](./src/core_performance.rs) | Capacity and preferred-core discovery |
| [tests/cli.rs](./tests/cli.rs) | CLI regression tests without attachment |
| [DESIGN.md](./DESIGN.md) | Current policy and known limits |
| [STATE.md](./STATE.md), [docs/](./docs/README.md) | Historical research and experiment records; may describe older or rejected behavior |
| [docs/PERFORMANCE.md](./docs/PERFORMANCE.md) | Measurement background and historical results |

License: GPL-2.0-only.
