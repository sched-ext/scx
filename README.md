# Sched_ext Schedulers and Tools

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/sched-ext/scx)

[`sched_ext`](https://github.com/sched-ext/scx) is a Linux kernel feature
which enables implementing kernel thread schedulers in BPF and dynamically
loading them. This repository contains various scheduler implementations and
support utilities.

`sched_ext` enables safe and rapid iterations of scheduler implementations, thus
radically widening the scope of scheduling strategies that can be experimented
with and deployed; even in massive and complex production environments.

You can find more information, links to blog posts and recordings, in the [wiki](https://github.com/sched-ext/scx/wiki).
The following are a few highlights of this repository.

- The [`scx_layered` case
  study](https://github.com/sched-ext/scx/blob/case-studies/case-studies/scx_layered.md)
  concretely demonstrates the power and benefits of `sched_ext`.
- For a high-level but thorough overview of the `sched_ext` (especially its
  motivation), please refer to the [overview document](OVERVIEW.md).
- For a description of the schedulers shipped with this tree, please refer to
  the [schedulers document](scheds/README.md).
- The following video is the [`scx_rustland`](https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_rustland)
  scheduler which makes most scheduling decisions in userspace `Rust` code showing
  better FPS in terraria while kernel is being compiled. This doesn't mean that
  `scx_rustland` is a better scheduler but does demonstrate how safe and easy it is to
  implement a scheduler which is generally usable and can outperform the default
  scheduler in certain scenarios.

[scx_rustland-terraria](https://github.com/sched-ext/scx/assets/1051723/42ec3bf2-9f1f-4403-80ab-bf5d66b7c2d5)

`sched_ext` is supported by the upstream kernel starting from version 6.12. Both
Meta and Google are fully committed to `sched_ext` and Meta is in the process of
mass production deployment. See [`#kernel-feature-status`](#kernel-feature-status) for more details.

In all example shell commands, `$SCX` refers to the root of this repository.

## Getting Started

All that's necessary for running `sched_ext` schedulers is a kernel with
`sched_ext` support and the scheduler binaries along with the libraries they
depend on. Switching to a `sched_ext` scheduler is as simple as running a
`sched_ext` binary:

```bash
root@test ~# cat /sys/kernel/sched_ext/state /sys/kernel/sched_ext/*/ops 2>/dev/null
disabled
root@test ~# scx_simple
local=1 global=0
local=74 global=15
local=78 global=32
local=82 global=42
local=86 global=54
^Zfish: Job 1, 'scx_simple' has stopped
root@test ~# cat /sys/kernel/sched_ext/state /sys/kernel/sched_ext/*/ops 2>/dev/null
enabled
simple
root@test ~# fg
Send job 1 (scx_simple) to foreground
local=635 global=179
local=696 global=192
^CEXIT: BPF scheduler unregistered
```

[`scx_simple`](https://github.com/sched-ext/scx/blob/main/scheds/c/scx_simple.bpf.c)
is a very simple global vtime scheduler which can behave acceptably on CPUs
with a simple topology (single socket and single L3 cache domain).

Above, we switch the whole system to use `scx_simple` by running the binary,
suspend it with `ctrl-z` to confirm that it's loaded, and then switch back
to the kernel default scheduler by terminating the process with `ctrl-c`.
For `scx_simple`, suspending the scheduler process doesn't affect scheduling
behavior because all that the userspace component does is print statistics.
This doesn't hold for all schedulers.

In addition to terminating the program, there are two more ways to disable a
`sched_ext` scheduler - `sysrq-S` and the watchdog timer. Ignoring kernel
bugs, the worst damage a `sched_ext` scheduler can do to a system is starving
some threads until the watchdog timer triggers.

As illustrated, once the kernel and binaries are in place, using `sched_ext`
schedulers is straightforward and safe. While developing and building
schedulers in this repository isn't complicated either, `sched_ext` makes use
of many new BPF features, some of which require build tools which are newer
than what many distros are currently shipping. This should become less of an
issue in the future. For the time being, the following custom repositories
are provided for select distros.

## Install Instructions by Distro

- [Ubuntu](INSTALL.md#ubuntu)
- [Arch Linux](INSTALL.md#arch-linux)
- [Gentoo Linux](INSTALL.md#gentoo-linux)
- [Fedora](INSTALL.md#fedora)
- [Nix](INSTALL.md#nix)
- [openSUSE Tumbleweed](INSTALL.md#opensuse-tumbleweed)

## Repository Structure

```
scx
|-- scheds               : Sched_ext scheduler implementations
|   |-- include          : Shared BPF and user C include files including vmlinux.h
|   |-- c                : Example schedulers - userspace code written C
|   \-- rust             : Example schedulers - userspace code written Rust
\-- rust                 : Rust support code
    \-- scx_utils        : Common utility library for Rust schedulers
```

## Build & Install

This repository provides two build systems:

- **C schedulers**: Use `make`
- **Rust schedulers**: Use `cargo`

**Dependencies:**

- `clang`: >=16 required, >=17 recommended
- `libbpf`: >=1.2.2 required, >=1.3 recommended
- `bpftool`: Usually available in `linux-tools-common` or similar packages
- `libelf`, `libz`, `libzstd`: For linking against libbpf
- `pkg-config`: For finding system libraries
- `Rust` toolchain: >=1.82

The kernel has to be built with the following configuration:

- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_JIT=y`
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_JIT_ALWAYS_ON=y`
- `CONFIG_BPF_JIT_DEFAULT_ON=y`
- `CONFIG_SCHED_CLASS_EXT=y`

The [`scx/kernel.config`](./kernel.config) file includes all required and other recommended options for using `sched_ext`.
You can append its contents to your kernel `.config` file to enable the necessary features.

### Building and Installing

#### C Schedulers

```shell
$ cd $SCX
$ make all                          # Build all C schedulers
$ make install INSTALL_DIR=~/bin    # Install to custom directory
```

#### Rust Schedulers

```shell
$ cd $SCX
$ cargo build --release                 # Build all Rust schedulers
$ cargo build --release -p scx_rusty    # Build specific scheduler
```

Rust schedulers are also published on `crates.io`:

```shell
$ cargo install scx_rusty
```

See: [CARGO BUILD](CARGO_BUILD.md)

### Binary Locations

- **C schedulers**: `build/scheds/c/scx_simple`
- **Rust schedulers**: `target/release/scx_rusty`

### Environment Variables

Both `make` and `cargo` support these environment variables for BPF compilation:

- `BPF_CLANG`: The clang command to use. (Default: `clang`)
- `BPF_CFLAGS`: Override all compiler flags for BPF compilation
- `BPF_BASE_CFLAGS`: Override base compiler flags (non-include)
- `BPF_EXTRA_CFLAGS_PRE_INCL`: Extra flags before include paths
- `BPF_EXTRA_CFLAGS_POST_INCL`: Extra flags after include paths

C schedulers only:

- `BPFTOOL`: The bpftool command to use. (Default: `bpftool`)
- `CC`: The C compiler to use. (Default: `cc`)

**Examples:**

```shell
# Use specific clang version for C schedulers
$ BPF_CLANG=clang-17 make all

# Use specific clang version for Rust schedulers
$ BPF_CLANG=clang-17 cargo build --release

# Use clang for C compilation and system bpftool
$ CC=clang BPFTOOL=/usr/bin/bpftool make all
```

## Checking scx_stats

With the implementation of `scx_stats`, schedulers no longer display statistics by default. To display the statistics from the currently running scheduler, a manual user action is required.
Below are examples of how to do this.

- To check the scheduler statistics, use the

```shell
$ scx_SCHEDNAME --monitor $INTERVAL
```

for example `0.5` - this will print the output every half a second

```shell
$ scx_bpfland --monitor 0.5
```

Some schedulers may implement different or multiple monitoring options. Refer to `--help` of each scheduler for details.
Most schedulers also accept `--stats $INTERVAL` to print the statistics directly from the scheduling instance.

#### Examples

- `scx_bpfland`

```shell
$ scx_bpfland --monitor 5
[scx_bpfland] tasks -> run:  3/4  int: 2  wait: 3    | nvcsw: 3    | dispatch -> dir: 0     prio: 73    shr: 9
[scx_bpfland] tasks -> run:  4/4  int: 2  wait: 2    | nvcsw: 3    | dispatch -> dir: 1     prio: 3498  shr: 1385
[scx_bpfland] tasks -> run:  4/4  int: 2  wait: 2    | nvcsw: 3    | dispatch -> dir: 1     prio: 2492  shr: 1311
[scx_bpfland] tasks -> run:  4/4  int: 2  wait: 3    | nvcsw: 3    | dispatch -> dir: 2     prio: 3270  shr: 1748
```

- `scx_rusty`

```shell
$ scx_rusty --monitor 5
###### Thu, 29 Aug 2024 14:42:37 +0200, load balance @  -265.1ms ######
cpu=   0.00 load=    0.17 mig=0 task_err=0 lb_data_err=0 time_used= 0.0ms
tot=     15 sync_prev_idle= 0.00 wsync= 0.00
prev_idle= 0.00 greedy_idle= 0.00 pin= 0.00
dir= 0.00 dir_greedy= 0.00 dir_greedy_far= 0.00
dsq=100.00 greedy_local= 0.00 greedy_xnuma= 0.00
kick_greedy= 0.00 rep= 0.00
dl_clamp=33.33 dl_preset=93.33
slice=20000us
direct_greedy_cpus=f
  kick_greedy_cpus=f
  NODE[00] load=  0.17 imbal=  +0.00 delta=  +0.00
   DOM[00] load=  0.17 imbal=  +0.00 delta=  +0.00
```

- `scx_lavd`

```shell
$ scx_lavd --monitor 5
|       12 |      1292 |         3 |         1 |      8510 |   37.6028 |   2.42068 |  99.1304 |      100 |  62.8907 |      100 |      100 |  62.8907 | performance |          100 |            0 |            0 |
|       13 |      2208 |         3 |         1 |      6142 |   33.3442 |   2.39336 |  98.7626 |      100 |  60.2084 |      100 |      100 |  60.2084 | performance |          100 |            0 |            0 |
|       14 |       941 |         3 |         1 |      5223 |    31.323 |     1.704 |   99.215 |  100.019 |  59.1614 |      100 |  100.019 |  59.1614 | performance |          100 |            0 |            0 |
```

- `scx_rustland`

```shell
$ scx_rustland --monitor 5
[RustLand] tasks -> r:  1/4  w: 3 /3  | pf: 0     | dispatch -> u: 4     k: 0     c: 0     b: 0     f: 0     | cg: 0
[RustLand] tasks -> r:  1/4  w: 2 /2  | pf: 0     | dispatch -> u: 28385 k: 0     c: 0     b: 0     f: 0     | cg: 0
[RustLand] tasks -> r:  0/4  w: 4 /0  | pf: 0     | dispatch -> u: 25288 k: 0     c: 0     b: 0     f: 0     | cg: 0
[RustLand] tasks -> r:  0/4  w: 2 /0  | pf: 0     | dispatch -> u: 30580 k: 0     c: 0     b: 0     f: 0     | cg: 0
[RustLand] tasks -> r:  0/4  w: 2 /0  | pf: 0     | dispatch -> u: 30824 k: 0     c: 0     b: 0     f: 0     | cg: 0
[RustLand] tasks -> r:  1/4  w: 1 /1  | pf: 0     | dispatch -> u: 33178 k: 0     c: 0     b: 0     f: 0     | cg: 0
```

## Kernel Feature Status

sched-ext has been fully upstreamed as of 6.12.

## [Breaking Changes](./BREAKING_CHANGES.md)

[A list of the breaking changes](./BREAKING_CHANGES.md) in the `sched_ext` kernel tree and the associated commits for the schedulers in this repo.

## [Developer Guide](./DEVELOPER_GUIDE.md)

Want to learn how to develop a scheduler or find some useful tools for working
with schedulers? See the developer guide for more details.

## Getting in Touch

We aim to build a friendly and approachable community around `sched_ext`. You
can reach us through the following channels:

- `GitHub`: https://github.com/sched-ext/scx
- `Discord`: https://discord.gg/b2J8DrWa7t
- `Mailing List`: sched-ext@lists.linux.dev (for kernel development)

We also hold weekly office hours every Tuesday. Please see the `#office-hours`
channel on `Discord` for details.

## Additional Resources

There are articles and videos about `sched_ext`, which helps you to explore
`sched_ext` in various ways. Following are some examples:

- [2025 Linux Plumbers Conference MC](https://lpc.events/event/19/sessions/229)
- [2024 Linux Plumbers Conference MC](https://lpc.events/event/18/sessions/192)
- [`Sched_ext` YT playlist](https://youtube.com/playlist?list=PLLLT4NxU7U1TnhgFH6k57iKjRu6CXJ3yB&si=DETiqpfwMoj8Anvl)
- [LWN: The extensible scheduler class (February, 2023)](https://lwn.net/Articles/922405/)
- [arighi's blog: Implement your own kernel CPU scheduler in Ubuntu with `sched_ext` (July, 2023)](https://arighi.blogspot.com/2023/07/implement-your-own-cpu-scheduler-in.html)
- [David Vernet's talk : Kernel Recipes 2023 - `sched_ext`: pluggable scheduling in the Linux kernel (September, 2023)](https://youtu.be/8kAcnNVSAdI)
- [Changwoo's blog: `sched_ext`: a BPF-extensible scheduler class (Part 1) (December, 2023)](https://blogs.igalia.com/changwoo/sched-ext-a-bpf-extensible-scheduler-class-part-1/)
- [arighi's blog: Getting started with `sched_ext` development (April, 2024)](https://arighi.blogspot.com/2024/04/getting-started-with-sched-ext.html)
- [Changwoo's blog: `sched_ext`: scheduler architecture and interfaces (Part 2) (June, 2024)](https://blogs.igalia.com/changwoo/sched-ext-scheduler-architecture-and-interfaces-part-2/)
- [arighi's YT channel: `scx_bpfland` Linux scheduler demo: topology awareness (August, 2024)](https://youtu.be/R-FEZOveG-I)
- [David Vernet's talk: Kernel Recipes 2024 - Scheduling with superpowers: Using `sched_ext` to get big perf gains (September, 2024)](https://youtu.be/Cy7-oqdcUCs)
- [arighi's talk: Kernel Recipes 2025 - Schedule Recipes (September, 2025)](https://youtu.be/NEwCs7EqAbU)
