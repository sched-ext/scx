# Sched_ext Schedulers and Tools

[sched_ext](https://github.com/sched-ext/scx) is a Linux kernel feature
which enables implementing kernel thread schedulers in BPF and dynamically
loading them. This repository contains various scheduler implementations and
support utilities.

sched_ext enables safe and rapid iterations of scheduler implementations
radically widening the scope of scheduling strategies that can be
experimented with and deployed even in massive and complex production
environments.

- The [scx_layered case
  study](https://github.com/sched-ext/scx/blob/case-studies/case-studies/scx_layered.md)
  concretely demonstrates the power and benefits of sched_ext.
- For more detailed high-level discussion, please refer to the [overview
  document](OVERVIEW.md).

While the kernel feature is not upstream yet, we believe sched_ext has a
reasonable chance of landing upstream in the foreseeable future. Both Meta
and Google are fully committed to sched_ext and Meta is in the process of
mass production deployment. See (#kernel-feature-status) for more details.

In all example shell commands, `$SCX` refers to the root of this repository.


## Getting Started

All that's necessary for running sched_ext schedulers is a kernel with
sched_ext support and the scheduler binaries along with the libraries they
depend on. Switching to a sched_ext scheduler is as simple as running a
sched_ext binary:

```
root@test ~# head -2 /sys/kernel/debug/sched/ext
ops                           :
enabled                       : 0
root@test ~# scx_simple
local=1 global=0
local=74 global=15
local=78 global=32
local=82 global=42
local=86 global=54
^Zfish: Job 1, 'scx_simple' has stopped
root@test ~# head -2 /sys/kernel/debug/sched/ext
ops                           : simple
enabled                       : 1
root@test ~# fg
Send job 1 (scx_simple) to foreground
local=635 global=179
local=696 global=192
^CEXIT: BPF scheduler unregistered
```

[`scx_simple`](https://github.com/sched-ext/scx/blob/main/scheds/kernel-examples/scx_simple.bpf.c)
is a very simple global vtime scheduler which can behave acceptably on CPUs
with a simple topology (single socket and single L3 cache domain).

Above, we switch the whole system to use `scx_simple` by running the binary,
suspend it with `ctrl-z` to confirm that it's loaded, and then switch back
to the kernel default scheduler by terminating the process with `ctrl-c`.
For `scx_simple`, suspending the scheduler process doesn't affect scheduling
behavior because all that the userspace component does is printing
statistics. This doesn't hold for all schedulers.

In addition to terminating the program, there are two more ways to disable a
sched_ext scheduler - `sysrq-S` and the watchdog timer. Ignoring kernel
bugs, the worst damage a sched_ext scheduler can do to a system is starving
some threads until the watchdog timer triggers.

As illustrated, once the kernel and binaries are in place, using sched_ext
schedulers is straightforward and safe. While developing and building
schedulers in this repository isn't complicated either, sched_ext makes use
of many new BPF features, some of which require build tools which are newer
than what many distros are currently shipping. This should become less of an
issue in the future. For the time being, the following custom repositories
are provided for select distros.

### Arch Linux

#### Adding the Repository

Import and locally sign the packager's GPG key. This can be skipped if the
signature checking is disabled when adding the repo.

```
pacman-key --recv-keys 697C63013E65270255EBC2608744DC1EB26B5A9A
pacman-key --lsign-key 697C63013E65270255EBC2608744DC1EB26B5A9A
```

Add the following custom repository section to `/etc/pacman.conf`.

```
[scx]
Server = https://github.com/sched-ext/scx-packaging-arch/releases/download/repo
```

If you haven't imported the GPG key, append the following line.

```
SigLevel = Never
```

#### Installing the Kernel and Schedulers

```
pacman -Sy scx/linux scx/libbpf scx/scx-scheds
```

Note that the above replaces the default kernel and libbpf packages. The
latter won't be unnecessary once libbpf is updated to >=1.3.0 in the Arch
repository. After a reboot, the scheduler binaries `/usr/bin/scx_*` should
be usable.

#### Setting Up Dev Environment

In addition to the packages from the previous step, install the followings.

```
pacman -Sy scx/linux-headers scx/clang-github-bin meson cargo bpf pahole
```

`clang-github-bin` is necessary because the recommended `clang` version is
17 while Arch is still shipping 16. It's built from the [AUR
package](https://aur.archlinux.org/packages/clang-github-bin) of the same
name. This is a repackage of the official LLVM release in `.deb` format.


## Repository Structure

```
scx
|-- scheds               : Sched_ext scheduler implementations
|   |-- include          : Shared BPF and user C include files including vmlinux.h
|   |-- kernel-examples  : Example schedulers from kernel tree (tools/sched_ext)
|   \-- rust-user        : Schedulers that use Rust for userspace component
\-- rust                 : Rust support code
    \-- scx_utils        : Common utility library for rust-user schedulers
```


## Build & Install

`meson` is the main build system but each Rust sub-project is its own
self-contained cargo project and can be built and published separately. The
followings are the dependencies and version requirements.

- `meson`: >=1.2, build scripts under `meson-scripts/` use `bash` and
  standard utilities including `awk`.
- `clang`: >=16 required, >=17 recommended
- `libbpf`: >=1.2.2 required, >=1.3 recommended (`RESIZE_ARRAY` support is
  new in 1.3)
- Rust toolchain: >=1.72
- `libelf`, `libz`, `libzstd` if linking against staic `libbpf.a`


### Setting Up and Building

`meson` always uses a separate build directory. Running the following
commands in the root of the tree builds and installs all schedulers under
`~/bin`.

```
$ cd $SCX
$ meson setup build --prefix ~
$ cd build
$ meson compile
$ meson install
```

Note that `meson compile` step is not strictly necessary as `install`
implies `compile`. The above also will build debug binaries with
optimizations turned off, which is useful for development but they aren't
optimized and big. For actual use you want to build release binaries.
`meson` uses `-D` argument to specify build options. The configuration
options can be specified at `setup` time but can also be changed afterwards
and `meson` will do the right thing. To switch to release builds, run the
following in the build directory and then compile and install again.

```
$ meson configure -Dbuildtype=release
```

Running `meson configure` without any argument shows all current build
options. For more information on `meson` arguments and built-in options,
please refer to `meson --help` and its
[documentation](https://mesonbuild.com/Builtin-options.html).


### Building Specific Schedulers and Binary Locations

If you just want to build a subset of schedulers, you can specify the
scheduler names as arguments to `meson compile`. For example, if we just
want to build the simple example scheduler
`scheds/kernel-examples/scx_simple` and the Rust userspace scheduler
`scheds/rust-user/scx_rusty`:

```
$ cd $SCX
$ meson setup build -Dbuildtype=release
$ cd build
$ meson compile -v scx_simple scx_rusty
```

You can also specify `-v` if you want to see the commands being used:

```
$ meson compile -v scx_pair
```

For C userspace schedulers such as the ones under `scheds/kernel-examples`,
the built binaries are located in the same directory under the build root.
For example, here, the `scx_simple` binary can be found at
`$SCX/build/scheds/kernel-examples/scx_simple`.

For Rust userspace schedulers such as the ones under `scheds/rust-user`, the
same directory under the build root is used as the cargo build target
directory. Thus, here, the `scx_rusty` binary can be found at
`$SCX/build/scheds/rust-user/scx_rusty/release/scx_rusty`.


### SCX specific build options

While the default options should work in most cases, it may be desirable to
override some of the toolchains and dependencies - e.g. to directly use
`libbpf` built from the kernel source tree. The following `meson` build
options can be used in such cases.

- `bpf_clang`: `clang` to use when compiling `.bpf.c`
- `bpftool`: `bpftool` to use when generating `.bpf.skel.h`
- `libbpf_a`: Static `libbpf.a` to use
- `libbpf_h`: `libbpf` header directories, only meaningful with `libbpf_a` option
- `cargo`: `cargo` to use when building rust sub-projects

For example, let's say you want to use `bpftool` and `libbpf` shipped in the
kernel tree located at `$KERNEL`. We need to build `bpftool` in the kernel
tree first, set up SCX build with the related options and then build &
install.

```
$ cd $KERNEL
$ make -C tools/bpf/bpftool
$ cd $SCX
$ BPFTOOL=$KERNEL/tools/bpf/bpftool
$ meson setup build -Dbuildtype=release -Dprefix=~/bin \
    -Dbpftool=$BPFTOOL/bpftool \
    -Dlibbpf_a=$BPFTOOL/libbpf/libbpf.a \
    -Dlibbpf_h=$BPFTOOL/libbpf/include
$ cd build
$ meson install
```

Note that we use `libbpf` which was produced as a part of `bpftool` build
process rather than buliding `libbpf` directly. This is necessary because
`libbpf` header files need to be installed for them to be in the expected
relative locations.


### Working with Rust Sub-projects

Each Rust sub-project is its own self-contained cargo project. When buildng
as a part of this repository, `meson` invokes `cargo` with the appropriate
options and environment variables to sync the build environment. When
building separately by running `cargo build` directly in a sub-project
directory, it will automatically figure out build environment. Please take a
look at the
[`scx_utils::BpfBuilder`](https://docs.rs/scx_utils/latest/scx_utils/struct.BpfBuilder.html)
documentation for details.

For example, the following builds and runs the `scx_rusty` scheduler:

```
$ cd $SCX/scheds/rust-user/scx_rusty
$ cargo build --release
$ cargo run --release
```

Here too, the `build` step is not strictly necessary as it's implied by
`run`.

Note that Rust userspace schedulers are published on `crates.io` and can be
built and installed without cloning this repository as long as the necessary
toolchains are available. Simply run:

```
$ cargo install scx_rusty
```

and `scx_rusty` will be built and installed as `~/.cargo/bin/scx_rusty`.


## Kernel Feature Status

The kernel feature is not yet upstream and can be found in the
[sched_ext](https://github.com/sched-ext/sched_ext) repository. The
followings are important branches:

- [`sched_ext`](https://github.com/sched-ext/sched_ext): The main development
  branch. This branch periodically pulls from the
  [bpf-next](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/)
  tree to stay in sync with the kernel and BPF developments.
- `sched_ext-release-*`: sched_ext backports on top of released kernels. We
  plan to maintain backports for a few recent kernel releases until
  sched_ext is merged upstream. Currently maintained backports:
  - [`sched_ext-release-v6.6`](https://github.com/sched-ext/sched_ext/tree/sched_ext-release-v6.6)
- `sched_ext-vN`: Patchsets posted upstream. The v4 LKML thread has
  high-level discussions.
  - [RFC](https://github.com/htejun/sched_ext):
    [LMKL thread](http://lkml.kernel.org/r/20221130082313.3241517-1-tj@kernel.org)
  - [`sched_ext-v2'](https://github.com/sched-ext/sched_ext/tree/sched_ext-v2):
    [LKML thread](http://lkml.kernel.org/r/20230128001639.3510083-1-tj@kernel.org)
  - [`sched_ext-v3'](https://github.com/sched-ext/sched_ext/tree/sched_ext-v3):
    [LKML thread](http://lkml.kernel.org/r/20230317213333.2174969-1-tj@kernel.org)
  - [`sched_ext-v4'](https://github.com/sched-ext/sched_ext/tree/sched_ext-v4):
    [LKML thread](http://lkml.kernel.org/r/20230711011412.100319-1-tj@kernel.org)
  - [`sched_ext-v5'](https://github.com/sched-ext/sched_ext/tree/sched_ext-v5):
    [LKML thread](http://lkml.kernel.org/r/20231111024835.2164816-1-tj@kernel.org)


## Getting in Touch

We aim to build a friendly and approachable community around sched_ext. You
can reach us through the following channels:

- github: https://github.com/sched-ext/scx
- Slack: https://schedextworkspace.slack.com
- Reddit: https://reddit.com/r/sched_ext

We also hold weekly office hours every monday. Please see the #office-hours
channel on slack for details.
