SCHED_EXT SCHEDULERS
====================

# Introduction

This directory contains the repo's schedulers.

Some of these schedulers are simply examples of different types of schedulers
that can be built using `sched_ext`. They can be loaded and used to schedule on
your system, but their primary purpose is to illustrate how various features of
`sched_ext` can be used.

Other schedulers are actually performant, production-ready schedulers. That is,
for the correct workload and with the correct tuning, they may be deployed in a
production environment with acceptable or possibly even improved performance.
Some of the examples could be improved to become production schedulers.

Please see the following `README` files for details on each of the various types
of schedulers:

- [`rust`](rust/README.md) describes all of the schedulers with `Rust`
  user space components.


# Note on C schedulers

This directory previously also held C schedulers for illustration purposes. These
schedulers are now found only in the Linux kernel repository in
[`tools/sched_ext`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/sched_ext).
Each C scheduler's purpose was to demonstrate a single technique for development,
often BPF-related. The C schedulers were kept synced between upstream and this
repository.

As the ecosystem has matured these schedulers have been superseded by those in the
`rust/` directory, many of which are production-ready. These schedulers better represent
modern `sched_ext` codebases and are a more appropriate starting point for newcomers.
The build system and surrouding crates ecosystem is also geared towards Rust schedulers.
As a result, the C schedulers are no longer mirrored here and are only available
from the kernel source.
