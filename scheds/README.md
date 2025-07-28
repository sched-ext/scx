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
- [`c`](c/README.md) describes all of the schedulers with `C` user space
  components.

## Note on syncing

Note that there is a [`sync-to-kernel.sh`](sync-to-kernel.sh) script in this
directory. This is used to sync any changes to the specific schedulers
with the Linux kernel tree. If you've made any changes to a scheduler in please
use the script to synchronize with the `sched_ext` Linux kernel tree:

```shell
$ ./sync-to-kernel.sh /path/to/kernel/tree
```
