# scx_wd40

An experimental fork of the scx_rusty scheduler that uses BPF arenas to simplify scheduler development. Found in the main [sched_ext](https://github.com/sched-ext/scx/tree/main) repository. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

A multi-domain, BPF / user space hybrid scheduler. The BPF portion of the
scheduler does a simple round robin in each domain, and the user space portion
(written in Rust) calculates the load factor of each domain, and informs BPF of
how tasks should be load balanced accordingly.

## Goals

This scheduler ultimately aims to demonstrate how to build modular BPF schedulers
to enable easy code reuse between scheduler codebases. The main way of achieving
this is through the use of BPF arenas that make it possible to directly share memory
between the userspace and kernel scheduler components. This in turn lets us offload
most of the complexity of the scheduler to userspace. Userspace components can be
more easily combined, as opposed to scheduler BPF methods that are often mutually
exclusive.

## Production Ready?

No. This scheduler heavily uses BPF arenas and as such routinely requires a 
bleeding-edge kernel toolchain to even run and verify.
