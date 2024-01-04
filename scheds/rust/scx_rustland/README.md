# scx_rustland

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_rustland is made of a BPF component (dispatcher) that implements the low
level sched-ext functionalities and a user-space counterpart (scheduler),
written in Rust, that implements the actual scheduling policy.

The BPF dispatcher is completely agnostic of the particular scheduling policy
implemented in user-space. For this reason developers that are willing to use
this scheduler to experiment scheduling policies should be able to simply
modify the Rust component, without having to deal with any internal kernel /
BPF details.

## How To Install

Available as a [Rust crate](https://crates.io/crates/scx_rustland): `cargo add scx_rustland`

## Typical Use Case

scx_rustland is designed to be "easy to read" template that can be used by any
developer to quickly experiment more complex scheduling policies, that can be
fully implemented in Rust.

## Production Ready?

Not quite. For production scenarios, other schedulers are likely to exhibit
better performance, as offloading all scheduling decisions to user-space comes
with a certain cost.

However, a scheduler entirely implemented in user-space holds the potential for
seamless integration with sophisticated libraries, tracing tools, external
services (e.g., AI), etc. Hence, there might be situations where the benefits
outweigh the overhead, justifying the use of this scheduler in a production
environment.
