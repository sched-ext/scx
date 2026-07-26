# CAPE-Q S2 ticket-container source shape

This directory is a quarantined source-only translation of the S2 canonical
topology-cover visibility container. It is intentionally absent from Cake's
`build.rs`, Cargo inputs, production BPF include graph, and scheduler ops.

The proposed primitive uses one distinct arena ATQ node per cover ticket and
keeps task custody singular. It does **not** call public `scx_atq_peek()` for
ephemeral tickets because that API returns an arena pointer after releasing the
queue lock. Instead it encodes:

- a scalar-only head snapshot copied while the ATQ lock is held;
- a second lock acquisition which claims only the same head, allocator
  generation, task cookie, task epoch, node, group, and order key;
- exact embedded-rbtree-node removal;
- `LINKED -> CLAIMED` ownership before an arena pointer can escape the lock;
- owner detach and claimant release as a two-party reclamation protocol;
- no recycle while a claim exists;
- allocator-generation rejection of a snapshot after slot reuse; and
- fail-stop on lock, counter, identity, or lifecycle corruption.

This file is only the ordered ticket lifetime/removal primitive. Canonical mask
decomposition, per-node CAPE-Q group composition, unique/wrap-safe order-key
encoding, task-state CAS, per-CPU staging DSQs, scheduler callbacks, userspace
arena initialization, build linkage, and teardown are deliberately not claimed
complete.

No build, verifier load, scheduler activation, benchmark, or performance claim
may use this directory while the execution quarantine is active.

