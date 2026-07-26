# CAPE-Q S1 source-only custody candidate

This directory is a quarantine surface for translating the offline CAPE-Q
proof into verifier-shaped BPF source. It is intentionally absent from
`scx_cake/build.rs`, Cargo inputs, and the production Cake BPF include graph.

`cape_qfq_s1.bpf.c` currently represents the single-domain custody and integer
lifecycle boundary:

- one 2,752-byte ARRAY value with one top-level spinlock;
- one 32-byte TASK_STORAGE record per task;
- 14 priority DSQs for sparse groups `[8..20, 22]`;
- direct-insert, auxiliary-publication, and core-commit ordering;
- packed custody epochs, counter/mask maintenance, and fail-stop overflow;
- bounded snapshot iteration and kernel-authoritative multi-CPU moves;
- task-linear logical removal/reservation before the physical move;
- synchronous `ops.dequeue()` reservation closure plus `SCX_ENQ_REENQ`
  cancellation and stable-move-failure fail-stop;
- source-ordered `runnable`, `running`, `stopping`, `quiescent`, and
  `set_weight` transitions;
- exact remaining-real-service preservation across administrative pauses;
- bounded signed Q17 task lag and Q32 aggregate virtual-time fractions; and
- a bounded active-weight denominator with exact runtime baselines;
- constant-work ER/IR/EB/IB classification, sparse eligibility movement, and
  dispatch-versus-deactivation unblock intervals; and
- work-conserving virtual-time jumps when no task is running and no queued
  group is eligible; and
- a dispatch-to-running service-custody token, including core-sched execution,
  with partial stops forced back through `ops.enqueue()` so locally retained
  tasks cannot disappear from the global service law.

The lowest eligible-ready dense group is now the source-level QFQ selector.
This is only a mechanical translation of the offline integer law; it is not a
compiler, verifier, runtime, or performance result. Continuous cgroup weights,
wrap-aware timestamps, and `exit_task` teardown remain open. Affinity-compatible
work conservation is now constructively impossible for the current finite-scan,
single-shared-DSQ representation and is an S2 affinity-visible sharding/indexing
gate. The selected offline S2 shape is a canonical topology-cover ordered ticket
index plus a single-entry per-CPU staging handoff; it is intentionally not
encoded in this S1 file. The source encodes the offline task-linear reservation
law, but it has not been compiled, verifier-loaded, or exercised at runtime.
`CAPEQ_POLICY_COMPLETE`, verifier-load authority, runtime authority, score
authority, and promotion authority are all false.

No build, verifier load, scheduler activation, or benchmark should use this
directory until a receipt-producing builder exists and the repository's
execution quarantine is lifted.
