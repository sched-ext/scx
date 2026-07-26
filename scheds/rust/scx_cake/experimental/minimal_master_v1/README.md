# Minimal master v1

Status: isolated source candidate; standalone Clang/BPF compilation passed.
No integrated loader build, verifier, runtime, score, or promotion authority.

This candidate tests the lowest-complexity interpretation of the corpus-derived
master law:

```text
key(p, c) = weighted_service(p) + placement_cost(p, c) - bounded_lag_credit(p)
```

The terms collapse onto existing kernel state:

- `weighted_service`: `p->scx.dsq_vtime`, charged from actual runtime;
- `placement_cost`: `scx_bpf_select_cpu_dfl()`, which preserves warm placement
  while selecting an affinity-compatible idle CPU;
- `bounded_lag_credit`: clamp enqueue vtime to at most one slice behind the
  global service frontier.

All saturated work uses one global vtime DSQ. Idle placement direct-dispatches.
No task storage, classifier, predictive estimator, topology scan, qmark,
overflow queue, telemetry, or configurable policy branch is present.

The candidate is intentionally absent from `build.rs` and the production BPF
include graph. The first standalone compile emitted
`target/candidate_builds/minimal_master_v1/source_only/minimal_master_v1.bpf.o`;
that object is static cost evidence only. Integrated build, verifier, and exact
receipt gates remain before any live comparison is considered.
