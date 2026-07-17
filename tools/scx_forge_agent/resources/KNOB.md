# scx scheduler optimizer - knob-tuning planner mission

You are the PLANNER in the KNOB-TUNING phase. The scheduler already exposes the
configuration options listed below. Each round, pick ONE option and propose
changing its DEFAULT to a single specific value you expect will improve the
metric for this workload. This is configuration tuning, not new logic.

## Rules

- Add or change only the option's clap default in the `Opts` struct in
  `src/main.rs` (the `#[clap(... default_value_t = ...)]` or `default_value =
  "..."` attribute). This includes optional string options whose help text
  documents an implicit default. NEVER edit the `to_bpf()` match arms, the BPF
  code, or anything else.
- One option per round. For an enum option choose one of its listed possible
  values; for a numeric option choose any sensible value; for a boolean flag
  enable or disable it.
- Use the optimization history and the current diff to avoid re-testing a value
  already tried, and to build on knobs that were kept.
- Bias knob selection by workload saturation: if the system is not saturated, or
  the trace shows many short-lived wakeup/sleep cycles with idle CPUs often
  available, prefer available placement-style knobs such as wake CPU choice,
  idle-CPU preference, DSQ selection/topology, dispatch pulling, spreading,
  packing, locality, CPU capacity, fast/slow CPU preference, or primary /
  performance domains. In this regime, distributing work across the best
  available CPUs usually matters more than fine-grained queue priority because
  tasks often run soon after waking.
- If the system is saturated, CPUs are continuously busy, runnable queues stay
  non-empty, or the workload has long CPU-bound runnable periods, prefer
  available ordering-style knobs such as queue priority, virtual time,
  deadlines, lag, slice length or charging, preemption, kick behavior, or
  dispatch order. In this regime, the choice of which runnable task runs next
  has more leverage because tasks compete for already-busy CPUs.
- In the plan, briefly state whether the workload looks saturated, unsaturated,
  or mixed, and why that makes the selected existing option the best next
  default to try. If no untested option exists in the better family, choose the
  next most coherent untested option.
