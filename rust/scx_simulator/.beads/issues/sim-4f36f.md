---
title: Simulate performance counters (PMU events)
status: open
priority: 2
issue_type: feature
depends_on:
  sim-ea456: related
created_at: 2026-02-13T13:04:24.436408933+00:00
updated_at: 2026-02-13T13:07:58.514943617+00:00
---

# Description

COSMOS uses hardware performance counters to classify tasks as "event-heavy"
(perf_enabled=false disables this). When enabled:

- start_counters() / stop_counters() bracket task execution to measure PMU events
- is_event_heavy() classifies tasks based on event rates
- pick_least_busy_event_cpu() routes event-heavy tasks to less loaded CPUs
- cosmos_select_cpu and cosmos_enqueue have perf-specific dispatch paths

Work needed:
- Model per-task PMU event counters (simulated instruction counts, cache misses)
- Implement bpf_perf_event_read_value with simulated values (currently macro stub)
- Add synthetic workload profiles (compute-bound vs memory-bound)
- Add COSMOS test config with perf_enabled=true
- Verify event-heavy classification and dispatch paths are exercised

This feature is coupled with cpufreq and benefits from having that done first.
