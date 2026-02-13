---
title: Simulate cpufreq / performance scaling
status: open
priority: 2
issue_type: feature
created_at: 2026-02-13T13:04:22.695345080+00:00
updated_at: 2026-02-13T13:07:58.514732120+00:00
---

# Description

COSMOS has dynamic CPU frequency scaling (cpufreq_enabled=false disables this).
When enabled:

- update_cpu_load() tracks CPU utilization with EWMA smoothing
- update_cpufreq() sets CPU performance level via scx_bpf_cpuperf_set
- Performance levels affect effective throughput (higher perf = more work done
  per unit time)
- Hysteresis prevents rapid frequency switching

Work needed:
- Model CPU performance levels in SimCpu (current perf level, capacity)
- Make scx_bpf_cpuperf_set actually record the perf level (currently no-op)
- Optionally model the effect of perf scaling on task execution speed
- Add COSMOS test config with cpufreq_enabled=true
- Verify update_cpu_load and update_cpufreq paths are exercised
