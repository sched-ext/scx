# scx_flow

## What

scx_flow orders tasks by virtual deadline using per-CPU arena binary search trees (bounded at depth 32 with right-chained ties in insertion order) plus one fallback FIFO DSQ. Running tasks pay for burnt time scaled by nice weight. Unpredicted tasks run pure EEVDF with a 1ms slice quantum and bounded virtual lag credit. Steady predicted tasks (tracked via shift-only EWMA over an 8-slot run history ring) receive a custom slice quantum [62.5us, 1ms] and an EEVDF virtual deadline complemented by Highest Response Ratio Next (HRRN) wait-over-service attenuation. Placement prefers idle cores across cache tiers (L1 > L2 > L3, breaking ties by larger cache size buckets) and drains in the same topological order. Wakeups ramp idle targets to max frequency before kicking and use guarded preemption (gated by deadline gap, minimum runtime granularity, and remaining slice tail) at most once per run.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
