# v2 Design Goals

v2 explores whether sustained delay pressure should influence scheduler-level policy, not just slice gain.

## Primary Goal

Improve partial-saturation behavior:
- When is locality-first appropriate?
- When should the scheduler expand more aggressively?
- How to handle asymmetric CPU topologies?

## Design Principles

1. **Delay stays the main control signal** - per TIMELY
2. **Clean policy shift, not micro-heuristics** - per Swift
3. **Bounded and reversible** - changes should be measurable and safe

## What v2 Adds

- **Global pressure tracking**: System-wide EMA of delay-pressured tasks
- **Expand/Contract mode**: Scheduler switches policy based on sustained pressure
- **Hysteresis**: Different enter/exit thresholds prevent oscillation

## What v2 Avoids

- Hard partitioning
- Large affinity rewrites
- Chains of tiny benchmark-sensitive heuristics
- Claims that noise-heavy single runs prove architecture

## Success Criteria

- Lower elapsed time without loss of responsiveness
- Lower queue pressure under load
- Cleaner explanation of scheduling behavior

## Reference Papers

- **TIMELY**: RTT-based congestion control for datacenter
- **Swift**: Delay is simple and effective
- **Shenango**: High CPU efficiency for latency-sensitive workloads
