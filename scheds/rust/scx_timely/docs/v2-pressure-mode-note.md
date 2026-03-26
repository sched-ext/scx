# v2 Pressure Mode Implementation

## Problem

v1 TIMELY gives excellent slice-gain control via delay feedback. But under sustained pressure, the scheduler was still making localized decisions without a clear system-wide policy shift.

## Solution: Expand/Contract Mode

### Contract (Locality-First)
- System is not saturated
- Favor keeping work on the favored CPU set
- Use locality fallback when idle-pick misses

### Expand (Balance-First)
- System is saturated (sustained delay pressure)
- Skip locality fallback, dispatch to shared queues
- Spread work to reduce queue delay
- **Exception**: Wake-heavy tasks (audio/interactive) still get locality fallback to preserve cache warmth

## Implementation

### Global Pressure Tracking

```c
// In timely_running(), update_global_pressure():
v2_global_pressure = EMA of delay-pressured tasks
v2_primary_domain_busy = nr_running / nr_online_cpus

if (!v2_expand_mode && v2_global_pressure >= v2ExpandThreshold)
    v2_expand_mode = 1;  // Enter expand

if (v2_expand_mode && v2_global_pressure < v2ContractThreshold)
    v2_expand_mode = 0;  // Exit expand
```

### Policy Decision

```c
// In timely_enqueue():
if (!should_expand_skip_locality(tctx))
    fallback_kind = locality_fallback_kind(...);

// should_expand_skip_locality() returns true (skip locality) when:
// - v2_expand_mode is active AND task is NOT wake-heavy, OR
// - Task is in pressure mode AND primary domain > 50% saturated
//
// Wake-heavy tasks (high wakeup_freq, e.g., audio/interactive) always
// get locality fallback to preserve cache locality.
```

## Thresholds

| Mode | Expand | Contract |
|------|--------|----------|
| Desktop | 75% | 50% |
| Powersave | 65% | 40% |
| Server | 80% | 55% |

## Why This Is Clean

1. **Single signal**: Delay pressure drives everything
2. **Hysteresis**: Different enter/exit thresholds prevent oscillation
3. **Bounded**: Changes are limited to dispatch path
4. **Observable**: Counters track expand vs contract behavior

## What This Is NOT

- Hard partitioning (still allows work to move)
- CPU borrowing (no CPU stealing)
- Complex isolation (simple mode flag)
