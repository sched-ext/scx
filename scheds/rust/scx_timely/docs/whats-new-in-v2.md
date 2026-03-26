# What's New in v2

v2 introduces **pressure-aware load-balancing** - a Swift-influenced evolution where sustained delay pressure drives scheduler-level policy shifts.

## Core Change: Expand/Contract Mode

The scheduler now switches between two modes based on system-wide pressure:

### Contract Mode (Locality-First)
- **When**: Low delay pressure (system below expand threshold)
- **Behavior**: Favor keeping work close to the favored CPU set
- **Use case**: Interactive workloads, light background work

### Expand Mode (Balance-First)
- **When**: Sustained delay pressure (system above expand threshold)
- **Behavior**: Skip locality fallback, dispatch directly to shared queues for better load distribution
- **Exception**: Wake-heavy tasks (audio/interactive) preserve locality even in expand mode to prevent audio crackling
- **Use case**: Higher saturation, heavy multi-threaded work

### Hysteresis
- Enter expand at 75% (desktop default)
- Exit expand at 50% (desktop default)
- This prevents rapid oscillation around the boundary

## Per-Task Pressure Mode (from earlier v2)

v2 also retains per-task pressure mode tracking:
- `v2_pressure_enter_streak`: Consecutive delay-pressured samples to enter
- `v2_pressure_exit_streak`: Consecutive recovered samples to exit

This is orthogonal to global expand/contract mode.

## Mode-Specific Settings

| Mode | Enter | Exit | Expand | Contract |
|------|-------|------|--------|----------|
| Desktop | 3 | 3 | 75% | 50% |
| Powersave | 4 | 4 | 65% | 40% |
| Server | 2 | 2 | 80% | 55% |

Powersave is more conservative (harder to enter expand).
Server is more aggressive (easier to enter expand).

## New Metrics

- `v2exp`: Shared dispatches while in expand mode
- `v2con`: Shared dispatches while in contract mode
- `v2pme`, `v2pmx`, `v2pms`: Pressure mode entries, exits, samples

## Design Inspiration

- **TIMELY**: Delay as the main control signal
- **Swift**: Delay targets driving clear policy shifts
- **Shenango**: Saturation-driven CPU spreading

See [design-vs-bpfland.md](design-vs-bpfland.md) for line-by-line code reference.
