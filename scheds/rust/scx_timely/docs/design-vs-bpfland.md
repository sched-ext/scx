# scx_timely v2 vs scx_timely v1

This document explains the line-by-line changes in v2 relative to the `scx_timely` v1 base (which itself is built on `scx_bpfland`).

For the full `scx_bpfland` code, see: https://github.com/sched-ext/scx/tree/main/scheds/rust/scx_bpfland

## What Stays The Same

Everything from v1 stays intact:
- TIMELY delay regions (Tlow/Thigh)
- Queue-delay and delay-gradient feedback
- Slice gain control (AIMD + HAI)
- Per-task pressure mode
- All v1 locality fallback mechanisms
- Mode-based policy surface (desktop, powersave, server)

## What v2 Adds or Changes

v2 adds **pressure-aware load-balancing** via an expand/contract mode.

## Where To Look In Code

### New v2 Configuration Variables (BPF)

[`src/bpf/main.bpf.c#L87-100`](../src/bpf/main.bpf.c#L87-100)
- Lines 87-100: v2 threshold and configuration declarations

### New v2 Global State (BPF)

[`src/bpf/main.bpf.c#L196-201`](../src/bpf/main.bpf.c#L196-201)
- Lines 196-201: v2_global_pressure, v2_expand_mode, counters

### New v2 Counters (BPF)

[`src/bpf/main.bpf.c#L178`](../src/bpf/main.bpf.c#L178)
- Line 178: nr_v2_expand_mode_dispatches, nr_v2_contract_mode_dispatches

### New v2 Functions (BPF)

[`src/bpf/main.bpf.c#L829-928`](../src/bpf/main.bpf.c#L829-928)
- Lines 829-865: `update_global_pressure()` - updates global pressure EMA and expand/contract mode
- Lines 903-905: `is_expand_mode_active()` - returns true if in expand mode
- Lines 913-928: `should_expand_skip_locality()` - core policy: returns true to skip locality fallback

### Modified Enqueue Logic (BPF)

[`src/bpf/main.bpf.c#L1485-1520`](../src/bpf/main.bpf.c#L1485-1520)
- Lines 1488-1489: Changed from `!pressure_mode_active` to `!should_expand_skip_locality(tctx)`
- Lines 1514-1519: Track expand vs contract mode dispatches

### Global Pressure Update Called (BPF)

[`src/bpf/main.bpf.c#L1721`](../src/bpf/main.bpf.c#L1721)
- Line 1721: `update_global_pressure(tctx)` called from `timely_running()`

### New v2 Rust Config (main.rs)

[`src/main.rs#L73-78`](../src/main.rs#L73-78)
- Lines 73-78: New DEFAULT_V2_EXPAND_THRESHOLD and DEFAULT_V2_CONTRACT_THRESHOLD constants

[`src/main.rs#L84-90`](../src/main.rs#L84-90)
- Lines 84-90: New fields in EffectiveConfig struct

[`src/main.rs#L104-108`](../src/main.rs#L104-108)
- Lines 104-108: New fields in Desktop mode defaults

[`src/main.rs#L186-191`](../src/main.rs#L186-191)
- Lines 186-191: New fields in Powersave mode defaults

[`src/main.rs#L222-227`](../src/main.rs#L222-227)
- Lines 222-227: New fields in Server mode defaults

[`src/main.rs#L293-300`](../src/main.rs#L293-300)
- Lines 293-300: CLI override logic for new thresholds

[`src/main.rs#L495-510`](../src/main.rs#L495-510)
- Lines 495-510: New CLI options --v2-expand-threshold and --v2-contract-threshold

[`src/main.rs#L778-781`](../src/main.rs#L778-781)
- Lines 778-781: rodata wiring for v2ExpandThreshold and v2ContractThreshold

[`src/main.rs#L705-728`](../src/main.rs#L705-728)
- Lines 705-728: Log output includes new v2 thresholds

[`src/main.rs#L1070-1074`](../src/main.rs#L1070-1074)
- Lines 1070-1074: Metrics include nr_v2_expand_mode_dispatches and nr_v2_contract_mode_dispatches

### New v2 Metrics (stats.rs)

[`src/stats.rs#L113-117`](../src/stats.rs#L113-117)
- Lines 113-117: New metric definitions

[`src/stats.rs#L121`](../src/stats.rs#L121)
- Line 121: v2exp and v2con added to summary_line format

[`src/stats.rs#L170`](../src/stats.rs#L170)
- Line 170: v2exp and v2con added to format output

[`src/stats.rs#L295-298`](../src/stats.rs#L295-298)
- Lines 295-298: v2exp and v2con added to delta calculation

## v2 Policy Summary

### Contract Mode (Locality-First)
- Default state when pressure is low
- Allows locality fallback after idle-pick miss
- Work stays close to favored CPU set

### Expand Mode (Balance-First)
- Activated when global pressure >= v2ExpandThreshold
- Skips locality fallback, dispatches directly to shared queues
- Work spreads to reduce queue delay

### Hysteresis
- Enter expand at v2ExpandThreshold (75% desktop default)
- Exit expand at v2ContractThreshold (50% desktop default)
- Prevents oscillation around boundary
