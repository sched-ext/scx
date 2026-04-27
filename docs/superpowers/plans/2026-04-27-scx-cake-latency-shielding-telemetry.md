# scx_cake Latency Shielding Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dry-run wake classifiers, shadow busy-preempt telemetry, dump output, and dump-to-dump comparison support without changing scheduler policy.

**Architecture:** The first slice is observational only. BPF debug code records wake class samples, reason counts, owner/wakee class combinations, and the shadow preempt decision that would have happened under the proposed policy; Rust/TUI code aggregates and prints those counters; an offline compare command reads two dump files and reports before/after deltas.

**Tech Stack:** sched_ext BPF C, libbpf-rs generated bindings, Rust TUI/dump code, clap CLI, cargo tests/checks.

---

## File Structure

- Modify `scheds/rust/scx_cake/src/bpf/intf.h`
  - Add wake-policy enums and global debug counters.
  - Reuse the existing per-CPU padding byte for the last observed running wake class.
- Modify `scheds/rust/scx_cake/src/bpf/cake.bpf.c`
  - Add debug-only shadow classifier helpers.
  - Record class samples in `cake_running`.
  - Record busy preempt shadow decisions in `enqueue_dsq_dispatch`.
  - Keep the live `kick_flags` behavior unchanged.
- Modify `scheds/rust/scx_cake/src/tui.rs`
  - Aggregate the new counters.
  - Add lifetime and windowed dump lines for wake-policy shadow telemetry.
  - Reset the new counters when the TUI reset key is pressed.
- Create `scheds/rust/scx_cake/src/dump_compare.rs`
  - Parse `tui_dump_*.txt` files.
  - Compare the metrics needed for policy review.
  - Include unit tests with embedded dump fixtures.
- Modify `scheds/rust/scx_cake/src/main.rs`
  - Add `--compare-dump BASELINE CANDIDATE`.
  - Run comparison and exit before loading BPF.
- Modify `scheds/rust/scx_cake/README.md`
  - Document dry-run classifier telemetry and the compare command.

## Task 1: Interface Enums And Counters

**Files:**
- Modify: `scheds/rust/scx_cake/src/bpf/intf.h`

- [ ] **Step 1: Add wake-policy enums**

Add the following block immediately after `enum cake_kick_kind`:

```c
enum cake_wake_class {
	CAKE_WAKE_CLASS_NONE    = 0,
	CAKE_WAKE_CLASS_NORMAL  = 1,
	CAKE_WAKE_CLASS_SHIELD  = 2,
	CAKE_WAKE_CLASS_CONTAIN = 3,
	CAKE_WAKE_CLASS_MAX     = 4,
};

enum cake_wake_class_reason {
	CAKE_WAKE_CLASS_REASON_LOW_UTIL      = 0,
	CAKE_WAKE_CLASS_REASON_SHORT_RUN     = 1,
	CAKE_WAKE_CLASS_REASON_WAKE_DENSE    = 2,
	CAKE_WAKE_CLASS_REASON_LATENCY_PRIO  = 3,
	CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY = 4,
	CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY = 5,
	CAKE_WAKE_CLASS_REASON_PRESSURE_HIGH = 6,
	CAKE_WAKE_CLASS_REASON_MAX           = 7,
};

enum cake_busy_preempt_shadow {
	CAKE_BUSY_PREEMPT_SHADOW_ALLOW = 0,
	CAKE_BUSY_PREEMPT_SHADOW_SKIP  = 1,
	CAKE_BUSY_PREEMPT_SHADOW_MAX   = 2,
};
```

- [ ] **Step 2: Reuse the per-CPU padding byte**

In `struct cake_cpu_bss`, replace:

```c
	u8  _pad_status;        /* 1B: padding / future per-CPU state */
```

with:

```c
	u8  last_wake_class;    /* 1B: last running task's shadow wake class */
```

This should not change the struct size because it consumes existing padding.

- [ ] **Step 3: Add global debug counters**

In `struct cake_stats`, place the following fields after `nr_wake_kick_preempt` and before the affinity kick counters:

```c
	u64 wake_class_sample_count[CAKE_WAKE_CLASS_MAX]; /* Shadow wake class samples */
	u64 wake_class_reason_count[CAKE_WAKE_CLASS_REASON_MAX]; /* Shadow class reason hits */
	u64 wake_class_transition_count[CAKE_WAKE_CLASS_MAX][CAKE_WAKE_CLASS_MAX]; /* Per-CPU owner class transitions */
	u64 busy_preempt_shadow_count[CAKE_BUSY_PREEMPT_SHADOW_MAX]; /* Shadow busy-wake decision counts */
	u64 busy_preempt_shadow_wakee_class_count[CAKE_WAKE_CLASS_MAX]; /* Busy shadow by wakee class */
	u64 busy_preempt_shadow_owner_class_count[CAKE_WAKE_CLASS_MAX]; /* Busy shadow by owner class */
	u64 busy_preempt_shadow_local; /* Busy shadow decisions where waker CPU matched target CPU */
	u64 busy_preempt_shadow_remote; /* Busy shadow decisions where target CPU was remote */
```

- [ ] **Step 4: Run the interface build check**

Run:

```bash
cargo check -p scx_cake
```

Expected: command passes. The generated bindings should tolerate the new fields
before Rust starts displaying them.

- [ ] **Step 5: Commit Task 1**

```bash
git add scheds/rust/scx_cake/src/bpf/intf.h
git commit -m "scx_cake: add wake policy telemetry interface"
```

## Task 2: BPF Shadow Classifier And Busy-Preempt Dry Run

**Files:**
- Modify: `scheds/rust/scx_cake/src/bpf/cake.bpf.c`

- [ ] **Step 1: Add classifier helpers**

Add these helpers near the existing wake helper functions, before `enqueue_dsq_dispatch`:

```c
#ifndef CAKE_RELEASE
static __always_inline u32 cake_class_reason_bit(u32 reason)
{
	return 1u << reason;
}

static __always_inline void cake_record_wake_class_reasons(
	struct cake_stats *stats, u32 reason_mask)
{
	if (!stats)
		return;

	if (reason_mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LOW_UTIL))
		stats->wake_class_reason_count[CAKE_WAKE_CLASS_REASON_LOW_UTIL]++;
	if (reason_mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_SHORT_RUN))
		stats->wake_class_reason_count[CAKE_WAKE_CLASS_REASON_SHORT_RUN]++;
	if (reason_mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_WAKE_DENSE))
		stats->wake_class_reason_count[CAKE_WAKE_CLASS_REASON_WAKE_DENSE]++;
	if (reason_mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LATENCY_PRIO))
		stats->wake_class_reason_count[CAKE_WAKE_CLASS_REASON_LATENCY_PRIO]++;
	if (reason_mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY))
		stats->wake_class_reason_count[CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY]++;
	if (reason_mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY))
		stats->wake_class_reason_count[CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY]++;
	if (reason_mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_PRESSURE_HIGH))
		stats->wake_class_reason_count[CAKE_WAKE_CLASS_REASON_PRESSURE_HIGH]++;
}

static __always_inline u8 cake_shadow_classify_task(
	struct task_struct *p,
	struct cake_task_ctx __arena *tctx,
	u32 *reason_mask)
{
	u32 mask = 0;
	u8 cls = CAKE_WAKE_CLASS_NORMAL;

	if (p->se.avg.util_avg < 64)
		mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LOW_UTIL);
	if (p->prio < 120 || p->scx.weight > 120)
		mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LATENCY_PRIO);

	if (tctx) {
		u32 runs = tctx->telemetry.total_runs;
		u64 avg_run_ns = runs ? tctx->telemetry.total_runtime_ns / runs : 0;
		u64 full = tctx->telemetry.quantum_full_count;
		u64 blocked = tctx->telemetry.quantum_yield_count;
		u64 preempt = tctx->telemetry.quantum_preempt_count;
		u64 q_total = full + blocked + preempt;

		if (runs >= 32 && avg_run_ns > 0 && avg_run_ns <= 100000)
			mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_SHORT_RUN);
		if (runs >= 256 && avg_run_ns > 0 && avg_run_ns <= 250000)
			mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_WAKE_DENSE);
		if (q_total >= 32 && full * 100 >= q_total * 20)
			mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY);
		if (q_total >= 32 && preempt * 100 >= q_total * 10)
			mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY);
	}

	if ((mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_LATENCY_PRIO)) ||
	    ((mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_SHORT_RUN)) &&
	     (mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_WAKE_DENSE)))) {
		cls = CAKE_WAKE_CLASS_SHIELD;
	} else if ((mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY)) ||
		   (mask & cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY))) {
		cls = CAKE_WAKE_CLASS_CONTAIN;
	}

	*reason_mask = mask;
	return cls;
}

static __always_inline u8 cake_shadow_busy_preempt_decision(
	u8 wakee_class, u8 owner_class, u8 target_pressure)
{
	if (wakee_class == CAKE_WAKE_CLASS_SHIELD)
		return CAKE_BUSY_PREEMPT_SHADOW_ALLOW;
	if (owner_class == CAKE_WAKE_CLASS_CONTAIN)
		return CAKE_BUSY_PREEMPT_SHADOW_ALLOW;
	if (target_pressure >= 64)
		return CAKE_BUSY_PREEMPT_SHADOW_ALLOW;
	return CAKE_BUSY_PREEMPT_SHADOW_SKIP;
}

static __always_inline void cake_record_busy_preempt_shadow(
	struct cake_stats *stats,
	u8 decision,
	u8 wakee_class,
	u8 owner_class,
	bool local_target)
{
	if (!stats)
		return;
	if (decision < CAKE_BUSY_PREEMPT_SHADOW_MAX)
		stats->busy_preempt_shadow_count[decision]++;
	if (wakee_class < CAKE_WAKE_CLASS_MAX)
		stats->busy_preempt_shadow_wakee_class_count[wakee_class]++;
	if (owner_class < CAKE_WAKE_CLASS_MAX)
		stats->busy_preempt_shadow_owner_class_count[owner_class]++;
	if (local_target)
		stats->busy_preempt_shadow_local++;
	else
		stats->busy_preempt_shadow_remote++;
}
#endif
```

The first pass intentionally leaves SMT exposure as a TUI/dump-derived
interpretation. BPF records CPU pressure in the busy-preempt shadow path instead
of adding a per-task SMT field to `cake_task_ctx`.

- [ ] **Step 2: Record running class samples**

In `cake_running`, inside the `if (bss->last_pid != p->pid)` task-change block after `struct cake_task_ctx __arena *tctx = get_task_ctx(p);`, add:

```c
#ifndef CAKE_RELEASE
		if (stats_on) {
			struct cake_stats *s_run = get_local_stats_for(cpu);
			u32 reason_mask = 0;
			u8 old_class = READ_ONCE(bss->last_wake_class);
			u8 new_class = cake_shadow_classify_task(p, tctx, &reason_mask);

			if (new_class > CAKE_WAKE_CLASS_NONE && new_class < CAKE_WAKE_CLASS_MAX)
				s_run->wake_class_sample_count[new_class]++;
			if (old_class < CAKE_WAKE_CLASS_MAX && new_class < CAKE_WAKE_CLASS_MAX)
				s_run->wake_class_transition_count[old_class][new_class]++;
			cake_record_wake_class_reasons(s_run, reason_mask);
			WRITE_ONCE(bss->last_wake_class, new_class);
		}
#endif
```

Keep the existing home CPU update block in place immediately after this addition.

- [ ] **Step 3: Record busy preempt shadow decisions**

In `enqueue_dsq_dispatch`, keep the live line unchanged:

```c
		kick_flags = idle_hint ? SCX_KICK_IDLE : SCX_KICK_PREEMPT;
```

Immediately after that line, add debug-only dry-run recording:

```c
#ifndef CAKE_RELEASE
		if (is_wakeup && stats_on && tctx) {
			u32 reason_mask = 0;
			u8 wakee_class = cake_shadow_classify_task(p, tctx, &reason_mask);
			u8 owner_class = READ_ONCE(cpu_bss[target_cpu_idx].last_wake_class);
			u8 pressure = READ_ONCE(cpu_bss[target_cpu_idx].cpu_pressure);
			u8 decision = cake_shadow_busy_preempt_decision(
				wakee_class, owner_class, pressure);

			if (pressure >= 64)
				reason_mask |= cake_class_reason_bit(CAKE_WAKE_CLASS_REASON_PRESSURE_HIGH);
			if (wakee_class > CAKE_WAKE_CLASS_NONE &&
			    wakee_class < CAKE_WAKE_CLASS_MAX)
				stats->wake_class_sample_count[wakee_class]++;
			cake_record_wake_class_reasons(stats, reason_mask);
			cake_record_busy_preempt_shadow(
				stats, decision, wakee_class, owner_class, wake_target_local);
		}
#endif
```

This step must not change queue target, `kick_cpu`, `kick_flags`, slice, vtime, or dispatch behavior.

- [ ] **Step 4: Verify policy did not change**

Run:

```bash
rg -n "kick_flags = idle_hint \\? SCX_KICK_IDLE : SCX_KICK_PREEMPT" scheds/rust/scx_cake/src/bpf/cake.bpf.c
```

Expected: the original unconditional busy-wake preempt assignment is still present.

- [ ] **Step 5: Build-check BPF and Rust bindings**

Run:

```bash
cargo check -p scx_cake
```

Expected: command passes. The shadow classifier is debug-only and should not
require TUI display support before it compiles.

- [ ] **Step 6: Commit Task 2**

```bash
git add scheds/rust/scx_cake/src/bpf/cake.bpf.c
git commit -m "scx_cake: dry-run wake policy classifier in BPF"
```

## Task 3: TUI Aggregation And Dump Output

**Files:**
- Modify: `scheds/rust/scx_cake/src/tui.rs`

- [ ] **Step 1: Add labels**

Near `wake_reason_label` and `select_reason_short_label`, add:

```rust
fn wake_class_label(class: usize) -> &'static str {
    match class {
        1 => "normal",
        2 => "shield",
        3 => "contain",
        _ => "none",
    }
}

fn wake_class_reason_label(reason: usize) -> &'static str {
    match reason {
        0 => "low_util",
        1 => "short_run",
        2 => "wake_dense",
        3 => "latency_prio",
        4 => "runtime_heavy",
        5 => "preempt_heavy",
        6 => "pressure_high",
        _ => "unknown",
    }
}
```

- [ ] **Step 2: Aggregate new fields**

In `aggregate_stats`, after aggregating `nr_wake_kick_preempt`, add loops:

```rust
for class in 0..4 {
    total.wake_class_sample_count[class] += s.wake_class_sample_count[class];
    total.busy_preempt_shadow_wakee_class_count[class] +=
        s.busy_preempt_shadow_wakee_class_count[class];
    total.busy_preempt_shadow_owner_class_count[class] +=
        s.busy_preempt_shadow_owner_class_count[class];
    for next in 0..4 {
        total.wake_class_transition_count[class][next] +=
            s.wake_class_transition_count[class][next];
    }
}
for reason in 0..7 {
    total.wake_class_reason_count[reason] += s.wake_class_reason_count[reason];
}
for decision in 0..2 {
    total.busy_preempt_shadow_count[decision] += s.busy_preempt_shadow_count[decision];
}
total.busy_preempt_shadow_local += s.busy_preempt_shadow_local;
total.busy_preempt_shadow_remote += s.busy_preempt_shadow_remote;
```

- [ ] **Step 3: Add window delta support**

In `stats_delta`, after the wake kick counters are subtracted, add:

```rust
for class in 0..current.wake_class_sample_count.len() {
    delta.wake_class_sample_count[class] = current.wake_class_sample_count[class]
        .saturating_sub(previous.wake_class_sample_count[class]);
    delta.busy_preempt_shadow_wakee_class_count[class] = current
        .busy_preempt_shadow_wakee_class_count[class]
        .saturating_sub(previous.busy_preempt_shadow_wakee_class_count[class]);
    delta.busy_preempt_shadow_owner_class_count[class] = current
        .busy_preempt_shadow_owner_class_count[class]
        .saturating_sub(previous.busy_preempt_shadow_owner_class_count[class]);
    for next in 0..current.wake_class_transition_count[class].len() {
        delta.wake_class_transition_count[class][next] = current
            .wake_class_transition_count[class][next]
            .saturating_sub(previous.wake_class_transition_count[class][next]);
    }
}
for reason in 0..current.wake_class_reason_count.len() {
    delta.wake_class_reason_count[reason] = current.wake_class_reason_count[reason]
        .saturating_sub(previous.wake_class_reason_count[reason]);
}
for decision in 0..current.busy_preempt_shadow_count.len() {
    delta.busy_preempt_shadow_count[decision] = current.busy_preempt_shadow_count[decision]
        .saturating_sub(previous.busy_preempt_shadow_count[decision]);
}
delta.busy_preempt_shadow_local = current
    .busy_preempt_shadow_local
    .saturating_sub(previous.busy_preempt_shadow_local);
delta.busy_preempt_shadow_remote = current
    .busy_preempt_shadow_remote
    .saturating_sub(previous.busy_preempt_shadow_remote);
```

- [ ] **Step 4: Add formatter helpers**

Near the other dump summary formatters, add:

```rust
fn format_wake_class_counts(counts: &[u64]) -> String {
    (1..counts.len())
        .map(|class| format!("{}={}", wake_class_label(class), counts[class]))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_wake_class_reasons(counts: &[u64]) -> String {
    counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(reason, count)| format!("{}={}", wake_class_reason_label(reason), count))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_busy_preempt_shadow(stats: &cake_stats) -> String {
    format!(
        "allow={} skip={} local={} remote={} wakee=[{}] owner=[{}]",
        stats.busy_preempt_shadow_count[0],
        stats.busy_preempt_shadow_count[1],
        stats.busy_preempt_shadow_local,
        stats.busy_preempt_shadow_remote,
        format_wake_class_counts(&stats.busy_preempt_shadow_wakee_class_count),
        format_wake_class_counts(&stats.busy_preempt_shadow_owner_class_count),
    )
}
```

- [ ] **Step 5: Add dump section appender**

Add:

```rust
fn append_wake_policy_section(output: &mut String, label: &str, stats: &cake_stats) {
    output.push_str(&format!(
        "{}: class=[{}] reasons=[{}] busy_shadow:{}\n",
        label,
        format_wake_class_counts(&stats.wake_class_sample_count),
        format_wake_class_reasons(&stats.wake_class_reason_count),
        format_busy_preempt_shadow(stats),
    ));
}
```

- [ ] **Step 6: Print lifetime and windowed policy lines**

In `format_stats_for_clipboard`, after the existing `slice:` line, add:

```rust
append_wake_policy_section(&mut output, "wakepolicy.life", stats);
```

In `append_window_stats`, after the existing `win.slice:` line, add:

```rust
append_wake_policy_section(output, &format!("win.wakepolicy.{}", label), stats);
```

- [ ] **Step 7: Reset the new counters**

In the TUI reset handler under `KeyCode::Char('r')`, inside the existing debug BSS reset block, reset the generated arrays:

```rust
for s in &mut bss.global_stats {
    s.wake_class_sample_count = Default::default();
    s.wake_class_reason_count = Default::default();
    s.wake_class_transition_count = Default::default();
    s.busy_preempt_shadow_count = Default::default();
    s.busy_preempt_shadow_wakee_class_count = Default::default();
    s.busy_preempt_shadow_owner_class_count = Default::default();
    s.busy_preempt_shadow_local = 0;
    s.busy_preempt_shadow_remote = 0;
}
```

If this overlaps with the existing `for s in &mut bss.global_stats { *s = Default::default(); }`, do not add a second loop. Confirm the new fields are covered by the existing full-struct reset and add no duplicate work.

- [ ] **Step 8: Run formatting and build check**

Run:

```bash
cargo fmt -p scx_cake
cargo check -p scx_cake
```

Expected: both commands pass.

- [ ] **Step 9: Commit Task 3**

```bash
git add scheds/rust/scx_cake/src/tui.rs
git commit -m "scx_cake: show wake policy shadow telemetry"
```

## Task 4: Offline Dump Comparison Command

**Files:**
- Create: `scheds/rust/scx_cake/src/dump_compare.rs`
- Modify: `scheds/rust/scx_cake/src/main.rs`

- [ ] **Step 1: Create parser tests first**

Create `scheds/rust/scx_cake/src/dump_compare.rs` with this initial test module and stubs:

```rust
use anyhow::{Context, Result};
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct DumpMetrics {
    busy_wakes: u64,
    busy_preempt_allow: u64,
    busy_preempt_skip: u64,
    direct_wait_max_us: u64,
    busy_wait_max_us: u64,
    smt_runtime_contended_tenths: u64,
    shield_samples: u64,
    contain_samples: u64,
}

fn parse_dump_metrics(text: &str) -> DumpMetrics {
    let mut metrics = DumpMetrics::default();
    for line in text.lines() {
        if line.starts_with("disp:") || line.starts_with("win.disp:") {
            metrics.busy_wakes = parse_named_u64(line, "busy").unwrap_or(metrics.busy_wakes);
        } else if line.starts_with("wakewait.all:") || line.starts_with("win.wakewait.all:") {
            metrics.direct_wait_max_us =
                parse_wait_max_us(line, "dir").unwrap_or(metrics.direct_wait_max_us);
            metrics.busy_wait_max_us =
                parse_wait_max_us(line, "busy").unwrap_or(metrics.busy_wait_max_us);
        } else if line.starts_with("smt:") || line.starts_with("win.smt:") {
            metrics.smt_runtime_contended_tenths =
                parse_percent_tenths(line, "runtime_contended")
                    .unwrap_or(metrics.smt_runtime_contended_tenths);
        } else if line.starts_with("wakepolicy.life:")
            || line.starts_with("win.wakepolicy.")
        {
            metrics.busy_preempt_allow =
                parse_named_u64(line, "allow").unwrap_or(metrics.busy_preempt_allow);
            metrics.busy_preempt_skip =
                parse_named_u64(line, "skip").unwrap_or(metrics.busy_preempt_skip);
            metrics.shield_samples =
                parse_named_u64(line, "shield").unwrap_or(metrics.shield_samples);
            metrics.contain_samples =
                parse_named_u64(line, "contain").unwrap_or(metrics.contain_samples);
        }
    }
    metrics
}

fn parse_named_u64(line: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn parse_percent_tenths(line: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let value: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = value.split('.');
    let whole: u64 = parts.next()?.parse().ok()?;
    let frac = parts.next().and_then(|p| p.chars().next()).unwrap_or('0');
    Some(whole * 10 + frac.to_digit(10)? as u64)
}

fn parse_wait_max_us(line: &str, key: &str) -> Option<u64> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let slash = rest.find('/')?;
    let after_slash = &rest[slash + 1..];
    let end = after_slash.find("us")?;
    after_slash[..end].parse().ok()
}

pub fn run_compare(baseline: &Path, candidate: &Path) -> Result<()> {
    let before = std::fs::read_to_string(baseline)
        .with_context(|| format!("failed to read {}", baseline.display()))?;
    let after = std::fs::read_to_string(candidate)
        .with_context(|| format!("failed to read {}", candidate.display()))?;
    let before = parse_dump_metrics(&before);
    let after = parse_dump_metrics(&after);
    print_comparison(&before, &after);
    Ok(())
}

fn signed_delta(after: u64, before: u64) -> i128 {
    after as i128 - before as i128
}

fn print_comparison(before: &DumpMetrics, after: &DumpMetrics) {
    println!("scx_cake dump comparison");
    println!("busy_wakes: {} -> {} ({:+})", before.busy_wakes, after.busy_wakes, signed_delta(after.busy_wakes, before.busy_wakes));
    println!("busy_preempt.allow: {} -> {} ({:+})", before.busy_preempt_allow, after.busy_preempt_allow, signed_delta(after.busy_preempt_allow, before.busy_preempt_allow));
    println!("busy_preempt.skip: {} -> {} ({:+})", before.busy_preempt_skip, after.busy_preempt_skip, signed_delta(after.busy_preempt_skip, before.busy_preempt_skip));
    println!("wakewait.direct.max_us: {} -> {} ({:+})", before.direct_wait_max_us, after.direct_wait_max_us, signed_delta(after.direct_wait_max_us, before.direct_wait_max_us));
    println!("wakewait.busy.max_us: {} -> {} ({:+})", before.busy_wait_max_us, after.busy_wait_max_us, signed_delta(after.busy_wait_max_us, before.busy_wait_max_us));
    println!("smt.runtime_contended: {:.1}% -> {:.1}% ({:+.1}%)", before.smt_runtime_contended_tenths as f64 / 10.0, after.smt_runtime_contended_tenths as f64 / 10.0, signed_delta(after.smt_runtime_contended_tenths, before.smt_runtime_contended_tenths) as f64 / 10.0);
    println!("class.shield: {} -> {} ({:+})", before.shield_samples, after.shield_samples, signed_delta(after.shield_samples, before.shield_samples));
    println!("class.contain: {} -> {} ({:+})", before.contain_samples, after.contain_samples, signed_delta(after.contain_samples, before.contain_samples));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_dump_metrics() {
        let dump = "\
disp: dsq_total=0 local=0 steal=0 miss=18857453 queue=0 ins:direct=16997201 affine=242498 shared=0 wake:direct=13635512 busy=3181716 queued=0 total=16817228
wakewait.all: dir=3/9252us(13635512) busy=3/9175us(3181716) queue=55/55us(1)
smt: runtime_contended=27.4% overlap=15.0% runs_contended=21.4%
wakepolicy.life: class=[normal=100 shield=25 contain=8] reasons=[short_run=11] busy_shadow:allow=9 skip=3 local=10 remote=2 wakee=[normal=1 shield=8 contain=3] owner=[normal=2 shield=1 contain=9]
";
        let metrics = parse_dump_metrics(dump);
        assert_eq!(metrics.busy_wakes, 3_181_716);
        assert_eq!(metrics.direct_wait_max_us, 9_252);
        assert_eq!(metrics.busy_wait_max_us, 9_175);
        assert_eq!(metrics.smt_runtime_contended_tenths, 274);
        assert_eq!(metrics.busy_preempt_allow, 9);
        assert_eq!(metrics.busy_preempt_skip, 3);
        assert_eq!(metrics.shield_samples, 25);
        assert_eq!(metrics.contain_samples, 8);
    }
}
```

- [ ] **Step 2: Wire the module into main**

In `main.rs`, add:

```rust
mod dump_compare;
```

near the existing module declarations.

Add this import:

```rust
use std::path::PathBuf;
```

Add this field to `Args`:

```rust
    /// Compare two scx_cake TUI dump files and exit without loading BPF.
    #[arg(long, value_names = ["BASELINE", "CANDIDATE"], num_args = 2)]
    compare_dump: Option<Vec<PathBuf>>,
```

After `let args = Args::parse();` and after the version check, add:

```rust
    if let Some(paths) = args.compare_dump.as_ref() {
        dump_compare::run_compare(&paths[0], &paths[1])?;
        return Ok(());
    }
```

This branch must run before signal handler setup and before `Scheduler::new`.

- [ ] **Step 3: Run the unit test**

Run:

```bash
cargo test -p scx_cake dump_compare::tests::parses_core_dump_metrics
```

Expected: test passes.

- [ ] **Step 4: Run compare against a real dump twice**

Run:

```bash
cargo run -p scx_cake -- --compare-dump target/debug/tui_dump_1777309522.txt target/debug/tui_dump_1777309522.txt
```

Expected: command prints `scx_cake dump comparison` and all deltas are `+0` or `+0.0%` for the parsed baseline metrics that exist in the current dump. New wakepolicy metrics may print zero until a fresh dump contains the new line.

- [ ] **Step 5: Commit Task 4**

```bash
git add scheds/rust/scx_cake/src/dump_compare.rs scheds/rust/scx_cake/src/main.rs
git commit -m "scx_cake: add dump comparison command"
```

## Task 5: README And Full Verification

**Files:**
- Modify: `scheds/rust/scx_cake/README.md`

- [ ] **Step 1: Document the dry-run telemetry**

In the Debug TUI section, add:

```markdown
Debug dumps include `wakepolicy.life` and `win.wakepolicy.*` lines when built
without `--release`. These are dry-run classifier counters for latency
shielding and busy-wake preempt policy experiments. They do not change live
scheduling behavior by themselves.
```

- [ ] **Step 2: Document dump comparison**

After the dump/TUI text, add:

````markdown
### Compare Dumps

```bash
cargo run -p scx_cake -- --compare-dump baseline.txt candidate.txt
```

The comparison command reads two TUI dump files and exits without loading BPF.
Use it to compare busy wake counts, busy preempt shadow decisions, wake wait
tails, SMT contention, and wake-policy class counts before enabling policy
experiments.
````

- [ ] **Step 3: Run formatting and tests**

Run:

```bash
cargo fmt -p scx_cake
cargo test -p scx_cake dump_compare
cargo check -p scx_cake
```

Expected: all commands pass.

- [ ] **Step 4: Verify no policy behavior changed**

Run:

```bash
rg -n "kick_flags = idle_hint \\? SCX_KICK_IDLE : SCX_KICK_PREEMPT|SCX_KICK_PREEMPT" scheds/rust/scx_cake/src/bpf/cake.bpf.c
```

Expected: the busy wake path still assigns `SCX_KICK_PREEMPT` exactly as before. Any new occurrences should be telemetry-only and not affect `kick_flags`.

- [ ] **Step 5: Commit Task 5**

```bash
git add scheds/rust/scx_cake/README.md
git commit -m "docs: describe scx_cake wake policy telemetry"
```

## Final Verification

- [ ] **Step 1: Confirm branch state**

Run:

```bash
git status --short --branch
```

Expected: branch is `RitzDaCat/scx_cake-nightly`; only known unrelated untracked files may remain.

- [ ] **Step 2: Confirm the feature is telemetry-only**

Run:

```bash
git diff HEAD~5..HEAD -- scheds/rust/scx_cake/src/bpf/cake.bpf.c | rg -n "kick_flags|SCX_KICK|dsq_insert|vtime|slice"
```

Expected: changes show shadow telemetry around `kick_flags`; no code changes the selected `kick_flags`, queue target, vtime, or slice policy.

- [ ] **Step 3: Capture a fresh post-telemetry dump**

Run debug `scx_cake --verbose`, press `d`, and compare the new dump against `target/debug/tui_dump_1777309522.txt`:

```bash
cargo run -p scx_cake -- --compare-dump target/debug/tui_dump_1777309522.txt target/debug/tui_dump_NEW.txt
```

Expected: the comparison shows wakepolicy class and busy shadow counts in the candidate dump. Runtime metrics are allowed to differ because the workload is live.

## Notes For Subagents

- Do not change scheduling behavior in this plan.
- Do not add process-name allowlists.
- Keep release overhead zero or near-zero by wrapping classifier work in `#ifndef CAKE_RELEASE` and `stats_on`.
- Do not expand `struct cake_task_ctx` in this first slice.
- If generated binding names differ from the C field names, inspect `target/debug/build/scx_cake-*/out/bpf_intf.rs` after `cargo check` and adjust Rust field access to match the generated names.
