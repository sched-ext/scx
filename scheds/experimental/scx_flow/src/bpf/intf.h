/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __INTF_H
#define __INTF_H

/*
 * Shared BPF constants for scx_flow.
 */
enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),

	FLOW_SLICE_MIN_NS = (50ULL * NSEC_PER_USEC),
	FLOW_SLICE_RESERVED_MAX_NS = (250ULL * NSEC_PER_USEC),
	FLOW_SLICE_RESERVED_TUNE_MAX_NS = (350ULL * NSEC_PER_USEC),
	FLOW_BUDGET_MAX_NS = (2ULL * NSEC_PER_MSEC),
	FLOW_BUDGET_MIN_NS = (500ULL * NSEC_PER_USEC),
	FLOW_SLEEP_MAX_NS = (250ULL * NSEC_PER_MSEC),
	FLOW_INTERACTIVE_SLEEP_MIN_NS = (750ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_NS = (100ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_MIN_NS = (80ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_MAX_NS = (200ULL * NSEC_PER_USEC),
	FLOW_REFILL_DIV = 100ULL,

	/* Per-CPU pinned DSQ base: each CPU gets FLOW_PINNED_DSQ_BASE + cpu.
	 * Non-migratable userspace tasks (nr_cpus_allowed == 1) are routed
	 * here on non-wakeup re-enqueue, checked first in dispatch so that
	 * pinned latency-sensitive tasks bypass global vtime DSQ contention.
	 * The nr_cpus_allowed signal is kernel-enforced, not a heuristic.
	 * Addition used instead of bitwise-OR to avoid DSQ ID collisions on
	 * systems with cpu >= FLOW_PINNED_DSQ_BASE (reviewer comment). */
	FLOW_PINNED_DSQ_BASE = 2048ULL,

	/* O(1) multi-level FIFO dispatch tiers for non-wakeup re-enqueues.
	 * Each tier is an independent FIFO DSQ, checked in priority order
	 * during dispatch.  Tasks are classified by budget at enqueue time:
	 *   PRIORITY (≥ 1500 us)  — tasks that slept a long time (interactive)
	 *   NORMAL   (≥ 1000 us)  — tasks with typical budget
	 *   LOW      (≥  500 us)  — tasks with modest budget
	 *   DEFICIT  (<  500 us)  — tasks that exhausted their budget (bulk workers)
	 * Within each tier, tasks dispatch in FIFO order (O(1) per operation).
	 * The tier boundaries are compile-time constants — no adaptive tuning,
	 * no scoring signals, no classification heuristics.  Same inputs always
	 * produce the same tier assignment.
	 *
	 * Budget thresholds (in nanoseconds) used by enqueue's select_tier(). */
	FLOW_BUDGET_TIER_PRIORITY_NS = 1500000ULL,  /* 1500 us */
	FLOW_BUDGET_TIER_NORMAL_NS   = 1000000ULL,  /* 1000 us */
	FLOW_BUDGET_TIER_LOW_NS      =  500000ULL,  /*  500 us */
	FLOW_TIER_PRIORITY_DSQ = 3000ULL,
	FLOW_TIER_NORMAL_DSQ   = 3001ULL,
	FLOW_TIER_LOW_DSQ      = 3002ULL,
	FLOW_TIER_DEFICIT_DSQ  = 3003ULL,

	/* Enqueue flags (defined directly to bypass weak-volatile compat) */
	FLOW_ENQ_WAKEUP  = 0x0000000000000001ULL,  /* SCX_ENQ_WAKEUP */
	FLOW_ENQ_HEAD    = 0x0000000000010000ULL,  /* SCX_ENQ_HEAD */
	FLOW_ENQ_PREEMPT = 0x0000000100000000ULL,  /* SCX_ENQ_PREEMPT */

	/* CPU selection flags */
	FLOW_PICK_IDLE_CORE = 0x01ULL,  /* scx_bpf_pick_idle_cpu: both SMT siblings idle */

	/* Built-in DSQ IDs (kernel ABI, stable):
	 *   SCX_DSQ_LOCAL   = 0x8000000000000002  — per-CPU local DSQ
	 *   SCX_DSQ_GLOBAL  = 0x8000000000000001  — global FIFO DSQ
	 *   SCX_DSQ_LOCAL_ON = 0xC000000000000000 | cpu — local DSQ + atomic reschedule */
	FLOW_DSQ_LOCAL     = 0x8000000000000002ULL,
	FLOW_DSQ_LOCAL_ON  = 0xC000000000000000ULL,

};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;
#endif /* __VMLINUX_H__ */

struct flow_cpu_state {
	u64 budget_exhaustions;
	u64 runnable_wakeups;
	u64 cpu_migrations;
	/* per-tier dispatch counters are BSS volatiles (not per-CPU),
	 * aggregated in the Rust loader for the web UI. */
};

#endif /* __INTF_H */
