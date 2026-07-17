/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Galih Tama <galpt@v.recipes> */
#ifndef __INTF_H
#define __INTF_H

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

	/* Per-CPU pinned DSQ base. */
	FLOW_PINNED_DSQ_BASE = 2048ULL,
	/* Per-CPU vtime DSQ base (per-core bandwidth sharing). */
	FLOW_VTIME_DSQ_BASE = 4096ULL,
	/* Shared batch DSQ (fallback when no per-CPU DSQ available). */
	FLOW_BATCH_DSQ            = 8192ULL,

	/* Carriage pool — stats-only ring buffer for the web UI.
	 * Non-wakeup tasks are dispatched to per-CPU vtime DSQs
	 * (FLOW_VTIME_DSQ_BASE + cpu) from the enqueue callback.
	 * The carriage pool records a rolling sample of dispatched PIDs. */
	FLOW_NR_CARRIAGES        = 64ULL,
	FLOW_CARRIAGE_CAPACITY   = 64ULL,
	FLOW_CARRIAGE_NS         = 100000ULL,

	/* Enqueue flags */
	FLOW_ENQ_WAKEUP  = 0x0000000000000001ULL,
	FLOW_ENQ_HEAD    = 0x0000000000010000ULL,
	FLOW_ENQ_PREEMPT = 0x0000000100000000ULL,

	/* CPU selection flags */
	FLOW_PICK_IDLE_CORE = 0x01ULL,

	/* Built-in DSQ IDs */
	FLOW_DSQ_GLOBAL    = 0x8000000000000001ULL,
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
#endif

struct flow_carriage {
	u64 tasks[FLOW_CARRIAGE_CAPACITY];	/* PIDs for web UI */
	u32 count;
};

struct flow_cpu_state {
	u64 budget_exhaustions;
	u64 runnable_wakeups;
	u64 cpu_migrations;
};

#endif /* __INTF_H */
