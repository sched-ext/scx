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
 * Quick and Normal lane BPF constants for scx_flow.
 */
enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),

	FLOW_SLICE_MIN_NS = (50ULL * NSEC_PER_USEC),
	FLOW_SLICE_RESERVED_MAX_NS = (250ULL * NSEC_PER_USEC),
	FLOW_SLICE_RESERVED_TUNE_MAX_NS = (350ULL * NSEC_PER_USEC),
	FLOW_SLICE_SHARED_NS = (1ULL * NSEC_PER_MSEC),
	FLOW_SLICE_SHARED_MIN_NS = (750ULL * NSEC_PER_USEC),
	FLOW_SLICE_SHARED_MAX_NS = (1500ULL * NSEC_PER_USEC),
	FLOW_BUDGET_MAX_NS = (2ULL * NSEC_PER_MSEC),
	FLOW_BUDGET_MIN_NS = (500ULL * NSEC_PER_USEC),
	FLOW_SLEEP_MAX_NS = (250ULL * NSEC_PER_MSEC),
	FLOW_INTERACTIVE_SLEEP_MIN_NS = (750ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_NS = (100ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_MIN_NS = (80ULL * NSEC_PER_USEC),
	FLOW_INTERACTIVE_FLOOR_MAX_NS = (200ULL * NSEC_PER_USEC),
	FLOW_REFILL_DIV = 100ULL,

	/* DSQ IDs */
	FLOW_QUICK_CPU_DSQ_BASE = 0x100000ULL,
	FLOW_NORMAL_DSQ = 1025ULL,

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
	u64 quick_dispatches;
	u64 normal_dispatches;
	u64 cpu_migrations;
};

#endif /* __INTF_H */
