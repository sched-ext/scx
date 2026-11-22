/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define CLAMP(val, lo, hi) MIN(MAX(val, lo), hi)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),

	/* The most CPUs, LLCs and nodes the scheduler handles. */
	MAX_CPUS = 1024,
	/* The words of the queued mask, 256 cache lines. */
	QUEUED_WORDS = 2048,
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

/*
 * What each CPU counts for the statistics, in a per-CPU map that user space
 * sums: only the CPU a callback runs on writes its counters.
 */
struct counters {
	/* Wakeups sent straight to an idle CPU. */
	u64 direct;
	/* Wakeups placed on borrowed virtual time. */
	u64 borrowed;
	/* Wakeups queued on another CPU to take it, and searches that found none. */
	u64 moved;
	u64 missed;
	/* Preemptions of a running task by a waking one. */
	u64 preempts;
	/* Tasks taken from another CPU's queue. */
	u64 steals;
	/* Running tasks moved by the tick to a better idle CPU. */
	u64 balanced;
	/* Tasks handed from a worse CPU to a CPU of the best tier. */
	u64 rotated;
};

/*
 * In and out of bpfland_cpu_priority(): the CPU, and its packing priority
 * and whether its domains pack asymmetrically.
 */
struct cpu_priority_args {
	u64 cpu;
	s64 priority;
	u64 asym_packing;
};

#endif /* __INTF_H */
