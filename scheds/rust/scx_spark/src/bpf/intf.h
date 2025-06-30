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

	/* Kernel definitions */
	CLOCK_BOOTTIME		= 7,

	/* DSQ modes */
	DSQ_MODE_CPU = 1,
	DSQ_MODE_SHARED = 2,

	/* Maximum number of GPU task PIDs to track */
	MAX_GPU_TASK_PIDS = 10000,

	MAX_WORKLOAD_PIDS = 10000,

	/* Maximum command name length for workload detection */
	MAX_COMM_LEN = 16,

	WORKLOAD_TYPE_UNKNOWN = 0,
	WORKLOAD_TYPE_INFERENCE = 1,
	WORKLOAD_TYPE_TRAINING = 2,
	WORKLOAD_TYPE_VALIDATION = 3,
	WORKLOAD_TYPE_PREPROCESSING = 4,
	WORKLOAD_TYPE_DATA_LOADING = 5,
	WORKLOAD_TYPE_MODEL_LOADING = 6,
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

struct cpu_arg {
	s32 cpu_id;
};

struct enable_cpu_arg {
	s32 cpu_id;
	s32 mask_type;  /* 0 = primary, 1 = big, 2 = little, 3 = turbo */
};

struct domain_arg {
	s32 lvl_id;
	s32 cpu_id;
	s32 sibling_cpu_id;
};

struct workload_info {
	u32 workload_type;
	u64 detection_time;
	u64 gpu_usage_count;
	u64 cpu_usage_time;
	u64 io_operations;
	u64 memory_allocations;
};

#endif /* __INTF_H */
