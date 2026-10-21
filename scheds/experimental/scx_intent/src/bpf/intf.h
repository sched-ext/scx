/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Rahad Bhuiya <rahadbhuiya2021@gmail.com>
 */
#ifndef __INTF_H
#define __INTF_H

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),
};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

typedef int pid_t;
#endif /* __VMLINUX_H__ */

enum intent_type {
	INTENT_AUDIT = 0,
	INTENT_INTERACTIVE = 1,
	INTENT_IO = 2,
	INTENT_NETWORK = 3,
	INTENT_COMPUTE = 4,
	INTENT_COUNT = 5,
};

#define DSQ_AUDIT       0ULL
#define DSQ_INTERACTIVE 1ULL
#define DSQ_IO          2ULL
#define DSQ_NETWORK     3ULL
#define DSQ_COMPUTE     4ULL

#define SLICE_AUDIT_NS       (10ULL * NSEC_PER_MSEC)
#define SLICE_INTERACTIVE_NS (4ULL * NSEC_PER_MSEC)
#define SLICE_IO_NS          (5ULL * NSEC_PER_MSEC)
#define SLICE_NETWORK_NS     (8ULL * NSEC_PER_MSEC)
#define SLICE_COMPUTE_NS     (20ULL * NSEC_PER_MSEC)

#define STARVATION_THRESHOLD 32
#define MAX_INTENT_RULES 256
#define TASK_COMM_LEN 16

struct intent_stats {
	u64 enqueued[INTENT_COUNT];
	u64 dispatched[INTENT_COUNT];
	u64 starved_dispatches[INTENT_COUNT];
};

#endif /* __INTF_H */
