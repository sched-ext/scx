/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Changwoo Min <changwoo@igalia.com>
 */
#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

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

enum {
	TASK_COMM_LEN = 16,
};

#define __kptr
#endif

#ifdef __VMLINUX_H__
#define MAX_NICE	19
#define MIN_NICE	-20
#define NICE_WIDTH	(MAX_NICE - MIN_NICE + 1)
#define MAX_RT_PRIO	100

struct bpf_iter_task;
extern int bpf_iter_task_new(struct bpf_iter_task *it,
		struct task_struct *task, unsigned int flags) __weak __ksym;
extern struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __weak __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __weak __ksym;
#endif /* __KERNEL__ */

/*
 * common constants
 */
enum consts {
	CLOCK_BOOTTIME			= 7,
	NSEC_PER_USEC			= 1000L,
	NSEC_PER_MSEC			= (1000L * NSEC_PER_USEC),
	LAVD_TIME_ONE_SEC		= (1000L * NSEC_PER_MSEC),
	LAVD_MAX_CAS_RETRY		= 8,

	LAVD_SLICE_MIN_NS		= (300 * NSEC_PER_USEC),
	LAVD_SLICE_MAX_NS		= (3 * NSEC_PER_MSEC),
	LAVD_TARGETED_LATENCY_NS	= (15 * NSEC_PER_MSEC),
	LAVD_SLICE_GREEDY_FT		= 3,

	LAVD_LC_FREQ_MAX		= 1000000,
	LAVD_LC_RUNTIME_MAX		= (4 * LAVD_SLICE_MAX_NS),
	LAVD_LC_RUNTIME_SHIFT		= 10,

	LAVD_BOOST_RANGE		= 14, /* 35% of nice range */
	LAVD_BOOST_WAKEUP_LAT		= 1,
	LAVD_SLICE_BOOST_MAX_PRIO	= (LAVD_SLICE_MAX_NS/LAVD_SLICE_MIN_NS),
	LAVD_SLICE_BOOST_MAX_STEP	= 3,
	LAVD_GREEDY_RATIO_MAX		= USHRT_MAX,

	LAVD_ELIGIBLE_TIME_LAT_FT	= 2,
	LAVD_ELIGIBLE_TIME_MAX		= (LAVD_TARGETED_LATENCY_NS >> 1),

	LAVD_CPU_UTIL_MAX		= 1000, /* 100.0% */
	LAVD_CPU_UTIL_INTERVAL_NS	= (100 * NSEC_PER_MSEC), /* 100 msec */
	LAVD_CPU_ID_HERE		= 0xFE,
	LAVD_CPU_ID_NONE		= 0xFF,

	LAVD_GLOBAL_DSQ			= 0,
};

/*
 * System-wide CPU utilization
 */
struct sys_cpu_util {
	volatile u64	last_update_clk;
	volatile u64	util;		/* average of the CPU utilization */

	volatile u64	load_ideal;	/* average ideal load of runnable tasks */
	volatile u64	load_actual;	/* average actual load of runnable tasks */

	volatile u64	avg_lat_cri;	/* average latency criticality (LC) */
	volatile u64	max_lat_cri;	/* maximum latency criticality (LC) */
	volatile u64	min_lat_cri;	/* minimum latency criticality (LC) */

	volatile s64	inc1k_low;	/* increment from low LC to priority mapping */
	volatile s64	inc1k_high;	/* increment from high LC to priority mapping */
};

/*
 * Per-CPU context
 */
struct cpu_ctx {
	/* 
	 * Information used to keep track of CPU utilization
	 */
	volatile u64	idle_total;	/* total idle time so far */
	volatile u64	idle_start_clk;	/* when the CPU becomes idle */

	/*
	 * Information used to keep track of load
	 */
	volatile u64	load_actual;	/* actual load of runnable tasks */
	volatile u64	load_ideal;	/* ideal loaf of runnable tasks */

	/*
	 * Information used to keep track of latency criticality
	 */
	volatile u64	max_lat_cri;	/* maximum latency criticality */
	volatile u64	min_lat_cri;	/* minimum latency criticality */
	volatile u64	sum_lat_cri;	/* sum of latency criticality */
	volatile u64	sched_nr;	/* number of schedules */
};

struct task_ctx {
	/*
	 * Essential task running statistics for latency criticality calculation
	 */
	u64	last_start_clk;	/* last time when scheduled in */
	u64	last_stop_clk;	/* last time when scheduled out */
	u64	run_time_ns;	/* average runtime per schedule */
	u64	run_freq;	/* scheduling frequency in a second */
	u64	last_wait_clk;	/* last time when a task waits for an event */
	u64	wait_freq;	/* waiting frequency in a second */
	u64	wake_freq;	/* waking-up frequency in a second */
	u64	last_wake_clk;	/* last time when a task wakes up others */

	u64	load_actual;	/* task load derived from run_time and run_freq */
	u64	vdeadline_delta_ns;
	u64	eligible_delta_ns;
	u64	slice_ns;
	u64	greedy_ratio;
	u64	lat_cri;
	u16	slice_boost_prio;/* how many times a task fully consumed the slice */
	u16	lat_prio;	/* latency priority */
	s16	lat_boost_prio;	/* DEBUG */
};

struct task_ctx_x {
	pid_t	pid;
	char	comm[TASK_COMM_LEN + 1];
	u16	static_prio;	/* nice priority */
	u16	cpu_id;		/* where a task ran */
	u64	cpu_util;	/* cpu utilization in [0..100] */
	u64	max_lat_cri;	/* maximum latency criticality */
	u64	min_lat_cri;	/* minimum latency criticality */
	u64	avg_lat_cri;	/* average latency criticality */
};


/*
 * introspection
 */
enum {
       LAVD_CMD_NOP		= 0x0,
       LAVD_CMD_SCHED_N		= 0x1,
       LAVD_CMD_PID		= 0x2,
       LAVD_CMD_DUMP		= 0x3,
};

enum {
       LAVD_MSG_TASKC		= 0x1,
};

struct introspec {
	volatile u64	arg;
	volatile u32	cmd;
	u8		requested;
};

struct msg_hdr {
	u32		kind;
};

struct msg_task_ctx {
	struct msg_hdr		hdr;
	struct task_ctx		taskc;
	struct task_ctx_x	taskc_x;
};

#endif /* __INTF_H */
