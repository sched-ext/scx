// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifndef __INTF_H
#define __INTF_H

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#endif
#include <stdbool.h>


enum consts {
	MAX_COMM	= 16,
};

enum stat_id {
	STAT_DROPPED_EVENTS,
	NR_SCXTOP_STATS,
};

enum mode {
	MODE_NORMAL,
	MODE_TRACING,
	MODE_TRACE_STOPPING,
};

enum event_type {
	CPU_HP,
	CPU_PERF_SET,
	GPU_MEM,
	IPI,
	SCHED_REG,
	SCHED_SWITCH,
	SCHED_UNREG,
	SCHED_WAKEUP,
	SCHED_WAKING,
	SOFTIRQ,
	TRACE_STARTED,
	TRACE_STOPPED,
	EVENT_MAX,
};

struct sched_switch_event {
	u32		cpu;
	bool		preempt;
	char		next_comm[MAX_COMM];
	u64		next_dsq_id;
	u64		next_dsq_lat_us;
	u32		next_dsq_nr;
	u64		next_dsq_vtime;
	u64		next_slice_ns;
	u32		next_pid;
	u32		next_tgid;
	int		next_prio;
	char		prev_comm[MAX_COMM];
	u64		prev_dsq_id;
	u64		prev_used_slice_ns;
	u64		prev_slice_ns;
	u32		prev_pid;
	u32		prev_tgid;
	u64		prev_state;
	int		prev_prio;
};

struct wakeup_event {
	u32		pid;
	int		prio;
	char		comm[MAX_COMM];
};

struct set_perf_event {
	u32		perf;
};

struct softirq_event {
	u64		entry_ts;
	u64		exit_ts;
	u32		pid;
	int		softirq_nr;
};

struct ipi_event {
	u32		pid;
	u32		target_cpu;
};

struct gpu_mem_event {
	u64             size;
	u32             gpu;
	u32             pid;
};

struct cpuhp_event {
	u32             cpu;
	u32             pid;
	int             target;
	int             state;
};

struct trace_started_event {
	bool		start_immediately;
	bool		stop_scheduled;
};

struct bpf_event {
	int		type;
	u64		ts;
	u32		cpu;
	union {
		struct  gpu_mem_event gm;
		struct  cpuhp_event chp;
		struct	ipi_event ipi;
		struct	sched_switch_event sched_switch;
		struct	set_perf_event perf;
		struct	softirq_event softirq;
		struct	wakeup_event wakeup;
		struct	wakeup_event waking;
		struct  trace_started_event trace;
	} event;
};

struct task_ctx {
	u64		wakeup_ts;
	u64		dsq_id;
	u64		dsq_insert_time;
	u64		dsq_vtime;
	u64		slice_ns;
	u64		last_run_ns;
};

struct schedule_stop_trace_args {
	u64		stop_timestamp;
};

#endif /* __INTF_H */
