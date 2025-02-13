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

enum event_type {
	CPU_PERF_SET,
	SCHED_REG,
	SCHED_SWITCH,
	SCHED_UNREG,
	SCHED_WAKEUP,
	SCHED_WAKING,
	SOFTIRQ,
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

struct bpf_event {
	int		type;
	u64		ts;
	u32		cpu;
	union {
		struct	sched_switch_event sched_switch;
		struct	wakeup_event waking;
		struct	wakeup_event wakeup;
		struct	set_perf_event perf;
		struct	softirq_event softirq;
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

#endif /* __INTF_H */
