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

enum event_type {
	CPU_PERF_SET,
	SCHED_REG,
	SCHED_UNREG,
	SCHED_SWITCH,
	SCHED_WAKEUP,
	EVENT_MAX,
};

struct bpf_event {
	int		type;
	u32		cpu;
	u32		perf;
	u64		next_dsq_id;
	u64		next_dsq_lat_us;
	u32		next_dsq_nr;
	u64		next_dsq_vtime;
	u64		next_slice_ns;
	u64		prev_dsq_id;
	u64		prev_used_slice_ns;
	u64		prev_slice_ns;
};

struct task_ctx {
	u64		dsq_id;
	u64		dsq_insert_time;
	u64		dsq_vtime;
	u64		slice_ns;
	u64		last_run_ns;
};

#endif /* __INTF_H */
