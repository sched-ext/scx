// SPDX-License-Identifier: GPL-2.0
/*
 * Definitions shared by the flow BPF scheduler and its userspace loader.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_INTF_H
#define __FLOW_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned long long u64;
#endif

enum flow_consts {
	FLOW_MAX_CPUS		= 1024,
	FLOW_MAX_LLCS		= 64,
	FLOW_MAX_GROUPS		= 64,
};

/*
 * Event counters. Each CPU keeps its own copy and userspace folds them
 * per LLC when it reports.
 */
enum flow_stat_idx {
	FLOW_STAT_DISPATCHED,	/* moved from a flow DSQ to a local DSQ */
	FLOW_STAT_DIRECT,	/* sent to an idle CPU straight from wakeup */
	FLOW_STAT_STEAL,	/* pulled from the DSQ of another LLC */
	FLOW_STAT_FALLBACK,	/* inserted into the fallback DSQ */
	FLOW_STAT_KICK_IDLE,	/* idle CPU woken up after an enqueue */
	FLOW_STAT_KICK_PREEMPT,	/* running task asked to give up its CPU */
	FLOW_STAT_KEEP,		/* previous task kept running with a new slice */
	FLOW_STAT_PREEMPTED,	/* task stopped while still runnable */
	FLOW_NR_STATS,
};

struct flow_cpu_stats {
	u64 cnt[FLOW_NR_STATS];
};

#endif /* __FLOW_INTF_H */
