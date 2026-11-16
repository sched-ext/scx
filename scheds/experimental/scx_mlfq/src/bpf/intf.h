// SPDX-License-Identifier: GPL-2.0
/*
 * Definitions shared by the mlfq BPF scheduler and its userspace loader.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __MLFQ_INTF_H
#define __MLFQ_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned long long u64;
#endif

enum mlfq_consts {
	MLFQ_MAX_CPUS		= 1024,
	MLFQ_MAX_LLCS		= 64,
	MLFQ_MAX_GROUPS		= 64,
};

/*
 * Event counters. Each CPU keeps its own copy and userspace folds them
 * per LLC when it reports.
 */
enum mlfq_stat_idx {
	MLFQ_STAT_DISPATCHED,	/* moved from an mlfq DSQ to a local DSQ */
	MLFQ_STAT_DIRECT,	/* sent to an idle CPU straight from wakeup */
	MLFQ_STAT_STEAL,	/* pulled from the DSQ of another LLC */
	MLFQ_STAT_FALLBACK,	/* inserted into the fallback DSQ */
	MLFQ_STAT_KICK_IDLE,	/* idle CPU woken up after an enqueue */
	MLFQ_STAT_KICK_PREEMPT,	/* running task asked to give up its CPU */
	MLFQ_STAT_KEEP,		/* previous task kept running with a new slice */
	MLFQ_STAT_PREEMPTED,	/* task stopped while still runnable */
	MLFQ_STAT_PROMOTED,	/* woke up below the top level and went back to it */
	MLFQ_STAT_DEMOTED,	/* dropped to a lower level while running */
	MLFQ_NR_STATS,
};

struct mlfq_cpu_stats {
	u64 cnt[MLFQ_NR_STATS];
};

#endif /* __MLFQ_INTF_H */
