// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#ifndef __KERNEL__
typedef unsigned long long u64;
typedef unsigned int u32;
typedef _Bool bool;
#endif

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/ravg.bpf.h"
#else
#include <scx/ravg.bpf.h>
#endif

/* ---- Work stealing config (compile-time) ------------------------------- */
#ifndef MITOSIS_ENABLE_STEALING
#define MITOSIS_ENABLE_STEALING 1
#endif
/* ----------------------------------------------------------------------- */

enum consts {
	CACHELINE_SIZE = 64,
	MAX_CPUS_SHIFT = 9,
	MAX_CPUS = 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8 = MAX_CPUS / 8,
	MAX_CELLS = 16,
	USAGE_HALF_LIFE = 100000000, /* 100ms */

	PCPU_BASE = 0x80000000,
	MAX_CG_DEPTH = 256,
};

/* Statistics */
enum cell_stat_idx {
	CSTAT_LOCAL,
	CSTAT_CPU_DSQ,
	CSTAT_CELL_DSQ,
	CSTAT_AFFN_VIOL,
	NR_CSTATS,
};

/* Function invocation counters */
enum fn_counter_idx {
	COUNTER_SELECT_CPU,
	COUNTER_ENQUEUE,
	COUNTER_DISPATCH,
	NR_COUNTERS,
};

struct cpu_ctx {
	u64 cstats[MAX_CELLS][NR_CSTATS];
	u64 cell_cycles[MAX_CELLS];
	u32 cell;
	u64 vtime_now;
};

struct cgrp_ctx {
	u32 cell;
	bool cell_owner;
};

#endif /* __INTF_H */
