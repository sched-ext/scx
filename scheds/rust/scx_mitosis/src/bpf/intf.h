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

enum consts {
	MAX_CPUS_SHIFT = 9,
	MAX_CPUS = 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8 = MAX_CPUS / 8,
	MAX_CELLS = 16,
	USAGE_HALF_LIFE = 100000000, /* 100ms */
};

/* Statistics */
enum cell_stat_idx {
	CSTAT_LOCAL,
	CSTAT_GLOBAL,
	CSTAT_AFFN_VIOL,
	NR_CSTATS,
};

struct cpu_ctx {
	u64 cstats[MAX_CELLS][NR_CSTATS];
	u64 cell_cycles[MAX_CELLS];
	u32 prev_cell;
	u32 cell;
};

struct cgrp_ctx {
	struct ravg_data load_rd;
	u64 load;
	struct ravg_data pinned_load_rd;
	u64 pinned_load;
	u32 cell;
};

#endif /* __INTF_H */
