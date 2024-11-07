/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#ifndef __LAYERED_COST_H
#define __LAYERED_COST_H

#ifdef LSP
#define __bpf__
#ifndef LSP_INC
#include "../../../../include/scx/common.bpf.h"
#endif
#endif
#include "intf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum cost_consts {
	COST_GLOBAL_KEY		= 0,
	HI_FALLBACK_DSQ_WEIGHT	= 50,
	LO_FALLBACK_DSQ_WEIGHT	= 10,

	/*
	 * Max global budgets map fallback DSQs (per LLC) as well as layers.
	 * This is so that budgets can easily be calculated between fallback
	 * dsqs and weights. The cost accounting could be done at the DSQ
	 * level, which would simplify some things at the cost of the size of
	 * the cost struct.
	 */
	MAX_GLOBAL_BUDGETS	= MAX_LLCS + MAX_LAYERS + 1,
};

/*
 * Cost accounting struct that is used in both the per CPU and global context.
 * Budgets are allowed to recurse to parent structs.
 */
struct cost {
	s64		budget[MAX_GLOBAL_BUDGETS];
	s64		capacity[MAX_GLOBAL_BUDGETS];
	u32		pref_budget; // the cost with the most budget
	u32		pref_layer; // the layer with the most budget.
	u32		idx;
	bool		overflow;
	bool		has_parent;
};


#endif /* __LAYERED_COST_H */
