// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __CHAOS_INTF_H
#define __CHAOS_INTF_H

#ifndef __KERNEL__
typedef unsigned long long u64;
#endif

enum chaos_consts {
	CHAOS_DSQ_BASE_SHIFT	= 16,
	CHAOS_DSQ_BASE		= 1 << CHAOS_DSQ_BASE_SHIFT,

	CHAOS_NUM_PPIDS_CHECK	= 1 << 20,
};

enum chaos_match {
	CHAOS_MATCH_UNKNOWN		= 0,
	CHAOS_MATCH_COMPLETE		= 1 << 0,
	CHAOS_MATCH_EXCLUDED		= 1 << 1,
	CHAOS_MATCH_HAS_PARENT		= 1 << 2,

	CHAOS_MATCH_MAX			= 1 << 3,
};

enum chaos_trait_kind {
	CHAOS_TRAIT_NONE,
	CHAOS_TRAIT_RANDOM_DELAYS,
	CHAOS_TRAIT_MAX,
};

struct chaos_task_ctx {
	// chaos_task_ctx is initialised zero'd
	enum chaos_match	match;

	enum chaos_trait_kind	next_trait;
	u64			enq_flags;
	u64			p2dq_vtime;
};

#endif /* __CHAOS_INTF_H */
