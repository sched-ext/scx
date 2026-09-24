/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. */
#pragma once

#include <scx/common.bpf.h>

/* Contiguous CID ranges supplied by the kernel's topology ordering. */
struct scx_cid_ranges {
	u32 core_base;
	u32 core_nr;
	u32 llc_base;
	u32 llc_nr;
	u32 node_base;
	u32 node_nr;
};

/* State for a walk from the highest CID to the lowest. */
struct scx_cid_range_builder {
	s32 last_core;
	s32 last_llc;
	s32 last_node;
	u32 core_nr;
	u32 llc_nr;
	u32 node_nr;
};

#define SCX_CID_RANGE_BUILDER_INIT { \
	.last_core = -1, .last_llc = -1, .last_node = -1 \
}

/*
 * Build the ranges of @cid while walking the CID space backwards. The first
 * CID seen in each domain is its highest, so its distance from the domain's
 * base gives the domain size without another pass. CIDs without topology
 * each get a singleton range and leave the builder state alone.
 */
static __always_inline void
scx_cid_ranges_build(struct scx_cid_ranges __arena *out,
		     struct scx_cid_range_builder *builder,
		     const struct scx_cid_topo *topo, u32 cid)
{
	if (topo->core_cid < 0 || topo->llc_cid < 0 || topo->node_cid < 0) {
		out->core_base = cid;
		out->core_nr = 1;
		out->llc_base = cid;
		out->llc_nr = 1;
		out->node_base = cid;
		out->node_nr = 1;
		return;
	}

	if (topo->core_cid != builder->last_core) {
		builder->last_core = topo->core_cid;
		builder->core_nr = cid + 1 - topo->core_cid;
	}
	if (topo->llc_cid != builder->last_llc) {
		builder->last_llc = topo->llc_cid;
		builder->llc_nr = cid + 1 - topo->llc_cid;
	}
	if (topo->node_cid != builder->last_node) {
		builder->last_node = topo->node_cid;
		builder->node_nr = cid + 1 - topo->node_cid;
	}

	out->core_base = topo->core_cid;
	out->core_nr = builder->core_nr;
	out->llc_base = topo->llc_cid;
	out->llc_nr = builder->llc_nr;
	out->node_base = topo->node_cid;
	out->node_nr = builder->node_nr;
}

/*
 * The smallest represented topology range containing a domain of @span CIDs.
 * An intermediate kernel level, such as a cluster, rounds up to its LLC.
 * The result packs the length in the upper 32 bits and base in the lower.
 */
static __always_inline u64
scx_cid_domain_range(const struct scx_cid_ranges __arena *ranges,
		     u32 span, u32 fallback, u32 nr_cids)
{
	if (!span)
		span = fallback;
	if (span <= ranges->core_nr)
		return (u64)ranges->core_nr << 32 | ranges->core_base;
	if (span <= ranges->llc_nr)
		return (u64)ranges->llc_nr << 32 | ranges->llc_base;
	if (span <= ranges->node_nr)
		return (u64)ranges->node_nr << 32 | ranges->node_base;
	return (u64)nr_cids << 32;
}
