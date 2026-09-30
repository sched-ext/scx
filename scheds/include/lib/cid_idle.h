/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. */
#pragma once

#include <lib/cid_topology.h>
#include <lib/arena_map.h>

/*
 * CID idle tracking for sched_ext schedulers
 * ------------------------------------------
 *
 * This header owns the idle and idle-core-hint cmasks and provides the
 * operations needed to scan and claim idle CIDs. The scheduler decides which
 * candidate fits a task. It must use a CID space framed as [0, nr_cids), with a
 * scx_cid_ranges entry for each CID whose core and shard ranges are in that
 * space. See cid_topology.h for the range builder.
 *
 * In ops.init(), call scx_cid_idle_init() with the SMT setting and split
 * level. It allocates ranges and segments, then marks every CID idle so CPUs
 * which start idle can be selected. The initial set is optimistic: a claim
 * or ops.update_idle() clears a CID that is already busy. Segment allocations
 * use the CID's NUMA node when the kfunc is available.
 *
 * Schedulers with ranges embedded in another topology table can pass the
 * first ranges entry and the table stride to scx_cid_idle_init(). Set
 * nr_cids_max before init when a larger CID space is needed. A scheduler
 * that rewrites a level's base and length must rewrite its index to match:
 * init sizes each node's pool from the first and last index of the split
 * level in the node.
 *
 * Each segment of the split level must start at a core boundary and lie
 * within one node; init fails otherwise. Kernel-built shards satisfy this,
 * since they are cut on core boundaries inside an LLC. Shard boundaries
 * passed to scx_bpf_cid_override() must follow the same rules to use
 * SCX_CID_IDLE_SPLIT_SHARD.
 *
 * Runtime lifecycle:
 *
 *   ops.update_idle(cid, true)  -> scx_cid_idle_set()
 *   ops.update_idle(cid, false) -> scx_cid_idle_clear()
 *   ops.dispatch() on an idle CPU -> scx_cid_idle_rearm()
 *
 * A claim clears the bit, so concurrent selectors cannot both take the same
 * CID. Initialize with smt_enabled=false when whole-core tracking is not
 * needed.
 *
 * Winning a claim excludes other claimers, but does not guarantee that the
 * target CPU stays idle until the task arrives.
 *
 * scx_cid_idle_pick() searches the anchor CID's core, LLC, node, or all CIDs.
 * SCX_CID_IDLE_SAME_CORE tries the specified cid first, then its siblings.
 * Wider scopes start after the target cid and wrap. The picker checks task
 * affinity and claims the chosen CID.
 *
 * SCX_CID_IDLE_FULL_CORE accepts only a candidate whose SMT siblings are idle
 * at the time of the check.
 *
 * SCX_CID_IDLE_ANY_CPU accepts either a lone idle sibling or a whole idle core.
 * These scopes include smaller domains, so a node scan can revisit its target
 * LLC. A successful claim reserves one CID, not the whole core.
 *
 * Example idle cid management lifecycle:
 *
 *   #define TOUCH_ARENA() asm volatile("" :: "r"(&arena))
 *   extern const volatile bool smt_enabled;
 *   struct scx_cid_idle_state idle_state;
 *
 *   // ops.init(): allocate ranges and segments, then seed idle CIDs.
 *   s32 BPF_STRUCT_OPS_SLEEPABLE(example_init)
 *   {
 *           TOUCH_ARENA();
 *           return scx_cid_idle_init(&idle_state, smt_enabled,
 *                                    SCX_CID_IDLE_SPLIT_SHARD, NULL, 0);
 *   }
 *
 *   // ops.update_idle(): own the idle bitmap after registering this op.
 *   void BPF_STRUCT_OPS(example_update_idle, s32 cid, bool is_idle)
 *   {
 *           TOUCH_ARENA();
 *           if (cid < 0 || (u32)cid >= idle_state.nr_cids)
 *                   return;
 *           if (is_idle)
 *                   scx_cid_idle_set(&idle_state, cid);
 *           else
 *                   scx_cid_idle_clear(&idle_state, cid);
 *   }
 *
 *   // ops.dispatch(): rearm only after failing to dispatch work.
 *   void BPF_STRUCT_OPS(example_dispatch, s32 cid,
 *                       struct task_struct *prev)
 *   {
 *           TOUCH_ARENA();
 *           // dispatch_queued_task() is supplied by the scheduler.
 *           if (dispatch_queued_task(cid))
 *                   return;
 *           scx_cid_idle_rearm(&idle_state, cid);
 *   }
 *
 *   // ops.select_cid(): try the previous core, then widen the search.
 *   s32 BPF_STRUCT_OPS(example_select_cid, struct task_struct *p,
 *                      s32 prev_cid, u64 wake_flags)
 *   {
 *           s32 cid = -EBUSY;
 *
 *           TOUCH_ARENA();
 *           if (idle_state.smt_enabled) {
 *                   cid = scx_cid_idle_pick(&idle_state, p, prev_cid,
 *                                           SCX_CID_IDLE_SAME_CORE,
 *                                           SCX_CID_IDLE_FULL_CORE);
 *                   if (cid < 0)
 *                           cid = scx_cid_idle_pick(&idle_state, p, prev_cid,
 *                                   SCX_CID_IDLE_SAME_LLC,
 *                                   SCX_CID_IDLE_FULL_CORE);
 *                   if (cid < 0)
 *                           cid = scx_cid_idle_pick(&idle_state, p,
 *                                   prev_cid, SCX_CID_IDLE_SAME_NODE,
 *                                   SCX_CID_IDLE_FULL_CORE);
 *                   if (cid < 0)
 *                           cid = scx_cid_idle_pick(&idle_state, p,
 *                                   prev_cid, SCX_CID_IDLE_ANYWHERE,
 *                                   SCX_CID_IDLE_FULL_CORE);
 *                   if (cid >= 0)
 *                           return cid;
 *           }
 *           cid = scx_cid_idle_pick(&idle_state, p, prev_cid,
 *                                   SCX_CID_IDLE_SAME_CORE,
 *                                   SCX_CID_IDLE_ANY_CPU);
 *           if (cid < 0)
 *                   cid = scx_cid_idle_pick(&idle_state, p, prev_cid,
 *                           SCX_CID_IDLE_SAME_LLC,
 *                           SCX_CID_IDLE_ANY_CPU);
 *           if (cid < 0)
 *                   cid = scx_cid_idle_pick(&idle_state, p, prev_cid,
 *                                           SCX_CID_IDLE_SAME_NODE,
 *                                           SCX_CID_IDLE_ANY_CPU);
 *           if (cid < 0)
 *                   cid = scx_cid_idle_pick(&idle_state, p, prev_cid,
 *                                           SCX_CID_IDLE_ANYWHERE,
 *                                           SCX_CID_IDLE_ANY_CPU);
 *           return cid >= 0 ? cid : prev_cid;
 *   }
 */
struct scx_cid_idle_state {
	struct scx_cid_idle_segment __arena * __arena *segments;
	struct scx_cid_idle_segment __arena * __arena *node_summaries;
	struct scx_cmask __arena * __arena *node_core_llcs;
	struct scx_cid_ranges __arena *ranges;
	u32 range_stride;
	u32 nr_cids_max;
	u32 nr_cids;
	bool smt_enabled;
	/* BSS scratch for scx_bpf_cid_topo(), used only in ops.init(). */
	struct scx_cid_topo topo_buf;
};

/*
 * One topology segment's idle mask, isolated by cache lines. A node summary
 * is a segment too: its idle mask has a bit set at the base of each segment
 * of the node that may have an idle CID, and its core-hint mask follows it
 * in the node's pool, reached through scx_cid_idle_state->node_core_llcs.
 */
struct scx_cid_idle_segment {
	struct scx_cid_idle_segment __arena *summary;
	struct scx_cmask idle;
};

struct scx_cid_idle_build {
	char __arena *node_pool;
	struct scx_cid_idle_segment __arena *node_summary;
	u32 node_pool_size;
	u32 node_pool_off;
	u32 node_pool_base;
};

static __always_inline struct scx_cid_ranges __arena *
scx_cid_idle_ranges(const struct scx_cid_idle_state *state, u32 cid)
{
	return (void __arena *)((char __arena *)state->ranges +
				 (u64)cid * state->range_stride);
}

enum scx_cid_idle_scope {
	SCX_CID_IDLE_SAME_CORE,
	SCX_CID_IDLE_SAME_LLC,
	SCX_CID_IDLE_SAME_NODE,
	SCX_CID_IDLE_ANYWHERE,
};

enum scx_cid_idle_kind {
	SCX_CID_IDLE_ANY_CPU,
	SCX_CID_IDLE_FULL_CORE,
};

enum scx_cid_idle_split {
	SCX_CID_IDLE_SPLIT_CORE,
	SCX_CID_IDLE_SPLIT_SHARD,
	SCX_CID_IDLE_SPLIT_LLC,
	SCX_CID_IDLE_SPLIT_NODE,
};

static __always_inline int
scx_cid_idle_split_range(const struct scx_cid_ranges __arena *ranges,
			 enum scx_cid_idle_split split, u32 *base, u32 *nr)
{
	switch (split) {
	case SCX_CID_IDLE_SPLIT_CORE:
		*base = ranges->core_base;
		*nr = ranges->core_nr;
		break;
	case SCX_CID_IDLE_SPLIT_SHARD:
		*base = ranges->shard_base;
		*nr = ranges->shard_nr;
		break;
	case SCX_CID_IDLE_SPLIT_LLC:
		*base = ranges->llc_base;
		*nr = ranges->llc_nr;
		break;
	case SCX_CID_IDLE_SPLIT_NODE:
		*base = ranges->node_base;
		*nr = ranges->node_nr;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static __always_inline u32
scx_cid_idle_split_index(const struct scx_cid_ranges __arena *ranges,
			 enum scx_cid_idle_split split)
{
	switch (split) {
	case SCX_CID_IDLE_SPLIT_CORE:
		return ranges->core_idx;
	case SCX_CID_IDLE_SPLIT_SHARD:
		return ranges->shard_idx;
	case SCX_CID_IDLE_SPLIT_LLC:
		return ranges->llc_idx;
	case SCX_CID_IDLE_SPLIT_NODE:
		return ranges->node_idx;
	default:
		return 0;
	}
}

/* Allocate the pointer tables in ops.init(). */
static __always_inline int
scx_cid_idle_alloc(struct scx_cid_idle_state *state, u32 nr_cids_max)
{
	u64 segment_bytes;
	u32 segment_pages;
	struct scx_cid_idle_segment __arena * __arena *segments;
	struct scx_cid_idle_segment __arena * __arena *summaries;
	struct scx_cmask __arena * __arena *core_llcs;

	if (!nr_cids_max)
		return -EINVAL;
	segment_bytes = (u64)nr_cids_max * sizeof(*segments);
	segment_pages = (segment_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	segments = bpf_arena_alloc_pages(&arena, NULL, segment_pages,
					  NUMA_NO_NODE, 0);
	if (!segments)
		return -ENOMEM;
	summaries = bpf_arena_alloc_pages(&arena, NULL, segment_pages,
					   NUMA_NO_NODE, 0);
	if (!summaries) {
		bpf_arena_free_pages(&arena, segments, segment_pages);
		return -ENOMEM;
	}
	core_llcs = bpf_arena_alloc_pages(&arena, NULL, segment_pages,
					    NUMA_NO_NODE, 0);
	if (!core_llcs) {
		bpf_arena_free_pages(&arena, summaries, segment_pages);
		bpf_arena_free_pages(&arena, segments, segment_pages);
		return -ENOMEM;
	}

	state->segments = segments;
	state->node_summaries = summaries;
	state->node_core_llcs = core_llcs;
	state->nr_cids_max = nr_cids_max;
	state->nr_cids = 0;
	return 0;
}

/* Keep segments separate and align the node's core-hint mask. */
static __always_inline u64
scx_cid_idle_segment_bytes(u32 nr, bool with_core_hints)
{
	u64 mask_bytes = (sizeof(struct scx_cmask) +
			  (u64)CMASK_NR_WORDS(nr) * sizeof(u64) + 63) & ~63ULL;
	u64 idle_bytes = (sizeof(struct scx_cid_idle_segment) +
			  (u64)CMASK_NR_WORDS(nr) * sizeof(u64) + 63) & ~63ULL;

	return idle_bytes + (with_core_hints ? mask_bytes : 0);
}

/* Bound each segment by the node size to size the pool in one pass. */
static __always_inline int
scx_cid_idle_node_pool_bytes(const struct scx_cid_ranges __arena *first,
			     const struct scx_cid_ranges __arena *last,
			     enum scx_cid_idle_split split, u64 *bytes)
{
	u32 first_idx = scx_cid_idle_split_index(first, split);
	u32 last_idx = scx_cid_idle_split_index(last, split);
	u32 nr_segments;

	if (last_idx < first_idx ||
	    last_idx - first_idx >= first->node_nr)
		return -EINVAL;
	nr_segments = last_idx - first_idx + 1;
	*bytes = scx_cid_idle_segment_bytes(first->node_nr, true) +
		 (u64)nr_segments *
		 scx_cid_idle_segment_bytes(first->node_nr, false);
	return 0;
}

/* The node's core-hint mask follows its summary segment in the pool. */
static __always_inline struct scx_cmask __arena *
scx_cid_idle_summary_core_llcs(struct scx_cid_idle_segment __arena *summary)
{
	return (void __arena *)((char __arena *)summary +
		scx_cid_idle_segment_bytes(summary->idle.nr_cids, false));
}

static __always_inline struct scx_cid_idle_segment __arena *
scx_cid_idle_alloc_segment(struct scx_cid_idle_build *build, u32 base,
			   u32 nr, bool with_core_hints)
{
	struct scx_cid_idle_segment __arena *seg;
	u64 bytes;

	bytes = scx_cid_idle_segment_bytes(nr, with_core_hints);
	if (!build->node_pool || bytes > build->node_pool_size - build->node_pool_off)
		return NULL;
	seg = (void __arena *)(build->node_pool + build->node_pool_off);
	build->node_pool_off += bytes;
	seg->summary = NULL;
	cmask_init(&seg->idle, base, nr);
	if (with_core_hints)
		cmask_init(scx_cid_idle_summary_core_llcs(seg), base, nr);
	return seg;
}

/* Allocate one NUMA-local pool for a node's summary and all its segments. */
static __always_inline int
scx_cid_idle_start_node(struct scx_cid_idle_state *state,
			struct scx_cid_idle_build *build, u32 node_base,
			u32 node_nr, u64 bytes, s32 node)
{
	u64 pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	if (!node_nr || node_base >= state->nr_cids ||
	    node_nr > state->nr_cids - node_base ||
	    !pages || pages > (u64)~0U / PAGE_SIZE)
		return -EINVAL;
	build->node_pool = bpf_arena_alloc_pages(&arena, NULL, pages, node, 0);
	if (!build->node_pool)
		return -ENOMEM;
	build->node_pool_size = pages * PAGE_SIZE;
	build->node_pool_off = 0;
	build->node_pool_base = node_base;
	build->node_summary = scx_cid_idle_alloc_segment(build, node_base,
							  node_nr, true);
	if (!build->node_summary)
		return -ENOMEM;
	state->node_summaries[node_base] = build->node_summary;
	state->node_core_llcs[node_base] =
		scx_cid_idle_summary_core_llcs(build->node_summary);
	return 0;
}

/* Validate a node's range and allocate its summary and segment pool. */
static __always_inline int
scx_cid_idle_init_node(struct scx_cid_idle_state *state,
		       struct scx_cid_idle_build *build, u32 cid,
		       enum scx_cid_idle_split split)
{
	const struct scx_cid_ranges __arena *first = scx_cid_idle_ranges(state, cid);
	const struct scx_cid_ranges __arena *last;
	u64 bytes;
	int ret;

	if (!first->node_nr || first->node_nr > state->nr_cids - cid)
		return -EINVAL;
	last = scx_cid_idle_ranges(state, cid + first->node_nr - 1);
	ret = scx_cid_idle_node_pool_bytes(first, last, split, &bytes);
	if (ret)
		return ret;
	return scx_cid_idle_start_node(state, build, cid, first->node_nr,
					    bytes, __COMPAT_scx_bpf_cid_node(cid));
}

/* Add a segment after scx_cid_idle_start_node() for its node. */
static __always_inline int
scx_cid_idle_add_segment(struct scx_cid_idle_state *state,
			 struct scx_cid_idle_build *build, u32 base, u32 nr,
			 u32 node_base, u32 node_nr)
{
	struct scx_cid_idle_segment __arena *seg, *summary;
	u32 cid;

	if (!state->segments || !nr || base >= state->nr_cids ||
	    nr > state->nr_cids - base || !node_nr ||
	    node_base > base || node_nr > state->nr_cids - node_base ||
	    nr > node_base + node_nr - base ||
	    node_base != build->node_pool_base || !build->node_summary)
		return -EINVAL;
	if (base != node_base && !state->segments[node_base])
		return -EINVAL;
	summary = build->node_summary;
	seg = scx_cid_idle_alloc_segment(build, base, nr, false);
	if (!seg)
		return -ENOMEM;
	seg->summary = summary;
	bpf_arena_for(cid, base, base + nr)
		state->segments[cid] = seg;
	return 0;
}

static __always_inline struct scx_cmask __arena *
scx_cid_idle_mask(const struct scx_cid_idle_state *state, u32 cid)
{
	struct scx_cid_idle_segment __arena *seg;

	seg = state->segments[cid];
	return &seg->idle;
}

/* Set the active CID count before adding segments. */
static __always_inline int
scx_cid_idle_init_state(struct scx_cid_idle_state *state, u32 nr_cids,
			bool smt_enabled)
{
	int ret;

	if (!nr_cids ||
	    (state->nr_cids_max && nr_cids > state->nr_cids_max))
		return -EINVAL;
	if (!state->segments && !state->node_summaries &&
	    !state->node_core_llcs) {
		ret = scx_cid_idle_alloc(state, state->nr_cids_max ?: nr_cids);
		if (ret)
			return ret;
	} else if (!state->segments || !state->node_summaries ||
		   !state->node_core_llcs) {
		return -EINVAL;
	}
	state->nr_cids = nr_cids;
	state->smt_enabled = smt_enabled;
	return 0;
}

static __always_inline bool
scx_cid_idle_test(const struct scx_cid_idle_state *state, s32 cid)
{
	return cid >= 0 && (u32)cid < state->nr_cids &&
	       __cmask_test(cid, scx_cid_idle_mask(state, cid));
}

static __always_inline bool
scx_cid_idle_empty(const struct scx_cid_idle_state *state)
{
	u32 cid;

	bpf_arena_for(cid, 0, state->nr_cids) {
		struct scx_cid_idle_segment __arena *summary =
			state->node_summaries[cid];

		if (!cmask_empty(&summary->idle))
			return false;
		cid = summary->idle.base + summary->idle.nr_cids - 1;
	}
	return true;
}

static __always_inline bool
scx_cid_idle_any_core(const struct scx_cid_idle_state *state)
{
	u32 cid;

	bpf_arena_for(cid, 0, state->nr_cids) {
		struct scx_cid_idle_segment __arena *summary =
			state->node_summaries[cid];

		if (!cmask_empty(state->node_core_llcs[cid]))
			return true;
		cid = summary->idle.base + summary->idle.nr_cids - 1;
	}
	return false;
}

/* Read only the part of one segment selected by the caller's range. */
static __always_inline u64
scx_cid_idle_segment_word(const struct scx_cid_idle_segment __arena *seg,
			  const struct scx_cmask __arena *tier,
			  u32 word, u32 base, u32 nr)
{
	u64 wlo = (u64)word * 64, lo = base, hi = (u64)base + nr;
	u64 bits;

	if (lo < wlo)
		lo = wlo;
	if (hi > wlo + 64)
		hi = wlo + 64;
	if (lo >= hi)
		return 0;
	bits = cmask_word(&seg->idle, word - seg->idle.base / 64) &
	       GENMASK_U64(hi - wlo - 1, lo - wlo);
	return tier ? bits & cmask_word(tier, word) : bits;
}

/*
 * Return the next nonempty word in a CID range, advancing @cursor.
 *
 * The segment at @cursor is read directly when @cursor is inside it or the
 * rest of the range ends inside it, so narrow scopes never touch a summary.
 * Wider scans then walk the node summaries: their set bits are the bases of
 * the segments that may have an idle CID, and every CID between the current
 * position and the next set bit belongs to an empty segment. Only the
 * segments found that way are read.
 */
static __always_inline u64
__scx_cid_idle_scan_word(const struct scx_cid_idle_state *state,
			 const struct scx_cmask __arena *tier,
			 u32 end, u32 *cursor)
{
	struct scx_cid_idle_segment __arena *seg, *summary;
	u32 pos, direct_end;

	if (*cursor >= end)
		return 0;
	seg = state->segments[*cursor];
	summary = seg->summary;
	direct_end = seg->idle.base + seg->idle.nr_cids;
	if (*cursor == seg->idle.base && direct_end < end)
		direct_end = 0;
	else if (direct_end > end)
		direct_end = end;

	bpf_arena_for(pos, *cursor, end) {
		u32 next, k;
		u64 bits;

		if (pos >= direct_end) {
			u32 summary_end = summary->idle.base +
					  summary->idle.nr_cids;
			u64 candidates;

			/* Only a node boundary reaches the end of a summary. */
			if (pos >= summary_end) {
				summary = state->node_summaries[pos];
				summary_end = summary->idle.base +
					      summary->idle.nr_cids;
			}
			candidates = cmask_word(&summary->idle,
				pos / 64 - summary->idle.base / 64) &
				GENMASK_U64(63, pos & 63);
			if (!candidates) {
				next = (pos / 64 + 1) * 64;
				if (next > summary_end)
					next = summary_end;
				pos = (next < end ? next : end) - 1;
				continue;
			}
			next = (pos & ~63U) + __builtin_ctzll(candidates);
			if (next != pos) {
				pos = (next < end ? next : end) - 1;
				continue;
			}
			seg = state->segments[pos];
			direct_end = seg->idle.base + seg->idle.nr_cids;
			if (direct_end > end)
				direct_end = end;
		}

		k = pos / 64;
		next = direct_end < (k + 1) * 64 ? direct_end : (k + 1) * 64;
		bits = scx_cid_idle_segment_word(seg, tier, k, pos, next - pos);
		if (bits) {
			*cursor = next;
			return bits;
		}
		pos = next - 1;
	}
	*cursor = end;
	return 0;
}

/*
 * A nonempty result ends in the word before @cursor. @tier, if not NULL, is
 * read by absolute word index, so it must be framed with base 0.
 */
static __always_inline u64
scx_cid_idle_scan_word(const struct scx_cid_idle_state *state,
		       const struct scx_cmask __arena *tier,
		       u32 base, u32 nr, u32 *cursor, u32 *word)
{
	u64 bits;

	if (!nr)
		return 0;
	bits = __scx_cid_idle_scan_word(state, tier, base + nr, cursor);
	if (bits)
		*word = (*cursor - 1) / 64;
	return bits;
}

/* A successful claim prevents another concurrent wakeup from taking @cid. */
static __always_inline bool
scx_cid_idle_claim(struct scx_cid_idle_state *state, s32 cid)
{
	struct scx_cid_idle_segment __arena *seg;

	if (cid < 0 || (u32)cid >= state->nr_cids)
		return false;
	seg = state->segments[cid];
	if (!cmask_test_and_clear(cid, &seg->idle))
		return false;
	/*
	 * Clear the summary bit of a segment this claim emptied, then check
	 * again: a concurrent scx_cid_idle_set() may have added a CID after
	 * the first check and skipped the summary because its bit was still
	 * set. Either that set() sees the bit cleared and sets it again, or
	 * the second check here sees its CID. This is the store-buffering
	 * pattern: each side does an atomic RMW on one word and then loads
	 * the other, which needs the RMWs to act as full barriers. C11
	 * acq_rel alone does not promise that, but the x86 and arm64 JITs
	 * emit fully ordered fetching RMWs, and the CAS fallback is a full
	 * barrier.
	 *
	 * That ordering is required, not an optimization. Without it both
	 * sides can miss each other: the summary bit ends up clear while the
	 * segment holds an idle CID, and it stays clear. The CPU gets no
	 * further ops.update_idle() and no dispatch unless it is kicked, so
	 * the summary-driven scans and scx_cid_idle_empty() skip it until
	 * another CID of the segment changes state. A JIT without fully
	 * ordered fetching RMWs on arena memory must use the CAS fallback.
	 *
	 * With the ordering, between the clear and the second check, a
	 * segment that just gained an idle CID looks empty to the
	 * summary-driven scans and to scx_cid_idle_empty(). That window is a
	 * few instructions long and a missed candidate only costs a less
	 * ideal placement, so it is not closed.
	 */
	if (cmask_empty(&seg->idle)) {
		cmask_clear(seg->idle.base, &seg->summary->idle);
		if (!cmask_empty(&seg->idle))
			cmask_set(seg->idle.base, &seg->summary->idle);
	}
	return true;
}

/* Mirror an idle exit without using the claim result. */
static __always_inline void
scx_cid_idle_clear(struct scx_cid_idle_state *state, s32 cid)
{
	(void)scx_cid_idle_claim(state, cid);
}

static __always_inline bool
scx_cid_idle_has_core(const struct scx_cid_idle_state *state, u32 llc_base,
		      u32 node_base)
{
	return llc_base < state->nr_cids &&
	       node_base < state->nr_cids &&
	       __cmask_test(llc_base, state->node_core_llcs[node_base]);
}

static __always_inline void
scx_cid_idle_set_core_hint(struct scx_cid_idle_state *state,
			   u32 llc_base, u32 node_base, bool has_idle_core)
{
	if (llc_base >= state->nr_cids || node_base >= state->nr_cids)
		return;
	if (has_idle_core)
		cmask_set(llc_base, state->node_core_llcs[node_base]);
	else
		cmask_clear(llc_base, state->node_core_llcs[node_base]);
}

/* Test whether every CID in a core is set in an idle cmask. */
static __always_inline bool
scx_cid_core_idle(const struct scx_cid_ranges __arena *ranges,
		  const struct scx_cmask __arena *idle)
{
	u32 base = ranges->core_base;
	u32 nr = ranges->core_nr;
	u32 shift = base & 63;
	u64 mask;

	/* cmask_full_range() clamps its input; a partial core is not idle. */
	if (!nr || base < idle->base ||
	    (u64)base + nr > (u64)idle->base + idle->nr_cids)
		return false;

	/* A core contained in one word, as every SMT core is, takes one load. */
	if (nr < 64 && shift + nr <= 64) {
		mask = ((1ULL << nr) - 1) << shift;
		return (*__cmask_word(base, idle) & mask) == mask;
	}

	return cmask_full_range(idle, base, nr);
}

static __always_inline bool
scx_cid_idle_core_idle(const struct scx_cid_idle_state *state,
		       const struct scx_cid_ranges __arena *ranges)
{
	return scx_cid_core_idle(ranges,
			      scx_cid_idle_mask(state, ranges->core_base));
}

/* Mirror an idle transition or seed the initial idle state. */
static __always_inline void
scx_cid_idle_set(struct scx_cid_idle_state *state, s32 cid)
{
	const struct scx_cid_ranges __arena *ranges;
	struct scx_cid_idle_segment __arena *seg;

	if (cid < 0 || (u32)cid >= state->nr_cids)
		return;
	ranges = scx_cid_idle_ranges(state, cid);
	seg = state->segments[cid];
	/*
	 * Set the CID before testing the summary; see scx_cid_idle_claim()
	 * for the other half. Testing first keeps CPUs going idle from
	 * writing the node's shared summary line when the bit is already set.
	 */
	cmask_set(cid, &seg->idle);
	if (!__cmask_test(seg->idle.base, &seg->summary->idle))
		cmask_set(seg->idle.base, &seg->summary->idle);
	if (state->smt_enabled &&
	    !scx_cid_idle_has_core(state, ranges->llc_base,
				   ranges->node_base) &&
	    scx_cid_idle_core_idle(state, ranges))
		scx_cid_idle_set_core_hint(state, ranges->llc_base,
					    ranges->node_base, true);
}

/* A dispatch from the idle task may lack an ops.update_idle() transition. */
static __always_inline void
scx_cid_idle_rearm(struct scx_cid_idle_state *state, s32 cid)
{
	struct task_struct *task;

	task = scx_bpf_cid_curr(cid);
	if (task && (task->flags & PF_IDLE))
		scx_cid_idle_set(state, cid);
}

/* Build ranges and seed idle state after allocating storage, in ops.init(). */
static __always_inline int
scx_cid_idle_init(struct scx_cid_idle_state *state, bool smt_enabled,
			  enum scx_cid_idle_split split,
			  struct scx_cid_ranges __arena *ranges, u32 stride)
{
	struct scx_cid_range_builder builder = SCX_CID_RANGE_BUILDER_INIT;
	struct scx_cid_idle_build build = {};
	u32 nr_cids = scx_bpf_nr_online_cids();
	u32 range_pages;
	u32 i;
	int ret;

	ret = scx_cid_idle_init_state(state, nr_cids, smt_enabled);
	if (ret) {
		scx_bpf_error("cid_idle: %u online cids, sized for %u (%d)",
			      nr_cids, state->nr_cids_max, ret);
		return ret;
	}
	if (ranges) {
		if (stride < sizeof(*ranges)) {
			scx_bpf_error("cid_idle: range stride %u too small",
				      stride);
			return -EINVAL;
		}
		state->ranges = ranges;
		state->range_stride = stride;
	} else {
		range_pages = ((u64)state->nr_cids_max * sizeof(*state->ranges) +
			       PAGE_SIZE - 1) / PAGE_SIZE;
		state->ranges = bpf_arena_alloc_pages(&arena, NULL, range_pages,
						      NUMA_NO_NODE, 0);
		if (!state->ranges) {
			scx_bpf_error("cid_idle: failed to allocate ranges");
			return -ENOMEM;
		}
		state->range_stride = sizeof(*state->ranges);

		/* The highest CID reveals each contiguous domain's length. */
		bpf_arena_for(i, 0, nr_cids) {
			u32 cid = nr_cids - 1 - i;

			scx_bpf_cid_topo(cid, &state->topo_buf);
			scx_cid_ranges_build(scx_cid_idle_ranges(state, cid),
					     &builder, &state->topo_buf, cid);
		}
	}
	bpf_arena_for(i, 0, nr_cids) {
		const struct scx_cid_ranges __arena *ranges =
			scx_cid_idle_ranges(state, i);
		u32 base, nr;

		ret = scx_cid_idle_split_range(ranges, split, &base, &nr);
		if (ret || base != i || !nr || ranges->core_base != i) {
			scx_bpf_error("cid_idle: cid %u: bad split %d segment %u+%u (core %u)",
				      i, split, base, nr, ranges->core_base);
			return -EINVAL;
		}
		if (i == ranges->node_base) {
			ret = scx_cid_idle_init_node(state, &build, i, split);
			if (ret) {
				scx_bpf_error("cid_idle: cid %u: node %u+%u pool failed (%d)",
					      i, ranges->node_base,
					      ranges->node_nr, ret);
				return ret;
			}
		}

		ret = scx_cid_idle_add_segment(state, &build, i, nr,
					       ranges->node_base, ranges->node_nr);
		if (ret) {
			scx_bpf_error("cid_idle: cid %u: segment %u+%u in node %u+%u failed (%d)",
				      i, base, nr, ranges->node_base,
				      ranges->node_nr, ret);
			return ret;
		}
		i += nr - 1;
	}
	bpf_arena_for(i, 0, nr_cids)
		scx_cid_idle_set(state, i);
	return 0;
}

/*
 * Pop one candidate from @bits, rechecking the idle bit after the scan.
 * Another wakeup can claim it between the word read and this test; return
 * -EAGAIN in that case so the caller can try the next bit.
 */
static __always_inline s32
scx_cid_idle_next(const struct scx_cid_idle_state *state, u64 *bits, u32 word)
{
	s32 cid;

	if (!*bits)
		return -EBUSY;
	cid = word * 64 + __builtin_ctzll(*bits);
	*bits &= *bits - 1;
	return scx_cid_idle_test(state, cid) ? cid : -EAGAIN;
}

/* The idle bit was checked by the caller; apply placement and claim it. */
static __always_inline bool
scx_cid_idle_claim_allowed(struct scx_cid_idle_state *state,
			   const struct task_struct *p, s32 cid,
			   enum scx_cid_idle_kind kind)
{
	s32 cpu;

	if (kind == SCX_CID_IDLE_FULL_CORE &&
	    !scx_cid_idle_core_idle(state, scx_cid_idle_ranges(state, cid)))
		return false;
	if (kind != SCX_CID_IDLE_FULL_CORE && kind != SCX_CID_IDLE_ANY_CPU)
		return false;
	cpu = scx_bpf_cid_to_cpu(cid);
	return cpu >= 0 && bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
	       scx_cid_idle_claim(state, cid);
}

/* Scan one contiguous CID range, checking affinity before claiming. */
static __always_inline s32
scx_cid_idle_pick_range(struct scx_cid_idle_state *state,
				const struct task_struct *p, u32 base, u32 nr,
				enum scx_cid_idle_kind kind)
{
	u32 cursor = base, word;
	u64 bits;

	if (!nr)
		return -EBUSY;
	while (cursor < base + nr && can_loop) {
		bits = scx_cid_idle_scan_word(state, NULL, base, nr,
					       &cursor, &word);
		while (bits && can_loop) {
			s32 found = scx_cid_idle_next(state, &bits, word);

			if (found >= 0 &&
			    scx_cid_idle_claim_allowed(state, p, found, kind))
				return found;
		}
	}
	return -EBUSY;
}

/* Pick and claim an idle CID in the requested topology scope. */
static __always_inline s32
scx_cid_idle_pick(struct scx_cid_idle_state *state,
		  const struct task_struct *p, s32 anchor,
		  enum scx_cid_idle_scope scope, enum scx_cid_idle_kind kind)
{
	const struct scx_cid_ranges __arena *ranges;
	u32 base, nr, start;
	s32 cid;

	if (!state->ranges || !state->nr_cids)
		return -EBUSY;
	if (kind != SCX_CID_IDLE_ANY_CPU &&
	    kind != SCX_CID_IDLE_FULL_CORE)
		return -EINVAL;
	if (scope == SCX_CID_IDLE_ANYWHERE) {
		base = 0;
		nr = state->nr_cids;
	} else {
		if (anchor < 0 || (u32)anchor >= state->nr_cids)
			return -EINVAL;
		ranges = scx_cid_idle_ranges(state, anchor);
		if (scope == SCX_CID_IDLE_SAME_CORE) {
			base = ranges->core_base;
			nr = ranges->core_nr;
		} else if (scope == SCX_CID_IDLE_SAME_LLC) {
			base = ranges->llc_base;
			nr = ranges->llc_nr;
		} else if (scope == SCX_CID_IDLE_SAME_NODE) {
			base = ranges->node_base;
			nr = ranges->node_nr;
		} else {
			return -EINVAL;
		}
	}
	if (!nr || base >= state->nr_cids ||
	    nr > state->nr_cids - base)
		return -EINVAL;

	/* Try @anchor first in its core; wider scopes start after it. */
	if (anchor >= 0 && (u32)anchor >= base &&
	    (u32)anchor < base + nr)
		start = (u32)anchor + (scope != SCX_CID_IDLE_SAME_CORE);
	else
		start = base;
	if (start == base + nr)
		start = base;
	cid = scx_cid_idle_pick_range(state, p, start,
				      base + nr - start, kind);
	if (cid >= 0 || start == base)
		return cid;
	return scx_cid_idle_pick_range(state, p, base, start - base, kind);
}
