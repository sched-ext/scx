/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. */
#pragma once

#include <lib/cid_topology.h>
#include <lib/arena_loop.h>

/*
 * CID idle tracking for sched_ext schedulers
 * ------------------------------------------
 *
 * This header owns the idle and idle-core-hint cmasks and provides the
 * operations needed to scan and claim idle CIDs. The scheduler decides which
 * candidate fits a task. It must use a CID space framed as [0, nr_cids), with a
 * scx_cid_ranges entry for each CID whose core and LLC ranges are in that
 * space. See cid_topology.h for the range builder.
 *
 * Setup before scheduling callbacks can select a CID:
 *
 *   1. Before attach, call scx_cid_idle_alloc() with an arena map. It sizes and
 *      allocates the masks and CID ranges for all possible CIDs.
 *   2. In ops.init(), call scx_cid_idle_init() with the SMT enabled setting.
 *      This reads the online CID count, frames the masks, builds the CID
 *      ranges, and marks every CID idle so CPUs which start idle can be
 *      selected. The initial set is optimistic, a claim or ops.update_idle()
 *      clears a CID that is already busy.
 *
 * Schedulers with ranges embedded in another topology table can supply their
 * own storage and use scx_cid_idle_init_masks() and scx_cid_idle_set_ranges()
 * instead. Set nr_cids_max when supplying masks.
 *
 * Runtime lifecycle:
 *
 *   ops.update_idle(cid, true)  -> scx_cid_idle_set()
 *   ops.update_idle(cid, false) -> scx_cid_idle_claim()
 *   ops.dispatch() about to idle without a transition -> use set() again
 *
 * A claim clears the bit, so concurrent selectors cannot both take the same
 * CID. Initialize with smt_enabled=false when whole-core tracking is not
 * needed.
 *
 * NOTE: a CID rearmed by ops.dispatch() can become busy without an idle
 * transition. Its stale bit is cleared by the next claim; schedulers must
 * handle a claimed CPU that turns out to be busy.
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
 *   // Run this syscall program before attach to allocate idle storage.
 *   SEC("syscall") int alloc_idle(void *ctx)
 *   {
 *           return scx_cid_idle_alloc(&idle_state, &arena);
 *   }
 *
 *   // ops.init(): frame the masks, build ranges, and seed idle CIDs.
 *   s32 BPF_STRUCT_OPS_SLEEPABLE(example_init)
 *   {
 *           TOUCH_ARENA();
 *           return scx_cid_idle_init(&idle_state, smt_enabled);
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
 *                   scx_cid_idle_claim(&idle_state, cid);
 *   }
 *
 *   // Call from ops.dispatch() if the claimed CID has no work to run.
 *   static void rearm_empty_dispatch(s32 cid)
 *   {
 *           TOUCH_ARENA();
 *           scx_cid_idle_set(&idle_state, cid);
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
	struct scx_cmask __arena *idle;
	struct scx_cmask __arena *core_llcs;
	struct scx_cid_ranges __arena *ranges;
	u32 nr_cids_max;
	u32 nr_cids;
	bool smt_enabled;
	/* BSS scratch for scx_bpf_cid_topo(), used only in ops.init(). */
	struct scx_cid_topo topo_buf;
};

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

/* Allocate both masks and the CID ranges before ops.init() runs. */
static __always_inline int
scx_cid_idle_alloc(struct scx_cid_idle_state *state, void *arena_map)
{
	u32 nr_cids_max = scx_bpf_nr_cids();
	u64 mask_bytes, range_bytes;
	u32 mask_pages, range_pages;
	struct scx_cmask __arena *idle, *core_llcs;
	struct scx_cid_ranges __arena *ranges;

	if (!nr_cids_max)
		return -EINVAL;
	mask_bytes = sizeof(struct scx_cmask) +
		     (u64)CMASK_NR_WORDS(nr_cids_max) * sizeof(u64);
	range_bytes = (u64)nr_cids_max * sizeof(*ranges);
	mask_pages = (mask_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	range_pages = (range_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	idle = bpf_arena_alloc_pages(arena_map, NULL, mask_pages, NUMA_NO_NODE, 0);
	if (!idle)
		return -ENOMEM;
	core_llcs = bpf_arena_alloc_pages(arena_map, NULL, mask_pages,
					 NUMA_NO_NODE, 0);
	if (!core_llcs)
		goto free_idle;
	ranges = bpf_arena_alloc_pages(arena_map, NULL, range_pages,
				       NUMA_NO_NODE, 0);
	if (!ranges)
		goto free_core_llcs;

	state->idle = idle;
	state->core_llcs = core_llcs;
	state->ranges = ranges;
	state->nr_cids_max = nr_cids_max;
	state->nr_cids = 0;
	return 0;

free_core_llcs:
	bpf_arena_free_pages(arena_map, core_llcs, mask_pages);
free_idle:
	bpf_arena_free_pages(arena_map, idle, mask_pages);
	return -ENOMEM;
}

/* Frame caller-supplied masks when ranges live in another topology table. */
static __always_inline int
scx_cid_idle_init_masks(struct scx_cid_idle_state *state, u32 nr_cids,
			bool smt_enabled)
{
	if (!nr_cids || !state->idle || !state->core_llcs ||
	    (state->nr_cids_max && nr_cids > state->nr_cids_max))
		return -EINVAL;
	state->nr_cids = nr_cids;
	state->smt_enabled = smt_enabled;
	cmask_init(state->idle, 0, nr_cids);
	cmask_init(state->core_llcs, 0, nr_cids);
	return 0;
}

static __always_inline bool
scx_cid_idle_test(const struct scx_cid_idle_state *state, s32 cid)
{
	return cid >= 0 && (u32)cid < state->nr_cids &&
	       __cmask_test(cid, state->idle);
}

static __always_inline bool
scx_cid_idle_empty(const struct scx_cid_idle_state *state)
{
	return cmask_empty(state->idle);
}

static __always_inline bool
scx_cid_idle_any_core(const struct scx_cid_idle_state *state)
{
	return !cmask_empty(state->core_llcs);
}

static __always_inline u64
scx_cid_idle_word(const struct scx_cid_idle_state *state, u32 word)
{
	return cmask_word(state->idle, word);
}

static __always_inline u32
scx_cid_idle_nr_words(const struct scx_cid_idle_state *state)
{
	return cmask_nr_words(state->idle);
}

/* A successful claim prevents another concurrent wakeup from taking @cid. */
static __always_inline bool
scx_cid_idle_claim(struct scx_cid_idle_state *state, s32 cid)
{
	return cid >= 0 && (u32)cid < state->nr_cids &&
	       cmask_test_and_clear(cid, state->idle);
}

static __always_inline bool
scx_cid_idle_has_core(const struct scx_cid_idle_state *state, u32 llc_base)
{
	return llc_base < state->nr_cids &&
	       __cmask_test(llc_base, state->core_llcs);
}

static __always_inline void
scx_cid_idle_set_core_hint(struct scx_cid_idle_state *state,
			   u32 llc_base, bool has_idle_core)
{
	if (llc_base >= state->nr_cids)
		return;
	if (has_idle_core)
		cmask_set(llc_base, state->core_llcs);
	else
		cmask_clear(llc_base, state->core_llcs);
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
	return scx_cid_core_idle(ranges, state->idle);
}

/* Use caller-owned ranges when they are embedded in another topology table. */
static __always_inline void
scx_cid_idle_set_ranges(struct scx_cid_idle_state *state, s32 cid,
			const struct scx_cid_ranges __arena *ranges)
{
	if (cid < 0 || (u32)cid >= state->nr_cids)
		return;
	cmask_set(cid, state->idle);
	if (state->smt_enabled &&
	    !scx_cid_idle_has_core(state, ranges->llc_base) &&
	    scx_cid_core_idle(ranges, state->idle))
		scx_cid_idle_set_core_hint(state, ranges->llc_base, true);
}

/* Rearm a CID after an idle transition or an empty dispatch. */
static __always_inline void
scx_cid_idle_set(struct scx_cid_idle_state *state, s32 cid)
{
	if (cid < 0 || (u32)cid >= state->nr_cids)
		return;
	scx_cid_idle_set_ranges(state, cid, &state->ranges[cid]);
}

/* Build ranges and seed idle state after allocating storage, in ops.init(). */
static __always_inline int
scx_cid_idle_init(struct scx_cid_idle_state *state, bool smt_enabled)
{
	struct scx_cid_range_builder builder = SCX_CID_RANGE_BUILDER_INIT;
	u32 nr_cids = scx_bpf_nr_online_cids();
	u32 i;
	int ret;

	if (!state->ranges)
		return -EINVAL;
	ret = scx_cid_idle_init_masks(state, nr_cids, smt_enabled);
	if (ret)
		return ret;

	/* The highest CID in a contiguous domain reveals its full length. */
	bpf_arena_for(i, 0, nr_cids) {
		u32 cid = nr_cids - 1 - i;

		scx_bpf_cid_topo(cid, &state->topo_buf);
		scx_cid_ranges_build(&state->ranges[cid], &builder,
				     &state->topo_buf, cid);
	}
	bpf_arena_for(i, 0, nr_cids)
		scx_cid_idle_set(state, i);
	return 0;
}

/* Return the idle candidates of one word in [@base, @base + @nr). */
static __always_inline u64
scx_cid_idle_scan_word(const struct scx_cid_idle_state *state,
		       const struct scx_cmask __arena *tier, u32 word,
		       u32 base, u32 nr)
{
	u64 bits = cmask_word(state->idle, word) &
		   cmask_range_word(state->idle, word, base, nr);

	return tier ? bits & cmask_word(tier, word) : bits;
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
	    !scx_cid_idle_core_idle(state, &state->ranges[cid]))
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
	u32 word;

	if (!nr)
		return -EBUSY;
	bpf_arena_for(word, base / 64, (base + nr - 1) / 64 + 1) {
		u64 bits = scx_cid_idle_scan_word(state, NULL, word, base, nr);

		while (bits && can_loop) {
			s32 cid = scx_cid_idle_next(state, &bits, word);

			if (cid >= 0 &&
			    scx_cid_idle_claim_allowed(state, p, cid, kind))
				return cid;
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
		ranges = &state->ranges[anchor];
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
