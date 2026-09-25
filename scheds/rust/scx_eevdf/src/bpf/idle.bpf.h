/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Which cids are idle, and the word-at-a-time scans of that bitmap the
 * wakeup path walks. The policy built on the scans, from wake_affine() to
 * the fork descent, is in idle.bpf.c.
 */
#pragma once

#include "eevdf.bpf.h"
#include "queue.bpf.h"
#include "load.bpf.h"

/*
 * Idle cid tracking.
 *
 * The idle state of every cid is kept here rather than in the kernel's
 * idle masks. Implementing ops.update_idle() turns the built-in tracking
 * off, and with it the kernel's own idle CPU selection, whose walk of the
 * topology masks was the single most expensive step of a wakeup and knew
 * nothing of the capacity ordering anyway.
 *
 * The state is a flag word per cid, the truth of that cid, and a bitmap
 * that follows the flags and that the scans read a word at a time, see
 * the note above the bitmap helpers for why the two are separate.
 * Whether a whole core is idle is read from the flags of its siblings,
 * contiguous in cid space, so there is no core bitmap or count to keep
 * in step: a count kept next to the bits is two operations, and between
 * the two another CPU reads a count that is off by one.
 *
 * ops.update_idle() only fires on real idle transitions. A cid that was
 * claimed for a task and kicked, and then found nothing to run, goes back
 * to idle without a transition and would keep its bit cleared for good:
 * ops.dispatch() re-arms the bit whenever a cid is about to idle. The
 * re-arm can be wrong the other way when a task lands on the cid before
 * it idles. The next idle claim or ops.update_idle(cid, false) clears
 * that stale hint; a claim of a busy cid is bounced back to ops.enqueue().
 */
static bool cid_idle_test(s32 cid)
{
	return scx_cid_idle_test(&eevdf_idle, cid);
}

/*
 * Return true if the whole core of @cid is idle, i.e. @cid is idle and so
 * are its SMT siblings, if any.
 */
static bool core_is_idle(s32 cid)
{
	if (!cid_valid(cid))
		return false;
	return scx_cid_idle_core_idle(&eevdf_idle, &cid_topo(cid)->ranges);
}

/*
 * Return true when every SMT sibling of @cid is idle. This is fair.c's
 * is_core_idle() test as sched_use_asym_prio() applies it to a running
 * source CPU: @cid itself is deliberately excluded.
 */
static bool siblings_idle(s32 cid)
{
	struct cid_topo __arena *topo;
	u32 sibling;

	if (!cid_valid(cid))
		return false;
	topo = cid_topo(cid);
	bpf_arena_for(sibling, topo->ranges.core_base, topo->ranges.core_base + topo->ranges.core_nr) {
		if (sibling != (u32)cid && !cid_idle_test(sibling))
			return false;
	}

	return true;
}

static bool smt_asym_active(s32 cid)
{
	return smt_enabled && cid_valid(cid) &&
	       (force_smt_asym_packing || cid_topo(cid)->smt_asym_packing);
}

static bool smt_prefer(s32 a, s32 b)
{
	if (!cid_valid(a) || !cid_valid(b))
		return false;
	if (force_smt_asym_packing)
		return cid_topo(a)->cpu < cid_topo(b)->cpu;
	return cid_topo(a)->place_tier < cid_topo(b)->place_tier;
}

/* fair.c's sd_balance_shared::has_idle_cores hint, keyed by LLC base cid. */
static bool test_idle_cores(s32 cid)
{
	struct cid_topo __arena *topo;

	if (!cid_valid(cid))
		return false;
	topo = cid_topo(cid);

	return scx_cid_idle_has_core(&eevdf_idle, topo->ranges.llc_base);
}

static void set_idle_cores(s32 cid, bool has_idle_core)
{
	struct cid_topo __arena *topo;

	if (!cid_valid(cid))
		return;
	topo = cid_topo(cid);
	scx_cid_idle_set_core_hint(&eevdf_idle, topo->ranges.llc_base,
				    has_idle_core);
}

/*
 * Claim the idle state of @cid, returning true if this caller is the one
 * that took it out of the idle state. Claiming keeps concurrent wakeups
 * from aiming at the same cid.
 */
static bool cid_idle_claim(s32 cid)
{
	return scx_cid_idle_claim(&eevdf_idle, cid);
}

/*
 * Mark @cid idle, unless it already is.
 */
static void cid_idle_set(s32 cid)
{
	if (!cid_valid(cid))
		return;

	scx_cid_idle_set_ranges(&eevdf_idle, cid, &cid_topo(cid)->ranges);
}

/*
 * fair.c's choose_sched_idle_rq(): a normal task may share a CPU whose
 * runqueue contains only SCHED_IDLE work instead of waiting on a normal
 * task elsewhere. scx_eevdf does not count policy classes in a remote EDQ, so
 * recognize the exact cheap case: a SCHED_IDLE current with no waiter.
 *
 * Work in an idle cgroup counts as SCHED_IDLE work here, the way a task
 * under a cfs_rq_is_idle() group counts in rq->cfs.h_nr_idle, see
 * eevdf_cpuctl_set_idle(). What @p itself is follows its policy alone, as
 * in choose_sched_idle_rq().
 */
static bool cid_sched_idle_target(const struct task_struct *p, s32 cid)
{
	struct cid_ctx __arena *cctx;

	if (!READ_ONCE(nr_sched_idle_curr) || p->policy == SCHED_IDLE ||
	    !cid_valid(cid) || cid_idle_test(cid) || cid_queued_test(cid))
		return false;
	cctx = cid_ctx(cid);

	return cctx->pack.curr_w && cctx->curr_sched_idle;
}

/*
 * Rotate @w right by @s bits, so that the bits from @s on come first.
 */
static __always_inline u64 rotr64(u64 w, u32 s)
{
	s &= 63;
	return s ? (w >> s) | (w << (64 - s)) : w;
}

/*
 * Return word @k of the cids in placement tier @t.
 */
static __always_inline u64 place_tier_word(u32 t, u32 k)
{
	return cmask_word(place_tier_mask(t), k);
}

/*
 * Return the first idle cid of word @k of @w that @p can run on and, if
 * @whole_core is set, whose whole core is idle, or -EBUSY.
 */
static __always_inline s32 first_idle_cid(const struct task_struct *p, u64 w,
					  u32 k, bool restricted, bool whole_core)
{
	while (w && can_loop) {
		s32 cid = scx_cid_idle_next(&eevdf_idle, &w, k);

		if (cid >= 0 && (!whole_core || core_is_idle(cid)) &&
		    (!restricted || cid_allowed(p, cid)))
			return cid;
	}

	return -EBUSY;
}

/* Scan idle cids without an asymmetric-packing tier restriction. */
static __always_inline s32
scan_idle_unranked_range(const struct task_struct *p, u32 base, u32 nr,
			 bool restricted, bool whole_core)
{
	u32 k, last;

	if (!nr)
		return -EBUSY;
	last = (base + nr - 1) / 64;
	bpf_arena_for(k, base / 64, last + 1) {
		u64 w = scx_cid_idle_scan_word(&eevdf_idle, NULL, k, base, nr);
		s32 cid;

		if (!w)
			continue;
		cid = first_idle_cid(p, w, k, restricted, whole_core);
		if (cid >= 0)
			return cid;
	}

	return -EBUSY;
}

/* scan_idle_range() restricted by CPU capacity rather than packing priority. */
static __always_inline s32
scan_idle_capacity_range(const struct task_struct *p, u32 t, u32 base, u32 nr,
			 bool restricted, bool whole_core)
{
	u32 k, last;

	if (!nr)
		return -EBUSY;
	last = (base + nr - 1) / 64;
	bpf_arena_for(k, base / 64, last + 1) {
		u64 w = scx_cid_idle_scan_word(&eevdf_idle, capacity_tier_mask(t),
					    k, base, nr);
		s32 cid;

		if (!w)
			continue;
		cid = first_idle_cid(p, w, k, restricted, whole_core);
		if (cid >= 0)
			return cid;
	}

	return -EBUSY;
}

static __always_inline u32 sis_idle_scan_nr(s32 cid)
{
	struct cid_topo __arena *topo;

	if (!sis_util || !cid_valid(cid))
		return UINT_MAX;
	topo = cid_topo(cid);
	return READ_ONCE(cid_ctx(topo->ranges.llc_base)->sis_idle_scan);
}

/* Flags for pick_idle_cid_topology() */
enum pick_idle_flags {
	/* @prev_cid is in @p's allowed set and can be returned as is */
	PICK_IDLE_PREV_ALLOWED	= 1 << 0,

	/* Only consider cids whose whole core is idle */
	PICK_IDLE_WHOLE_CORE	= 1 << 1,

	/* Return the cid without claiming it, for a caller that only kicks */
	PICK_IDLE_NO_CLAIM	= 1 << 2,

	/* Restrict the scan to the LLC containing @prev_cid */
	PICK_IDLE_LLC_ONLY	= 1 << 3,
};

/*
 * Would @p fit on a cid of this capacity, or does it want more of a CPU
 * than that one is?
 *
 * select_idle_sibling() asks this before it settles for a CPU the task
 * has already run on, and takes the idle one only if the task fits it:
 *
 *	if (prev != target && cpus_share_cache(prev, target) &&
 *	    (!cpus_allowed || cpumask_test_cpu(prev, allowed)) &&
 *	    choose_idle_cpu(prev, p) &&
 *	    asym_fits_cpu(task_util, util_min, util_max, prev)) {
 *
 * Without the last test a task that once landed on a slow CPU and keeps
 * waking while that CPU happens to be idle is never offered a faster one
 * again: the cheapest answer is always the one it already has. A task
 * that only wants a fraction of a CPU is welcome to stay, which is what
 * makes the short circuit worth having; one that wants the whole of it
 * goes on to the tier walk.
 *
 * Only asymmetric machines ask at all, as asym_fits_cpu() does with
 * sched_asym_cpucap_active().
 */
static bool task_fits_cid(task_ctx_t *tctx, s32 cid, u64 now)
{
	if (!asym_capacity || !tctx)
		return true;

	return util_fits_cap(task_util(tctx, now), cid_topo(cid)->cap);
}

/* fair.c's asym_fits_cpu(): asymmetric SMT placement requires an idle core. */
static bool asym_fits_cid(task_ctx_t *tctx, s32 cid, u64 now)
{
	if (!sched_asym_capacity && !force_asym_capacity)
		return true;

	return task_fits_cid(tctx, cid, now) &&
	       (!smt_enabled || core_is_idle(cid));
}

static __always_inline bool cid_in_range(s32 cid, u32 base, u32 nr)
{
	return cid >= 0 && (u32)cid >= base && (u32)cid - base < nr;
}

/*
 * fair.c's select_idle_smt_cpu(): redirect an idle CPU to a more-preferred
 * available sibling when SD_ASYM_PACKING is active in its SMT domain.
 */
static s32 select_idle_smt_cpu(const struct task_struct *p, s32 cid)
{
	struct cid_topo __arena *topo;
	s32 best = cid;
	u32 sibling;

	if (!smt_asym_active(cid))
		return cid;
	topo = cid_topo(cid);

	bpf_arena_for(sibling, topo->ranges.core_base, topo->ranges.core_base + topo->ranges.core_nr) {
		if (sibling == (u32)best || !cid_idle_test(sibling) ||
		    !cid_allowed(p, sibling))
			continue;
		if (smt_prefer(sibling, best))
			best = sibling;
	}

	return best;
}

static s32 claim_idle_cid(const struct task_struct *p, s32 cid)
{
	cid = select_idle_smt_cpu(p, cid);

	return cid_idle_claim(cid) ? cid : -EAGAIN;
}
