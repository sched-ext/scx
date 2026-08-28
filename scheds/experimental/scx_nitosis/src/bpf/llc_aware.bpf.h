/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header assists adding LLC cache awareness to scx_nitosis. LLC domains
 * come from the cid topology snapshot and per-task placement works on windowed
 * cmask scans of the task's effective mask.
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

typedef u32 llc_id_t;
#define LLC_INVALID ((llc_id_t)~0u)

/* struct cell LLC bitmaps use u64. */
_Static_assert(MAX_LLCS <= 64, "MAX_LLCS too high");

/* the LLC of @cid, LLC_INVALID for no-topo tail cids which belong to none */
static inline s32 llc_of_cid(s32 cid)
{
	return topo->cid[cid].llc_idx;
}

/*
 * Test whether @m has any cid set within @llc's contiguous cid range. LLC
 * ranges come from the topology snapshot, so the old per-LLC cpumasks and the
 * cached task-and-LLC intersection are both just windowed scans now.
 */
static inline bool cmask_intersects_llc(struct scx_cmask __arena *m, u32 llc)
{
	struct mitosis_topo __arena *t = topo;
	s32 base, end, cid;

	base = t->llc_cids[llc].base;
	end = base + t->llc_cids[llc].nr;
	if (t->llc_cids[llc].nr <= 0)
		return false;

	cid = cmask_next_set(m, base);
	return cid >= base && cid < end;
}

static inline s32 choose_task_llc(struct task_ctx __arena *tctx, s32 preferred_cid)
{
	struct scx_cmask __arena *effective = &tctx->effective;
	u32 pick;

	if (cmask_empty(effective))
		return LLC_INVALID;

	if (cmask_test(preferred_cid, effective))
		return llc_of_cid(preferred_cid);

	/* spread the fallback picks so retag bursts don't herd into one LLC */
	pick = cmask_any_distribute(effective);
	if (pick >= cmask_end(effective))
		return LLC_INVALID;
	return llc_of_cid(pick);
}

/*
 * The JIT rejects or/and atomics on arena memory (clang emits the fetching
 * forms which bpf_jit_supports_insn() disallows), so set and clear the drain
 * bits with cmpxchg loops instead. DRAIN_CAS_TRIES is sized so exhausting it
 * means seconds of real spinning on one word, past any plausible contention.
 */
#define DRAIN_CAS_TRIES		(1U << 23)

static inline void cell_llc_drain_enable(struct cell __arena *cell, u32 llc)
{
	u64 bit, old, new;
	u32 i;

	bit = 1LLU << llc;
	bpf_for(i, 0, DRAIN_CAS_TRIES) {
		old = cell->llcs_to_drain;
		if (old & bit)
			return;
		new = old | bit;
		if (__sync_val_compare_and_swap(&cell->llcs_to_drain, old, new) == old)
			return;
	}
	scx_bpf_error("drain_enable CAS exhausted at llc %u", llc);
}

static inline void cell_llc_drain_disable(struct cell __arena *cell, u32 llc)
{
	u64 bit, old, new;
	u32 i;

	bit = 1LLU << llc;
	bpf_for(i, 0, DRAIN_CAS_TRIES) {
		old = cell->llcs_to_drain;
		if (!(old & bit))
			return;
		new = old & ~bit;
		if (__sync_val_compare_and_swap(&cell->llcs_to_drain, old, new) == old)
			return;
	}
	scx_bpf_error("drain_disable CAS exhausted at llc %u", llc);
}

/*
 * Work around the kernel DSQ nr visibility bug: direct
 * scx_bpf_dsq_insert_vtime() from enqueue can leave a task invisible to
 * scx_bpf_dsq_nr_queued() until the enqueue callback finishes. Drain
 * interlocking needs the queue depth visible before enabling llcs_to_drain.
 */
static inline void cell_llc_nr_queued_inc(struct cell __arena *cell, u32 llc)
{
	__sync_fetch_and_add(&cell->llcs[llc].nr_queued, 1);
}

static inline u32 cell_llc_nr_queued_dec(struct cell __arena *cell, u32 llc)
{
	return __sync_sub_and_fetch(&cell->llcs[llc].nr_queued, 1);
}

static inline bool cell_llc_has_cpus(struct cell __arena *cell, u32 llc)
{
	return READ_ONCE(cell->llcs_with_cpus) & (1LLU << llc);
}

/*
 * Claim an idle cid in the cell and kick it. The claim keeps a racing picker
 * from selecting the same cid. SCX_KICK_IDLE makes the kick a no-op if the cid
 * ran something in the meantime.
 */
static inline void kick_cell_idle_cpu(u32 cell_id)
{
	struct mitosis_topo __arena *t = topo;
	struct scx_cmask __arena *cell_mask = &READ_ONCE(cell_masks)->mask[cell_id].cmask;
	s32 cid;

	cid = pick_idle_cid_shards(cell_mask, 0, t->nr_shards, -1);
	if (cid >= 0)
		scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
}

static inline int refresh_cell_llc_draining(u32 cell_id)
{
	struct cell __arena *cell;
	u64 llcs_with_cpus = 0;
	u32 nr_llcs = topo->nr_llcs;
	u32 llc;

	if (!enable_llc_awareness)
		return 0;

	cell = &cells[cell_id];

	struct scx_cmask __arena *cell_mask = &READ_ONCE(cell_masks)->mask[cell_id].cmask;

	bpf_for(llc, 0, nr_llcs) {
		if (cmask_intersects_llc(cell_mask, llc))
			llcs_with_cpus |= 1LLU << llc;
	}
	WRITE_ONCE(cell->llcs_with_cpus, llcs_with_cpus);

	/*
	 * Pair the post-publication queue count check with enqueue's
	 * post-increment cached no-CPU check. Either this path sees already
	 * queued work, or a racing enqueue sees the CPU-less LLC and enables
	 * draining itself. BPF has no standalone full-barrier instruction, so
	 * use an atomic op on a stack slot to avoid bouncing a shared cacheline.
	 */
	volatile unsigned long mb = 0;
	__sync_fetch_and_add(&mb, 0);

	bpf_for(llc, 0, nr_llcs) {
		if (llcs_with_cpus & (1LLU << llc)) {
			cell_llc_drain_disable(cell, llc);
			continue;
		}

		if (READ_ONCE(cell->llcs[llc].nr_queued) > 0) {
			cell_llc_drain_enable(cell, llc);
			kick_cell_idle_cpu(cell_id);
		}
	}

	return 0;
}

static inline int account_cell_llc_enqueue(u32 cell_id, u32 llc)
{
	struct cell __arena *cell;

	if (!enable_llc_awareness)
		return 0;

	if (llc >= topo->nr_llcs) {
		scx_bpf_error("account_cell_llc_enqueue: invalid LLC %u", llc);
		return -EINVAL;
	}

	cell = &cells[cell_id];

	/*
	 * Account the logical LLC DSQ insertion before checking llcs_with_cpus.
	 * This atomic op is the interlock with refresh_cell_llc_draining():
	 * either refresh observes the tracked queued work after publishing
	 * llcs_with_cpus, or this enqueue observes the CPU-less LLC below and
	 * enables draining.
	 */
	cell_llc_nr_queued_inc(cell, llc);

	if (cell_llc_has_cpus(cell, llc))
		return 0;

	cell_llc_drain_enable(cell, llc);
	kick_cell_idle_cpu(cell_id);
	return 0;
}

enum {
	CONTINUE_DISPATCH = 1,
};

/*
 * Returns 0 when work was dispatched to the local DSQ,
 * CONTINUE_DISPATCH when work was moved to a remote CPU DSQ, and a negative
 * error when no work was dispatched.
 */
static inline s32 try_draining_work(u32 cell_id, s32 local_llc, struct cpu_ctx *local_cctx)
{
	struct cell __arena *cell = &cells[cell_id];

	u64 drain_mask = READ_ONCE(cell->llcs_to_drain);
	if (!drain_mask)
		return -ENOENT;

	u32 nr_llcs = topo->nr_llcs;
	u32 i;

	bpf_for(i, 0, nr_llcs) {
		u32 candidate_llc = (local_llc + i) % nr_llcs;
		u64 bit;
		bool disabled = false;
		bool consumed;
		bool continue_dispatch = false;
		u32 pending;

		if (candidate_llc == local_llc)
			continue;

		bit = 1LLU << candidate_llc;
		if (!(drain_mask & bit))
			continue;

		dsq_id_t candidate_dsq = get_cell_llc_dsq_id(cell_id, candidate_llc);

		if (cell_llc_has_cpus(cell, candidate_llc)) {
			/*
			 * Normal dispatch can consume this DSQ now that the LLC
			 * has CPUs again. Don't clear the drain bit here:
			 * refresh/enqueue may be racing to mark it orphaned
			 * again, and disabling must be paired with checking
			 * whether queued work remains.
			 */
			continue;
		}

		pending = READ_ONCE(cell->llcs[candidate_llc].nr_queued);
		if (!pending) {
			cell_llc_drain_disable(cell, candidate_llc);
			/*
			 * Either a racing enqueue's drain enable lands after
			 * the disable above and draining stays enabled, or this
			 * recheck sees the work queued before the enable. The
			 * racing kick can be consumed while draining was
			 * disabled, so kick again.
			 */
			if (READ_ONCE(cell->llcs[candidate_llc].nr_queued)) {
				cell_llc_drain_enable(cell, candidate_llc);
				kick_cell_idle_cpu(cell_id);
			}
			continue;
		}

		/*
		 * Turn off draining before consuming if this consume is likely
		 * to drain the last known pending task. If a racing enqueue adds
		 * more work, either it observes the disabled bit and re-enables
		 * draining, or the pending count below remains non-zero and this
		 * path re-enables it.
		 */
		if (pending <= 1) {
			cell_llc_drain_disable(cell, candidate_llc);
			disabled = true;
		}

		consumed = scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0);

		/*
		 * The new cell cpumask is published before applied_configuration_seq
		 * is bumped at the end of apply_cell_config(). A task left in, or
		 * racing into, an LLC DSQ that became drain-only therefore still has
		 * a configuration sequence predating the published configuration.
		 * A task refreshed against the new sequence cannot select an LLC that
		 * no longer intersects the cell, so a rescued task will refresh its
		 * placement on its next select_cpu() or enqueue(). While stale, the
		 * head task may be affinity-ineligible for this CPU.
		 *
		 * The failed local move and the iterator remain racy: another CPU can
		 * consume the head task between them. Do not update task scheduling
		 * state until the remote move succeeds.
		 */
		if (unlikely(!consumed && READ_ONCE(cell->llcs[candidate_llc].nr_queued))) {
			struct task_struct *p;

			bpf_for_each(scx_dsq, p, candidate_dsq.raw, 0) {
				struct task_ctx __arena *tctx;
				struct cpu_ctx *target_cctx;
				dsq_id_t target_dsq;
				u64 basis_vtime;
				s32 cid;

				/*
				 * task_ctx is RCU protected and @p can exit and
				 * unlink it at any point.
				 */
				tctx = __scx_task_data(p);
				if (!tctx)
					break;

				cid = cmask_any_distribute(&tctx->allowed);
				if (cid >= cmask_end(&tctx->allowed))
					break;

				target_cctx = lookup_cid_ctx(cid);
				if (!target_cctx)
					break;

				target_dsq = get_cid_dsq_id(cid);
				if (dsq_is_invalid(target_dsq))
					break;

				basis_vtime = READ_ONCE(target_cctx->vtime_now);
				scx_bpf_dsq_move_set_vtime(BPF_FOR_EACH_ITER, basis_vtime);
				consumed = scx_bpf_dsq_move_vtime(BPF_FOR_EACH_ITER, p,
								  target_dsq.raw, 0);
				if (consumed) {
					tctx->basis_vtime = basis_vtime;
					tctx->dsq = target_dsq;
					/*
					 * Obviate any LLC updates during running(),
					 * next cell refresh on enqueue() will recompute
					 * these based on the current cell state.
					 */
					tctx->all_cell_cpus_allowed = false;
					tctx->llc = LLC_INVALID;

					continue_dispatch = true;
					/*
					 * cstats are per-cid and non-atomic.
					 * Account on the dispatching cid rather
					 * than the remote target.
					 */
					cstat_inc(CSTAT_DRAIN_AFFN_CNT, cell_id, local_cctx);
					scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
				}
				break;
			}
		}

		if (consumed) {
			pending = cell_llc_nr_queued_dec(cell, candidate_llc);
		} else {
			pending = READ_ONCE(cell->llcs[candidate_llc].nr_queued);
		}

		if (disabled && pending > 0) {
			cell_llc_drain_enable(cell, candidate_llc);
			/* Same consumed-kick window as the recheck above. */
			kick_cell_idle_cpu(cell_id);
		}

		if (consumed)
			return continue_dispatch ? CONTINUE_DISPATCH : 0;
	}
	return -ENOENT;
}

static inline s32 try_stealing_work(u32 cell_id, s32 local_llc)
{
	struct cell __arena *cell = &cells[cell_id];

	u32 nr_llcs = topo->nr_llcs;
	u32 i;

	bpf_for(i, 0, nr_llcs) {
		u32 candidate_llc = (local_llc + i) % nr_llcs;

		if (candidate_llc == local_llc)
			continue;

		if (!cell_llc_has_cpus(cell, candidate_llc))
			continue;

		dsq_id_t candidate_dsq = get_cell_llc_dsq_id(cell_id, candidate_llc);

		// Optimization: skip if faster than constructing an iterator
		// Not redundant with later checking if task found (race)

		/*
		 * We don't use tracked nr_queued here because we won't be able
		 * to consume until the actual racy dispatch got comitted.
		 */
		if (scx_bpf_dsq_nr_queued(candidate_dsq.raw) <= 0)
			continue;

		/*
		 * Attempt the steal - can fail because it's a race. The task's
		 * LLC is updated from the CPU it actually runs on in running().
		 */
		if (!scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0))
			continue;

		cell_llc_nr_queued_dec(cell, candidate_llc);
		return 0;
	}
	return -ENOENT;
}

static inline int set_task_llc(struct task_struct *p, struct task_ctx __arena *tctx,
			       u32 new_llc, bool reset_vtime)
{
	if (!tctx) {
		scx_bpf_error("Invalid task context");
		return -ENOENT;
	}

	u32 nr_llcs = topo->nr_llcs;

	if (new_llc >= nr_llcs) {
		scx_bpf_error("invalid LLC assignment: %u", new_llc);
		return -EINVAL;
	}

	struct cell __arena *cell = &cells[tctx->cell];

	u32 old_llc = tctx->llc;
	if (!cmask_intersects_llc(&tctx->effective, new_llc)) {
		scx_bpf_error("task can't run in cell %u LLC %u", tctx->cell, new_llc);
		return -EINVAL;
	}

	/*
	 * This writes a cell/LLC DSQ. Pinned tasks keep CPU DSQs.
	 */
	tctx->dsq = get_cell_llc_dsq_id(tctx->cell, new_llc);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	if (reset_vtime || old_llc >= nr_llcs) {
		scx_bpf_task_set_dsq_vtime(p, cell_llc_vtime_read(cell, new_llc));
	} else if (old_llc != new_llc) {
		s64 vtime_delta = p->scx.dsq_vtime - cell_llc_vtime_read(cell, old_llc);
		scx_bpf_task_set_dsq_vtime(p,
					   cell_llc_vtime_read(cell, new_llc) + vtime_delta);
	}

	tctx->llc = new_llc;
	return 0;
}

static inline int update_task_llc_assignment(struct task_struct *p,
					     struct task_ctx __arena *tctx,
					     s32 preferred_cid)
{
	s32 new_llc;

	new_llc = choose_task_llc(tctx, preferred_cid);
	if (new_llc >= topo->nr_llcs)
		return -EINVAL;

	return set_task_llc(p, tctx, new_llc, true);
}

static inline int maybe_update_task_llc(struct task_struct *p, struct task_ctx __arena *tctx,
					s32 preferred_cid)
{
	int ret;
	s32 new_llc;

	if (!tctx->all_cell_cpus_allowed)
		return 0;

	/* Retag only all-cell tasks; pinned tasks keep cid DSQs. */
	new_llc = choose_task_llc(tctx, preferred_cid);
	if (new_llc >= topo->nr_llcs)
		return 0;

	if (tctx->llc == new_llc)
		return 0;

	ret = set_task_llc(p, tctx, new_llc, false);
	if (ret && tctx->llc < topo->nr_llcs)
		return 0;
	return ret;
}
