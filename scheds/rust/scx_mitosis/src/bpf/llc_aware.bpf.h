/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header assists adding LLC cache awareness to scx_mitosis by defining
 * maps and fns for managing CPU-to-LLC domain mappings and maintaining
 * per-task LLC candidate masks derived from the task's base cpumask.
 */
#pragma once

#include "mitosis.bpf.h"
#include "intf.h"

typedef u32 llc_id_t;
#define LLC_INVALID ((llc_id_t)~0u)

/* struct subcell LLC bitmaps use u64. */
_Static_assert(MAX_LLCS <= 64, "MAX_LLCS too high");

/*
 * Global arrays for LLC topology, populated by userspace before load.
 * cpu_to_llc: Maps each CPU index to its LLC domain ID.
 * llc_to_cpus: Maps each LLC domain ID to a cpumask of CPUs in that domain.
 */
extern u32 cpu_to_llc[MAX_CPUS];
extern struct llc_cpumask llc_to_cpus[MAX_LLCS];

static inline bool llc_is_valid(u32 llc_id)
{
	if (llc_id == LLC_INVALID)
		return false;

	return llc_id < MAX_LLCS;
}

static inline void init_task_llc(struct task_ctx *tctx)
{
	tctx->llc = LLC_INVALID;
	tctx->llc_cpumask_id = LLC_INVALID;
}

static inline const struct cpumask *lookup_llc_cpumask(u32 llc)
{
	if (llc >= nr_llc || llc >= MAX_LLCS) {
		scx_bpf_error("llc index out of bounds: %d", llc);
		return NULL;
	}

	return (const struct cpumask *)&llc_to_cpus[llc];
}

static inline void invalidate_task_llc_cpumask(struct task_ctx *tctx)
{
	tctx->llc_cpumask_id = LLC_INVALID;
}

static inline void invalidate_task_llc(struct task_ctx *tctx)
{
	tctx->llc = LLC_INVALID;
	invalidate_task_llc_cpumask(tctx);
}

static inline s32 llc_from_cpu(s32 cpu)
{
	if (cpu < 0 || cpu >= nr_possible_cpus || cpu >= MAX_CPUS) {
		scx_bpf_error("cpu out of bounds for LLC lookup: %d", cpu);
		return LLC_INVALID;
	}

	u32 llc = cpu_to_llc[cpu];
	if (!llc_is_valid(llc) || llc >= nr_llc) {
		scx_bpf_error("cpu %d maps to invalid LLC %u", cpu, llc);
		return LLC_INVALID;
	}

	return (s32)llc;
}

static inline s32 choose_task_llc(struct task_ctx *tctx, s32 preferred_cpu)
{
	const struct cpumask *cpumask;
	s32 llc;

	cpumask = cast_mask(tctx->cpumask);
	if (!cpumask || bpf_cpumask_empty(cpumask))
		return LLC_INVALID;

	if (preferred_cpu >= 0 && preferred_cpu < nr_possible_cpus && preferred_cpu < MAX_CPUS &&
	    bpf_cpumask_test_cpu(preferred_cpu, cpumask)) {
		llc = llc_from_cpu(preferred_cpu);
		if (llc_is_valid(llc))
			return llc;
	}

	u32 cpu = bpf_cpumask_any_distribute(cpumask);
	return llc_from_cpu(cpu);
}

static inline int refresh_task_llc_cpumask(struct task_ctx *tctx, u32 llc)
{
	const struct cpumask *base_mask;
	const struct cpumask *cached_mask;
	const struct cpumask *llc_mask;
	struct bpf_cpumask *llc_cpumask;

	llc_cpumask = tctx->llc_cpumask;
	if (!llc_cpumask) {
		scx_bpf_error("tctx->llc_cpumask is NULL");
		return -EINVAL;
	}

	if (tctx->llc_cpumask_id == llc) {
		cached_mask = cast_mask(llc_cpumask);
		if (cached_mask && !bpf_cpumask_empty(cached_mask))
			return 0;
		tctx->llc_cpumask_id = LLC_INVALID;
	}

	base_mask = cast_mask(tctx->cpumask);
	if (!base_mask) {
		scx_bpf_error("tctx->cpumask is NULL");
		return -EINVAL;
	}

	llc_mask = lookup_llc_cpumask(llc);
	if (!llc_mask)
		return -ENOENT;

	bpf_cpumask_and(llc_cpumask, base_mask, llc_mask);
	if (bpf_cpumask_empty(cast_mask(llc_cpumask))) {
		tctx->llc_cpumask_id = LLC_INVALID;
		return -ENOENT;
	}

	tctx->llc_cpumask_id = llc;
	return 0;
}

static inline void subcell_llc_drain_enable(struct subcell *subcell, u32 llc)
{
	if (llc >= MAX_LLCS)
		return;

	__sync_or_and_fetch(&subcell->llcs_to_drain, 1LLU << llc);
}

static inline void subcell_llc_drain_disable(struct subcell *subcell, u32 llc)
{
	if (llc >= MAX_LLCS)
		return;

	__sync_and_and_fetch(&subcell->llcs_to_drain, ~(1LLU << llc));
}

/*
 * Work around the kernel DSQ nr visibility bug: direct
 * scx_bpf_dsq_insert_vtime() from enqueue can leave a task invisible to
 * scx_bpf_dsq_nr_queued() until the enqueue callback finishes. Drain
 * interlocking needs the queue depth visible before enabling llcs_to_drain.
 */
static inline void subcell_llc_nr_queued_inc(struct subcell *subcell, u32 llc)
{
	struct subcell_llc *subcell_llc = lookup_subcell_llc(subcell, llc);

	if (subcell_llc)
		__sync_fetch_and_add(&subcell_llc->nr_queued, 1);
}

static inline u32 subcell_llc_nr_queued_dec(struct subcell *subcell, u32 llc)
{
	struct subcell_llc *subcell_llc = lookup_subcell_llc(subcell, llc);

	if (!subcell_llc)
		return 0;

	return __sync_sub_and_fetch(&subcell_llc->nr_queued, 1);
}

static inline bool subcell_mask_intersects_llc(const struct cpumask *subcell_mask, u32 llc)
{
	const struct cpumask *llc_mask;

	if (!subcell_mask)
		return false;

	llc_mask = lookup_llc_cpumask(llc);
	if (!llc_mask)
		return false;

	return bpf_cpumask_intersects(subcell_mask, llc_mask);
}

static inline bool subcell_llc_has_cpus(struct subcell *subcell, u32 llc)
{
	return READ_ONCE(subcell->llcs_with_cpus) & (1LLU << llc);
}

/* Caller must hold RCU. */
static inline void kick_subcell_idle_cpu_locked(u32 cell_id, u32 subcell_id)
{
	s32 cpu = -1;
	const struct cpumask *subcell_mask = lookup_subcell_cpumask(cell_id, subcell_id);

	if (!subcell_mask)
		return;

	cpu = scx_bpf_pick_idle_cpu(subcell_mask, SCX_PICK_IDLE_CORE);
	if (cpu < 0)
		cpu = scx_bpf_pick_idle_cpu(subcell_mask, 0);

	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

static inline void kick_subcell_idle_cpu(u32 cell_id, u32 subcell_id)
{
	scoped_guard(rcu)
	{
		kick_subcell_idle_cpu_locked(cell_id, subcell_id);
	}
}

/* Caller must hold RCU for lookup_subcell_cpumask() and cpumask kfuncs. */
static inline int refresh_subcell_llc_draining(u32 cell_id, u32 subcell_id)
{
	struct subcell *subcell;
	u64 llcs_with_cpus = 0;
	u32 llc;

	if (!enable_llc_awareness)
		return 0;

	subcell = lookup_subcell(cell_id, subcell_id);
	if (!subcell)
		return -EINVAL;

	const struct cpumask *subcell_mask = lookup_subcell_cpumask(cell_id, subcell_id);

	if (!subcell_mask)
		return -EINVAL;

	bpf_for(llc, 0, nr_llc)
	{
		if (llc >= MAX_LLCS)
			break;

		if (subcell_mask_intersects_llc(subcell_mask, llc))
			llcs_with_cpus |= 1LLU << llc;
	}
	WRITE_ONCE(subcell->llcs_with_cpus, llcs_with_cpus);

	/*
	 * Pair the post-publication queue count check with enqueue's
	 * post-increment cached no-CPU check. Either this path sees already
	 * queued work, or a racing enqueue sees the CPU-less LLC and enables
	 * draining itself. BPF has no standalone full-barrier instruction, so
	 * use an atomic op on a stack slot to avoid bouncing a shared cacheline.
	 */
	volatile unsigned long mb = 0;
	__sync_fetch_and_add(&mb, 0);

	bpf_for(llc, 0, nr_llc)
	{
		struct subcell_llc *subcell_llc;

		if (llc >= MAX_LLCS)
			break;
		subcell_llc = lookup_subcell_llc(subcell, llc);
		if (!subcell_llc)
			return -EINVAL;

		if (llcs_with_cpus & (1LLU << llc)) {
			subcell_llc_drain_disable(subcell, llc);
			continue;
		}

		if (READ_ONCE(subcell_llc->nr_queued) > 0) {
			subcell_llc_drain_enable(subcell, llc);
			kick_subcell_idle_cpu_locked(cell_id, subcell_id);
		}
	}

	return 0;
}

static inline int account_subcell_llc_enqueue(u32 cell_id, u32 subcell_id, u32 llc)
{
	struct subcell *subcell;

	if (!enable_llc_awareness)
		return 0;

	if (!llc_is_valid(llc) || llc >= nr_llc) {
		scx_bpf_error("account_subcell_llc_enqueue: invalid LLC %u", llc);
		return -EINVAL;
	}

	subcell = lookup_subcell(cell_id, subcell_id);
	if (!subcell) {
		scx_bpf_error("account_subcell_llc_enqueue: invalid cell %u subcell %u", cell_id,
			      subcell_id);
		return -ENOENT;
	}

	/*
	 * Account the logical LLC DSQ insertion before checking llcs_with_cpus.
	 * This atomic op is the interlock with refresh_subcell_llc_draining():
	 * either refresh observes the tracked queued work after publishing
	 * llcs_with_cpus, or this enqueue observes the CPU-less LLC below and
	 * enables draining.
	 */
	subcell_llc_nr_queued_inc(subcell, llc);

	if (subcell_llc_has_cpus(subcell, llc))
		return 0;

	subcell_llc_drain_enable(subcell, llc);
	kick_subcell_idle_cpu(cell_id, subcell_id);
	return 0;
}

static inline s32 try_draining_work(u32 cell_id, u32 subcell_id, s32 local_llc)
{
	if (!llc_is_valid(local_llc)) {
		scx_bpf_error("try_draining_work: invalid local_llc: %d", local_llc);
		return -EINVAL;
	}

	struct subcell *subcell = lookup_subcell(cell_id, subcell_id);
	if (!subcell)
		return -EINVAL;

	u64 drain_mask = READ_ONCE(subcell->llcs_to_drain);
	if (!drain_mask)
		return -ENOENT;

	u32 i;
	bpf_for(i, 0, nr_llc)
	{
		u32 candidate_llc = (local_llc + i) % nr_llc;
		struct subcell_llc *candidate_llc_state;
		u64 bit;
		bool disabled = false;
		bool consumed;
		u32 pending;

		// Prevents the optimizer from removing the following conditional return
		// so that the verifier knows the read will be safe
		barrier_var(candidate_llc);

		if (candidate_llc >= MAX_LLCS)
			continue;
		candidate_llc_state = lookup_subcell_llc(subcell, candidate_llc);
		if (!candidate_llc_state)
			return -EINVAL;

		if (candidate_llc == local_llc)
			continue;

		bit = 1LLU << candidate_llc;
		if (!(drain_mask & bit))
			continue;

		dsq_id_t candidate_dsq =
			get_subcell_llc_dsq_id(cell_id, subcell_id, candidate_llc);

		if (subcell_llc_has_cpus(subcell, candidate_llc)) {
			/*
			 * Normal dispatch can consume this DSQ now that the LLC
			 * has CPUs again. Don't clear the drain bit here:
			 * refresh/enqueue may be racing to mark it orphaned
			 * again, and disabling must be paired with checking
			 * whether queued work remains.
			 */
			continue;
		}

		pending = READ_ONCE(candidate_llc_state->nr_queued);
		if (!pending) {
			subcell_llc_drain_disable(subcell, candidate_llc);
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
			subcell_llc_drain_disable(subcell, candidate_llc);
			disabled = true;
		}

		consumed = scx_bpf_dsq_move_to_local(candidate_dsq.raw, 0);

		/*
		 * There is a possibility that the task at the head of the
		 * candidate DSQ is not eligible to move to the local DSQ of
		 * this CPU due to affinity restrictions. This can happen when
		 * a subcell loses CPUs on an LLC where it previously ended up
		 * queuing tasks into the LLC DSQs since all cell CPUs were
		 * allowed for it.
		 */
		if (unlikely(!consumed && READ_ONCE(candidate_llc_state->nr_queued))) {
			struct task_struct *p;

			bpf_for_each(scx_dsq, p, candidate_dsq.raw, 0) {
				struct task_ctx *tctx;
				struct cpu_ctx *target_cctx;
				dsq_id_t cpu_dsq;
				u64 basis_vtime;
				u32 cpu;

				tctx = lookup_task_ctx(p);
				if (!tctx) {
					scx_bpf_error(
						"lookup_task_ctx() failed in try_draining_work()");
					break;
				}

				cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
				if (cpu >= nr_possible_cpus || cpu >= MAX_CPUS)
					break;

				target_cctx = lookup_cpu_ctx(cpu);
				if (!target_cctx)
					break;

				cpu_dsq = get_cpu_dsq_id(cpu);
				if (dsq_is_invalid(cpu_dsq))
					break;

				basis_vtime = READ_ONCE(target_cctx->vtime_now);
				tctx->basis_vtime = basis_vtime;
				tctx->dsq = cpu_dsq;
				/*
				 * Obviate any LLC updates during running(),
				 * next placement refresh on enqueue() will recompute
				 * these based on the current subcell state.
				 */
				tctx->all_cell_cpus_allowed = false;
				invalidate_task_llc(tctx);

				scx_bpf_dsq_move_set_vtime(BPF_FOR_EACH_ITER, basis_vtime);
				consumed = scx_bpf_dsq_move_vtime(BPF_FOR_EACH_ITER, p, cpu_dsq.raw,
								  0);
				if (consumed) {
					cstat_inc(CSTAT_DRAIN_AFFN_CNT, cell_id, target_cctx);
					scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
				}
				break;
			}
		}

		if (consumed) {
			pending = subcell_llc_nr_queued_dec(subcell, candidate_llc);
		} else {
			pending = READ_ONCE(candidate_llc_state->nr_queued);
		}

		if (disabled && pending > 0)
			subcell_llc_drain_enable(subcell, candidate_llc);

		if (consumed)
			return candidate_llc;
	}
	return -ENOENT;
}

static inline s32 try_stealing_work(u32 cell_id, u32 subcell_id, s32 local_llc)
{
	if (!llc_is_valid(local_llc)) {
		scx_bpf_error("try_stealing_work: invalid local_llc: %d", local_llc);
		return -EINVAL;
	}

	struct subcell *subcell = lookup_subcell(cell_id, subcell_id);
	if (!subcell)
		return -EINVAL;

	u32 i;
	bpf_for(i, 0, nr_llc)
	{
		u32 candidate_llc = (local_llc + i) % nr_llc;

		// Prevents the optimizer from removing the following conditional return
		// so that the verifier knows the read will be safe
		barrier_var(candidate_llc);

		if (candidate_llc >= MAX_LLCS)
			continue;

		if (candidate_llc == local_llc)
			continue;

		if (!subcell_llc_has_cpus(subcell, candidate_llc))
			continue;

		dsq_id_t candidate_dsq =
			get_subcell_llc_dsq_id(cell_id, subcell_id, candidate_llc);

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

		subcell_llc_nr_queued_dec(subcell, candidate_llc);
		return 0;
	}
	return -ENOENT;
}

static inline int set_task_llc(struct task_struct *p, struct task_ctx *tctx, u32 new_llc,
			       bool reset_vtime)
{
	if (!tctx) {
		scx_bpf_error("Invalid task context");
		return -ENOENT;
	}

	if (!llc_is_valid(new_llc) || new_llc >= nr_llc || new_llc >= MAX_LLCS) {
		scx_bpf_error("invalid LLC assignment: %u", new_llc);
		return -EINVAL;
	}

	struct subcell *subcell = lookup_subcell(tctx->cell, 0);
	struct subcell_llc *new_llc_state;
	if (!subcell) {
		scx_bpf_error("failed to lookup cell %u subcell 0 for LLC assignment", tctx->cell);
		return -ENOENT;
	}
	new_llc_state = lookup_subcell_llc(subcell, new_llc);
	if (!new_llc_state)
		return -EINVAL;

	u32 old_llc = tctx->llc;
	if (refresh_task_llc_cpumask(tctx, new_llc)) {
		scx_bpf_error("failed to refresh task LLC cpumask for cell %u LLC %u", tctx->cell,
			      new_llc);
		return -EINVAL;
	}

	/*
	 * This writes the default subcell's LLC DSQ. Pinned tasks keep CPU DSQs.
	 */
	tctx->dsq = get_subcell_llc_dsq_id(tctx->cell, 0, new_llc);
	if (dsq_is_invalid(tctx->dsq))
		return -EINVAL;

	if (reset_vtime || !llc_is_valid(old_llc) || old_llc >= nr_llc || old_llc >= MAX_LLCS) {
		scx_bpf_task_set_dsq_vtime(p, READ_ONCE(new_llc_state->vtime_now));
	} else if (old_llc != new_llc) {
		struct subcell_llc *old_llc_state = lookup_subcell_llc(subcell, old_llc);
		s64 vtime_delta;

		if (!old_llc_state)
			return -EINVAL;
		vtime_delta = p->scx.dsq_vtime - READ_ONCE(old_llc_state->vtime_now);
		scx_bpf_task_set_dsq_vtime(p, READ_ONCE(new_llc_state->vtime_now) + vtime_delta);
	}

	tctx->llc = new_llc;
	return 0;
}

static inline int update_task_llc_assignment(struct task_struct *p, struct task_ctx *tctx,
					     s32 preferred_cpu)
{
	s32 new_llc = choose_task_llc(tctx, preferred_cpu);
	if (!llc_is_valid(new_llc))
		return -EINVAL;

	return set_task_llc(p, tctx, (u32)new_llc, true);
}

static inline int maybe_update_task_llc(struct task_struct *p, struct task_ctx *tctx,
					s32 preferred_cpu)
{
	int ret;
	s32 new_llc;

	if (!tctx->all_cell_cpus_allowed)
		return 0;

	/* Retag only all-cell tasks; pinned tasks keep CPU DSQs. */
	new_llc = choose_task_llc(tctx, preferred_cpu);
	if (!llc_is_valid(new_llc))
		return 0;

	if (tctx->llc == new_llc) {
		ret = refresh_task_llc_cpumask(tctx, (u32)new_llc);
		if (ret && !llc_is_valid(tctx->llc))
			return -EINVAL;
		return 0;
	}

	ret = set_task_llc(p, tctx, (u32)new_llc, false);
	if (ret && llc_is_valid(tctx->llc))
		return 0;
	return ret;
}
