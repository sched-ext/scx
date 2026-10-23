/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023-2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include "power.bpf.h"
#include <lib/topology.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <lib/cgroup.h>

extern const volatile u8	no_fast_lb;
extern const volatile u64	warm_cpu_ns;

struct sticky_ctx {
	/*
	 * For test_cpu_stickable().
	 */
	unsigned int i_m;
	unsigned int i_nm;
	struct cpu_ctx *cpuc_match[2];
	struct cpu_ctx *cpuc_not_match[2];
};

/*
 * Per-domain idle tracking: cpdom_idle_cpumask[] holds each domain's idle
 * CPUs, cpdom_idle_smtmask[] its fully idle cores. Both are hints, repaired
 * by ops.running(), ops.dispatch() and the sys_stat resync; a claim clears
 * the idle bit atomically. Writers test a bit before the atomic RMW, since
 * test_and_set/clear_bit() lock the cacheline unconditionally.
 */
static __always_inline
void idle_mask_set(s32 cpu, struct bpf_cpumask *mask)
{
	if (!bpf_cpumask_test_cpu(cpu, cast_mask(mask)))
		bpf_cpumask_set_cpu(cpu, mask);
}

static __always_inline
void idle_mask_clear(s32 cpu, struct bpf_cpumask *mask)
{
	if (bpf_cpumask_test_cpu(cpu, cast_mask(mask)))
		bpf_cpumask_clear_cpu(cpu, mask);
}

static __always_inline
bool idle_mask_test_and_clear(s32 cpu, struct bpf_cpumask *mask)
{
	return bpf_cpumask_test_cpu(cpu, cast_mask(mask)) &&
	       bpf_cpumask_test_and_clear_cpu(cpu, mask);
}

/*
 * Mark @cpu idle, and its core fully idle if the sibling is idle too.
 */
__hidden
void set_cpu_idle_state(struct cpu_ctx *cpuc, s32 cpu)
{
	struct bpf_cpumask *i_mask, *is_mask, *online_mask;
	u64 cpdom_id = cpuc->cpdom_id;
	u32 sib;

	i_mask = MEMBER_VPTR(cpdom_idle_cpumask, [cpdom_id]);
	if (!i_mask)
		return;

	idle_mask_set(cpu, i_mask);

	if (!is_smt_active)
		return;

	is_mask = MEMBER_VPTR(cpdom_idle_smtmask, [cpdom_id]);
	online_mask = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
	if (!is_mask || !online_mask || cpu < 0 || cpu >= LAVD_CPU_ID_MAX)
		return;

	/*
	 * cpu_sibling[] is static, so an offline sibling is ignored and @cpu
	 * is a core on its own. Like per-core DSQs, it pairs up to two threads.
	 */
	sib = cpu_sibling[cpu];
	if (sib >= nr_cpu_ids ||
	    !bpf_cpumask_test_cpu(sib, cast_mask(online_mask))) {
		idle_mask_set(cpu, is_mask);
		return;
	}

	/*
	 * Racy like the kernel's idle_smt handling: a claim in between leaves
	 * a stale hint, which the next claim of either CPU clears again.
	 */
	if (bpf_cpumask_test_cpu(sib, cast_mask(i_mask))) {
		idle_mask_set(cpu, is_mask);
		idle_mask_set(sib, is_mask);
	}
}

/*
 * Drop the fully idle hints of @cpu's core, then claim @cpu by atomically
 * clearing its idle bit. Returns true if this caller claimed it. The hints
 * go whether or not the claim succeeds, as in the kernel's
 * scx_idle_test_and_clear_cpu().
 */
__hidden
bool clear_cpu_idle_state(struct cpu_ctx *cpuc, s32 cpu)
{
	struct bpf_cpumask *i_mask, *is_mask, *online_mask;
	u64 cpdom_id = cpuc->cpdom_id;
	u32 sib;

	i_mask = MEMBER_VPTR(cpdom_idle_cpumask, [cpdom_id]);
	online_mask = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
	if (!i_mask || !online_mask)
		return false;

	if (is_smt_active && cpu >= 0 && cpu < LAVD_CPU_ID_MAX &&
	    (is_mask = MEMBER_VPTR(cpdom_idle_smtmask, [cpdom_id]))) {
		idle_mask_clear(cpu, is_mask);

		/*
		 * The online sibling loses its hint too, unless @cpu itself
		 * went offline: then the sibling is a core on its own.
		 */
		sib = cpu_sibling[cpu];
		if (sib < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(sib, cast_mask(online_mask)) &&
		    bpf_cpumask_test_cpu(cpu, cast_mask(online_mask)))
			idle_mask_clear(sib, is_mask);
	}

	return idle_mask_test_and_clear(cpu, i_mask);
}

/*
 * Try to claim @cpu from its domain's idle mask.
 */
__hidden
bool claim_idle_cpu(s32 cpu)
{
	struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);

	return cpuc && clear_cpu_idle_state(cpuc, cpu);
}

/*
 * Is @cpuc's CPU marked idle in its domain?
 */
__hidden
bool is_cpu_hinted_idle(struct cpu_ctx *cpuc)
{
	struct bpf_cpumask *i_mask;

	i_mask = MEMBER_VPTR(cpdom_idle_cpumask, [cpuc->cpdom_id]);
	return i_mask && bpf_cpumask_test_cpu(cpuc->cpu_id, cast_mask(i_mask));
}

static __always_inline
s32 any_idle_cpu_in(const struct cpumask *idle, const struct cpumask *tier)
{
	if (tier)
		return bpf_cpumask_any_and_distribute(idle, tier);
	return bpf_cpumask_any_distribute(idle);
}

/*
 * Pick and claim an idle CPU of @cpdom within @tier_mask (any if NULL),
 * preferring fully idle cores like the kernel's pick_idle_cpu_in_node().
 * Without SMT every idle CPU is a fully idle core. A lost claim is retried
 * and clears the stale hint that caused it.
 */
static s32 pick_idle_cpu_in(s64 cpdom, const struct cpumask *tier_mask, u64 scope)
{
	struct bpf_cpumask *i_mask, *is_mask;
	s32 cpu;
	int i;

	i_mask = MEMBER_VPTR(cpdom_idle_cpumask, [cpdom]);
	is_mask = MEMBER_VPTR(cpdom_idle_smtmask, [cpdom]);
	if (!i_mask || !is_mask)
		return -ENOENT;

	bpf_for(i, 0, LAVD_MAX_RETRY) {
		if (is_smt_active) {
			cpu = any_idle_cpu_in(cast_mask(is_mask), tier_mask);
			if (cpu < nr_cpu_ids)
				goto claim;

			if (scope & SCX_PICK_IDLE_CORE)
				return -ENOENT;
		}

		cpu = any_idle_cpu_in(cast_mask(i_mask), tier_mask);
		if (cpu >= nr_cpu_ids)
			return -ENOENT;

claim:
		if (claim_idle_cpu(cpu))
			return cpu;
	}
	return -ENOENT;
}

/*
 * Approximate gate for the idle search within one domain. The kfunc scans
 * only nr_cpu_ids bits, so this is a single cache line up to 512 CPUs, and
 * it is the line the following pick reads anyway.
 */
static bool cpdom_has_idle_cpu(s64 cpdom)
{
	struct bpf_cpumask *i_mask = MEMBER_VPTR(cpdom_idle_cpumask, [cpdom]);

	return i_mask && !bpf_cpumask_empty(cast_mask(i_mask));
}

/*
 * Pick a CPU to kick after bandwidth replenishment, preferring fully idle
 * cores. Offline CPUs are never marked idle. No idle CPU means every CPU
 * is busy and reaches ops.dispatch() on its own.
 */
static s32 pick_idle_cpu_for_bw(void)
{
	int nr_pass = is_smt_active ? 2 : 1;
	u64 scope, id;
	s32 cpu;
	int i;

	bpf_for(i, 0, nr_pass) {
		scope = i ? 0 : SCX_PICK_IDLE_CORE;
		bpf_for(id, 0, nr_cpdoms) {
			if (id >= LAVD_CPDOM_MAX_NR)
				break;

			if (!cpdom_has_idle_cpu(id))
				continue;

			cpu = pick_idle_cpu_in(id, NULL, scope);
			if (cpu >= 0)
				return cpu;
		}
	}
	return -ENOENT;
}

__hidden
void scx_cgroup_bw_kick_idle_cb(void)
{
	s32 cpu = pick_idle_cpu_for_bw();

	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

static __always_inline
bool init_active_ovrflw_masks(struct pick_ctx *ctx)
{
	ctx->active = active_cpumask;
	ctx->ovrflw = ovrflw_cpumask;
	if (!ctx->active || !ctx->ovrflw)
		return false;
	return true;
}

static __always_inline
bool init_ao_masks(struct pick_ctx *ctx)
{
	ctx->cpuc_cur = get_cpu_ctx();
	if (!ctx->cpuc_cur)
		return false;

	ctx->temp_mask = ctx->cpuc_cur->temp_mask;
	if (!ctx->temp_mask)
		return false;

	if (!test_task_flag(ctx->taskc, LAVD_FLAG_IS_AFFINITIZED)) {
		ctx->a_mask = ctx->active;
		ctx->o_mask = ctx->ovrflw;
		ctx->a_empty = ctx->o_empty = false;
		return true;
	}

	ctx->a_mask = ctx->cpuc_cur->a_mask;
	ctx->o_mask = ctx->cpuc_cur->o_mask;
	if (!ctx->a_mask || !ctx->o_mask)
		return false;

	bpf_cpumask_and(ctx->a_mask, ctx->p->cpus_ptr, cast_mask(ctx->active));
	bpf_cpumask_and(ctx->o_mask, ctx->p->cpus_ptr, cast_mask(ctx->ovrflw));
	ctx->a_empty = bpf_cpumask_empty(cast_mask(ctx->a_mask));
	ctx->o_empty = bpf_cpumask_empty(cast_mask(ctx->o_mask));
	if (ctx->a_empty)
		ctx->a_mask = NULL;
	if (ctx->o_empty)
		ctx->o_mask = NULL;
	return true;
}

static __always_inline
bool is_preemption_vulnerable(struct pick_ctx *ctx)
{
	struct cpdom_ctx *cpdc;

	cpdc = MEMBER_VPTR(cpdom_ctxs, [ctx->cpuc_cur->cpdom_id]);
	if (!cpdc)
		return false;

	return preemption_vulnerability(ctx->taskc->normalized_lat_cri,
				       ctx->taskc->util_est) >= cpdc->vuln_thresh;
}

/*
 * For preemption-vulnerable tasks, repartition active/overflow masks based
 * on the pre-computed steady_cpumask. Steady (non-turbulent) CPUs become
 * the active set, and turbulent CPUs become the overflow set.
 */
static __always_inline
bool repartition_masks_for_latency(struct pick_ctx *ctx)
{
	struct bpf_cpumask *steady_set = ctx->cpuc_cur->a_mask;
	struct bpf_cpumask *turb_set = ctx->cpuc_cur->o_mask;
	struct bpf_cpumask *steady = steady_cpumask;

	if (!steady_set || !turb_set || !steady)
		return false;

	/*
	 * Start from the unfiltered active/overflow masks and apply
	 * affinity if needed. We can't reuse a_mask/o_mask from
	 * init_ao_masks() because they share the same scratch buffers
	 * we're about to overwrite.
	 *
	 * steady_set = eligible_cpus ∩ steady
	 * turb_set   = eligible_cpus - steady
	 */
	bpf_cpumask_or(steady_set, cast_mask(ctx->active), cast_mask(ctx->ovrflw));

	if (test_task_flag(ctx->taskc, LAVD_FLAG_IS_AFFINITIZED))
		bpf_cpumask_and(steady_set, ctx->p->cpus_ptr, cast_mask(steady_set));

	bpf_cpumask_copy(turb_set, cast_mask(steady_set));
	bpf_cpumask_and(steady_set, cast_mask(steady_set), cast_mask(steady));
	bpf_cpumask_xor(turb_set, cast_mask(turb_set), cast_mask(steady_set));

	ctx->a_mask = steady_set;
	ctx->o_mask = turb_set;
	ctx->a_empty = bpf_cpumask_empty(cast_mask(steady_set));
	ctx->o_empty = bpf_cpumask_empty(cast_mask(turb_set));
	if (ctx->a_empty)
		ctx->a_mask = NULL;
	if (ctx->o_empty)
		ctx->o_mask = NULL;

	return true;
}

__hidden
s32 find_cpu_in(const struct cpumask *src_mask, struct cpu_ctx *cpuc_cur)
{
	const volatile u16 *cpu_order = get_cpu_order();
	const struct cpumask *online_mask;
	struct bpf_cpumask *online_src_mask;
	s32 cpu;
	unsigned int i;

	/*
	 * online_src_mask = src_mask ∩ online_mask
	 */
	online_src_mask = cpuc_cur->temp_mask;
	if (!online_src_mask)
		return -ENOENT;

	online_mask = scx_bpf_get_online_cpumask();
	bpf_cpumask_and(online_src_mask, src_mask, online_mask);
	scx_bpf_put_cpumask(online_mask);

	/*
	 * Find a proper CPU in the preferred CPU order.
	 */
	bpf_for(i, sys_stat.nr_active, nr_cpu_ids) {
		if (i >= LAVD_CPU_ID_MAX)
			break;

		cpu = cpu_order[i];
		if (bpf_cpumask_test_cpu(cpu, cast_mask(online_src_mask)))
			return cpu;
	};
	return -ENOENT;
}


/*
 * Pick a fresh CPU to add to the overflow set during ops.select_cpu()
 * when active+overflow has no idle CPU usable by the waking task.
 *
 * Anchored to the same LLC as ctx->prev_cpu so the migration cost is
 * negligible. Returns -ENOENT when extension is disabled, the system
 * is already saturated, or no eligible candidate exists.
 */
static s32 find_cpu_for_ovrflw_extend(struct pick_ctx *ctx)
{
	const volatile u16 *cpu_order;
	const struct cpumask *online_mask;
	struct bpf_cpumask *online_src_mask, *ovrflw;
	s32 cpu, prev_llc;
	unsigned int i;

	/* User disabled the feature. */
	if (no_ovrflw_extend)
		return -ENOENT;

	/*
	 * Saturation guard: O(1). When sys_stat.nr_active is bumped to
	 * cover all online CPUs, there is no room to extend.
	 */
	if (sys_stat.nr_active >= nr_cpus_onln)
		return -ENOENT;

	/* Anchor LLC for proximity to prev_cpu. */
	prev_llc = topo_cpu_to_llc_id(ctx->prev_cpu);
	if (prev_llc < 0)
		return -ENOENT;

	online_src_mask = ctx->cpuc_cur->temp_mask;
	ovrflw = ovrflw_cpumask;
	if (!online_src_mask || !ovrflw)
		return -ENOENT;

	/*
	 * Candidate pool = p->cpus_ptr ∩ online. Active is implicit
	 * (iteration starts at sys_stat.nr_active); overflow exclusion
	 * happens per-iteration.
	 */
	online_mask = scx_bpf_get_online_cpumask();
	bpf_cpumask_and(online_src_mask, ctx->p->cpus_ptr, online_mask);
	scx_bpf_put_cpumask(online_mask);

	cpu_order = get_cpu_order();
	bpf_for(i, sys_stat.nr_active, nr_cpu_ids) {
		if (i >= LAVD_CPU_ID_MAX)
			break;
		cpu = cpu_order[i];
		/* Cheaper cpumask bit test first; LLC lookup is multi-load. */
		if (!bpf_cpumask_test_cpu(cpu, cast_mask(online_src_mask)))
			continue;
		/* Skip CPUs already in overflow. */
		if (bpf_cpumask_test_cpu(cpu, cast_mask(ovrflw)))
			continue;
		if (topo_cpu_to_llc_id(cpu) != prev_llc)
			continue;
		return cpu;
	}
	return -ENOENT;
}


static s32 pick_idle_cpu_at_cpdom(struct pick_ctx *ctx, s64 cpdom, u64 scope)
{
	struct cpdom_ctx *cpdc;
	s32 cpu;

	cpdc = MEMBER_VPTR(cpdom_ctxs, [cpdom]);
	if (!ctx || !cpdc || !cpdc->is_valid)
		return -ENOENT;

	/*
	 * Idle masks already restrict the search to this domain.
	 */
	if (!cpdom_has_idle_cpu(cpdom))
		return -ENOENT;

	/*
	 * Search an idle CPU in a compute domain
	 * in the order of turbo, active, and overflow.
	 */
	if (cpdc->nr_active_cpus && cpdc->is_big &&
	    have_turbo_core && turbo_cpumask && ctx->a_mask) {
		bpf_cpumask_and(ctx->temp_mask, cast_mask(ctx->a_mask),
				cast_mask(turbo_cpumask));
		cpu = pick_idle_cpu_in(cpdom, cast_mask(ctx->temp_mask), scope);
		if (cpu >= 0)
			return cpu;
	}
	if (cpdc->nr_active_cpus && ctx->a_mask) {
		cpu = pick_idle_cpu_in(cpdom, cast_mask(ctx->a_mask), scope);
		if (cpu >= 0)
			return cpu;
	}
	if (ctx->o_mask)
		return pick_idle_cpu_in(cpdom, cast_mask(ctx->o_mask), scope);
	return -ENOENT;
}

static __always_inline
s32 cpumask_any_distribute(struct pick_ctx *ctx)
{
	const struct cpumask *mask;
	s32 cpu;

	mask = cast_mask(ctx->a_mask);
	if (mask && ((cpu = bpf_cpumask_any_distribute(mask)) < nr_cpu_ids))
		return cpu;

	mask = cast_mask(ctx->o_mask);
	if (mask && ((cpu = bpf_cpumask_any_distribute(mask)) < nr_cpu_ids))
		return cpu;

	return -ENOENT;
}

static
s32 pick_random_cpu(struct pick_ctx *ctx)
{
	/*
	 * Pick a less loaded CPU using the random of two choices technique.
	 */
	s32 cpu0 = cpumask_any_distribute(ctx);
	s32 cpu1 = cpumask_any_distribute(ctx);
	struct cpu_ctx *cpuc0, *cpuc1;

	if (cpu0 == cpu1 && cpu0 != -ENOENT)
		return cpu0;

	cpuc0 = get_cpu_ctx_id(cpu0);
	cpuc1 = get_cpu_ctx_id(cpu1);
	if (!cpuc0 || !cpuc1)
		return ctx->prev_cpu;

	return (cpuc0->cur_util_invr < cpuc1->cur_util_invr) ? cpu0 : cpu1;
}

static
s32 find_sticky_cpu_at_cpdom(struct pick_ctx *ctx, s32 sticky_cpu, s64 sticky_cpdom)
{
	struct bpf_cpumask *cpd_mask;
	s32 cpu;

	if (sticky_cpu >= 0)
		return sticky_cpu;

	if (sticky_cpdom < 0)
		return -ENOENT;

	cpd_mask = MEMBER_VPTR(cpdom_cpumask, [sticky_cpdom]);
	if (cpd_mask) {
		if (ctx->a_mask) {
			cpu = bpf_cpumask_any_and_distribute(
				cast_mask(cpd_mask), cast_mask(ctx->a_mask));
			if (cpu < nr_cpu_ids)
					return cpu;
		}

		if (ctx->o_mask) {
			cpu = bpf_cpumask_any_and_distribute(
				cast_mask(cpd_mask), cast_mask(ctx->o_mask));
			if (cpu < nr_cpu_ids)
				return cpu;
		}

		/*
		 * We should not reach here since a sticky compute
		 * domain should have CPU(s) where a task can run on.
		 */
	}

	return -ENOENT;
}

static __always_inline
bool can_run_on_cpu(struct pick_ctx *ctx, s32 cpu)
{
	struct bpf_cpumask *a_mask;
	struct bpf_cpumask *o_mask;

	if (!test_task_flag(ctx->taskc, LAVD_FLAG_IS_AFFINITIZED))
		return true;

	if (!bpf_cpumask_test_cpu(cpu, ctx->p->cpus_ptr))
		return false;

	a_mask = ctx->a_mask;
	o_mask = ctx->o_mask;
	if ((a_mask && bpf_cpumask_test_cpu(cpu, cast_mask(a_mask))) ||
	    (o_mask && bpf_cpumask_test_cpu(cpu, cast_mask(o_mask))))
		return true;

	return false;
}

static __always_inline
bool can_run_on_domain(struct pick_ctx *ctx, s64 cpdom)
{
	struct cpdom_ctx *cpdc;
	struct bpf_cpumask *cpd_mask, *a_mask, *o_mask;

	if (!test_task_flag(ctx->taskc, LAVD_FLAG_IS_AFFINITIZED))
		return true;

	cpd_mask = MEMBER_VPTR(cpdom_cpumask, [cpdom]);
	cpdc = MEMBER_VPTR(cpdom_ctxs, [cpdom]);
	if (!cpd_mask || !cpdc)
		return false;

	a_mask = ctx->a_mask;
	if (a_mask && cpdc->nr_active_cpus &&
	    bpf_cpumask_intersects(cast_mask(a_mask), cast_mask(cpd_mask)))
		return true;

	o_mask = ctx->o_mask;
	if (o_mask &&
	    bpf_cpumask_intersects(cast_mask(o_mask), cast_mask(cpd_mask)))
		return true;

	return false;
}

static __always_inline
bool test_cpu_stickable(struct pick_ctx *ctx, struct sticky_ctx *sctx,
			s32 cpu, bool is_task_big)
{
	if (can_run_on_cpu(ctx, cpu)) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);

		if (!cpuc || sctx->i_m >= 2 || sctx->i_nm >= 2)
			return false;

		if (is_task_big == cpuc->big_core)
			sctx->cpuc_match[sctx->i_m++] = cpuc;
		else
			sctx->cpuc_not_match[sctx->i_nm++] = cpuc;
		return true;
	}
	return false;
}

static
bool is_sync_wakeup(struct pick_ctx *ctx)
{
	struct task_struct *waker;

	if (!(ctx->wake_flags & SCX_WAKE_SYNC))
		return false;

	/*
	 * If the waker is exiting now, it is not worth sticking to.
	 */
	waker = bpf_get_current_task_btf();
	if (waker->flags & PF_EXITING)
		return false;

	return true;
}

static
s32 find_sticky_cpu_and_cpdom(struct pick_ctx *ctx, s64 *sticky_cpdom)
{
	struct cpu_ctx *p0, *p1, *cpuc;
	struct cpdom_ctx *d0, *d1;
	struct sticky_ctx sctx;

	__builtin_memset(&sctx, 0, sizeof(sctx));

	/*
	 * Check if a task can stick on either previous CPU or a waker CPU.
	 */
	test_cpu_stickable(ctx, &sctx, ctx->prev_cpu, ctx->is_task_big);
	if (is_sync_wakeup(ctx)) {
		s32 waker_cpu = bpf_get_smp_processor_id();
		if (waker_cpu != ctx->prev_cpu) {
			ctx->sync_waker_cpu = waker_cpu;
			test_cpu_stickable(ctx, &sctx, ctx->sync_waker_cpu, ctx->is_task_big);
		}
	}

	/*
	 * Choose the least-loaded matching CPU and its associated domain
	 * where a task can run on.
	 * Note that when the loads are equal, prefer @p's prev_cpu.
	 */
	if (sctx.i_m == 1) {
		*sticky_cpdom = sctx.cpuc_match[0]->cpdom_id;
		return sctx.cpuc_match[0]->cpu_id;
	} else if (sctx.i_m == 2) {
		p0 = sctx.cpuc_match[0]; /* prev_cpu */
		p1 = sctx.cpuc_match[1]; /* sync_waker_cpu */
		d0 = MEMBER_VPTR(cpdom_ctxs, [p0->cpdom_id]);
		d1 = MEMBER_VPTR(cpdom_ctxs, [p1->cpdom_id]);

		if ((p0 != p1) && (d0 && d1) && (d0->load_invr > d1->load_invr)) {
			/*
			 * When a waker's compute domain is chosen, let's just
			 * stick to the waker's domain. Let's not decide to
			 * stick to the waker's CPU at this point. Since a
			 * single waker can trigger waking up many other tasks,
			 * always moving to the waker's CPU could introduce a
			 * thundering herd problem. So return -ENOENT.
			 */
			*sticky_cpdom = p1->cpdom_id;
			return -ENOENT;
		} else {
			*sticky_cpdom = p0->cpdom_id;
			return p0->cpu_id; /* prev_cpu */
		}
	}

	/*
	 * If there is no matching candidate, choose the least-loaded
	 * active alternative domain where @p can run on.
	 * Note that when the loads are equal, prefer @p's prev_cpu domain.
	 */
	if (sctx.i_nm == 1) {
		p0 = sctx.cpuc_not_match[0];
		if (can_run_on_domain(ctx, p0->cpdom_id)) {
			*sticky_cpdom = p0->cpdom_id;
			return -ENOENT;
		}
	} else if (sctx.i_nm == 2) {
		p0 = sctx.cpuc_not_match[0];
		p1 = sctx.cpuc_not_match[1];

		if ((p0 != p1) && can_run_on_domain(ctx, p0->cpdom_id) &&
		    can_run_on_domain(ctx, p1->cpdom_id)) {
			d0 = MEMBER_VPTR(cpdom_ctxs, [p0->cpdom_id]);
			d1 = MEMBER_VPTR(cpdom_ctxs, [p1->cpdom_id]);
			if (d0 && d1) {
				if (d0->load_invr > d1->load_invr) {
					*sticky_cpdom = p1->cpdom_id;
					return -ENOENT;
				}
				else {
					*sticky_cpdom = p0->cpdom_id;
					return -ENOENT;
				}
			}
		} else if (can_run_on_domain(ctx, p0->cpdom_id)) {
			*sticky_cpdom = p0->cpdom_id;
			return -ENOENT;
		} else if (can_run_on_domain(ctx, p1->cpdom_id)) {
			*sticky_cpdom = p1->cpdom_id;
			return -ENOENT;
		}

	}

	/*
	 * We reach here since both previous CPU and waker CPU are not in
	 * either active or overflow set. In this case, let's stick to
	 * the previous CPU's or waker's compute domain to reduce cross-domain
	 * migration.
	 */
	cpuc = get_cpu_ctx_id(ctx->prev_cpu);
	if (cpuc && can_run_on_domain(ctx, cpuc->cpdom_id)) {
		*sticky_cpdom = cpuc->cpdom_id;
		return -ENOENT;
	}

	if (ctx->sync_waker_cpu < 0)
		goto err_out;
	cpuc = get_cpu_ctx_id(ctx->sync_waker_cpu);
	if (cpuc && can_run_on_domain(ctx, cpuc->cpdom_id)) {
		*sticky_cpdom = cpuc->cpdom_id;
		return -ENOENT;
	}

err_out:
	/*
	 * If we cannot run on the previous CPU's domain, give up finding
	 * a sticky domain.
	 */
	*sticky_cpdom = -ENOENT;
	return -ENOENT;
}

static
bool is_sync_waker_idle(struct pick_ctx * ctx, s64 *cpdom_id)
{
	struct cpu_ctx *cpuc_waker, *cpuc_prev;

	if (ctx->sync_waker_cpu < 0)
		return false;

	/*
	 * When a task @p is woken up synchronously (SCX_WAKE_SYNC), the waker
	 * CPU (i.e., the current CPU) is not idle in the sense of idle mask
	 * because of running this code. So, test if the waker's local DSQ is
	 * empty to test if the waker CPU is idle.
	 */
	if (!can_run_on_cpu(ctx, ctx->sync_waker_cpu))
		return false;

	cpuc_waker = get_cpu_ctx_id(ctx->sync_waker_cpu);
	if (!cpuc_waker || queued_on_cpu(cpuc_waker))
		return false;

	if (nr_cpdoms > 1) {
		cpuc_prev = get_cpu_ctx_id(ctx->prev_cpu);
		if (!cpuc_prev ||
		    cpuc_prev->cpdom_id != cpuc_waker->cpdom_id)
			return false;
	}

	*cpdom_id = cpuc_waker->cpdom_id;
	return true;
}

/*
 * How much sooner @ctx's task would finish on @target than on @sticky, in
 * wall-clock ns; negative when later. Scoped to one LLC since we don't model
 * the L3 cache refill cost: a cross-LLC @target reads as no gain.
 */
static __always_inline s64
comp_time_gain(u64 svc_invr, u64 ct_s, struct cpdom_ctx *sticky,
	       struct cpdom_ctx *target)
{
	if (sticky->llc_id != target->llc_id)
		return 0;

	return (s64)ct_s - (s64)calc_comp_time_on_cpdom(svc_invr, target);
}

static
s32 migrate_to_neighbor(struct pick_ctx *ctx, struct cpdom_ctx *cpdc,
			u64 scope, bool stealer_only, bool *is_idle)
{
	struct cpdom_ctx *mig_cpdc;
	s64 mig_cpdom, nr_nbr, gain;
	s32 cpu = -ENOENT;
	bool ct_enabled = xmig_min_gain_ns > 0; /* Userspace forces this to 0 on a homogeneous machine. */
	u64 ct_s;
	bool via_idle = false;
	int i, j;

	/*
	 * The caller only gets here when the sticky domain is over-loaded
	 * (cpdc->is_stealee) and has no idle CPU or, with @stealer_only false,
	 * when a bursty wake-up finds no idle CPU in the sticky domain. Walk
	 * the neighbors in topology-distance order and take the first one
	 * that qualifies.
	 *
	 * On a homogeneous system a neighbor qualifies when the load balancer
	 * flagged it under-loaded (mig_cpdc->is_stealer) and it has an idle
	 * CPU: every core is alike, so an idle one always finishes the task
	 * sooner than the over-loaded queue. With @stealer_only false, any
	 * neighbor with an idle CPU qualifies. That is a fallback for bursty
	 * wake-ups, not load balancing, so it leaves the stealer and stealee
	 * flags alone.
	 *
	 * On a heterogeneous system the estimate decides instead: the task
	 * must finish on the neighbor sooner by more than xmig_min_gain_ns,
	 * idle core or not. An idle core does not qualify by itself, since a
	 * compute-heavy task would finish later on a slow idle core than in a
	 * fast queue; and a neighbor whose queue finishes the task clearly
	 * sooner qualifies even without an idle core, in which case the task
	 * joins that queue. An idle CPU is preferred when the neighbor has one.
	 *
	 * Note that when a system is under-loaded, task donation works better
	 * than task stealing because DSQs are mostly empty (i.e., it is hard
	 * to steal from a DSQ).
	 *
	 * Return the first hit, at the nearest distance. Scanning farther
	 * distances after a hit would overwrite it and leak the claim.
	 */
	if (ct_enabled)
		ct_s = calc_comp_time_on_cpdom(ctx->taskc->avg_runtime_invr, cpdc);

	bpf_for(i, 0, LAVD_CPDOM_MAX_DIST) {
		nr_nbr = min(cpdc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;
		bpf_for(j, 0, LAVD_CPDOM_MAX_NR) {
			if (unlikely(j >= nr_nbr))
				break;

			mig_cpdom = get_neighbor_id(cpdc, i, j);
			if (unlikely(mig_cpdom < 0))
				continue;

			mig_cpdc = MEMBER_VPTR(cpdom_ctxs, [mig_cpdom]);
			if (unlikely(!mig_cpdc))
				continue;

			if (ct_enabled) {
				gain = comp_time_gain(
					ctx->taskc->avg_runtime_invr, ct_s,
					cpdc, mig_cpdc);
				if (gain  <= (s64)xmig_min_gain_ns)
					continue;
			} else if (stealer_only &&
				   !READ_ONCE(mig_cpdc->is_stealer)) {
				continue;
			}

			cpu = pick_idle_cpu_at_cpdom(ctx, mig_cpdom, scope);
			if (cpu >= 0) {
				*is_idle = true;
				via_idle = true;
				goto found;
			}

			if (ct_enabled) {
				cpu = find_sticky_cpu_at_cpdom(ctx, -ENOENT, mig_cpdom);
				if (cpu >= 0) {
					*is_idle = false;
					goto found;
				}
			}
		}
	}

	return cpu;

found:
	/*
	 * Under the legacy balancer a donation consumes the imbalance. The
	 * any-neighbor walk is not a donation, so it leaves the flags alone.
	 */
	if (stealer_only && no_fast_lb) {
		WRITE_ONCE(mig_cpdc->is_stealer, false);
		WRITE_ONCE(cpdc->is_stealee, false);
	}
	debugln("migrate: neighbor %s[pid%d] cpdom%llu -> cpdom%llu cpu%d via=%s",
		ctx->p->comm, ctx->p->pid, cpdc->id, mig_cpdc->id, cpu,
		via_idle ? "idle-cpu" : "queue");
	return cpu;
}

__hidden __noinline
s32 pick_idle_cpu(struct pick_ctx *ctx, bool extend_ovrflw, bool *is_idle)
{
	struct bpf_cpumask *i_smt;
	s32 cpu = -ENOENT, sticky_cpu;
	s64 sticky_cpdom = -ENOENT;
	struct cpdom_ctx *cpdc;
	bool sticky_has_idle;

	/*
	 * At the high level, the idle CPU selection policy considers the
	 * following factors:
	 *
	 * 1) Warm CPU: Prefer the previous CPU while its cache is warm, if it
	 *    is idle or predicted to free up soon.
	 *
	 * 2) Current active and overflow set: Stay on the current active and
	 *    overflow sets if a task can run on them.
	 *
	 * 3) CPU preference order: Extend the overflow set following the CPU
	 *    preference order (performance mode vs. power-save mode) when a
	 *    task cannot run on the current active or overflow set. For a
	 *    bursty wake-up, also extend it, within the previous CPU's LLC,
	 *    when neither the sticky domain nor any neighbor has an idle CPU
	 *    in the active or overflow set.
	 *
	 * 4) CPU type vs. task type: If possible, try to run a task on the
	 *    matching CPU type (i.e., a big task on a big core vs. a little
	 *    task on a little core). If the matching CPUs are not active,
	 *    stay on the previous CPU.
	 *
	 * 5) Fully idle CPU vs. partially idle CPU: Choose a fully idle core
	 *    over a partially idle CPU within the sticky domain. When the
	 *    sticky domain is overloaded, a fully idle core in a neighbor also
	 *    wins over a partially idle CPU in the sticky domain.
	 *
	 * 6) Synchronous wake-up: If the waker CPU is idle, stay on the waker
	 *    CPU when the sticky domain has no fully idle core and the sticky
	 *    CPU is not idle. It is good for cache locality because the waker
	 *    task hands over the CPU to the wakee task for the further
	 *    processing after finishing its job.
	 *
	 * 7) Minimize cross-domain migration: Migrate a task to a neighbor
	 *    domain only when
	 *     - the sticky domain is relatively overloaded (i.e., stealee) and
	 *       the neighbor is relatively under-loaded (i.e., stealer) with a
	 *       fully idle core,
	 *     - the task prefers aggressive migration (e.g., freshly execv()-ed)
	 *       and the sticky domain has no idle CPU, in which case any idle
	 *       CPU of a stealer neighbor will do, or
	 *     - the wake-up is bursty and the sticky domain has no idle CPU, in
	 *       which case any idle CPU of any neighbor will do.
	 *    Otherwise, stay on the sticky CPU or domain for cache locality,
	 *    hoping that the load imbalance (if it exists) will be resolved by
	 *    the load balancing mechanism.
	 *
	 * Idle states come from per-domain idle masks, which are hints. A CPU
	 * is used as idle only after it is claimed by atomically clearing its
	 * idle bit.
	 */
	bpf_rcu_read_lock();
	ctx->a_mask = ctx->o_mask = NULL;

	/*
	 * If a task can run only on a single CPU (e.g., per-CPU kworker),
	 * we just go with that CPU and set the overflow set if needed.
	 * Note that do not extend the overflow set for a unpinned,
	 * non-migratable task since disabling task migration is temporary.
	 */
	if (!init_active_ovrflw_masks(ctx)) {
		/*
		 * ctx->a_mask and ctx->o_mask haven't been initialized yet,
		 * so we cannot rely on pick_random_cpu(). Hence, fall back to
		 * the prev_cpu and go out.
		 */
		cpu = ctx->prev_cpu;
		goto unlock_out;
	}

	/*
	 * Use effective pinning here so we cover both permanent pinning
	 * (nr_cpus_allowed == 1) and transient migrate_disable narrowing
	 * (cpus_ptr weight == 1, cached via ops.set_cpumask).
	 */
	if (is_effectively_pinned(ctx->taskc) || is_migration_disabled(ctx->p)) {
		cpu = ctx->prev_cpu;
		if (!bpf_cpumask_test_cpu(cpu, cast_mask(ctx->active))) {
			/*
			 * Extend the overflow set only for permanent pinning;
			 * migrate_disable is transient, so we don't want to
			 * pollute the overflow set with short-lived restrictions.
			 */
			if (is_permanently_pinned(ctx->p))
				ovrflw_test_and_set(ctx->ovrflw, cpu);
		}
		*is_idle = claim_idle_cpu(cpu);
		goto unlock_out;
	}
	/* NOTE: Now task @p is not a per-CPU task. */

	/*
	 * Warm-CPU preference: Prefer the previous CPU while its cache and TLB
	 * are still warm. Take it if idle or, if it is busy but predicted to
	 * free up within the warmth-extended budget.
	 *
	 * TODO: on asymmetric CPUs (big/LITTLE), stick to prev_cpu only when its
	 * core type matches the task type; otherwise fall through to allow a
	 * cross-cluster migration.
	 */
	if (warm_cpu_ns && ctx->prev_cpu >= 0 &&
	    bpf_cpumask_test_cpu(ctx->prev_cpu, cast_mask(ctx->active)) &&
	    bpf_cpumask_test_cpu(ctx->prev_cpu, ctx->p->cpus_ptr)) {
		if (claim_idle_cpu(ctx->prev_cpu)) {
			cpu = ctx->prev_cpu;
			goto idle_out;
		}

		if (ctx->taskc->lat_cri < sys_stat.thr_lat_cri &&
		    warm_cpu_wait_ok(ctx->taskc, ctx->prev_cpu, scx_bpf_now())) {
			cpu = ctx->prev_cpu;
			/*
			 * Previous CPU is busy, so wait on the previous CPU's
			 * Per-core DSQ.
			 */
			set_task_flag(ctx->taskc, LAVD_FLAG_WARM_CPU);
			goto unlock_out;
		}
	}

	/*
	 * If @p cannot run on either active or overflow set, extend the
	 * overflow set, respecting the cpu preference order.
	 */
	if (!init_ao_masks(ctx)) {
		/*
		 * ctx->a_mask and ctx->o_mask haven't been initialized yet,
		 * so we cannot rely on pick_random_cpu(). Hence, fall back to
		 * the prev_cpu and go out.
		 */
		cpu = ctx->prev_cpu;
		goto unlock_out;
	}
	if (ctx->a_empty && ctx->o_empty) {
		cpu = find_cpu_in(ctx->p->cpus_ptr, ctx->cpuc_cur);
		if (cpu >= 0) {
			ovrflw_test_and_set(ctx->ovrflw, cpu);
			*is_idle = claim_idle_cpu(cpu);
		}
		goto unlock_out;
	}
	/* NOTE: Now task @p can run on either active or overflow set. */

	/*
	 * For preemption-vulnerable tasks, repartition the active/overflow
	 * masks so the idle CPU search prefers non-turbulent CPUs with
	 * sufficient latency headroom.
	 */
	if (is_preemption_vulnerable(ctx)) {
		if (!repartition_masks_for_latency(ctx))
			goto err_out;
	}

	/*
	 * Find a sticky cpu and domain considering the core & task type
	 * to set an anchor for proximity.
	 */
	ctx->sync_waker_cpu = -ENOENT;
	ctx->is_task_big = is_perf_cri(ctx->taskc);
	sticky_cpu = find_sticky_cpu_and_cpdom(ctx, &sticky_cpdom);

	/*
	 * If failed to find a sticky domain -- i.e., @p cannot run on previous
	 * CPU's compute domain, choose an arbitrary CPU from the active and
	 * overflow set.
	 */
	if (sticky_cpdom < 0) {
		cpu = pick_random_cpu(ctx);
		goto unlock_out;
	}
	/* NOTE: There is a sticky domain. */

	/*
	 * Check once whether the sticky domain has any idle CPU and skip the
	 * searches within it when it does not; neighbors gate themselves.
	 */
	sticky_has_idle = cpdom_has_idle_cpu(sticky_cpdom);
	if (sticky_has_idle) {
		/*
		 * If the sticky CPU is fully idle, stay on it. Without SMT,
		 * a core is a CPU, so the idle mask stands in for the fully
		 * idle mask.
		 */
		if (sticky_cpu >= 0) {
			if (is_smt_active)
				i_smt = MEMBER_VPTR(cpdom_idle_smtmask, [sticky_cpdom]);
			else
				i_smt = MEMBER_VPTR(cpdom_idle_cpumask, [sticky_cpdom]);
			if (i_smt &&
			    bpf_cpumask_test_cpu(sticky_cpu, cast_mask(i_smt)) &&
			    claim_idle_cpu(sticky_cpu)) {
				cpu = sticky_cpu;
				goto idle_out;
			}
		}

		/*
		 * If there is a fully idle CPU in the sticky domain, stay on it.
		 */
		cpu = pick_idle_cpu_at_cpdom(ctx, sticky_cpdom,
					     SCX_PICK_IDLE_CORE);
		if (cpu >= 0)
			goto idle_out;
		/* NOTE: There is no fully idle CPU in the sticky domain. */

		/*
		 * If the sticky CPU is (partially) idle, stay on it.
		 */
		if (sticky_cpu >= 0 && claim_idle_cpu(sticky_cpu)) {
			cpu = sticky_cpu;
			goto idle_out;
		}
		/* NOTE: The sticky CPU is not (even partially) idle. */
	}

	/*
	 * If the synchronous waker CPU is idle and in the same domain with
	 * the previous CPU, stay on it. Note that in this case, the waker CPU
	 * is unnecessary to be kicked since it is busy running this code.
	 */
	if (!no_wake_sync && is_sync_waker_idle(ctx, &sticky_cpdom)) {
		cpu = ctx->sync_waker_cpu;
		goto unlock_out;
	}
	/* NOTE: The waker CPU is not (even partially) idle if there is. */

	/*
	 * So far, it is confirmed that
	 *  1) The sticky CPU and the waker CPU, if any, are not idle.
	 *  2) There is no fully idle core in the active/overflow set of the
	 *     sticky domain. Without SMT, a CPU is a core, so there is no idle
	 *     CPU at all there.
	 *  3) However, with SMT, the sticky domain may still have a partially
	 *     idle CPU in the active/overflow set. Nothing is known yet about
	 *     the neighbors, nor whether there is any idle CPU in the system.
	 *
	 * Consider donating the task to a neighbor: as before, only if the
	 * sticky domain is a stealee, the neighbor a stealer, and the neighbor
	 * has a fully idle core in the task's active/overflow set, or, on a
	 * heterogeneous system, if the task would finish there clearly sooner
	 * (see migrate_to_neighbor()). Each neighbor now gates itself on its
	 * own idle mask.
	 */
	if ((nr_cpdoms > 1) &&
	    (cpdc = MEMBER_VPTR(cpdom_ctxs, [sticky_cpdom])) &&
	    READ_ONCE(cpdc->is_stealee)) {
		cpu = migrate_to_neighbor(ctx, cpdc, SCX_PICK_IDLE_CORE, true,
					  is_idle);
		if (cpu >= 0)
			goto unlock_out;
	}
	/* NOTE: There is no fully idle CPU in the neighboring domain. */

	/*
	 * If there is an (partially) idle CPU in the sticky domain, stay on it.
	 * In the domain, search in the order of turbo, active, and overflow.
	 */
	if (sticky_has_idle) {
		cpu = pick_idle_cpu_at_cpdom(ctx, sticky_cpdom, 0);
		if (cpu >= 0)
			goto idle_out;
	}
	/* NOTE: There is no even partially idle CPU in the sticky domain. */

	/*
	 * So far, it is confirmed that
	 *  1) The sticky CPU and the waker CPU, if any, are not idle.
	 *  2) There is no idle CPU, not even a partially idle one, in the
	 *     active/overflow set of the sticky domain.
	 *  3) If the sticky domain is a stealee, no stealer neighbor has a
	 *     fully idle core in the active/overflow set and, on a
	 *     heterogeneous system, no neighbor would finish the task clearly
	 *     sooner.
	 *  4) However, a neighbor may still have an idle CPU in the
	 *     active/overflow set, and the sticky domain may have one outside
	 *     it. We don't even know whether there is any idle CPU in the
	 *     system.
	 *
	 * Find a partially idle CPU in a neighbor: in a stealer neighbor for
	 * an aggressive migration (e.g., a freshly execv()-ed task) when the
	 * sticky domain is a stealee, and in any neighbor, nearest first, for
	 * a bursty wake-up (ops.select_cpu() only) rather than queue on the
	 * sticky domain. On a heterogeneous system, the completion-time
	 * estimate picks the neighbor instead, as for the donation above.
	 */
	if ((nr_cpdoms > 1) &&
	    (cpdc = MEMBER_VPTR(cpdom_ctxs, [sticky_cpdom]))) {
		bool aggressive = test_task_flag(ctx->taskc,
						 LAVD_FLAG_MIGRATION_AGGRESSIVE) &&
				  READ_ONCE(cpdc->is_stealee);

		if (extend_ovrflw || aggressive) {
			cpu = migrate_to_neighbor(ctx, cpdc, 0, !extend_ovrflw,
						  is_idle);
			if (cpu >= 0)
				goto unlock_out;
		}
	}

	/*
	 * For a bursty wake-up, it is now confirmed that
	 *  1) The sticky CPU and the waker CPU, if any, are not idle.
	 *  2) There is no idle CPU, not even a partially idle one, in the
	 *     active/overflow set of the sticky domain.
	 *  3) There is no idle CPU, not even a partially idle one, in the
	 *     active/overflow set of any neighbor.
	 *  4) However, CPUs outside the active/overflow set, in the sticky
	 *     domain or a neighbor, may still be idle. We don't even know
	 *     whether there is any idle CPU in the system.
	 *
	 * So, grow the overflow set with a fresh LLC-anchored CPU, which can
	 * be one of those idle CPUs outside the set. It is claimed first so
	 * the set never gains a CPU we could not use.
	 */
	if (extend_ovrflw) {
		s32 new_cpu = find_cpu_for_ovrflw_extend(ctx);
		if (new_cpu >= 0 && claim_idle_cpu(new_cpu)) {
			ovrflw_test_and_set(ctx->ovrflw, new_cpu);
			debugln("migrate: ovrflw_extend %s[pid%d] prev_cpu=%d new_cpu=%d",
				ctx->p->comm, ctx->p->pid,
				ctx->prev_cpu, new_cpu);
			cpu = new_cpu;
			goto idle_out;
		}
	}

	/*
	 * No eligible idle CPU was claimed. Stay on the sticky CPU or domain.
	 */
	cpu = find_sticky_cpu_at_cpdom(ctx, sticky_cpu, sticky_cpdom);
	if (cpu >= 0)
		goto unlock_out;

	/*
	 * Instead of chasing a partially idle CPU in neighboring domains,
	 * let's stay on the previous CPU or the sticky domain for cache
	 * locality, hoping that the load imbalance (if it exists) will be
	 * resolved by the load balancing mechanism.
	 */
	if (can_run_on_cpu(ctx, ctx->prev_cpu)) {
		cpu = ctx->prev_cpu;
		sticky_cpdom = -ENOENT;
		goto unlock_out;
	}

err_out:
	cpu = -ENOENT;
	goto unlock_out;

idle_out:
	*is_idle = true;

unlock_out:
	/*
	 * For non-error cases, cpu should be chosen, so it cannot be negative.
	 */
	if (cpu < 0)
		cpu = pick_random_cpu(ctx);

	bpf_rcu_read_unlock();

	return cpu;
}
