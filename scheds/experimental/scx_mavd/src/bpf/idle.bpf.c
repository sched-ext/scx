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
 * Per-domain idle tracking: each cpdom_ctx holds the domain's idle cids in
 * ->idle and its fully idle cores in ->idle_smt. Both are hints, repaired by
 * ops.running(), ops.dispatch() and the sys_stat resync; a claim clears the
 * idle bit atomically. Writers test a bit before the atomic RMW, since the
 * fetching bit operations lock the cacheline unconditionally.
 */
static __always_inline void idle_mask_set(s32 cpu, struct scx_cmask *mask)
{
	if (!cmask_test(cpu, mask))
		cmask_set(cpu, mask);
}

static __always_inline void idle_mask_clear(s32 cpu, struct scx_cmask *mask)
{
	if (cmask_test(cpu, mask))
		cmask_clear(cpu, mask);
}

static __always_inline bool idle_mask_test_and_clear(s32 cpu, struct scx_cmask *mask)
{
	return cmask_test(cpu, mask) && cmask_test_and_clear(cpu, mask);
}

/*
 * Mark @cpuc's core fully idle if all of its cids are idle. On hotplug an
 * offline sibling is really off, so the online ones make a core of their own.
 * In sub mode a cid the parent does not grant runs someone else's work, so the
 * core is fully idle only when all of it is granted and idle. A cid that is not
 * granted is never marked idle. This is racy like the kernel's idle_smt
 * handling. A claim in between leaves a stale hint, which the next claim of any
 * cid of the core clears again.
 */
static __always_inline void mark_core_idle(struct cpu_ctx *cpuc, struct cpdom_ctx *cpdc)
{
	s32 sib;

	bpf_arena_for(sib, cpuc->core_cid, cpuc->core_cid + cpuc->core_nr_cids) {
		if (!cmask_test(sib, &cpdc->idle) &&
		    (sub_mode || cmask_test(sib, &cpdc->online)))
			return;
	}
	bpf_arena_for(sib, cpuc->core_cid, cpuc->core_cid + cpuc->core_nr_cids) {
		if (cmask_test(sib, &cpdc->online))
			idle_mask_set(sib, &cpdc->idle_smt);
	}
}

/*
 * Mark @cpu idle, and its core fully idle if its siblings are idle too.
 */
__hidden
void set_cpu_idle_state(struct cpu_ctx __arg_arena *cpuc, s32 cpu)
{
	struct cpdom_ctx *cpdc = get_cpdom_ctx(cpuc->cpdom_id);

	asm volatile("" :: "r"(&arena));
	idle_mask_set(cpu, &cpdc->idle);

	if (is_smt_active)
		mark_core_idle(cpuc, cpdc);
}

/*
 * Re-evaluate @cpuc's core after one of its cids went offline. The remaining
 * cids may now make a fully idle core. Only the fully idle hints change. A
 * sibling's own idle bit is set by that sibling and cleared by its claimer, so
 * setting it from here could undo a claim.
 */
__hidden
void update_core_idle_state(struct cpu_ctx __arg_arena *cpuc)
{
	asm volatile("" :: "r"(&arena));
	if (is_smt_active)
		mark_core_idle(cpuc, get_cpdom_ctx(cpuc->cpdom_id));
}

/*
 * Drop the fully idle hints of @cpu's core, then claim @cpu by atomically
 * clearing its idle bit. Returns true if this caller claimed it. The hints
 * go whether or not the claim succeeds, as in the kernel's
 * scx_idle_test_and_clear_cpu().
 */
__hidden
bool clear_cpu_idle_state(struct cpu_ctx __arg_arena *cpuc, s32 cpu)
{
	struct cpdom_ctx *cpdc = get_cpdom_ctx(cpuc->cpdom_id);
	s32 sib;

	asm volatile("" :: "r"(&arena));
	if (is_smt_active) {
		/*
		 * The siblings lose their hints too, unless @cpu itself went
		 * offline on hotplug. Then the online ones make a core without
		 * it. A revoke in sub mode leaves the core partly someone
		 * else's, so its siblings lose theirs.
		 */
		if (sub_mode || cmask_test(cpu, &cpdc->online)) {
			bpf_arena_for(sib, cpuc->core_cid,
				      cpuc->core_cid + cpuc->core_nr_cids)
				idle_mask_clear(sib, &cpdc->idle_smt);
		} else {
			idle_mask_clear(cpu, &cpdc->idle_smt);
		}
	}

	return idle_mask_test_and_clear(cpu, &cpdc->idle);
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
bool is_cpu_hinted_idle(struct cpu_ctx __arg_arena *cpuc)
{
	asm volatile("" :: "r"(&arena));
	return cmask_test(cpuc->cid, &get_cpdom_ctx(cpuc->cpdom_id)->idle);
}

static __always_inline
s32 any_idle_cpu_in(const struct scx_cmask *idle, const struct scx_cmask *tier)
{
	if (tier)
		return cmask_any_and_distribute(idle, tier);
	return cmask_any_distribute(idle);
}

/*
 * Pick and claim an idle CPU of @cpdom within @tier_mask (any if NULL),
 * preferring fully idle cores like the kernel's pick_idle_cpu_in_node().
 * Without SMT every idle CPU is a fully idle core. A lost claim is retried
 * and clears the stale hint that caused it. Global, so the verifier checks
 * the body once for its several callers.
 */
__hidden __noinline
s32 pick_idle_cpu_in(s64 cpdom, const struct scx_cmask __arg_arena *tier_mask,
		     u64 scope)
{
	struct cpdom_ctx *cpdc = get_cpdom_ctx(cpdom);
	s32 cpu;
	int i;

	asm volatile("" :: "r"(&arena));
	bpf_arena_for(i, 0, LAVD_MAX_RETRY) {
		if (is_smt_active) {
			cpu = any_idle_cpu_in(&cpdc->idle_smt, tier_mask);
			if (cpu < nr_cids)
				goto claim;

			if (scope & SCX_PICK_IDLE_CORE)
				return -ENOENT;
		}

		cpu = any_idle_cpu_in(&cpdc->idle, tier_mask);
		if (cpu >= nr_cids)
			return -ENOENT;

claim:
		if (claim_idle_cpu(cpu))
			return cpu;
	}
	return -ENOENT;
}

/*
 * Approximate gate for the idle search within one domain. The scan covers only
 * nr_cids bits, so this is a single cache line up to 512 cids, and it is the
 * line the following pick reads anyway.
 */
static __always_inline bool cpdom_has_idle_cpu(s64 cpdom)
{
	return !cmask_empty(&get_cpdom_ctx(cpdom)->idle);
}

/*
 * Pick a CPU to kick after bandwidth replenishment, preferring fully idle
 * cores. Offline CPUs are never marked idle. No idle CPU means every CPU
 * is busy and reaches ops.dispatch() on its own.
 */
static s32 pick_idle_cpu_for_bw(void)
{
	int nr_pass = is_smt_active ? 2 : 1;
	u64 scope;
	s32 cpu;
	u32 id;
	int i;

	bpf_arena_for(i, 0, nr_pass) {
		scope = i ? 0 : SCX_PICK_IDLE_CORE;
		bpf_arena_for(id, 0, nr_cpdoms) {
			if (!cpdom_has_idle_cpu(id))
				continue;

			cpu = pick_idle_cpu_in(id, NULL, scope);
			if (cpu >= 0)
				return cpu;
		}
	}
	return -ENOENT;
}

void scx_cgroup_bw_kick_idle_cb(void)
{
	s32 cpu = pick_idle_cpu_for_bw();

	if (cpu >= 0)
		scx_bpf_kick_cid(cpu, SCX_KICK_IDLE);
}

static __always_inline
void init_ao_masks(struct pick_ctx *ctx, struct task_struct *p)
{
	ctx->cpuc_cur = get_cpu_ctx();
	ctx->temp_mask = ctx->cpuc_cur->temp_mask;

	/*
	 * Evaluate the affinity once per pick, so that this function and
	 * the later can_run_on_cpu() and can_run_on_domain() calls agree.
	 */
	ctx->affinitized = is_affinitized(p, ctx->taskc);
	if (!ctx->affinitized) {
		ctx->a_mask = active_cmask;
		ctx->o_mask = ovrflw_cmask;
		ctx->a_empty = ctx->o_empty = false;
		return;
	}

	ctx->a_mask = ctx->cpuc_cur->a_mask;
	ctx->o_mask = ctx->cpuc_cur->o_mask;

	ctx->a_empty = !cmask_and(ctx->a_mask, &ctx->taskc->allowed, active_cmask);
	ctx->o_empty = !cmask_and(ctx->o_mask, &ctx->taskc->allowed, ovrflw_cmask);
	if (ctx->a_empty)
		ctx->a_mask = NULL;
	if (ctx->o_empty)
		ctx->o_mask = NULL;
}

static __always_inline
bool is_preemption_vulnerable(struct pick_ctx *ctx)
{
	struct cpdom_ctx *cpdc = get_cpdom_ctx(ctx->cpuc_cur->cpdom_id);

	return preemption_vulnerability(ctx->taskc->normalized_lat_cri,
				       ctx->taskc->util_est) >= cpdc->vuln_thresh;
}

/*
 * For preemption-vulnerable tasks, repartition active/overflow masks based
 * on the pre-computed steady_cmask. Steady (non-turbulent) CPUs become
 * the active set, and turbulent CPUs become the overflow set.
 */
static __always_inline
void repartition_masks_for_latency(struct pick_ctx *ctx)
{
	struct scx_cmask *steady_set = ctx->cpuc_cur->a_mask;
	struct scx_cmask *turb_set = ctx->cpuc_cur->o_mask;

	/*
	 * Start from the unfiltered active/overflow masks and apply
	 * affinity if needed. We can't reuse a_mask/o_mask from
	 * init_ao_masks() because they share the same scratch buffers
	 * we're about to overwrite.
	 *
	 * steady_set = eligible_cpus ∩ steady
	 * turb_set   = eligible_cpus - steady
	 */
	cmask_or(steady_set, active_cmask, ovrflw_cmask);

	if (ctx->affinitized)
		cmask_and(steady_set, steady_set, &ctx->taskc->allowed);

	ctx->a_mask = steady_set;
	ctx->o_mask = turb_set;
	ctx->o_empty = !cmask_andnot(turb_set, steady_set, steady_cmask);
	ctx->a_empty = !cmask_and(steady_set, steady_set, steady_cmask);
	if (ctx->a_empty)
		ctx->a_mask = NULL;
	if (ctx->o_empty)
		ctx->o_mask = NULL;
}

__hidden
s32 find_cpu_in(const struct scx_cmask __arg_arena *src_mask,
		struct cpu_ctx __arg_arena *cpuc_cur)
{
	const volatile u16 *cpu_order = get_cpu_order();
	const struct scx_cmask *online_mask;
	struct scx_cmask *online_src_mask = cpuc_cur->temp_mask;
	s32 cpu;
	unsigned int i;

	/*
	 * online_src_mask = src_mask ∩ online_mask
	 */
	online_mask = online_cmask;
	cmask_and(online_src_mask, src_mask, online_mask);

	/*
	 * Find a proper CPU in the preferred CPU order.
	 */
	bpf_arena_for(i, sys_stat.nr_active, nr_cpu_ids) {
		cpu = cpu_order[i];
		if (cmask_test(cpu, online_src_mask))
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
	struct scx_cmask *online_src_mask;
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
	prev_llc = topo_cpu_to_llc_id(scx_bpf_cid_to_cpu(ctx->prev_cpu));
	if (prev_llc < 0)
		return -ENOENT;

	online_src_mask = ctx->cpuc_cur->temp_mask;

	/*
	 * Candidate pool = the task's allowed mask, online only. Active is
	 * implicit (iteration starts at sys_stat.nr_active); overflow exclusion
	 * happens per-iteration.
	 */
	cmask_and(online_src_mask, &ctx->taskc->allowed, online_cmask);

	cpu_order = get_cpu_order();
	bpf_arena_for(i, sys_stat.nr_active, nr_cpu_ids) {
		cpu = cpu_order[i];
		/* Cheaper cpumask bit test first; LLC lookup is multi-load. */
		if (!cmask_test(cpu, online_src_mask))
			continue;
		/* Skip CPUs already in overflow. */
		if (cmask_test(cpu, ovrflw_cmask))
			continue;
		if (topo_cpu_to_llc_id(scx_bpf_cid_to_cpu(cpu)) != prev_llc)
			continue;
		return cpu;
	}
	return -ENOENT;
}

/*
 * Global, so the verifier checks the body once rather than on every caller
 * path. The picker's paths multiply through here and the sticky-domain search.
 */
__noinline
s32 pick_idle_cpu_at_cpdom(struct pick_ctx *ctx __arg_nonnull, s64 cpdom, u64 scope)
{
	struct cpdom_ctx *cpdc = get_cpdom_ctx(cpdom);
	s32 cpu;

	if (!cpdc->is_valid)
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
	if (cpdc->nr_active_cpus && cpdc->is_big && have_turbo_core && ctx->a_mask) {
		cmask_and(ctx->temp_mask, ctx->a_mask, turbo_cmask);
		cpu = pick_idle_cpu_in(cpdom, ctx->temp_mask, scope);
		if (cpu >= 0)
			return cpu;
	}
	if (cpdc->nr_active_cpus && ctx->a_mask) {
		cpu = pick_idle_cpu_in(cpdom, ctx->a_mask, scope);
		if (cpu >= 0)
			return cpu;
	}
	if (ctx->o_mask)
		return pick_idle_cpu_in(cpdom, ctx->o_mask, scope);
	return -ENOENT;
}

static __always_inline
s32 cpumask_any_distribute(struct pick_ctx *ctx)
{
	const struct scx_cmask *mask;
	s32 cpu;

	mask = ctx->a_mask;
	if (mask && ((cpu = cmask_any_distribute(mask)) < nr_cids))
		return cpu;

	mask = ctx->o_mask;
	if (mask && ((cpu = cmask_any_distribute(mask)) < nr_cids))
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
	struct scx_cmask *cpd_mask;
	s32 cpu;

	if (sticky_cpu >= 0)
		return sticky_cpu;

	if (sticky_cpdom < 0)
		return -ENOENT;

	cpd_mask = get_cpdom_mask(sticky_cpdom);
	if (ctx->a_mask) {
		cpu = cmask_any_and_distribute(cpd_mask, ctx->a_mask);
		if (cpu < nr_cids)
			return cpu;
	}

	if (ctx->o_mask) {
		cpu = cmask_any_and_distribute(cpd_mask, ctx->o_mask);
		if (cpu < nr_cids)
			return cpu;
	}

	/*
	 * We should not reach here since a sticky compute
	 * domain should have CPU(s) where a task can run on.
	 */
	return -ENOENT;
}

static __always_inline
bool can_run_on_cpu(struct pick_ctx *ctx, s32 cpu)
{
	struct scx_cmask *a_mask;
	struct scx_cmask *o_mask;

	/* unpinned tasks run anywhere in root mode, on held cids in sub mode */
	if (!ctx->affinitized)
		return !sub_mode || cmask_test(cpu, online_cmask);

	if (!cmask_test(cpu, &ctx->taskc->allowed))
		return false;

	a_mask = ctx->a_mask;
	o_mask = ctx->o_mask;
	if ((a_mask && cmask_test(cpu, a_mask)) || (o_mask && cmask_test(cpu, o_mask)))
		return true;

	return false;
}

static __always_inline
bool can_run_on_domain(struct pick_ctx *ctx, s64 cpdom)
{
	struct cpdom_ctx *cpdc;
	struct scx_cmask *cpd_mask, *a_mask, *o_mask;

	if (!ctx->affinitized)
		return true;

	cpd_mask = get_cpdom_mask(cpdom);
	cpdc = get_cpdom_ctx(cpdom);

	a_mask = ctx->a_mask;
	if (a_mask && cpdc->nr_active_cpus && cmask_intersects(a_mask, cpd_mask))
		return true;

	o_mask = ctx->o_mask;
	if (o_mask && cmask_intersects(o_mask, cpd_mask))
		return true;

	return false;
}

static __always_inline
bool test_cpu_stickable(struct pick_ctx *ctx, struct sticky_ctx *sctx,
			s32 cpu, bool is_task_big)
{
	if (can_run_on_cpu(ctx, cpu)) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);

		if (sctx->i_m >= 2 || sctx->i_nm >= 2)
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

/* global for the same reason as pick_idle_cpu_at_cpdom() */
__noinline
s32 find_sticky_cpu_and_cpdom(struct pick_ctx *ctx __arg_nonnull,
			      s64 *sticky_cpdom __arg_nonnull)
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
		s32 waker_cpu = scx_bpf_this_cid();
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
		return sctx.cpuc_match[0]->cid;
	} else if (sctx.i_m == 2) {
		p0 = sctx.cpuc_match[0]; /* prev_cpu */
		p1 = sctx.cpuc_match[1]; /* sync_waker_cpu */
		d0 = get_cpdom_ctx(p0->cpdom_id);
		d1 = get_cpdom_ctx(p1->cpdom_id);

		if ((p0 != p1) && (d0->load_invr > d1->load_invr)) {
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
			return p0->cid; /* prev_cpu */
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
			d0 = get_cpdom_ctx(p0->cpdom_id);
			d1 = get_cpdom_ctx(p1->cpdom_id);
			if (d0->load_invr > d1->load_invr) {
				*sticky_cpdom = p1->cpdom_id;
				return -ENOENT;
			}
			else {
				*sticky_cpdom = p0->cpdom_id;
				return -ENOENT;
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
	if (can_run_on_domain(ctx, cpuc->cpdom_id)) {
		*sticky_cpdom = cpuc->cpdom_id;
		return -ENOENT;
	}

	if (ctx->sync_waker_cpu < 0)
		goto err_out;
	cpuc = get_cpu_ctx_id(ctx->sync_waker_cpu);
	if (can_run_on_domain(ctx, cpuc->cpdom_id)) {
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
	struct cpu_ctx *cpuc_waker;

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
	if (queued_on_cpu(cpuc_waker))
		return false;

	if (nr_cpdoms > 1 && get_cpu_ctx_id(ctx->prev_cpu)->cpdom_id != cpuc_waker->cpdom_id)
		return false;

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

/*
 * Out of line, so that the print's argument array stays out of
 * migrate_to_neighbor()'s frame, which is on the picker's deepest stack chain.
 */
static __noinline
void debug_neighbor_migration(u32 pid, u64 from, u64 to, s32 cid, bool via_idle)
{
	debugln("migrate: neighbor pid%d cpdom%llu -> cpdom%llu cpu%d via=%s", pid, from, to,
		scx_bpf_cid_to_cpu(cid), via_idle ? "idle-cpu" : "queue");
}

static
s32 migrate_to_neighbor(struct pick_ctx *ctx, struct cpdom_ctx *cpdc, u64 scope,
			bool stealer_only, bool *is_idle)
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

	bpf_arena_for(i, 0, LAVD_CPDOM_MAX_DIST) {
		nr_nbr = cpdc->nr_neighbors[i];
		if (nr_nbr == 0)
			break;
		bpf_arena_for(j, 0, LAVD_CPDOM_MAX_NR) {
			if (unlikely(j >= nr_nbr))
				break;

			mig_cpdom = get_neighbor_id(cpdc, i, j);
			mig_cpdc = get_cpdom_ctx(mig_cpdom);

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
	debug_neighbor_migration(ctx->taskc->pid, cpdc->id, mig_cpdc->id, cpu, via_idle);
	return cpu;
}

__hidden __noinline
s32 pick_idle_cpu(struct pick_ctx *ctx, struct task_struct *p, bool extend_ovrflw,
		  bool *is_idle)
{
	const struct scx_cmask *i_smt;
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
	 *     - the task prefers aggressive migration (e.g., freshly
	 *       execv()-ed) and the sticky domain has no idle CPU, in which
	 *       case any idle CPU of a stealer neighbor will do, or
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
	ctx->a_mask = ctx->o_mask = NULL;

	/*
	 * A task that can run on a single CPU, such as a per-CPU kworker, stays
	 * there. Effective pinning covers both permanent pinning
	 * (nr_cpus_allowed == 1) and transient migrate_disable narrowing
	 * (cpus_ptr weight == 1, cached via ops.set_cmask).
	 */
	if (is_effectively_pinned(ctx->taskc) || is_migration_disabled(p)) {
		cpu = ctx->prev_cpu;
		/* a cid mavd does not hold is left to enqueue's rescue */
		if (sub_mode && !cmask_test(cpu, online_cmask)) {
			*is_idle = false;
			goto out;
		}
		if (!cmask_test(cpu, active_cmask)) {
			/*
			 * Extend the overflow set only for permanent pinning;
			 * migrate_disable is transient, so we don't want to
			 * pollute the overflow set with short-lived restrictions.
			 */
			if (is_permanently_pinned(p))
				ovrflw_test_and_set(ovrflw_cmask, cpu);
		}
		*is_idle = claim_idle_cpu(cpu);
		goto out;
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
	if (warm_cpu_ns && ctx->prev_cpu >= 0 && cmask_test(ctx->prev_cpu, active_cmask) &&
	    cmask_test(ctx->prev_cpu, &ctx->taskc->allowed)) {
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
			goto out;
		}
	}

	/*
	 * If @p cannot run on either active or overflow set, extend the
	 * overflow set, respecting the cpu preference order.
	 */
	init_ao_masks(ctx, p);
	if (ctx->a_empty && ctx->o_empty) {
		cpu = find_cpu_in(&ctx->taskc->allowed, ctx->cpuc_cur);
		if (cpu >= 0) {
			ovrflw_test_and_set(ovrflw_cmask, cpu);
			*is_idle = claim_idle_cpu(cpu);
		}
		goto out;
	}
	/* NOTE: Now task @p can run on either active or overflow set. */

	/*
	 * For preemption-vulnerable tasks, repartition the active/overflow
	 * masks so the idle CPU search prefers non-turbulent CPUs with
	 * sufficient latency headroom.
	 */
	if (is_preemption_vulnerable(ctx))
		repartition_masks_for_latency(ctx);

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
		goto out;
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
			cpdc = get_cpdom_ctx(sticky_cpdom);
			i_smt = is_smt_active ? &cpdc->idle_smt : &cpdc->idle;
			if (cmask_test(sticky_cpu, i_smt) &&
			    claim_idle_cpu(sticky_cpu)) {
				cpu = sticky_cpu;
				goto idle_out;
			}
		}

		/*
		 * If the sticky domain has a fully idle CPU, stay on it.
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
		goto out;
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
	cpdc = get_cpdom_ctx(sticky_cpdom);
	if ((nr_cpdoms > 1) && READ_ONCE(cpdc->is_stealee)) {
		cpu = migrate_to_neighbor(ctx, cpdc, SCX_PICK_IDLE_CORE, true,
					  is_idle);
		if (cpu >= 0)
			goto out;
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
	if (nr_cpdoms > 1) {
		bool aggressive = test_task_flag(ctx->taskc,
						 LAVD_FLAG_MIGRATION_AGGRESSIVE) &&
				  READ_ONCE(cpdc->is_stealee);

		if (extend_ovrflw || aggressive) {
			cpu = migrate_to_neighbor(ctx, cpdc, 0, !extend_ovrflw,
						  is_idle);
			if (cpu >= 0)
				goto out;
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
			ovrflw_test_and_set(ovrflw_cmask, new_cpu);
			debugln("migrate: ovrflw_extend %s[pid%d] prev_cid=%d new_cid=%d",
				p->comm, p->pid, ctx->prev_cpu, new_cpu);
			cpu = new_cpu;
			goto idle_out;
		}
	}

	/*
	 * No eligible idle CPU was claimed. Stay on the sticky CPU or domain.
	 */
	cpu = find_sticky_cpu_at_cpdom(ctx, sticky_cpu, sticky_cpdom);
	if (cpu >= 0)
		goto out;

	/*
	 * Instead of chasing a partially idle CPU in neighboring domains,
	 * let's stay on the previous CPU or the sticky domain for cache
	 * locality, hoping that the load imbalance (if it exists) will be
	 * resolved by the load balancing mechanism.
	 */
	if (can_run_on_cpu(ctx, ctx->prev_cpu)) {
		cpu = ctx->prev_cpu;
		sticky_cpdom = -ENOENT;
		goto out;
	}

	cpu = -ENOENT;
	goto out;

idle_out:
	*is_idle = true;

out:
	/*
	 * For non-error cases, cpu should be chosen, so it cannot be negative.
	 */
	if (cpu < 0)
		cpu = pick_random_cpu(ctx);

	return cpu;
}
