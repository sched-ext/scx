/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023-2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */
struct pick_ctx {
	/*
	 * Input arguments for pick_idle_cpu().
	 */
	const struct task_struct *p;
	struct task_ctx *taskc;
	s32 prev_cpu;
	u64 wake_flags;
	/*
	 * Additional output arguments for pick_idle_cpu().
	 */
	u64 cpdom_id;
	/*
	 * Additional output arguments for init_active_ovrflw_masks().
	 */
	struct bpf_cpumask *active; /* global active mask */
	struct bpf_cpumask *ovrflw; /* global overflow mask */
	/*
	 * Additional output arguments for init_ao_masks().
	 * Additional input arguments for find_sticky_cpu_and_cpdom().
	 */
	struct cpu_ctx *cpuc_cur;
	struct bpf_cpumask *a_mask; /* task's active mask */
	struct bpf_cpumask *o_mask; /* task's overflow mask */
	bool a_empty;
	bool o_empty;
	/*
	 * Additional input arguments for find_sticky_cpu_and_cpdom().
	 */
	s32 sync_waker_cpu;
	bool is_task_big;
	/*
	 * Additional input arguments for test_cpu_stickable().
	 */
	unsigned int i_m;
	unsigned int i_nm;
	s32 cpus_match[2];
	s32 cpus_not_match[2];
	s64 cpdoms_match[2];
	s64 cpdoms_not_match[2];
	/*
	 * Additional input arguments for init_idle_i_mask().
	 */
	const struct cpumask *i_mask;
	bool i_empty;
	/*
	 * Additional input arguments for init_idle_ato_masks().
	 * Additional input arguments for pick_idle_cpu_at_cpdom().
	 */
	struct bpf_cpumask *ia_mask;
	struct bpf_cpumask *iat_mask;
	struct bpf_cpumask *io_mask;
	struct bpf_cpumask *temp_mask;
	/*
	 * Additional output arguments for init_idle_ato_masks().
	 * Additional input arguments for pick_idle_cpu_at_cpdom().
	 */
	bool ia_empty;
	bool iat_empty;
	bool io_empty;
};

static __always_inline
bool init_idle_i_mask(struct pick_ctx *ctx, const struct cpumask *idle_cpumask)
{
	if (!ctx->taskc->is_affinitized)
		ctx->i_mask = idle_cpumask;
	else {
		struct bpf_cpumask *_i_mask = ctx->cpuc_cur->tmp_i_mask;
		if (!_i_mask)
			return false;
		bpf_cpumask_and(_i_mask, ctx->p->cpus_ptr, idle_cpumask);
		ctx->i_mask = cast_mask(_i_mask);
	}
	ctx->i_empty = bpf_cpumask_empty(ctx->i_mask);
	return true;
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

	if (!ctx->taskc->is_affinitized) {
		ctx->a_mask = ctx->active;
		ctx->o_mask = ctx->ovrflw;
		ctx->a_empty = ctx->o_empty = false;
		return true;
	}

	ctx->a_mask = ctx->cpuc_cur->tmp_a_mask;
	ctx->o_mask = ctx->cpuc_cur->tmp_o_mask;
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
bool init_idle_ato_masks(struct pick_ctx *ctx, const struct cpumask *idle_mask)
{
	ctx->ia_mask = ctx->cpuc_cur->tmp_t_mask;
	ctx->io_mask = ctx->cpuc_cur->tmp_t2_mask;
	ctx->iat_mask = ctx->cpuc_cur->tmp_t3_mask;
	ctx->temp_mask = ctx->cpuc_cur->tmp_l_mask; /* l_mask is no longer used, recyle it. */
	if (!ctx->ia_mask || !ctx->io_mask || !ctx->iat_mask || !ctx->temp_mask)
		return false;

	if (ctx->a_mask) {
		bpf_cpumask_and(ctx->ia_mask, idle_mask, cast_mask(ctx->a_mask));
		ctx->ia_empty = bpf_cpumask_empty(cast_mask(ctx->ia_mask));
	}
	else
		ctx->ia_empty = true;

	if (ctx->o_mask) {
		bpf_cpumask_and(ctx->io_mask, idle_mask, cast_mask(ctx->o_mask));
		ctx->io_empty = bpf_cpumask_empty(cast_mask(ctx->io_mask));
	}
	else
		ctx->io_empty = true;

	if (ctx->ia_empty || !have_turbo_core || !turbo_cpumask)
		ctx->iat_empty = true;
	else if (turbo_cpumask) {
		bpf_cpumask_and(ctx->iat_mask, cast_mask(ctx->ia_mask),
				cast_mask(turbo_cpumask));
		ctx->iat_empty = bpf_cpumask_empty(cast_mask(ctx->iat_mask));
	}
	return true;
}

static s32 find_cpu_in(const struct cpumask *src_mask, struct cpu_ctx *cpuc_cur)
{
	const volatile u16 *cpu_order = get_cpu_order();
	const struct cpumask *online_mask;
	struct bpf_cpumask *online_src_mask;
	s32 cpu;
	int i;

	/*
	 * online_src_mask = src_mask ∩ online_mask
	 */
	online_src_mask = cpuc_cur->tmp_l_mask;
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

static
s32 pick_idle_cpu_at_cpdom(struct pick_ctx *ctx, s64 cpdom, u64 scope,
			   bool *is_idle)
{
	struct bpf_cpumask *cpd_mask;
	struct cpdom_ctx *cpdc;
	s32 cpu;

	cpd_mask = MEMBER_VPTR(cpdom_cpumask, [cpdom]);
	cpdc = MEMBER_VPTR(cpdom_ctxs, [cpdom]);
	if (!ctx || !cpdc || !cpd_mask || !cpdc->is_valid)
		return -ENOENT;

	/*
	 * Search an idle CPU in a compute domain
	 * in the order of turbo, active, and overflow.
	 */
	if (!ctx->iat_empty && cpdc->nr_active_cpus && cpdc->is_big) {
		bpf_cpumask_and(ctx->temp_mask,
				cast_mask(cpd_mask), cast_mask(ctx->iat_mask));
		cpu = scx_bpf_pick_idle_cpu(cast_mask(ctx->temp_mask), scope);
		if (cpu >= 0) {
			*is_idle = true;
			return cpu;
		}
	}
	if (!ctx->ia_empty && cpdc->nr_active_cpus) {
		bpf_cpumask_and(ctx->temp_mask,
				cast_mask(cpd_mask), cast_mask(ctx->ia_mask));
		cpu = scx_bpf_pick_idle_cpu(cast_mask(ctx->temp_mask), scope);
		if (cpu >= 0) {
			*is_idle = true;
			return cpu;
		}
	}
	if (!ctx->io_empty) {
		bpf_cpumask_and(ctx->temp_mask,
				cast_mask(cpd_mask), cast_mask(ctx->io_mask));
		cpu = scx_bpf_pick_idle_cpu(cast_mask(ctx->temp_mask), scope);
		if (cpu >= 0) {
			*is_idle = true;
			return cpu;
		}
	}
	return -ENOENT;
}

static __always_inline
s32 cpumask_any_dsitribute(struct pick_ctx *ctx)
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

	if (!ctx->taskc->is_affinitized)
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

	if (!ctx->taskc->is_affinitized)
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
bool test_cpu_stickable(struct pick_ctx *ctx, s32 cpu, bool is_task_big)
{
	if (can_run_on_cpu(ctx, cpu)) {
		struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc || ctx->i_m >= 2 || ctx->i_nm >= 2)
			return false;

		if (is_task_big == cpuc->big_core) {
			ctx->cpdoms_match[ctx->i_m] = cpuc->cpdom_id;
			ctx->cpus_match[ctx->i_m] = cpu;
			ctx->i_m++;
		}
		else {
			ctx->cpdoms_not_match[ctx->i_m] = cpuc->cpdom_alt_id;
			ctx->cpus_not_match[ctx->i_nm] = cpu;
			ctx->i_nm++;
		}
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
	struct cpu_ctx *cpuc;
	u64 q0, q1;

	/*
	 * Check if a task can stick on either previous CPU or a waker CPU.
	 */
	ctx->cpus_match[0] = -ENOENT;
	ctx->cpus_match[1] = -ENOENT;
	ctx->cpus_not_match[0] = -ENOENT;
	ctx->cpus_not_match[1] = -ENOENT;
	ctx->i_m = 0;
	ctx->i_nm = 0;
	test_cpu_stickable(ctx, ctx->prev_cpu, ctx->is_task_big);
	if (is_sync_wakeup(ctx)) {
		s32 waker_cpu = bpf_get_smp_processor_id();
		if (waker_cpu != ctx->prev_cpu) {
			ctx->sync_waker_cpu = waker_cpu;
			test_cpu_stickable(ctx, ctx->sync_waker_cpu, ctx->is_task_big);
		}
	}

	/*
	 * Choose the least-loaded matching CPU and its associated domain
	 * where a task can run on.
	 * Note that when the loads are equal, prefer @p's prev_cpu.
	 */
	if (ctx->i_m == 1) {
		*sticky_cpdom = ctx->cpdoms_match[0];
		return ctx->cpus_match[0];
	} else if (ctx->i_m == 2) {
		q0 = ctx->cpdoms_match[0]; /* prev_cpu */
		q1 = ctx->cpdoms_match[1]; /* sync_waker_cpu */
		if (q0 != q1 &&
		    (scx_bpf_dsq_nr_queued(q0) > scx_bpf_dsq_nr_queued(q1))) {
			/*
			 * When a waker's compute domain is chosen, let's just
			 * stick to the waker's domain. Let's not decide to
			 * stick to the waker's CPU at this point. Since a
			 * single waker can trigger waking up many other tasks,
			 * always moving to the waker's CPU could introduce a
			 * thundering herd problem. So return -ENOENT.
			 */
			*sticky_cpdom = q1;
			return -ENOENT;
		} else {
			*sticky_cpdom = q0;
			return ctx->cpus_match[0]; /* prev_cpu */
		}
	}

	/*
	 * If there is no matching candidate, choose the least-loaded
	 * active alternative domain where @p can run on.
	 * Note that when the loads are equal, prefer @p's prev_cpu domain.
	 */
	if (ctx->i_nm == 1) {
		q0 = ctx->cpdoms_not_match[0];
		if (can_run_on_domain(ctx, q0)) {
			*sticky_cpdom = q0;
			return -ENOENT;
		}
	} else if (ctx->i_nm == 2) {
		q0 = ctx->cpdoms_not_match[0];
		q1 = ctx->cpdoms_not_match[1];

		if (q0 != q1 && can_run_on_domain(ctx, q0) &&
		    can_run_on_domain(ctx, q1)) {
			if (scx_bpf_dsq_nr_queued(q0) > scx_bpf_dsq_nr_queued(q1)) {
				*sticky_cpdom = q1;
				return -ENOENT;
			}
			else {
				*sticky_cpdom = q0;
				return -ENOENT;
			}
		} else if (can_run_on_domain(ctx, q0)) {
			*sticky_cpdom = q0;
			return -ENOENT;
		} else if (can_run_on_domain(ctx, q1)) {
			*sticky_cpdom = q1;
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

	if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | ctx->sync_waker_cpu))
		return false;

	cpuc_waker = get_cpu_ctx_id(ctx->sync_waker_cpu);
	if (!cpuc_waker || scx_bpf_dsq_nr_queued(cpuc_waker->cpdom_id))
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

static
s32 pick_idle_cpu(struct pick_ctx *ctx, bool *is_idle)
{
	const struct cpumask *idle_cpumask = NULL, *idle_smtmask = NULL;
	struct cpdom_ctx *cpdc, *mig_cpdc;
	s32 cpu = -ENOENT, sticky_cpu;
	bool i_smt_empty;
	s64 sticky_cpdom = -ENOENT, mig_cpdom, nr_nbr, nuance;
	int i, j;

	/*
	 * At the high level, the idle CPU selection policy considers the
	 * following factors:
	 * 
	 * 1) Current active and overflow set: Stay on the current active and
	 *    overflow sets if a task can run on them.
	 * 
	 * 2) CPU preference order: If a task cannot run on the current active
	 *    or overflow set, extend the overflow set following the CPU
	 *    preference order (performance mode vs. power-save mode).
	 * 
	 * 3) CPU type vs. task type: If possible, try to run a task on the
	 *    matching CPU type (i.e., a big task on a big core vs. a little
	 *    task on a little core). If the matching CPUs are not active,
	 *    stay on the previous CPU.
	 * 
	 * 4) Fully idle CPU vs. partially idle CPU: Choose a fully idle CPU
	 *    over a partially idle CPU within the previous CPU's domain.
	 *
	 * 5) Synchronous wake-up: If the waker CPU is idle, stay on the waker
	 *    CPU when there is no other idle CPU in the sticky domain. It is
	 *    good for cache locality because the waker task hands over the CPU
	 *    to the wakee task for the further processing after finishing
	 *    its job.
	 * 
	 * 6) Minimize cross-domain migration: Before migrating to a neighbor
	 *    domain, try to find an (any) idle CPU on the current domain.
	 *    Migrate a task to another domain only when the current sticky
	 *    domain is relatively highly overloaded (i.e., stealee) and the
	 *    target domain is relatively under-loaded (i.e., stealer) and the
	 *    target domain has a fully idle core. Otherwise, stay on the
	 *    previous CPU for cache locality, hoping that the load imbalance
	 *    (if it exists) will be resolved by the load balancing mechanism.
	 */
	bpf_rcu_read_lock();

	/*
	 * If a task can run only on a single CPU (e.g., per-CPU kworker),
	 * we just go with that CPU and set the overflow set if needed.
	 * Note that do not extend the overflow set for a unpinned,
	 * non-migratable task since disabling task migration is temporary.
	 */
	if (!init_active_ovrflw_masks(ctx))
		goto err_out;
	if (is_pinned(ctx->p) || is_migration_disabled(ctx->p)) {
		cpu = ctx->prev_cpu;
		if (!bpf_cpumask_test_cpu(cpu, cast_mask(ctx->active))) {
			if (is_pinned(ctx->p))
				bpf_cpumask_test_and_set_cpu(cpu, ctx->ovrflw);
		}
		*is_idle = scx_bpf_test_and_clear_cpu_idle(cpu);
		goto unlock_out;
	}
	/* NOTE: Now task @p is not a per-CPU task. */

	/*
	 * If @p cannot run on either active or overflow set, extend the
	 * overflow set, respecting the cpu preference order.
	 */
	if (!init_ao_masks(ctx))
		goto err_out;
	if (ctx->a_empty && ctx->o_empty) {
		cpu = find_cpu_in(ctx->p->cpus_ptr, ctx->cpuc_cur);
		if (cpu >= 0) {
			bpf_cpumask_set_cpu(cpu, ctx->ovrflw);
			*is_idle = scx_bpf_test_and_clear_cpu_idle(cpu);
		}
		goto unlock_out;
	}
	/* NOTE: Now task @p can run on either active or overflow set. */

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
		cpu = cpumask_any_dsitribute(ctx);
		goto unlock_out;
	}
	/* NOTE: There is a sticky domain. */

	/*
	 * If there is no idle CPU, stay on the sticky CPU or domain.
	 */
	idle_cpumask = scx_bpf_get_idle_cpumask();
	if (!init_idle_i_mask(ctx, idle_cpumask))
		goto err_out;
	if (ctx->i_empty) {
		cpu = find_sticky_cpu_at_cpdom(ctx, sticky_cpu, sticky_cpdom);
		goto unlock_out;
	}
	/* NOTE: There is at least one idle CPU. */

	/*
	 * If SMT is enabled and the sticky CPU is fully idle, stay on it.
	 */
	if (is_smt_active) {
		idle_smtmask = scx_bpf_get_idle_smtmask();
		i_smt_empty = bpf_cpumask_empty(idle_smtmask);
	} else
		i_smt_empty = true;

	if (!i_smt_empty && sticky_cpu >= 0 &&
	    bpf_cpumask_test_cpu(sticky_cpu, idle_smtmask) &&
	    scx_bpf_test_and_clear_cpu_idle(sticky_cpu)) {
		cpu = sticky_cpu;
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * If SMT is enabled and there is a fully idle CPU
	 * in the sticky domain, stay on it.
	 */
	if (!i_smt_empty) {
		if (!init_idle_ato_masks(ctx, idle_smtmask))
			goto err_out;
		if (!ctx->ia_empty || !ctx->io_empty) {
			cpu = pick_idle_cpu_at_cpdom(ctx, sticky_cpdom,
				SCX_PICK_IDLE_CORE, is_idle);
			if (cpu >= 0)
				goto unlock_out;
		}
	}
	/* NOTE: There is no fully idle CPU in the sticky domain. */

	/*
	 * If the sticky CPU is (partially) idle, stay on it.
	 */
	if (sticky_cpu >= 0 && scx_bpf_test_and_clear_cpu_idle(sticky_cpu)) {
		cpu = sticky_cpu;
		*is_idle = true;
		goto unlock_out;
	}
	/* NOTE: The sticky CPU is not (even partially) idle. */

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
	 * If there is no idle CPU in the active and overflow set,
	 * stay on the sticky CPU or domain.
	 */
	if (!init_idle_ato_masks(ctx, ctx->i_mask))
		goto err_out;
	if (ctx->ia_empty && ctx->io_empty) {
		cpu = find_sticky_cpu_at_cpdom(ctx, sticky_cpu, sticky_cpdom);
		goto unlock_out;
	}
	/* NOTE: There is at least one idle CPU in either active or overflow set. */

	/*
	 * So far, it is confirmed that
	 *  1) There is no fully idle CPU in the sticky domain.
	 *  2) The sticky CPU or waker CPU is not idle.
	 *  3) But there is at least one idle CPU in active/overflow set.
	 *
	 * If there is a fully idle core in the system (i.e., !is_smt_empty),
	 * let's migrate a task to another domain when
	 *  1) The sticky domain is over-loaded (cpdc->is_stealee)
	 *  2) The target domain is under-loaded (mig_cpdc->is_stealer)
	 *     that has a fully idle core.
	 *
	 * Note that when a system is under-loaded, task donation works better
	 * than task stealing because DSQs are mostly empty (i.e., it is hard
	 * to steal from a DSQ).
	 */
	if (i_smt_empty || nr_cpdoms == 1)
		goto skip_fully_idle_neighbor;

	cpdc = MEMBER_VPTR(cpdom_ctxs, [sticky_cpdom]);
	if (!cpdc || !READ_ONCE(cpdc->is_stealee))
		goto skip_fully_idle_neighbor;

	nuance = bpf_get_prandom_u32();
	mig_cpdom = sticky_cpdom;
	for (i = 0; i < LAVD_CPDOM_MAX_DIST && cpdc; i++) {
		nr_nbr = min(cpdc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;
		for (j = 0; j < LAVD_CPDOM_MAX_NR; j++, nuance = mig_cpdom + 1) {
			if (j >= nr_nbr)
				break;
			mig_cpdom  = pick_any_bit(cpdc->neighbor_bits[i], nuance);
			if (mig_cpdom < 0)
				continue;

			mig_cpdc = MEMBER_VPTR(cpdom_ctxs, [mig_cpdom]);
			if (!mig_cpdc || !READ_ONCE(mig_cpdc->is_stealer))
				continue;

			cpu = pick_idle_cpu_at_cpdom(ctx, mig_cpdom, SCX_PICK_IDLE_CORE, is_idle);
			if (cpu >= 0) {
				/*
				 * If task donation is successful, mark the stealer
				 * and the stealee's job done. By marking done,
				 * those compute domains would not be involved in
				 * load balancing until the end of this round,
				 * so this helps gradual migration. It is racy
				 * in task stealings and donations, but we don't
				 * care because a slight over-migration does not matter.
				 */
				WRITE_ONCE(mig_cpdc->is_stealer, false);
				WRITE_ONCE(cpdc->is_stealee, false);
				sticky_cpdom = mig_cpdom;
				goto unlock_out;
			}
		}
	}
skip_fully_idle_neighbor:
	/* NOTE: There is no fully idle CPU in the neighboring domain,
	 * it is not worth migrating. So try to find any idle CPU from
	 * the sticky domain. */

	/*
	 * If there is an (partially) idle CPU in the sticky domain, stay on it.
	 * In the domain, search in the order of turbo, active, and overflow.
	 */
	cpu = pick_idle_cpu_at_cpdom(ctx, sticky_cpdom, 0, is_idle);
	if (cpu >= 0)
		goto unlock_out;
	/* NOTE: There is no even partially idle CPU in the sticky domain. */

	/*
	 * Instead of chasing a partially idle CPU in neighboring domains,
	 * let's stay on the previous CPU or the sticky domain for cache
	 * locality, hoping that the load imbalance (if it exists) will be
	 * resolved by the load balancing mechanism.
	 */
	if (can_run_on_cpu(ctx, ctx->prev_cpu)) {
		cpu = ctx->prev_cpu;
		sticky_cpdom = -ENOENT;
	}

	/*
	 * We should not reach here because there is an idle CPU in either
	 * active or overflow sets, but we failed find it. That is impossible.
	 */
err_out:
	cpu = -ENOENT;
unlock_out:
	if (idle_smtmask)
		scx_bpf_put_idle_cpumask(idle_smtmask);
	if (idle_cpumask)
		scx_bpf_put_idle_cpumask(idle_cpumask);
	bpf_rcu_read_unlock();

	if (sticky_cpdom < 0) {
		struct cpu_ctx *cpuc;
		cpuc = get_cpu_ctx_id(cpu >= 0 ? cpu : ctx->prev_cpu);
		if (cpuc)
			ctx->cpdom_id = cpuc->cpdom_id;
	} else
		ctx->cpdom_id = sticky_cpdom;
	return cpu;
}

static
s64 pick_proper_dsq(const struct task_struct *p, struct task_ctx *taskc,
		    s32 task_cpu, s32 *cpu, bool *is_idle)
{
	struct pick_ctx ictx = {
		.p = p,
		.taskc = taskc,
		.prev_cpu = task_cpu,
		.wake_flags = 0,
		.cpdom_id = -ENOMEM,
	};

	*cpu = pick_idle_cpu(&ictx, is_idle);
	return ictx.cpdom_id;
}
