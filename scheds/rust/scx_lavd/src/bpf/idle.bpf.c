/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

static bool match_task_core_type(struct task_ctx *taskc,
				 struct cpu_ctx *cpuc_prev,
				 struct sys_stat *stat_cur)
{
	/*
	 * If a task is performance critical, it is better to run on a big core
	 * even paying some cost looking for a big core.
	 */
	if (is_perf_cri(taskc, stat_cur) && !cpuc_prev->big_core)
		return false;

	/*
	 * Otherwise, it doesn't matter where it runs.
	 */
	return true;
}

static __always_inline
bool could_run_on(struct task_struct *p, s32 cpu,
			 struct bpf_cpumask *a_cpumask,
			 struct bpf_cpumask *o_cpumask)
{
	bool ret;

	ret = bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
	      (bpf_cpumask_test_cpu(cpu, cast_mask(a_cpumask)) ||
	       bpf_cpumask_test_cpu(cpu, cast_mask(o_cpumask)));

	return ret;
}

static __always_inline
bool test_and_clear_cpu_idle(s32 cpu, const struct cpumask *idle_mask,
			     bool reserve_cpu)
{
	if (reserve_cpu)
		return scx_bpf_test_and_clear_cpu_idle(cpu);
	return bpf_cpumask_test_cpu(cpu, idle_mask);
}

static __always_inline
s32 find_idle_cpu_in(struct bpf_cpumask *cpumask,
		     const struct cpumask *idle_mask, bool reserve_cpu)
{
	s32 cpu_id;

	if (reserve_cpu) {
		/*
		 * Pick a fully idle core within a cpumask, then pick an
		 * any idle core if there is no.
		 */
		cpu_id = scx_bpf_pick_idle_cpu(cast_mask(cpumask), 0);
	} else {
		cpu_id = bpf_cpumask_any_and_distribute(cast_mask(cpumask), idle_mask);
		if (cpu_id >= nr_cpu_ids)
			cpu_id = -EBUSY;
	}

	return cpu_id;
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
	bpf_for(i, 0, nr_cpu_ids) {
		if (i >= LAVD_CPU_ID_MAX)
			break;

		cpu = cpu_order[i];
		if (bpf_cpumask_test_cpu(cpu, cast_mask(online_src_mask)))
			return cpu;
	};

	return -ENOENT;
}

static __always_inline
s32 find_idle_cpu(struct task_struct *p, struct task_ctx *taskc, s32 prev_cpu,
		  u64 wake_flags, bool reserve_cpu, bool *is_idle)
{
	struct sys_stat *stat_cur = get_sys_stat_cur();
	struct cpu_ctx *cpuc, *cpuc_prev, *cpuc_waker;
	struct bpf_cpumask *a_cpumask, *o_cpumask, *t_cpumask, *t2_cpumask;
	struct bpf_cpumask *active, *ovrflw, *big, *little;
	struct bpf_cpumask *cpdom_mask_prev, *cpdom_mask_waker;
	const struct cpumask *idle_mask;
	s32 cpu_id, waker_cpu;
	int cpdom_id;

	idle_mask = scx_bpf_get_idle_cpumask();

	/*
	 * If there is no idle cpu, stay on the previous cpu.
	 */
	if (!have_idle_cpus(idle_mask)) {
		cpu_id = prev_cpu;
		goto out;
	}

	/*
	 * If a task can run only on a single CPU (e.g., per-CPU kworker), we
	 * simply check if a task is still pinned on the prev_cpu and go.
	 */
	if (is_per_cpu_task(p) &&
	    bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		if (test_and_clear_cpu_idle(prev_cpu, idle_mask, reserve_cpu))
			*is_idle = true;
		cpu_id = prev_cpu;
		goto out;
	}

	/*
	 * Prepare cpumaks.
	 */
	bpf_rcu_read_lock();

	cpuc = get_cpu_ctx();
	cpuc_prev = get_cpu_ctx_id(prev_cpu);
	if (!cpuc || !cpuc_prev || !taskc) {
		scx_bpf_error("Failed to lookup the current cpu_ctx");
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	a_cpumask = cpuc->tmp_a_mask;
	o_cpumask = cpuc->tmp_o_mask;
	t_cpumask = cpuc->tmp_t_mask;
	t2_cpumask = cpuc->tmp_t2_mask;
	active  = active_cpumask;
	ovrflw  = ovrflw_cpumask;
	big = big_cpumask;
	little = little_cpumask;
	if (!a_cpumask || !o_cpumask || !t_cpumask || !t2_cpumask ||
	    !active || !ovrflw || !big || !little) {
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	cpdom_id = cpuc_prev->cpdom_id;
	cpdom_mask_prev = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
	if (!cpdom_mask_prev) {
		scx_bpf_error("Failed to lookup cpdom_cpumask for %d",
			      cpuc_prev->cpdom_id);
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	cpuc_waker = get_cpu_ctx();
	if (!cpuc_waker) {
		scx_bpf_error("Failed to lookup the current cpu_ctx");
		cpu_id = -ENOENT;
		goto unlock_out;
	}
	waker_cpu = cpuc_waker->cpu_id;

	cpdom_id = cpuc_waker->cpdom_id;
	cpdom_mask_waker = MEMBER_VPTR(cpdom_cpumask, [cpdom_id]);
	if (!cpdom_mask_waker) {
		scx_bpf_error("Failed to lookup cpdom_cpumask for %d",
			      cpuc_waker->cpdom_id);
		cpu_id = -ENOENT;
		goto unlock_out;
	}

	bpf_cpumask_and(a_cpumask, p->cpus_ptr, cast_mask(active));
	bpf_cpumask_and(o_cpumask, p->cpus_ptr, cast_mask(ovrflw));

	/*
	 * Try to stay on the previous core if it is on active or ovrfw.
	 */
	if (match_task_core_type(taskc, cpuc_prev, stat_cur) &&
	    could_run_on(p, prev_cpu, a_cpumask, o_cpumask) &&
	    test_and_clear_cpu_idle(prev_cpu, idle_mask, reserve_cpu)) {
		cpu_id = prev_cpu;
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Try to stay on the waker's core if it is on active or ovrfw.
	 */
	if (wake_flags & SCX_WAKE_SYNC && prev_cpu != waker_cpu &&
	    match_task_core_type(taskc, cpuc_waker, stat_cur) &&
	    could_run_on(p, waker_cpu, a_cpumask, o_cpumask) &&
	    test_and_clear_cpu_idle(waker_cpu, idle_mask, reserve_cpu)) {
		cpu_id = waker_cpu;
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Find cpumasks for a matching core type and LLC domain.
	 */
	if (bpf_cpumask_empty(cast_mask(a_cpumask)))
		goto start_omask;

	if (!have_little_core || is_perf_cri(taskc, stat_cur) || no_core_compaction) {
		bpf_cpumask_and(t_cpumask, cast_mask(a_cpumask), cast_mask(big));
	}
	else {
		bpf_cpumask_and(t_cpumask, cast_mask(a_cpumask), cast_mask(little));
		goto start_llc_mask;
	}

	/*
	 * Pick an idle core among turbo boost-enabled CPUs with a matching
	 * core type.
	 */
	if (!have_turbo_core || no_prefer_turbo_core || !turbo_cpumask)
		goto start_llc_mask;

	bpf_cpumask_and(t2_cpumask, cast_mask(t_cpumask), cast_mask(turbo_cpumask));
	if (bpf_cpumask_empty(cast_mask(t2_cpumask)))
		goto start_llc_mask;

	cpu_id = find_idle_cpu_in(t2_cpumask, idle_mask, reserve_cpu);
	if (cpu_id >= 0) {
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Pick an idle core among active CPUs with a matching core type within
	 * the prev CPU's LLC domain.
	 */
start_llc_mask:
	bpf_cpumask_and(t2_cpumask, cast_mask(t_cpumask), cast_mask(cpdom_mask_prev));
	if (bpf_cpumask_empty(cast_mask(t2_cpumask)))
		goto start_tmask;

	cpu_id = find_idle_cpu_in(t2_cpumask, idle_mask, reserve_cpu);
	if (cpu_id >= 0) {
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Pick an idle core among active CPUs with a matching core type within
	 * the waker CPU's LLC domain.
	 */
	if (wake_flags & SCX_WAKE_SYNC && prev_cpu != waker_cpu) {
		bpf_cpumask_and(t2_cpumask, cast_mask(t_cpumask), cast_mask(cpdom_mask_waker));
		if (bpf_cpumask_empty(cast_mask(t2_cpumask)))
			goto start_tmask;

		cpu_id = find_idle_cpu_in(t2_cpumask, idle_mask, reserve_cpu);
		if (cpu_id >= 0) {
			*is_idle = true;
			goto unlock_out;
		}
	}

	/*
	 * Pick an idle core among active CPUs with a matching core type.
	 */
start_tmask:
	if (have_little_core) {
		cpu_id = find_idle_cpu_in(t_cpumask, idle_mask, reserve_cpu);
		if (cpu_id >= 0) {
			*is_idle = true;
			goto unlock_out;
		}
	}

	/*
	 * Pick an idle core among active CPUs.
	 */
	cpu_id = find_idle_cpu_in(a_cpumask, idle_mask, reserve_cpu);
	if (cpu_id >= 0) {
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * Pick an any idle core among overflow CPUs.
	 */
start_omask:
	if (bpf_cpumask_empty(cast_mask(o_cpumask)))
		goto start_any_mask;

	cpu_id = find_idle_cpu_in(o_cpumask, idle_mask, reserve_cpu);
	if (cpu_id >= 0) {
		*is_idle = true;
		goto unlock_out;
	}

	/*
	 * If there is no idle core under our control, pick random core
	 * either in active or overflow CPUs.
	 */
	if (!bpf_cpumask_empty(cast_mask(a_cpumask))) {
		cpu_id = bpf_cpumask_any_distribute(cast_mask(a_cpumask));
		goto unlock_out;
	}

	if (!bpf_cpumask_empty(cast_mask(o_cpumask))) {
		cpu_id = bpf_cpumask_any_distribute(cast_mask(o_cpumask));
		goto unlock_out;
	}

	/*
	 * If the task cannot run on either active or overflow cores,
	 * extend the overflow set following the CPU preference order.
	 */
start_any_mask:
	cpu_id = find_cpu_in(p->cpus_ptr, cpuc);
	if (cpu_id >= 0) {
		if (test_and_clear_cpu_idle(cpu_id, idle_mask, reserve_cpu))
			*is_idle = true;
		bpf_cpumask_set_cpu(cpu_id, ovrflw);
		goto unlock_out;
	}

	/*
	 * If nothing works, stay on the previous core.
	 */
	cpu_id = prev_cpu;

unlock_out:
	bpf_rcu_read_unlock();

out:
	scx_bpf_put_idle_cpumask(idle_mask);
	return cpu_id;
}

