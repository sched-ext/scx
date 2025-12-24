/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <lib/cgroup.h>


extern const volatile u8	mig_delta_pct;

u64 __attribute__ ((noinline)) calc_mig_delta(u64 avg_sc_load, int nz_qlen)
{
	/*
	 * Note that added "noinline" to make the verifier happy.
	 */
	if (nz_qlen >= sys_stat.nr_active_cpdoms)
		return avg_sc_load >> LAVD_CPDOM_MIG_SHIFT_OL;
	if (nz_qlen == 0)
		return avg_sc_load >> LAVD_CPDOM_MIG_SHIFT_UL;
	return avg_sc_load >> LAVD_CPDOM_MIG_SHIFT;
}

__weak
int plan_x_cpdom_migration(void)
{
	struct cpdom_ctx *cpdomc;
	u64 cpdom_id;
	u32 stealer_threshold, stealee_threshold, nr_stealee = 0;
	u64 avg_sc_load = 0, min_sc_load = U64_MAX, max_sc_load = 0;
	u64 x_mig_delta, util, qlen, sc_qlen;
	bool overflow_running = false;
	int nz_qlen = 0;

	/*
	 * The load balancing aims for two goals:
	 *
	 * 1) The *non-scaled* CPU utilizations of all active CPUs should be
	 * the same or similar. This helps to maintain low latency
	 * when the system is underloaded.
	 *
	 * 2) The *scaled* queue lengths of active compute domains should be
	 * the same or similar. Using scaled queue length allows putting more
	 * tasks to the powerful compute domains. This helps to maintain high
	 * throughput when the system is overloaded.
	 */

	/*
	 * Calculate scaled load for each active compute domain.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		if (!cpdomc->nr_active_cpus) {
			/*
			 * If tasks are running on an overflow domain,
			 * need load balancing.
			 */
			if (cpdomc->cur_util_sum > 0) {
				overflow_running = true;
				cpdomc->sc_load = U32_MAX;
			}
			else
				cpdomc->sc_load = 0;
			continue;
		}

		/*
		 * Use avg_util_sum when mig_delta_pct is set, otherwise use cur_util_sum.
		 */
		if (mig_delta_pct > 0)
			util = (cpdomc->avg_util_sum << LAVD_SHIFT) / cpdomc->nr_active_cpus;
		else
			util = (cpdomc->cur_util_sum << LAVD_SHIFT) / cpdomc->nr_active_cpus;
		qlen = cpdomc->nr_queued_task;
		sc_qlen = (qlen << (LAVD_SHIFT * 3)) / cpdomc->cap_sum_active_cpus;
		cpdomc->sc_load = util + sc_qlen;
		avg_sc_load += cpdomc->sc_load;

		if (min_sc_load > cpdomc->sc_load)
			min_sc_load = cpdomc->sc_load;
		if (max_sc_load < cpdomc->sc_load)
			max_sc_load = cpdomc->sc_load;
		if (qlen)
			nz_qlen++;
	}
	if (sys_stat.nr_active_cpdoms)
		avg_sc_load /= sys_stat.nr_active_cpdoms;

	/*
	 * Determine the criteria for stealer and stealee domains.
	 * The more the system is loaded, the tighter criteria will be chosen.
	 * When mig_delta_pct is set (non-zero), use it as a fixed percentage
	 * instead of the dynamic calculation.
	 */
	if (mig_delta_pct > 0) {
		u64 mig_delta_factor = (mig_delta_pct << LAVD_SHIFT) / 100;
		x_mig_delta = avg_sc_load * mig_delta_factor / LAVD_SCALE;
	} else {
		x_mig_delta = calc_mig_delta(avg_sc_load, nz_qlen);
	}
	stealer_threshold = avg_sc_load - x_mig_delta;
	stealee_threshold = avg_sc_load + x_mig_delta;

	if ((stealee_threshold > max_sc_load) && !overflow_running) {
		/*
		 * If there is no overloaded domain, do not try to steal.
		 *  <~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>
		 * [stealer_threshold ... avg_sc_load ... max_sc_load ... stealee_threshold]
		 *            -------------------------------------->
		 */
		return 0;
	}
	if ((stealee_threshold <= max_sc_load || overflow_running) &&
	    (stealer_threshold < min_sc_load)) {
		/*
		 * If there is a overloaded domain, always try to steal.
		 *  <~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>
		 * [stealer_threshold ... min_sc_load ... avg_sc_load ... stealee_threshold ... max_sc_load]
		 *                        <--------------------------------------------------------------->
		 */
		stealer_threshold = min_sc_load;
	}

	/*
	 * Determine stealer and stealee domains.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);

		/*
		 * Under-loaded active domains become a stealer.
		 */
		if (cpdomc->nr_active_cpus &&
		    cpdomc->sc_load <= stealer_threshold) {
			WRITE_ONCE(cpdomc->is_stealer, true);
			WRITE_ONCE(cpdomc->is_stealee, false);
			continue;
		}

		/*
		 * Over-loaded or non-active domains become a stealee.
		 */
		if (!cpdomc->nr_active_cpus ||
		    cpdomc->sc_load >= stealee_threshold) {
			WRITE_ONCE(cpdomc->is_stealer, false);
			WRITE_ONCE(cpdomc->is_stealee, true);
			nr_stealee++;
			continue;
		}

		/*
		 * Otherwise, keep tasks as it is.
		 */
		WRITE_ONCE(cpdomc->is_stealer, false);
		WRITE_ONCE(cpdomc->is_stealee, false);
	}

	sys_stat.nr_stealee = nr_stealee;

	return 0;
}

/*
 * dsq_id: candidate DSQ to consume from, can be per-cpdom or per-cpu.
 */
static bool consume_dsq(struct cpdom_ctx *cpdomc, u64 dsq_id)
{
	bool ret;
	u64 before = 0;

	if (is_monitored)
		before = bpf_ktime_get_ns();
	/*
	 * Try to consume a task on the associated DSQ.
	 */
	ret = scx_bpf_dsq_move_to_local(dsq_id);

	if (is_monitored)
		cpdomc->dsq_consume_lat = time_delta(bpf_ktime_get_ns(), before);

	return ret;
}

u64 __attribute__((noinline)) pick_most_loaded_dsq(struct cpdom_ctx *cpdomc)
{
	u64 pick_dsq_id = -ENOENT;
	s32 highest_queued = -1;

	if (!cpdomc) {
		scx_bpf_error("Invalid cpdom context");
		return -ENOENT;
	}

	/*
	 * For simplicity, try to just steal from the (either per-CPU or
	 * per-domain) DSQs with the highest number of queued_tasks
	 * in this domain.
	 */
	if (use_cpdom_dsq()) {
		pick_dsq_id = cpdom_to_dsq(cpdomc->id);
		highest_queued = scx_bpf_dsq_nr_queued(pick_dsq_id);
	}

	/*
	 * When tasks on a per-CPU DSQ are not migratable
	 * (e.g., pinned_slice_ns is on but per_cpu_dsq is not),
	 * there is no need to check per-CPU DSQs.
	 */
	if (is_per_cpu_dsq_migratable()) {
		int pick_cpu = -ENOENT, cpu, i, j, k;

		bpf_for(i, 0, LAVD_CPU_ID_MAX/64) {
			u64 cpumask = cpdomc->__cpumask[i];
			bpf_for(k, 0, 64) {
				s32 queued;
				j = cpumask_next_set_bit(&cpumask);
				if (j < 0)
					break;
				cpu = (i * 64) + j;
				if (cpu >= nr_cpu_ids)
					break;
				queued = scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu)) +
					 scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
				if (queued > highest_queued) {
					highest_queued = queued;
					pick_cpu = cpu;
				}
			}
		}

		if (pick_cpu != -ENOENT)
			pick_dsq_id = cpu_to_dsq(pick_cpu);
	}

	return pick_dsq_id;
}

static bool try_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	s64 nr_nbr, cpdom_id;

	/*
	 * Only active domains steal the tasks from other domains.
	 */
	if (!cpdomc->nr_active_cpus)
		return false;

	/*
	 * Probabilistically make a go or no go decision to avoid the
	 * thundering herd problem. In other words, one out of nr_cpus
	 * will try to steal a task at a moment.
	 */
	if (!prob_x_out_of_y(1, cpdomc->nr_active_cpus * LAVD_CPDOM_MIG_PROB_FT))
		return false;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbors in the same distance in circular distance order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++) {
			u64 dsq_id;
			if (j >= nr_nbr)
				break;

			cpdom_id = get_neighbor_id(cpdomc, i, j);
			if (cpdom_id < 0)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", cpdom_id);
				return false;
			}

			if (!READ_ONCE(cpdomc_pick->is_stealee) || !cpdomc_pick->is_valid)
				continue;

			dsq_id = pick_most_loaded_dsq(cpdomc_pick);

			/*
			 * If task stealing is successful, mark the stealer
			 * and the stealee's job done. By marking done,
			 * those compute domains would not be involved in
			 * load balancing until the end of this round,
			 * so this helps gradual migration. Note that multiple
			 * stealers can steal tasks from the same stealee.
			 * However, we don't coordinate concurrent stealing
			 * because the chance is low and there is no harm
			 * in slight over-stealing.
			 */
			if (consume_dsq(cpdomc_pick, dsq_id)) {
				WRITE_ONCE(cpdomc_pick->is_stealee, false);
				WRITE_ONCE(cpdomc->is_stealer, false);
				return true;
			}
		}

		/*
		 * Now, we need to steal a task from a farther neighbor
		 * for load balancing. Since task migration from a farther
		 * neighbor is more expensive (e.g., crossing a NUMA boundary),
		 * we will do this with a lot of hesitation. The chance of
		 * further migration will decrease exponentially as distance
		 * increases, so, on the other hand, it increases the chance
		 * of closer migration.
		 */
		if (!prob_x_out_of_y(1, LAVD_CPDOM_MIG_PROB_FT))
			break;
	}

	return false;
}

static bool force_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	s64 nr_nbr, cpdom_id;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbors in the same distance in circular distance order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++) {
			u64 dsq_id;
			if (j >= nr_nbr)
				break;

			cpdom_id = get_neighbor_id(cpdomc, i, j);
			if (cpdom_id < 0)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", cpdom_id);
				return false;
			}

			if (!cpdomc_pick->is_valid)
				continue;

			dsq_id = pick_most_loaded_dsq(cpdomc_pick);

			if (consume_dsq(cpdomc_pick, dsq_id))
				return true;
		}
	}

	return false;
}

__hidden
bool consume_task(u64 cpu_dsq_id, u64 cpdom_dsq_id)
{
	struct cpdom_ctx *cpdomc;
	struct task_struct *p;
	u64 vtime = U64_MAX;

	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_to_cpdom(cpdom_dsq_id)]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_to_cpdom(cpdom_dsq_id));
		return false;
	}

	/*
	 * If the current compute domain is a stealer, try to steal
	 * a task from any of stealee domains probabilistically.
	 */
	if (nr_cpdoms > 1 && READ_ONCE(cpdomc->is_stealer) &&
	    try_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	/*
	 * When per_cpu_dsq or pinned_slice_ns is enabled, compare vtimes
	 * across cpu_dsq and cpdom_dsq to select the task with the lowest vtime.
	 */
	if (use_per_cpu_dsq() && use_cpdom_dsq()) {
		u64 dsq_id = cpu_dsq_id;
		u64 backup_dsq_id = cpdom_dsq_id;

		p = __COMPAT_scx_bpf_dsq_peek(cpu_dsq_id);
		if (p)
			vtime = p->scx.dsq_vtime;

		p = __COMPAT_scx_bpf_dsq_peek(cpdom_dsq_id);
		if (p && p->scx.dsq_vtime < vtime) {
			dsq_id = cpdom_dsq_id;
			backup_dsq_id = cpu_dsq_id;
		}

		/*
		 * There is a scenario where the task on the Cpdom DSQ has a
		 * lower vtime, but this CPU fails to win the race and causes
		 * the pinned task to stall and wait on the Per-CPU DSQ for the
		 * next scheduling round. Always try consuming from the other DSQ
		 * to prevent this scenario.
		 */
		if (consume_dsq(cpdomc, dsq_id))
			return true;
		if (consume_dsq(cpdomc, backup_dsq_id))
			return true;
	} else if (use_cpdom_dsq()) {
		if (consume_dsq(cpdomc, cpdom_dsq_id))
			return true;
	} else if (use_per_cpu_dsq()) {
		if (consume_dsq(cpdomc, cpu_dsq_id))
			return true;
	}

	/*
	 * If there is no task in the assssociated DSQ, traverse neighbor
	 * compute domains in distance order -- task stealing.
	 * Skip force stealing when mig_delta_pct is set (> 0) to rely
	 * only on the is_stealer/is_stealee thresholds.
	 */
	if (nr_cpdoms > 1 && mig_delta_pct == 0 && force_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	return false;

	/*
	 * Task migration across compute domains happens.
	 */
x_domain_migration_out:
	return true;
}
