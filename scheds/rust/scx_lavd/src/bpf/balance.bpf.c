/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
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
extern const volatile u64	lb_low_util_wall;

u64 __attribute__ ((noinline)) calc_mig_delta(u64 avg_load_invr, int nz_qlen,
					      u64 mig_delta_factor)
{
	/*
	 * Note that added "noinline" to make the verifier happy.
	 * When mig_delta_factor > 0, the user specified a fixed
	 * migration delta percentage; otherwise use the dynamic
	 * shift-based heuristic.
	 */
	if (mig_delta_factor > 0)
		return avg_load_invr * mig_delta_factor / LAVD_SCALE;
	if (nz_qlen >= sys_stat.nr_active_cpdoms)
		return avg_load_invr >> LAVD_CPDOM_MIG_SHIFT_OL;
	if (nz_qlen == 0)
		return avg_load_invr >> LAVD_CPDOM_MIG_SHIFT_UL;
	return avg_load_invr >> LAVD_CPDOM_MIG_SHIFT;
}

/*
 * Classify a single compute domain as stealer, stealee, or neutral.
 * Returns 1 if the domain became a stealee, 0 otherwise.
 * Marked noinline so the verifier analyses it separately from the
 * calling loop, keeping the jump complexity of the caller manageable.
 */
int __attribute__((noinline))
classify_cpdom(struct cpdom_ctx *cpdomc, u64 total_load_invr,
	       u64 total_cap_sum, int nz_qlen, u64 mig_delta_factor)
{
	u64 x_mig_delta = 0;
	u64 fair_share_invr = 0;
	u64 stealer_threshold = 0;
	u64 stealee_threshold = 0;

	if (!cpdomc)
		return 0;

	if (cpdomc->nr_active_cpus && total_cap_sum > 0) {
		fair_share_invr = total_load_invr *
			     cpdomc->cap_sum_active_cpus /
			     total_cap_sum;

		x_mig_delta = calc_mig_delta(
				fair_share_invr, nz_qlen,
				mig_delta_factor);

		stealer_threshold = fair_share_invr - x_mig_delta;
		stealee_threshold = fair_share_invr + x_mig_delta;
	}

	/*
	 * Under-loaded active domains become a stealer.
	 * Ingress budget = half the deficit below fair share.
	 */
	if (cpdomc->nr_active_cpus &&
	    cpdomc->load_invr <= stealer_threshold) {
		u64 stealer_budget = 0;

		if (fair_share_invr > cpdomc->load_invr)
			stealer_budget = (fair_share_invr -
					  cpdomc->load_invr) / 2;

		WRITE_ONCE(cpdomc->stealer_budget_invr, stealer_budget);
		WRITE_ONCE(cpdomc->stealee_budget_invr, 0);
		WRITE_ONCE(cpdomc->is_stealer, true);
		WRITE_ONCE(cpdomc->is_stealee, false);
		return 0;
	}

	/*
	 * Over-loaded or non-active domains become a stealee.
	 * Egress budget = half the excess above fair share.
	 * Skip domains with nothing to steal: a domain may appear
	 * overloaded due to running task utilization (avg_util_invr_sum)
	 * but have an empty DSQ — trying to steal from it would waste
	 * cycles and could cause oscillation.
	 */
	if (!cpdomc->nr_active_cpus ||
	    cpdomc->load_invr >= stealee_threshold) {
		u64 stealee_budget_invr = 0;

		if (cpdomc->qload_invr == 0)
			goto reset_role;

		if (cpdomc->load_invr > fair_share_invr)
			stealee_budget_invr = (cpdomc->load_invr -
					       fair_share_invr) / 2;

		if (!stealee_budget_invr)
			goto reset_role;

		WRITE_ONCE(cpdomc->stealee_budget_invr, stealee_budget_invr);
		WRITE_ONCE(cpdomc->stealer_budget_invr, 0);
		WRITE_ONCE(cpdomc->is_stealer, false);
		WRITE_ONCE(cpdomc->is_stealee, true);
		return 1;
	}

reset_role:
	WRITE_ONCE(cpdomc->stealee_budget_invr, 0);
	WRITE_ONCE(cpdomc->stealer_budget_invr, 0);
	WRITE_ONCE(cpdomc->is_stealer, false);
	WRITE_ONCE(cpdomc->is_stealee, false);
	return 0;
}

__weak
int plan_x_cpdom_migration(void)
{
	struct cpdom_ctx *cpdomc;
	u64 cpdom_id;
	u32 nr_stealee = 0;
	u64 max_avg_util_wall = 0;
	u64 util;
	u64 total_load_invr = 0;
	u64 total_cap_sum = 0;
	bool overflow_running = false;
	int nz_qlen = 0;

	/*
	 * Calculate load for each active compute domain.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		if (!cpdomc->nr_active_cpus) {
			if (cpdomc->cur_util_wall_sum > 0)
				overflow_running = true;
			continue;
		}

		util = (cpdomc->avg_util_wall_sum << LAVD_SHIFT) / cpdomc->nr_active_cpus;
		if ((util >> LAVD_SHIFT) > max_avg_util_wall)
			max_avg_util_wall = util >> LAVD_SHIFT;

		/*
		 * Domain load combines running load (avg_util_invr_sum)
		 * and queued load (qload_invr, tracked atomically via
		 * account/unaccount at enqueue/running).
		 */
		cpdomc->load_invr = cpdomc->avg_util_invr_sum +
				    cpdomc->qload_invr;
		total_load_invr += cpdomc->load_invr;
		total_cap_sum += cpdomc->cap_sum_active_cpus;

		if (cpdomc->qload_invr)
			nz_qlen++;
	}

	/*
	 * When the highest per-CPU utilization among all compute
	 * domains is below the low utilization threshold, there is
	 * no meaningful workload worth rebalancing across domains.
	 */
	if (lb_low_util_wall > 0 && max_avg_util_wall < lb_low_util_wall)
		goto reset_and_skip_lb;

	/*
	 * Classify stealer and stealee domains using per-domain
	 * capacity-proportional targets. Each domain's target is its
	 * fair share of total system load scaled by its capacity
	 * proportion.
	 */
	u64 mig_delta_factor = 0;
	if (mig_delta_pct > 0)
		mig_delta_factor = (mig_delta_pct << LAVD_SHIFT) / 100;

	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);

		nr_stealee += classify_cpdom(cpdomc, total_load_invr,
					     total_cap_sum, nz_qlen,
					     mig_delta_factor);
	}

	if (nr_stealee == 0 && !overflow_running)
		goto reset_and_skip_lb;

	sys_stat.nr_stealee = nr_stealee;

	return 0;

reset_and_skip_lb:
	if (sys_stat.nr_stealee > 0) {
		bpf_for(cpdom_id, 0, nr_cpdoms) {
			if (cpdom_id >= LAVD_CPDOM_MAX_NR)
				break;

			cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
			WRITE_ONCE(cpdomc->stealee_budget_invr, 0);
			WRITE_ONCE(cpdomc->stealer_budget_invr, 0);
			WRITE_ONCE(cpdomc->is_stealer, false);
			WRITE_ONCE(cpdomc->is_stealee, false);
		}
		sys_stat.nr_stealee = 0;
	}
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
	ret = scx_bpf_dsq_move_to_local(dsq_id, 0);

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

			if (READ_ONCE(cpdomc_pick->stealee_budget_invr) == 0)
				continue;

			dsq_id = pick_most_loaded_dsq(cpdomc_pick);

			/*
			 * Peek at the head task to get its size for
			 * budget accounting.
			 */
			u64 task_load = 0;
			struct task_struct *peek_p =
				__COMPAT_scx_bpf_dsq_peek(dsq_id);
			if (peek_p) {
				task_ctx *peek_taskc = get_task_ctx(peek_p);
				if (peek_taskc)
					task_load = task_load_metric(peek_taskc);
			}

			/*
			 * On success, decrement both egress and ingress
			 * budgets. The stealer stays active for the
			 * entire round. Budget exhaustion clears the
			 * is_stealee/is_stealer flags via the decrement
			 * helpers.
			 */
			if (consume_dsq(cpdomc_pick, dsq_id)) {
				decrement_stealee_budget(cpdomc_pick, task_load);
				decrement_stealer_budget(cpdomc, task_load);
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
	struct cpu_ctx *cpuc;
	u64 cpdom_turb_dsq_id;
	bool turbulent;
	struct dsq_entry dsqs[3];

	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_to_cpdom(cpdom_dsq_id)]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_to_cpdom(cpdom_dsq_id));
		return false;
	}

	cpdom_turb_dsq_id = cpdom_to_turb_dsq(dsq_to_cpdom(cpdom_dsq_id));

	/*
	 * Determine if this CPU is turbulent (high IRQ/steal time).
	 * Non-turbulent CPUs consume from all 3 DSQs.
	 * Turbulent CPUs only consume from the turbulent DSQ
	 * (which holds non-latency-critical tasks).
	 */
	cpuc = get_cpu_ctx();
	if (!cpuc)
		return false;
	turbulent = cpuc->lat_headroom < LAVD_LC_LATENCY_SENSITIVE_THRESH;

	/*
	 * If the current compute domain is a stealer, try to steal
	 * a task from any of stealee domains probabilistically.
	 */
	if (nr_cpdoms > 1 && READ_ONCE(cpdomc->is_stealer) &&
	    try_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	/*
	 * Collect eligible DSQs and consume in lowest-vtime-first order.
	 * Non-turbulent CPUs always see the cpdom DSQ. Turbulent CPUs
	 * also see it when it has more queued tasks than the turbulent
	 * DSQ (to prevent starvation) or when there are no steady CPUs
	 * to drain it.
	 */
	dsqs[0] = (struct dsq_entry){ cpu_dsq_id,       U64_MAX, use_per_cpu_dsq() };
	dsqs[1] = (struct dsq_entry){ cpdom_dsq_id,     U64_MAX, use_cpdom_dsq() &&
		(!turbulent ||
		 scx_bpf_dsq_nr_queued(cpdom_dsq_id) > scx_bpf_dsq_nr_queued(cpdom_turb_dsq_id) ||
		 cpdomc->nr_steady_cpus == 0) };
	dsqs[2] = (struct dsq_entry){ cpdom_turb_dsq_id, U64_MAX, use_cpdom_dsq() };

	if (dsqs[0].eligible)
		dsqs[0].vtime = peek_dsq_vtime(dsqs[0].dsq_id);
	if (dsqs[1].eligible)
		dsqs[1].vtime = peek_dsq_vtime(dsqs[1].dsq_id);
	if (dsqs[2].eligible)
		dsqs[2].vtime = peek_dsq_vtime(dsqs[2].dsq_id);

	sort_dsqs(&dsqs[0], &dsqs[1], &dsqs[2]);

	if (dsqs[0].eligible && consume_dsq(cpdomc, dsqs[0].dsq_id))
		return true;
	if (dsqs[1].eligible && consume_dsq(cpdomc, dsqs[1].dsq_id))
		return true;
	if (dsqs[2].eligible && consume_dsq(cpdomc, dsqs[2].dsq_id))
		return true;

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
