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
extern const volatile u8	no_fast_lb;
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
	       u64 total_cap_sum, u64 x_mig_delta)
{
	u64 fair_share_invr = 0;
	u64 stealer_threshold = 0;
	u64 stealee_threshold = 0;

	if (!cpdomc)
		return 0;

	if (no_fast_lb && sys_stat.nr_active_cpdoms) {
		u64 avg = total_load_invr / sys_stat.nr_active_cpdoms;
		stealer_threshold = avg - x_mig_delta;
		stealee_threshold = avg + x_mig_delta;
	} else if (cpdomc->nr_active_cpus && total_cap_sum > 0) {
		fair_share_invr = total_load_invr *
			     cpdomc->cap_sum_active_cpus /
			     total_cap_sum;
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
		debugln("load_balance: cpdom%llu becomes a stealer", cpdomc->id);
		return 0;
	}

	/*
	 * Over-loaded or non-active domains become a stealee.
	 * Egress budget = half the excess above fair share. Halving
	 * (rather than draining the full excess) avoids two failure
	 * modes:
	 * - Ping-pong: prevent overshooting. Moving everything in one
	 *   round may trigger the imbalance and ping-pong effect.
	 * - Thundering-herd: without a per-round limit, every stealer
	 *   that sees this domain can migrate out the tasks from it and
	 *   drain it past the fair share in a single round.
	 *
	 * Also skip domains with nothing to steal: a domain may appear
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
		debugln("load_balance: cpdom%llu becomes a stealee", cpdomc->id);
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
	u64 min_cap_sum = U64_MAX;
	u64 x_mig_delta = 0;
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
		if (no_fast_lb) {
			u64 qlen = cpdomc->nr_queued_task;
			u64 qlen_invr = (qlen << (LAVD_SHIFT * 3)) /
					cpdomc->cap_sum_active_cpus;
			cpdomc->load_invr = util + qlen_invr;
			if (qlen)
				nz_qlen++;
		} else {
			cpdomc->load_invr = cpdomc->avg_util_invr_sum +
					    cpdomc->qload_invr;
			if (cpdomc->qload_invr)
				nz_qlen++;
		}
		total_load_invr += cpdomc->load_invr;
		total_cap_sum += cpdomc->cap_sum_active_cpus;
		if (cpdomc->cap_sum_active_cpus < min_cap_sum)
			min_cap_sum = cpdomc->cap_sum_active_cpus;
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
	 *
	 * The band around the target is the same width for every domain:
	 * a fraction of the smallest active domain's fair share. The
	 * smallest domain bounds how much load can be out of place, so
	 * it sets the granularity of an imbalance. On a homogeneous
	 * machine every fair share is the smallest, so nothing changes
	 * there.
	 */
	u64 mig_delta_factor = 0;
	if (mig_delta_pct > 0)
		mig_delta_factor = (mig_delta_pct << LAVD_SHIFT) / 100;

	if (no_fast_lb && sys_stat.nr_active_cpdoms) {
		x_mig_delta = calc_mig_delta(
				total_load_invr / sys_stat.nr_active_cpdoms,
				nz_qlen, mig_delta_factor);
	} else if (total_cap_sum > 0 && min_cap_sum != U64_MAX) {
		x_mig_delta = calc_mig_delta(
				total_load_invr * min_cap_sum / total_cap_sum,
				nz_qlen, mig_delta_factor);
	}

	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);

		nr_stealee += classify_cpdom(cpdomc, total_load_invr,
					     total_cap_sum, x_mig_delta);
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

/*
 * Estimated completion time for a task, in wall-clock ns.
 *
 *   comp_time = wait + run
 *   wait      = queued_svc_invr             * LAVD_SCALE / cap_sum
 *   run       = task_svc_invr   * nr_cpus   * LAVD_SCALE / cap_sum
 *
 * Both inputs are invariant time -- time as it would elapse on a CPU of
 * capacity LAVD_SCALE -- so multiplying by LAVD_SCALE and dividing by the
 * summed capacity converts them to wall clock at the target's mean per-CPU
 * capacity, cap_sum / nr_cpus. @nr_cpus scales the run term because the queue
 * drains across every CPU while the task itself runs on one.
 *
 * The run term is optional. A caller passes @task_svc_invr as 0 for the wait
 * alone, when the question is how soon the task starts rather than when it
 * finishes, or when its service time is not known well enough to price.
 *
 * Two approximations, both over-estimates, so they largely cancel when the
 * result is used as a difference between two candidate targets:
 *   - the task is served last, ignoring its vtime position; that error grows
 *     with queue depth, biasing away from deep queues as desired;
 *   - it is not preempted once running.
 *
 * Returns LAVD_COMP_TIME_INF for a target with no capacity, so it never wins.
 *
 * Marked noinline so the verifier analyses it once as a subprogram instead of
 * inlining into lavd_select_cpu(), the heaviest program in the object.
 */
u64 __attribute__((noinline))
calc_comp_time(u64 task_svc_invr, u64 queued_svc_invr, u64 cap_sum, u64 nr_cpus)
{
	u64 svc_invr;

	if (unlikely(!cap_sum))
		return LAVD_COMP_TIME_INF;

	svc_invr = queued_svc_invr + (task_svc_invr * nr_cpus);

	return (svc_invr * LAVD_SCALE) / cap_sum;
}

/*
 * Estimated completion time for a task placed on @cpuc, in wall-clock ns: the
 * time to drain that CPU's queues and the task itself.
 *
 * Inclusive of @cpuc's local DSQ and its per-CPU DSQ -- qload_svc_invr already
 * carries both, since account_queued_load_pcpu() is called for either
 * destination.
 *
 * The per-CPU DSQ is per physical core: lavd_init() creates one only for the
 * primary sibling, and every writer charges qload_svc_invr through
 * get_primary_cpu(). So read the queue from the primary -- a secondary
 * sibling, which no writer ever charges, would otherwise report an empty queue
 * forever -- and count both siblings in the drain rate, since both consume
 * that DSQ. Each sibling counts as a full core here, as it does everywhere
 * else in lavd's capacity model.
 *
 * Summing the two capacities halves the wait term while leaving the run term
 * unchanged, @nr_cpus scaling it back: the queue drains on two threads, the
 * task runs on one.
 *
 * No residual for the task already running, as with calc_comp_time_on_cpdom(),
 * so the two stay comparable; a caller that wants a wall-clock wait adds
 * calc_residual_time() itself.
 */
__hidden __attribute__((noinline))
u64 calc_comp_time_on_cpu(u64 task_svc_invr, struct cpu_ctx *cpuc)
{
	struct cpu_ctx *primary_cpuc = cpuc, *sibling_cpuc;
	u64 cap_sum = READ_ONCE(cpuc->effective_capacity);
	u64 nr_cpus = 1;
	u32 cpu = cpuc->cpu_id, sib;

	sib = get_sibling_cpu(cpu);
	if (sib != cpu) {
		sibling_cpuc = get_cpu_ctx_id(sib);
		if (unlikely(!sibling_cpuc))
			return LAVD_COMP_TIME_INF;
		/*
		 * An offline sibling drains nothing. The queue may still live
		 * on its ctx, though: writers charge get_primary_cpu() whether
		 * or not that CPU is online, so the redirect below stays.
		 */
		if (sibling_cpuc->is_online) {
			cap_sum += READ_ONCE(sibling_cpuc->effective_capacity);
			nr_cpus = 2;
		}
		/*
		 * Ask get_primary_cpu() rather than re-deriving the rule: if
		 * @cpu is not the primary, its sibling is, and that is the
		 * ctx every writer charges.
		 */
		if (get_primary_cpu(cpu) != cpu)
			primary_cpuc = sibling_cpuc;
	}

	return calc_comp_time(task_svc_invr, primary_cpuc->qload_svc_invr,
			      cap_sum, nr_cpus);
}

/*
 * Estimated completion time for a task dispatched straight to @cpuc's local
 * DSQ, in wall-clock ns.
 *
 * Inclusive of everything already queued on that local DSQ. This is the
 * innermost level, so there is nothing beneath it. No residual, like the other
 * entry points; a caller that wants a wall-clock wait adds calc_residual_time().
 */
__hidden __attribute__((noinline))
u64 calc_comp_time_on_local(u64 task_svc_invr, struct cpu_ctx *cpuc)
{
	return calc_comp_time(task_svc_invr, cpuc->qload_svc_local_invr,
			      READ_ONCE(cpuc->effective_capacity), 1);
}

/*
 * Estimated completion time for a task placed in @cpdomc.
 *
 * Inclusive of every task queued anywhere in the domain -- local, per-CPU and
 * cpdom DSQs alike -- because all of them compete for the domain's CPUs.
 * account_queued_load() runs unconditionally at the end of the enqueue path, so
 * qload_svc_invr already carries all three.
 *
 * No residual for tasks already running. A domain has many of them and no
 * single one to read, so any residual would be a statistic. Hence, when
 * comparing against a domain's completion time, the other side must not
 * include its residual either, to be fair.
 *
 * The domain's two DSQs are collapsed into one logical queue, and the drain
 * rate is the whole domain to match: qload_svc_invr counts the tasks queued in
 * both, so charging only the steady CPUs would bill them for work the
 * turbulent ones actually serve.
 *
 * Collapsing them is a fair approximation because the queues are not
 * independent. Steady CPUs drain the turbulent DSQ, and
 * can_consume_steady_dsq() lets a turbulent CPU reach into the steady one to
 * prevent starvation, so the split is a routing preference rather than a
 * partition. Accounting the two loads separately would not make the wait
 * predictable, only the accounting more expensive.
 */
u64 __attribute__((noinline))
calc_comp_time_on_cpdom(u64 task_svc_invr, struct cpdom_ctx *cpdomc)
{
	u64 cap_sum, nr_cpus;

	if (unlikely(!cpdomc))
		return LAVD_COMP_TIME_INF;

	cap_sum = (u64)cpdomc->cap_sum_active_cpus +
		  cpdomc->cap_sum_overflow_cpus;
	nr_cpus = (u64)cpdomc->nr_active_cpus +
		  cpdomc->nr_overflow_cpus;

	return calc_comp_time(task_svc_invr, cpdomc->qload_svc_invr,
			      cap_sum, nr_cpus);
}

u64 __attribute__((noinline)) dsq_peek_task_load(u64 dsq_id)
{
	struct task_struct *peek_p = __COMPAT_scx_bpf_dsq_peek(dsq_id);

	if (peek_p) {
		task_ctx *peek_taskc = get_task_ctx(peek_p);
		if (peek_taskc)
			return task_load_metric(peek_taskc);
	}
	return 0;
}

u64 __attribute__((noinline)) pick_most_loaded_dsq(struct cpdom_ctx *cpdomc)
{
	u64 pick_dsq_id = -ENOENT;
	u64 highest_load = 0;

	if (!cpdomc) {
		scx_bpf_error("Invalid cpdom context");
		return -ENOENT;
	}

	/*
	 * Pick the (per-CPU or per-domain) DSQ in this compute domain
	 * with the highest RAVG-weighted queued load.
	 */
	if (use_cpdom_dsq()) {
		pick_dsq_id = cpdom_to_dsq(cpdomc->id);
		if (no_fast_lb)
			highest_load = scx_bpf_dsq_nr_queued(pick_dsq_id);
		else
			highest_load = READ_ONCE(cpdomc->qload_invr);
	}

	/*
	 * When tasks on a per-CPU DSQ are not migratable
	 * (e.g., pinned_slice_ns is on but per_cpu_dsq is not),
	 * there is no need to check per-CPU DSQs.
	 */
	if (is_per_cpu_dsq_migratable()) {
		int pick_cpu = -ENOENT, cpu, i, j, k;

		bpf_for(i, 0, LAVD_CPU_ID_MAX/64) {
			u64 cpumask;
			if ((u32)i * 64 >= nr_cpu_ids)
				break;
			cpumask = cpdomc->__cpumask[i];
			bpf_for(k, 0, 64) {
				u64 load;

				j = cpumask_next_set_bit(&cpumask);
				if (j < 0)
					break;
				cpu = (i * 64) + j;
				if (cpu >= nr_cpu_ids)
					break;

				if (no_fast_lb) {
					load = scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu)) +
					       scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
				} else {
					struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
					load = cpuc ? READ_ONCE(cpuc->qload_invr) : 0;
				}
				if (load > highest_load) {
					highest_load = load;
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

	if (no_fast_lb &&
	    !prob_x_out_of_y(1, cpdomc->nr_active_cpus * LAVD_CPDOM_MIG_PROB_FT))
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

			if (READ_ONCE(cpdomc_pick->stealee_budget_invr) <= 0)
				continue;

			dsq_id = pick_most_loaded_dsq(cpdomc_pick);

			/*
			 * No DSQ in cpdomc_pick has any queued load.
			 * Move on to the next neighbor rather than passing
			 * -ENOENT to dsq_peek_task_load() / consume_dsq(),
			 * which would abort the scheduler.
			 */
			if ((s64)dsq_id < 0)
				continue;

			/*
			 * Peek at the head task to get its size for budget
			 * accounting. Skip the peek when no_fast_lb is set
			 * since the budget path below is bypassed and the
			 * value would be unused.
			 *
			 * TOCTOU: the task peeked here may not be the one
			 * actually consumed by consume_dsq() below. To be more
			 * specific, another CPU may grab the head first, or the
			 * task may become ineligible during the window between
			 * the peek and the consume_dsq. The budget is just a
			 * hint, and over-debiting will be self-corrected
			 * because the next LB round recomputes budgets from
			 * scratch.
			 */
			u64 task_load = no_fast_lb ? 0 : dsq_peek_task_load(dsq_id);

			/*
			 * On success, decrement both egress and ingress
			 * budgets. The stealer stays active for the
			 * entire round. Budget exhaustion clears the
			 * is_stealee/is_stealer flags via the decrement
			 * helpers.
			 */
			if (consume_dsq(cpdomc_pick, dsq_id)) {
				if (no_fast_lb) {
					WRITE_ONCE(cpdomc_pick->is_stealee, false);
					WRITE_ONCE(cpdomc->is_stealer, false);
				} else {
					decrement_stealee_budget(cpdomc_pick, task_load);
					decrement_stealer_budget(cpdomc, task_load);
				}
				debugln("migrate: try_steal stealer=cpdom%llu stealee=cpdom%llu load=%llu cpu=%d",
					cpdomc->id, cpdomc_pick->id, task_load,
					bpf_get_smp_processor_id());
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
			/*
			 * Same defensive check as the try_to_steal_task
			 * path above.
			 */
			if ((s64)dsq_id < 0)
				continue;

			/*
			 * Peek at the head task to get its size. Skip the
			 * peek when no_fast_lb is set since the budget
			 * accounting below is bypassed and the value would
			 * be unused.
			 */
			u64 task_load = no_fast_lb ? 0 : dsq_peek_task_load(dsq_id);

			/*
			 * Force steal is unconditional for work
			 * conservation. Decrement budgets to keep
			 * the accounting consistent.
			 */
			if (consume_dsq(cpdomc_pick, dsq_id)) {
				if (!no_fast_lb) {
					decrement_stealee_budget(cpdomc_pick, task_load);
					decrement_stealer_budget(cpdomc, task_load);
				}
				debugln("migrate: force_steal stealer=cpdom%llu stealee=cpdom%llu load=%llu cpu=%d",
					cpdomc->id, cpdomc_pick->id, task_load,
					bpf_get_smp_processor_id());
				return true;
			}
		}
	}

	return false;
}

__hidden
bool consume_task(u64 cpdom_id)
{
	struct cpdom_ctx *cpdomc;
	struct cpu_ctx *cpuc;
	u64 cpu_dsq_id, cpdom_dsq_id, cpdom_turb_dsq_id;
	struct dsq_entry dsqs[3];
	int i;

	cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", cpdom_id);
		return false;
	}

	cpuc = get_cpu_ctx();
	if (!cpuc) {
		return false;
	}

	cpu_dsq_id        = cpu_to_dsq(cpuc->cpu_id);
	cpdom_dsq_id      = cpdom_to_dsq(cpdom_id);
	cpdom_turb_dsq_id = cpdom_to_turb_dsq(cpdom_id);

	/*
	 * If the current compute domain is a stealer, try to steal
	 * a task from any of stealee domains probabilistically.
	 */
	if (nr_cpdoms > 1 && READ_ONCE(cpdomc->is_stealer) &&
	    try_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	/*
	 * Collect the DSQs this CPU may consume and take them in
	 * lowest-vtime-first order. Each entry is seeded with its head-task
	 * vtime, or U64_MAX when this CPU should not consume it (sorts last
	 * and is skipped). can_consume_steady_dsq() gates the steady cpdom
	 * DSQ on the steady/turbulent policy.
	 */
	dsqs[0] = (struct dsq_entry){
			cpu_dsq_id,
			use_per_cpu_dsq() ?
				peek_dsq_vtime(cpu_dsq_id) : U64_MAX };
	dsqs[1] = (struct dsq_entry){
			cpdom_dsq_id,
			(use_cpdom_dsq() && can_consume_steady_dsq(cpdomc)) ?
				peek_dsq_vtime(cpdom_dsq_id) : U64_MAX };
	dsqs[2] = (struct dsq_entry){
			cpdom_turb_dsq_id,
			use_cpdom_dsq() ?
				peek_dsq_vtime(cpdom_turb_dsq_id) : U64_MAX };

	sort_dsqs(&dsqs[0], &dsqs[1], &dsqs[2]);

	/* Consume in lowest-vtime-first order; U64_MAX vtime marks skip. */
	for (i = 0; i < 3; i++) {
		if (dsqs[i].vtime != U64_MAX &&
		    consume_dsq(cpdomc, dsqs[i].dsq_id)) {
			return true;
		}
	}

	/*
	 * If there is no task in the associated DSQ, traverse neighbor
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
