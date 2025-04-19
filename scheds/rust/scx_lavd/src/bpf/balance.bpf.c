/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

/*
 * To be included to the main.bpf.c
 */

static bool consume_dsq(u64 dsq_id)
{
	struct cpdom_ctx *cpdomc;

	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
		return false;
	}

	/*
	 * Try to consume a task on the associated DSQ.
	 */
	return scx_bpf_dsq_move_to_local(dsq_id);
}

static bool try_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	s64 nr_nbr, dsq_id;
	s64 nuance;

	/*
	 * If all CPUs are not used -- i.e., the system is under-utilized,
	 * there is no point of load balancing. It is better to make an
	 * effort to increase the system utilization.
	 */
	if (!use_full_cpus())
		return false;

	/*
	 * Probabilistically make a go or no go decision to avoid the
	 * thundering herd problem. In other words, one out of nr_cpus
	 * will try to steal a task at a moment.
	 */
	if (!prob_x_out_of_y(1, cpdomc->nr_cpus * LAVD_CPDOM_X_PROB_FT))
		return false;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	nuance = bpf_get_prandom_u32();
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbor in the same distance in arbitrary order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++, nuance = dsq_id + 1) {
			if (j >= nr_nbr)
				break;

			dsq_id = pick_any_bit(cpdomc->neighbor_bits[i], nuance);
			if (dsq_id < 0)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
				return false;
			}

			if (!cpdomc_pick->is_stealee || !cpdomc_pick->is_valid)
				continue;

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
			if (consume_dsq(dsq_id)) {
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
		if (!prob_x_out_of_y(1, LAVD_CPDOM_X_PROB_FT))
			break;
	}

	return false;
}

static bool force_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	s64 nr_nbr, dsq_id;
	s64 nuance;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	nuance = bpf_get_prandom_u32();
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbor in the same distance in arbitrary order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++, nuance = dsq_id + 1) {
			if (j >= nr_nbr)
				break;

			dsq_id = pick_any_bit(cpdomc->neighbor_bits[i], nuance);
			if (dsq_id < 0)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
				return false;
			}

			if (!cpdomc_pick->is_valid)
				continue;

			if (consume_dsq(dsq_id))
				return true;
		}
	}

	return false;
}

static bool consume_task(struct cpu_ctx *cpuc)
{
	struct cpdom_ctx *cpdomc;
	u64 dsq_id;

	dsq_id = cpuc->cpdom_id;
	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_id]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_id);
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
	 * Try to consume a task from CPU's associated DSQ.
	 */
	if (consume_dsq(dsq_id))
		return true;

	/*
	 * If there is no task in the assssociated DSQ, traverse neighbor
	 * compute domains in distance order -- task stealing.
	 */
	if (nr_cpdoms > 1 && force_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	return false;

	/*
	 * Task migration across compute domains happens.
	 */
x_domain_migration_out:
	return true;
}
