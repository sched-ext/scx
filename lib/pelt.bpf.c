/*
 * SPDX-License-Identifier: GPL-2.0
 * Author: Cheng-Yang Chou <yphbchou0911@gmail.com>
 */

/*
 * This design is heavily inspired by `[RFC PATCH 0/1] sched/pelt: Change PELT
 * halflife at runtime` [1].
 * [1]: https://lore.kernel.org/all/20220829055450.1703092-1-dietmar.eggemann@arm.com/
 */

#include <scx/common.bpf.h>
#include <lib/pelt.h>

/*
 * pelt_do_accumulate_sum - accumulate elapsed time into *_sum fields
 * @delta: elapsed time in 1024us units, already stretched by lshift
 * @prq: PELT state to update
 * @load: load weight (0 if task is not on rq)
 * @runnable: runnable weight (0 if not runnable)
 * @running: 1 if the CPU is executing a task, 0 otherwise
 *
 * Returns the number of full 1024us periods crossed, or 0 if no
 * period boundary was reached.
 *
 * Corresponds to accumulate_sum() in kernel/sched/pelt.c.
 */
static __always_inline u32
pelt_do_accumulate_sum(u64 delta, struct pelt_rq *prq,
		       unsigned long load, unsigned long runnable, int running)
{
	/*
	 * When no full period has elapsed, @delta itself is the contribution.
	 * This is overwritten below if we do cross a period boundary.
	 */
	u32 contrib = (u32)delta;
	u64 periods;

	delta += prq->period_contrib;
	periods = delta / 1024;

	/*
	 * Step 1: decay existing sums across any full periods that elapsed.
	 */
	if (periods) {
		prq->load_sum = pelt_decay_load(prq->load_sum, periods);
		prq->runnable_sum = pelt_decay_load(prq->runnable_sum, periods);
		prq->util_sum = (u32)pelt_decay_load((u64)prq->util_sum, periods);

		/*
		 * Step 2: accumulate d1 (tail of previous period), d2 (full
		 * middle periods), and d3 (head of current period). Only
		 * needed when there is a load contribution.
		 */
		delta %= 1024;
		if (load)
			contrib = pelt_accumulate_segments(periods,
					1024 - prq->period_contrib, (u32)delta);
	}
	prq->period_contrib = (u32)(delta % 1024);

	if (load)
		prq->load_sum += load * contrib;
	if (runnable)
		prq->runnable_sum += (u64)runnable * contrib << PELT_CAPACITY_SHIFT;
	if (running)
		prq->util_sum += contrib << PELT_CAPACITY_SHIFT;

	return (u32)periods;
}

/*
 * pelt_update - update PELT state for a CPU
 * @prq: PELT state to update
 * @now: current time from bpf_ktime_get_ns()
 * @load: load weight (0 if task is not on rq)
 * @runnable: runnable weight (0 if not runnable)
 * @running: 1 if the CPU is executing a task, 0 otherwise
 * @lshift: half-life control; 0 = 32ms (standard), 1 = 16ms, 2 = 8ms (PELT_LSHIFT_MAX)
 *
 * Must be called from ops.running() with running=1, from ops.stopping() with
 * running=0, and periodically from ops.tick() to keep the signal fresh when
 * the CPU is idle.
 *
 * After returning 1 the caller can read prq->util_avg, prq->runnable_avg,
 * and prq->load_avg. Returns 0 if no period boundary was crossed (averages
 * unchanged) or if time moved backwards.
 *
 * Corresponds to ___update_load_sum() + ___update_load_avg() in
 * kernel/sched/pelt.c.
 */
__weak
int pelt_update(struct pelt_rq *prq, u64 now, unsigned long load,
		unsigned long runnable, int running)
{
	u64 delta;
	u32 divider, lshift;

	if (!prq)
		return 0;

	lshift = prq->lshift;
	delta = now - prq->last_update_time;
	/*
	 * Protect against time going backwards.
	 */
	if ((s64)delta < 0) {
		prq->last_update_time = now;
		return 0;
	}

	/*
	 * Convert nanoseconds to 1024ns units (~1us). Advance last_update_time
	 * by the aligned delta so residual nanoseconds are rolled forward on
	 * the next call, exactly as the kernel does.
	 */
	delta >>= 10;
	if (!delta)
		return 0;

	prq->last_update_time += delta << 10;

	/*
	 * Stretch time to shorten the effective half-life. lshift=1 doubles
	 * the apparent elapsed time, halving the half-life to 16ms; lshift=2
	 * quadruples it, giving an 8ms half-life.
	 */
	delta <<= lshift;

	/*
	 * A task with zero load cannot be runnable or running.
	 */
	if (!load)
		runnable = running = 0;

	if (!pelt_do_accumulate_sum(delta, prq, load, runnable, running))
		return 0;

	/*
	 * Normalize sums to averages. The divider accounts for the current
	 * position within the ongoing period so the average does not
	 * oscillate near period boundaries.
	 *
	 * divider = PELT_LOAD_AVG_MAX - 1024 + period_contrib
	 *         = PELT_MIN_DIVIDER + period_contrib
	 *
	 * period_contrib is in [0, 1023], so divider is always in
	 * [PELT_MIN_DIVIDER, PELT_LOAD_AVG_MAX - 1] and never zero.
	 */
	divider = PELT_MIN_DIVIDER + prq->period_contrib;

	prq->load_avg = (u32)(load * prq->load_sum / divider);
	prq->runnable_avg = (u32)(prq->runnable_sum / divider);
	prq->util_avg = prq->util_sum / divider;

	return 1;
}
