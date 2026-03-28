/*
 * SPDX-License-Identifier: GPL-2.0
 * Author: Cheng-Yang Chou <yphbchou0911@gmail.com>
 */
#pragma once

#ifndef __SCX_PELT_H__
#define __SCX_PELT_H__

/*
 * BPF PELT (Per-Entity Load Tracking) library.
 *
 * This design is heavily inspired by `[RFC PATCH 0/1] sched/pelt: Change PELT
 * halflife at runtime` [1].
 * [1]: https://lore.kernel.org/all/20220829055450.1703092-1-dietmar.eggemann@arm.com/
 *
 * Re-implements the kernel's PELT math entirely in BPF with support for a
 * configurable half-life via time-stretching. No kernel kfuncs are required.
 *
 * The standard kernel PELT uses a 32ms half-life (y^32 = 0.5 where each
 * period is 1024us). This library supports shorter half-lives by left-shifting
 * the elapsed delta before feeding it into the PELT accumulator, which makes
 * time appear to pass faster and causes the signal to converge more quickly:
 *
 *   lshift = 0  ->  1x stretch ->  32ms half-life (standard)
 *   lshift = 1  ->  2x stretch ->  16ms half-life
 *   lshift = 2  ->  4x stretch ->   8ms half-life
 *
 * Typical usage in a BPF scheduler:
 *
 *   struct {
 *       __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 *       __uint(max_entries, 1);
 *       __type(key, u32);
 *       __type(value, struct pelt_rq);
 *   } pelt_rq_map SEC(".maps");
 *
 *   // called once at BPF scheduler init
 *   void init_pelt(void)
 *   {
 *       u32 key = 0;
 *       struct pelt_rq *prq = bpf_map_lookup_elem(&pelt_rq_map, &key);
 *       if (prq)
 *           prq->lshift = 1; // 16ms half-life
 *   }
 *
 *   void BPF_STRUCT_OPS(foo_running, struct task_struct *p)
 *   {
 *       u32 key = 0;
 *       struct pelt_rq *prq = bpf_map_lookup_elem(&pelt_rq_map, &key);
 *       if (prq)
 *           pelt_update(prq, bpf_ktime_get_ns(), 1, 1, 1);
 *   }
 *
 *   void BPF_STRUCT_OPS(foo_stopping, struct task_struct *p, bool runnable)
 *   {
 *       u32 key = 0;
 *       struct pelt_rq *prq = bpf_map_lookup_elem(&pelt_rq_map, &key);
 *       if (prq)
 *           pelt_update(prq, bpf_ktime_get_ns(), 1, runnable ? 1 : 0, 0);
 *   }
 *
 * After calling pelt_update(), read prq->util_avg for CPU utilization.
 * Zeroing the struct is sufficient for initialization.
 */

/* Matches kernel LOAD_AVG_MAX from kernel/sched/sched-pelt.h */
#define PELT_LOAD_AVG_MAX	47742
/* Half-life is 32 periods of 1024us each */
#define PELT_LOAD_AVG_PERIOD	32
/* Minimum value of the normalizing divider */
#define PELT_MIN_DIVIDER	(PELT_LOAD_AVG_MAX - 1024)
/* Maximum supported lshift value */
#define PELT_LSHIFT_MAX		2
/* Matches kernel SCHED_CAPACITY_SHIFT */
#define PELT_CAPACITY_SHIFT	10

/*
 * Per-CPU PELT state tracked by the BPF scheduler.
 * Zero-initialize before first use; set @lshift before the first call to
 * pelt_update() if a shorter half-life is desired (0 = standard 32ms).
 *
 * The *_sum fields mirror struct sched_avg in the kernel. util_sum is u32
 * (bounded by PELT_LOAD_AVG_MAX * 1024); load_sum and runnable_sum are u64
 * to accommodate load weights larger than 1.
 */
struct pelt_rq {
	u64	load_sum;
	u64	runnable_sum;
	u32	util_sum;
	u32	period_contrib;
	u64	last_update_time;	/* nanoseconds, real monotonic clock */

	/* computed averages, updated by pelt_update() */
	u32	load_avg;
	u32	runnable_avg;
	u32	util_avg;

	/*
	 * Half-life control. Set once at BPF scheduler init;
	 * do not change at runtime without also zeroing the *_sum fields.
	 *
	 *   0  ->  32ms half-life (standard kernel PELT)
	 *   1  ->  16ms half-life
	 *   2  ->   8ms half-life (PELT_LSHIFT_MAX)
	 */
	u32	lshift;
};

#ifdef __BPF__

/*
 * Precomputed y^n for n in [0, 31] where y^32 = 0.5.
 * Copied from kernel/sched/sched-pelt.h (runnable_avg_yN_inv[]).
 * This shouldn't be modified.
 */
static const u32 pelt_yN_inv[] = {
	0xffffffff, 0xfa83b2da, 0xf5257d14, 0xefe4b99a, 0xeac0c6e6, 0xe5b906e6,
	0xe0ccdeeb, 0xdbfbb796, 0xd744fcc9, 0xd2a81d91, 0xce248c14, 0xc9b9bd85,
	0xc5672a10, 0xc12c4cc9, 0xbd08a39e, 0xb8fbaf46, 0xb504f333, 0xb123f581,
	0xad583ee9, 0xa9a15ab4, 0xa5fed6a9, 0xa2704302, 0x9ef5325f, 0x9b8d39b9,
	0x9837f050, 0x94f4efa8, 0x91c3d373, 0x8ea4398a, 0x8b95c1e3, 0x88980e80,
	0x85aac367, 0x82cd8698,
};

/*
 * pelt_decay_load - apply geometric decay to a load value
 * @val: value to decay
 * @n: number of periods to decay over
 *
 * Computes val * y^n where y^32 == 0.5. Large @n values are handled by
 * folding powers of 2 (each PELT_LOAD_AVG_PERIOD halves the value) before
 * applying the fractional remainder via the lookup table.
 *
 * Corresponds to decay_load() in kernel/sched/pelt.c.
 */
static __attribute__((unused, always_inline))
u64 pelt_decay_load(u64 val, u64 n)
{
	unsigned int local_n;

	if (n > (u64)PELT_LOAD_AVG_PERIOD * 63)
		return 0;

	local_n = (unsigned int)n;

	if (local_n >= PELT_LOAD_AVG_PERIOD) {
		val >>= local_n / PELT_LOAD_AVG_PERIOD;
		local_n %= PELT_LOAD_AVG_PERIOD;
	}

	/*
	 * val * y^local_n. val is bounded by PELT_LOAD_AVG_MAX * 1024 (~49M)
	 * and pelt_yN_inv[] <= 0xffffffff, so the product fits in a u64 before
	 * the right shift.
	 */
	val = (val * (u64)pelt_yN_inv[local_n]) >> 32;
	return val;
}

/*
 * pelt_accumulate_segments - compute the d1 + d2 + d3 PELT contribution
 * @periods: number of full periods elapsed
 * @d1: partial period before the first full period (in 1024us units)
 * @d3: partial period after the last full period (in 1024us units)
 *
 * Corresponds to __accumulate_pelt_segments() in kernel/sched/pelt.c.
 */
static __attribute__((unused, always_inline))
u32 pelt_accumulate_segments(u64 periods, u32 d1, u32 d3)
{
	u32 c1, c2, c3 = d3;

	/* c1 = d1 * y^periods */
	c1 = (u32)pelt_decay_load((u64)d1, periods);

	/*
	 * c2 = 1024 * sum(y^n, n=1..periods-1)
	 *    = LOAD_AVG_MAX - decay(LOAD_AVG_MAX, periods) - 1024
	 */
	c2 = PELT_LOAD_AVG_MAX -
	     (u32)pelt_decay_load(PELT_LOAD_AVG_MAX, periods) - 1024;

	return c1 + c2 + c3;
}

/*
 * See lib/pelt.bpf.c for implementation details.
 */
int pelt_update(struct pelt_rq *prq, u64 now, unsigned long load,
		unsigned long runnable, int running);

#endif /* __BPF__ */

#endif /* __SCX_PELT_H__ */
