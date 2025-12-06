#include <scx/common.bpf.h>

#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

#include <lib/ravg.h>

/*
 * Pre-computed decayed full-period values. This is quicker and keeps the bpf
 * verifier happy by removing the need for looping.
 *
 * [0] = ravg_decay(1 << RAVG_FRAC_BITS, 1)
 * [1] = [0] + ravg_decay(1 << RAVG_FRAC_BITS, 2)
 * [2] = [1] + ravg_decay(1 << RAVG_FRAC_BITS, 3)
 * ...
 */
static const u64 ravg_full_sum[] = {
	 524288,  786432,  917504,  983040,
	1015808, 1032192, 1040384, 1044480,
	1046528, 1047552, 1048064, 1048320,
	1048448, 1048512, 1048544, 1048560,
	1048568, 1048572, 1048574, 1048575,
	/* the same from here on */
};

static const int ravg_full_sum_len = sizeof(ravg_full_sum) / sizeof(ravg_full_sum[0]);

/**
 * ravg_accumulate - Accumulate a new value
 * @rd: ravg_data to accumulate into
 * @new_val: new value
 * @now: current timestamp
 * @half_life: decay period, must be the same across calls
 *
 * The current value is changing to @val at @now. Accumulate accordingly.
 */
__weak
int ravg_accumulate(struct ravg_data *rd, u64 new_val, u64 now,
					  u32 half_life)
{
	u32 cur_seq, val_seq, seq_delta;

	/*
	 * It may be difficult for the caller to guarantee monotonic progress if
	 * multiple CPUs accumulate to the same ravg_data. Handle @now being in
	 * the past of @rd->val_at.
	 */
	if (now < rd->val_at)
		now = rd->val_at;

	cur_seq = now / half_life;
	val_seq = rd->val_at / half_life;
	seq_delta = cur_seq - val_seq;

	/*
	 * Decay ->old and fold ->cur into it.
	 *
	 *                                                          @end
	 *                                                            v
	 * timeline     |---------|---------|---------|---------|---------|
	 * seq delta         4         3         2         1          0
	 * seq            ->seq                                    cur_seq
	 * val            ->old     ->cur                  ^
	 *                   |         |                   |
	 *                   \---------+------------------/
	 */
	if (seq_delta > 0) {
		/* decay ->old to bring it upto the cur_seq - 1 */
		rd->old = ravg_decay(rd->old, seq_delta);
		/* non-zero ->cur must be from val_seq, calc and fold */
		ravg_add(&rd->old, ravg_decay(rd->cur, seq_delta));
		/* clear */
		rd->cur = 0;
	}

	if (!rd->val)
		goto out;

	/*
	 * Accumulate @rd->val between @rd->val_at and @now.
	 *
	 *                       @rd->val_at                        @now
	 *                            v                               v
	 * timeline     |---------|---------|---------|---------|---------|
	 * seq delta                  [  3  |    2    |    1    |  0  ]
	 */
	if (seq_delta > 0) {
		u32 dur;

		/* fold the oldest period which may be partial */
		dur = ravg_normalize_dur(half_life - rd->val_at % half_life, half_life);
		ravg_add(&rd->old, rd->val * ravg_decay(dur, seq_delta));

		/* fold the full periods in the middle with precomputed vals */
		if (seq_delta > 1) {
			u32 idx = seq_delta - 2;

			if (idx >= ravg_full_sum_len)
				idx = ravg_full_sum_len - 1;

			ravg_add(&rd->old, rd->val * ravg_full_sum[idx]);
		}

		/* accumulate the current period duration into ->cur */
		rd->cur += rd->val * ravg_normalize_dur(now % half_life,
							half_life);
	} else {
		rd->cur += rd->val * ravg_normalize_dur(now - rd->val_at,
							half_life);
	}
out:
	if (new_val >= 1LLU << RAVG_VAL_BITS)
		rd->val = (1LLU << RAVG_VAL_BITS) - 1;
	else
		rd->val = new_val;
	rd->val_at = now;

	return 0;
}

/**
 * u64_x_u32_rshift - Calculate ((u64 * u32) >> rshift)
 * @a: multiplicand
 * @b: multiplier
 * @rshift: number of bits to shift right
 *
 * Poor man's 128bit arithmetic. Calculate ((@a * @b) >> @rshift) where @a is
 * u64 and @b is u32 and (@a * @b) may be bigger than #U64_MAX. The caller must
 * ensure that the final shifted result fits in u64.
 */
static inline
u64 u64_x_u32_rshift(u64 a, u32 b, u32 rshift)
{
	const u64 mask32 = (u32)-1;
	u64 al = a & mask32;
	u64 ah = (a & (mask32 << 32)) >> 32;

	/*
	 *                                        ah: high 32     al: low 32
	 * a                                   |--------------||--------------|
	 *
	 * ah * b              |--------------||--------------|
	 * al * b                              |--------------||--------------|
	 */
	al *= b;
	ah *= b;

	/*
	 * (ah * b) >> rshift        |--------------||--------------|
	 * (al * b) >> rshift                        |--------------||--------|
	 *                                                           <-------->
	 *                                                           32 - rshift
	 */
	al >>= rshift;
	if (rshift <= 32)
		ah <<= 32 - rshift;
	else
		ah >>= rshift - 32;

	return al + ah;
}

/**
 * ravg_scale - Scale a running avg
 * @rd: ravg_data to scale
 * @mult: multipler
 * @rshift: right shift amount
 *
 * Scale @rd by multiplying the tracked values by @mult and shifting right by
 * @rshift.
 */
__weak
int ravg_scale(struct ravg_data *rd, u32 mult, u32 rshift)
{
	rd->val = u64_x_u32_rshift(rd->val, mult, rshift);
	rd->old = u64_x_u32_rshift(rd->old, mult, rshift);
	rd->cur = u64_x_u32_rshift(rd->cur, mult, rshift);

	return 0;
}

/**
 * ravg_read - Read the current running avg
 * @rd: ravg_data to read from
 * @now: timestamp as of which to read the running avg
 * @half_life: decay period, must match ravg_accumulate()'s
 *
 * Read running avg from @rd as of @now.
 */
__weak
u64 ravg_read(struct ravg_data *rd, u64 now, u64 half_life)
{
	struct ravg_data trd;
	u32 elapsed;

	/*
	 * It may be difficult for the caller to guarantee monotonic progress if
	 * multiple CPUs accumulate to the same ravg_data. Handle @now being in
	 * the past of @rd->val_at.
	 */
	if (now < rd->val_at)
		now = rd->val_at;

	elapsed = now % half_life;

	/*
	 * Accumulate the ongoing period into a temporary copy. This allows
	 * external readers to access up-to-date avg without strongly
	 * synchronizing with the updater (we need to add a seq lock tho).
	 */
	trd = *rd;
	rd = &trd;
	ravg_accumulate(rd, 0, now, half_life);

	/*
	 * At the beginning of a new half_life period, the running avg is the
	 * same as @rd->old. At the beginning of the next, it'd be old load / 2
	 * + current load / 2. Inbetween, we blend the two linearly.
	 */
	if (elapsed) {
		u32 progress = ravg_normalize_dur(elapsed, half_life);
		/*
		 * `H` is the duration of the half-life window, and `E` is how
		 * much time has elapsed in this window. `P` is [0.0, 1.0]
		 * representing how much the current window has progressed:
		 *
		 *   P = E / H
		 *
		 * If `old` is @rd->old, we would want to calculate the
		 * following for blending:
		 *
		 *   old * (1.0 - P / 2)
		 *
		 * Because @progress is [0, 1 << RAVG_FRAC_BITS], let's multiply
		 * and then divide by 1 << RAVG_FRAC_BITS:
		 *
		 *         (1 << RAVG_FRAC_BITS) - (1 << RAVG_FRAC_BITS) * P / 2
		 *   old * -----------------------------------------------------
		 *                       1 << RAVG_FRAC_BITS
		 *
		 * As @progress is (1 << RAVG_FRAC_BITS) * P:
		 *
		 *         (1 << RAVG_FRAC_BITS) - progress / 2
		 *   old * ------------------------------------
		 *                1 << RAVG_FRAC_BITS
		 *
		 * As @rd->old uses full 64bit, the multiplication can overflow,
		 * but we also know that the final result is gonna be smaller
		 * than @rd->old and thus fit. Use u64_x_u32_rshift() to handle
		 * the interim multiplication correctly.
		 */
		u64 old = u64_x_u32_rshift(rd->old,
					   (1 << RAVG_FRAC_BITS) - progress / 2,
					   RAVG_FRAC_BITS);
		/*
		 * If `S` is the Sum(val * duration) for this half-life window,
		 * the avg for this window is:
		 *
		 *   S / E
		 *
		 * We would want to calculate the following for blending:
		 *
		 *   S / E * (P / 2)
		 *
		 * As P = E / H,
		 *
		 *   S / E * (E / H / 2)
		 *   S / H / 2
		 *
		 * Expanding S, the above becomes:
		 *
		 *   Sum(val * duration) / H / 2
		 *   Sum(val * (duration / H)) / 2
		 *
		 * As we use RAVG_FRAC_BITS bits for fixed point arithmetic,
		 * let's multiply the whole result accordingly:
		 *
		 *   (Sum(val * (duration / H)) / 2) * (1 << RAVG_FRAC_BITS)
		 *
		 *             duration * (1 << RAVG_FRAC_BITS)
		 *   Sum(val * --------------------------------) / 2
		 *                            H
		 *
		 * The righthand multiplier inside Sum() is the normalized
		 * duration returned from ravg_normalize_dur(), so, the whole
		 * Sum term equals @rd->cur.
		 *
		 *  rd->cur / 2
		 */
		u64 cur = rd->cur / 2;

		return old + cur;
	} else {
		return rd->old;
	}
}
