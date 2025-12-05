#ifndef __SCX_RAVG_BPF_H__
#define __SCX_RAVG_BPF_H__

/*
 * Running average helpers to be used in BPF progs. Assumes vmlinux.h has
 * already been included.
 */
enum ravg_consts {
	RAVG_VAL_BITS		= 44,		/* input values are 44bit */
	RAVG_FRAC_BITS		= 20,		/* 1048576 is 1.0 */
};

#ifdef __BPF__

/*
 * Running avg mechanism. Accumulates values between 0 and RAVG_MAX_VAL in
 * arbitrary time intervals. The accumulated values are halved every half_life
 * with each period starting when the current time % half_life is 0. Zeroing is
 * enough for initialization.
 *
 * See ravg_accumulate() and ravg_read() for more details.
 */
struct ravg_data {
	/* current value */
	u64			val;

	/*
	 * The timestamp of @val. The latest completed seq #:
	 *
	 *   (val_at / half_life) - 1
	 */
	u64			val_at;

	/* running avg as of the latest completed seq  */
	u64			old;

	/*
	 * Accumulated value of the current period. Input value is 48bits and we
	 * normalize half-life to 16bit, so it should fit in a u64.
	 */
	u64			cur;
};

#define RAVG_FN_ATTRS __attribute__((unused, always_inline))

int ravg_scale(struct ravg_data *rd, u32 mult, u32 rshift);
u64 ravg_read(struct ravg_data *rd, u64 now, u64 half_life);
int ravg_accumulate(struct ravg_data *rd, u64 new_val, u64 now, u32 half_life);

static RAVG_FN_ATTRS void ravg_add(u64 *sum, u64 addend)
{
	u64 new = *sum + addend;

	if (new >= *sum)
		*sum = new;
	else
		*sum = -1;
}

static RAVG_FN_ATTRS inline u64 ravg_decay(u64 v, u32 shift)
{
	if (shift >= 64)
		return 0;
	else
		return v >> shift;
}

static RAVG_FN_ATTRS u32 ravg_normalize_dur(u32 dur, u32 half_life)
{
	if (dur < half_life)
		return (((u64)dur << RAVG_FRAC_BITS) + half_life - 1) /
			half_life;
	else
		return 1 << RAVG_FRAC_BITS;
}

/**
 * ravg_transfer - Transfer in or out a component running avg
 * @base: ravg_data to transfer @xfer into or out of
 * @base_new_val: new value for @base
 * @xfer: ravg_data to transfer
 * @xfer_new_val: new value for @xfer
 * @is_xfer_in: transfer direction
 *
 * An ravg may be a sum of component ravgs. For example, a scheduling domain's
 * load is the sum of the load values of all member tasks. If a task is migrated
 * to a different domain, its contribution should be subtracted from the source
 * ravg and added to the destination one.
 *
 * This function can be used for such component transfers. Both @base and @xfer
 * must have been accumulated at the same timestamp. @xfer's contribution is
 * subtracted if @is_fer_in is %false and added if %true.
 */
static RAVG_FN_ATTRS void ravg_transfer(struct ravg_data *base, u64 base_new_val,
					struct ravg_data *xfer, u64 xfer_new_val,
					u32 half_life, bool is_xfer_in)
{
	/* synchronize @base and @xfer */
	if ((s64)(base->val_at - xfer->val_at) < 0)
		ravg_accumulate(base, base_new_val, xfer->val_at, half_life);
	else if ((s64)(base->val_at - xfer->val_at) > 0)
		ravg_accumulate(xfer, xfer_new_val, base->val_at, half_life);

	/* transfer */
	if (is_xfer_in) {
		base->old += xfer->old;
		base->cur += xfer->cur;
	} else {
		if (base->old > xfer->old)
			base->old -= xfer->old;
		else
			base->old = 0;

		if (base->cur > xfer->cur)
			base->cur -= xfer->cur;
		else
			base->cur = 0;
	}
}

#endif /* __BPF__ */

#endif /* __SCX_RAVG_BPF_H__ */
