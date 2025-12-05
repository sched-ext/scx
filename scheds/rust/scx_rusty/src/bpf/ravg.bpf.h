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

#endif /* __SCX_RAVG_BPF_H__ */
