#include <scx/common.bpf.h>

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

/* the operations, once for native and once for arena-resident averages */
#define RAVG_AS
#define RAVG_ARG
#define RAVG_FN(name)	name
#include "ravg_impl.bpf.h"
#undef RAVG_AS
#undef RAVG_ARG
#undef RAVG_FN

#define RAVG_AS		__arena
#define RAVG_ARG	__arg_arena
#define RAVG_FN(name)	name##_arena
#include "ravg_impl.bpf.h"
