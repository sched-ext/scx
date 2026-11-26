/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LERTICK_MODEL_H
#define LERTICK_MODEL_H

/* vmlinux.h supplies these types to the BPF translation unit. */
#ifndef __VMLINUX_H__
#ifdef __linux__
#include <linux/types.h>
#else
#include <stdint.h>
typedef int32_t	 __s32;
typedef int64_t	 __s64;
typedef uint64_t __u64;
#endif
#endif

#define LERTICK_FEATURES 5
#define LERTICK_Q 65536
#define LERTICK_WEIGHT_LIMIT (4 * LERTICK_Q)
#define LERTICK_ALPHA_Q16 (LERTICK_Q / 64)
#define LERTICK_INLINE static __attribute__((always_inline)) inline

/* All features and targets are Q16 fractions in [0, 1]. Signed divisions
 * truncate toward zero, as required by C. Five bounded products fit in s64:
 * |dot| <= 20 * Q^2. |alpha * error * feature| <= Q^3 / 64.
 * Use a causal feature snapshot captured before the completed burst label.
 */
struct lertick_model {
	__s32 weight_q16[LERTICK_FEATURES];
	__u64 updates;
};

LERTICK_INLINE __s32 lertick_clip_q16(__s32 value)
{
	if (value < 0)
		return 0;
	if (value > LERTICK_Q)
		return LERTICK_Q;
	return value;
}

LERTICK_INLINE __s32 lertick_clip_weight(__s64 value)
{
	if (value < -LERTICK_WEIGHT_LIMIT)
		return -LERTICK_WEIGHT_LIMIT;
	if (value > LERTICK_WEIGHT_LIMIT)
		return LERTICK_WEIGHT_LIMIT;
	return (__s32)value;
}

/* BPF ISA v3 has no signed division. Both callers use constant positive
 * shifts (16 or 32). Arithmetic right shift plus a sign-derived bias preserves
 * C's truncation toward zero without a branch. The bias is zero for positive
 * values and at most 2^32 - 1 for negative values, so addition cannot overflow.
 * Supported Clang/GCC hosts and the BPF runtime use arithmetic signed shifts.
 */
LERTICK_INLINE __s64 lertick_trunc_shift(__s64 value, unsigned int shift)
{
	__s64 mask = (__s64)(((__u64)1 << shift) - 1);

	return (value + ((value >> 63) & mask)) >> shift;
}

LERTICK_INLINE void lertick_model_init(struct lertick_model *model)
{
	int i;

#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
	for (i = 0; i < LERTICK_FEATURES; i++) {
		model->weight_q16[i] = 0;
	}
	model->weight_q16[0] = LERTICK_Q / 4;
	model->updates	     = 0;
}

LERTICK_INLINE __s32
lertick_model_raw_q16(const struct lertick_model *model,
		      const __s32		  features[LERTICK_FEATURES])
{
	__s64 dot = 0;
	int   i;

#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
	for (i = 0; i < LERTICK_FEATURES; i++)
		dot += (__s64)lertick_clip_weight(model->weight_q16[i]) *
		       lertick_clip_q16(features[i]);
	return (__s32)lertick_trunc_shift(dot, 16);
}

LERTICK_INLINE __s32
lertick_model_predict_q16(const struct lertick_model *model,
			  const __s32 features[LERTICK_FEATURES])
{
	return lertick_clip_q16(lertick_model_raw_q16(model, features));
}

/* Return the clipped pre-update raw residual for telemetry. Inference is
 * clipped, but training uses raw output, so saturated predictions can recover.
 */
LERTICK_INLINE __s32 lertick_model_train(struct lertick_model *model,
					 const __s32 features[LERTICK_FEATURES],
					 __s32	     target_q16)
{
	__s64 error = (__s64)lertick_clip_q16(target_q16) -
		      lertick_model_raw_q16(model, features);
	int i;

	if (error > LERTICK_Q)
		error = LERTICK_Q;
	if (error < -LERTICK_Q)
		error = -LERTICK_Q;
#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
	for (i = 0; i < LERTICK_FEATURES; i++) {
		__s64 update = (__s64)LERTICK_ALPHA_Q16 * error *
			       lertick_clip_q16(features[i]);

		update		     = lertick_trunc_shift(update, 32);
		model->weight_q16[i] = lertick_clip_weight(
			(__s64)lertick_clip_weight(model->weight_q16[i]) +
			update);
	}
	if (model->updates != ~(__u64)0)
		model->updates++;
	return (__s32)error;
}

/* Exact floor(min(ns / cap, 1) * Q), including full u64 inputs. The normal
 * nanosecond range uses a multiply/divide. Extreme caps use sixteen bounded
 * restoring steps, maintaining remainder < cap without overflowing 2 * rem.
 */
LERTICK_INLINE __s32 lertick_scale_ns_q16(__u64 ns, __u64 cap_ns)
{
	__u64 remainder = ns;
	__s32 fraction	= 0;
	int   bit;

	if (!cap_ns)
		return 0;
	if (ns >= cap_ns)
		return LERTICK_Q;
	if (cap_ns <= (~(__u64)0) / LERTICK_Q)
		return (__s32)((ns * LERTICK_Q) / cap_ns);
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
	for (bit = 0; bit < 16; bit++) {
		fraction *= 2;
		if (remainder >= cap_ns - remainder) {
			remainder -= cap_ns - remainder;
			fraction++;
		} else {
			remainder += remainder;
		}
	}
	return fraction;
}

#endif /* LERTICK_MODEL_H */
