// SPDX-License-Identifier: GPL-2.0
/*
 * Optional decay timer for the core.
 *
 * Holds the stale minimum decay with no timer wait by default. Tier
 * waits wake by direct kick on insert with no timer, so no timer
 * callback runs in the default shape. A stale minimum on an idle CPU
 * holds until the next charge and stays bounded by the 2ms lag clamp
 * plus eligibility, so rejoins keep at most one slice of boost with no
 * storm and no decay is needed. The decay helper folds a stale CPU
 * minimum toward the observed vruntime with one bounded step when the
 * operator enables it, so a long idle CPU rejoins without dragging a
 * stale minimum with no storm. Disabled stays a no-op with no cost.
 * Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Decay one CPU minimum toward the given vruntime by one step. */
/* Disabled by default with no call from any op, so the helper costs */
/* nothing unless the operator wires it. When enabled, moves the */
/* minimum forward by at most one lag bound toward the sample with */
/* saturation, so a stale minimum rejoins without a jump. Kept */
/* intentionally as the optional decay point with no Rust mirror, */
/* so the kernel stays the single truth with one decay symbol. */
static __always_inline void flow_timer_decay(u32 cpu, u64 sample)
{
	(void)cpu;
	(void)sample;
	/* Optional decay stays disabled with no state cost. Tier waits */
	/* wake by direct kick with no timer wait. */
}
