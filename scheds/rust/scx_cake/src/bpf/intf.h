/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake — shared interface between the BPF scheduler and the Rust loader.
 * DESIGN.md has the design; HYPOTHESES.md §S the measurements behind these.
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif /* __VMLINUX_H__ */

/*
 * No cflag sets topology — the loader measures the host into rodata at
 * attach, so one binary fits any machine. Policy is source-only so an A/B
 * is two commits, not two flags (§S.6).
 */

/* Multi-CCD steal order: 0 off, 1 same-CCD first, 2 also group cache tiers. */
#define CAKE_CCD_STEAL_POLICY 2

enum consts {
	NSEC_PER_USEC	= 1000,
	NSEC_PER_MSEC	= (1000 * NSEC_PER_USEC),

	/* The slice every task gets. Dose-responsed U-curve minimum (§S.1). */
	SLICE_NS	= 3000 * NSEC_PER_USEC,

	/* Vtime credit for time an occupant already ran (§S.2). */
	HOME_PREEMPT_RAN_CREDIT_SHIFT	= 1,

	/* Occupant protection: FIXED slice fractions, so only long-running
	 * compute is ever preempted and no shared clock moves them (§R.28). */
	PREEMPT_PROTECT_SHIFT		= 4,
	PROBE_PROTECT_SHIFT		= 2,

	/* Slice cap: half the task's OWN mean cycle (§G12, §R.28). */
	PERIOD_SLICE_CAP_SHIFT		= 1,

	/* Pre-scale for the wait:run cross-multiply; it cancels (§G12). */
	CAKE_RATIO_SHIFT		= 16,

	/*
	 * WALL-CLOCK starvation bound for the global wake queue, ~3 frames at
	 * 120 Hz: a vtime bound cannot bound a wall-clock stall (§S.4).
	 */
	WAKE_STARVE_WALL_NS		= 24 * NSEC_PER_MSEC,
	WAKE_STARVE_REFRESH_NS		= WAKE_STARVE_WALL_NS / 2,

	/*
	 * FRAME CLOCK band over ENGINE cadence, not display refresh — an
	 * uncapped engine outruns any panel. A clamp, not a knob (§G11, §G27).
	 */
	FRAME_HZ_MAX			= 2000,
	FRAME_HZ_MIN			= 25,
	FRAME_PERIOD_MIN_NS		= 1000 * NSEC_PER_MSEC / FRAME_HZ_MAX,
	FRAME_PERIOD_MAX_NS		= 1000 * NSEC_PER_MSEC / FRAME_HZ_MIN,
	/* Floor boot stays display-class; the band min is no safe start (§G27). */
	FRAME_FLOOR_BOOT_NS		= 2 * NSEC_PER_MSEC,
	/* Vote buckets spanning that band; width need only separate cadences. */
	FRAME_BUCKET_SHIFT		= 17,
	FRAME_BUCKETS			= 512,

	/* Widest host the CCD steal matrix covers (u16² = 32 KB rodata);
	 * wider machines take the generic ring walk at runtime. */
	STEAL_SPAN			= 128,
	CCD_STEAL_POLICY		= CAKE_CCD_STEAL_POLICY,

	/* Fixed-point weight scaling: representation, not policy (§S.7). */
	RECIP_SHIFT		= 20,
	RECIP_ONE		= 1 << RECIP_SHIFT,
	RECIP_MASK		= RECIP_ONE - 1,
	STATIC_PRIO_BASE	= 100,
	RECIP_TABLE_SIZE	= 64,
	RECIP_INDEX_MASK	= RECIP_TABLE_SIZE - 1,
	IDLE_RECIP_INDEX	= 40,
	MAX_RECIP_WEIGHT	= 357913941,

	/* Cache-isolated mutable-state slot geometry (§R.10). */
	STATE_SLOT_BYTES	= 128,
	STATE_SLOT_WORDS	= STATE_SLOT_BYTES / sizeof(u64),

	/* §G51: cpuidle exit-latency table entries (sysfs state count cap). */
	CAKE_CSTATE_TABLE	= 16,

	/* Runnable-stall safety watchdog, not a scheduling threshold. */
	WATCHDOG_TIMEOUT_MS	= 5 * 1000,

	/*
	 * Verifier sizing bound for per-CPU state and the steal loops, a power
	 * of 2 so hot-path indexes reduce to a mask. NOT the DSQ count. WAKE_DSQ
	 * sits one id above that range and holds wakeups, so the FIRST CPU to
	 * block anywhere finds them; MAX_CPUS + 1 is retired, not recycled (§S.7).
	 */
	MAX_CPUS	= 1024,
	WAKE_DSQ	= MAX_CPUS,

	/* The steal-ring queue hint, one bit per CPU (§G25). */
	QMASK_WORDS	= MAX_CPUS / 64,

	/* §G56 FOLD: LLC band count bound for the banded steal tables. */
	MAX_LLCS	= 64,

	/*
	 * §G57: a saturated wake moves to an earlier-freeing CPU only when the
	 * gain clears this fraction of the slice. A partner inside it keeps the
	 * wake home: the herd-collapse guard expressed as time, not depth.
	 */
	FREE_MOVE_MARGIN_SHIFT		= 5,

	/* §G58: the reservation outlives the fire by this fraction of the
	 * task's cycle (prediction error scales with the cycle), floored at
	 * twice the lead. */
	PREWAKE_WINDOW_SHIFT		= 4,
	PREWAKE_WINDOW_MULT		= 2,
	/* §G58: pre-wake lead on a host with no cpuidle table. */
	PREWAKE_LEAD_DEFAULT_NS		= 50 * NSEC_PER_USEC,

	/* §G59: affine idle candidates the depth pick compares. */
	DEPTH_SCAN_MAX			= 4,
	L2_HANDOFF_BURST_NS		= 16 * NSEC_PER_USEC,	/* §G72: wakee burst bound for a sibling handoff */
	STACK_TOLERANCE_NS		= 40 * NSEC_PER_USEC,	/* §G74: queue behind prev only if it frees within this */
	GROOVE_HOME_MISS		= 8,		/* §G75: home misses before the task stops asking */
	GROOVE_PROBE_MASK		= 63,		/* §G75: re-probe the home every 64 wakes */
	SEAT_BURST_MIN_NS		= 64 * NSEC_PER_USEC,	/* §G79: stage-class burst that earns a seat */
};

#endif /* __CAKE_INTF_H */
