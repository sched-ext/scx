/* SPDX-License-Identifier: GPL-2.0 */
/*
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

#define CAKE_CCD_STEAL_POLICY 2	/* steal order: 0 off, 1 same-CCD first, 2 also group cache tiers */

enum consts {
	NSEC_PER_USEC	= 1000,
	NSEC_PER_MSEC	= (1000 * NSEC_PER_USEC),

	/* Kthread grant and vtime lag unit; the grant cap and protect windows are shifts of it. */
	SLICE_NS	= 3000 * NSEC_PER_USEC,

	/* Vtime credit for time an occupant already ran. */
	HOME_PREEMPT_RAN_CREDIT_SHIFT	= 1,

	/* Occupant protect windows: SLICE_NS >> shift, capped by the wakee's slice. */
	PREEMPT_PROTECT_SHIFT		= 4,
	PROBE_PROTECT_SHIFT		= 2,

	PERIOD_SLICE_CAP_SHIFT		= 1,
	CAKE_GRANT_CAP_NS	= SLICE_NS >> PERIOD_SLICE_CAP_SHIFT,	/* longest computed grant */

	CAKE_RATIO_SHIFT		= 16,	/* wait:run cross-multiply pre-scale; it cancels */

	/* Dispatch-time starvation escalation; this arms no timer. */
	WAKE_STARVE_WALL_NS		= 24 * NSEC_PER_MSEC,
	WAKE_STARVE_REFRESH_NS		= WAKE_STARVE_WALL_NS / 2,

	/* Widest host the u16 steal matrix covers; wider hosts take the ring walk. */
	STEAL_SPAN			= 128,
	CCD_STEAL_POLICY		= CAKE_CCD_STEAL_POLICY,

	/* Fixed-point weight scaling: representation, not policy. */
	RECIP_SHIFT		= 20,
	RECIP_ONE		= 1 << RECIP_SHIFT,
	RECIP_MASK		= RECIP_ONE - 1,
	STATIC_PRIO_BASE	= 100,
	RECIP_TABLE_SIZE	= 64,
	RECIP_INDEX_MASK	= RECIP_TABLE_SIZE - 1,
	IDLE_RECIP_INDEX	= 40,
	MAX_RECIP_WEIGHT	= 357913941,
	NICE_0_WEIGHT		= 1024,	/* sched_prio_to_weight[20] */
	NICE_19_WEIGHT		= 15,	/* sched_prio_to_weight[39] */
	/* One nice-19 grant: the most vtime lead over the frontier any weight holds. */
	CAKE_VTIME_CAP_MAX_NS	= ((u64)CAKE_GRANT_CAP_NS *
				   (((u64)NICE_0_WEIGHT << RECIP_SHIFT) / NICE_19_WEIGHT)) >> RECIP_SHIFT,

	STATE_SLOT_BYTES	= 128,
	STATE_SLOT_WORDS	= STATE_SLOT_BYTES / sizeof(u64),

	WATCHDOG_TIMEOUT_MS	= 5 * 1000,
	TICK_MAX_NS		= 20 * NSEC_PER_MSEC,	/* longest tick the loader takes (HZ 50) */

	MAX_CPUS	= 1024,	/* verifier bound; a power of 2 so indexes mask; not a DSQ count */
	WAKE_DSQ	= MAX_CPUS,
	MAX_LLCS	= 16,			/* wake pools and served stamps per LLC */
	LLC_WAKE_DSQ_BASE	= MAX_CPUS + 2,	/* pool of LLC i is LLC_WAKE_DSQ_BASE + i */

	QMASK_WORDS	= MAX_CPUS / 64,	/* steal-ring queue hint, one bit per CPU */
	SEAT_BURST_MIN_NS	= 64 * NSEC_PER_USEC,	/* burst that earns a seat */
	CLAIM_TRIES_MIN		= 4,		/* idle bits tried per claim; scales with the die */
	SEAT_CAP		= 64,		/* seats live inside one idle word */
	/* RT displacement census in log2 bands of ~1 us (ns >> 10), 1 us .. >= 128 us. */
	CAKE_RELEASE_BAND_SHIFT	= 10,
	CAKE_RELEASE_BANDS	= 8,
	CAKE_RELEASE_PATHS	= 3,		/* arrival: non-IMMED / IMMED / slice-exhausted */
	CAKE_RELEASE_REASONS	= 4,		/* RT / DL / stop / unknown */
	SEAT_HOLDER_SLOTS	= 4 * SEAT_CAP,	/* census by pid; full word hits 1/4 non-holders */
	CAKE_PEND_SPIN_MAX	= 4,		/* self-kicks per CPU waiting for a pool landing */
	CAKE_IDLE_STATES	= 16,		/* cpuidle states tracked; power of two, masked */
	CAKE_HIST_SHIFT		= 8,		/* observe-only histogram: log2 bands from 256 ns */
	CAKE_HIST_BANDS		= 16,		/* ... to 8 ms */
	CAKE_HIST_KINDS		= 4,		/* hop, handoff quantum, burst; power of two */
	RATE_FLOOR_SHIFT	= 4,		/* F rises >= 2^-this ns per ns: see asserts */
	FRONTIER_GRAIN_NS	= 1 << 16,	/* 65 us frontier steps: readers use slice scale */
	CAKE_POOL_TAG_MASK	= 0x1f,		/* slice tag: pool + 1 <= MAX_LLCS; lose <= 31 ns */
};

/* Observe-only histogram kinds; the count is a power of two. */
enum cake_hist_kind {
	CAKE_HIST_HOP,			/* direct placement: enqueue stamp to run */
	CAKE_HIST_HANDOFF,		/* quantum after a wake, at block */
	CAKE_HIST_BURST,		/* mean burst of the task, at block */
};

/* Gates reached, for the tried/fired census (probe). Power of two: the index is masked. */
enum cake_tried_gate {
	CAKE_TRIED_SERIAL,		/* the waker's handoff bit is saturated */
	CAKE_TRIED_RETAKE,		/* a stage wake whose seat another task runs */
	CAKE_TRIED_PROBE,		/* neighbour probe: no idle CPU, occupant kept tcpu */
	CAKE_TRIED_TICK,		/* tick test evaluated on an idle candidate */
	CAKE_TRIED_NR,
};

#endif /* __CAKE_INTF_H */
