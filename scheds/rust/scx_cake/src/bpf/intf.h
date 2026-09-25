/* SPDX-License-Identifier: GPL-2.0 */
/* This software may be used and distributed according to the terms of the GNU
 * General Public License version 2. */
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

/* No topology cflags: the loader measures the host into rodata at attach. */

/* Multi-CCD steal order: 0 off, 1 same-CCD first, 2 also group cache tiers. */
#define CAKE_CCD_STEAL_POLICY 2

enum consts {
	NSEC_PER_USEC	= 1000,
	NSEC_PER_MSEC	= (1000 * NSEC_PER_USEC),

	/* The slice every task gets: the dose-response minimum. */
	SLICE_NS	= 3000 * NSEC_PER_USEC,

	/* Vtime credit for time an occupant already ran. */
	HOME_PREEMPT_RAN_CREDIT_SHIFT	= 1,

	/* Occupant protection and slice cap: fixed fractions of the task's own run
	 * and mean cycle, so only long-running compute is ever preempted. */
	PREEMPT_PROTECT_SHIFT		= 4,
	PROBE_PROTECT_SHIFT		= 2,

	PERIOD_SLICE_CAP_SHIFT		= 1,

	/* Pre-scale for the wait:run cross-multiply; it cancels. */
	CAKE_RATIO_SHIFT		= 16,

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

	STATE_SLOT_BYTES	= 128,
	STATE_SLOT_WORDS	= STATE_SLOT_BYTES / sizeof(u64),

	WATCHDOG_TIMEOUT_MS	= 5 * 1000,

	/* Verifier sizing bound, a power of 2 so indexes mask; not the DSQ count. */
	MAX_CPUS	= 1024,
	WAKE_DSQ	= MAX_CPUS,
	MAX_LLCS	= 16,			/* wake pools and served stamps per LLC */
	LLC_WAKE_DSQ_BASE	= MAX_CPUS + 2,	/* pool of LLC i is LLC_WAKE_DSQ_BASE + i */

	/* The steal-ring queue hint, one bit per CPU. */
	QMASK_WORDS	= MAX_CPUS / 64,
	SEAT_BURST_MIN_NS		= 64 * NSEC_PER_USEC,	/* burst that earns a seat */
	CLAIM_TRIES_MIN			= 4,			/* idle-word bits tried per claim, floor; the loader scales with the die */
	SEAT_CAP			= 64,			/* seats live inside one idle word */
	/* RT displacement census in log2 bands of ~1 us (ns >> 10), 1 us .. >= 128 us. */
	CAKE_RELEASE_BAND_SHIFT		= 10,
	CAKE_RELEASE_BANDS		= 8,
	CAKE_RELEASE_PATHS		= 3,			/* arrival: non-IMMED / IMMED / slice-exhausted */
	CAKE_RELEASE_REASONS		= 4,			/* RT / DL / stop / unknown */
	SEAT_HOLDER_SLOTS		= 4 * SEAT_CAP,		/* holder census by pid: a full word collides with a quarter of the non-holders */
	CAKE_PEND_SPIN_MAX		= 4,			/* dispatch re-picks waiting for a pool landing before clearing the token */
	CAKE_IDLE_STATES		= 16,			/* cpuidle states tracked; a power of two, indexed masked */
	CAKE_HIST_SHIFT			= 8,			/* observe-only histograms: log2 bands from 256 ns */
	CAKE_HIST_BANDS			= 16,			/* ... to 8 ms */
	CAKE_HIST_KINDS			= 4,			/* hop, handoff quantum, burst; power of two */
	FRONTIER_GRAIN_NS		= 1 << 16,		/* the frontier advances in 65 us steps: readers work at slice scale */
	CAKE_POOL_TAG_MASK		= 0x1f,			/* a pooled slice's low bits carry its pool + 1; MAX_LLCS + 1 fits; grants lose <= 31 ns */
};

/* Gates reached, for the tried/fired census (probe). Power of two: the index is masked. */
enum cake_hist_kind {
	CAKE_HIST_HOP,			/* direct placement: enqueue stamp to run */
	CAKE_HIST_HANDOFF,		/* quantum after a wake, at block */
	CAKE_HIST_BURST,		/* mean burst of the task, at block */
};

enum cake_tried_gate {
	CAKE_TRIED_SERIAL,		/* the waker's handoff bit is saturated */
	CAKE_TRIED_RETAKE,		/* a stage wake whose seat another task runs */
	CAKE_TRIED_PROBE,		/* neighbour probe entered: no idle CPU, occupant kept tcpu */
	CAKE_TRIED_TICK,		/* tick test evaluated on an idle candidate */
	CAKE_TRIED_NR,
};

#endif /* __CAKE_INTF_H */
