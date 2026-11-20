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

enum consts {
	NSEC_PER_USEC	= 1000,
	NSEC_PER_MSEC	= (1000 * NSEC_PER_USEC),

	/* Kthread grant and vtime lag unit; the grant cap and protect windows are shifts of it. */
	SLICE_NS	= 3000 * NSEC_PER_USEC,

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
	CAKE_DSQ_SCAN_DEPTH	= 64,	/* deep queues use bounded candidate selection */
	CAKE_DSQ_SCAN_MAX	= 8,
	TICK_MAX_NS		= 20 * NSEC_PER_MSEC,	/* longest tick the loader takes (HZ 50) */

	MAX_CPUS	= 1024,	/* verifier bound; a power of 2 so indexes mask; not a DSQ count */
	MAX_LLCS	= 16,			/* wake pools and served stamps per LLC */
	LLC_WAKE_DSQ_BASE	= MAX_CPUS + 2,	/* pool of LLC i is LLC_WAKE_DSQ_BASE + i */

	QMASK_WORDS	= MAX_CPUS / 64,	/* steal-ring queue hint, one bit per CPU */
	SEAT_BURST_MIN_NS	= 64 * NSEC_PER_USEC,	/* burst that earns a seat */
	HOME_SLOTS		= 64,			/* home table, hashed by pid */
	HOME_TICK_MASK		= 63,			/* share sampled once per 64 blocks */
	HOME_WINDOW_NS		= 64 * NSEC_PER_MSEC,	/* shortest share window */
	HOME_CENSUS_WINDOWS	= 4,			/* share windows per busy-thread census */
	HOME_ON_DIV		= 5,			/* a home at 1/5 of a CPU */
	HOME_OFF_DIV		= 10,			/* given up under 1/10 */
	HOME_STALE_NS		= 2000 * NSEC_PER_MSEC,	/* an unsampled home may be taken */
	CLAIM_TRIES_MIN		= 4,		/* idle bits tried per claim; scales with the die */
	CPU_WORD_BITS		= 64,		/* CPU ids one idle word holds: the one-word paths' range */
	SEAT_CAP		= CPU_WORD_BITS,	/* seats live inside one idle word */
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
	CAKE_SIGNAL_HOPS	= 6,		/* input tag: wakes inherited past the root wake */
	CAKE_SIGNAL_LOG2_BANDS	= 32,		/* wake-to-run latency histogram bands, per cause */
};

/* --kernel-signals counters; rows that come in pairs are input, then fence. */
enum cake_signal_stat {
	CAKE_SIGNAL_SELECT_INPUT,
	CAKE_SIGNAL_SELECT_FENCE,
	CAKE_SIGNAL_SELECT_UNKNOWN,
	CAKE_SIGNAL_RUNNING,			/* pair */
	CAKE_SIGNAL_RUNNING_UNKNOWN	= CAKE_SIGNAL_RUNNING + 2,
	CAKE_SIGNAL_EXPIRED_SELECT,
	CAKE_SIGNAL_CLOCK_ERROR,
	CAKE_SIGNAL_IRQ_SAMPLES,
	CAKE_SIGNAL_IRQ_UNKNOWN,
	CAKE_SIGNAL_IRQ_HOT,
	CAKE_SIGNAL_WAKE_NS_SUM,		/* pair */
	CAKE_SIGNAL_WAKE_NS_MAX		= CAKE_SIGNAL_WAKE_NS_SUM + 2,	/* pair, merged by maximum */
	CAKE_SIGNAL_WAKE_LOG2		= CAKE_SIGNAL_WAKE_NS_MAX + 2,	/* pair of band rows */
	CAKE_SIGNAL_INHERIT_BASE	= CAKE_SIGNAL_WAKE_LOG2 + 2 * CAKE_SIGNAL_LOG2_BANDS,
	CAKE_SIGNAL_IRQ_WAKER		= CAKE_SIGNAL_INHERIT_BASE + CAKE_SIGNAL_HOPS,
	CAKE_SIGNAL_HOP_LIMIT,
	CAKE_SIGNAL_CLEARED,
	CAKE_SIGNAL_STATS,
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

/* Probe census counters (--toggle probe=1); the loader names each one in exit_report.rs. */
enum cake_stat {
	CAKE_STAT_SELECT = 0,		/* ops.select_cpu entries */
	CAKE_STAT_SERIAL,		/* serial-handoff arm placed */
	CAKE_STAT_HOME,			/* prev-cpu warm home claim placed */
	CAKE_STAT_WP_ATTEMPT,		/* wake_preempt reached with a live occupant */
	CAKE_STAT_WP_TINY,		/* wakee burst <= 4us (microsecond-class shape) */
	CAKE_STAT_WP_SMALL,		/* wakee burst <= 64us */
	CAKE_STAT_WP_PROTECT,		/* rejected: protect window not met */
	CAKE_STAT_WP_VTIME,		/* rejected: vtime bar */
	CAKE_STAT_WP_STARVED,		/* rejected: starved occupant */
	CAKE_STAT_WP_FIRED,		/* kick issued */
	/* PROBE hold attribution: 5 queue kinds x {placed, wait>300us, wait>1ms} */
	CAKE_STAT_PL_LOCAL,		/* select_cpu direct, own CPU (LOCAL) */
	CAKE_STAT_PL_LOCAL_ON,		/* select_cpu direct, LOCAL_ON|cpu */
	CAKE_STAT_PL_CPUQ_WAKE,		/* enqueue wake into a per-CPU DSQ */
	CAKE_STAT_PL_CPUQ_CONT,		/* enqueue continuation into a per-CPU DSQ */
	CAKE_STAT_PL_GLOBAL,		/* an LLC wake pool */
	CAKE_STAT_H3_LOCAL, CAKE_STAT_H3_LOCAL_ON, CAKE_STAT_H3_CPUQ_WAKE,
	CAKE_STAT_H3_CPUQ_CONT, CAKE_STAT_H3_GLOBAL,
	CAKE_STAT_H10_LOCAL, CAKE_STAT_H10_LOCAL_ON, CAKE_STAT_H10_CPUQ_WAKE,
	CAKE_STAT_H10_CPUQ_CONT, CAKE_STAT_H10_GLOBAL,
	CAKE_STAT_PL_SELF, CAKE_STAT_H3_SELF, CAKE_STAT_H10_SELF, /* LOCAL_ON to the calling CPU */
	CAKE_STAT_HD_SYNC, CAKE_STAT_HD_STARVED, CAKE_STAT_HD_IRQ,
	CAKE_STAT_HD_AFF, CAKE_STAT_HD_CONTENDED, CAKE_STAT_HD_NOTIDLE, /* PROBE: home declines */
	CAKE_STAT_HOME_BUSY,		/* home claim succeeded on a CPU with a running task */
	CAKE_STAT_HOME_LOCALQ,		/* home claim succeeded on a CPU with local DSQ work */
	CAKE_STAT_H3_HOME_BUSY,		/* ... and the wakee then waited >300us */
	/* PROBE site census: shared-line writes, clock reads and claiming kfuncs. */
	CAKE_SITE_QMARK_SET,
	CAKE_SITE_QMARK_SET_SKIP,
	CAKE_SITE_QMARK_CLR,
	CAKE_SITE_QMARK_CLR_SKIP,
	CAKE_SITE_RUNNING,
	CAKE_SITE_FRONTIER_ST,
	CAKE_SITE_WAKE_SERVED_ST,
	CAKE_SITE_WAKE_MARK_ST,
	CAKE_SITE_TACI,
	CAKE_SITE_TACI_WIN,
	CAKE_SITE_TACI_HOME,
	CAKE_SITE_TACI_GROOVE,
	CAKE_SITE_TACI_WARM,
	CAKE_SITE_TACI_NOTIFY,
	CAKE_SITE_TACI_PINNED,
	CAKE_SITE_PICK_IDLE,
	CAKE_SITE_KICK,
	CAKE_SITE_NRQ,
	CAKE_SITE_DSQ_INSERT,
	CAKE_SITE_MOVE_LOCAL,
	CAKE_SITE_KT,
	CAKE_SITE_KT_PERIOD,
	CAKE_SITE_KT_TICKSOON,
	CAKE_SITE_KT_OCCUPANT,
	CAKE_SITE_KT_HANDOFF,
	CAKE_SITE_KT_WAKECLOCK,
	CAKE_SITE_KT_RUNNING,
	CAKE_SITE_KT_PROBE,
	CAKE_SITE_TASK_STORAGE,
	CAKE_SITE_CPU_CURR,
	CAKE_SITE_CORE_CONTENDED,
	CAKE_SITE_STAGE_PROBE,
	CAKE_SITE_TACIW_HOME,
	CAKE_SITE_TACIW_GROOVE,
	CAKE_SITE_TACIW_WARM,
	CAKE_SITE_TACIW_NOTIFY,
	CAKE_SITE_TACIW_PINNED,
	/* clock-pair sums (ns) around one call each; T_CAL is the empty pair. */
	CAKE_SITE_T_NRQ,
	CAKE_SITE_T_TACI,
	CAKE_SITE_T_PICK,
	CAKE_SITE_T_KICK,
	CAKE_SITE_T_CPU_CURR,
	CAKE_SITE_T_TASK_STORAGE,
	CAKE_SITE_T_MOVE,
	CAKE_SITE_T_INSERT,
	CAKE_SITE_T_QMARK,
	CAKE_SITE_T_CAL,
	/* Held seats another task met, by site. */
	CAKE_SITE_LEAK_HOME,
	CAKE_SITE_LEAK_DISPATCH,
	/* Seat rules, one count per fire. */
	CAKE_SITE_SEAT_IMMUNE,
	CAKE_SITE_SEAT_RETAKE,
	CAKE_SITE_SEAT_REROUTE,
	CAKE_SITE_SEAT_DECLINE,
	/* A pool head this CPU may not run, forwarded to one that may. */
	CAKE_SITE_POOL_FORWARD,
	/* A kthread wake sent to the pool. */
	CAKE_SITE_KT_POOL,
	/* Cross-LLC census: destination die differs from the task's previous die. */
	CAKE_SITE_SERIAL_X,
	CAKE_SITE_KT_LOCAL,
	CAKE_SITE_KT_LOCAL_X,
	CAKE_SITE_CLAIM_X,
	CAKE_SITE_NOTIFY_KICK,
	CAKE_SITE_NOTIFY_KICK_X,
	CAKE_SITE_PROBE_FIRED,
	CAKE_SITE_PROBE_FIRED_X,
	CAKE_SITE_POOL_SERVED,
	CAKE_SITE_POOL_SERVED_X,
	CAKE_SITE_STEAL_MOVED,
	CAKE_SITE_STEAL_MOVED_X,
	CAKE_STAT_POOL_DIRECT,		/* pool-bound wake directly used an idle claim */
	CAKE_SITE_KICK_ALONE,		/* continuation alone at its owner: no idle kick */
	/* PROBE: the occupant's remaining grant when a continuation wake pools behind it. */
	CAKE_SITE_GRANT_VACANT,		/* slot mid-switch or torn: not priced */
	CAKE_SITE_GRANT_EXPIRED,	/* past its grant, the tick has not fired */
	CAKE_SITE_GRANT_LT_TICK,	/* expires before the next tick */
	CAKE_SITE_GRANT_GE_TICK,	/* a tick or more of grant left */
	CAKE_STAT_HD_COREBUSY,		/* stage wake skipped its home: sibling busy */
	CAKE_SITE_REJ_IRQ,		/* idle candidate rejected: chronic or live IRQ */
	CAKE_SITE_REJ_TICK,		/* idle candidate rejected: tick within a hop */
	CAKE_SITE_EXPIRY_PREEMPT,	/* continuation wake: occupant past its grant yielded */
	CAKE_SITE_RELEASE,		/* a higher class took the CPU (cake_release_census) */
	CAKE_SITE_ACQUIRE,		/* the CPU came back (hold bands in cake_acquire_hist) */
	CAKE_STAT_SELECT_DIRECT,	/* undecided wake claimed an idle CPU from select_cpu */
	CAKE_SITE_UI_KICK,		/* update_idle saw the pool token and kicked self */
	CAKE_SITE_PEND_KICK,		/* both-empty dispatch waited for a landing */
	CAKE_SITE_PEND_HEAL,		/* unserved reset at zero token: pops the serve never saw */
	CAKE_SITE_RELEASE_SERVE,	/* cpu_release found own-queue work, kicked an idle CPU */
	CAKE_SITE_PINNED_PREEMPT,	/* pinned wake preempted the occupant on its insert */
	CAKE_SITE_PINNED_CLAIM,		/* pinned wake claimed idle owner: local DSQ, no dispatch */
	CAKE_SITE_PINNED_KICK,		/* pinned preempt behind own-queue work, sent as a kick */
	CAKE_SITE_YIELD_KEEP,		/* a yield kept its slice: nothing waits for this CPU */
	CAKE_SITE_YIELD_GIVE,		/* a yield gave its slice up to waiting work */
	CAKE_STAT_NR,
};

#endif /* __CAKE_INTF_H */
