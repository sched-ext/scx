/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake: claimed idle placement, per-CPU continuation queues, per-LLC
 * wake pools and weighted virtual time.
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 */
#include <scx/common.bpf.h>
#include "intf.h"

/* on_cpu changed from signed int to u8. Separate CO-RE flavors keep both
 * reads relocatable; load-time constants prune the unused paths. */
struct task_struct___cake_on_cpu_u8 {
	u8 on_cpu;
} __attribute__((preserve_access_index));

struct task_struct___cake_on_cpu_int {
	int on_cpu;
} __attribute__((preserve_access_index));

static __always_inline bool cake_task_on_cpu(struct task_struct *p)
{
	struct task_struct___cake_on_cpu_u8 *new = (void *)p;
	struct task_struct___cake_on_cpu_int *old = (void *)p;

	if (bpf_core_field_exists(new->on_cpu)) {
		if (bpf_core_field_size(new->on_cpu) == sizeof(new->on_cpu))
			return new->on_cpu != 0;
	}
	if (bpf_core_field_exists(old->on_cpu)) {
		if (bpf_core_field_size(old->on_cpu) == sizeof(old->on_cpu))
			return old->on_cpu != 0;
	}
	/* Unknown layout: retain the idle kick rather than assume continuation. */
	return false;
}

_Static_assert((MAX_CPUS & (MAX_CPUS - 1)) == 0,
	       "MAX_CPUS must remain a power of two");
_Static_assert((RECIP_TABLE_SIZE & (RECIP_TABLE_SIZE - 1)) == 0,
	       "reciprocal table must remain mask-indexable");
_Static_assert(STEAL_SPAN <= MAX_CPUS,
	       "steal matrix span must fit Cake MAX_CPUS");

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* SCX_* enumerators as load-time immediates instead of rodata loads. The
 * #undef is permanent and must follow every scx header. */
#undef SCX_DSQ_LOCAL
#undef SCX_DSQ_LOCAL_ON
#undef SCX_ENQ_WAKEUP
#undef SCX_ENQ_IMMED
#undef SCX_KICK_IDLE
#undef SCX_KICK_PREEMPT
#undef SCX_TASK_QUEUED
#undef SCX_WAKE_SYNC
#define CAKE_DSQ_LOCAL    bpf_core_enum_value(enum scx_dsq_id_flags, SCX_DSQ_LOCAL)
#define CAKE_DSQ_LOCAL_ON bpf_core_enum_value(enum scx_dsq_id_flags, SCX_DSQ_LOCAL_ON)
#define CAKE_ENQ_WAKEUP   bpf_core_enum_value(enum scx_enq_flags,    SCX_ENQ_WAKEUP)
/* The CO-RE enum builtin cannot fold these 64-bit enumerators; spell their
 * scx ABI values here (PREEMPT bit 32, REENQ bit 40). */
#define CAKE_ENQ_PREEMPT  ((u64)1 << 32)
#define CAKE_ENQ_REENQ    ((u64)1 << 40)
/* An idle claim can lose its CPU before insertion; IMMED lets the kernel
 * return it through enqueue. Folds to 0 on a kernel without the flag. */
#define CAKE_ENQ_IMMED    __COMPAT_ENUM_OR_ZERO(enum scx_enq_flags, SCX_ENQ_IMMED)
#define CAKE_KICK_IDLE    bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_IDLE)
#define CAKE_KICK_PREEMPT bpf_core_enum_value(enum scx_kick_flags,   SCX_KICK_PREEMPT)
#define CAKE_TASK_QUEUED  bpf_core_enum_value(enum scx_ent_flags,    SCX_TASK_QUEUED)
/* With IMMED on a local DSQ, core re-enqueues the task itself when a higher
 * class preempts it (ext.c put_prev_task_scx); 0 where the flag is absent. */
#define CAKE_TASK_IMMED   SCX_TASK_IMMED
#define CAKE_WAKE_SYNC    bpf_core_enum_value(enum scx_wake_flags,   SCX_WAKE_SYNC)
#define CAKE_PICK_IDLE_CORE \
	bpf_core_enum_value(enum scx_pick_idle_cpu_flags, SCX_PICK_IDLE_CORE)

/* Declared ahead of the toggle block: the probe census below reads it. */
const volatile u8 cake_tog_probe;		/* diagnostics: placement census, hold attribution, black box (--toggle probe=1) */

/* PROBE placement census for ops.select_cpu, not for scoring: per-CPU map,
 * plain increment on this CPU's copy, no atomic, no shared line. */
enum cake_stat {
	CAKE_STAT_SELECT = 0,		/* ops.select_cpu entries */
	CAKE_STAT_SERIAL,		/* serial-handoff arm placed */
	CAKE_STAT_HOME,			/* prev-cpu warm home claim placed */
	CAKE_STAT_WP_ATTEMPT,		/* wake_preempt reached with a live occupant */
	CAKE_STAT_WP_TINY,		/* wakee burst <= 4us (microsecond-class shape) */
	CAKE_STAT_WP_SMALL,		/* wakee burst <= 64us */
	CAKE_STAT_WP_PROTECT,		/* rejected: protect window not met */
	CAKE_STAT_WP_VTIME,		/* rejected: vtime bar */
	CAKE_STAT_WP_STARVED,		/* rejected: pipeline-stage veto */
	CAKE_STAT_WP_FIRED,		/* kick issued */
	/* PROBE hold attribution: 5 queue kinds x {placed, wait>300us, wait>1ms} */
	CAKE_STAT_PL_LOCAL,		/* select_cpu direct, own CPU (LOCAL) */
	CAKE_STAT_PL_LOCAL_ON,		/* select_cpu direct, LOCAL_ON|cpu */
	CAKE_STAT_PL_CPUQ_WAKE,		/* enqueue wake into a per-CPU DSQ */
	CAKE_STAT_PL_CPUQ_CONT,		/* enqueue continuation into a per-CPU DSQ */
	CAKE_STAT_PL_GLOBAL,		/* WAKE_DSQ */
	CAKE_STAT_H3_LOCAL, CAKE_STAT_H3_LOCAL_ON, CAKE_STAT_H3_CPUQ_WAKE,
	CAKE_STAT_H3_CPUQ_CONT, CAKE_STAT_H3_GLOBAL,
	CAKE_STAT_H10_LOCAL, CAKE_STAT_H10_LOCAL_ON, CAKE_STAT_H10_CPUQ_WAKE,
	CAKE_STAT_H10_CPUQ_CONT, CAKE_STAT_H10_GLOBAL,
	CAKE_STAT_PL_SELF, CAKE_STAT_H3_SELF, CAKE_STAT_H10_SELF, /* LOCAL_ON to the calling CPU */
	CAKE_STAT_HD_SYNC, CAKE_STAT_HD_STARVED, CAKE_STAT_HD_IRQ,
	CAKE_STAT_HD_AFF, CAKE_STAT_HD_CONTENDED, CAKE_STAT_HD_NOTIDLE, /* PROBE: home declines */
	CAKE_STAT_HOME_BUSY,		/* home claim succeeded on a CPU with a running task */
	CAKE_STAT_HOME_LOCALQ,		/* home claim succeeded on a CPU whose local DSQ is non-empty */
	CAKE_STAT_H3_HOME_BUSY,		/* ... and the wakee then waited >300us */
	/* PROBE site census: shared-line writes, clock reads and claiming kfuncs. */
	CAKE_SITE_UI_ENTER,
	CAKE_SITE_UI_ENTER_IDLEW,
	CAKE_SITE_UI_EXIT,
	CAKE_SITE_UI_EXIT_IDLEW,
	CAKE_SITE_QMARK_SET,
	CAKE_SITE_QMARK_SET_SKIP,
	CAKE_SITE_QMARK_CLR,
	CAKE_SITE_QMARK_CLR_SKIP,
	CAKE_SITE_SEAT_CLR,
	CAKE_SITE_SEAT_SET,
	CAKE_SITE_RUNNING,
	CAKE_SITE_FRONTIER_ST,
	CAKE_SITE_WAKE_SERVED_ST,
	CAKE_SITE_WAKE_MARK_ST,
	CAKE_SITE_TACI,
	CAKE_SITE_TACI_WIN,
	CAKE_SITE_TACI_STAGE,
	CAKE_SITE_TACI_HOME,
	CAKE_SITE_TACI_GROOVE,
	CAKE_SITE_TACI_WARM_CORE,
	CAKE_SITE_TACI_WARM_THREAD,
	CAKE_SITE_TACI_WARM,
	CAKE_SITE_TACI_HINT,
	CAKE_SITE_TACI_NOTIFY,
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
	CAKE_SITE_TACIW_STAGE,
	CAKE_SITE_TACIW_HOME,
	CAKE_SITE_TACIW_GROOVE,
	CAKE_SITE_TACIW_WARM_CORE,
	CAKE_SITE_TACIW_WARM_THREAD,
	CAKE_SITE_TACIW_WARM,
	CAKE_SITE_TACIW_HINT,
	CAKE_SITE_TACIW_NOTIFY,
	/* clock-pair sums (ns) around one call each; T_CAL is the empty pair. */
	CAKE_SITE_T_NRQ,
	CAKE_SITE_T_TACI,
	CAKE_SITE_T_PICK,
	CAKE_SITE_T_KICK,
	CAKE_SITE_T_CPU_CURR,
	CAKE_SITE_T_TASK_STORAGE,
	CAKE_SITE_T_MOVE,
	CAKE_SITE_T_INSERT,
	CAKE_SITE_T_UI_IDLEW,
	CAKE_SITE_T_QMARK,
	CAKE_SITE_T_CAL,
	/* Seat leaks, counted whether or not the toggle blocks them. */
	CAKE_SITE_LEAK_HOME,
	CAKE_SITE_LEAK_KICK,
	CAKE_SITE_LEAK_DISPATCH,
	/* Seat rules, one count per fire. */
	CAKE_SITE_SEAT_IMMUNE,
	CAKE_SITE_SEAT_RETAKE,
	CAKE_SITE_SEAT_REROUTE,
	CAKE_SITE_SEAT_DECLINE,
	/* A pool head this CPU may not run, forwarded to one that may. */
	CAKE_SITE_POOL_FORWARD,
	/* A second or later bit tried; a kthread wake sent to the pool. */
	CAKE_SITE_CLAIM_RETRY,
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
	CAKE_SITE_SEAT_SKIP,		/* running: seat held elsewhere, this task holds none */
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
	CAKE_SITE_PEND_HEAL,		/* pool token cleared after the wait bound */
	CAKE_SITE_RELEASE_SERVE,	/* cpu_release found own-queue work and kicked an idle CPU */
	CAKE_SITE_PINNED_PREEMPT,	/* pinned wake preempted the occupant on its insert */
	CAKE_STAT_NR,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CAKE_STAT_NR);
	__type(key, u32);
	__type(value, u64);
} cake_stats SEC(".maps");

/* PROBE census of gates reached, one slot per CPU, beside each construct's
 * fired count. Plain increments: every caller runs with interrupts off on
 * the CPU it names. Never inline in select_cpu: it spilled prev_cpu. */
u64 cake_tried[MAX_CPUS][STATE_SLOT_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
_Static_assert((int)CAKE_TRIED_NR <= (int)STATE_SLOT_WORDS, "one slot per CPU holds the gates");

static __always_inline void cake_tried_inc(u32 cpu, u32 idx)
{
	if (unlikely(cake_tog_probe))
		cake_tried[cpu & (MAX_CPUS - 1)][idx & (CAKE_TRIED_NR - 1)]++;
}

/* The counters live in cold subprograms: a hot-frame probe site is one rodata
 * test and a call the verifier removes with the toggle off, leaving no stack
 * key, lookup frame or spill in the JIT'd stream. */
static __noinline void cake_stat_inc_cold(u32 idx)
{
	u64 *v = bpf_map_lookup_elem(&cake_stats, &idx);

	if (v)
		(*v)++;
}

static __noinline void cake_stat_add_cold(u32 idx, u64 add)
{
	u64 *v = bpf_map_lookup_elem(&cake_stats, &idx);

	if (v)
		*v += add;
}

/* Two counts from one toggle test: a class total and its site. */
static __noinline void cake_stat_inc2_cold(u32 idx, u32 site)
{
	cake_stat_inc_cold(idx);
	cake_stat_inc_cold(site);
}

static __always_inline void cake_stat_inc(u32 idx)
{
	if (unlikely(cake_tog_probe))
		cake_stat_inc_cold(idx);
}

static __always_inline void cake_stat_inc2(u32 idx, u32 site)
{
	if (unlikely(cake_tog_probe))
		cake_stat_inc2_cold(idx, site);
}

/* PROBE site timing: a clock pair around one call, summed per CPU; the
 * running callback records an empty pair (T_CAL) to subtract. The call is
 * spelled in both arms so no clock value lives across it in the hot arm. */
#define CAKE_TIMED_COLD(site, expr) ({						\
	u64 __t0 = bpf_ktime_get_ns();						\
	typeof(expr) __r = (expr);						\
	cake_stat_add_cold((site), bpf_ktime_get_ns() - __t0);			\
	__r; })
#define CAKE_TIMED(site, expr) ({						\
	typeof(expr) __r;							\
	if (unlikely(cake_tog_probe))						\
		__r = CAKE_TIMED_COLD(site, expr);				\
	else									\
		__r = (expr);							\
	__r; })
#define CAKE_TIMED_VOID_COLD(site, stmt) do {					\
	u64 __t0 = bpf_ktime_get_ns();						\
	stmt;									\
	cake_stat_add_cold((site), bpf_ktime_get_ns() - __t0);			\
} while (0)
#define CAKE_TIMED_VOID(site, stmt) do {					\
	if (unlikely(cake_tog_probe))						\
		CAKE_TIMED_VOID_COLD(site, stmt);				\
	else									\
		stmt;								\
} while (0)

/* PROBE site census wrappers: the kfunc, the clock read, plus one per-CPU
 * count each when --toggle probe=1; one toggle test per site when off. */
static __noinline bool cake_taci_probe(s32 cpu, u32 site)
{
	bool won = CAKE_TIMED_COLD(CAKE_SITE_T_TACI,
				   scx_bpf_test_and_clear_cpu_idle(cpu));

	cake_stat_inc2_cold(CAKE_SITE_TACI, site);
	if (won)
		cake_stat_inc2_cold(CAKE_SITE_TACI_WIN,
				    site + (CAKE_SITE_TACIW_STAGE - CAKE_SITE_TACI_STAGE));
	return won;
}

static __always_inline bool cake_taci(s32 cpu, u32 site)
{
	if (unlikely(cake_tog_probe))
		return cake_taci_probe(cpu, site);
	return scx_bpf_test_and_clear_cpu_idle(cpu);
}

/* CLOCK_MONOTONIC: for deltas against kernel ktime fields (start_time,
 * clockevent next_event). One clocksource read per call. */
static __always_inline u64 cake_now(u32 site)
{
	cake_stat_inc2(CAKE_SITE_KT, site);
	return bpf_ktime_get_ns();
}

/* Task age at tick resolution, no clocksource read: jiffies and p->start_time
 * share CLOCK_MONOTONIC at an offset ops.init measures once; a zero tick keeps
 * the precise read. A lifetime quantity only: never a deadline or a delta. */
const volatile u64 cake_tick_ns;	/* the loader's clock_getres(CLOCK_MONOTONIC_COARSE); 0: precise clock */
u64 cake_jiffies_offset;	/* precise ns minus jiffies * tick, at init */

static __always_inline u64 cake_task_age(const struct task_struct *p, u32 site)
{
	u64 now;

	cake_stat_inc2(CAKE_SITE_KT, site);
	if (cake_tick_ns)
		now = bpf_jiffies64() * cake_tick_ns + cake_jiffies_offset;
	else
		now = bpf_ktime_get_ns();
	return time_delta(now, p->start_time);
}

/* The rq clock: stamps compared only with others of this family (run start,
 * pool served), never with cake_now(). Cross-CPU deltas are clamped by the
 * reader: the rq clock orders per CPU only. */
static __always_inline u64 cake_now_rq(u32 site)
{
	cake_stat_inc2(CAKE_SITE_KT, site);
	return scx_bpf_now();
}

static __noinline s32 cake_pick_idle_probe(const struct cpumask *m, u64 flags)
{
	cake_stat_inc_cold(CAKE_SITE_PICK_IDLE);
	return CAKE_TIMED_COLD(CAKE_SITE_T_PICK, scx_bpf_pick_idle_cpu(m, flags));
}

static __always_inline s32 cake_pick_idle(const struct cpumask *m, u64 flags)
{
	if (unlikely(cake_tog_probe))
		return cake_pick_idle_probe(m, flags);
	return scx_bpf_pick_idle_cpu(m, flags);
}

static __noinline void cake_kick_probe(s32 cpu, u64 flags)
{
	cake_stat_inc_cold(CAKE_SITE_KICK);
	CAKE_TIMED_VOID_COLD(CAKE_SITE_T_KICK, scx_bpf_kick_cpu(cpu, flags));
}

static __always_inline void cake_kick(s32 cpu, u64 flags)
{
	if (unlikely(cake_tog_probe))
		cake_kick_probe(cpu, flags);
	else
		scx_bpf_kick_cpu(cpu, flags);
}

static __noinline s32 cake_nrq_probe(u64 dsq_id)
{
	cake_stat_inc_cold(CAKE_SITE_NRQ);
	return CAKE_TIMED_COLD(CAKE_SITE_T_NRQ, scx_bpf_dsq_nr_queued(dsq_id));
}

static __always_inline s32 cake_nrq(u64 dsq_id)
{
	if (unlikely(cake_tog_probe))
		return cake_nrq_probe(dsq_id);
	return scx_bpf_dsq_nr_queued(dsq_id);
}

/* Kfunc bindings through compat.bpf.h's ladders: same-shape arms stay inline
 * (the verifier prunes them); a fallback needing its own stack lives in a
 * __noinline subprogram. Global subprograms return s32: pre-6.19 rejects void. */
/* PROBE (hold attribution): tag every placement with its queue kind. */
static __noinline void cake_probe_place(struct task_struct *p, u64 dsq_id,
					u64 enq_flags);


static __noinline bool cake_dsq_insert_vtime_probe(struct task_struct *p, u64 dsq_id,
						   u64 slice, u64 vtime, u64 enq_flags)
{
	cake_stat_inc_cold(CAKE_SITE_DSQ_INSERT);
	cake_probe_place(p, dsq_id, enq_flags);
	return CAKE_TIMED_COLD(CAKE_SITE_T_INSERT,
			       scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags));
}

static __noinline bool cake_dsq_insert_vtime(struct task_struct *p, u64 dsq_id,
					     u64 slice, u64 vtime, u64 enq_flags)
{
	/* Guarded here: the verifier removes the call, not only its body. */
	if (unlikely(cake_tog_probe))
		return cake_dsq_insert_vtime_probe(p, dsq_id, slice, vtime, enq_flags);
	return scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
}

static __noinline bool cake_dsq_insert_probe(struct task_struct *p, u64 dsq_id,
					     u64 slice, u64 enq_flags)
{
	cake_stat_inc_cold(CAKE_SITE_DSQ_INSERT);
	cake_probe_place(p, dsq_id, enq_flags);
	return CAKE_TIMED_COLD(CAKE_SITE_T_INSERT,
			       scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags));
}

static __always_inline bool cake_dsq_insert(struct task_struct *p, u64 dsq_id,
					    u64 slice, u64 enq_flags)
{
	if (unlikely(cake_tog_probe))
		return cake_dsq_insert_probe(p, dsq_id, slice, enq_flags);
	return scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags);
}

static __noinline bool cake_move_to_local_probe(u64 dsq_id)
{
	cake_stat_inc_cold(CAKE_SITE_MOVE_LOCAL);
	return CAKE_TIMED_COLD(CAKE_SITE_T_MOVE, scx_bpf_dsq_move_to_local(dsq_id, 0));
}

static __always_inline bool cake_move_to_local(u64 dsq_id)
{
	if (unlikely(cake_tog_probe))
		return cake_move_to_local_probe(dsq_id);
	return scx_bpf_dsq_move_to_local(dsq_id, 0);
}

/* The occupant of @cpu; advisory-racy exactly as the kfunc read is.
 * flatten: the compat ladder is spelled in both arms, and LLVM outlines a
 * static inline it sees twice into a BPF call the hot arm would pay. */
static __noinline __attribute__((flatten)) struct task_struct *cake_cpu_curr(s32 cpu)
{
	if (unlikely(cake_tog_probe)) {
		cake_stat_inc_cold(CAKE_SITE_CPU_CURR);
		return CAKE_TIMED_COLD(CAKE_SITE_T_CPU_CURR, __COMPAT_scx_bpf_cpu_curr(cpu));
	}
	return __COMPAT_scx_bpf_cpu_curr(cpu);
}

/* Local-DSQ depth. */
static __always_inline u64 cake_local_nr(s32 cpu)
{
	return cake_nrq(CAKE_DSQ_LOCAL_ON | (u32)cpu);
}

static __noinline struct task_struct *cake_dsq_peek(u64 dsq_id)
{
	return __COMPAT_scx_bpf_dsq_peek(dsq_id);
}

/* Direct field write: scx_bpf_task_set_slice() runs a sub-scheduler authority
 * check cake never needs. */
static __always_inline void cake_set_slice(struct task_struct *p, u64 slice)
{
	p->scx.slice = slice;
}

/* SCHED_* are uapi macros, not a BTF enum, so CO-RE has nothing to hook. */
#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif
#ifndef SCHED_RR
#define SCHED_RR   2
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

/* All mutable hot state in one BSS struct of 128-byte-stride slots, so any two
 * accessed words land in different 64 B lines and different adjacent-line
 * prefetcher pairs whatever the struct's base alignment. */
struct cake_slot {
	u64 word;
	u64 pad[STATE_SLOT_WORDS - 1];
};

struct cake_llc_slot {
	u64 pending;	/* tasks inserted and not yet seen out of the pool: proof */
	u64 unserved;	/* inserts not yet moved out by a serve: the interlock's kick */
	u64 mark;
	u64 served;
	u64 pad[STATE_SLOT_WORDS - 4];
};
_Static_assert(sizeof(struct cake_llc_slot) == STATE_SLOT_BYTES,
	       "cake_llc_slot must keep the slot stride");

struct cake_run_slot {
	u64 stamp;
	u64 sum;
	/* Per-CPU handoff learning: WOKE plus a saturating confidence count of
	 * consecutive wake-then-block-quickly quanta. Owner-written, no atomics. */
	u64 hint;
	/* The holder was just placed behind a stranger; the stranger's re-enqueue
	 * reads it and takes the pool; ops.running clears it. */
	u64 retake;
	/* The stamp's owner: the pid ops.running stamped, 0 from ops.stopping until
	 * the next running. A remote pricer whose occupant read differs from this
	 * pid sees a mid-switch or torn slot and prices nothing. Compiler barriers
	 * on x86 TSO order writer stamp, pid, then the charge after the zero;
	 * reader vtime, pid, stamp. */
	u64 pid;
	/* The slice ops.running granted, beside its start stamp: a remote reader
	 * prices the remaining grant from one line. */
	u64 grant;
	u64 pend_spin;
	/* PROBE, on the slot's second line so the hot ops stay on the first: what
	 * ops.stopping knew about a task a higher class displaced, for
	 * ops.cpu_release (the local DSQ has no peek): burst inputs, slice left,
	 * IMMED, and the release stamp for cpu_acquire's hold length. */
	u64 out_sum;
	u64 out_nvcsw;
	u64 out_slice;
	u64 out_immed;
	u64 release;
	u64 pad[STATE_SLOT_WORDS - 12];
};

enum {
	CAKE_HINT_WOKE		= 1ULL << 0,
	CAKE_HINT_CONF_SHIFT	= 8,
	CAKE_HINT_CONF_MAX	= 3,
	CAKE_NEIGHBOUR_PROBE_DEPTH = 3,
};

/* HARDWARE-ANCHORED: how short a quantum still counts as "woke someone and
 * got out of the way", a property of the CPU's syscall and switch path, not
 * of the timeslice. The loader probes and logs it but does not drive it. */
const volatile u64 cake_handoff_max_ns		= 1464;

/* Mean burst: runtime per voluntary switch, exact to the nanosecond. */
static __always_inline u64 cake_burst_ns(const struct task_struct *p)
{
	return p->se.sum_exec_runtime / (p->nvcsw | 1);
}

/* A burst shorter than one handoff: no relocation costs less than the wait it
 * would cure, so the starved gate keeps the warm home. Cross-multiplied; past
 * 2^32 switches the task leaves the class. */
static __always_inline bool cake_subhandoff(const struct task_struct *p)
{
	u64 n = p->nvcsw | 1;

	return !(n >> 32) && p->se.sum_exec_runtime < cake_handoff_max_ns * n;
}

/* Stage class: cross-multiply only while the product fits; beyond that no u64
 * runtime reaches the threshold. */
static __always_inline bool cake_stage(const struct task_struct *p)
{
	u64 n = p->nvcsw | 1;

	return n <= (~0ULL / SEAT_BURST_MIN_NS) &&
	       p->se.sum_exec_runtime >= SEAT_BURST_MIN_NS * n;
}

/* Does this task wait longer than it runs? run_delay/pcount is the mean wait,
 * sum_exec_runtime/nvcsw the mean burst; cross-multiplied, the shared
 * pre-scale cancels. The threshold is a definition, not a tuning. */
static __always_inline bool cake_starved(const struct task_struct *p)
{
	u64 wait = p->sched_info.run_delay >> CAKE_RATIO_SHIFT;
	u64 run = p->se.sum_exec_runtime >> CAKE_RATIO_SHIFT;

	if (!run)
		return false;
	return wait * (p->nvcsw | 1) > run * (p->sched_info.pcount | 1);
}

/* Does this task wait longer than one turn of its own? cake_starved has no
 * dead zone (a microsecond worker reads starved on the wake hop alone), and
 * relocation pays only past a whole turn: the margin is the task's own slice. */
static __always_inline bool cake_starved_turn(const struct task_struct *p)
{
	u64 wait = p->sched_info.run_delay >> CAKE_RATIO_SHIFT;
	u64 run = p->se.sum_exec_runtime >> CAKE_RATIO_SHIFT;

	if (!run)
		return false;
	return wait * (p->nvcsw | 1) > (run << 1) * (p->sched_info.pcount | 1);
}

_Static_assert(sizeof(struct cake_slot) == STATE_SLOT_BYTES,
	       "cake_slot must preserve cache-isolation stride");
_Static_assert(sizeof(struct cake_run_slot) == STATE_SLOT_BYTES,
	       "cake_run_slot must preserve cache-isolation stride");

struct cake_state {
	/* Global vtime frontier: conditional store from every ops.running. */
	struct cake_slot frontier;
	/* Per-CPU run accounting: stamp is read remotely by wake preemption; sum is
	 * owner-only, so ops.stopping charges runtime with no clock read. One slot,
	 * so ops.running dirties one line. */
	struct cake_run_slot run[MAX_CPUS];
	/* One line per LLC pool: the pending-insert token of the enqueue/update_idle
	 * interlock (raised before the insert, which lands after its op), the
	 * "may hold work" mark the foreign peek reads, and the rq-clock stamp of
	 * the last service. A both-empty dispatch reads one line, not three. */
	struct cake_llc_slot pool[MAX_LLCS];
	/* A claimed remote idle CPU accepts one pool offer at its next dispatch.
	 * Zero means none; otherwise the value is the source pool index + 1. */
	struct cake_slot remote_pool[64];
	/* "DSQ[i] may hold work" hint gating the steal ring, one bit per CPU: a
	 * going-idle dispatch reads QMASK_WORDS words, not one slot per CPU. A stale
	 * bit is benign. */
	u64 qmask[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
};

_Static_assert(sizeof(((struct cake_state *)0)->qmask) <= STATE_SLOT_BYTES,
	       "qmask must fit one cache-isolation slot");

static struct cake_state cake;

/* The retake's occupant read, counted as the gate reached, in its own frame
 * (inline, the count spilled prev_cpu across select_cpu). Only the seat's
 * holder passes the pid test, so the plain count is exact. */
static __noinline struct task_struct *cake_cpu_curr_retake(s32 cpu)
{
	cake_tried_inc((u32)cpu, CAKE_TRIED_RETAKE);
	return cake_cpu_curr(cpu);
}


/* Test before the atomic: the bit shares a word with 63 CPUs, so an
 * unconditional atomic would serialise every dispatch on one line; only an
 * empty<->nonempty transition pays. */
static __always_inline void cake_qmark_set(u32 cpu)
{
	u64 bit;

	cpu &= MAX_CPUS - 1;
	bit = 1ULL << (cpu & 63);
	if (!(cake.qmask[cpu >> 6] & bit)) {
		cake_stat_inc(CAKE_SITE_QMARK_SET);
		CAKE_TIMED_VOID(CAKE_SITE_T_QMARK,
				__atomic_fetch_or(&cake.qmask[cpu >> 6], bit, __ATOMIC_RELAXED));
	} else {
		cake_stat_inc(CAKE_SITE_QMARK_SET_SKIP);
	}
}

static __always_inline void cake_qmark_clear(u32 cpu)
{
	u64 bit;

	cpu &= MAX_CPUS - 1;
	bit = 1ULL << (cpu & 63);
	if (cake.qmask[cpu >> 6] & bit) {
		cake_stat_inc(CAKE_SITE_QMARK_CLR);
		CAKE_TIMED_VOID(CAKE_SITE_T_QMARK,
				__atomic_fetch_and(&cake.qmask[cpu >> 6], ~bit, __ATOMIC_RELAXED));
	} else {
		cake_stat_inc(CAKE_SITE_QMARK_CLR_SKIP);
	}
}

static __always_inline bool cake_qmark_test(u32 cpu)
{
	cpu &= MAX_CPUS - 1;
	return cake.qmask[cpu >> 6] & (1ULL << (cpu & 63));
}

/* Wake-routing emptiness reads the queue count: marks are steal hints, not
 * proof, and the count is a snapshot. __noinline: inlined, the word address
 * pins across the callers' kfuncs. */
static __noinline bool cake_cpu_dsq_idle(u32 cpu)
{
	return !cake_nrq((u64)cpu);
}

/* Republish this CPU's mark from a head peek. __noinline: inlined, LLVM hoists
 * the shared bit and word address above the peek and pins them across it,
 * spilling the caller's cpu id. */
static __noinline void cake_qmark_publish(u32 cpu, bool queued)
{
	if (queued)
		cake_qmark_set(cpu);
	else
		cake_qmark_clear(cpu);
}

/* Foreign rescue skips pools with a clear mark. The setter marks after the
 * insert and retirement clears before its recheck, so a racing clear cannot
 * hide queued work. A single pool has no foreign mark readers. */
extern const volatile u32 nr_llcs;

/* More than one wake pool: rodata, so a one-LLC host folds every foreign pool
 * path. Tested at each caller so the verifier removes the call itself. */
static __always_inline bool cake_multi_llc(void)
{
	return nr_llcs > 1;
}

static __always_inline void cake_wake_mark_set(u32 llc)
{
	if (!cake_multi_llc())
		return;
	if (!__atomic_exchange_n(&cake.pool[llc & (MAX_LLCS - 1)].mark,
				 1, __ATOMIC_SEQ_CST))
		cake_stat_inc(CAKE_SITE_WAKE_MARK_ST);
}

static __always_inline void cake_pool_pending_inc(u32 llc)
{
	struct cake_llc_slot *ps = &cake.pool[llc & (MAX_LLCS - 1)];

	__sync_fetch_and_add(&ps->pending, 1);
	__atomic_fetch_add(&ps->unserved, 1, __ATOMIC_RELAXED);
}

/* A serve moved a task out: the landing the interlock kicks for is over. A
 * kernel-side pop leaves this high; the proof token at zero licenses the
 * reset (cake_pool_unserved). */
static __always_inline void cake_pool_served_dec(u32 llc)
{
	u64 *w = &cake.pool[llc & (MAX_LLCS - 1)].unserved;

	if ((s64)__sync_fetch_and_sub(w, 1) <= 0)
		__sync_fetch_and_add(w, 1);
}

/* Inserts in flight, by proof: a raised unserved with a zero pending token is
 * a pop the serve never saw, cleared here. */
static __always_inline u64 cake_pool_unserved(u32 llc)
{
	struct cake_llc_slot *ps = &cake.pool[llc & (MAX_LLCS - 1)];
	u64 u = ps->unserved;

	if (u && !ps->pending && __sync_bool_compare_and_swap(&ps->unserved, u, 0)) {
		/* An insert between the token read and the CAS raised both words;
		 * its count was taken with the stale one: give it back. */
		if (!ps->pending)
			return 0;
		__sync_fetch_and_add(&ps->unserved, 1);
		return 1;
	}
	return u;
}

static __always_inline void cake_pool_pending_dec(u32 llc)
{
	__atomic_fetch_sub(&cake.pool[llc & (MAX_LLCS - 1)].pending, 1, __ATOMIC_RELAXED);
}

/* The token is proof, not a hint: a pooled task carries its pool + 1 in the
 * low bits of its slice, which cake writes at every insert with those bits
 * zero (cake_slice_from_service) and the kernel touches only while the task
 * runs. The token lowers where the task is next seen out of the pool --
 * ops.running before anything else, a re-enqueue, ops.disable -- so every
 * departure passes one of those and a zero token means an empty pool. */
static __always_inline u64 cake_pool_tag(u64 slice, u32 llc)
{
	return (slice & ~(u64)CAKE_POOL_TAG_MASK) | ((llc & (MAX_LLCS - 1)) + 1);
}

_Static_assert(!(SLICE_NS & CAKE_POOL_TAG_MASK),
	       "the flat slice must leave the pool tag bits clear");

/* Lower the token a tagged slice carries and strip the tag; false when untagged. */
static __always_inline bool cake_pool_seen(struct task_struct *p)
{
	u64 slice = p->scx.slice;
	u32 tag = (u32)(slice & CAKE_POOL_TAG_MASK);

	if (!tag)
		return false;
	cake_pool_pending_dec(tag - 1);
	p->scx.slice = slice & ~(u64)CAKE_POOL_TAG_MASK;
	return true;
}

static __always_inline bool cake_pool_pending(u32 llc)
{
	return cake.pool[llc & (MAX_LLCS - 1)].pending != 0;
}

/* Loader-filled SMT map; -1 means the CPU has no online sibling. */
const volatile s32 cpu_sibling[MAX_CPUS];
/* Loader-proven uniform SMT displacement; 64 selects the generic map walk. */
const volatile u32 cake_smt_shift = 64;
const volatile u64 cake_smt_left;
const volatile u64 cake_smt_right;

/* Loader-maintained, live: sink-ness follows device load, re-probed on the
 * run loop. One slot each; the first word is the hot read. */
u64 cpu_irq_hot_words[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
/* The same set expanded to whole cores by the loader, not on every claim walk. */
u64 cpu_irq_hot_cores[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));

/* Kernel-pushed in-handler depth per CPU from the handler entry/exit
 * tracepoints. Only the owning CPU writes; cross-CPU reads race benignly.
 * Slot-padded: kHz-rate writers never share a line with the readers. */
struct cake_irq_slot {
	u32 depth;
	u8 pad[STATE_SLOT_BYTES - sizeof(u32)];
};
/* One slot per CPU, never a sibling pair: a shared slot took the sink's line
 * away mid-handler and its exit paid the transfer. The loader reads it under -v. */
struct cake_irq_slot cake_irq_live[MAX_CPUS] __attribute__((aligned(STATE_SLOT_BYTES)));

static __always_inline bool cake_cpu_irq_hot(u32 c)
{
	return cpu_irq_hot_words[(c & (MAX_CPUS - 1)) >> 6] & (1ULL << (c & 63));
}

/* Bad wake target: chronically loud (the mask, the average truth) or inside a
 * handler now (the instantaneous truth); each alone misses what the other sees. */
static __always_inline bool cake_cpu_irq_bad(s32 cpu)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);

	return cpu >= 0 && (cake_cpu_irq_hot(c) || cake_irq_live[c].depth);
}

/* The timer is the one interrupt scheduled ahead: a CPU whose next tick fires
 * within one wake hop lands the task inside the handler the live check just
 * missed. Hop cost is the loader's startup probe p99; zero turns this off. */
const volatile u64 cake_wake_hop_ns;

extern const struct tick_device tick_cpu_device __ksym __weak;

/* One clock read per idle search (0 with the predictor off), so every
 * candidate is judged at the same instant. */
static __always_inline u64 cake_tick_clock(void)
{
	if (!cake_wake_hop_ns || !bpf_ksym_exists(&tick_cpu_device))
		return 0;
	return cake_now(CAKE_SITE_KT_TICKSOON);
}

static __noinline bool cake_cpu_tick_soon(s32 cpu, u64 now)
{
	const struct tick_device *td;
	const struct clock_event_device *ed;
	u64 next;

	if (!now)
		return false;
	td = bpf_per_cpu_ptr(&tick_cpu_device, (u32)cpu);
	if (!td)
		return false;
	ed = td->evtdev;
	if (!ed)
		return false;
	/* An overdue next_event means the tick is firing right now; a
	 * stopped nohz tick reads as far-future and never trips. */
	next = (u64)ed->next_event;
	return next <= now + cake_wake_hop_ns;
}

static __always_inline void cake_irq_edge(bool enter)
{
	u32 c = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
	u32 *d = &cake_irq_live[c].depth;

	if (enter)
		(*d)++;
	else if (*d)
		/* Attach can land mid-handler: first exit has no entry. */
		(*d)--;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(cake_irq_enter)
{
	cake_irq_edge(true);
	return 0;
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(cake_irq_leave)
{
	cake_irq_edge(false);
	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(cake_softirq_enter)
{
	cake_irq_edge(true);
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(cake_softirq_leave)
{
	cake_irq_edge(false);
	return 0;
}

/* The CPU id span cake scans: rodata, so the verifier folds the walk bounds;
 * ops.init validates it against nr_cpu_ids. */
const volatile u32 nr_cpu_span;
/* Three times the online CPU count of each CPU's LLC, and of the host. */
const volatile u32 cpu_llc_online3[MAX_CPUS];
const volatile u32 nr_cpu_online3;
/* Idle-word bits tried per claim: at least CLAIM_TRIES_MIN, a quarter of the die. */
const volatile u32 cake_claim_tries = CLAIM_TRIES_MIN;
/* Every present CPU id is below 64: idle words, seats, qmask and die-local
 * claims run on word 0. Keyed on present ids, not the span (hotplug headroom). */
const volatile u8 cake_one_word = 1;

/* One-word host: affinity is one load of the task's own mask word. */
static __always_inline bool cake_allowed(const struct task_struct *p, s32 cpu)
{
	if (cake_one_word && (u32)cpu < 64)
		return (p->cpus_ptr->bits[0] >> ((u32)cpu & 63)) & 1;
	return bpf_cpumask_test_cpu(cpu, p->cpus_ptr);
}

/* Loader-sorted: same CCD, same cache tier, then unrestricted. Fixed span so
 * one binary fits any host; live only with multiple CCDs inside the matrix. */
const volatile u16 cpu_steal_order[STEAL_SPAN * STEAL_SPAN];
/* Populated entries per row, distinct from the possible CPU ID span. */
const volatile u32 nr_steal_cpus;
/* The CPUs sharing each CPU's LLC, one word per CPU. All ones on a one-LLC
 * host or an unreadable topology: the LLC-blind walk. */
const volatile u64 cpu_llc_word[MAX_CPUS];
/* Dense LLC index per CPU (0 on a one-LLC host) and the LLC count. */
const volatile u8 cpu_llc_id[MAX_CPUS];
/* Physical domain identity survives pool collapse and covers every CPU.
 * 0xffff means topology unavailable; narrow masks are only pick accelerators. */
const volatile u16 cpu_llc_domain[MAX_CPUS];
const volatile u32 nr_llcs = 1;

static __always_inline u32 cake_llc_of(s32 cpu)
{
	if (!cake_multi_llc())
		return 0;
	return (u32)cpu_llc_id[(u32)cpu & (MAX_CPUS - 1)] & (MAX_LLCS - 1);
}

static __always_inline u64 cake_pool_dsq(u32 llc)
{
	return (u64)LLC_WAKE_DSQ_BASE + (llc & (MAX_LLCS - 1));
}

/* Physical locality, independent of the pool layout and g89 toggle. */
static __always_inline bool cake_cross_llc(s32 from, s32 to)
{
	u32 a = (u32)from, b = (u32)to;
	u16 da, db;

	if (a >= MAX_CPUS || b >= MAX_CPUS)
		return false;
	/* Keep the masks on the indexing registers: LLVM may combine the
	 * bounds above into (a | b), which the verifier cannot propagate back. */
	barrier_var(a);
	barrier_var(b);
	da = cpu_llc_domain[a & (MAX_CPUS - 1)];
	db = cpu_llc_domain[b & (MAX_CPUS - 1)];
	return da != 0xffff && db != 0xffff && da != db;
}

/* PROBE: count a cross-die placement at @site; called only under the toggle. */
static __noinline void cake_probe_x(u32 site, s32 from, s32 to)
{
	if (cake_cross_llc(from, to))
		cake_stat_inc(site);
}
const volatile u8 steal_order_live;

/* Division-free vtime weights: recip_weight[i] = (1024 << 20) /
 * sched_prio_to_weight[i], indexed by static_prio - 100; SCHED_IDLE's weight
 * 3 sits at IDLE_RECIP_INDEX. Power-of-2 size so the index masks. */
static const u64 recip_weight[RECIP_TABLE_SIZE] = {
	   12097,    14964,    19009,    23204,    29587, /* nice -20..-16 */
	   36830,    46174,    57404,    71827,    90109, /* nice -15..-11 */
	  112457,   140911,   176023,   218952,   274895, /* nice -10..-6  */
	  344037,   429324,   539297,   677012,   840831, /* nice  -5..-1  */
	 1048576,  1309441,  1639300,  2041334,  2538396, /* nice  +0..+4  */
	 3205199,  3947580,  4994148,  6242685,  7837531, /* nice  +5..+9  */
	 9761289, 12341860, 15339168, 19173961, 23860929, /* nice +10..+14 */
	29826161, 37025580, 46684427, 59652323, 71582788, /* nice +15..+19 */
	/* SCHED_IDLE raw weight 3, then padding [41..63] at nice +19. */
	357913941, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
	71582788, 71582788, 71582788, 71582788, 71582788, 71582788,
};

#define CAKE_RECIP_RUNTIME_FAST_MAX (~0ULL / (u64)MAX_RECIP_WEIGHT)

static __noinline u64 cake_scale_vtime_slow(u64 base, u64 runtime, u64 reciprocal)
{
	return base + (runtime >> RECIP_SHIFT) * reciprocal +
	       ((runtime & RECIP_MASK) * reciprocal >> RECIP_SHIFT);
}


/* @base plus @runtime scaled by the reciprocal weight, without a wrapping
 * product: splitting at the fixed-point radix is exact past eight years of
 * nice-19 runtime. @base folds in here so it need not live across the call. */
static __always_inline u64 cake_scale_vtime_add(u64 base, u64 runtime, u32 idx)
{
	u64 reciprocal = recip_weight[idx & RECIP_INDEX_MASK];

	/* Every ordinary slice takes the original single-multiply fast path. */
	if (runtime <= CAKE_RECIP_RUNTIME_FAST_MAX)
		return base + ((runtime * reciprocal) >> RECIP_SHIFT);

	return cake_scale_vtime_slow(base, runtime, reciprocal);
}

static __always_inline u64 cake_scale_vtime(u64 runtime, u32 idx)
{
	return cake_scale_vtime_add(0, runtime, idx);
}

/* Preserve the exact 40-level nice table while honoring SCHED_IDLE weight 3. */
static __always_inline u32 cake_recip_index(const struct task_struct *p)
{
	if (p->policy == SCHED_IDLE)
		return IDLE_RECIP_INDEX;
	return (u32)(p->static_prio - STATIC_PRIO_BASE);
}

/* The occupant of @tcpu: how long it has held the CPU (@ran_out) and its live
 * vtime once that runtime is charged; 0 with no SCX occupant. @curr is the
 * caller's occupant read; @now zero reads the clock after the rejections. */
static __always_inline u64 cake_occupant_live_of(struct task_struct *curr, s32 tcpu,
						 u64 now, u64 *ran_out)
{
	struct cake_run_slot *rs = &cake.run[(u32)tcpu & (MAX_CPUS - 1)];
	u64 cv, ran, stamp;
	u32 cidx;

	if (!curr)
		return 0;
	/* Not on the ext runqueue (RT, DL, idle, or promoted to SCHED_FIFO with a
	 * stale dsq_vtime): nothing to out-deserve or evict. */
	if (!(curr->scx.flags & CAKE_TASK_QUEUED))
		return 0;
	cv = curr->scx.dsq_vtime;
	if (!cv)
		return 0;
	/* Vtime before owner, owner before stamp, the reverse of the writers' order:
	 * an owner match proves an uncharged vtime and a new owner a new stamp; the
	 * remaining tear under-prices, the safe direction. */
	barrier();
	if (rs->pid != (u64)(u32)curr->pid)
		return 0;
	barrier();
	cidx = cake_recip_index(curr);

	stamp = rs->stamp;
	ran = time_delta(now ? now : cake_now_rq(CAKE_SITE_KT_OCCUPANT), stamp);
	*ran_out = ran;
	return cake_scale_vtime_add(cv, ran, cidx);
}

static __noinline u64 cake_occupant_live(s32 tcpu, u64 *ran_out)
{
	return cake_occupant_live_of(cake_cpu_curr(tcpu), tcpu, 0, ran_out);
}

static u64 cake_seat_word __attribute__((aligned(STATE_SLOT_BYTES)));

/* The kernel owns claim and idle-to-idle recovery. Never mirror claimable
 * state in BSS: update_idle does not report every idle-mask refresh. */
/* The kernel's idle masks live for the machine's lifetime (idle.c
 * scx_idle_init_masks; a hotplug restarts the scheduler): their addresses,
 * captured at init, make a hot read one probe load instead of a kfunc pair.
 * Their own section: a kptr makes its map un-mmapable, and the loader reads
 * .bss through the mmap; statics only, so libbpf never asks for one. */
static struct cpumask __kptr_untrusted *cake_mask_cpu SEC(".data.masks");
static struct cpumask __kptr_untrusted *cake_mask_smt SEC(".data.masks");

static __always_inline u64 cake_idle_word(void)
{
	struct cpumask *m = cake_mask_cpu;

	if (likely(m))
		return m->bits[0];
	return 0;
}

static __always_inline u64 cake_core_word(void)
{
	struct cpumask *m = cake_mask_smt;

	if (likely(m))
		return m->bits[0];
	return 0;
}

/* Wide-host home test: the sibling's occupant. It misses an undispatched
 * claim; one-word hosts read the whole-core word instead (cake_core_busy). */
static __always_inline bool cake_core_contended(s32 cpu)
{
	s32 sib = cpu_sibling[(u32)cpu & (MAX_CPUS - 1)];
	struct task_struct *curr;

	cake_stat_inc(CAKE_SITE_CORE_CONTENDED);
	if (sib < 0)
		return false;

	curr = cake_cpu_curr(sib);
	return curr && curr->pid;
}

/* A home must be free as a whole core, including pending sibling claims: the
 * whole-core word the caller holds. Without SMT it is the logical-idle mask. */
static __always_inline bool cake_core_busy(u64 cores, s32 cpu)
{
	cake_stat_inc(CAKE_SITE_CORE_CONTENDED);
	return (u32)cpu >= 64 || !(cores & (1ULL << ((u32)cpu & 63)));
}

/* Lower rank is better. Equal/unknown platforms prune the ranked scan. */
/* Hybrid hosts: the high-capacity CPUs; zero tiers on a uniform host folds the arm. */
const volatile u8 cake_cap_tiers;
const volatile u64 cake_cap_word;
/* cpuidle exit latency per state and the deepest enabled state; 0: no driver. */
const volatile u64 cake_idle_state_ns[CAKE_IDLE_STATES];
const volatile u64 cake_idle_exit_max_ns;
/* CPUs asleep in a state whose exit outlasts one handoff, from the cpu_idle
 * tracepoint; each CPU remembers whether it counted itself. */
u64 cake_deep_idle_word __attribute__((aligned(STATE_SLOT_BYTES)));
u8 cake_idle_deep[MAX_CPUS] __attribute__((aligned(STATE_SLOT_BYTES)));
/* The die a stage thread homes to on a multi-LLC host; the loader keeps it current. */
u64 cake_llc_pref_word __attribute__((aligned(STATE_SLOT_BYTES)));

static __always_inline u64 cake_deep_word(void)
{
	return cake_idle_exit_max_ns ? cake_deep_idle_word : 0;
}

/* Attached only on a host with a cpuidle driver: the governor's chosen state on
 * entry, PWR_EVENT_EXIT on exit. One-word hosts only. */
SEC("tp_btf/cpu_idle")
int BPF_PROG(cake_cpu_idle, u32 state, u32 cpu_id)
{
	u32 c = cpu_id & (MAX_CPUS - 1);

	if (c >= 64)
		return 0;
	if (state == (u32)-1) {
		if (cake_idle_deep[c]) {
			cake_idle_deep[c] = 0;
			__atomic_fetch_and(&cake_deep_idle_word, ~(1ULL << c), __ATOMIC_RELAXED);
		}
	} else if (state < CAKE_IDLE_STATES &&
		   cake_idle_state_ns[state] > cake_handoff_max_ns) {
		cake_idle_deep[c] = 1;
		__atomic_fetch_or(&cake_deep_idle_word, 1ULL << c, __ATOMIC_RELAXED);
	}
	return 0;
}

const volatile u32 cake_rank_tiers;
const volatile u64 cpu_perf_tier[64];
const volatile u64 cpu_perf_known;

static __always_inline u64 cake_rank_tier(u64 w)
{
	u32 i;

	if (cake_rank_tiers <= 1 || (w & ~cpu_perf_known))
		return w;
	for (i = 0; i < 64; i++) {
		u64 best;

		if (i >= cake_rank_tiers)
			break;
		best = w & cpu_perf_tier[i];
		if (best)
			return best;
	}
	return w; /* newly online/unranked CPUs remain usable */
}

/* Serializes owner + reservation-bit transitions on this CPU only. No
 * helpers may run under the lock; all decisions still revalidate claims. */
struct cake_seat_lock {
	struct bpf_spin_lock lock;
	u8 pad[STATE_SLOT_BYTES - sizeof(struct bpf_spin_lock)];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, u32);
	__type(value, struct cake_seat_lock);
} cake_seat_locks SEC(".maps");

enum { CAKE_SEAT_RELEASE, CAKE_SEAT_RUN, CAKE_SEAT_HOLD };

/* A seat: the CPU a stage-class thread blocked on, held for its return. Other
 * wakes skip held cores while another core is free; whoever runs there clears
 * the bit. Apart from the run slot, which every switch dirties. */
struct cake_seat_slot {
	u64 pid;	/* owner persists for retake after running clears the seat bit */
	u64 seq;	/* acquisition generation disambiguates retirement after PID reuse */
	u64 held;	/* this CPU's bit of cake_seat_word: one-CPU tests read their own line */
	u64 pad[STATE_SLOT_WORDS - 3];
};
static struct cake_seat_slot cake_seat[64] __attribute__((aligned(STATE_SLOT_BYTES)));
_Static_assert(sizeof(struct cake_seat_slot) == STATE_SLOT_BYTES,
	       "cake_seat_slot must preserve cache-isolation stride");

/* Readers pass a CPU already tested below 64; the mask must still land on
 * the register the load scales, or the verifier bounds it by MAX_CPUS. */
/* u64 index: a u32 behind the barrier costs a zero-extend pair. The mask
 * follows the barrier so LLVM cannot fold it into a wider one upstream. */
static __always_inline u64 cake_seat_pid(u32 cpu)
{
	u64 c = cpu;

	barrier_var(c);
	return cake_seat[c & 63].pid;
}

/* Is @cpu a held seat? The CPU's own slot line, not the shared word every
 * stage switch rewrites. */
static __always_inline bool cake_seat_held(u32 cpu)
{
	u64 c = cpu;

	barrier_var(c);
	return cake_seat[c & 63].held != 0;
}

/* The word RMWs discard their result: the relaxed fetch form JITs to one
 * lock-prefixed or/and; the __sync form is a cmpxchg loop, two transfers of a
 * line every stage switch writes. lock is a full barrier on x86 either way. */
static __always_inline u64 cake_seat_update(u32 cpu, u32 pid, u32 action, u64 seq)
{
	struct cake_seat_lock *lock;
	struct cake_seat_slot *ss;
	u64 bit;

	if (!cake_one_word || cpu >= 64)
		return 0;
	/* RUN clears only: HOLD and RUN on seat[cpu] both run under rq(cpu),
	 * and RELEASE, the one writer outside it, decides on pid and seq that
	 * RUN never touches. No lock, no map lookup. */
	if (action == CAKE_SEAT_RUN) {
		u64 c = cpu;

		barrier_var(c);
		c &= 63;
		cake_seat[c].held = 0;
		__atomic_fetch_and(&cake_seat_word, ~(1ULL << c), __ATOMIC_RELAXED);
		return 0;
	}
	lock = bpf_map_lookup_elem(&cake_seat_locks, &cpu);
	if (!lock)
		return 0;
	/* The helper can invalidate the verifier's bound on the stack key.
	 * Rebound the reloaded value before the array access and shift. */
	cpu &= 63;
	ss = &cake_seat[cpu];
	bit = 1ULL << cpu;
	bpf_spin_lock(&lock->lock);
	if (action == CAKE_SEAT_HOLD) {
		seq = ++ss->seq;
		ss->pid = pid;
		ss->held = 1;
		__atomic_fetch_or(&cake_seat_word, bit, __ATOMIC_RELAXED);
	} else if (ss->pid == pid && ss->seq == seq) {
		ss->held = 0;
		__atomic_fetch_and(&cake_seat_word, ~bit, __ATOMIC_RELAXED);
		ss->pid = 0;
	}
	bpf_spin_unlock(&lock->lock);
	return seq;
}

/* Is @cpu a seat held by a task other than @p? Counts the leak at @site. */
static __always_inline bool cake_seat_blocks(s32 cpu, const struct task_struct *p,
					     u32 site)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);

	if (c >= 64 || !cake_seat_held(c) ||
	    cake_seat_pid(c) == (u64)(u32)p->pid)
		return false;
	cake_stat_inc(site);
	/* A rodata read, not a constant: folded as true the same way, but a
	 * constant here re-ran select_cpu's register allocation (+10 spills). */
	return cake_one_word != 0;
}
static u64 cake_idle_words[QMASK_WORDS] __attribute__((aligned(STATE_SLOT_BYTES)));
/* PROBE scratch: the pool head this CPU is about to take is from another die. */
static u8 cake_probe_pool_x[MAX_CPUS] __attribute__((aligned(STATE_SLOT_BYTES)));

/* Expand a CPU set through the SMT map: a preference, never a reservation. */
static __always_inline u64 cake_smt_expand(u64 seats)
{
	u64 cores = seats;
	u32 i, shift = cake_smt_shift;

	/* The map factored once at startup; no-SMT maps reduce to identity. */
	if (!shift)
		return seats;
	if (shift < 64)
		return seats | ((seats & cake_smt_left) << shift) |
		       ((seats & cake_smt_right) >> shift);

	for (i = 0; i < 64 && seats; i++) {
		u32 c = (u32)__builtin_ctzll(seats);
		s32 sib = cpu_sibling[c & (MAX_CPUS - 1)];

		if (sib >= 0 && sib < 64)
			cores |= 1ULL << ((u32)sib & 63);
		seats &= seats - 1;
	}
	return cores;
}

/* Chronic IRQ preference on cores; keep the set when every choice is noisy. */
static __always_inline u64 cake_prefer_irq_clean(u64 word, u64 noisy)
{
	u64 clean = word & ~noisy;

	return clean ? clean : word;
}

/* Cold choices: whole core, seat, measured IRQ interference, then platform
 * rank. The caller removes failed claims from its FULL eligible set. */
static __always_inline s32 cake_pick_cold(u64 w, u64 cores, u64 seats, u64 noisy)
{
	u64 best;

	/* Capacity before anything: an idle little core is always a whole core. */
	if (cake_cap_tiers && (w & cake_cap_word))
		w &= cake_cap_word;
	best = w & cores;

	if (!best)
		best = w;
	if (best & ~seats)
		best &= ~seats;
	return (s32)__builtin_ctzll(cake_rank_tier(cake_prefer_irq_clean(best, noisy)));
}

/* PROBE hold attribution -- not for scoring. */
struct cake_probe_tag {
	u64 place_ns;
	u32 kind;
	u32 target;		/* dsq id low bits (cpu) */
	u32 caller;		/* placing CPU */
	u32 waker_pid;
	u64 seats, core_free, thread_free, idle_word;
};

/* PROBE black box: the placement context of the last waits > 10 ms. */
struct cake_bb_rec {
	u64 wait_ns, place_ns, seats, core_free, thread_free, idle_word;
	u32 pid, kind, target, caller, waker_pid, ran_on;
	char comm[16];
};
struct cake_bb_rec cake_blackbox[4];
u32 cake_blackbox_n;

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_probe_tag);
} cake_probe_tags SEC(".maps");

/* Slot-aligned: unaligned it false-shared cake_seat_word's line under probe=1. */
static u32 cake_probe_busy_flag[MAX_CPUS] __attribute__((aligned(STATE_SLOT_BYTES)));

static __noinline void cake_probe_place(struct task_struct *p, u64 dsq_id,
					u64 enq_flags)
{
	struct cake_probe_tag *t;
	u32 kind;
	u32 me;

	me = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

	if (!(dsq_id & CAKE_DSQ_LOCAL_ON) && dsq_id >= (u64)LLC_WAKE_DSQ_BASE &&
	    dsq_id < (u64)LLC_WAKE_DSQ_BASE + MAX_LLCS)
		kind = 4;
	else if (dsq_id & CAKE_DSQ_LOCAL_ON)
		kind = ((u32)dsq_id & (MAX_CPUS - 1)) ==
		       (bpf_get_smp_processor_id() & (MAX_CPUS - 1)) ? 5 : 1;
	else if (dsq_id == CAKE_DSQ_LOCAL)
		kind = 0;
	else
		kind = (enq_flags & CAKE_ENQ_WAKEUP) ? 2 : 3;
	t = bpf_task_storage_get(&cake_probe_tags, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	t->place_ns = cake_now_rq(CAKE_SITE_KT_PROBE);
	t->target = (u32)dsq_id & (MAX_CPUS - 1);
	t->caller = me;
	{
		struct task_struct *w = bpf_get_current_task_btf();

		t->waker_pid = w ? (u32)w->pid : 0;
	}
	t->seats = cake_seat_word; t->core_free = cake_core_word();
	t->thread_free = cake_idle_word(); t->idle_word = cake_idle_word();
	if (cake_probe_busy_flag[me]) {
		kind = 6;
		cake_probe_busy_flag[me] = 0;
	}
	t->kind = kind;
	if (kind == 6)
		return;
	cake_stat_inc(kind == 5 ? CAKE_STAT_PL_SELF : CAKE_STAT_PL_LOCAL + kind);
}

/* Grant the occupant @hc of @tcpu still holds: CAKE_GRANT_VACANT when the slot
 * is mid-switch or torn, 0 once past its grant, else the remainder. Expiry is
 * enforced at the tick alone, so 0 means the tick has not yet stopped it. */
#define CAKE_GRANT_VACANT (~0ULL)

static __always_inline u64 cake_grant_left(struct task_struct *hc, s32 tcpu)
{
	struct cake_run_slot *rs = &cake.run[(u32)tcpu & (MAX_CPUS - 1)];
	u64 ran;

	if (rs->pid != (u64)(u32)hc->pid)
		return CAKE_GRANT_VACANT;
	barrier();
	ran = time_delta(cake_now_rq(CAKE_SITE_KT_OCCUPANT), rs->stamp);
	return ran >= rs->grant ? 0 : rs->grant - ran;
}

/* PROBE: the occupant's remaining grant, in tick bands, behind a pooled wake. */
static __noinline void cake_probe_grant(struct task_struct *hc, s32 tcpu)
{
	u64 rem = cake_grant_left(hc, tcpu);

	if (rem == CAKE_GRANT_VACANT)
		cake_stat_inc_cold(CAKE_SITE_GRANT_VACANT);
	else if (!rem)
		cake_stat_inc_cold(CAKE_SITE_GRANT_EXPIRED);
	else
		cake_stat_inc_cold(cake_tick_ns && rem < cake_tick_ns ?
				   CAKE_SITE_GRANT_LT_TICK : CAKE_SITE_GRANT_GE_TICK);
}

static __noinline void cake_probe_run(struct task_struct *p)
{
	/* Running's clock, from the slot it stamped before this call. */
	u64 now = cake.run[(u32)p->thread_info.cpu & (MAX_CPUS - 1)].stamp;
	struct cake_probe_tag *t;
	u64 wait;

	t = bpf_task_storage_get(&cake_probe_tags, p, 0, 0);
	if (!t || !t->place_ns)
		return;
	wait = time_delta(now, t->place_ns);
	if (wait > 10 * NSEC_PER_MSEC) {
		u32 i = __atomic_fetch_add(&cake_blackbox_n, 1, __ATOMIC_RELAXED) & 3;
		struct cake_bb_rec *b = &cake_blackbox[i];

		b->wait_ns = wait; b->place_ns = t->place_ns; b->seats = t->seats;
		b->core_free = t->core_free; b->thread_free = t->thread_free;
		b->idle_word = t->idle_word; b->pid = (u32)p->pid; b->kind = t->kind;
		b->target = t->target; b->caller = t->caller; b->waker_pid = t->waker_pid;
		b->ran_on = (u32)p->thread_info.cpu;
		__builtin_memcpy(b->comm, p->comm, 16);
	}
	t->place_ns = 0;
	if (wait > 300 * NSEC_PER_USEC)
		cake_stat_inc(t->kind == 6 ? CAKE_STAT_H3_HOME_BUSY :
			      t->kind == 5 ? CAKE_STAT_H3_SELF :
			      CAKE_STAT_H3_LOCAL + (t->kind & 7));
	if (wait > 1000 * NSEC_PER_USEC)
		cake_stat_inc(t->kind == 5 ? CAKE_STAT_H10_SELF :
			      CAKE_STAT_H10_LOCAL + (t->kind & 7));
}

/* Task storage: seat ownership only. */
struct cake_groove {
	u16 seat_cpu; /* owned CPU + 1, including retained retake identity */
	u16 pad;
	u32 seat_pid; /* identity used at acquisition; nonleader exec changes pid */
	u64 seat_seq; /* release only this acquisition, including after PID reuse */
};

/* Seat holders by acquisition pid: ops.running reads one word before asking
 * task storage for a seat to release, so a non-holder switch pays no lookup.
 * Exact under collision (a collider pays the lookup). Atomics: slots are shared. */
static u32 cake_seat_holders[SEAT_HOLDER_SLOTS] __attribute__((aligned(STATE_SLOT_BYTES)));
_Static_assert((SEAT_HOLDER_SLOTS & (SEAT_HOLDER_SLOTS - 1)) == 0,
	       "the holder census indexes by a pid mask");

static __always_inline u32 *cake_seat_holder(u32 pid)
{
	return &cake_seat_holders[pid & (SEAT_HOLDER_SLOTS - 1)];
}

/* A task's callbacks serialize its storage. Seat replacement on another
 * CPU is concurrent, hence the owner-checked locked transition below. */
static __always_inline void cake_seat_retire(struct cake_groove *gr, u32 pid,
					    u32 keep_cpu_plus_one)
{
	if (gr && gr->seat_cpu &&
	    (gr->seat_cpu != keep_cpu_plus_one || gr->seat_pid != pid)) {
		cake_seat_update((u32)gr->seat_cpu - 1, gr->seat_pid,
				 CAKE_SEAT_RELEASE, gr->seat_seq);
		gr->seat_cpu = 0;
		__sync_fetch_and_sub(cake_seat_holder(gr->seat_pid), 1);
	}
}

/* One pool insert: the die's pool, then its mark after the insert. */
static __always_inline void cake_pool_insert(struct task_struct *p, s32 tcpu,
					     u64 slice, u64 vt, u64 flags)
{
	u32 llc = cake_llc_of(tcpu);

	cake_pool_pending_inc(llc);
	cake_dsq_insert_vtime(p, cake_pool_dsq(llc), cake_pool_tag(slice, llc), vt, flags);
	cake_wake_mark_set(llc);
}

/* Retire an observed empty pool, then recheck after the clear. A producer
 * inserts before publishing its mark, so either this recheck or that
 * publication preserves visibility. Only empty transitions pay the atomic. */
static __noinline void cake_wake_mark_retire(u32 llc)
{
	u32 l = llc & (MAX_LLCS - 1);

	if (!cake.pool[l].mark)
		return;
	__atomic_exchange_n(&cake.pool[l].mark, 0, __ATOMIC_SEQ_CST);
	if (cake_nrq(cake_pool_dsq(l)))
		cake_wake_mark_set(l);
}

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_groove);
} cake_grooves SEC(".maps");

static __always_inline struct cake_groove *cake_groove_of(struct task_struct *p)
{
	if (unlikely(cake_tog_probe)) {
		cake_stat_inc_cold(CAKE_SITE_TASK_STORAGE);
		return CAKE_TIMED_COLD(CAKE_SITE_T_TASK_STORAGE,
				       bpf_task_storage_get(&cake_grooves, p, 0,
							    BPF_LOCAL_STORAGE_GET_F_CREATE));
	}
	return bpf_task_storage_get(&cake_grooves, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __noinline u64 cake_task_slice(struct task_struct *p __arg_trusted);
static __noinline s32 cake_pick_idle_clean(struct task_struct *p __arg_trusted);

/* A wakee's wait behind a fresh occupant is bounded by its own slice, not only
 * a fixed frame fraction: a microsecond sleeper waited out the whole SLICE_NS>>4
 * window. The slice already carries the handoff floor the occupant keeps. */
/* Its own frame: inlined at wake_place's two sites it grew the function by 80 insns. */
static __noinline u64 cake_wake_protect(u32 protect_shift, u64 slice)
{
	u64 protect = (u64)SLICE_NS >> protect_shift;

	return slice < protect ? slice : protect;
}

/* Wake preemption verdict: @tcpu's occupant yields once it has run @protect
 * and @p out-deserves its LIVE vtime (dsq_vtime is charged only at stopping).
 * @curr is the caller's read; a changed occupant fails the slot pid test. */
static __noinline bool cake_wake_preempt(struct task_struct *p, struct task_struct *curr,
					 s32 tcpu, u64 protect, u64 now)
{
	u64 ran = 0;
	u64 live = cake_occupant_live_of(curr, tcpu, now, &ran);

	/* PROBE census: which gate refuses the microsecond-class successor. Guarded
	 * so normal execution drops the task reads with the counters. */
	if (cake_tog_probe) {
		u64 se = p->se.sum_exec_runtime;
		u64 n = p->nvcsw | 1;

		cake_stat_inc(CAKE_STAT_WP_ATTEMPT);
		if (!((4096 | n) >> 32) && se < 4096 * n)
			cake_stat_inc(CAKE_STAT_WP_TINY);
		if (!((65536 | n) >> 32) && se < 65536 * n)
			cake_stat_inc(CAKE_STAT_WP_SMALL);
	}

	if (!live)
		return false;
	if (ran < protect) {
		cake_stat_inc(CAKE_STAT_WP_PROTECT);
		return false;
	}
	if (!time_before(p->scx.dsq_vtime, live)) {
		cake_stat_inc(CAKE_STAT_WP_VTIME);
		return false;
	}

	/* Never preempt a pipeline stage; tested last so rejections stay cheap. */
	if (curr && cake_starved(curr)) {
		cake_stat_inc(CAKE_STAT_WP_STARVED);
		return false;
	}
	/* A stage on its own seat is never the victim: cake_starved never covers it
	 * (it runs more than it waits) and every gate above elects its high vtime. */
	if (curr && (u32)tcpu < 64 &&
	    cake_seat_pid((u32)tcpu) == (u64)(u32)curr->pid) {
		cake_stat_inc(CAKE_SITE_SEAT_IMMUNE);
		return false;
	}

	cake_stat_inc(CAKE_STAT_WP_FIRED);
	return true;
}


/* Idle census: one-word hosts popcount the idle word; wider hosts keep this
 * counter, flipped with the bit by ops.update_idle and seeded by ops.init. */
static u64 cake_idle_nr __attribute__((aligned(STATE_SLOT_BYTES)));


/* Claimed warm placement, narrow hosts only: a whole idle core, then any idle
 * thread, each taken with the atomic idle claim so no second waker stacks
 * behind it; -1 sends the wake to the pool. @cores is an older snapshot. */
static __noinline s32 cake_claim_warm(struct task_struct *p __arg_trusted, u64 cores)
{
	u32 prev = (u32)p->thread_info.cpu & (MAX_CPUS - 1);
	u64 w, seats, preferred, noisy;
	s32 c;
	u32 i;

	if (!cake_one_word)
		return -1;
	w = cake_idle_word() & p->cpus_ptr->bits[0];
	if (cake_multi_llc()) {
		u64 pref = cake_llc_pref_word;

		if (cake_stage(p)) {
			/* A stage thread off the preferred die re-homes when a whole
			 * core is free there; on it, its own die as usual. */
			if (pref && !(cpu_llc_word[prev] & pref) && (w & pref & cores)) {
				c = cake_pick_cold(w & pref, cores, cake_smt_expand(cake_seat_word),
						   cpu_irq_hot_cores[0] | cake_deep_word());
				if (cake_taci(c, CAKE_SITE_TACI_WARM))
					return c;
			}
		} else {
			/* A worker follows its waker's die, where the data is. */
			prev = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
		}
	}
	w &= cpu_llc_word[prev];
	if (!w)
		return -1;
	cores &= w;
	/* One IRQ snapshot per search, expanded to cores by the loader. */
	noisy = cpu_irq_hot_cores[0] | cake_deep_word();
	seats = cake_seat_word;
	if (prev < 64 && cake_seat_pid(prev) == (u64)(u32)p->pid)
		seats &= ~(1ULL << prev);
	seats = cake_smt_expand(seats);
	preferred = cores & ~seats;
	if (!preferred)
		preferred = cores;
	preferred = cake_prefer_irq_clean(preferred, noisy);
	/* The task's own core first when it is in the preferred set: without it the
	 * main threads migrated 1.4x more. */
	if (prev < 64 && (preferred & (1ULL << prev))) {
		if (cake_taci((s32)prev, CAKE_SITE_TACI_GROOVE))
			return (s32)prev;
		w &= ~(1ULL << prev);
	}
	/* A failed preferred claim cannot discard less-preferred idle CPUs. */
	for (i = 0; i < cake_claim_tries && w; i++) {
		c = cake_pick_cold(w, cores, seats, noisy);
		if (cake_taci(c, CAKE_SITE_TACI_WARM))
			return c;
		w &= ~(1ULL << c);
	}
	return -1;
}

/* Is the system serial? Co-location bets nothing beats the waker's CPU, true
 * only while almost nothing is runnable; per-CPU emptiness cannot tell. */
/* "Almost nothing runnable" on the waker's die: at least three quarters of
 * its online CPUs idle. Wide hosts keep the machine-wide count. */
static __noinline bool cake_system_serial(u32 wc)
{
	u32 c = wc & (MAX_CPUS - 1);

	if (cake_one_word)
		return (u32)__builtin_popcountll(cake_idle_word() & cpu_llc_word[c]) * 4 >=
		       cpu_llc_online3[c];
	return (u32)cake_idle_nr * 4 >= nr_cpu_online3;
}

/* The serial gate's first call, counted as the gate reached; not inline in
 * select_cpu (see cake_tried). */
static __noinline bool cake_system_serial_tried(u32 wc)
{
	cake_tried_inc(wc, CAKE_TRIED_SERIAL);
	return cake_system_serial(wc);
}

/* Liveness term: nrq counts waiters, not the occupant, so a busy CPU reads
 * empty. Admit when the occupant is within one handoff of its own mean burst
 * end, relative to it, not an absolute age. Operands >= 2^32 take the divide. */
static __noinline bool cake_handoff_yields(s32 tcpu)
{
	struct task_struct *curr = cake_cpu_curr(tcpu);
	struct cake_run_slot *rs = &cake.run[(u32)tcpu & (MAX_CPUS - 1)];
	u64 ran, burst, lim, n;

	/* Missing/non-SCX state cannot prove that an occupant will yield;
	 * neither can a slot the occupant read does not own. */
	if (!curr || !(curr->scx.flags & CAKE_TASK_QUEUED) || !curr->scx.dsq_vtime)
		return false;
	barrier();
	if (rs->pid != (u64)(u32)curr->pid)
		return false;
	barrier();

	ran = time_delta(cake_now_rq(CAKE_SITE_KT_HANDOFF), rs->stamp);
	n = curr->nvcsw | 1;
	lim = ran + cake_handoff_max_ns;

	if (!((lim | n) >> 32))
		return curr->se.sum_exec_runtime < lim * n;

	burst = cake_burst_ns(curr);
	return burst <= ran || burst - ran < cake_handoff_max_ns;
}


/* Exact min(2 * floor(runtime/n), floor(age/(2*n))) with one division: q =
 * floor(min(runtime, age/4)/n); the low bit needs both terms to reach 2*q+1.
 * @q_out is q, the mean burst whenever the runtime term won. */
static __always_inline u64 cake_slice_from_service(u64 runtime, u64 age, u64 n,
						   u64 *q_out)
{
	u64 cycle_budget = age >> PERIOD_SLICE_CAP_SHIFT;
	u64 work = cycle_budget >> 1;
	u64 q, base, want;
	u64 cap = (u64)SLICE_NS >> PERIOD_SLICE_CAP_SHIFT;

	if (runtime < work)
		work = runtime;
	q = work / n;
	*q_out = q;
	base = q * n;
	want = (q << 1) + (runtime - base >= n &&
			   cycle_budget - (base << 1) >= n);

	if (want > cap)
		want = cap;
	if (want < cake_handoff_max_ns)
		want = cake_handoff_max_ns;
	/* The low bits are the pool tag's (cake_pool_tag): zero on every grant. */
	return want & ~(u64)CAKE_POOL_TAG_MASK;
}

/* Twice the mean burst, capped at half the mean cycle and the fixed slice,
 * floored at the handoff cost: a preemption timer from the task's own inputs.
 * Age reads the tick clock; a task younger than a tick reads as one slice old. */
static __noinline u64 cake_task_slice(struct task_struct *p __arg_trusted)
{
	u64 age = cake_task_age(p, CAKE_SITE_KT_PERIOD);
	u64 q;

	if (age < SLICE_NS)
		age = SLICE_NS;
	return cake_slice_from_service(p->se.sum_exec_runtime, age, p->nvcsw | 1, &q);
}

/* Three quarters of the unused slice, as two shifts. */
static __always_inline u64 cake_sleeper_dose(u64 unused)
{
	return (unused >> 1) + (unused >> 2);	/* 3/4 */
}

/* One admit frame: the grant and the insert key from one set of task loads.
 * The key is the sleeper clamp against a floor deepened by the slice fraction
 * left unused, starved tasks only (ungated a worker outranks a stage). */
static __always_inline u64 cake_admit_frame(struct task_struct *p, u64 *vt)
{
	u64 age = cake_task_age(p, CAKE_SITE_KT_PERIOD);
	u64 runtime = p->se.sum_exec_runtime;
	u64 n = p->nvcsw | 1;
	u64 q, slice, depth = 0, lo, d;

	if (age < SLICE_NS)
		age = SLICE_NS;
	slice = cake_slice_from_service(runtime, age, n, &q);
	if (cake_starved(p)) {
		u64 burst = runtime <= ((age >> PERIOD_SLICE_CAP_SHIFT) >> 1) ?
			    q : runtime / n;

		if (burst < SLICE_NS)
			depth = cake_sleeper_dose(SLICE_NS - burst);
	}
	lo = cake.frontier.word - SLICE_NS - depth;
	d = p->scx.dsq_vtime - lo;
	*vt = lo + (d & ~((u64)((s64)d >> 63)));
	return slice;
}

/* The undecided wake: the key returns beside the grant; the insert that ends
 * the route stamps it (cake_wake_place). */
static __noinline u64 cake_wake_admit(struct task_struct *p __arg_trusted, u64 *vt)
{
	return cake_admit_frame(p, vt);
}

/* Every decided admission stamps the key: scx_bpf_dsq_insert() takes no vtime,
 * so a long sleeper admitted directly would keep an arbitrarily old key. Its
 * own frame, not a stack slot at each site. */
static __noinline u64 cake_admit_direct(struct task_struct *p __arg_trusted)
{
	u64 vt;
	u64 slice = cake_admit_frame(p, &vt);

	p->scx.dsq_vtime = vt;
	return slice;
}



/* An undecided wake whose home holds a well-served peer claims an idle CPU as
 * select_cpu's verdict: on LOCAL_ON ext.c inserts synchronously, where the
 * same claim from enqueue takes the deferred-local lane (two rq-lock switches). */
static __noinline s32 cake_select_undecided(struct task_struct *p __arg_trusted,
					    s32 prev_cpu)
{
	struct task_struct *hc;
	s32 idle;

	if (prev_cpu < 0 || (p->flags & PF_KTHREAD) || cake_starved_turn(p))
		return prev_cpu;
	hc = cake_cpu_curr(prev_cpu);
	if (!hc || hc == p || (hc->flags & PF_IDLE) || cake_starved(hc))
		return prev_cpu;
	idle = cake_pick_idle_clean(p);
	if (idle < 0)
		return prev_cpu;	/* enqueue routes it (the pool) */
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)idle, cake_admit_direct(p),
			CAKE_ENQ_IMMED);
	cake_stat_inc(CAKE_STAT_SELECT_DIRECT);
	return idle;
}

/* ops.select_cpu: claimed idle placement, admitted busy home, or the pool.
 * Serial handoff and seat retake are admissions behind an occupant; a wake
 * admitted by none returns prev_cpu and ops.enqueue pools it. */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool stage;
	/* A busy/ineligible home is not a warm-half candidate. */
	bool home_askable = false, seat_blocked;
	u32 home_decline = CAKE_STAT_HD_SYNC;
	u64 cores = 0;
	u64 flags;
	s32 c;

	cake_stat_inc(CAKE_STAT_SELECT);

	/* Serial-handoff co-location: saturated hint, no WAKE_SYNC (SYNC wakes here
	 * collapse pipe throughput), wakee allowed here, both queues empty, occupant
	 * about to yield, never an IRQ sink (an ISR wake mimics the shape). No preempt. */
	{
		u32 wc = bpf_get_smp_processor_id() & (MAX_CPUS - 1);
		struct cake_run_slot *wr = &cake.run[wc];
		bool serial = ((wr->hint >> CAKE_HINT_CONF_SHIFT) &
			       CAKE_HINT_CONF_MAX) >= CAKE_HINT_CONF_MAX;

		if (!(wr->hint & CAKE_HINT_WOKE))
			wr->hint |= CAKE_HINT_WOKE;

		/* No core-contended veto here: a handoff sibling is usually another transient
		 * pair, and the veto exiled mutex pairs from co-location. */
		if (serial && !(wake_flags & CAKE_WAKE_SYNC) &&
		    !cake_cpu_irq_bad((s32)wc) &&
		    cake_allowed(p, (s32)wc) &&
		    cake_system_serial_tried(wc) &&
		    cake_cpu_dsq_idle(wc) &&
		    !cake_local_nr((s32)wc) &&
		    cake_handoff_yields((s32)wc)) {
			if (unlikely(cake_tog_probe)) {
				cake_stat_inc_cold(CAKE_STAT_SERIAL);
				cake_probe_x(CAKE_SITE_SERIAL_X, prev_cpu, (s32)wc);
			}
			c = (s32)wc;
			flags = 0;
			goto place;
		}
	}

	/* Serial placement above needs neither groove storage nor stage class. */
	stage = cake_stage(p);

	/* Seat retake: a stage whose own seat runs a non-stage occupant takes it back
	 * at once, behind the occupant with PREEMPT; ops.enqueue reroutes the evictee
	 * to the pool. RT, idle, pinned and another stage are never evicted; a seat
	 * bit still up means nothing ran there, so the occupant read is skipped. */
	if (stage && prev_cpu >= 0 && (u32)prev_cpu < 64 &&
	    !cake_seat_held((u32)prev_cpu) &&
	    cake_seat_pid((u32)prev_cpu) == (u64)(u32)p->pid &&
	    !cake_cpu_irq_bad(prev_cpu) &&
	    cake_allowed(p, prev_cpu)) {
		struct task_struct *hc = cake_cpu_curr_retake(prev_cpu);

		/* Retake needs eligibility, not a weighted runtime calculation.
		 * Read one occupant instead of pricing one and testing another. */
		if (hc && (hc->scx.flags & CAKE_TASK_QUEUED) &&
		    hc->scx.dsq_vtime && hc != p && hc->nr_cpus_allowed > 1 &&
		    !cake_stage(hc)) {
			cake.run[(u32)prev_cpu & (MAX_CPUS - 1)].retake = 1;
			/* The eviction rides the insert: a local insert with ENQ_PREEMPT
			 * zeroes the occupant's slice and reschedules under the rq lock
			 * enqueue holds; a kick took that lock twice (ext.c dispatch_enqueue). */
			cake_stat_inc(CAKE_SITE_SEAT_RETAKE);
			c = prev_cpu;
			flags = CAKE_ENQ_PREEMPT;
			goto place;
		}
	}

	/* One whole-core snapshot serves the home test and the warm claim's core
	 * preference; the atomic claim still decides admission. */
	if (cake_one_word)
		cores = cake_core_word();
	if (cake_one_word && prev_cpu >= 0 &&
	    (!(wake_flags & CAKE_WAKE_SYNC) || stage) &&
	    cake_core_busy(cores, prev_cpu)) {
		/* PROBE: the exile a one-word host could not count. */
		if (stage)
			cake_stat_inc(CAKE_STAT_HD_COREBUSY);
		goto skip_home;
	}
	/* Another task's held seat is not this task's home. */
	seat_blocked = prev_cpu >= 0 &&
		       cake_seat_blocks(prev_cpu, p, CAKE_SITE_LEAK_HOME);
	/* Cache-warm home claim for a served task, declined on a contended core. A
	 * stage-class wakee keeps its home even on SYNC: its own L1 outweighs the
	 * waker's line. The probe records the decision and makes no claim of its own. */
	if (cake_tog_probe && stage && prev_cpu >= 0 && !seat_blocked)
		cake_stat_inc(CAKE_SITE_STAGE_PROBE);
	if ((!(wake_flags & CAKE_WAKE_SYNC) || stage) &&
	    prev_cpu >= 0 && !seat_blocked) {
		if (cake_starved_turn(p) && !cake_subhandoff(p))
			home_decline = CAKE_STAT_HD_STARVED;
		/* The thread, not the core: the ISR shadow is the handler's own thread; the
		 * sibling pays at most the sink's share of the core, less than a cold home. */
		else if (cake_cpu_irq_bad(prev_cpu))
			home_decline = CAKE_STAT_HD_IRQ;
		else if (!cake_allowed(p, prev_cpu))
			home_decline = CAKE_STAT_HD_AFF;
		else {
			home_askable = true;
			home_decline = !cake_one_word && cake_core_contended(prev_cpu) ?
				CAKE_STAT_HD_CONTENDED : CAKE_STAT_HD_NOTIDLE;
		}
	}
	if (home_askable && home_decline != CAKE_STAT_HD_CONTENDED &&
	    cake_taci(prev_cpu, CAKE_SITE_TACI_HOME)) {

		if (cake_tog_probe) {	/* PROBE: is the claimed CPU actually running someone? */
			struct task_struct *hc = cake_cpu_curr(prev_cpu);
			u32 me = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

			if (hc && hc->pid) {
				cake_stat_inc(CAKE_STAT_HOME_BUSY);
				cake_probe_busy_flag[me] = 1;
			}
			if (cake_nrq(CAKE_DSQ_LOCAL_ON | (u32)prev_cpu) > 0)
				cake_stat_inc(CAKE_STAT_HOME_LOCALQ);
		}
		cake_stat_inc(CAKE_STAT_HOME);
		c = prev_cpu;
		flags = CAKE_ENQ_IMMED;
		goto place;
	}
	if (cake_tog_probe && stage && prev_cpu >= 0 && !seat_blocked)
		cake_stat_inc(home_decline);
skip_home:

	/* Claimed warm placement or the pool; nothing unclaimed below. */
	c = cake_claim_warm(p, cores);

	if (c < 0)
		return cake_select_undecided(p, prev_cpu);
	if (cake_tog_probe)
		cake_probe_x(CAKE_SITE_CLAIM_X, prev_cpu, c);
	flags = CAKE_ENQ_IMMED;
place:
	/* One insert for every decided arm. */
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)c, cake_admit_direct(p), flags);
	return c;
}

/* Idle pick with retries away from a bad target (loud or mid-handler); when
 * only a bad one is idle it still wins: any CPU beats queueing. */
static __noinline s32 cake_pick_idle_clean(struct task_struct *p __arg_trusted)
{
	s32 cpu;

	if (cake_one_word) {
		u32 prev = (u32)p->thread_info.cpu & (MAX_CPUS - 1);
		u64 w = cake_idle_word() & p->cpus_ptr->bits[0] & cpu_llc_word[prev];
		u64 cores;
		u64 seats;
		u64 noisy;
		u64 now;
		u64 rejected = 0;
		u32 i;

		/* A fresh empty snapshot ends this search, not the wakeup
		 * protocol. Do not spend ranking or IRQ reads on it. */
		if (!w)
			return -1;
		cores = cake_core_word() & w;
		seats = cake_smt_expand(cake_seat_word);
		noisy = cpu_irq_hot_cores[0] | cake_deep_word();
		now = cake_tick_clock();

		/* Cleanliness test: loud or mid-handler, then about to take its tick, each
		 * reject counted on its own. */
		for (i = 0; i < cake_claim_tries && w; i++) {
			cpu = cake_pick_cold(w, cores, seats, noisy);
			w &= ~(1ULL << cpu);
			if (cake_cpu_irq_bad(cpu)) {
				cake_stat_inc(CAKE_SITE_REJ_IRQ);
				rejected |= 1ULL << cpu;
			} else {
				cake_tried_inc(bpf_get_smp_processor_id(), CAKE_TRIED_TICK);
				if (cake_cpu_tick_soon(cpu, now)) {
					cake_stat_inc(CAKE_SITE_REJ_TICK);
					rejected |= 1ULL << cpu;
				} else if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY)) {
					return cpu;
				}
			}
		}
		/* Cleanliness is a preference. Never strand work on a die whose
		 * remaining capacity is noisy, reserved, or a partial SMT core. */
		w |= rejected;
		for (i = 0; i < cake_claim_tries && w; i++) {
			cpu = cake_pick_cold(w, cores, seats, noisy);
			if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY))
				return cpu;
			w &= ~(1ULL << cpu);
		}
		/* A die-local pool is offered remotely by its caller. */
		if (cake_multi_llc())
			return -1;
	}

	/* Kernel fallback covers wide hosts and claims lost past CLAIM_TRIES. */
	cpu = cake_pick_idle(p->cpus_ptr, CAKE_PICK_IDLE_CORE);
	if (cpu < 0)
		cpu = cake_pick_idle(p->cpus_ptr, 0);
	return cpu;
}

/* Claim one CPU of @free for pool work, cold-ranked; -1 when every try loses.
 * A kick to an unclaimed CPU raced every direct claim for it. */
static __noinline s32 cake_claim_free(u64 free)
{
	u64 cores = cake_core_word();
	u64 seats = cake_smt_expand(cake_seat_word);
	u64 noisy = cpu_irq_hot_cores[0];
	u32 i;

	for (i = 0; i < cake_claim_tries && free; i++) {
		s32 c = cake_pick_cold(free, cores, seats, noisy);

		if (cake_taci(c, CAKE_SITE_TACI_NOTIFY))
			return c;
		free &= ~(1ULL << ((u32)c & 63));
	}
	return -1;
}

/* Local service had no idle winner. Offer one compatible remote CPU the
 * already-published pool, using the kernel idle claim to bound fan-out. */
static __noinline bool cake_offer_remote(struct task_struct *p __arg_trusted, s32 tcpu)
{
	u64 w, cores, seats, noisy;
	u32 i;

	if (!cake_one_word)
		return false;
	w = cake_idle_word() & p->cpus_ptr->bits[0] &
		~cpu_llc_word[(u32)tcpu & (MAX_CPUS - 1)];
	cores = w ? cake_core_word() & w : 0;
	seats = cake_smt_expand(cake_seat_word);
	noisy = w ? cpu_irq_hot_cores[0] : 0;
	for (i = 0; i < cake_claim_tries && w; i++) {
		s32 cpu = cake_pick_cold(w, cores, seats, noisy);

		if (cake_taci(cpu, CAKE_SITE_TACI_NOTIFY)) {
			u32 target = (u32)cpu;

			/* LLVM knows ctz is < 64 and otherwise removes the mask.
			 * Its BPF byte-table lowering only proves < 256 to the
			 * verifier. Keep the bound on the actual array index. */
			barrier_var(target);
			__atomic_exchange_n(&cake.remote_pool[target & 63].word,
					    (u64)cake_llc_of(tcpu) + 1, __ATOMIC_SEQ_CST);
			cake_kick(cpu, CAKE_KICK_IDLE);
			return true;
		}
		w &= ~(1ULL << ((u32)cpu & 63));
	}
	return false;
}

/* A wake bound to one CPU: the vtime key stays the task's; @flags is IMMED for
 * a claimed idle CPU or PREEMPT for a yielding occupant (slice zero and resched
 * under the rq lock enqueue holds; a kick instead took that lock twice). */
static __always_inline void cake_wake_bind(struct task_struct *p, s32 cpu,
					   u64 slice, u64 vt, u64 flags)
{
	p->scx.dsq_vtime = vt;
	cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)cpu, slice,
			CAKE_ENQ_WAKEUP | flags);
}

/* Place a pool-bound wake: a claimed idle CPU or a yielding occupant takes it
 * on its local queue; only an undecided wake enters the pool, followed by one
 * more idle search, since a CPU that idled meanwhile has nothing to tell it. */
__noinline s32 cake_wake_place(struct task_struct *p __arg_trusted, s32 tcpu,
			       u64 slice, u64 vt,
			       struct task_struct *curr __arg_trusted __arg_nullable)
{
	s32 idle;
	u64 now;

	idle = cake_pick_idle_clean(p);
	if (idle >= 0) {
		if (unlikely(cake_tog_probe)) {
			cake_stat_inc_cold(CAKE_SITE_NOTIFY_KICK);
			cake_probe_x(CAKE_SITE_NOTIFY_KICK_X, tcpu, idle);
		}
		cake_wake_bind(p, idle, slice, vt, CAKE_ENQ_IMMED);
		return 0;
	}

	/* Pre-6.18 compat returns an untrusted rq->curr pointer. Read it here
	 * instead of passing it through the trusted global-subprogram argument.
	 * Kernels with the kfunc retain the caller's single occupant read. */
	if (!bpf_ksym_exists(scx_bpf_cpu_curr))
		curr = cake_cpu_curr(tcpu);

	/* No idle CPU anywhere, and every route owes tcpu a decision: the occupant
	 * loses the CPU or the wakee waits because the occupant deserves it. Cake has
	 * no .tick, so deciding neither leaves the wakee to the watchdog. One clock. */
	now = cake_now_rq(CAKE_SITE_KT_OCCUPANT);
	if (cake_wake_preempt(p, curr, tcpu,
			      cake_wake_protect(PREEMPT_PROTECT_SHIFT, slice), now)) {
		cake_wake_bind(p, tcpu, slice, vt, CAKE_ENQ_PREEMPT);
		return 0;
	}

	/* Globally queued only: hunt a mid-slice compute occupant among the
	 * neighbours; a home-routed wake stays put to keep the locality just bought. */
	{
		u32 cand = (u32)tcpu;
		u32 pi;

		cake_tried_inc(bpf_get_smp_processor_id(), CAKE_TRIED_PROBE);
		for (pi = 0; pi < CAKE_NEIGHBOUR_PROBE_DEPTH; pi++) {
			/* The loader's locality order (same die first), not cpu+1,
			 * which wraps into the other die. */
			if (steal_order_live && (u32)tcpu < STEAL_SPAN) {
				if (pi >= nr_steal_cpus)
					break;
				/* The compare must land on the register the load scales:
				 * the verifier carries no later bound back to it. */
				u32 ix = (u32)tcpu * STEAL_SPAN + pi;

				barrier_var(ix);
				if (ix >= STEAL_SPAN * STEAL_SPAN)
					break;
				cand = cpu_steal_order[ix];
			} else {
				break;
			}
			if (!cake_allowed(p, (s32)cand))
				continue;
			if (cake_wake_preempt(p, cake_cpu_curr((s32)cand), (s32)cand,
					      cake_wake_protect(PROBE_PROTECT_SHIFT, slice),
					      now)) {
				if (unlikely(cake_tog_probe)) {
					cake_stat_inc_cold(CAKE_SITE_PROBE_FIRED);
					cake_probe_x(CAKE_SITE_PROBE_FIRED_X, tcpu, (s32)cand);
				}
				cake_wake_bind(p, (s32)cand, slice, vt, CAKE_ENQ_PREEMPT);
				return 0;
			}
		}
	}

	/* Undecided: the pool, visible to every idle CPU, then the search only the
	 * insert can make complete. */
	cake_pool_insert(p, tcpu, slice, vt, CAKE_ENQ_WAKEUP);
	idle = cake_pick_idle_clean(p);
	if (idle >= 0) {
		cake_kick(idle, CAKE_KICK_IDLE);
		return 0;
	}
	if (cake_multi_llc())
		cake_offer_remote(p, tcpu);
	return 0;
}

/* The wake half of ops.enqueue: route the wakee and insert it where the verdict
 * says. A global subprogram with its own BTF signature and register budget;
 * @p is __arg_trusted so the verifier checks it independently. */
__noinline s32 cake_enqueue_wake(struct task_struct *p __arg_trusted, s32 tcpu)
{
	struct task_struct *curr = cake_cpu_curr(tcpu);

	/* Self-race first: waking the task this CPU is still switching out (the ttwu
	 * wakelist lands here with curr == p, the pipe/futex on-cpu shape). Home is
	 * right even behind a queue; hottest wake path, so it precedes nr_queued. */
	if (curr == p) {
		u64 slice = cake_admit_direct(p);

		cake_qmark_set((u32)tcpu);
		cake_dsq_insert_vtime(p, (u64)(u32)tcpu, slice, p->scx.dsq_vtime,
				      CAKE_ENQ_WAKEUP);
		return 0;
	}

	/* Every other wake is placed by cake_wake_place: a claimed idle CPU, a
	 * yielding occupant, or the pool. The wake bit as a literal: a PRIQ insert
	 * into a custom DSQ reads none of the caller's positional bits. */
	{
		u64 vt;
		u64 slice = cake_wake_admit(p, &vt);

		cake_wake_place(p, tcpu, slice, vt,
				bpf_ksym_exists(scx_bpf_cpu_curr) ? curr : NULL);
	}
	return 0;
}

/* Pinned-wake service: a pinned task's wake takes the continuation path and no
 * other CPU may steal it, so without this it waits out the occupant's slice.
 * Preempts by raw sleep depth @d, read before the insert rewrites dsq_vtime. */
static __noinline bool cake_pinned_wake_preempt(struct task_struct *p __arg_trusted,
						s32 tcpu, u64 d, u64 slice)
{
	u64 cran = 0;
	u64 clive = cake_occupant_live(tcpu, &cran);
	u64 lo, dd, pvt, vs;

	if (!clive)
		return false;

	vs = SLICE_NS;
	lo = cake.frontier.word - vs;
	dd = d + vs;
	pvt = lo - vs + (dd & ~((u64)((s64)dd >> 63)));

	/* The margin is the wakee's own slice, not half of SLICE_NS: a pinned
	 * microsecond sleeper could not out-deserve any occupant by 1.5 ms. */
	return time_before(pvt + slice, clive);
}

/* ops.enqueue: insert into the owner's vtime queue (dsq_id == task_cpu). This
 * callback holds that rq lock, so the owner scans its queue after the insert
 * or core's wakeup_preempt wakes it; then kick one idle CPU so wakers fan out. */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
	/* task_cpu(p) read directly; the kfunc is one load behind a call. */
	s32 tcpu = (s32)p->thread_info.cpu;
	u64 lo, d, slice;
	s32 idle;
	bool pooled = false, alone, pin;

	/* A pooled task re-enqueued before it ran (property change, requeue). */
	cake_pool_seen(p);

	/* Kernel-thread wakes go straight to the selected CPU's local DSQ: softirq and
	 * workqueue service is bounded by one occupant slice, not herd order (the scx
	 * watchdog rides unbound kworkers). Only the wake; a continuation falls through. */


	if ((enq_flags & CAKE_ENQ_WAKEUP) && (p->flags & PF_KTHREAD)) {
		/* A one-CPU task can only land on its own CPU: the pick finds nothing
		 * else by definition. */
		s32 kcpu = p->nr_cpus_allowed > 1 ? cake_pick_idle_clean(p) : -1;
		u64 kflags = enq_flags;

		if (kcpu >= 0)
			kflags |= CAKE_ENQ_IMMED;
		else if (p->nr_cpus_allowed == 1 &&
			 cake_pinned_wake_preempt(p, tcpu, p->scx.dsq_vtime -
						  (cake.frontier.word - SLICE_NS),
						  SLICE_NS)) {
			cake_stat_inc(CAKE_SITE_PINNED_PREEMPT);
			kflags |= CAKE_ENQ_PREEMPT;
		}

		/* Nothing idle was claimed: the pool with the notify's preempt bounds the
		 * wait by a vtime test, not the occupant's slice (display kthreads queued
		 * behind a worker while a CPU sat idle). Pinned kthreads keep the local queue. */
		if (kcpu < 0 && p->nr_cpus_allowed > 1) {
			cake_stat_inc(CAKE_SITE_KT_POOL);
			cake_enqueue_wake(p, tcpu);
			return;
		}

		if (unlikely(cake_tog_probe)) {
			cake_stat_inc_cold(CAKE_SITE_KT_LOCAL);
			if (kcpu >= 0)
				cake_probe_x(CAKE_SITE_KT_LOCAL_X, tcpu, kcpu);
		}
		/* The key only: a kthread's grant is the flat slice. */
		cake_admit_direct(p);
		cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON |
				   (u32)(kcpu >= 0 ? kcpu : tcpu),
				   SLICE_NS, kflags);
		return;
	}

	/* Sleeper clamp max(own, frontier - one slice), branchless and wrap-safe:
	 *   d = own - lo; own >= lo => (s64)d >= 0 => mask = ~0 => lo + d = own
	 *                 own <  lo => (s64)d <  0 => mask =  0 => lo + 0 = lo
	 * Only the continuation arm consumes it. */
	lo = cake.frontier.word - SLICE_NS;
	d  = p->scx.dsq_vtime - lo;

	/* Stage wakeups are global, everything else local: the routing key is the
	 * wakeup bit and the burst class. Single-CPU tasks take the continuation arm. */
	if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed > 1 &&
	    cake_starved_turn(p)) {
		cake_enqueue_wake(p, tcpu);
		return;
	}

	/* The continuation arm: ordinary continuations stay on their owner's queue,
	 * exposed to the steal ring by the mark while keeping L1/L2 warmth. Forced
	 * requeues and seat collisions use the pool. The slice is the task's own. */
	{
		u64 vt = lo + (d & ~((u64)((s64)d >> 63)));
		struct task_struct *hc = NULL;

		/* Anti-collision: home held by an equally well-served peer, whose whole slice
		 * would be waited out while other CPUs sit idle. Reaching here proves p is not
		 * turn-starved, so only the occupant is tested, on the wake arm that reads it. */
		if ((enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed > 1)
			hc = cake_cpu_curr(tcpu);
		if (hc && hc != p && !(hc->flags & PF_IDLE) && !cake_starved(hc)) {
			/* The idle claim for this wake failed in select_cpu; a claim here for
			 * another CPU takes the deferred-local lane. What remains: the occupant's
			 * grant, then the pool. */
			if (unlikely(cake_tog_probe))
				cake_probe_grant(hc, tcpu);
			/* An occupant past its grant that the tick has not yet stopped yields
			 * now; its expiry waited up to a tick's grace. A stage on its own seat
			 * keeps the CPU; a forced requeue keeps its pool escape. */
			if (!(enq_flags & CAKE_ENQ_REENQ) &&
			    (hc->scx.flags & CAKE_TASK_QUEUED) && hc->scx.dsq_vtime &&
			    !((u32)tcpu < 64 &&
			      cake_seat_pid((u32)tcpu) == (u64)(u32)hc->pid) &&
			    !cake_grant_left(hc, tcpu)) {
				cake_stat_inc(CAKE_SITE_EXPIRY_PREEMPT);
				cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)tcpu,
						cake_admit_direct(p), enq_flags | CAKE_ENQ_PREEMPT);
				return;
			}
			slice = cake_admit_direct(p);
			cake_pool_insert(p, tcpu, slice, p->scx.dsq_vtime, enq_flags);
			pooled = true;
			/* Then the search only the insert can make complete: a CPU that idled
			 * between the pick and this insert read the pool empty. */
			goto kick_idle;
		}

		/* A forced requeue cannot rely on service at its owner: cpu_release
		 * evacuates work a higher class displaced. The pool lets kick_idle offer an
		 * idle remote die. Seat collisions take the same route; pinned tasks cannot. */
		if (p->nr_cpus_allowed > 1 &&
		    ((enq_flags & CAKE_ENQ_REENQ) ||
		     ((u32)tcpu < 64 &&
		      cake.run[(u32)tcpu & (MAX_CPUS - 1)].retake &&
		      cake_seat_pid((u32)tcpu) != (u64)(u32)p->pid))) {
			if (cake_tog_probe && !(enq_flags & CAKE_ENQ_REENQ))
				cake_stat_inc(CAKE_SITE_SEAT_REROUTE);
			/* A claimed idle CPU serves the evictee directly, as the anti-collision
			 * arm serves its wake; the pool only when no claim wins. */
			idle = cake_pick_idle_clean(p);
			if (idle >= 0) {
				p->scx.dsq_vtime = vt;
				cake_dsq_insert(p, CAKE_DSQ_LOCAL_ON | (u32)idle,
						cake_task_slice(p), enq_flags | CAKE_ENQ_IMMED);
				cake_stat_inc(CAKE_STAT_POOL_DIRECT);
				return;
			}
			cake_pool_insert(p, tcpu, cake_task_slice(p), vt, enq_flags);
			pooled = true;
			goto kick_idle;
		}

		slice = cake_task_slice(p);
		/* The owner's own put_prev (p still on_cpu) serves its queue on the next
		 * pick; a kicked idle CPU would lose the steal race or move it cold. Any
		 * other re-enqueue has no owner about to pick. The mark is read before
		 * the insert sets it; a stale set bit keeps the kick. */
			alone = !(enq_flags & CAKE_ENQ_WAKEUP) && cake_task_on_cpu(p) &&
			!cake_qmark_test((u32)tcpu);
		/* The own vtime queue is a user DSQ, where the kernel ignores
		 * ENQ_PREEMPT: the verdict, taken before the insert so its inputs
		 * do not outlive it, is delivered as a kick after. */
		pin = (enq_flags & CAKE_ENQ_WAKEUP) && p->nr_cpus_allowed == 1 &&
		      cake_pinned_wake_preempt(p, tcpu, d, slice);
		cake_qmark_set((u32)tcpu);
		cake_dsq_insert_vtime(p, (u64)(u32)tcpu, slice, vt, enq_flags);
		if (pin) {
			cake_stat_inc(CAKE_SITE_PINNED_PREEMPT);
			cake_kick(tcpu, CAKE_KICK_PREEMPT);
		}
		if (alone && !cake_local_nr(tcpu)) {
			cake_stat_inc(CAKE_SITE_KICK_ALONE);
			goto no_idle;
		}
	}

kick_idle:

	/* A one-CPU task's owner is rescheduled by core's activate path (see
	 * above); the pick could only ever name that owner. */
	idle = p->nr_cpus_allowed > 1 ? cake_pick_idle_clean(p) : -1;
	if (idle >= 0) {
		cake_kick(idle, CAKE_KICK_IDLE);
		return;
	}
no_idle:
	if (pooled && cake_multi_llc())
		cake_offer_remote(p, tcpu);
}

/* Staggered ring steal from cpu+1, the anti-herd stagger. The marks are a
 * bitmask, so a span of 64 answers every probe from one load. Missing a bit
 * raised mid-walk costs a steal, never liveness: the owner is woken anyway. */

/* PROBE: count a steal from @idx's queue by die relation, per attempt that
 * reached the move; the move itself may find the queue empty. */
static __always_inline bool cake_probe_steal(u32 ucpu, u32 idx)
{
	if (cake_tog_probe) {
		cake_stat_inc(CAKE_SITE_STEAL_MOVED);
		if (cake_cross_llc((s32)ucpu, (s32)idx))
			cake_stat_inc(CAKE_SITE_STEAL_MOVED_X);
	}
	return true;
}

static __noinline bool cake_ring_walk(u32 ucpu)
{
	u32 nr = nr_cpu_span;
	u32 cw = (u32)-1;	/* which qmask word `m` holds; none yet */
	u64 m = 0;
	u32 i;

	if (CCD_STEAL_POLICY > 0 && steal_order_live && ucpu < STEAL_SPAN) {
		/* One precomputed locality order avoids verifier-multiplying
		 * scan loops. */
		for (i = 0; i < STEAL_SPAN; i++) {
			u32 idx;

			if (i >= nr_steal_cpus)
				break;
			idx = cpu_steal_order[ucpu * STEAL_SPAN + i];
			if (!cake_qmark_test(idx))
				continue;
			/* Across a die only a head a whole slice behind the frontier is
			 * worth the fabric; a fresh wake waits for its own die. */
			if (cake_cross_llc((s32)ucpu, (s32)idx)) {
				struct task_struct *h = cake_dsq_peek((u64)idx);

				if (!h || !time_before(h->scx.dsq_vtime + SLICE_NS,
						       cake.frontier.word))
					continue;
			}
			if (cake_probe_steal(ucpu, idx) && cake_move_to_local((u64)idx))
				return true;
		}
		return false;
	}

	for (i = 1; i < MAX_CPUS; i++) {
		u32 idx = ucpu + i, wi;

		if (i >= nr)
			break;
		if (idx >= nr)
			idx -= nr;
		wi = (idx >> 6) & (QMASK_WORDS - 1);
		if (wi != cw) {
			cw = wi;
			m = cake.qmask[wi];
		}
		if (!(m & (1ULL << (idx & 63))))
			continue;
		if (cake_probe_steal(ucpu, idx) && cake_move_to_local((u64)idx))
			return true;
	}

	return false;
}

/* Nothing marked anywhere is one word read in the caller's frame, not a
 * call into the walk. */
static __always_inline bool cake_ring_steal(u32 ucpu)
{
	if (cake_one_word &&
	    !(cake.qmask[0] & ~(1ULL << (ucpu & 63))))
		return false;
	return cake_ring_walk(ucpu);
}

/* Has the global wake queue gone unserved for a full WALL-clock window? */
static __noinline bool cake_wake_starved(u32 llc)
{
	return time_before(cake.pool[llc & (MAX_LLCS - 1)].served +
			   WAKE_STARVE_WALL_NS, cake_now_rq(CAKE_SITE_KT_WAKECLOCK));
}

/* Record that someone served the global wake queue. */
static __noinline void cake_wake_serve_stamp(u32 llc)
{
	cake_stat_inc(CAKE_SITE_WAKE_SERVED_ST);
	cake.pool[llc & (MAX_LLCS - 1)].served = cake_now_rq(CAKE_SITE_KT_WAKECLOCK);
}

/* An empty wake queue is a served wake queue; otherwise the escalation stays
 * armed where wakes route home. Refreshed only once the stamp is half a window
 * old: every dispatch polls this line, and a blind store is an RFO per switch. */
static __noinline void cake_wake_idle_stamp(u32 llc)
{
	u64 now = cake_now_rq(CAKE_SITE_KT_WAKECLOCK);
	struct cake_llc_slot *ws = &cake.pool[llc & (MAX_LLCS - 1)];

	if (time_before(ws->served + WAKE_STARVE_REFRESH_NS, now)) {
		cake_stat_inc(CAKE_SITE_WAKE_SERVED_ST);
		ws->served = now;
	}
}

/* The both-empty dispatch keeps the clock off its path: the stamp is refreshed
 * when this CPU's own last running stamp says the served stamp is half a
 * window stale. One clock read per half window per die; no stale light die. */
static __always_inline void cake_wake_idle_refresh(u32 llc, u32 ucpu)
{
	u64 served = cake.pool[llc & (MAX_LLCS - 1)].served;
	u64 seen = cake.run[ucpu & (MAX_CPUS - 1)].stamp;

	if (time_before(served + WAKE_STARVE_REFRESH_NS, seen))
		cake_wake_idle_stamp(llc);
}

/* The other dies' pools, taken only when a head is a whole slice behind the
 * frontier or its pool went unserved for the wall; a fresh wake waits. */
static __noinline bool cake_llc_pool_rescue(u32 own)
{
	u32 i;

	for (i = 0; i < MAX_LLCS; i++) {
		struct task_struct *h;

		if (i >= nr_llcs)
			break;
		if (i == own || !cake.pool[i].mark)
			continue;
		h = cake_dsq_peek(cake_pool_dsq(i));
		if (!h) {
			cake_wake_mark_retire(i);
			continue;
		}
		if (time_before(h->scx.dsq_vtime + SLICE_NS, cake.frontier.word) ||
		    cake_wake_starved(i)) {
			if (cake_move_to_local(cake_pool_dsq(i))) {
				cake_pool_served_dec(i);
				cake_wake_serve_stamp(i);
				return true;
			}
		}
	}
	return false;
}

/* An offered pool is eligible at once: the producer found its own die full.
 * Cleared even on failure so a replaced head leaves no stale offer. */
static __noinline bool cake_take_remote(u32 cpu)
{
	u64 offer;
	u32 llc;

	if (!cake_one_word || cpu >= 64)
		return false;
	if (!cake.remote_pool[cpu & 63].word)
		return false;
	offer = __atomic_exchange_n(&cake.remote_pool[cpu & 63].word, 0,
				    __ATOMIC_SEQ_CST);
	if (!offer || offer > nr_llcs)
		return false;
	llc = (u32)(offer - 1) & (MAX_LLCS - 1);
	if (llc == cake_llc_of((s32)cpu))
		return false;
	if (!cake_move_to_local(cake_pool_dsq(llc)))
		return false;
	cake_pool_served_dec(llc);
	cake_wake_serve_stamp(llc);
	return true;
}

/* The dispatch search: earliest eligible vtime of {own queue, pool}, then the
 * ring steal; true when it moved work local. The vtime comparison makes this
 * starvation-free: a stranded pool head's vtime freezes while others advance. */
/* The token is up but nothing has landed: the insert lands after its op
 * returns. Kick self and pick again instead of sleeping past it; a token that
 * nothing lands for (a kernel-side pop) is cleared after the bound. */
static __noinline bool cake_pending_spin(u32 ucpu, u32 llc)
{
	struct cake_run_slot *rs = &cake.run[ucpu & (MAX_CPUS - 1)];

	/* The bound ends the kick storm only: a count that outlives it is a
	 * pop the serve never saw, and the proof token clears it. */
	if (rs->pend_spin < CAKE_PEND_SPIN_MAX) {
		rs->pend_spin++;
		cake_stat_inc(CAKE_SITE_PEND_KICK);
		/* PREEMPT: a refilled prev would otherwise keep the CPU and the
		 * kick would never reach dispatch; an idle curr is unaffected. */
		cake_kick((s32)ucpu, CAKE_KICK_PREEMPT);
	}
	return false;
}

/* No token is the common case: one line read in the caller's frame. */
static __always_inline bool cake_pending_wait(u32 ucpu, u32 llc)
{
	u64 seen = cake_pool_unserved(llc);

	if (!seen) {
		cake.run[ucpu & (MAX_CPUS - 1)].pend_spin = 0;
		return false;
	}
	return cake_pending_spin(ucpu, llc);
}

/* The both-empty exit: retire a stale foreign mark, refresh the served stamp,
 * steal, rescue, or wait for a landing the token promises. */
static __always_inline bool cake_dispatch_empty(u32 ucpu, u32 llc, bool multi)
{
	if (multi)
		cake_wake_mark_retire(llc);
	cake_wake_idle_refresh(llc, ucpu);
	if (cake_ring_steal(ucpu) || (multi && cake_llc_pool_rescue(llc)))
		return true;
	return cake_pending_wait(ucpu, llc);
}

static __noinline bool cake_dispatch_search(s32 cpu)
{
	u32 ucpu = (u32)cpu;
	const bool multi = cake_multi_llc();
	u32 llc = cake_llc_of(cpu);
	u64 pool = cake_pool_dsq(llc);
	u64 first = (u64)ucpu, second = pool;
	struct task_struct *own, *wake;

	if (multi && cake_take_remote(ucpu))
		return true;

	/* Own queue first, pool second, with a one-slice margin: hysteresis, not
	 * fairness slack; without it every CPU takes the pool first and the wake-storm
	 * serialisation returns. An empty own queue costs one count, not an iterator. */
	{
		u32 own_n = 0;
		u32 wake_n;
		bool seat;

		/* A clear mark is proof of an empty own queue: every insert into
		 * DSQ[cpu] sets the mark under this rq's lock, and only this
		 * dispatch clears it. The count runs only behind a set mark. */
		if (cake_qmark_test(ucpu)) {
			own_n = (u32)cake_nrq((u64)ucpu);
			if (!own_n)
				cake_qmark_publish(ucpu, false);
		}
		/* A zero token is proof of an empty pool (cake_pool_seen); a raised
		 * one still needs the count, since the task may have left the pool
		 * for a local queue and not run yet. Both empty, the idle-bound
		 * CPU's common dispatch, leaves before the seat and peek state. */
		if (!own_n && !cake_pool_pending(llc))
			return cake_dispatch_empty(ucpu, llc, multi);
		wake_n = (u32)cake_nrq(pool);
		if (!(own_n | wake_n))
			return cake_dispatch_empty(ucpu, llc, multi);
		/* Test before set: an unconditional store took the shared line every dispatch. */
		if (wake_n)
			cake_wake_mark_set(llc);
		seat = !own_n && cake_one_word && ucpu < 64 && cake_seat_held(ucpu);
		/* Each peek is a DSQ hash lookup: a head is read only to order it against
		 * the other head, to test the seat's free CPUs, or for the census. */
		own = own_n && wake_n ? cake_dsq_peek((u64)ucpu) : NULL;
		/* Seat leak: a held seat with an empty own queue would take pool work and
		 * its stage would return to a busy CPU. While another idle CPU is nobody's
		 * seat, the seat stays idle; that CPU was kicked for the pool wake. */
		wake = wake_n && (own_n || seat) ?
		       cake_dsq_peek(pool) : NULL;
		if (seat) {
			/* A free CPU on this die only; pool work is never kicked across the L3. */
			u64 free = cake_idle_word() & ~cake_seat_word &
				   cpu_llc_word[ucpu & (MAX_CPUS - 1)];

			/* The kick lands where the pool head can run: consume skips a task the
			 * CPU may not serve, and a seat declining a head no free CPU could run
			 * stranded it for the watchdog. Another CPU's own work needs no test. */
			if (wake)
				free &= wake->cpus_ptr->bits[0];
			if (free && (wake || (cake.qmask[0] & ~(1ULL << ucpu)))) {
				cake_stat_inc(CAKE_SITE_LEAK_DISPATCH);
				/* The seat stays idle for its holder; an idle non-seat CPU
				 * is kicked for the work. A head unserved for the wall-clock
				 * window is served here. */
				if (!(wake && cake_wake_starved(llc))) {
					s32 c = cake_claim_free(free);

					/* No claim won: the seat serves the head
					 * itself rather than decline it to nobody. */
					if (c >= 0) {
						cake_stat_inc(CAKE_SITE_SEAT_DECLINE);
						cake_kick(c, CAKE_KICK_IDLE);
						return false;
					}
				}
			}
		}
		if (!wake_n) {
			if (multi)
				cake_wake_mark_retire(llc);
			/* An empty pool is served: the starvation clock matters only when the
			 * own queue competes. Judged by this CPU's run stamp, as on the both-empty
			 * path; a CPU back from a long idle may read the pool starved once. */
			cake_wake_idle_refresh(llc, ucpu);
		}
		/* Either the own queue is empty, the vtime margin favours the pool head, or
		 * nobody served the pool in a wall-clock window. A head that drained between
		 * count and peek falls through to the moves. */
		if (!own_n) {
			first  = pool;
			second = (u64)ucpu;
		} else if (wake) {
			if (!own ||
			    time_before(wake->scx.dsq_vtime + SLICE_NS,
					own->scx.dsq_vtime) ||
			    cake_wake_starved(llc)) {
				first  = pool;
				second = (u64)ucpu;
			}
		}
		if (cake_tog_probe && wake_n) {
			/* PROBE: the pool head's previous die vs this CPU's, before the move that
			 * may take it; its own peek keeps the census off the ordinary condition. */
			struct task_struct *h = wake ? wake : cake_dsq_peek(pool);
			u32 slot = ucpu & (MAX_CPUS - 1);

			/* The index reloads from the stack past the peek; keep the mask on the
			 * register the store uses. */
			barrier_var(slot);
			cake_probe_pool_x[slot] =
				h && cake_cross_llc((s32)h->thread_info.cpu, cpu);
		}
	}
	if (cake_move_to_local(first)) {
		if (first == pool) {
			cake_pool_served_dec(llc);
			cake_wake_serve_stamp(llc);
			if (cake_tog_probe) {
				cake_stat_inc(CAKE_SITE_POOL_SERVED);
				u32 slot = ucpu & (MAX_CPUS - 1);

				barrier_var(slot);
				if (cake_probe_pool_x[slot])
					cake_stat_inc(CAKE_SITE_POOL_SERVED_X);
			}
		}
		return true;
	}
	/* Unconditional: a second healing net under a lost mark; a peek guard spilled. */
	if (cake_move_to_local(second)) {
		if (second == pool) {
			cake_pool_served_dec(llc);
			cake_wake_serve_stamp(llc);
			if (cake_tog_probe) {
				cake_stat_inc(CAKE_SITE_POOL_SERVED);
				u32 slot = ucpu & (MAX_CPUS - 1);

				barrier_var(slot);
				if (cake_probe_pool_x[slot])
					cake_stat_inc(CAKE_SITE_POOL_SERVED_X);
			}
		}
		return true;
	}

	/* Both moves failed: this CPU may not run the head (affinity, migration
	 * disabled) and consume skipped it silently. Forward it to an idle CPU on this
	 * die that may, a non-seat first; re-peek, since a move may have raced. */
	if (cake_one_word) {
		wake = cake_dsq_peek(pool);
		if (wake) {
			u64 can = cake_idle_word() & wake->cpus_ptr->bits[0] &
				  cpu_llc_word[ucpu & (MAX_CPUS - 1)] &
				  ~(1ULL << (ucpu & 63));

			if (can & ~cake_seat_word)
				can &= ~cake_seat_word;
			if (can) {
				s32 c = cake_claim_free(can);

				if (c >= 0) {
					cake_stat_inc(CAKE_SITE_POOL_FORWARD);
					cake_kick(c, CAKE_KICK_IDLE);
				}
			}
		}
	}

	return cake_ring_steal(ucpu) ||
	       (multi && cake_llc_pool_rescue(llc));
}

/* ops.dispatch: run the search; with nothing anywhere, keep prev running with
 * a fresh slice rather than idle. */
void BPF_STRUCT_OPS(cake_dispatch, s32 cpu, struct task_struct *prev)
{
	if (cake_dispatch_search(cpu))
		return;

	/* A local insert made mid-dispatch skipped its preempt: refill prev only
	 * when nothing landed, else the landed task runs next. */
	if (prev && (prev->scx.flags & CAKE_TASK_QUEUED) && !cake_local_nr(cpu)) {
		cake_set_slice(prev, cake_task_slice(prev));
		return;
	}

}

/* PROBE census: releases by the displaced task's arrival path and displacer
 * burst band, and by reason; holds by band. Read from .bss or the exit print. */
u64 cake_release_census[CAKE_RELEASE_PATHS][CAKE_RELEASE_BANDS]
	__attribute__((aligned(STATE_SLOT_BYTES)));
u64 cake_release_reason[CAKE_RELEASE_REASONS] __attribute__((aligned(STATE_SLOT_BYTES)));
u64 cake_acquire_hist[CAKE_RELEASE_BANDS] __attribute__((aligned(STATE_SLOT_BYTES)));

/* log2 band of @ns above CAKE_RELEASE_BAND_SHIFT, saturating. */
static __always_inline u32 cake_release_band(u64 ns)
{
	u64 v = ns >> CAKE_RELEASE_BAND_SHIFT;
	u32 b = 0;

	while (b < CAKE_RELEASE_BANDS - 1 && (v >> (b + 1)))
		b++;
	return b;
}

/* PROBE, observe-only: log2 histograms per CPU of the distributions the
 * fixed thresholds stand for -- the wake-to-run hop of a direct placement,
 * the quantum after a wake (the handoff floor), the mean burst at block (the
 * stage boundary). The loader prints them and their split; nothing reads
 * them in BPF. */
u64 cake_hist[MAX_CPUS][CAKE_HIST_KINDS][CAKE_HIST_BANDS]
	__attribute__((aligned(STATE_SLOT_BYTES)));

static __always_inline u32 cake_hist_band(u64 ns)
{
	u64 v = ns >> CAKE_HIST_SHIFT;
	u32 b = 0;

	while (b < CAKE_HIST_BANDS - 1 && (v >> (b + 1)))
		b++;
	return b;
}

static __always_inline void cake_hist_add(u32 kind, u64 ns)
{
	u32 c = bpf_get_smp_processor_id() & (MAX_CPUS - 1);

	cake_hist[c][kind & (CAKE_HIST_KINDS - 1)][cake_hist_band(ns)]++;
}

/* The direct placement's wait from its enqueue stamp to this run, both on
 * the rq clock; a pooled task's stamp includes its queue wait and is skipped. */
static __noinline void cake_probe_hop(struct task_struct *p, u64 now)
{
	u64 lq;

	if (!(p->scx.flags & CAKE_TASK_IMMED))
		return;
	if (!bpf_core_field_exists(p->sched_info.last_queued))
		return;
	lq = p->sched_info.last_queued;
	if (lq && now > lq)
		cake_hist_add(CAKE_HIST_HOP, now - lq);
}

static __noinline void cake_probe_quantum(struct task_struct *p, u64 used, bool woke)
{
	if (woke)
		cake_hist_add(CAKE_HIST_HANDOFF, used);
	cake_hist_add(CAKE_HIST_BURST, cake_burst_ns(p));
}

static __noinline void cake_probe_release(s32 cpu, struct scx_cpu_release_args *args)
{
	struct cake_run_slot *rs = &cake.run[(u32)cpu & (MAX_CPUS - 1)];
	struct task_struct *d = args->task;
	u32 path = !rs->out_slice ? 2 : rs->out_immed ? 1 : 0;
	u32 reason = (u32)args->reason;
	u64 burst = d ? d->se.sum_exec_runtime / (d->nvcsw | 1) : 0;
	u32 band = cake_release_band(burst);

	cake_stat_inc_cold(CAKE_SITE_RELEASE);
	/* The path is one of three constants, so the verifier carries its
	 * bound; a power-of-two mask folded the IMMED row into the first. */
	__sync_fetch_and_add(&cake_release_census[path]
					     [band & (CAKE_RELEASE_BANDS - 1)], 1);
	__sync_fetch_and_add(&cake_release_reason[reason & (CAKE_RELEASE_REASONS - 1)], 1);
	rs->release = cake_now_rq(CAKE_SITE_KT_OCCUPANT);
}

static __noinline void cake_probe_acquire(s32 cpu)
{
	struct cake_run_slot *rs = &cake.run[(u32)cpu & (MAX_CPUS - 1)];
	u64 hold;

	if (!rs->release)
		return;
	hold = time_delta(cake_now_rq(CAKE_SITE_KT_OCCUPANT), rs->release);
	rs->release = 0;
	cake_stat_inc_cold(CAKE_SITE_ACQUIRE);
	__sync_fetch_and_add(&cake_acquire_hist[cake_release_band(hold) & (CAKE_RELEASE_BANDS - 1)], 1);
}

/* A higher class took this CPU. Core keeps an interrupted SCX task with slice
 * left on this local DSQ, beyond the steal queues; re-enqueue it through the
 * continuation path so idle CPUs can serve it. Free on SCX-to-SCX switches. */
void BPF_STRUCT_OPS(cake_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	if (unlikely(cake_tog_probe))
		cake_probe_release(cpu, args);
	scx_bpf_reenqueue_local();
	/* A continuation left on this CPU's own queue has no owner until the
	 * higher class yields; an idle CPU on the die takes it now. */
	if (cake_one_word && cake_qmark_test((u32)cpu) && cake_nrq((u64)(u32)cpu)) {
		s32 c = cake_claim_free(cake_idle_word() &
					cpu_llc_word[(u32)cpu & (MAX_CPUS - 1)]);

		if (c >= 0) {
			cake_stat_inc(CAKE_SITE_RELEASE_SERVE);
			cake_kick(c, CAKE_KICK_IDLE);
		}
	}
}

/* The higher class is done. Registered only under --toggle probe=1: hold census. */
void BPF_STRUCT_OPS(cake_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	if (unlikely(cake_tog_probe))
		cake_probe_acquire(cpu);
}

/* A task returning with a large weighted lead must not drag active peers' wake
 * floor with it: ordinary advances read nothing remote; an outlier is capped
 * against observed live service, until within the admission window. */
static __noinline u64 cake_frontier_candidate(u64 vtime, u32 cpu)
{
	u64 near = cake.frontier.word + SLICE_NS;
	u64 now;
	int c;

	if (!time_before(near, vtime))
		return vtime;
	/* Running's own clock, from the slot it just stamped. */
	now = cake.run[cpu & (MAX_CPUS - 1)].stamp;
	/* Numeric iteration keeps verifier work bounded on wide CPU spans.
	 * Ordinary advances return before creating the iterator. */
	bpf_for(c, 0, nr_cpu_span < MAX_CPUS ? nr_cpu_span : MAX_CPUS) {
		u64 ran = 0, live;

		if ((u32)c == cpu)
			continue;
		/* One clock for the sweep: running's own. */
		live = cake_occupant_live_of(cake_cpu_curr((s32)c), (s32)c, now, &ran);
		if (live && time_before(live, vtime)) {
			vtime = live;
			if (!time_before(near, vtime))
				break;
		}
	}
	return vtime;
}

/* ops.running: stamp the per-CPU run start and advance the vtime frontier.
 * The frontier store is conditional, not a branchless max: this is the hottest
 * shared line, and a select would dirty it every quantum. Racy is fine. */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
	u64 task_vtime;
	/* The task's CPU: a remote property change fires this op from the caller's
	 * CPU, whose smp id charged a foreign slot. */
	u32 cpu = p->thread_info.cpu;
	struct cake_run_slot *run = &cake.run[cpu & (MAX_CPUS - 1)];
	u64 now = cake_now_rq(CAKE_SITE_KT_RUNNING);

	/* First: the grant below and every later reader want the untagged slice. */
	cake_pool_seen(p);
	run->stamp = now;
	run->sum = p->se.sum_exec_runtime;
	run->retake = 0;
	run->grant = p->scx.slice;
	/* Stamp before owner (see cake_run_slot). */
	barrier();
	run->pid = (u64)(u32)p->pid;
	if (unlikely(cake_tog_probe)) {
		cake_stat_inc_cold(CAKE_SITE_RUNNING);
		CAKE_TIMED_VOID_COLD(CAKE_SITE_T_CAL, (void)0);
		cake_probe_run(p);
		cake_probe_hop(p, now);
	}
	/* The storage read serves only a seat held elsewhere: with no seat bit up
	 * nothing needs release now; while seats are held, the holder count by pid
	 * says whether this task can hold one, so a non-holder skips the lookup. */
	if (cake_one_word) {
		/* The holder census by pid and this CPU's own seat line: the shared
		 * word is read here only by holders. */
		if (*cake_seat_holder((u32)p->pid)) {
			struct cake_groove *gr =
				bpf_task_storage_get(&cake_grooves, p, 0, 0);

			cake_seat_retire(gr, (u32)p->pid, cpu + 1);
		}
		if (cpu < 64 && cake_seat_held(cpu))
			cake_seat_update(cpu, (u32)p->pid, CAKE_SEAT_RUN, 0);
	}

	/* Read after the seat block: nothing charges p's vtime under its own running. */
	task_vtime = p->scx.dsq_vtime;
	/* A store every leading run rewrote a line every CPU reads per op; the
	 * readers work at slice scale, so the frontier moves by the grain. */
	if (time_before(cake.frontier.word + FRONTIER_GRAIN_NS, task_vtime)) {
		task_vtime = cake_frontier_candidate(task_vtime, cpu);
		if (time_before(cake.frontier.word + FRONTIER_GRAIN_NS, task_vtime)) {
			cake_stat_inc(CAKE_SITE_FRONTIER_ST);
			cake.frontier.word = task_vtime;
		}
	}
}

/* ops.stopping: charge the wall time used to the task's vtime, weighted by the
 * reciprocal table (no division on the hot path). */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
	/* The task's CPU, never the callback's (see ops.running). */
	u32 cpu = p->thread_info.cpu;
	u64 used = p->se.sum_exec_runtime -
		   cake.run[cpu & (MAX_CPUS - 1)].sum;
	u32 idx = cake_recip_index(p);
	struct cake_run_slot *rs = &cake.run[cpu & (MAX_CPUS - 1)];
	u64 hint = 0;

	/* The slot is vacant until the next running stamps it; the vtime
	 * charge below stays after the zero (see cake_run_slot). */
	rs->pid = 0;
	barrier();
	/* PROBE census: a task still runnable was displaced or expired; keep what
	 * cpu_release needs to price it. */
	if (unlikely(cake_tog_probe)) {
		if (runnable) {
			rs->out_sum = p->se.sum_exec_runtime;
			rs->out_nvcsw = p->nvcsw;
			rs->out_slice = p->scx.slice;
			rs->out_immed = p->scx.flags & CAKE_TASK_IMMED;
		} else {
			cake_probe_quantum(p, used, rs->hint & CAKE_HINT_WOKE);
		}
	}
	/* Allocation failure means no reservation, never failed scheduling. The stage
	 * class is tested last: the gates cost a load each, the class an imul. */
	if (cake_one_word && !runnable && cpu < 64 && cake_stage(p)) {
		struct cake_groove *gr = cake_groove_of(p);

		if (gr) {
			cake_seat_retire(gr, (u32)p->pid, cpu + 1);
			/* Counted once per held record: a hold kept by the
			 * retire above is already in the count. */
			if (!gr->seat_cpu)
				__sync_fetch_and_add(cake_seat_holder((u32)p->pid), 1);
			gr->seat_seq = cake_seat_update(cpu, (u32)p->pid, CAKE_SEAT_HOLD, 0);
			gr->seat_cpu = (u16)(cpu + 1);
			gr->seat_pid = (u32)p->pid;
		}
	}

	/* Count consecutive wake-then-block-quickly quanta: `used` is exact here and
	 * `runnable` tells blocking from a requeue, so no clock read. Saturating, not
	 * latching one quantum (a producer trips that); a preempted task leaves it. */
	hint = (rs->hint >> CAKE_HINT_CONF_SHIFT) & CAKE_HINT_CONF_MAX;
	if (!runnable) {
		if ((rs->hint & CAKE_HINT_WOKE)) {
			if (used < cake_handoff_max_ns) {
				if (hint < CAKE_HINT_CONF_MAX)
					hint++;
			} else {
				hint = 0;
			}
		} else {
			hint = 0;
		}
	}
	hint <<= CAKE_HINT_CONF_SHIFT;
	rs->hint = hint;


	/* Direct write: scx_bpf_task_set_dsq_vtime()'s authority check cost +28-36%
	 * on this, the hottest per-switch callback. */
	p->scx.dsq_vtime += cake_scale_vtime(used, idx);
}

/* ops.update_idle: the idle census. KEEP_BUILTIN_IDLE keeps the kernel tracking
 * every pick uses; this only mirrors it into one word. */
void BPF_STRUCT_OPS(cake_update_idle, s32 cpu, bool idle)
{
	u32 c = (u32)cpu & (MAX_CPUS - 1);
	u64 bit = 1ULL << (c & 63);

	/* The kernel sets the idle bit before this call: an insert that read the
	 * old bit raised the token, seen here; kicking self runs dispatch again. */
	if (cake_one_word) {
		if (idle && cake_pool_unserved(cake_llc_of(cpu))) {
			cake_stat_inc(CAKE_SITE_UI_KICK);
			scx_bpf_kick_cpu(cpu, 0);
		}
		return;
	}
	/* Wide-host count is actual idle occupancy, never claim availability. */
	if (idle) {
		if (!(__sync_fetch_and_or(&cake_idle_words[c >> 6], bit) & bit))
			__sync_fetch_and_add(&cake_idle_nr, 1);
	} else {
		if (__sync_fetch_and_and(&cake_idle_words[c >> 6], ~bit) & bit)
			__sync_fetch_and_sub(&cake_idle_nr, 1);
	}
}

/* ops.enable: a fresh task starts at the vtime frontier, neither starved nor
 * granted windfall credit. */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	scx_bpf_task_set_dsq_vtime(p, cake.frontier.word);
}

/* ops.exit_task: a holder that exits gives its seat back. Only running on that
 * CPU clears a seat, and on a quiet host nothing runs there, so a recycled pid
 * would inherit the retake and the immunity. */
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct cake_groove *gr;

	if (!cake_one_word)
		return;
	gr = bpf_task_storage_get(&cake_grooves, p, 0, 0);
	cake_seat_retire(gr, (u32)p->pid, 0);
}

/* ops.disable: a holder that leaves the class (RT promotion) while blocked
 * would otherwise keep its seat until something ran on that CPU. */
void BPF_STRUCT_OPS(cake_disable, struct task_struct *p)
{
	struct cake_groove *gr;

	/* A pooled task leaving the class before it ran. */
	cake_pool_seen(p);
	if (!cake_one_word)
		return;
	gr = bpf_task_storage_get(&cake_grooves, p, 0, 0);
	cake_seat_retire(gr, (u32)p->pid, 0);
}

/* ops.init (sleepable): confirm the loader's CPU span covers nr_cpu_ids, then
 * create one vtime DSQ per possible CPU (dsq_id == cpu) and one pool per LLC.
 * A span narrower than nr_cpu_ids would stop the steal ring short: refuse it. */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	{
		const struct cpumask *im = scx_bpf_get_idle_cpumask();
		const struct cpumask *sm = scx_bpf_get_idle_smtmask();

		if (im) {
			cake_mask_cpu = (struct cpumask *)im;
			scx_bpf_put_idle_cpumask(im);
		}
		if (sm) {
			cake_mask_smt = (struct cpumask *)sm;
			scx_bpf_put_idle_cpumask(sm);
		}
	}
	u32 nr = scx_bpf_nr_cpu_ids();
	s32 i, ret;

	if (nr > MAX_CPUS) {
		scx_bpf_error("nr_cpu_ids %u exceeds Cake MAX_CPUS %u", nr,
			      MAX_CPUS);
		return -EINVAL;
	}
	if (nr_cpu_span < nr) {
		scx_bpf_error("loader CPU span %u is narrower than nr_cpu_ids %u",
			      nr_cpu_span, nr);
		return -EINVAL;
	}

	/* Tick clock for task age: the offset to the precise clock, measured once. */
	if (cake_tick_ns)
		cake_jiffies_offset = bpf_ktime_get_ns() - bpf_jiffies64() * cake_tick_ns;

	bpf_for(i, 0, nr) {
		ret = scx_bpf_create_dsq((u64)(u32)i, -1);
		if (ret)
			return ret;
	}
	/* One wake pool per LLC; a one-LLC host, or g89=0, uses pool 0. */
	bpf_for(i, 0, MAX_LLCS) {
		if ((u32)i >= nr_llcs)
			break;
		ret = scx_bpf_create_dsq(cake_pool_dsq((u32)i), -1);
		if (ret)
			return ret;
	}

	/* Seed wide actual-idle occupancy only. */
	if (!cake_one_word) {
		const struct cpumask *im = scx_bpf_get_idle_cpumask();
		u32 c, n = 0;

		bpf_for(c, 0, nr_cpu_span) {
			if (bpf_cpumask_test_cpu((s32)c, im)) {
				cake_idle_words[(c & (MAX_CPUS - 1)) >> 6] |=
					1ULL << (c & 63);
				n++;
			}
		}
		scx_bpf_put_idle_cpumask(im);
		cake_idle_nr = n;
	}

	return 0;
}

/* Core event counters, copied out at exit for the loader's report. */
struct scx_event_stats cake_events;

void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	__COMPAT_scx_bpf_events(&cake_events, sizeof(cake_events));
	UEI_RECORD(uei, ei);
}

/* ALLOW_QUEUED_WAKEUP lets remote activation ride the batched TTWU queue instead
 * of taking the remote rq lock per wake, so no policy here may depend on
 * process identity or assume enqueue's current is the waker. */
SCX_OPS_DEFINE(cake_ops,
	       .select_cpu	= (void *)cake_select_cpu,
	       .enqueue		= (void *)cake_enqueue,
	       .dispatch	= (void *)cake_dispatch,
	       .cpu_release	= (void *)cake_cpu_release,
	       .cpu_acquire	= (void *)cake_cpu_acquire,
	       .running		= (void *)cake_running,
	       .stopping	= (void *)cake_stopping,
	       .update_idle	= (void *)cake_update_idle,
	       .enable		= (void *)cake_enable,
	       .exit_task	= (void *)cake_exit_task,
	       .disable		= (void *)cake_disable,
	       .init		= (void *)cake_init,
	       .exit		= (void *)cake_exit,
	       .flags		= SCX_OPS_ALLOW_QUEUED_WAKEUP |
				  SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms	= WATCHDOG_TIMEOUT_MS,
	       .name		= "cake");
