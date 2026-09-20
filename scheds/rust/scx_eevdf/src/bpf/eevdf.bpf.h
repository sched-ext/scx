/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The types, the globals and the small accessors every part of the
 * scheduler is built on: the cid space and the tables indexed by it, the
 * per-task and per-cid state, and the two clocks everything is timed in.
 *
 * scx_eevdf is one translation unit: main.bpf.c includes the component
 * sources, as kernel/sched/build_policy.c includes fair.c and the rest. A
 * header carries what its component's callers need to see; a .c carries
 * the component itself. Nothing here has to be reachable across objects,
 * so everything stays static and the compiler inlines across the whole
 * scheduler.
 */
#pragma once

#include <scx/common.bpf.h>
#include <lib/arena_map.h>
#include <lib/edq.h>
#include <lib/ravg.h>
#include <lib/arena_loop.h>
#include <lib/sdt_alloc.h>
#include "intf.h"

#ifndef __BPF_FEATURE_ADDR_SPACE_CAST
#error "scx_eevdf requires a compiler with bpf_addr_space_cast support"
#endif

/*
 * The verifier only associates a program with the arena if the program
 * loads the map itself. Reaching the arena through a pointer kept in a
 * global does not, so every program that touches arena memory says so.
 */
#define TOUCH_ARENA()	do { asm volatile("" :: "r"(&arena)); } while (0)

/*
 * How many times the idle CPU scan tries again after losing a claim.
 */
#define CLAIM_RETRIES	4

/*
 * The globals written on the hot path sit on cache lines of their own.
 *
 * The rest of .bss is read by every op on every CPU (the sizes, the arena
 * pointers) and a written word sharing a line with them makes every one of
 * those reads a miss: the layout of .bss follows the whims of the compiler
 * and adding one global once moved nr_words next to the system vruntime
 * that used to live here, which cost ~5% of the BPF time.
 */
#define __hot_written	__attribute__((aligned(64)))

/*
 * The options user space sets before the scheduler is loaded, and the few
 * counters that are not static, defined in main.bpf.c. They are declared
 * here because the inline helpers below and in the component headers read
 * them, and those are compiled before main.bpf.c defines them.
 */
extern const volatile bool cpufreq_enabled;
extern const volatile bool numa_enabled;
extern const volatile bool smt_enabled;
extern const volatile bool force_smt_asym_packing;
extern const volatile bool smt_whole_core;
extern const volatile bool cgroup_enabled;
extern const volatile bool cpu_max_enabled;
extern const volatile bool no_wake_sync;
extern const volatile u64 slice_ns;
extern const volatile u64 tick_ns;
extern const volatile u64 migration_cost_ns;
extern const volatile u32 cache_nice_tries;
extern const volatile bool no_newidle_cost;
extern const volatile bool newidle_sampling;
extern const volatile bool sis_util;
extern const volatile bool llc_extend;
extern const volatile bool no_wakeup_preempt;
extern const volatile bool wa_weight;
extern const volatile u32 busy_balance_factor;
extern const volatile bool capacity_pressure;
extern const volatile bool no_task_clock;
extern const volatile bool no_eligibility;
extern const volatile bool no_eligible_scan;
extern const volatile bool no_run_to_parity;
extern const volatile bool no_preempt_short;
extern const volatile bool no_place_lag;
extern const volatile bool no_place_rel_deadline;
extern const volatile bool latency_credit;
extern const volatile u64 latency_credit_ns;
extern const volatile u64 latency_credit_user_thresh;
extern const volatile bool no_vref_update;
extern const volatile bool no_delay_dequeue;
extern const volatile bool no_delay_requeue;
extern const volatile bool no_hrtick;

extern u32 nr_sched_idle_curr;
extern volatile u64 nr_sis_updates;
extern volatile u64 sis_scan_sum;

/*
 * Size of the cid space this scheduler schedules on, [0, nr_cids), the
 * number of u64 words one bit per cid takes, and the size of the cid
 * space the arena was allocated for, which is what the kernel says it can
 * ever be. Set by eevdf_arena_init() and ops.init().
 */
static u32 nr_cids;
static u32 nr_words;
static u32 nr_cids_max;

/*
 * Number of possible CPU ids, in cpu space. Used to tell the tasks that
 * can run anywhere.
 */
static u32 nr_cpu_ids;

/*
 * Packing and capacity are independent kernel policies and have independent
 * tiers, both with 0 as the most preferred. Packing tiers are used by
 * SD_ASYM_PACKING balance; capacity tiers are used only when CPU capacity is
 * asymmetric.
 */
static u32 nr_place_tiers;
static u32 nr_capacity_tiers;
static bool asym_capacity;
static bool sched_asym_capacity;
static bool force_asym_capacity;
static bool asym_packing;

typedef struct cid_edq_task __arena cid_edq_task_t;

/*
 * EDQ membership state, embedded at the start of struct task_ctx.
 */
enum cid_edq_task_state {
	CID_EDQ_NONE,
	CID_EDQ_ENQUEUED,
	CID_EDQ_DISPATCHING,
	CID_EDQ_DISPATCHED,
	CID_EDQ_PARKED,		/* waiting on its cgroup's cpu.max, see cid_park() */
};

struct cid_edq_task {
	struct scx_edq_task common;
	u64 tid;
	s32 cid;
	u32 state;
	u64 slice;
	u64 enq_flags;
};

typedef struct pack __arena pack_t;

/*
 * What EEVDF keeps of one member of a pack, sched_entity. The EDQ node comes
 * first, so an EDQ pop returns the address of the entity, and of the context
 * that embeds the entity first.
 */
struct sched_ent {
	struct cid_edq_task edq;
	u64 vruntime;
	u64 deadline;
	u64 request;
	s64 vlag;
	u64 vw;			/* weight @vlag and @deadline are scaled to */
	u64 vjoin_w;		/* weight it joined @vpack with, see vref_join() */
	u64 vjoin_v;		/* vruntime last folded into @vpack */
	pack_t *vpack;		/* pack it is a member of, or NULL */
};

typedef struct sched_ent __arena sched_ent_t;

struct grp_hdr;

/*
 * Per-task context. It lives in the arena, like the EDQ node it embeds, so
 * anything holding the node reaches the whole context. Task storage only maps
 * the task to it, see try_lookup_task_ctx().
 */
struct task_ctx {
	struct sched_ent se;	/* first, EDQ pops return its address */
	u64 last_run_at;
	u64 last_stop_at;
	struct ravg_data run_avg;	/* fraction of wall time spent running */
	u64 util_est;		/* what the last activation used */
	u64 runnable_at;	/* when the last wakeup made the task runnable */
	u64 runnable_est;	/* fraction of wall time runnable, see task_runnable_update() */
	u64 last_utime;
	u64 last_sleep_at;	/* last block, used to decay WA_WEIGHT task load */
	s32 delay_cid;		/* pack a negative @vlag is owed to, see delay_settle() */
	u64 delay_vref;		/* its reference when the task left it */
	u64 delay_w;		/* its weight without the task */
	u64 delay_gen;		/* its @empty_gen then */
	struct grp_hdr __arena *bw_hdr;	/* the cgroup it waits on, see cid_park() */
	struct grp_q __arena *grp;	/* its cgroup's queues, NULL at the root */
	struct grp_q __arena *gq;	/* the one it is a member of, see grp_contrib_sync() */
	u64 gw;				/* the weight it is a member with */
	u64 wakee_decay_at;
	u32 wakee_flips;
	s32 last_wakee_pid;
	s32 recent_used_cid;
	s32 dispatch_migrate_cid; /* preferred destination chosen for running @p */
	bool pressure_migrate; /* requeue this detached task on a less loaded cid */

	/* still owed its first, halved request, see task_dl() */
	bool initial;
	bool place_pending;	/* a direct dispatch left its placement to ops.running() */
};

typedef struct task_ctx __arena task_ctx_t;

static struct scx_allocator task_ctx_allocator;

struct task_ctx_ref {
	task_ctx_t *tctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx_ref);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 *
 * The cache is installed by ops.enable() and the kernel clears it before
 * ops.exit_task(). Task callbacks are serialized against exit by the task's
 * scheduler locks. EDQ operations which keep a context across that
 * serialization hold its embedded node until they are done. Task storage
 * covers the windows before enable and after disable.
 */
static __always_inline task_ctx_t *try_lookup_task_ctx(const struct task_struct *p)
{
	struct task_ctx_ref *ref;
	u64 ptr;

	TOUCH_ARENA();
	ptr = p->scx.dsq_vtime;
	if (likely(ptr))
		return (task_ctx_t *)ptr;
	ref = bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
	return ref ? ref->tctx : NULL;
}

/*
 * Topology of a cid, filled in ops.init() from scx_bpf_cid_topo() and the
 * capacity user space reported for the CPU behind it. All the ranges are
 * in cid space and contiguous.
 */
struct cid_topo {
	u32 cpu;		/* cpu behind this cid, for affinity tests */
	u32 place_tier;		/* SD_ASYM_PACKING priority tier */
	u32 capacity_tier;	/* CPU capacity tier */
	u32 smt_asym_packing;	/* SMT domain follows SD_ASYM_PACKING */
	u64 cap;		/* capacity, 1024 = fastest */
	u32 core_base;		/* first cid of the core */
	u32 core_nr;		/* cids in the core (SMT siblings) */
	u32 llc_base;		/* first cid of the LLC */
	u32 llc_nr;		/* cids in the LLC */
	u32 llc_place_tier;	/* best SD_ASYM_PACKING tier in the LLC */
	u32 node_base;		/* first cid of the node */
	u32 node_nr;		/* cids in the node */
	u32 fork_base;		/* highest SD_BALANCE_FORK domain */
	u32 fork_nr;
	u32 wake_affine_base;	/* highest SD_WAKE_AFFINE domain */
	u32 wake_affine_nr;
	u32 asym_capacity_base; /* lowest SD_ASYM_CPUCAPACITY_FULL domain */
	u32 asym_capacity_nr;
};

/*
 * Per-cid scheduling state.
 */
enum busy_balance_level {
	BUSY_BALANCE_LLC,
	BUSY_BALANCE_NODE,
	BUSY_BALANCE_SYSTEM,
	BUSY_BALANCE_LEVELS,
};

struct busy_balance_env {
	/* Arena scratch keeps the nested scan within the verifier stack limit. */
	u64 avg_norm;
	u64 local_room;
	u64 dst_norm;
	u64 group_load;
	u64 group_cap;
	u64 source_excess;
	u64 move_budget;
	u64 scan_deadline;
	u64 scan_seq;
	u64 alternate_deadline;
	u64 alternate_seq;
	u64 local_norm;
	u32 local_base;
	u32 local_nr;
	u32 group_base;
	u32 group_nr;
	s32 move_dst_cid;
	s32 alternate_dst_cid;
	u32 level;
	u32 dst_overloaded;
	u32 local_overloaded;
	u32 group_queued;
	u32 scan_valid;
	u32 detach_failed;
};

enum newidle_level {
	NEWIDLE_LLC,
	NEWIDLE_NODE,
	NEWIDLE_SYSTEM,
	NEWIDLE_LEVELS,
};

struct newidle_stats {
	u64 stamp[NEWIDLE_LEVELS];
	u32 call[NEWIDLE_LEVELS];
	u32 success[NEWIDLE_LEVELS];
	u32 ratio[NEWIDLE_LEVELS];
};

/*
 * A pack, cfs_rq: the entities queued on one cid, in deadline order, and the
 * one running there, with the reference all of them are placed against and
 * tested against, see pack_vref().
 */
struct pack {
	u64 vsum_w;
	u64 vref;
	u64 vref_rem;
	u64 empty_gen;		/* bumped when the last member leaves */
	u64 curr_dl;		/* deadline of the entity running here */
	u64 curr_v;		/* its vruntime when it was picked */
	u64 curr_w;		/* its weight */
	u64 curr_run_at;	/* when its service was last charged */
	u64 curr_since;		/* when it was picked, see keep_running() */
	u64 curr_request;	/* request for which it was picked */
	u64 curr_vprot;		/* protected vruntime, see set_protect_slice() */
	s32 cid;		/* the cid whose task clock the pack runs in */
	struct scx_edq edq;
};

struct core_sched_state {
	u64 vzero;	/* virtual-time origin for core scheduling */
	u64 gen;	/* pack empty generation plus one; zero is invalid */
};

struct cid_ctx {
	struct ravg_data run_avg;	/* fraction of wall time spent running */
	struct ravg_data load_avg;	/* weight of what is runnable here, see cid_load() */
	u64 fork_place_at;	/* last fork selection, meaningful at core_base */
	u64 smt_busy_since;	/* first tick that found the sibling busy with our queue empty, see idle_balance_cid() */
	struct pack pack;	/* the tasks of this cid */
	u64 hrtick_at;		/* when its hrtick is armed for, see hrtick_start() */
	u64 hrtick_due;		/* when the running task's hrtick is due, see hrtick_fire() */
	u64 hrtick_run_at;	/* the run @hrtick_due was armed for, pack.curr_run_at */
	u64 clock_off;		/* rq clock minus task clock, see cid_clock_task_owned() */
	u32 requeue_pending;	/* the task that was running comes back to the queue, see cid_queued_check() */
	u64 active_balance_next;	/* destination: next asymmetric balance */
	u32 active_balance_interval_ms; /* destination: balance backoff */
	u64 busy_balance_next[BUSY_BALANCE_LEVELS]; /* next balance per domain */
	u32 busy_balance_interval_ms[BUSY_BALANCE_LEVELS]; /* domain backoff */
	u32 busy_balance_cursor[BUSY_BALANCE_LEVELS]; /* source-cid tie-break cursor */
	u32 busy_balance_failed[BUSY_BALANCE_LEVELS]; /* failed periodic detach passes */
	struct busy_balance_env busy_balance_env; /* tick scan scratch space */
	u64 busy_balance_load; /* latest domain-scan load sample */
	u64 busy_balance_cap; /* latest delivered-capacity estimate */
	u64 busy_balance_scan_cap; /* capacity paired with the load sample */
	u64 wake_load; /* tick-sampled load for wake_affine_weight() */
	u64 pressure_lost; /* cumulative higher-class displacement time */
	u64 pressure_lost_at; /* displacement time at the window start */
	u64 pressure_blocked_at; /* task clock when a higher class displaced it */
	u64 pressure_clock_off_at; /* IRQ/steal clock offset at window start */
	u64 pressure_at; /* wall-clock start of the pressure window */
	u64 pressure_idle_at; /* demand disappeared; stale estimates expire */
	u64 pressure_migrate_next; /* pace higher-class displacement handoffs */
	u32 pressure_migrate_failed; /* detach passes rejected by move guards */
	u32 pressure_avail; /* delivered capacity, 1024 = no pressure */
	u32 pressure_demand; /* sched_ext has runnable work on this cid */
	u32 pressure_valid; /* a current demand window has been sampled */
	u32 curr_idle;		/* it is a SCHED_IDLE task */
	u32 curr_sched_idle;	/* that, or it is in an idle cgroup, see cid_sched_idle_target() */
	u32 steal_cursor;
	/* Persistent scans of this cid as a source. */
	struct scx_edq_cursor detach_cursor;
	struct scx_edq_cursor busy_scan_cursor;
	/* Candidate handed from a periodic scan to destination dispatch. */
	struct scx_edq_cursor busy_dispatch_cursor;
	u32 nr_balance_failed;	/* idle scans that found nothing they could take */
	u64 idle_stamp;		/* when the last idle pull began, see newidle_cost() */
	u64 avg_idle;		/* how long the cid stays idle after one, rq->avg_idle */
	u64 max_idle_balance_cost;	/* its worst pull, rq->max_idle_balance_cost */
	u64 newidle_cost[NEWIDLE_LEVELS]; /* worst pull per level, sd->max_newidle_lb_cost */
	u64 newidle_decay_at[NEWIDLE_LEVELS]; /* sd->last_decay_max_lb_cost */
	u32 force_steal;	/* an enqueue saw this cid idle beside one waiter */
	s32 busy_balance_cid; /* queued cid selected by periodic busy balance */
	s32 busy_balance_owner; /* cid which owns the selected domain pass */
	u32 busy_balance_level; /* domain whose failure count the pass updates */
	u64 busy_balance_expire; /* when an unconsumed selection is dropped */
	u64 busy_balance_budget; /* load left in this deferred balance pass */
	u32 active_balance_pending; /* destination reservation: 0 none, 1 held, 2 ready */
	s32 active_balance_cid;	/* idle cid asking for the running task */
	u64 user_acc;
	u64 user_util_ewma;
	u64 user_eval_at;
	bool user_busy;
	u32 sis_idle_scan;	/* nr_idle_scan, meaningful at llc_base */
};

/*
 * Arena resident tables, indexed by cid unless noted, carved out of the
 * pages eevdf_arena_init() takes. Arena pointers are not range tracked
 * by the verifier, so a cid that is known to be in range indexes them
 * directly.
 */
static struct cid_topo __arena *topos;
static struct cid_ctx __arena *cctxs;
static struct core_sched_state __arena *core_sched_states;
static struct newidle_stats __arena *newidle_stats;
static struct scx_cmask __arena *idle_cids;	/* one bit per idle cid */
static struct scx_cmask __arena *idle_core_llcs; /* LLCs known to have an idle core */
static struct scx_cmask __arena *queued_cids;	/* one bit per cid with a queued task */
static struct scx_cmask __arena *place_tier_cids; /* one mask per placement tier */
static struct scx_cmask __arena *capacity_tier_cids; /* one mask per capacity tier */
static u64 place_tier_stride;			 /* bytes between placement tier masks */
static u64 capacity_tier_stride;			 /* bytes between capacity tier masks */

/*
 * The bitmaps are struct scx_cmask, the type the kernel's cid interfaces
 * take and hand out, framed at cid 0 over the whole cid space, so that a
 * domain or a sub-scheduler can be given one as is, and they are read and
 * written through the cmask helpers throughout: a bit with cmask_set(),
 * cmask_clear() and cmask_test_and_clear(), a word with cmask_word() and
 * cmask_range_word(). What the scans stay away from is the per-cid
 * iterators, not the helpers: a scan reads whole words.
 */
static __always_inline struct scx_cmask __arena *place_tier_mask(u32 t)
{
	return (struct scx_cmask __arena *)((char __arena *)place_tier_cids +
					     t * place_tier_stride);
}
static __always_inline struct scx_cmask __arena *capacity_tier_mask(u32 t)
{
	return (struct scx_cmask __arena *)((char __arena *)capacity_tier_cids +
					     t * capacity_tier_stride);
}
static u64 __arena *cpu_cap_in;		/* cpu space: capacity from user space */
static u32 __arena *cpu_place_tier_in; /* cpu space: placement tier */
static u32 __arena *cpu_capacity_tier_in; /* cpu space: capacity tier */
static u32 __arena *cpu_smt_asym_in;	/* cpu space: SMT SD_ASYM_PACKING */
static u32 __arena *cpu_fork_span_in;	/* cpu space: SD_BALANCE_FORK span */
static u32 __arena *cpu_wake_span_in;	/* cpu space: SD_WAKE_AFFINE span */
static u32 __arena *cpu_asym_span_in;	/* cpu space: asym-capacity span */

/*
 * Translate a kernel sched-domain weight into the smallest enclosing topology
 * range scx_eevdf represents. The cid topology has core, LLC, node and system
 * levels; an intermediate kernel level (for example, a cluster) is therefore
 * conservatively represented by its containing LLC.
 */
static __always_inline u64 topo_domain_range(struct cid_topo __arena *topo,
					      u32 span, u32 fallback)
{
	if (!span)
		span = fallback;
	if (span <= topo->core_nr)
		return (u64)topo->core_nr << 32 | topo->core_base;
	if (span <= topo->llc_nr)
		return (u64)topo->llc_nr << 32 | topo->llc_base;
	if (span <= topo->node_nr)
		return (u64)topo->node_nr << 32 | topo->node_base;
	return (u64)nr_cids << 32;
}

/*
 * Return true if @cid is one this scheduler can address. The tables above
 * are indexed without a bounds check, so every id that comes in from the
 * outside goes through here first.
 */
static __always_inline bool cid_valid(s32 cid)
{
	return cid >= 0 && (u32)cid < nr_cids;
}

static __always_inline struct cid_topo __arena *cid_topo(s32 cid)
{
	return &topos[cid];
}

static __always_inline struct cid_ctx __arena *cid_ctx(s32 cid)
{
	return &cctxs[cid];
}

static __always_inline pack_t *cid_pack(s32 cid)
{
	return &cctxs[cid].pack;
}

/*
 * The pack the task of @tctx is queued in and runs in on @cid.
 */
static __always_inline pack_t *task_pack(const task_ctx_t *tctx, s32 cid)
{
	return cid_pack(cid);
}

/*
 * How much of a CPU a task uses, tracked as the fraction of wall time it
 * spends running, decayed with a half life. fair.c gets the same number
 * from PELT; nothing maintains p->se.avg for a sched_ext task, so it is
 * measured here.
 *
 * The value is carried in the [0 .. SCX_CPUPERF_ONE] range that capacity
 * is expressed in, so the two can be compared directly.
 */
#define UTIL_HALF_LIFE_NS	32000000U
#define UTIL_SHIFT		(RAVG_FRAC_BITS - 10)

/*
 * Is a task of @util small enough to run on a CPU of @cap without filling
 * it? fits_capacity() asks the same, with the same fifth off the top:
 *
 *	#define fits_capacity(cap, max)	((cap) * 1280 < (max) * 1024)
 */
#define util_fits_cap(util, cap)	((util) * 1280 < (cap) * 1024)

/*
 * ravg_accumulate() and ravg_read() on a running average in the arena, which
 * they cannot be handed a pointer into, staged through the stack.
 *
 * Copy field by field rather than with ravg_from_arena() and ravg_to_arena():
 * LLVM 19 drops the address space cast on their word casts when @ard is a task
 * context pointer, and the verifier sees a scalar dereference.
 */
static void ravg_accumulate_arena(struct ravg_data __arena *ard, u64 new_val, u64 now)
{
	struct ravg_data rd = {
		.val = ard->val,
		.val_at = ard->val_at,
		.old = ard->old,
		.cur = ard->cur,
	};

	ravg_accumulate(&rd, new_val, now, UTIL_HALF_LIFE_NS);
	ard->val = rd.val;
	ard->val_at = rd.val_at;
	ard->old = rd.old;
	ard->cur = rd.cur;
}

static u64 ravg_read_arena(struct ravg_data __arena *ard, u64 now)
{
	struct ravg_data rd = {
		.val = ard->val,
		.val_at = ard->val_at,
		.old = ard->old,
		.cur = ard->cur,
	};

	return ravg_read(&rd, now, UTIL_HALF_LIFE_NS);
}

/*
 * rq_clock_task(): the clock update_curr() charges service in, read off
 * the runqueue behind @cid. It is rq->clock less the interrupt time and
 * the hypervisor steal time that CPU has accumulated, so a task is not
 * charged for interrupts that land on its CPU or for time the host took
 * from its vCPU, and it is a per-CPU clock: two cids' task clocks differ
 * by the difference of what they have lost, seconds over an uptime, and
 * are never compared. Everything in a cid's virtual time is in its task
 * clock: the stamp a pick is charged from, ops.running() to
 * ops.stopping(), keep_charge(), the projections pack_vref_at() and
 * pack_vref_place() make of the running task's progress, the hrtick's
 * distance to the deadline. Everything measured between CPUs stays on
 * the rq clock, scx_bpf_now(): the running averages, cache hotness, the
 * idle time, the balance intervals, the wakee-flip decay, and the time an
 * hrtick is due at, which hrtick_start() converts with the offset between
 * the two clocks, see @clock_off. The rq clock is the one fair.c keeps
 * those in too, and it is read off the runqueue for the price of a load
 * from every op that holds the lock; the cost of a newidle pull is the
 * one thing measured on a fresh clock, see try_steal_task().
 *
 * The runqueue's clock is read only by an op that holds that runqueue's
 * lock, which is what scx_clock_task() asks for: ops.running(),
 * ops.stopping(), ops.dispatch(), ops.yield() and ops.enqueue() on the
 * task's own cid, and each such read publishes the offset between the
 * two clocks, cid_clock_task_owned(). Everything else, a lag against
 * the pack a task left, a delayed dequeue settling up, a placement on a
 * migration target, the source of an idle pull, the hrtick timer,
 * converts the rq clock it already holds through that offset,
 * cid_clock_task_at(), and never touches another CPU's runqueue. The
 * offset moves by the interrupt time the cid takes between two owned
 * reads, microseconds, where the remote clock itself would sit still
 * between that CPU's scheduling events and for the whole of its idle.
 *
 * --no-task-clock charges wall time, interrupts and steal included: both
 * return @now and the offset stays zero.
 */
static u64 cid_clock_task_owned(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx = cid_ctx(cid);
	u64 tnow;

	if (no_task_clock)
		return now;
	tnow = scx_clock_task(cid_topo(cid)->cpu);
	cctx->clock_off = now - tnow;

	return tnow;
}

static u64 cid_clock_task_at(s32 cid, u64 now)
{
	u64 off;

	if (no_task_clock)
		return now;
	off = READ_ONCE(cid_ctx(cid)->clock_off);

	return now >= off ? now - off : 0;
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Return true if @p cannot run on every CPU: only those tasks need their
 * affinity tested against a candidate.
 */
static inline bool is_restricted(const struct task_struct *p)
{
	return p->nr_cpus_allowed < nr_cpu_ids;
}

/*
 * Return true if @p can run on @cid.
 */
static __always_inline bool cid_allowed(const struct task_struct *p, s32 cid)
{
	return bpf_cpumask_test_cpu(cid_topo(cid)->cpu, p->cpus_ptr);
}

#define SCHED_BATCH	3
#define SCHED_IDLE	5

/*
 * Weight of a nice 0 task on the kernel's own scale, NICE_0_LOAD after
 * scale_load_down(), which is what calc_delta_fair() divides by.
 */
#define NICE_0_WEIGHT	1024

/*
 * The kernel's nice-to-weight table, sched_prio_to_weight[], indexed by
 * @p->static_prio - MAX_RT_PRIO. Each step of nice is worth about 1.25x.
 */
#define MAX_RT_PRIO	100
#define WEIGHT_IDLEPRIO	3
static const u32 prio_to_weight[40] = {
 /* -20 */	88761,	71755,	56483,	46273,	36291,
 /* -15 */	29154,	23254,	18705,	14949,	11916,
 /* -10 */	 9548,	 7620,	 6100,	 4904,	 3906,
 /*  -5 */	 3121,	 2501,	 1991,	 1586,	 1277,
 /*   0 */	 1024,	  820,	  655,	  526,	  423,
 /*   5 */	  335,	  272,	  215,	  172,	  137,
 /*  10 */	  110,	   87,	   70,	   56,	   45,
 /*  15 */	   36,	   29,	   23,	   18,	   15,
};
