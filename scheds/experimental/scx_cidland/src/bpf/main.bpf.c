/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * A cid-form scheduler (struct sched_ext_ops_cid): CPUs are addressed by
 * their cid, a dense id space ordered by topology, so that the CPUs of a
 * core, of an LLC and of a NUMA node occupy contiguous ranges of it. A
 * topology domain is a (base, len) slice of the cid space, and "is this
 * core idle" or "is there an idle CPU in my LLC" is a range of a bitmap.
 *
 * Everything sized by the machine lives in a BPF arena, allocated once by
 * user space before the scheduler is attached, so nothing here caps the
 * number of CPUs, cores, LLCs, nodes or placement tiers.
 */
#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include <lib/arena_map.h>
#include <lib/edq.h>
#include <lib/ravg.h>
#include <lib/arena_loop.h>
#include <lib/sdt_alloc.h>
#include "intf.h"

#ifndef __BPF_FEATURE_ADDR_SPACE_CAST
#error "scx_cidland requires a compiler with bpf_addr_space_cast support"
#endif

char _license[] SEC("license") = "GPL";

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
 * Enable cpufreq integration.
 */
const volatile bool cpufreq_enabled = true;

/*
 * Enable NUMA optimizations: prefer the node a task last ran on.
 */
const volatile bool numa_enabled;

/*
 * Consider SMT siblings: prefer a core whose siblings are all idle.
 */
const volatile bool smt_enabled = true;

/*
 * Rank the threads of a core by CPU id when the kernel exposes no priority
 * between them, for placement only: a determinism aid, see the option.
 */
const volatile bool force_smt_asym_packing;

/*
 * Let a wakeup leave its LLC for a whole idle core rather than settle for
 * the idle sibling of a busy one. See pick_idle_cid(). Off by default:
 * select_idle_sibling() stops at the LLC, and this is the one place the
 * scan deliberately does not.
 */
const volatile bool smt_whole_core;

/*
 * Honor the weight of the cpu controller's cgroups, cpu.weight, on top of
 * the weight a task gets from its nice level. See cgrp_weight().
 */
const volatile bool cgroup_enabled = true;

/*
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * Default time slice, fair.c's normalized_sysctl_sched_base_slice. Its end
 * is enforced by the hrtick when the task has company, see hrtick_start(),
 * and from task_tick_scx() otherwise.
 */
const volatile u64 slice_ns = 700000ULL;

/*
 * Timing granularity, TICK_NSEC. The kernel's HZ is not visible from
 * here, so user space passes it; 1000000 is HZ=1000.
 */
const volatile u64 tick_ns = 1000000ULL;

/*
 * A task that ran within this long on its CPU is still cache hot there and
 * is not stolen, like task_hot() with sysctl_sched_migration_cost.
 */
const volatile u64 migration_cost_ns = 500000ULL;

/*
 * How many times in a row an idle cid may come back from a scan with
 * nothing it is allowed to take before it stops honouring cache hotness,
 * like sd->cache_nice_tries against sd->nr_balance_failed in
 * can_migrate_task(). This is the value for a scan within the LLC; one
 * more is allowed beyond it, the way sd_init() gives a SD_NUMA domain
 * one more than a SD_SHARE_LLC one.
 */
const volatile u32 cache_nice_tries = 1;

/*
 * Scan for work on an idle cid whatever the scan costs against how long
 * the cid has been staying idle, dropping sched_balance_newidle()'s
 * avg_idle budget, see newidle_cost().
 */
const volatile bool no_newidle_cost;

/*
 * Do not interrupt a running task for one that wakes up with an earlier
 * deadline, leaving it to run until its slice ends.
 */
const volatile bool no_wakeup_preempt;

/*
 * Send a wakee to the waking cid when both it and its previous cid are
 * busy and the loads say that leaves the two better balanced, the
 * effective-load comparison of wake_affine_weight(), see
 * wake_affine_weight_cid(). Off by default: a wakee stays on its previous
 * cid, and the load averages behind the comparison are not kept.
 */
const volatile bool wa_weight;
const volatile u32 busy_balance_factor = 16;
const volatile bool no_task_clock;

/*
 * Interrupt a running task on the deadlines alone, without asking which
 * of the two is owed service, see kick_queued_cid().
 */
const volatile bool no_eligibility;

/*
 * At dispatch, take the head of a deadline-ordered EDQ as the pick
 * instead of walking it for its first eligible task, see
 * move_first_eligible_to_local(). Implied by @no_eligibility.
 */
const volatile bool no_eligible_scan;

/*
 * Interrupt a running task that is still owed service, when the task
 * that woke holds the earlier deadline, see kick_queued_cid().
 *
 * This is RUN_TO_PARITY turned off, in the sense the feature had when
 * EEVDF was merged: the running task is not kept for the rest of the
 * service its pack owes it. The woken task is still asked for its own
 * eligibility, which is what tells this apart from @no_eligibility:
 * that one decides on the deadlines alone, this one only stops the
 * task already running from being protected by the service it is owed.
 *
 * fair.c has since moved the switch: pick_eevdf() takes the protection
 * as an argument now, and the feature selects which slice sizes it in
 * set_protect_slice(). On a queue where every task asks for the same
 * slice that choice makes no difference, so the older reading is the
 * one that names anything here.
 */
const volatile bool no_run_to_parity;

/*
 * Keep the running task's protection against an eligible wakee that asks
 * for a shorter request. This is PREEMPT_SHORT turned off.
 */
const volatile bool no_preempt_short;

/*
 * Do not inflate a placement offset to preserve it across the task joining
 * the weighted-average virtual-time reference. This restores cidland's
 * placement before its fair.c PLACE_LAG compensation was added.
 */
const volatile bool no_place_lag;

/*
 * Grant a task that is moved or queued again without having slept a
 * whole new request, rather than what is left of the one it was in the
 * middle of. This is PLACE_REL_DEADLINE off, see set_vruntime().
 */
const volatile bool no_place_rel_deadline;

/*
 * Place tasks and test them for eligibility against the pack reference as
 * it stands, without the service the task running there has taken since
 * it was picked, see pack_vref_at().
 */
const volatile bool no_vref_update;

/*
 * Let a task that blocks over-served carry the whole of its debt across
 * the sleep, rather than have it paid off by the pack it left as fair.c
 * does with DELAY_DEQUEUE and DELAY_ZERO, see delay_settle().
 */
const volatile bool no_delay_dequeue;

/*
 * Wake a task that blocked over-served through the wakeup placement
 * instead of on the cid it blocked on, see delay_requeue_cid(). Implied by
 * @no_delay_dequeue.
 */
const volatile bool no_delay_requeue;

/*
 * Notice the end of a request at the tick that follows it rather than
 * when it happens, without the timer fair.c runs as HRTICK, see
 * hrtick_start().
 */
const volatile bool no_hrtick;

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
 * Scheduler statistics.
 */
volatile u64 nr_steals __hot_written;
volatile u64 nr_busy_balances __hot_written;
volatile u64 nr_active_balances __hot_written;
volatile u64 nr_preempts __hot_written;
volatile u64 nr_delay_requeues __hot_written;
volatile u64 nr_hrticks __hot_written;
volatile u64 nr_newidle_skips __hot_written;

/*
 * Scheduler's exit status.
 */
UEI_DEFINE(uei);

/*
 * Size of the cid space this scheduler schedules on, [0, nr_cids), the
 * number of u64 words one bit per cid takes, and the size of the cid
 * space the arena was allocated for, which is what the kernel says it can
 * ever be. Set by cidland_arena_init() and ops.init().
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
	struct ravg_data runnable_avg;	/* fraction of wall time spent runnable, see task_load() */
	u64 util_est;		/* what the last activation used */
	s32 delay_cid;		/* pack a negative @vlag is owed to, see delay_settle() */
	u64 delay_vref;		/* its reference when the task left it */
	u64 delay_w;		/* its weight without the task */
	u64 delay_gen;		/* its @empty_gen then */
	u32 cgw;		/* weight of its cgroup, see cgrp_weight() */
	u64 cgw_gen;		/* the @cgrp_gen @cgw was taken at */
	u64 wakee_decay_at;
	u32 wakee_flips;
	s32 last_wakee_pid;
	s32 recent_used_cid;
	s32 dispatch_migrate_cid; /* preferred destination chosen for running @p */

	/* still owed its first, halved request, see task_dl() */
	bool initial;
	bool direct_placed;	/* select_cid() already placed and joined it */
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
 * PROTOTYPE: cidland never orders a DSQ by vtime, so @p->scx.dsq_vtime is
 * free to carry the context pointer, set in ops.enable(), and a lookup is a
 * load instead of a task-storage helper call. The kernel zeroes the field
 * when @p leaves the scheduler, so fall back to task storage while it is
 * zero, from ops.init_task() to ops.enable() and after ops.disable().
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
 * Per-cgroup context: what the cpu controller says about a cgroup.
 */
struct cgrp_ctx {
	u32 weight;	/* its own cpu.weight */
	u32 cweight;	/* that composed with its ancestors', see cgrp_weight() */
	u64 gen;	/* the @cgrp_gen @cweight was composed at */
};

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
} cgrp_ctx_stor SEC(".maps");

/*
 * One hrtick per cid, see hrtick_start(). The map is sized to the cid
 * space by user space before the program is loaded.
 */
struct hrtick {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct hrtick);
	__uint(max_entries, 1);
} hrticks SEC(".maps");

/*
 * Bumped by ops.cpuctl_set_weight(), which expires every composed weight
 * cached anywhere, cgroup and task alike: one cpu.weight write changes the
 * weight of everything under that cgroup, and there is no walking down to
 * them from here. A cache that carries a generation older than this one is
 * recomputed the next time its task runs.
 *
 * Read on the wakeup path, written only when a cpu.weight file is, so it
 * belongs with the read-mostly globals and not on a __hot_written line.
 * Never 0: a task context starts zeroed and has to look stale.
 */
static u64 cgrp_gen = 1;

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
	u64 local_norm;
	u32 local_base;
	u32 local_nr;
	u32 group_base;
	u32 group_nr;
	s32 move_dst_cid;
	u32 level;
	u32 dst_overloaded;
	u32 local_overloaded;
	u32 group_queued;
};

enum newidle_level {
	NEWIDLE_LLC,
	NEWIDLE_NODE,
	NEWIDLE_SYSTEM,
	NEWIDLE_LEVELS,
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
	s32 cid;		/* the cid whose task clock the pack runs in */
	struct scx_edq edq;
};

struct cid_ctx {
	struct ravg_data run_avg;	/* fraction of wall time spent running */
	struct ravg_data load_avg;	/* weight of what is runnable here, see cid_load() */
	u64 smt_busy_since;	/* first tick that found the sibling busy with our queue empty, see idle_balance_cid() */
	struct pack pack;	/* the tasks of this cid */
	u64 hrtick_at;		/* when its hrtick is armed for, see hrtick_start() */
	u64 clock_off;		/* rq clock minus task clock, see cid_clock_task_owned() */
	u32 requeue_pending;	/* the task that was running comes back to the queue, see cid_queued_check() */
	u64 active_balance_next;	/* destination: next asymmetric balance */
	u32 active_balance_interval_ms; /* destination: balance backoff */
	u64 busy_balance_next[BUSY_BALANCE_LEVELS]; /* next balance per domain */
	u32 busy_balance_interval_ms[BUSY_BALANCE_LEVELS]; /* domain backoff */
	u32 busy_balance_cursor[BUSY_BALANCE_LEVELS]; /* source-cid tie-break cursor */
	struct busy_balance_env busy_balance_env; /* tick scan scratch space */
	u64 busy_balance_load; /* latest domain-scan load sample */
	u32 curr_idle;		/* it is a SCHED_IDLE task */
	u32 steal_cursor;
	u32 nr_balance_failed;	/* idle scans that found nothing they could take */
	u64 idle_stamp;		/* when the last idle pull began, see newidle_cost() */
	u64 avg_idle;		/* how long the cid stays idle after one, rq->avg_idle */
	u64 max_idle_balance_cost;	/* its worst pull, rq->max_idle_balance_cost */
	u64 newidle_cost[NEWIDLE_LEVELS]; /* worst pull per level, sd->max_newidle_lb_cost */
	u64 newidle_decay_at[NEWIDLE_LEVELS]; /* sd->last_decay_max_lb_cost */
	u32 force_steal;	/* an enqueue saw this cid idle beside one waiter */
	s32 busy_balance_cid; /* queued cid selected by periodic busy balance */
	u64 busy_balance_expire; /* when an unconsumed selection is dropped */
	u64 busy_balance_budget; /* load left in this deferred balance pass */
	u32 active_balance_pending; /* destination reservation: 0 none, 1 held, 2 ready */
	s32 active_balance_cid;	/* idle cid asking for the running task */
};

/*
 * Arena resident tables, indexed by cid unless noted, carved out of the
 * pages cidland_arena_init() takes. Arena pointers are not range tracked
 * by the verifier, so a cid that is known to be in range indexes them
 * directly.
 */
static struct cid_topo __arena *topos;
static struct cid_ctx __arena *cctxs;
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

/*
 * Scratch space for scx_bpf_cid_topo(), only used by ops.init(). It has
 * to be readable as a whole at the call, which stack slots that are never
 * read back are not.
 */
static struct scx_cid_topo init_topo;

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
 * Note that @p started or stopped running at @now.
 */
static void util_set_running(task_ctx_t *tctx, bool running, u64 now)
{
	ravg_accumulate_arena(&tctx->run_avg, running, now);
}

/*
 * Return what @p is using, the larger of what it is using now and what it
 * used over its last activation. This is task_util_est():
 *
 *	return max(task_util(p), _task_util_est(p));
 *
 * A task that runs in bursts, a frame at a time, is idle when it wakes,
 * and the running average alone would call it small at exactly the moment
 * it is about to ask for a whole CPU again.
 */
static u64 task_util(task_ctx_t *tctx, u64 now)
{
	u64 util = ravg_read_arena(&tctx->run_avg, now) >> UTIL_SHIFT;

	return MAX(util, tctx->util_est);
}

/*
 * Fold what @p just used into its estimate, as it stops being runnable.
 *
 * The estimate rises to a new demand at once and comes down slowly, which
 * is what util_est_update() does:
 *
 *	if (ewma <= dequeued) {
 *		ewma = dequeued;
 *		goto done;
 *	}
 *
 * before smoothing the decrease. A task is asked to prove that it needs
 * less, over several activations; it is taken at its word that it needs
 * more.
 */
static void util_est_update(task_ctx_t *tctx, u64 now)
{
	u64 dequeued = ravg_read_arena(&tctx->run_avg, now) >> UTIL_SHIFT;

	if (tctx->util_est <= dequeued)
		tctx->util_est = dequeued;
	else
		tctx->util_est -= (tctx->util_est - dequeued) >> 2;
}

/*
 * Note that @cid started or stopped running a task at @now, and fold the
 * interval that just ended into how busy it has been.
 */
static void cid_util_set_running(s32 cid, bool running, u64 now)
{
	/*
	 * Placement uses this signal too, so keep it even when frequency
	 * control is disabled. update_cpufreq() independently honors
	 * cpufreq_enabled before applying it to the governor.
	 */
	if (!cid_valid(cid))
		return;
	ravg_accumulate_arena(&cid_ctx(cid)->run_avg, running, now);
}

/*
 * Return how busy @cid has been, in the [0 .. SCX_CPUPERF_ONE] range the
 * cpufreq governor is driven in.
 */
static u64 cid_util(s32 cid, u64 now)
{
	return ravg_read_arena(&cid_ctx(cid)->run_avg, now) >> UTIL_SHIFT;
}

/*
 * The load of a cid, cpu_load(): what cfs_rq->avg.load_avg is, the weight
 * of the runnable tasks averaged over time, and what wake_affine_weight()
 * compares. The weight is the pack's, @vsum_w, the sum over the running
 * task and the queued ones, and it is sampled into the average from the
 * cid's own CPU. ops.tick() always maintains it for periodic balancing, and
 * ops.update_idle() records the empty pack when the tick stops with the CPU;
 * WA_WEIGHT additionally updates it in ops.running() and ops.stopping(),
 * where wake-affine needs the finer-grained signal. A join or a leave from
 * another CPU changes @vsum_w atomically but cannot update a running average
 * that is not owned there, and the sample is at most an event behind. A read
 * from another CPU is the same unlocked read cid_util() makes.
 */
static void cid_load_accumulate(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;

	if (!cid_valid(cid))
		return;
	cctx = cid_ctx(cid);

	ravg_accumulate_arena(&cctx->load_avg, cctx->pack.vsum_w, now);
}

static void cid_load_update(s32 cid, u64 now)
{
	if (wa_weight)
		cid_load_accumulate(cid, now);
}

static u64 task_load(const struct task_struct *p, task_ctx_t *tctx, u64 now);

static u64 cid_load(s32 cid, u64 now)
{
	return ravg_read_arena(&cid_ctx(cid)->load_avg, now) >> RAVG_FRAC_BITS;
}

/*
 * Tell the cpufreq governor how busy @cid is.
 *
 * Just how busy it is, with nothing added: what schedutil is handed is a
 * utilization, and it does the shaping itself in
 * sugov_effective_cpu_perf():
 *
 *	actual = map_util_perf(actual);
 *	if (actual < max)
 *		max = actual;
 *	return max(min, max);
 *
 * so the quarter of headroom is already there, the ceiling is already
 * there, and @min already keeps a CPU above whatever floor the bandwidth
 * of what runs on it demands. This is what the fair class passes, see
 * cpu_util_cfs_boost() in sugov_get_util().
 */
static void update_cpufreq(s32 cid, u64 now)
{
	if (!cpufreq_enabled || !cid_valid(cid))
		return;

	/*
	 * cpu_util_cfs() reads the average as of the last update, and
	 * ops.running() has just brought it up to @now: no second clock read.
	 */
	scx_bpf_cidperf_set(cid, cid_util(cid, now));
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

static __always_inline bool cid_allowed(const struct task_struct *p, s32 cid);
static inline bool is_restricted(const struct task_struct *p);

static cid_edq_task_t *cid_edq_task(task_ctx_t *tctx)
{
	return tctx ? &tctx->se.edq : NULL;
}

/*
 * Queue inspection is advisory. Never join a contended lock wait from a
 * preemption decision or a remote steal scan; the queue owner will make
 * progress and a later dispatch can try again.
 */
static int cid_edq_try_peek(s32 cid, cid_edq_task_t **atp)
{
	u64 task;
	int ret;

	*atp = NULL;
	ret = scx_edq_try_peek_hold(&cid_pack(cid)->edq, &task);
	if (ret) {
		if (ret != -EBUSY)
			scx_bpf_error("EDQ peek failed for cid %d: %d", cid, ret);
		return ret;
	}
	*atp = (cid_edq_task_t *)task;
	return 0;
}

static int cid_edq_try_peek_nth(s32 cid, u32 nth, cid_edq_task_t **atp)
{
	u64 task;
	int ret;

	if (!nth)
		return cid_edq_try_peek(cid, atp);
	*atp = NULL;
	ret = scx_edq_try_peek_nth_hold(&cid_pack(cid)->edq, nth, &task);
	if (ret) {
		if (ret != -EBUSY)
			scx_bpf_error("EDQ nth peek failed for cid %d: %d", cid, ret);
		return ret;
	}
	*atp = (cid_edq_task_t *)task;
	return 0;
}

static void cid_edq_mark_dispatched(task_ctx_t *tctx)
{
	cid_edq_task_t *at;

	at = cid_edq_task(tctx);
	if (at)
		WRITE_ONCE(at->state, CID_EDQ_DISPATCHED);
}

static u32 cid_queue_nr(s32 cid)
{
	return scx_edq_nr_queued(&cid_pack(cid)->edq);
}

/*
 * Return the sched_ext tid at the EDQ head, or 0. For the cid's own ops
 * only: they hold the rq lock, so the only other holder of the lock is a
 * remote trylocker in a short peek or remove, and waiting for it is
 * cheaper than skipping the decision. peek_hold keeps the arena object
 * alive across the unlocked tid load; the caller resolves it under RCU.
 */
static u64 cid_edq_peek_tid_owned(s32 cid)
{
	cid_edq_task_t *at;
	u64 tid = 0;

	at = (cid_edq_task_t *)scx_edq_peek_hold(&cid_pack(cid)->edq);
	if (at) {
		tid = at->tid;
		scx_edq_task_drop(&at->common);
	}
	return tid;
}

/*
 * scx_bpf_tid_to_task() returns an RCU-protected pointer. Every lookup below
 * runs from a non-sleepable struct_ops callback, which BPF treats as an
 * implicit RCU read-side critical section. Keep lookups out of sleepable ops.
 */
static __noinline bool cid_edq_dispatch_popped(cid_edq_task_t *at,
					       struct task_struct *p, s32 dst_cid)
{
	if (__sync_val_compare_and_swap(&at->state, CID_EDQ_ENQUEUED,
					CID_EDQ_DISPATCHING) != CID_EDQ_ENQUEUED) {
		scx_edq_task_drop(&at->common);
		return false;
	}
	if (!p)
		p = scx_bpf_tid_to_task(at->tid);
	if (!p) {
		/*
		 * The sched_ext tid remains resolvable through task exit. Failure here
		 * means the queue entry outlived the task or was otherwise corrupted;
		 * fail into scheduler rescue rather than silently losing its only
		 * runnable-queue entry.
		 */
		scx_bpf_error("EDQ cannot resolve queued tid %llu", at->tid);
		scx_edq_task_drop(&at->common);
		return false;
	}
	if (!is_task_queued(p)) {
		scx_edq_task_drop(&at->common);
		return false;
	}
	if (READ_ONCE(at->state) != CID_EDQ_DISPATCHING) {
		scx_edq_task_drop(&at->common);
		return false;
	}
	/*
	 * The task's affinity can change after EDQ selected it. Unlike a DSQ
	 * move, a direct LOCAL insertion with a now-invalid destination is a
	 * scheduler error. A changed affinity belongs to a scheduler-property
	 * workflow: drop this old pop and let the core's matching enqueue place the
	 * task again, as fair's sched_change dequeue/enqueue pair does.
	 */
	if (is_restricted(p) && !cid_allowed(p, dst_cid)) {
		scx_edq_task_drop(&at->common);
		return false;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, at->slice, at->enq_flags);
	scx_edq_task_drop(&at->common);
	return true;
}

enum cid_edq_move_result {
	CID_EDQ_MOVE_MISS,
	CID_EDQ_MOVE_MOVED,
	CID_EDQ_MOVE_BUSY,
};

static __noinline enum cid_edq_move_result
cid_edq_remove_held_to_local(s32 src_cid, s32 dst_cid, cid_edq_task_t *at,
				    struct task_struct *p)
{
	int ret;

	ret = scx_edq_try_remove(&cid_pack(src_cid)->edq, &at->common);
	if (ret) {
		if (ret != -EINVAL && ret != -EBUSY)
			scx_bpf_error("EDQ exact remove failed for tid %llu: %d",
				      at->tid, ret);
		scx_edq_task_drop(&at->common);
		return ret == -EBUSY ? CID_EDQ_MOVE_BUSY : CID_EDQ_MOVE_MISS;
	}

	return cid_edq_dispatch_popped(at, p, dst_cid) ? CID_EDQ_MOVE_MOVED :
							 CID_EDQ_MOVE_MISS;
}

/*
 * A pop that fails to dispatch has still removed its node: the task it
 * chose is in the hands of a concurrent dequeue, and the core enqueues it
 * again. The rest of the queue is not, so pop again rather than end the
 * round and leave the CPU idle over tasks that are ready to run. Every
 * iteration removes a node, so the queue depth bounds the loop.
 */
static __noinline bool cid_queue_move_head_to_local(s32 cid)
{
	struct scx_edq __arena *edq = &cid_pack(cid)->edq;
	cid_edq_task_t *at;

	while (can_loop) {
		at = (cid_edq_task_t *)scx_edq_pop(edq, true);
		if (!at)
			return false;
		if (cid_edq_dispatch_popped(at, NULL, cid))
			return true;
	}
	return false;
}

/*
 * Atomically remove the earliest-deadline task whose vruntime is eligible.
 * If a lockless V snapshot finds none, retain the existing head fallback so
 * a transiently all-ineligible queue cannot be stranded. Pops again after a
 * failed dispatch, see cid_queue_move_head_to_local().
 */
static __noinline bool cid_edq_move_first_eligible_to_local(s32 cid, u64 vref)
{
	struct scx_edq __arena *edq = &cid_pack(cid)->edq;
	cid_edq_task_t *at;

	while (can_loop) {
		at = (cid_edq_task_t *)scx_edq_pop_first_eligible_or_first(
								edq, vref, true);
		if (!at)
			return false;
		if (cid_edq_dispatch_popped(at, NULL, cid))
			return true;
	}
	return false;
}

static bool cid_queue_insert(struct task_struct *p, task_ctx_t *tctx,
			     s32 cid, u64 slice,
			     u64 deadline, u64 vruntime, u64 enq_flags)
{
	cid_edq_task_t *at;
	int ret;

	at = cid_edq_task(tctx);
	if (!at) {
		scx_bpf_error("missing EDQ task for pid %d", p->pid);
		return false;
	}
	/*
	 * A held node was popped by an older enqueue workflow. A property-change
	 * dequeue can end that workflow and re-enqueue the task before the old
	 * dispatcher drops its hold. Do not let the one intrusive node represent
	 * both workflows: direct-dispatch the new one and make the stale pop fail
	 * its state check.
	 */
	if (READ_ONCE(at->common.holdcnt)) {
		WRITE_ONCE(at->state, CID_EDQ_DISPATCHED);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid, slice, enq_flags);
		return false;
	}
	if (READ_ONCE(at->state) == CID_EDQ_ENQUEUED)
		scx_bpf_error("EDQ double enqueue for pid %d", p->pid);
	at->slice = slice;
	at->enq_flags = enq_flags;
	at->cid = cid;
	/* Publish custody before the node becomes visible to another CPU's pop. */
	WRITE_ONCE(at->state, CID_EDQ_ENQUEUED);
	ret = scx_edq_insert(&cid_pack(cid)->edq, &at->common, deadline,
			      vruntime);
	if (ret) {
		__sync_val_compare_and_swap(&at->state, CID_EDQ_ENQUEUED,
					CID_EDQ_NONE);
		scx_bpf_error("EDQ insert failed for pid %d: %d", p->pid, ret);
		return false;
	}
	return true;
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
 * Idle cid tracking.
 *
 * The idle state of every cid is kept here rather than in the kernel's
 * idle masks. Implementing ops.update_idle() turns the built-in tracking
 * off, and with it the kernel's own idle CPU selection, whose walk of the
 * topology masks was the single most expensive step of a wakeup and knew
 * nothing of the capacity ordering anyway.
 *
 * The state is a flag word per cid, the truth of that cid, and a bitmap
 * that follows the flags and that the scans read a word at a time, see
 * the note above the bitmap helpers for why the two are separate.
 * Whether a whole core is idle is read from the flags of its siblings,
 * contiguous in cid space, so there is no core bitmap or count to keep
 * in step: a count kept next to the bits is two operations, and between
 * the two another CPU reads a count that is off by one.
 *
 * ops.update_idle() only fires on real idle transitions. A cid that was
 * claimed for a task and kicked, and then found nothing to run, goes back
 * to idle without a transition and would keep its bit cleared for good:
 * ops.dispatch() re-arms the bit whenever a cid is about to idle. The
 * re-arm can be wrong the other way, when a task lands on the cid right
 * after it, since a cid that never went idle sees no transition either:
 * ops.running() clears the bit again in that case.
 */
static bool cid_idle_test(s32 cid)
{
	return cid_valid(cid) && __cmask_test(cid, idle_cids);
}

/*
 * Return true if the whole core of @cid is idle, i.e. @cid is idle and so
 * are its SMT siblings, if any.
 */
static bool core_is_idle(s32 cid)
{
	struct cid_topo __arena *topo;
	u32 base, nr, shift;
	u64 mask;

	if (!cid_valid(cid))
		return false;
	topo = cid_topo(cid);
	base = topo->core_base;
	nr = topo->core_nr;
	shift = base & 63;

	/* A core within one word, which every SMT core is: one load. */
	if (nr && nr < 64 && shift + nr <= 64 && __cmask_contains(base, idle_cids)) {
		mask = ((1ULL << nr) - 1) << shift;
		return (*__cmask_word(base, idle_cids) & mask) == mask;
	}

	return cmask_full_range(idle_cids, base, nr);
}

/*
 * Return true when every SMT sibling of @cid is idle. This is fair.c's
 * is_core_idle() test as sched_use_asym_prio() applies it to a running
 * source CPU: @cid itself is deliberately excluded.
 */
static bool siblings_idle(s32 cid)
{
	struct cid_topo __arena *topo;
	u32 sibling;

	if (!cid_valid(cid))
		return false;
	topo = cid_topo(cid);
	bpf_arena_for(sibling, topo->core_base, topo->core_base + topo->core_nr) {
		if (sibling != (u32)cid && !cid_idle_test(sibling))
			return false;
	}

	return true;
}

static bool smt_asym_active(s32 cid)
{
	return smt_enabled && cid_valid(cid) &&
	       (force_smt_asym_packing || cid_topo(cid)->smt_asym_packing);
}

static bool smt_prefer(s32 a, s32 b)
{
	if (!cid_valid(a) || !cid_valid(b))
		return false;
	if (force_smt_asym_packing)
		return cid_topo(a)->cpu < cid_topo(b)->cpu;
	return cid_topo(a)->place_tier < cid_topo(b)->place_tier;
}

static bool active_balance_due(s32 cid, u64 now);

/* fair.c's sd_balance_shared::has_idle_cores hint, keyed by LLC base cid. */
static bool test_idle_cores(s32 cid)
{
	struct cid_topo __arena *topo;

	if (!cid_valid(cid))
		return false;
	topo = cid_topo(cid);

	return __cmask_test(topo->llc_base, idle_core_llcs);
}

static void set_idle_cores(s32 cid, bool has_idle_core)
{
	struct cid_topo __arena *topo;

	if (!cid_valid(cid))
		return;
	topo = cid_topo(cid);
	if (has_idle_core)
		cmask_set(topo->llc_base, idle_core_llcs);
	else
		cmask_clear(topo->llc_base, idle_core_llcs);
}

/*
 * Claim the idle state of @cid, returning true if this caller is the one
 * that took it out of the idle state. Claiming keeps concurrent wakeups
 * from aiming at the same cid.
 */
static bool cid_idle_claim(s32 cid)
{
	return cid_valid(cid) && cmask_test_and_clear(cid, idle_cids);
}

/*
 * Mark @cid idle, unless it already is.
 */
static void cid_idle_set(s32 cid)
{
	if (!cid_valid(cid))
		return;

	cmask_set(cid, idle_cids);
	if (smt_enabled && !test_idle_cores(cid) && core_is_idle(cid))
		set_idle_cores(cid, true);
}

/*
 * Queued cid tracking.
 *
 * One bit per cid whose EDQ holds at least one task, kept next to the
 * idle bitmap and scanned the same way, so that a cid looking for work
 * to pull walks a word of it instead of peeking at every EDQ of the node.
 *
 * The bit is set after a task is queued and cleared by whoever finds the
 * EDQ empty, with a second look after the clear in case a task was queued
 * in between. It is a hint: the kernel can dequeue a task behind the
 * scheduler's back, and a bit left set is cleared by the first cid that
 * peeks and finds nothing.
 */
static bool cid_queued_test(s32 cid)
{
	return cid_valid(cid) && __cmask_test(cid, queued_cids);
}

/*
 * fair.c's choose_sched_idle_rq(): a normal task may share a CPU whose
 * runqueue contains only SCHED_IDLE work instead of waiting on a normal
 * task elsewhere. Cidland does not count policy classes in a remote EDQ, so
 * recognize the exact cheap case: a SCHED_IDLE current with no waiter.
 */
static bool cid_sched_idle_target(const struct task_struct *p, s32 cid)
{
	struct cid_ctx __arena *cctx;

	if (p->policy == SCHED_IDLE || !cid_valid(cid) || cid_idle_test(cid) ||
	    cid_queued_test(cid))
		return false;
	cctx = cid_ctx(cid);

	return cctx->pack.curr_w && cctx->curr_idle;
}

static void cid_queued_set(s32 cid)
{
	if (cid_valid(cid))
		cmask_set(cid, queued_cids);
}

/*
 * Clear the queued bit of @cid if its EDQ is empty, looking again after
 * the clear for a task queued in the meantime.
 */
static void cid_queued_check(s32 cid)
{
	if (!cid_valid(cid) || cid_queue_nr(cid))
		return;
	/*
	 * The queue is empty because ops.dispatch() has just taken its head
	 * while the task that was running is still runnable: that task is
	 * enqueued back here as soon as ops.dispatch() returns,
	 * put_prev_task_scx(). Clearing the bit now and setting it again
	 * then is two atomic writes per switch to a word every CPU shares,
	 * and the cacheline bouncing between CPUs each switching between
	 * two of their own tasks ran a pinned pair of yielders per CPU five
	 * times slower than fair.c. Leave the bit alone: the enqueue finds
	 * it set and writes nothing, and clears the flag.
	 */
	if (READ_ONCE(cid_ctx(cid)->requeue_pending))
		return;
	cmask_clear(cid, queued_cids);
	if (cid_queue_nr(cid))
		cmask_set(cid, queued_cids);
}

/*
 * Rotate @w right by @s bits, so that the bits from @s on come first.
 */
static __always_inline u64 rotr64(u64 w, u32 s)
{
	s &= 63;
	return s ? (w >> s) | (w << (64 - s)) : w;
}

/*
 * Return word @k of the cids in placement tier @t.
 */
static __always_inline u64 place_tier_word(u32 t, u32 k)
{
	return cmask_word(place_tier_mask(t), k);
}

static __always_inline u64 capacity_tier_word(u32 t, u32 k)
{
	return cmask_word(capacity_tier_mask(t), k);
}

/*
 * Return the first idle cid of word @k of @w that @p can run on and, if
 * @whole_core is set, whose whole core is idle, or -EBUSY.
 */
static __always_inline s32 first_idle_cid(const struct task_struct *p, u64 w,
					  u32 k, bool restricted, bool whole_core)
{
	while (w && can_loop) {
		s32 cid = k * 64 + __builtin_ctzll(w);

		/*
		 * The flag is the truth: a cid that was just claimed keeps
		 * its bit until the claim's add lands, and a scan that took
		 * the bit for the truth picked the same cid again on every
		 * retry after losing a claim to it, ran out of retries and
		 * had a fork fall back to the shallowest queue, the sibling
		 * of a busy CPU as often as not.
		 */
		if (__cmask_test(cid, idle_cids) &&
		    (!whole_core || core_is_idle(cid)) &&
		    (!restricted || cid_allowed(p, cid)))
			return cid;
		w &= w - 1;
	}

	return -EBUSY;
}

/*
 * Return the first cid of word @k of @w that @p can run on, or -EBUSY.
 * first_idle_cid() without the idle test, for a word that is not a slice
 * of the idle bitmap: a word of the cids with nothing queued is what a
 * fork wants, whether or not they are running something.
 */
static __always_inline s32 first_allowed_cid(const struct task_struct *p,
					     u64 w, u32 k, bool restricted)
{
	while (w && can_loop) {
		s32 cid = k * 64 + __builtin_ctzll(w);

		if (!restricted || cid_allowed(p, cid))
			return cid;
		w &= w - 1;
	}

	return -EBUSY;
}

/* Scan idle cids without an asymmetric-packing tier restriction. */
static __always_inline s32
scan_idle_unranked_range(const struct task_struct *p, u32 base, u32 nr,
			 bool restricted, bool whole_core)
{
	u32 k, last;

	if (!nr)
		return -EBUSY;
	last = (base + nr - 1) / 64;
	bpf_arena_for(k, base / 64, last + 1) {
		u64 w = cmask_word(idle_cids, k) &
			cmask_range_word(idle_cids, k, base, nr);
		s32 cid;

		if (!w)
			continue;
		cid = first_idle_cid(p, w, k, restricted, whole_core);
		if (cid >= 0)
			return cid;
	}

	return -EBUSY;
}

/* scan_idle_range() restricted by CPU capacity rather than packing priority. */
static __always_inline s32
scan_idle_capacity_range(const struct task_struct *p, u32 t, u32 base, u32 nr,
			 bool restricted, bool whole_core)
{
	u32 k, last;

	if (!nr)
		return -EBUSY;
	last = (base + nr - 1) / 64;
	bpf_arena_for(k, base / 64, last + 1) {
		u64 w = cmask_word(idle_cids, k) & capacity_tier_word(t, k) &
			cmask_range_word(idle_cids, k, base, nr);
		s32 cid;

		if (!w)
			continue;
		cid = first_idle_cid(p, w, k, restricted, whole_core);
		if (cid >= 0)
			return cid;
	}

	return -EBUSY;
}

/* Flags for pick_idle_cid_topology() */
enum pick_idle_flags {
	/* @prev_cid is in @p's allowed set and can be returned as is */
	PICK_IDLE_PREV_ALLOWED	= 1 << 0,

	/* Only consider cids whose whole core is idle */
	PICK_IDLE_WHOLE_CORE	= 1 << 1,

	/* Return the cid without claiming it, for a caller that only kicks */
	PICK_IDLE_NO_CLAIM	= 1 << 2,

	/* Restrict the scan to the LLC containing @prev_cid */
	PICK_IDLE_LLC_ONLY	= 1 << 3,
};

/*
 * Would @p fit on a cid of this capacity, or does it want more of a CPU
 * than that one is?
 *
 * select_idle_sibling() asks this before it settles for a CPU the task
 * has already run on, and takes the idle one only if the task fits it:
 *
 *	if (prev != target && cpus_share_cache(prev, target) &&
 *	    (!cpus_allowed || cpumask_test_cpu(prev, allowed)) &&
 *	    choose_idle_cpu(prev, p) &&
 *	    asym_fits_cpu(task_util, util_min, util_max, prev)) {
 *
 * Without the last test a task that once landed on a slow CPU and keeps
 * waking while that CPU happens to be idle is never offered a faster one
 * again: the cheapest answer is always the one it already has. A task
 * that only wants a fraction of a CPU is welcome to stay, which is what
 * makes the short circuit worth having; one that wants the whole of it
 * goes on to the tier walk.
 *
 * Only asymmetric machines ask at all, as asym_fits_cpu() does with
 * sched_asym_cpucap_active().
 */
static bool task_fits_cid(task_ctx_t *tctx, s32 cid, u64 now)
{
	if (!asym_capacity || !tctx)
		return true;

	return util_fits_cap(task_util(tctx, now), cid_topo(cid)->cap);
}

/*
 * fair.c's select_idle_smt_cpu(): redirect an idle CPU to a more-preferred
 * available sibling when SD_ASYM_PACKING is active in its SMT domain.
 */
static s32 select_idle_smt_cpu(const struct task_struct *p, s32 cid)
{
	struct cid_topo __arena *topo;
	s32 best = cid;
	u32 sibling;

	if (!smt_asym_active(cid))
		return cid;
	topo = cid_topo(cid);

	bpf_arena_for(sibling, topo->core_base, topo->core_base + topo->core_nr) {
		if (sibling == (u32)best || !cid_idle_test(sibling) ||
		    !cid_allowed(p, sibling))
			continue;
		if (smt_prefer(sibling, best))
			best = sibling;
	}

	return best;
}

/* select_idle_smt_cpu(), restricted to active-balance destinations that are due. */
static s32 select_idle_smt_balance_cid(const struct task_struct *p, s32 cid,
				       u64 now)
{
	struct cid_topo __arena *topo;
	s32 best = cid;
	u32 sibling;

	if (!smt_asym_active(cid))
		return cid;
	topo = cid_topo(cid);
	bpf_arena_for(sibling, topo->core_base, topo->core_base + topo->core_nr) {
		if (sibling == (u32)best || !cid_idle_test(sibling) ||
		    !cid_allowed(p, sibling) || !active_balance_due(sibling, now))
			continue;
		if (smt_prefer(sibling, best))
			best = sibling;
	}

	return best;
}

static s32 claim_idle_cid(const struct task_struct *p, s32 cid)
{
	cid = select_idle_smt_cpu(p, cid);

	return cid_idle_claim(cid) ? cid : -EAGAIN;
}

/*
 * Pick an idle cid for @p in topology order. Ordinary fair.c idle selection
 * does not rank different cores by SD_ASYM_PACKING priority: it searches the
 * target LLC and redirects only the selected CPU to a preferred SMT sibling.
 * Keep that policy out of this wakeup path. When CPU capacity itself is
 * asymmetric, capacity tiers remain the outer ordering, corresponding to
 * fair.c's separate select_idle_capacity() path.
 * Only fully idle cores are considered if @whole_core is set, any idle cid
 * otherwise. pick_idle_cid() uses the LLC's has_idle_core hint to decide
 * whether to run the whole-core pass, the way select_idle_sibling() chooses
 * between select_idle_core() and select_idle_cpu().
 *
 * An idle @prev_cid wins before capacity tiers are walked. Otherwise, each
 * capacity tier considers a cid in the same LLC, then the same node, then any
 * cid. On uniform-capacity systems there is one unranked pass instead. This
 * keeps a task where its cache is warm instead of moving it for a transient
 * capacity advantage. The domain order is the one select_idle_sibling()
 * applies, with the node on top since this scan covers them all. Each domain
 * is a contiguous range, so a wakeup reads the words of its own LLC before
 * anything else.
 *
 * The idle state is claimed only for the cid that is returned. -EAGAIN
 * means a candidate was found but claimed by someone else first. @flags
 * is a mask of PICK_IDLE_*.
 *
 * A global function: verified once rather than at every call site, of
 * which the claim retries make eight.
 */
__noinline s32 pick_idle_cid_topology(struct task_struct *p __arg_trusted,
				      s32 prev_cid, u32 flags)
{
	bool is_prev_allowed = flags & PICK_IDLE_PREV_ALLOWED;
	bool whole_core = flags & PICK_IDLE_WHOLE_CORE;
	bool llc_only = flags & PICK_IDLE_LLC_ONLY;
	struct cid_topo __arena *prev;
	bool restricted;
	s32 best = -EBUSY;
	u32 nr_tiers = asym_capacity ? nr_capacity_tiers : 1;
	u32 t;
	/* Only an asymmetric machine asks task_fits_cid() anything. */
	task_ctx_t *tctx = asym_capacity ? try_lookup_task_ctx(p) : NULL;
	u64 now = asym_capacity ? scx_bpf_now() : 0;

	TOUCH_ARENA();

	if (!cid_valid(prev_cid))
		return -EBUSY;
	prev = cid_topo(prev_cid);
	restricted = is_restricted(p);
	if (is_prev_allowed && cid_idle_test(prev_cid) &&
	    (!whole_core || core_is_idle(prev_cid)) &&
	    task_fits_cid(tctx, prev_cid, now)) {
		best = prev_cid;
		goto claim;
	}

	bpf_arena_for(t, 0, nr_tiers) {
		/*
		 * A domain that is the whole of the next one is not scanned
		 * twice.
		 */
		if (asym_capacity)
			best = scan_idle_capacity_range(p, t, prev->llc_base,
						prev->llc_nr, restricted, whole_core);
		else
			best = scan_idle_unranked_range(p, prev->llc_base,
						prev->llc_nr, restricted, whole_core);
		if (best < 0 && !llc_only && numa_enabled && prev->node_nr > prev->llc_nr)
			best = asym_capacity ?
				scan_idle_capacity_range(p, t, prev->node_base,
							 prev->node_nr, restricted, whole_core) :
				scan_idle_unranked_range(p, prev->node_base,
						       prev->node_nr, restricted, whole_core);
		if (best < 0 && !llc_only &&
		    (numa_enabled ? prev->node_nr : prev->llc_nr) < nr_cids)
			best = asym_capacity ?
				scan_idle_capacity_range(p, t, 0, nr_cids,
							 restricted, whole_core) :
				scan_idle_unranked_range(p, 0, nr_cids,
						       restricted, whole_core);
		if (best >= 0)
			break;
	}

claim:
	if (best >= 0) {
		best = select_idle_smt_cpu(p, best);
		if (!(flags & PICK_IDLE_NO_CLAIM))
			best = cid_idle_claim(best) ? best : -EAGAIN;
	}

	return best;
}

/* fair.c's select_idle_smt(): scan the previous CPU's SMT siblings. */
static s32 select_idle_smt(const struct task_struct *p, s32 prev_cid,
			   s32 target)
{
	struct cid_topo __arena *prev, *dst;
	u32 sibling;

	if (!smt_enabled || !cid_valid(prev_cid) || !cid_valid(target))
		return -EBUSY;
	prev = cid_topo(prev_cid);
	dst = cid_topo(target);
	if (prev->llc_base != dst->llc_base)
		return -EBUSY;

	bpf_arena_for(sibling, prev->core_base, prev->core_base + prev->core_nr) {
		s32 cid;

		if (sibling == (u32)prev_cid || !cid_idle_test(sibling) ||
		    !cid_allowed(p, sibling))
			continue;
		cid = claim_idle_cid(p, sibling);
		if (cid >= 0)
			return cid;
	}

	return -EBUSY;
}

/*
 * Scan for an idle cid in fair.c's order within the target LLC: a fully idle
 * core when the LLC says one exists, otherwise an idle sibling of @prev_cid,
 * then any idle CPU. Cidland's node/global extensions follow only if the LLC
 * has no whole idle core left to offer.
 *
 * Under @smt_whole_core the order departs from select_idle_sibling()
 * in one place: a whole idle core outside the target LLC is taken before a
 * half-busy core inside it. An idle sibling of a busy core is not a free CPU;
 * it is half of a core that is already working, and taking it costs the
 * thread running there about half its throughput for as long as the two
 * overlap. fair.c never has to choose, because select_idle_sibling() stops at
 * the LLC and leaves the rest to the periodic balancer; this scan does cross
 * LLCs, so it has to say which it prefers.
 *
 * Measured on a 2-node 176-core Olympus SMT machine with one LLC per node:
 * with node 0 saturated by an 88-thread NVPL SGEMM, everything else the
 * machine woke landed on node 0's idle siblings while node 1's 88 fully idle
 * cores sat unused. The workers themselves were placed correctly, and it
 * still cost 10-14% of throughput, because the hierarchical barrier makes
 * every worker wait for the halved one: about 1 s of dual-thread operation
 * over a run turned into 4.4 s per thread of extra barrier wait. Repairing it
 * from the balance side cannot work - those visits have a median length of
 * 24 us against an active-balance interval of the domain weight in ms - so
 * placement is the only point at which it can be prevented.
 *
 * The trade is cache locality for core throughput, so it is spent only when
 * there is a whole idle core to be had. The idle_core_llcs hint says whether
 * any LLC has one, which makes "no" a single word test.
 */
static s32 pick_idle_cid(const struct task_struct *p, s32 prev_cid, s32 target)
{
	u32 flags = !is_restricted(p) || cid_allowed(p, target) ?
		    PICK_IDLE_PREV_ALLOWED : 0;
	s32 cid = -EBUSY;
	int i;

	/*
	 * If the task can't migrate, there's no point looking for other
	 * cids.
	 */
	if (is_pcpu_task(p))
		return cid_idle_claim(prev_cid) ? prev_cid : -EBUSY;

	/*
	 * Nothing idle at all is the common case under load: say so without
	 * walking the tiers.
	 */
	if (cmask_empty(idle_cids))
		return -EBUSY;

	/*
	 * A claim that fails lost a race with another wakeup for the same
	 * cid. Scan again rather than give up: the bit is clear now, so the
	 * next candidate is a different cid, the way scx_bpf_pick_idle_cpu()
	 * keeps picking until a claim sticks. Giving up queued the loser on
	 * a busy CPU, and whichever idle CPU dispatched next, the sibling of
	 * a busy CPU as often as not, took it from there while whole idle
	 * cores sat unused: that is how a burst of forks or wakeups ended up
	 * with both siblings of a P-core busy and E-cores idle.
	 */
	for (i = 0; i < CLAIM_RETRIES; i++) {
		bool has_idle_core = smt_enabled && test_idle_cores(target);
		bool whole_scanned = false;

		if (has_idle_core) {
			cid = pick_idle_cid_topology((struct task_struct *)p, target,
						   flags | PICK_IDLE_WHOLE_CORE |
						   PICK_IDLE_LLC_ONLY);
			if (cid >= 0)
				return cid;
			if (cid == -EAGAIN)
				continue;
			set_idle_cores(target, false);
		}

		/*
		 * Cidland extends select_idle_sibling() beyond the target LLC.
		 * The extension goes first while a whole idle core is left
		 * anywhere: everything below this settles for an idle sibling
		 * of a busy core, which halves the thread already running on
		 * it. The hint mask has no bit set once no LLC has an idle
		 * core, which is the loaded case this must not slow down.
		 */
		if (smt_whole_core && smt_enabled &&
		    !cmask_empty(idle_core_llcs)) {
			whole_scanned = true;
			cid = pick_idle_cid_topology((struct task_struct *)p, target,
						   flags | PICK_IDLE_WHOLE_CORE);
			if (cid >= 0)
				return cid;
			if (cid == -EAGAIN)
				continue;
		}

		if (!has_idle_core && !asym_capacity) {
			cid = select_idle_smt(p, prev_cid, target);
			if (cid >= 0)
				return cid;
		}

		cid = pick_idle_cid_topology((struct task_struct *)p, target,
					   flags | PICK_IDLE_LLC_ONLY);
		if (cid >= 0)
			return cid;
		if (cid == -EAGAIN)
			continue;

		/*
		 * The same extension in its original place, still ahead of
		 * taking any idle cid at all, unless the pass above has just
		 * run this scan and failed. With the option on it is reached
		 * when the hint said no LLC had an idle core, and the scan
		 * still runs there because the hint is only a hint.
		 */
		if (smt_enabled && !whole_scanned) {
			cid = pick_idle_cid_topology((struct task_struct *)p, target,
						   flags | PICK_IDLE_WHOLE_CORE);
			if (cid >= 0)
				return cid;
			if (cid == -EAGAIN)
				continue;
		}

		cid = pick_idle_cid_topology((struct task_struct *)p, target, flags);
		if (cid != -EAGAIN)
			return cid >= 0 ? cid : -EBUSY;
	}

	return -EBUSY;
}

#define ACTIVE_BALANCE_MAX_INTERVAL_MS 512U

enum active_balance_outcome {
	ACTIVE_BALANCE_MISS,
	ACTIVE_BALANCE_MOVED,
	ACTIVE_BALANCE_PINNED,
};

/*
 * fair.c keeps the balance interval on the idle CPU which runs the balance,
 * not on the busy CPU which asks for one. Cidland has one active-balance
 * level covering the placement domain, so its minimum interval is the
 * domain weight in milliseconds. Ordinary misses back off only to twice
 * that interval; affinity failures may use the longer migration backoff.
 */
static u32 active_balance_min_ms(s32 cid)
{
	struct cid_topo __arena *topo = cid_topo(cid);

	return numa_enabled ? topo->node_nr : nr_cids;
}

static bool active_balance_due(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;

	if (!cid_valid(cid))
		return false;
	cctx = cid_ctx(cid);

	return !READ_ONCE(cctx->active_balance_pending) &&
	       !time_before(now, READ_ONCE(cctx->active_balance_next));
}

/*
 * Claim a due destination before sending its IPI. Stamping the next balance
 * while the claim is held prevents two source ticks from kicking the same
 * idle CPU for one interval.
 */
static bool active_balance_reserve(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;
	u32 interval;

	if (!active_balance_due(cid, now) || !cid_idle_test(cid))
		return false;
	cctx = cid_ctx(cid);
	/* 1 is an unpublished reservation; dispatch consumes only state 2. */
	if (__sync_val_compare_and_swap(&cctx->active_balance_pending, 0, 1))
		return false;
	if (!cid_idle_test(cid) ||
	    time_before(now, READ_ONCE(cctx->active_balance_next))) {
		WRITE_ONCE(cctx->active_balance_pending, 0);
		return false;
	}
	interval = MAX(READ_ONCE(cctx->active_balance_interval_ms),
		       active_balance_min_ms(cid));
	WRITE_ONCE(cctx->active_balance_next,
		   now + (u64)interval * NSEC_PER_MSEC);
	__sync_val_compare_and_swap(&cctx->active_balance_pending, 1, 2);

	return true;
}

static void active_balance_complete(s32 cid, u32 outcome)
{
	struct cid_ctx __arena *cctx;
	u32 min_ms, interval, max_ms;

	if (!cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	min_ms = active_balance_min_ms(cid);
	interval = MAX(READ_ONCE(cctx->active_balance_interval_ms), min_ms);
	if (outcome == ACTIVE_BALANCE_MOVED)
		interval = min_ms;
	else {
		max_ms = outcome == ACTIVE_BALANCE_PINNED ?
			 ACTIVE_BALANCE_MAX_INTERVAL_MS : min_ms * 2;
		interval = MIN(interval * 2, max_ms);
	}
	WRITE_ONCE(cctx->active_balance_interval_ms, interval);
}

/*
 * Scan packing tier @t for a fully idle, due active-balance destination.
 * Unlike wake placement this does not claim the idle bit; reservation is a
 * separate atomic step immediately before the kick.
 */
static __always_inline s32
balance_scan_range(const struct task_struct *p, s32 t, u32 base, u32 nr,
		   bool restricted, u64 now)
{
	u32 k, last;

	if (!nr)
		return -EBUSY;
	last = (base + nr - 1) / 64;
	bpf_arena_for(k, base / 64, last + 1) {
		u64 w = cmask_word(idle_cids, k) &
			cmask_range_word(idle_cids, k, base, nr);

		if (t >= 0)
			w &= place_tier_word(t, k);

		while (w && can_loop) {
			s32 cid = k * 64 + __builtin_ctzll(w);

			w &= w - 1;
			if (!cid_valid(cid) || !cid_idle_test(cid) ||
			    (smt_enabled && !core_is_idle(cid)) ||
			    (restricted && !cid_allowed(p, cid)) ||
			    !active_balance_due(cid, now))
				continue;
			return cid;
		}
	}

	return -EBUSY;
}

/*
 * Find the idle destination that fair.c's asymmetric active balance would
 * use to pull @p off @src_cid. Across cores, sched_use_asym_prio() requires
 * the destination core to be fully idle under SMT. Within an SMT domain CPU
 * priority is always usable, so a preferred idle sibling is considered first.
 */
static s32 idle_asym_packing_cid(const struct task_struct *p, s32 src_cid,
				 u64 now)
{
	struct cid_topo __arena *src;
	task_ctx_t *tctx;
	bool restricted;
	u32 base, nr, nr_tiers, sibling, t;

	if (!asym_packing || !cid_valid(src_cid) || is_pcpu_task(p))
		return -EBUSY;
	src = cid_topo(src_cid);
	restricted = is_restricted(p);

	if (smt_enabled && src->smt_asym_packing) {
		bpf_arena_for(sibling, src->core_base, src->core_base + src->core_nr) {
			if (sibling != (u32)src_cid && cid_idle_test(sibling) &&
			    cid_topo(sibling)->place_tier < src->place_tier &&
			    (!restricted || cid_allowed(p, sibling)) &&
			    active_balance_due(sibling, now))
				return sibling;
		}
	}

	/*
	 * cidland has no fair-style group load attached to the running task.
	 * Do not actively chase a bursty current task through transient idle
	 * gaps; queued work is handled independently by the detach scan.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx || util_fits_cap(task_util(tctx, now), src->cap))
		return -EBUSY;

	/* Balance the child LLC domain before walking its parent, as fair.c does. */
	nr_tiers = src->place_tier;
	if (smt_enabled && !siblings_idle(src_cid))
		nr_tiers = nr_place_tiers;
	if (!nr_tiers)
		goto parent;
	bpf_arena_for(t, 0, nr_tiers) {
		s32 cid = balance_scan_range(p, t, src->llc_base, src->llc_nr,
					     restricted, now);

		if (cid >= 0)
			return cid;
	}

parent:
	/*
	 * At the parent domain, compare scheduling groups by their preferred
	 * CPU, not an arbitrary source CPU. The local-LLC scan above already
	 * exhausted these tiers, so a global scan cannot select it again.
	 */
	nr_tiers = src->llc_place_tier;
	if (!nr_tiers)
		return -EBUSY;
	base = numa_enabled ? src->node_base : 0;
	nr = numa_enabled ? src->node_nr : nr_cids;
	bpf_arena_for(t, 0, nr_tiers) {
		s32 cid = balance_scan_range(p, t, base, nr, restricted, now);

		if (cid >= 0 && cid_topo(cid)->llc_base != src->llc_base)
			return cid;
	}

	return -EBUSY;
}

/*
 * Find a fully idle CPU of the highest capacity available to a task that does
 * not fit @src_cid, mirroring fair.c's misfit active-balance case. A saturated
 * task does not pass fits_capacity() even on the fastest CPU; fair.c stops
 * treating it as misfit there through p->max_allowed_capacity instead. Thus
 * the destination is the task's highest allowed capacity, not necessarily a
 * CPU on which its current utilization passes the headroom test.
 */
static s32 idle_misfit_cid(const struct task_struct *p, s32 src_cid, u64 now)
{
	task_ctx_t *tctx;
	bool restricted;
	u64 util, src_cap, max_cap = 0;
	s32 best = -EBUSY;
	u32 cid;

	if (!asym_capacity || !cid_valid(src_cid) || is_pcpu_task(p))
		return -EBUSY;
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return -EBUSY;
	util = task_util(tctx, now);
	src_cap = cid_topo(src_cid)->cap;
	restricted = is_restricted(p);

	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_topo __arena *dst;

		if (restricted && !cid_allowed(p, cid))
			continue;
		dst = cid_topo(cid);
		if (dst->cap > max_cap)
			max_cap = dst->cap;
	}
	if (src_cap == max_cap || util_fits_cap(util, src_cap))
		return -EBUSY;

	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_topo __arena *dst = cid_topo(cid);

		if (dst->cap != max_cap || cid == (u32)src_cid ||
		    !cid_idle_test(cid) ||
		    (smt_enabled && !core_is_idle(cid)) ||
		    (restricted && !cid_allowed(p, cid)) ||
		    !active_balance_due(cid, now))
			continue;
		best = cid;
		break;
	}

	return best;
}

static s32 idle_balance_cid(const struct task_struct *p, s32 src_cid, u64 now)
{
	struct cid_topo __arena *src;
	s32 cid;

	if (cmask_empty(idle_cids) || !cid_valid(src_cid) || is_pcpu_task(p))
		return -EBUSY;

	/*
	 * fair.c's group_smt_balance: a task sharing its core is moved to a
	 * fully idle core of the LLC first. The tick asks every millisecond
	 * and fair.c samples once a balance interval, so the contention has
	 * to have lasted a slice before a core is asked to split it: a
	 * sibling that is busy for one wakeup is not a core worth splitting.
	 */
	src = cid_topo(src_cid);
	if (smt_enabled && !siblings_idle(src_cid)) {
		struct cid_ctx __arena *cctx = cid_ctx(src_cid);

		if (!cctx->smt_busy_since)
			cctx->smt_busy_since = now;
		else if (!time_before(now, cctx->smt_busy_since + slice_ns)) {
			cid = balance_scan_range(p, -1, src->llc_base,
						 src->llc_nr, is_restricted(p),
						 now);
			if (cid >= 0)
				return select_idle_smt_balance_cid(p, cid, now);
		}
	} else if (smt_enabled) {
		cid_ctx(src_cid)->smt_busy_since = 0;
	}

	if (!asym_packing && !asym_capacity)
		return -EBUSY;
	cid = idle_asym_packing_cid(p, src_cid, now);
	if (cid < 0)
		cid = idle_misfit_cid(p, src_cid, now);

	return cid >= 0 ? select_idle_smt_balance_cid(p, cid, now) : cid;
}

enum active_balance_type {
	ACTIVE_BALANCE_NONE,
	ACTIVE_BALANCE_CAPACITY,
	ACTIVE_BALANCE_REMOTE_PACKING,
	ACTIVE_BALANCE_LOCAL_SMT,
	ACTIVE_BALANCE_LOCAL_PACKING,
};

/*
 * Classify the imbalance between an idle destination and a source. This is
 * task-independent: affinity and capacity fit are checked when a queued task
 * is detached or the source revalidates its current task.
 */
static u32 active_balance_type(s32 dst_cid, s32 src_cid)
{
	struct cid_topo __arena *dst, *src;

	if (!cid_valid(dst_cid) || !cid_valid(src_cid) || dst_cid == src_cid ||
	    cid_idle_test(src_cid))
		return ACTIVE_BALANCE_NONE;
	dst = cid_topo(dst_cid);
	src = cid_topo(src_cid);
	/*
	 * Between the threads of one core only a kernel-provided priority
	 * moves a running task; --smt-asym-packing ranks equal threads for
	 * placement and never migrates between them.
	 */
	if (dst->core_base == src->core_base)
		return asym_packing && dst->smt_asym_packing &&
		       dst->place_tier < src->place_tier ?
		       ACTIVE_BALANCE_LOCAL_PACKING : ACTIVE_BALANCE_NONE;
	if (smt_enabled && dst->llc_base == src->llc_base &&
	    core_is_idle(dst_cid) && !siblings_idle(src_cid))
		return ACTIVE_BALANCE_LOCAL_SMT;

	if (asym_packing) {
		if (dst->llc_base == src->llc_base &&
		    (!smt_enabled || core_is_idle(dst_cid))) {
			if (dst->place_tier < src->place_tier)
				return ACTIVE_BALANCE_LOCAL_PACKING;
			if (smt_enabled && !siblings_idle(src_cid))
				return ACTIVE_BALANCE_LOCAL_SMT;
		}
		if (dst->llc_base != src->llc_base &&
		    (!numa_enabled || dst->node_base == src->node_base) &&
		    (!smt_enabled || core_is_idle(dst_cid)) &&
		    dst->llc_place_tier < src->llc_place_tier) {
			return ACTIVE_BALANCE_REMOTE_PACKING;
		}
	}

	if (asym_capacity && dst->cap > src->cap &&
	    (!smt_enabled || core_is_idle(dst_cid)))
		return ACTIVE_BALANCE_CAPACITY;

	return ACTIVE_BALANCE_NONE;
}

static bool task_hot(const task_ctx_t *tctx, s32 src_cid, s32 dst_cid,
		     u64 now);

#define BALANCE_TASK_SCAN	8U

/*
 * Validate and remove the first usable task in a bounded deadline-ordered EDQ
 * prefix. Holding each node across the affinity and hotness checks and
 * removing that exact node prevents a concurrent enqueue from substituting a
 * different task before the steal, giving EDQ the same validate-the-entity
 * semantics as fair's locked detach.
 */
static __noinline enum cid_edq_move_result
cid_edq_move_usable_task_to_local(s32 dst_cid, s32 src_cid, u64 now,
				  bool check_hot)
{
	u32 nth;

	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		struct task_struct *p;
		enum cid_edq_move_result move;
		int ret;

		ret = cid_edq_try_peek_nth(src_cid, nth, &at);
		if (ret)
			return ret == -EBUSY ? CID_EDQ_MOVE_BUSY :
					      CID_EDQ_MOVE_MISS;
		if (!at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		if (READ_ONCE(at->state) != CID_EDQ_ENQUEUED ||
		    (check_hot &&
		     task_hot((task_ctx_t *)at, src_cid, dst_cid, now))) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		p = scx_bpf_tid_to_task(at->tid);
		if (!p || !cid_allowed(p, dst_cid)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		move = cid_edq_remove_held_to_local(src_cid, dst_cid, at, p);
		if (move != CID_EDQ_MOVE_MISS)
			return move;
	}

	return CID_EDQ_MOVE_MISS;
}

/*
 * Detach one eligible queued task from the selected source. Scan past an
 * affinity-restricted or cache-hot EDQ head, as fair.c's detach_tasks() walks
 * the CFS task list looking for a candidate.
 */
static __noinline u32 detach_one_queued_task(s32 dst_cid, s32 src_cid,
					     u64 now)
{
	bool pinned = false;
	u32 nth;

	TOUCH_ARENA();
	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		enum cid_edq_move_result move;
		struct task_struct *p;
		bool movable;
		int ret;

		ret = cid_edq_try_peek_nth(src_cid, nth, &at);
		if (ret == -EBUSY)
			break;
		if (ret || !at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		p = scx_bpf_tid_to_task(at->tid);
		if (!p || READ_ONCE(at->state) != CID_EDQ_ENQUEUED) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		movable = !is_pcpu_task(p) &&
			  bpf_cpumask_test_cpu(cid_topo(dst_cid)->cpu,
					       p->cpus_ptr);
		if (!movable)
			pinned = true;
		else if (task_hot((task_ctx_t *)at, src_cid, dst_cid, now))
			movable = false;
		if (!movable) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		move = cid_edq_remove_held_to_local(src_cid, dst_cid, at, p);
		if (move == CID_EDQ_MOVE_MOVED) {
			__sync_fetch_and_add(&nr_steals, 1);
			cid_queued_check(src_cid);
			return ACTIVE_BALANCE_MOVED;
		}
		if (move == CID_EDQ_MOVE_BUSY)
			break;
	}
	return pinned ? ACTIVE_BALANCE_PINNED : ACTIVE_BALANCE_MISS;
}

/*
 * Select the busiest source with the strongest asymmetric imbalance. Try to
 * detach an eligible queued task from it first; only if that fails ask for its
 * current task through active balance. This is the focused equivalent of
 * sched_balance_find_src_group(), sched_balance_find_src_rq(), detach_tasks()
 * and the active-balance fallback.
 */
static bool request_active_balance(s32 dst_cid, u64 now)
{
	struct cid_ctx __arena *dst = cid_ctx(dst_cid);
	u32 base = numa_enabled ? cid_topo(dst_cid)->node_base : 0;
	u32 nr = numa_enabled ? cid_topo(dst_cid)->node_nr : nr_cids;
	u32 start = dst->steal_cursor;
	u32 best_type = ACTIVE_BALANCE_NONE, best_tier = 0;
	u32 best_nr_running = 0;
	u32 detach = ACTIVE_BALANCE_MISS;
	u64 best_util = 0;
	s32 best = -1;
	u32 i;

	if ((!smt_enabled && !asym_packing && !asym_capacity) ||
	    !cid_idle_test(dst_cid))
		return false;
	if (start < base || start >= base + nr)
		start = base;

	bpf_arena_for(i, 0, nr) {
		s32 src_cid = base + (start - base + i) % nr;
		struct cid_ctx __arena *src = cid_ctx(src_cid);
		u32 type = active_balance_type(dst_cid, src_cid);
		u32 nr_running;
		u64 util;

		if (!type)
			continue;
		nr_running = cid_queue_nr(src_cid) +
			     !!READ_ONCE(src->pack.curr_w);
		if (!nr_running)
			continue;
		util = cid_util(src_cid, now);
		if (best >= 0 && type < best_type)
			continue;
		if (best >= 0 && type == best_type &&
		    cid_topo(src_cid)->place_tier < best_tier)
			continue;
		if (best >= 0 && type == best_type &&
		    cid_topo(src_cid)->place_tier == best_tier &&
		    nr_running < best_nr_running)
			continue;
		if (best >= 0 && type == best_type &&
		    cid_topo(src_cid)->place_tier == best_tier &&
		    nr_running == best_nr_running && util <= best_util)
			continue;
		best = src_cid;
		best_type = type;
		best_tier = cid_topo(src_cid)->place_tier;
		best_nr_running = nr_running;
		best_util = util;
	}

	if (best < 0) {
		active_balance_complete(dst_cid, ACTIVE_BALANCE_MISS);
		return false;
	}
	dst->steal_cursor = best + 1;
	if (cid_queued_test(best)) {
		detach = detach_one_queued_task(dst_cid, best, now);
		if (detach == ACTIVE_BALANCE_MOVED) {
			active_balance_complete(dst_cid, detach);
			return true;
		}
	}
	if (!READ_ONCE(cid_pack(best)->curr_w) ||
	    __sync_val_compare_and_swap(&cid_ctx(best)->active_balance_cid, -1,
					    dst_cid) != -1) {
		active_balance_complete(dst_cid, detach);
		return false;
	}
	scx_bpf_kick_cid(best, SCX_KICK_PREEMPT);

	return false;
}

/*
 * Consume and revalidate an idle destination's active-balance request against
 * the task which is actually running on @src_cid now.
 */
static s32 active_balance_target(const struct task_struct *p, s32 src_cid,
				 u64 now)
{
	struct cid_ctx __arena *cctx = cid_ctx(src_cid);
	struct cid_topo __arena *src, *dst;
	task_ctx_t *tctx = NULL;
	s32 dst_cid = READ_ONCE(cctx->active_balance_cid);
	s32 target = -EBUSY;
	u32 outcome = ACTIVE_BALANCE_MISS;
	u32 type;
	bool restricted;

	if (dst_cid < 0 ||
	    __sync_val_compare_and_swap(&cctx->active_balance_cid, dst_cid,
					 -1) != dst_cid)
		return -EBUSY;
	if (!cid_valid(dst_cid))
		return -EBUSY;
	if (is_pcpu_task(p) || !cid_allowed(p, dst_cid)) {
		outcome = ACTIVE_BALANCE_PINNED;
		goto out;
	}
	if (!cid_idle_test(dst_cid))
		goto out;
	src = cid_topo(src_cid);
	dst = cid_topo(dst_cid);

	type = active_balance_type(dst_cid, src_cid);
	if (type > ACTIVE_BALANCE_CAPACITY) {
		/* Preferred SMT siblings remain fair.c's direct priority case. */
		if (dst->core_base == src->core_base) {
			target = dst_cid;
			goto out;
		}
		if (type == ACTIVE_BALANCE_LOCAL_SMT) {
			target = dst_cid;
			goto out;
		}
		tctx = try_lookup_task_ctx(p);
		if (tctx && !util_fits_cap(task_util(tctx, now), src->cap))
			target = dst_cid;
		goto out;
	}

	if (!asym_capacity || dst->cap <= src->cap ||
	    (smt_enabled && !core_is_idle(dst_cid)))
		goto out;
	if (!tctx)
		tctx = try_lookup_task_ctx(p);
	if (!tctx)
		goto out;

	/* Match update_misfit_status(): stop at the maximum allowed capacity. */
	restricted = is_restricted(p);
	if (!util_fits_cap(task_util(tctx, now), src->cap)) {
		u64 max_cap = 0;
		u32 cid;

		bpf_arena_for(cid, 0, nr_cids) {
			if ((!restricted || cid_allowed(p, cid)) &&
			    cid_topo(cid)->cap > max_cap)
				max_cap = cid_topo(cid)->cap;
		}
		if (dst->cap == max_cap)
			target = dst_cid;
	}

out:
	if (target >= 0)
		outcome = ACTIVE_BALANCE_MOVED;
	active_balance_complete(dst_cid, outcome);
	return target;
}

#define WAKEE_DECAY_NS NSEC_PER_SEC

/* The record_wakee() half of fair.c's wake-affinity heuristic. */
static void record_wakee_cid(const struct task_struct *p, task_ctx_t *wctx,
			     u64 now)
{
	if (!wctx)
		return;

	if (time_after(now, wctx->wakee_decay_at + WAKEE_DECAY_NS)) {
		wctx->wakee_flips >>= 1;
		wctx->wakee_decay_at = now;
	}

	/* A pid is the closest BPF-storable identity to fair.c's task pointer. */
	if (wctx->last_wakee_pid != p->pid) {
		wctx->last_wakee_pid = p->pid;
		wctx->wakee_flips++;
	}
}

/* The wake_wide() half; cid LLC width stands in for sd_llc_size. */
static bool wake_wide_cid(const task_ctx_t *pctx, const task_ctx_t *wctx,
			  s32 this_cid)
{
	u32 master, slave, factor;

	if (!wctx || !pctx)
		return false;

	master = wctx->wakee_flips;
	slave = pctx->wakee_flips;
	factor = cid_topo(this_cid)->llc_nr;
	if (master < slave) {
		u32 tmp = master;

		master = slave;
		slave = tmp;
	}

	return slave >= factor && master >= slave * factor;
}

/*
 * Pick the target around which the idle search should run.
 *
 * This is the WA_IDLE half of fair.c's wake_affine(). The effective-load
 * half, wake_affine_weight(), is there but opt-in, --wa-weight, see
 * wake_affine_weight_cid(). As in fair.c, affinity is only considered for
 * a wakeup, when the waking cid is allowed and is in the previous cid's
 * LLC.
 *
 * Returning @this_cid does not select it. select_idle_sibling_cid() below
 * first looks for an idle target and previous cid, then scans around the
 * target, and only the caller's final return stacks the wakee there. This
 * distinction is what keeps wake_affine() ahead of select_idle_sibling()
 * without skipping select_idle_sibling().
 */
/*
 * The WA_WEIGHT half of wake_affine(): with both cids busy, the wakee goes
 * to the waking cid when that leaves the two better balanced than its
 * previous cid would, wake_affine_weight():
 *
 *	this_eff_load = cpu_load(cpu_rq(this_cpu));
 *	if (sync) {
 *		unsigned long current_load = task_h_load(current);
 *		if (current_load > this_eff_load)
 *			return this_cpu;
 *		this_eff_load -= current_load;
 *	}
 *	task_load = task_h_load(p);
 *	this_eff_load += task_load;
 *	if (sched_feat(WA_BIAS))
 *		this_eff_load *= 100;
 *	this_eff_load *= capacity_of(prev_cpu);
 *
 *	prev_eff_load = cpu_load(cpu_rq(prev_cpu));
 *	prev_eff_load -= task_load;
 *	if (sched_feat(WA_BIAS))
 *		prev_eff_load *= 100 + (sd->imbalance_pct - 100) / 2;
 *	prev_eff_load *= capacity_of(this_cpu);
 *	if (sync)
 *		prev_eff_load += 1;
 *	return this_eff_load < prev_eff_load ? this_cpu : nr_cpumask_bits;
 *
 * The loads are the time-averaged runnable weights, see cid_load() and
 * task_load(), which is what makes this different from counting queued
 * tasks: a waker that runs a little and sleeps a lot weighs little on its
 * cid, so a wakee it has just woken lands there, where it is next in line
 * behind a task about to sleep, rather than behind a full slice on the
 * cid it came from. This is where a waker hands a CPU to its wakee under
 * load, and without it a wakee on a saturated machine waited a slice on
 * its previous cid for one wakeup in five, where fair.c waits on one in
 * fourteen. The bias is the half of the domain's imbalance_pct fair.c
 * uses, 117 within an LLC and 110 within a core.
 *
 * It is off by default and --wa-weight turns it on: that saturated
 * wakeup pattern is the one place it has been measured to matter, and
 * across the rest of the benchmark set it is within noise at a cost of a
 * few percent on the wakeup-heavy runs, which fair.c pays for WA_WEIGHT
 * too.
 */
static __always_inline s32 wake_affine_weight_cid(const struct task_struct *p,
				  task_ctx_t *tctx,
				  const struct task_struct *waker,
				  task_ctx_t *wctx, s32 prev_cid,
				  s32 this_cid, bool sync, u64 now)
{
	s64 this_eff, prev_eff;
	u64 load;
	u32 pct;

	this_eff = cid_load(this_cid, now);
	if (sync) {
		u64 current_load = wctx ? task_load(waker, wctx, now) : 0;

		if (current_load > this_eff)
			return this_cid;
		this_eff -= current_load;
	}

	load = task_load(p, tctx, now);
	this_eff += load;
	this_eff *= 100;
	this_eff *= cid_topo(prev_cid)->cap;

	pct = smt_enabled && cid_topo(prev_cid)->core_base == cid_topo(this_cid)->core_base ?
	      100 + (110 - 100) / 2 : 100 + (117 - 100) / 2;
	prev_eff = (s64)cid_load(prev_cid, now) - (s64)load;
	prev_eff *= pct;
	prev_eff *= cid_topo(this_cid)->cap;
	if (sync)
		prev_eff += 1;

	return this_eff < prev_eff ? this_cid : prev_cid;
}

static s32 wake_affine_cid(const struct task_struct *p, task_ctx_t *tctx,
			   s32 prev_cid, s32 this_cid, u64 wake_flags, u64 now)
{
	const struct task_struct *waker;
	task_ctx_t *wctx;
	bool sync;

	if (!(wake_flags & SCX_WAKE_TTWU) || !cid_valid(this_cid))
		return prev_cid;

	waker = (void *)bpf_get_current_task_btf();
	wctx = waker ? try_lookup_task_ctx(waker) : NULL;
	record_wakee_cid(p, wctx, now);

	if (!cid_allowed(p, this_cid) || wake_wide_cid(tctx, wctx, this_cid) ||
	    cid_topo(this_cid)->llc_base != cid_topo(prev_cid)->llc_base)
		return prev_cid;

	/*
	 * If this cid is idle the wakeup came from interrupt context. Keep an
	 * idle previous cid when both are available, exactly as
	 * wake_affine_idle() does.
	 */
	if (cid_idle_test(this_cid))
		return cid_idle_test(prev_cid) ? prev_cid : this_cid;

	sync = !no_wake_sync && (wake_flags & SCX_WAKE_SYNC) && waker &&
	       !(waker->flags & PF_EXITING);

	/*
	 * There is no rq->nr_running available to BPF. A running cid with no
	 * task in either of its queues is the equivalent of nr_running == 1.
	 */
	if (sync && !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL) &&
	    !cid_queued_test(this_cid))
		return this_cid;

	/*
	 * wake_affine_idle()'s last word, an idle previous cid, and then the
	 * loads, if asked for: both cids are busy, and the one that ends up
	 * lighter wins.
	 */
	if (!wa_weight || cid_idle_test(prev_cid))
		return prev_cid;

	return wake_affine_weight_cid(p, tctx, waker, wctx, prev_cid, this_cid, sync,
				      now);
}

/*
 * The front of select_idle_sibling(): try its computed @target first, then
 * an idle cache-affine @prev_cid. pick_idle_cid() supplies the remaining
 * whole-core and idle-cid scan around @target.
 */
static s32 select_idle_sibling_cid(const struct task_struct *p, task_ctx_t *tctx,
				   s32 prev_cid, s32 target, bool *direct, u64 now)
{
	s32 cid;
	s32 recent = -1;

	if (cid_idle_test(target) && cid_allowed(p, target) &&
	    task_fits_cid(tctx, target, now)) {
		cid = claim_idle_cid(p, target);
		if (cid >= 0) {
			*direct = true;
			return cid;
		}
	}
	if (cid_allowed(p, target) && task_fits_cid(tctx, target, now) &&
	    cid_sched_idle_target(p, target))
		return target;

	if (prev_cid != target &&
	    cid_topo(prev_cid)->llc_base == cid_topo(target)->llc_base &&
	    cid_idle_test(prev_cid) && cid_allowed(p, prev_cid) &&
	    task_fits_cid(tctx, prev_cid, now)) {
		cid = claim_idle_cid(p, prev_cid);
		if (cid >= 0) {
			*direct = true;
			return cid;
		}
	}
	if (prev_cid != target &&
	    cid_topo(prev_cid)->llc_base == cid_topo(target)->llc_base &&
	    cid_allowed(p, prev_cid) && task_fits_cid(tctx, prev_cid, now) &&
	    cid_sched_idle_target(p, prev_cid))
		return prev_cid;

	/* Check and rotate p->recent_used_cpu at the same point fair.c does. */
	recent = tctx->recent_used_cid;
	tctx->recent_used_cid = prev_cid;
	if (cid_valid(recent) && recent != prev_cid && recent != target &&
	    cid_topo(recent)->llc_base == cid_topo(target)->llc_base &&
	    cid_idle_test(recent) && cid_allowed(p, recent) &&
	    task_fits_cid(tctx, recent, now)) {
		cid = claim_idle_cid(p, recent);
		if (cid >= 0) {
			*direct = true;
			return cid;
		}
	}
	if (cid_valid(recent) && recent != prev_cid && recent != target &&
	    cid_topo(recent)->llc_base == cid_topo(target)->llc_base &&
	    cid_allowed(p, recent) && task_fits_cid(tctx, recent, now) &&
	    cid_sched_idle_target(p, recent))
		return recent;

	cid = pick_idle_cid(p, prev_cid, target);
	if (cid >= 0)
		*direct = true;

	return cid;
}

/*
 * Return the cid of the node of @prev_cid with the fewest tasks queued
 * that @p can run on, the most-preferred one on ties, or -EBUSY.
 *
 * A new task that finds no idle CPU would otherwise be queued behind its
 * parent, and a parent forking a hundred workers on a busy system would
 * stack them all on one queue. find_idlest_cpu() spreads forks by load for
 * the same reason.
 */
static s32 shallowest_queue_cid(const struct task_struct *p, s32 prev_cid)
{
	struct cid_topo __arena *prev = cid_topo(prev_cid);
	u32 base = numa_enabled ? prev->node_base : 0;
	u32 nr = numa_enabled ? prev->node_nr : nr_cids;
	bool restricted = is_restricted(p);
	u32 t, k, last = (base + nr - 1) / 64;
	s32 best = -EBUSY, best_nr = 0;

	if (!nr)
		return -EBUSY;

	/*
	 * A cid with nothing queued is the usual answer and the bitmaps give it
	 * without a lookup. SD_ASYM_PACKING is not a fork-placement order in
	 * fair.c; rank this choice only when capacity itself is asymmetric.
	 */
	bpf_arena_for(t, 0, asym_capacity ? nr_capacity_tiers : 1) {
		bpf_arena_for(k, base / 64, last + 1) {
			u64 w = ~cmask_word(queued_cids, k) &
				cmask_range_word(queued_cids, k, base, nr);
			s32 cid;

			if (asym_capacity)
				w &= capacity_tier_word(t, k);
			if (!w)
				continue;
			cid = first_allowed_cid(p, w, k, restricted);
			if (cid >= 0)
				return cid;
		}
	}

	/* Every queue has something: look for the shallowest, a lookup per cid. */
	bpf_arena_for(k, base, base + nr) {
		s32 cid = k, nr_queued;

		if (cid >= nr_cids)
			break;
		if (restricted && !cid_allowed(p, cid))
			continue;
		nr_queued = cid_queue_nr(cid);
		if (best < 0 || nr_queued < best_nr ||
		    (nr_queued == best_nr && asym_capacity &&
		     cid_topo(cid)->capacity_tier < cid_topo(best)->capacity_tier)) {
			best = cid;
			best_nr = nr_queued;
		}
	}

	return best;
}

/*
 * Return an idle cid that @p can run on, or -ENOENT. The idle state is
 * not claimed: the caller only kicks the cid, so that it comes and looks
 * at a queue it would otherwise never read.
 *
 * Fully idle cores first, then any idle cid, with the same topology/capacity
 * ordering a wakeup uses. SD_ASYM_PACKING priority is deliberately absent:
 * this kick only supplies an idle balancer for queued work, while packing
 * policy is applied when that balancer pulls and through active balance.
 */
static s32 idle_peer_cid(const struct task_struct *p, s32 cid)
{
	s32 other;

	if (!cid_valid(cid) || is_pcpu_task(p) || cmask_empty(idle_cids))
		return -ENOENT;

	if (smt_enabled) {
		other = pick_idle_cid_topology((struct task_struct *)p, cid,
					     PICK_IDLE_NO_CLAIM |
					     PICK_IDLE_WHOLE_CORE);
		if (other >= 0)
			return other;
	}

	other = pick_idle_cid_topology((struct task_struct *)p, cid,
				     PICK_IDLE_NO_CLAIM);

	return other >= 0 ? other : -ENOENT;
}

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

/*
 * Periodic busy load balancing, corresponding to fair.c's rebalance_domains().
 *
 * There is one interval for each sched-domain-like range cidland represents:
 * LLC, NUMA node and machine. Equal adjacent ranges are skipped by the caller.
 * The range weight times @busy_balance_factor is its initial interval in
 * milliseconds, fair's sd->min_interval scaled by sd->busy_factor for a busy
 * CPU, and balanced ranges back off to twice that, sd->max_interval. Different
 * destination cids are staggered across that interval instead of all walking
 * the same shared state on one tick.
 *
 * The old dispatch-time sampler compared instantaneous EDQ depths and moved a
 * task whenever a sampled queue happened to be deeper. Wakeup-heavy workloads
 * made that transient condition true millions of times. Here the decision is
 * calculate_imbalance()'s, on time-averaged, capacity-normalized loads. Like
 * update_sd_lb_stats(), each range is split into the sched groups immediately
 * below it: NUMA nodes below the machine, LLCs below a node, and cores below
 * an LLC. A pull requires capacity below the range average in the local group
 * and load above it in the source group. The movable load is the smaller of
 * that room and excess, and sd->imbalance_pct (117%) is required between busy
 * groups. Like sched_balance_find_src_group() and
 * sched_balance_find_src_rq(), the busiest eligible child group is selected
 * first, then its busiest queued cid. The individual source and destination
 * cids get the same guard when the destination has something queued. A bounded
 * deadline-ordered prefix is searched for a movable task whose weight fits the
 * group imbalance, as detach_tasks() does for migrate_load.
 *
 * Like should_we_balance(), one cid owns a pass for each local group. It
 * retains the calculated imbalance as a budget and dispatch drains it one
 * cold, affinity-compatible EDQ candidate at a time. If the task cannot run
 * on the owner, can_migrate_task()'s new_dst_cpu rule redirects the reservation
 * to another allowed cid in the same local group.
 */
#define BUSY_BALANCE_IMBALANCE_PCT	117U
/*
 * The capacity-normalized load of the whole range, sds->avg_load, one read
 * per cid like update_sd_lb_stats().
 */
__noinline u64 busy_balance_avg_load(u32 base, u32 nr, u64 now)
{
	u64 load = 0, cap = 0;
	u32 i;

	TOUCH_ARENA();
	bpf_arena_for(i, base, base + nr) {
		s32 cid = i;
		u64 sample;

		if (!cid_valid(cid))
			break;
		sample = cid_load(cid, now);
		/* Group totals below reuse the samples collected by this pass. */
		WRITE_ONCE(cid_ctx(cid)->busy_balance_load, sample);
		load += sample;
		cap += cid_topo(cid)->cap;
	}

	return cap ? load * 1024 / cap : 0;
}

/* Load above or capacity below @avg_norm for one sched group. */
__noinline u64
busy_balance_group_delta(s32 dst_cid, u64 group, u64 avg_norm, bool excess)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 load = 0, cap = 0;
	u32 base = group, nr = group >> 32;
	u32 i;

	TOUCH_ARENA();
	env->group_queued = 0;
	bpf_arena_for(i, base, base + nr) {
		if (!cid_valid(i))
			break;
		load += READ_ONCE(cid_ctx(i)->busy_balance_load);
		cap += cid_topo(i)->cap;
		if (cid_queued_test(i))
			env->group_queued = 1;
	}
	env->group_load = load;
	env->group_cap = cap;

	if (excess)
		return load > avg_norm * cap / 1024 ?
			load - avg_norm * cap / 1024 : 0;
	return avg_norm * cap / 1024 > load ?
		avg_norm * cap / 1024 - load : 0;
}

/*
 * Pick the busiest sched group outside the destination's local group, as
 * sched_balance_find_src_group() does before looking at individual runqueues.
 * The group load samples were collected by busy_balance_avg_load(), so this
 * pass only aggregates those samples at the child level of the domain.
 */
__noinline bool busy_balance_find_src_group(s32 dst_cid, u32 base, u32 nr)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 best_load = 0, best_cap = 1, best_excess = 0;
	u32 best_base = 0, best_nr = 0;
	u32 i;

	TOUCH_ARENA();
	bpf_arena_for(i, base, base + nr) {
		u32 group_base, group_nr;
		u64 excess, norm;

		if (!cid_valid(i))
			break;
		if (env->level == BUSY_BALANCE_SYSTEM) {
			group_base = cid_topo(i)->node_base;
			group_nr = cid_topo(i)->node_nr;
		} else if (env->level == BUSY_BALANCE_NODE) {
			group_base = cid_topo(i)->llc_base;
			group_nr = cid_topo(i)->llc_nr;
		} else {
			group_base = cid_topo(i)->core_base;
			group_nr = cid_topo(i)->core_nr;
		}
		/* Each child group is contiguous; aggregate it only at its base. */
		if (i != group_base ||
		    group_base == env->local_base || !group_nr)
			continue;
		excess = busy_balance_group_delta(
					dst_cid,
					(u64)group_nr << 32 | group_base,
					env->avg_norm, true);
		if (!excess || !env->group_queued)
			continue;
		norm = env->group_load * 1024 / MAX(env->group_cap, 1ULL);
		if (env->local_overloaded &&
		    norm * 100 <=
		    env->local_norm * BUSY_BALANCE_IMBALANCE_PCT)
			continue;
		/* Compare load / capacity without losing precision to division. */
		if (env->group_load * best_cap <= best_load * env->group_cap)
			continue;
		best_load = env->group_load;
		best_cap = env->group_cap;
		best_excess = excess;
		best_base = group_base;
		best_nr = group_nr;
	}

	if (!best_nr)
		return false;
	env->group_base = best_base;
	env->group_nr = best_nr;
	env->source_excess = best_excess;
	return true;
}

/*
 * Within the busiest group, select the busiest queued cid, corresponding to
 * sched_balance_find_src_rq(). Rotate equal-load choices after the previous
 * source so that repeated passes do not always drain the lowest cid.
 */
__noinline s32 busy_balance_find_src_cid(s32 dst_cid, u32 start)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 best_load = 0, best_cap = 1;
	s32 best = -1;
	u32 off;

	TOUCH_ARENA();
	if (!env->group_nr)
		return -1;
	if (start < env->group_base ||
	    start >= env->group_base + env->group_nr)
		start = env->group_base;
	bpf_arena_for(off, 0, env->group_nr) {
		s32 cid = env->group_base +
			  (start - env->group_base + off) % env->group_nr;
		u64 load, cap, norm;

		if (!cid_valid(cid) || cid_idle_test(cid) || !cid_queued_test(cid))
			continue;
		load = READ_ONCE(cid_ctx(cid)->busy_balance_load);
		cap = MAX(cid_topo(cid)->cap, 1ULL);
		norm = load * 1024 / cap;
		if (norm <= env->avg_norm)
			continue;
		if (env->dst_overloaded &&
		    norm * 100 <=
		    env->dst_norm * BUSY_BALANCE_IMBALANCE_PCT)
			continue;
		if (load * best_cap > best_load * cap) {
			best_load = load;
			best_cap = cap;
			best = cid;
		}
	}

	return best;
}

/*
 * fair.c's can_migrate_task() records new_dst_cpu when a task cannot run on
 * the CPU elected by should_we_balance(), but can run on another CPU in its
 * local scheduling group. The elected cid still owns and serializes the scan;
 * return the first destination in that group which can consume its result.
 */
static __always_inline s32
busy_balance_dst_cid(const struct task_struct *p, s32 owner_cid)
{
	struct busy_balance_env __arena *env =
		&cid_ctx(owner_cid)->busy_balance_env;
	u32 i;

	if (cid_allowed(p, owner_cid))
		return owner_cid;
	bpf_arena_for(i, 0, env->local_nr) {
		s32 cid = env->local_base + i;

		if (cid == owner_cid || !cid_valid(cid) ||
		    !cid_allowed(p, cid) ||
		    READ_ONCE(cid_ctx(cid)->busy_balance_cid) != -1)
			continue;
		return cid;
	}

	return -1;
}

/*
 * Like detach_tasks(), walk a bounded prefix of the selected source queue
 * instead of letting one pinned, hot, or oversized head hide movable work.
 * EDQ order is deadline order, so the first task accepted here is the one
 * cidland would prefer among the inspected candidates.
 */
static __noinline bool
busy_balance_has_movable_task(s32 dst_cid, s32 src_cid, u64 now)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 budget = MIN(env->local_room, env->source_excess);
	u32 nth;

	TOUCH_ARENA();
	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		struct task_struct *p;
		s32 move_dst;
		int ret;

		ret = cid_edq_try_peek_nth(src_cid, nth, &at);
		if (ret)
			return false;
		if (!at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		if (READ_ONCE(at->state) != CID_EDQ_ENQUEUED ||
		    ((task_ctx_t *)at)->se.vjoin_w > budget ||
		    task_hot((task_ctx_t *)at, src_cid, dst_cid, now)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		p = scx_bpf_tid_to_task(at->tid);
		move_dst = p ? busy_balance_dst_cid(p, dst_cid) : -1;
		scx_edq_task_drop(&at->common);
		if (move_dst < 0)
			continue;
		env->move_budget = budget;
		env->move_dst_cid = move_dst;
		return true;
	}

	return false;
}

static __always_inline s32
busy_balance_from_range(s32 dst_cid, u32 base, u32 nr, u32 start, u64 now,
			u32 level)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	s32 cid;

	if (!nr)
		return -1;
	env->avg_norm = busy_balance_avg_load(base, nr, now);
	env->dst_norm = cid_load(dst_cid, now) * 1024 /
			MAX(cid_topo(dst_cid)->cap, 1ULL);
	if (env->dst_norm >= env->avg_norm)
		return -1;
	env->dst_overloaded = cid_queue_nr(dst_cid) > 0;
	if (level == BUSY_BALANCE_SYSTEM) {
		env->local_base = cid_topo(dst_cid)->node_base;
		env->local_nr = cid_topo(dst_cid)->node_nr;
	} else if (level == BUSY_BALANCE_NODE) {
		env->local_base = cid_topo(dst_cid)->llc_base;
		env->local_nr = cid_topo(dst_cid)->llc_nr;
	} else {
		env->local_base = cid_topo(dst_cid)->core_base;
		env->local_nr = cid_topo(dst_cid)->core_nr;
	}
	env->local_room = busy_balance_group_delta(dst_cid,
						    (u64)env->local_nr << 32 |
						    env->local_base,
						    env->avg_norm, false);
	env->local_norm = env->group_load * 1024 / MAX(env->group_cap, 1ULL);
	env->local_overloaded = env->group_load > env->group_cap;
	env->level = level;
	if (!env->local_room)
		return -1;
	if (!busy_balance_find_src_group(dst_cid, base, nr))
		return -1;
	cid = busy_balance_find_src_cid(dst_cid, start);
	if (cid < 0)
		return -1;
	if (!busy_balance_has_movable_task(dst_cid, cid, now))
		return -1;
	return cid;
}

static __noinline bool
busy_balance_domain(s32 dst_cid, u32 base, u32 nr, u32 level, u64 now)
{
	struct cid_ctx __arena *dst = cid_ctx(dst_cid);
	struct cid_ctx __arena *move = dst;
	u32 min_ms, max_ms, interval, start;
	s32 src, move_dst = dst_cid;

	if (!nr || level >= BUSY_BALANCE_LEVELS)
		return false;
	/*
	 * fair.c's should_we_balance() lets one CPU in each local group run a
	 * periodic balance pass, falling back to group_balance_cpu() when the
	 * group is busy. Cidland's periodic pass runs from ops.tick(), so an
	 * idle cid cannot be its owner; newly-idle balance handles that case.
	 * Use the fixed group leader here, which is the fair.c choice once all
	 * CPUs in the group are busy, and let it drain the calculated imbalance
	 * over successive dispatch callbacks below.
	 */
	if ((level == BUSY_BALANCE_SYSTEM &&
	     dst_cid != cid_topo(dst_cid)->node_base) ||
	    (level == BUSY_BALANCE_NODE &&
	     dst_cid != cid_topo(dst_cid)->llc_base) ||
	    (level == BUSY_BALANCE_LLC &&
	     dst_cid != cid_topo(dst_cid)->core_base))
		return false;
	/* A fair-style detach pass is still draining through dispatch. */
	if (READ_ONCE(dst->busy_balance_cid) != -1)
		return true;
	min_ms = MAX(nr * busy_balance_factor, 1U);
	max_ms = 2 * min_ms;
	interval = READ_ONCE(dst->busy_balance_interval_ms[level]);
	if (!interval) {
		WRITE_ONCE(dst->busy_balance_interval_ms[level], min_ms);
		WRITE_ONCE(dst->busy_balance_next[level],
			   now + (u64)(1 + (dst_cid - base) % min_ms) *
				 NSEC_PER_MSEC);
		return false;
	}
	if (time_before(now, READ_ONCE(dst->busy_balance_next[level])) ||
	    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL))
		return false;

	start = READ_ONCE(dst->busy_balance_cursor[level]);
	if (start < base || start >= base + nr)
		start = base;
	src = busy_balance_from_range(dst_cid, base, nr, start, now,
				      level);
	if (src >= 0) {
		move_dst = dst->busy_balance_env.move_dst_cid;
		if (!cid_valid(move_dst))
			src = -1;
		else
			move = cid_ctx(move_dst);
	}
	if (src >= 0) {
		/* Claim first, so a failed selection cannot extend an older one. */
		if (__sync_val_compare_and_swap(&move->busy_balance_cid,
							-1, -2) != -1)
			src = -1;
	}
	if (src >= 0) {
		WRITE_ONCE(move->busy_balance_expire,
			   now + (u64)min_ms * NSEC_PER_MSEC);
		WRITE_ONCE(move->busy_balance_budget,
			   dst->busy_balance_env.move_budget);
		WRITE_ONCE(move->busy_balance_cid, src);
		if (move_dst != dst_cid)
			scx_bpf_kick_cid(move_dst, SCX_KICK_IDLE);
	}
	WRITE_ONCE(dst->busy_balance_cursor[level],
		   src >= 0 ? src + 1 : start + 1);
	interval = src >= 0 ? min_ms : MIN(interval * 2, max_ms);
	WRITE_ONCE(dst->busy_balance_interval_ms[level], interval);
	WRITE_ONCE(dst->busy_balance_next[level],
		   now + (u64)interval * NSEC_PER_MSEC);

	return src >= 0;
}

/*
 * The scale cpu.weight is written on: what a cgroup nobody has touched
 * carries, and the most one can be given.
 */
#define CGROUP_WEIGHT_DFL	100
#define CGROUP_WEIGHT_MAX	10000

/*
 * Return the weight of @cgrp, composed with the weights of the cgroups it
 * sits under, on the cpu.weight scale.
 *
 * cpu.weight is written on a cgroup and means "against my siblings", so a
 * task's standing against the whole machine is the product of the ratios
 * along the path from the root down to it: a service of the default weight
 * under a slice given ten times its siblings' is worth ten of the same
 * service in a default slice. Composing is what makes the knob work at all
 * on a systemd machine, where the weights that get set sit on the slices
 * and the tasks live in the leaves under them.
 *
 * This is a per-task weight, not a share of the machine handed to a cgroup
 * and divided among its members: two tasks in a cgroup of twice the weight
 * get twice the CPU each, where fair.c would give them twice between them.
 * Doing it fair.c's way needs the weight of the runnable siblings at every
 * level, which is a count kept on a cacheline shared by every CPU that
 * wakes a task, and this scheduler is not willing to pay that on a wakeup.
 * What the composition does buy is the ordering: heavier cgroups get more,
 * in the right direction and by the right ratios among equal-sized groups.
 *
 * The product is capped at what a single cpu.weight can ask for. Left
 * unbounded a few nested boosts multiply into a weight so large that the
 * vruntime of anything under it stops advancing, which is a starvation
 * bug rather than a strong preference.
 *
 * The result is cached on the cgroup and expires with @cgrp_gen, so the
 * walk runs once per cgroup per cpu.weight write.
 */
static u32 cgrp_weight(struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc;
	u64 w = CGROUP_WEIGHT_DFL;
	u32 level;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (cgc && cgc->gen == cgrp_gen)
		return cgc->cweight;

	/*
	 * Level 0 is the root, which has no cpu.weight of its own, and the
	 * last level is @cgrp itself.
	 */
	bpf_arena_for(level, 1, cgrp->level + 1) {
		struct cgroup *anc = bpf_cgroup_ancestor(cgrp, level);
		struct cgrp_ctx *acgc;

		if (!anc)
			return CGROUP_WEIGHT_DFL;

		acgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, anc, 0, 0);
		if (acgc && acgc->weight)
			w = w * acgc->weight / CGROUP_WEIGHT_DFL;
		bpf_cgroup_release(anc);

		if (!w)
			w = 1;
		else if (w > CGROUP_WEIGHT_MAX)
			w = CGROUP_WEIGHT_MAX;
	}

	if (cgc) {
		cgc->cweight = w;
		cgc->gen = cgrp_gen;
	}

	return w;
}

/*
 * Return the weight the kernel gives @p, on the kernel's own scale.
 *
 * Not @p->scx.weight: that is this weight put through
 * sched_weight_to_cgroup(),
 *
 *	clamp(DIV_ROUND_CLOSEST(weight * 100, 1024), 1, 10000)
 *
 * which is coarse at the light end. A nice 19 task weighs 15, that is 1.46
 * on the cgroup scale, and comes out as 1. Charging the vruntime against
 * that makes it pay 100x the service it used where calc_delta_fair()
 * charges 1024/15 = 68x, so it waits half again as long as EEVDF asks
 * before its pack catches up - long enough, under a deep backlog, to turn
 * a fair-share wait into an ops.timeout_ms stall. SCHED_IDLE fares worse:
 * its weight of 3 rounds to 0 and is clamped back up to 1, so it is
 * charged the same as nice 19.
 *
 * @p->se.load.weight is not the answer either, even though set_load_weight()
 * fills it from this same table: for a task in the sched_ext class the
 * store goes through reweight_task_scx(), which derives @p->scx.weight from
 * the new load weight and drops it, leaving @p->se.load holding whatever
 * the fair class last left there. Go back to the table.
 *
 * That weight is then scaled by the weight of the cgroup @p sits in, see
 * cgrp_weight(), taken from the copy @tctx carries. A task with no context
 * yet, or one under --disable-cgroups, weighs what its nice level says and
 * nothing else.
 */
static u64 task_weight(const struct task_struct *p, const task_ctx_t *tctx)
{
	u64 w;
	u32 idx, cgw;

	if (p->policy == SCHED_IDLE) {
		w = WEIGHT_IDLEPRIO;
	} else {
		idx = p->static_prio - MAX_RT_PRIO;
		w = idx < ARRAY_SIZE(prio_to_weight) ?
			prio_to_weight[idx] : NICE_0_WEIGHT;
	}

	cgw = tctx ? tctx->cgw : 0;
	if (!cgw || cgw == CGROUP_WEIGHT_DFL)
		return w;

	/*
	 * A light task in a light cgroup can scale down to nothing, and
	 * calc_delta_fair() divides by this.
	 */
	w = w * cgw / CGROUP_WEIGHT_DFL;

	return w ? w : 1;
}

/*
 * The load of a task, task_h_load(): its weight scaled by the fraction of
 * the time it has been runnable, se->avg.load_avg, so that a task that
 * sleeps most of the time weighs less on a queue than one that never
 * does. The runnable average is kept from ops.runnable() to
 * ops.quiescent(), where util_avg is kept from ops.running() to
 * ops.stopping().
 */
static u64 task_load(const struct task_struct *p, task_ctx_t *tctx, u64 now)
{
	u64 runnable = ravg_read_arena(&tctx->runnable_avg, now) >> UTIL_SHIFT;

	return task_weight(p, tctx) * MIN(runnable, 1024) / 1024;
}

/*
 * Charge @delta of service to a task of @p's weight, the way
 * calc_delta_fair() does:
 *
 *	delta_fair = delta * NICE_0_LOAD / se->load.weight
 */
static u64 calc_delta_fair(const struct task_struct *p,
			   const task_ctx_t *tctx, u64 delta)
{
	return delta * NICE_0_WEIGHT / task_weight(p, tctx);
}

/*
 * Floor on the weight used to stretch the request and the lag bound.
 *
 * A nice 19 task has a weight of 15, so its request would be sixty eight
 * times the base slice and the lag it can carry a hundred and thirty six
 * times: under a deep backlog V takes many seconds to cover that, well
 * past the watchdog. The vruntime is still charged with the real weight,
 * so the share is what nice asks for; only how far ahead the deadline and
 * the lag can stretch is capped, which update_deadline() itself notes is
 * "probably good enough".
 */
#define MIN_DL_WEIGHT	(NICE_0_WEIGHT / 4)

static u64 scale_by_dl_weight(const struct task_struct *p,
			      const task_ctx_t *tctx, u64 value)
{
	u64 weight = task_weight(p, tctx);

	if (weight < MIN_DL_WEIGHT)
		weight = MIN_DL_WEIGHT;

	return value * NICE_0_WEIGHT / weight;
}

/*
 * Bound on the lag a task can carry, in virtual time. This is the one
 * entity_lag() clamps to:
 *
 *	u64 max_slice = cfs_rq_max_slice(cfs_rq) + TICK_NSEC;
 *	limit = calc_delta_fair(max_slice, se);
 *	return clamp(vlag, -limit, limit);
 *
 * EEVDF's steady state bound, -r_max < lag < max(r_max, q), where r_max
 * is the largest request on the queue and q the timing granularity.
 *
 * cfs_rq_max_slice() walks the queue for that largest request; there is
 * no equivalent to walk here, so the largest of this task's own and the
 * default stands in for it. The two agree unless some other task on the
 * cid asked for more than the default, in which case the bound is the
 * tighter of the two, which errs the safe way.
 */
static u64 task_request(const struct task_struct *p);

static u64 lag_limit(const struct task_struct *p, const task_ctx_t *tctx)
{
	u64 request = task_request(p);

	if (request < slice_ns)
		request = slice_ns;

	return scale_by_dl_weight(p, tctx, request + tick_ns);
}

/*
 * Return the task's effective request. sched_runtime is the request hint for
 * fair policies, including SCHED_EXT; zero leaves cidland's default in force.
 */
static u64 task_request(const struct task_struct *p)
{
	return p->se.custom_slice ? p->se.slice : slice_ns;
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 * This is EEVDF's virtual deadline, see update_deadline():
 *
 *	vd_i = ve_i + r_i / w_i
 *
 * The request size r_i is @slice_ns by default, like sysctl_sched_base_slice,
 * and a task can override it with sched_attr.sched_runtime. The weight does
 * not buy a task a longer time slice, it buys it an earlier deadline, so it
 * runs more often instead of running longer.
 *
 * The deadline is the EDQ key and nothing else. The vruntime is stored
 * separately in task_ctx.vruntime and copied into the EDQ augmentation.
 *
 * pick_eevdf() considers only the eligible tasks, v_i <= V, and picks the
 * earliest deadline among them. The EDQ subtree augmentation applies that
 * filter at dispatch without changing the deadline key.
 *
 * The deadline stands until the request it was issued for is consumed,
 * which is the test update_deadline() opens with:
 *
 *	if ((s64)(se->vruntime - se->deadline) < 0)
 *		return;
 *
 * A task queued again without having run for its whole request keeps the
 * deadline it was queued with, instead of being pushed a full request
 * further back for the fraction it did get.
 *
 * A re-placed vruntime takes the deadline with it, see set_vruntime(): a
 * deadline is a position in the virtual time of one cid and the packs
 * drift apart, so what is carried is its distance from the vruntime, not
 * the value, and only for a task that did not sleep.
 */
static u64 task_dl(const struct task_struct *p, task_ctx_t *tctx)
{
	u64 request = task_request(p);

	/*
	 * sched_setattr() can change a runnable task's request between two
	 * enqueues. A deadline belongs to the request that created it, so do
	 * not carry one calculated from the old request into the new one.
	 */
	if (tctx->se.request != request) {
		tctx->se.request = request;
		tctx->se.deadline = 0;
	}

	if (tctx->se.deadline && time_before(tctx->se.vruntime, tctx->se.deadline))
		return tctx->se.deadline;

	/*
	 * A task that has just been forked asks for half a request the
	 * first time, which is PLACE_DEADLINE_INITIAL:
	 *
	 *	if (sched_feat(PLACE_DEADLINE_INITIAL) && (flags & ENQUEUE_INITIAL))
	 *		vslice /= 2;
	 *
	 * The tasks it is joining are on average halfway through requests
	 * of their own, so a whole one puts it behind all of them and it
	 * waits out the competition before it has run at all. Half a
	 * request is the average of what they have left, which is what
	 * joining in the middle should cost. It buys no extra service: the
	 * deadline is where the task sits in the order, the vruntime is
	 * what it is charged, and only the first one is halved.
	 */
	if (tctx->initial) {
		tctx->initial = false;
		request /= 2;
	}

	tctx->se.deadline = tctx->se.vruntime + scale_by_dl_weight(p, tctx, request);

	return tctx->se.deadline;
}

/*
 * Return true if @p is here because a direct dispatch of it was refused.
 *
 * A task inserted with %SCX_ENQ_IMMED is handed back when the CPU turns out
 * not to be free for it, and the kernel records why in @p's flags. Only the
 * %SCX_TASK_REENQ_IMMED case says the cid is still a fine place for the
 * task: %SCX_TASK_REENQ_CAP means the caps for that cid are gone and the
 * task has to move, and would re-enqueue without end if put back.
 */
static bool reenq_immed(const struct task_struct *p, u64 enq_flags)
{
	return (enq_flags & SCX_ENQ_REENQ) &&
	       (p->scx.flags & SCX_TASK_REENQ_REASON_MASK) == SCX_TASK_REENQ_IMMED;
}

/*
 * Return true if @p was pushed off its cid by a higher scheduling class.
 *
 * The kernel hands an IMMED task back with %SCX_TASK_REENQ_PREEMPTED when a
 * higher class takes the CPU while the task still has slice left, which is
 * the one re-enqueue that wants a different cid: the old one is taken for an
 * unknown time. It is the reason, not %SCX_ENQ_REENQ on its own - a bounced
 * direct dispatch is also a re-enqueue and wants the opposite, see
 * reenq_immed().
 */
static bool reenq_preempted(const struct task_struct *p, u64 enq_flags)
{
	return (enq_flags & SCX_ENQ_REENQ) &&
	       (p->scx.flags & SCX_TASK_REENQ_REASON_MASK) == SCX_TASK_REENQ_PREEMPTED;
}

/*
 * Return true if the task should attempt a migration, false otherwise.
 */
static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	/*
	 * Attempt a migration on wakeup (task was not running) and only if
	 * ops.select_cid() has not been called already.
	 */
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

/*
 * Per-cid vruntime reference.
 *
 * With one deadline queue per CPU, each queue is a pack of tasks that
 * advance in lockstep, and the packs drift apart from the system-wide V
 * with their load: a CPU running nine hogs accrues vruntime slower than
 * one running six, and slower than V, which follows the average. A task
 * placed at V minus its lag then lands behind the whole pack of a crowded
 * CPU and waits for the pack to climb past it, or ahead of everything on a
 * lightly loaded one. EEVDF's reference is per runqueue for that reason:
 * the weighted average of the tasks queued there, kept incrementally,
 *
 *	V = \Sum (w_i * v_i) / \Sum w_i
 *
 * and a task is placed against the runqueue it joins with the lag it took
 * from the one it left, which is also how a migration keeps its fairness.
 *
 * Do the same per cid: a task joins the cid it is queued on or runs on,
 * leaves it when it stops being runnable, and its contribution follows
 * the vruntime it is charged in ops.stopping().
 *
 * Keep V itself rather than the two sums it is the quotient of. A cfs_rq
 * divides \Sum w_i*v_i by \Sum w_i under its rq lock and always gets a
 * pair that belongs together; here the words are updated by whichever CPU
 * the task is on, so a reader can take one from either side of a join and
 * divide sums that never coexisted. The miss is the joining weight over
 * the old total, which a nice -20 task landing on a pack of one nice 19
 * task inflates by almost six thousand, and the result is not merely read
 * but assigned as a task's vruntime in place_task().
 *
 * So move V by the exact increment each event is worth, and let a reader
 * take it in a single load, which cannot tear:
 *
 *	join    V' = (W*V + w_i*v_i) / (W + w_i) = V + w_i*(v_i - V)/(W + w_i)
 *	leave   V' = (W*V - w_i*v_i) / (W - w_i) = V + w_i*(V - v_i)/(W - w_i)
 *	charge  dV = w_i * dv_i / W
 *
 * The W each increment divides by is read without a lock too, but a stale
 * W only scales a bounded increment slightly wrong, where a stale divisor
 * under a quotient produced a number with no relation to the pack.
 *
 * The last member out divides by nothing and leaves V where it stands,
 * which is what an empty pack wants: the clock of an idle cid stops,
 * nothing is served there so nothing is owed there, and a task arriving
 * later starts from where the cid was left. That is cfs_rq->zero_vruntime
 * without a field of its own.
 */
/*
 * Divide a signed value by a positive one. BPF has no signed division, so
 * take the magnitude through the unsigned divide and put the sign back.
 */
static s64 vdiv(s64 v, u64 d)
{
	if (v < 0)
		return -(s64)((u64)(-v) / d);

	return (s64)((u64)v / d);
}

/*
 * The reference of @pk.
 */
static u64 pack_vref(pack_t *pk)
{
	return pk->vref;
}

/*
 * The reference of @pk at @now, with the service the task running there
 * has taken since it was picked folded in, see pack_vref().
 *
 * A running task's vruntime is only charged in ops.stopping(), so between
 * two context switches the reference stands still while the CPU goes on
 * delivering service, and everything read off it in between is behind by
 * as much as a whole request. A task placed against a reference that low
 * is placed further back than it should be, and one tested against it
 * looks over-served when it is not.
 *
 * fair.c has no such window. update_curr() runs before every
 * place_entity() and every entity_eligible(), so V is exact wherever it
 * is used. This is that update, for the one task a cid knows it is
 * running,
 *
 *	dV = w_i * dv_i / W
 *
 * and it is only a read: the service is charged for real, once, by
 * vref_charge() when the task stops. ops.stopping() clears @curr_w, so a
 * cid with nothing of ours on it projects nothing, and past a whole
 * request there is nothing worth projecting either: the task is due to
 * be rescheduled, and if it is kept it is charged for real at that
 * point, see cidland_dispatch(), so the estimate would be running past
 * what it can know.
 */
static u64 pack_vref_at(pack_t *pk, u64 now)
{
	u64 w, sum_w, delta, dv;

	w = pk->curr_w;
	sum_w = pk->vsum_w;
	delta = now - pk->curr_run_at;
	if (!w || !sum_w || delta >= pk->curr_request)
		return pk->vref;

	dv = delta * NICE_0_WEIGHT / w;

	return pk->vref + dv * w / sum_w;
}

/*
 * The reference to place a task against and to test it against, which is
 * pack_vref_at() unless --no-vref-update pins it to the stored value.
 */
static u64 pack_vref_place(pack_t *pk, u64 now)
{
	return no_vref_update ? pack_vref(pk) : pack_vref_at(pk, now);
}

/*
 * The reference to place @se against when it is about to join @pk with
 * weight @join_w.
 *
 * pack_vref_at() projects the running task's uncharged service over the
 * pack's current weight W. Once a task of weight w joins, the same service
 * is projected over W + w instead. Placing at the pre-join projection can
 * therefore leave a zero-lag task one unit above the post-join reference
 * through integer truncation, and incorrectly make it ineligible.
 *
 * Let q be the projection after the join. Place against
 *
 *	V' = V + q * (W + w) / W.
 *
 * vref_join() then contributes w * (V' - V) / (W + w), and adding q
 * reconstructs V'. Thus a zero-lag task remains eligible after joining,
 * with the same left bias avg_vruntime() gives fair.c's reference.
 */
static u64 pack_vref_before_join(pack_t *pk, const sched_ent_t *se,
				 u64 join_w, u64 now)
{
	u64 curr_w, sum_w, delta, dv, projection;

	if (no_vref_update || se->vpack == pk)
		return pack_vref_place(pk, now);

	curr_w = pk->curr_w;
	sum_w = pk->vsum_w;
	delta = now - pk->curr_run_at;
	if (!curr_w || !sum_w || delta >= pk->curr_request)
		return pk->vref;

	dv = delta * NICE_0_WEIGHT / curr_w;
	projection = dv * curr_w / (sum_w + join_w);

	return pk->vref + projection * (sum_w + join_w) / sum_w;
}

/*
 * Return the lag of @se against @pk at @now, rq clock, clamped to @limit
 * both ways as entity_lag() does.
 */
static s64 ent_lag_at(const sched_ent_t *se, pack_t *pk, s64 limit, u64 now)
{
	s64 lag;

	lag = (s64)(pack_vref_place(pk, cid_clock_task_at(pk->cid, now)) - se->vruntime);
	if (lag > limit)
		lag = limit;
	else if (lag < -limit)
		lag = -limit;

	return lag;
}

/* Return @p's current lag against @pk, clamped as entity_lag() does. */
static s64 task_lag_at(const struct task_struct *p,
		       const task_ctx_t *tctx, pack_t *pk, u64 now)
{
	return ent_lag_at(&tctx->se, pk, (s64)lag_limit(p, tctx), now);
}

/*
 * Is the entity running in @pk still owed service at @now?
 *
 * Its vruntime is only charged in ops.stopping() too, so the service it
 * has taken since it was picked is added to it here, and to the reference
 * it is measured against by pack_vref_at(). This is what
 * wakeup_preempt_fair() calls update_curr_fair() for before deciding
 * anything. A task that has run for a whole request is past its deadline
 * as well and has no protection left either way.
 */
static bool curr_owed_service(pack_t *pk, u64 now)
{
	u64 w = pk->curr_w, delta = now - pk->curr_run_at;
	u64 dv;

	if (!w || delta >= pk->curr_request)
		return false;
	dv = delta * NICE_0_WEIGHT / w;

	return !time_after(pk->curr_v + dv, pack_vref_at(pk, now));
}

/*
 * Shortest an hrtick is armed for, the floor hrtick_start() in core.c
 * applies to its own:
 *
 *	delta = max_t(s64, delay, 10000LL);
 */
#define HRTICK_MIN_NS	10000ULL

/*
 * Wall-clock time the entity running in @pk needs to reach its deadline,
 * read off @pk's published view of it, or 0 if it is there already or
 * nothing is running.
 *
 * The view is read without a lock, from other cids too, and can be of a
 * task picked after @now was taken: that task has consumed nothing yet.
 */
static s64 curr_dl_in(pack_t *pk, u64 now)
{
	u64 w = pk->curr_w, run_at = pk->curr_run_at, v;
	s64 vdelta;

	if (!w)
		return 0;

	if (time_before(now, run_at))
		now = run_at;
	v = pk->curr_v + (now - run_at) * NICE_0_WEIGHT / w;
	vdelta = (s64)(pk->curr_dl - v);
	if (vdelta <= 0)
		return 0;

	return (u64)vdelta * w / NICE_0_WEIGHT;
}

/*
 * Arm @cid's hrtick for the deadline of the task running there, when it
 * has company in the queue, or kick @cid if the deadline has passed.
 *
 * A request is only enforced from task_tick_scx(): a task whose request
 * runs out between two ticks holds the CPU until the next one, up to a
 * whole tick late, and a task that woke behind it and did not win the
 * pick waits that long for its turn. Under a saturated schbench that was
 * a wakeup latency of ~900 us at the median, at a request of 700 us, and
 * shortening the request only buys the tick back at the cost of
 * throughput. fair.c has an hrtimer for exactly this, HRTICK, which
 * set_next_task_fair() arms at every pick for the time the running
 * task's vruntime takes to reach its deadline, whenever it has company,
 *
 *	if (rq->cfs.h_nr_queued <= 1)
 *		return;
 *	vdelta = se->deadline - se->vruntime;
 *	delta = (se->h_load.weight * vdelta) / NICE_0_LOAD;
 *	hrtick_start(rq, delta);
 *
 * and enqueue_task_fair() arms, through hrtick_update(), the moment a
 * task joins a lone runner. When it fires, task_tick_fair() runs
 * update_curr(), which reissues the deadline and asks for a reschedule,
 * and pick_eevdf() decides. A deadline already behind is a reschedule on
 * the spot:
 *
 *	if ((s64)vdelta < 0) {
 *		if (task_current_donor(rq, p))
 *			resched_curr(rq);
 *		return;
 *	}
 *
 * sched_ext has no hrtick, so this is a bpf_timer per cid. It fires at
 * the deadline and kicks the CPU if the cid still has something queued,
 * which is the reschedule; the dispatch that follows asks keep_running(),
 * which is the pick. Every op runs with interrupts off, and from there
 * bpf_timer_start() cannot touch the hrtimer itself: it queues the arming
 * to an irq_work of this CPU, which runs on the way out of the op. That
 * is a self-IPI per arming, and why it is only armed with company, as
 * fair.c does.
 *
 * The timer is not pinned. It queues on the CPU that arms it, this one
 * when the pick does and the waker's when a wakeup does, and an idle CPU
 * hands it to a busy one when it is armed again, so a CPU is not woken
 * for a deadline that is not its own. It cannot be cancelled from an op
 * either, so one left behind by a task that blocked fires once for
 * nothing, and hrtick_fire() finds nothing running and lets it lapse.
 */
static void hrtick_start(s32 cid, u64 tnow)
{
	struct cid_ctx __arena *cctx = cid_ctx(cid);
	struct hrtick *ht;
	u32 key = cid;
	s64 delta;
	u64 now, at;

	if (no_hrtick || !cctx->pack.curr_w)
		return;

	delta = curr_dl_in(&cctx->pack, tnow);
	if (!delta) {
		scx_bpf_kick_cid(cid, SCX_KICK_PREEMPT);
		return;
	}
	if (delta < HRTICK_MIN_NS)
		delta = HRTICK_MIN_NS;

	/*
	 * The distance is in the task clock. The timer is armed relative
	 * to now; @at, the rq clock it fires at through the offset
	 * ops.stopping() last sampled, is what the check below compares.
	 */
	now = tnow + cctx->clock_off;
	at = now + delta;

	/*
	 * A timer still pending for no later than this is left alone: it
	 * fires early for this task and hrtick_fire() arms it again for the
	 * deadline from there, where that costs nothing. Moving it from here
	 * is an irq_work and a self-IPI every time, and under perf bench
	 * sched messaging that was one per context switch, 1.5 million of
	 * them for 4000 that ever fired.
	 */
	if (time_before(now, cctx->hrtick_at) &&
	    !time_after(cctx->hrtick_at, at + HRTICK_MIN_NS))
		return;

	ht = bpf_map_lookup_elem(&hrticks, &key);
	if (!ht)
		return;

	cctx->hrtick_at = at;
	bpf_timer_start(&ht->timer, delta, 0);
}

/*
 * @cid's hrtick fired. Ask the running task to give the CPU up if it has
 * company and its deadline has come, hrtick() in core.c:
 *
 *	rq->donor->sched_class->task_tick(rq, rq->donor, 1);
 *
 * The timer was armed for the deadline of whatever was running when it
 * was armed. If the cid has since picked something else, whose deadline
 * is still ahead, this is that task's hrtick now: arm it again for that
 * deadline, which can be done from here directly, interrupts being on.
 */
static int hrtick_fire(void *map, int *key, struct hrtick *ht)
{
	struct cid_ctx __arena *cctx;
	s32 cid = *key;
	s64 delta;
	u64 now;

	TOUCH_ARENA();

	if (!cid_valid(cid))
		return 0;

	cctx = cid_ctx(cid);
	if (!cctx->pack.curr_w || !cid_queued_test(cid))
		return 0;

	now = scx_bpf_now();
	delta = curr_dl_in(&cctx->pack, now - cctx->clock_off);
	if (delta > HRTICK_MIN_NS) {
		cctx->hrtick_at = now + delta;
		bpf_timer_start(&ht->timer, delta, 0);
		return 0;
	}

	scx_bpf_kick_cid(cid, SCX_KICK_PREEMPT);
	__sync_fetch_and_add(&nr_hrticks, 1);

	return 0;
}

/*
 * Move the earliest-deadline eligible task from @cid to this CPU. EDQ selects
 * and removes under its lock. If every observed queued task is ineligible,
 * fall back to the head rather than strand a runnable queue. This can happen
 * when the current task is the pack's sole eligible member but active balance
 * is moving it elsewhere, or when the lockless reference and queue snapshots
 * race. Callers enter here only when eligible scanning and eligibility
 * enforcement are both enabled.
 */
static __noinline bool move_first_eligible_to_local(s32 cid, u64 tnow)
{
	TOUCH_ARENA();
	return cid_edq_move_first_eligible_to_local(
		cid, pack_vref_place(cid_pack(cid), tnow));
}

/*
 * Longest a task may hold a CPU across the end of its slice before the
 * queue gets its turn whatever the deadlines say, see keep_running().
 *
 * The share a weight buys is charged in the vruntime and is untouched by
 * this: what it bounds is how long the task at the back of the queue can
 * wait. fair.c lets that run to whatever the weights ask for, and a nice
 * -20 task against a nice 19 one asks for a ratio of 5917, four seconds
 * of one holding the CPU at the default slice. sched_ext does not have
 * that much room: ops.timeout_ms ends the scheduler when a runnable task
 * has not run for as long, and it does so before the ratio is served.
 * Every nice pair inside a factor of a hundred and forty is exact at the
 * default slice; past that the interleaving is forced finer than fair.c
 * would make it, which costs the light task nothing.
 */
#define KEEP_RUNNING_MAX_NS	100000000ULL

/*
 * The deadline the entity running in @pk would be picked again with at @now,
 * or false when it is not in the pick at all.
 */
static bool curr_pick_dl(pack_t *pk, u64 now, u64 *dlp)
{
	u64 w, v, dl;

	w = pk->curr_w;
	if (!w)
		return false;

	if (now - pk->curr_since >= KEEP_RUNNING_MAX_NS)
		return false;

	v = pk->curr_v + (now - pk->curr_run_at) * NICE_0_WEIGHT / w;

	/*
	 * A task that has had more than its share is not in the pick at all,
	 * whatever its deadline: pick_eevdf() drops it before it looks at
	 * the tree,
	 *
	 *	if (curr && (!curr->on_rq || !entity_eligible(cfs_rq, curr)))
	 *		curr = NULL;
	 *
	 * and this is the same test kick_queued_cid() applies when a task
	 * wakes against it. Applied here too, the two agree: a task kicked
	 * off the CPU for being over-served was kept by the dispatch that
	 * followed whenever its deadline happened to be the earlier one,
	 * and got a whole new slice out of it. A probe waking next to a hog
	 * waited 1.6 ms for that on one wakeup in four, 0.3 ms under fair.c.
	 */
	if (!no_eligibility && time_after(v, pack_vref_at(pk, now)))
		return false;

	/*
	 * A deadline stands until the request it was issued for is consumed,
	 * see task_dl(); past that it is reissued from where the vruntime
	 * has reached, which is what puts a task that has had its turn behind
	 * the ones that have not.
	 */
	dl = pk->curr_dl;
	if (!dl || !time_before(v, dl)) {
		if (w < MIN_DL_WEIGHT)
			w = MIN_DL_WEIGHT;
		dl = v + pk->curr_request * NICE_0_WEIGHT / w;
	}

	*dlp = dl;
	return true;
}

/*
 * Does the task running on @cid keep it, rather than hand it to the head
 * of @cid's queue?
 *
 * fair.c asks this at every pick. pick_next_task_fair() calls
 * pick_next_entity(), which runs pick_eevdf() over the queued entities
 * *and* curr, so a task whose slice has just ended goes on running
 * whenever nothing queued has an earlier deadline. A slice bounds how
 * long a task may hold a CPU without being asked again; it is not a turn
 * it has to give up at the end of.
 *
 * Without the question there is no answer to give. A dispatch that always
 * takes the head hands the CPU over in strict rotation, and the weights
 * stop meaning anything wherever the queue holds a single task - which is
 * every CPU running two runnable tasks, the shape a build next to a video
 * call has. A nice 0 and a nice 6 task pinned together measured 1.02 to
 * one where fair.c gives 3.76, and cpu.weight fared the same. Queue a
 * third task and the deadline order picks among them and the ratios come
 * out right, which is how this went unnoticed.
 *
 * The comparison is the one ops.stopping() and task_dl() would reach a
 * moment later, taken from @cid's published view of what it is running so
 * that nothing has to be looked up to decide: the service taken since it
 * was last charged, charged at its weight, is the vruntime it is about to
 * carry, and a request that vruntime has consumed is a deadline about to
 * be reissued from there.
 */
static bool keep_running(s32 cid, u64 now)
{
	pack_t *pk = cid_pack(cid);
	u64 dl, head_dl;

	if (!curr_pick_dl(pk, now, &dl))
		return false;

	/*
	 * Only now the head: the queue lookup is the expensive step, and a
	 * yielder that has just forfeited its request fails the test above.
	 *
	 * Nothing queued here to be preferred to. Say so rather than keep
	 * the task: the queued bitmap is the only thing consulted, and the
	 * dispatch that follows has a lookup of the EDQ itself to fall back
	 * on for the races the bitmap loses.
	 */
	if (!cid_queued_test(cid))
		return false;
	if (scx_edq_first_deadline(&pk->edq, &head_dl))
		return false;

	/* A tie is kept: giving the CPU up costs a switch. */
	return !time_after(dl, head_dl);
}

/*
 * Drop @se out of its pack's reference, see pack_vref().
 */
static void vref_leave(sched_ent_t *se)
{
	pack_t *pk = se->vpack;
	u64 w;
	s64 d;

	if (!pk)
		return;

	w = __sync_fetch_and_sub(&pk->vsum_w, se->vjoin_w);

	/*
	 * V' = V + w_i*(V - v_i) / (W - w_i), and the last one out leaves
	 * the reference standing where it is.
	 */
	if (w > se->vjoin_w) {
		d = (s64)(pk->vref - se->vjoin_v);
		__sync_fetch_and_add(&pk->vref,
				     vdiv((s64)se->vjoin_w * d, w - se->vjoin_w));
	} else {
		/* Nothing left to pay a debt off, see delay_settle(). */
		__sync_fetch_and_add(&pk->empty_gen, 1);
	}

	se->vpack = NULL;
}

/*
 * Fold @se, of weight @join_w, into @pk's reference, see pack_vref(). The
 * entity is not a member of any pack.
 */
static void vref_join(pack_t *pk, sched_ent_t *se, u64 join_w)
{
	u64 w;
	s64 d;

	se->vjoin_w = join_w;
	se->vjoin_v = se->vruntime;
	se->vpack = pk;

	/*
	 * V' = V + w_i*(v_i - V) / (W + w_i). On an empty pack W is 0 and
	 * the increment is exactly v_i - V, so the first member becomes the
	 * reference, which is what the average of one is.
	 */
	w = __sync_fetch_and_add(&pk->vsum_w, join_w);
	d = (s64)(se->vruntime - pk->vref);
	__sync_fetch_and_add(&pk->vref, vdiv((s64)join_w * d, w + join_w));
}

/*
 * Make @p a member of its pack on @cid, leaving the one it was in, see
 * vref_join().
 */
static void task_vref_join(s32 cid, const struct task_struct *p,
			   task_ctx_t *tctx)
{
	pack_t *pk = cid_valid(cid) ? task_pack(tctx, cid) : NULL;

	if (tctx->se.vpack == pk)
		return;
	vref_leave(&tctx->se);

	if (!pk)
		return;
	vref_join(pk, &tctx->se, task_weight(p, tctx));
}

/*
 * Bring @tctx's copy of its cgroup weight up to date.
 *
 * The weight is read from the cgroup and kept on the task, so the paths
 * that ask a task what it weighs read a word they already have in hand.
 * The copy is taken again when the generation says a cpu.weight has been
 * written somewhere, or when ops.cpuctl_move() puts the task in another
 * cgroup, and the walk that composes it costs one wakeup of one task per
 * cgroup per write.
 *
 * Called from the two ops that precede every use of the weight, so what a
 * task carries is at worst one slice out of date: ops.runnable() before it
 * is placed and queued, and ops.running() before it is charged for what it
 * runs. Both take @p as their task argument, which is what
 * scx_bpf_task_cgroup() asks for.
 *
 * A pack holds the weight of each of its members as of the moment it
 * joined, see vref_join(), so a task whose weight has just changed has to
 * leave and rejoin for the sums to mean anything. Leaving is done here;
 * both callers rejoin, one through place_task() and one directly.
 */
static void reweight_task(const struct task_struct *p, task_ctx_t *tctx,
			  bool dequeued);

static void cgw_refresh(const struct task_struct *p, task_ctx_t *tctx)
{
	struct cgroup *cgrp;
	u32 w;

	if (!cgroup_enabled || tctx->cgw_gen == cgrp_gen)
		return;

	cgrp = scx_bpf_task_cgroup((struct task_struct *)p);
	if (!cgrp)
		return;
	w = cgrp_weight(cgrp);
	bpf_cgroup_release(cgrp);

	tctx->cgw_gen = cgrp_gen;
	if (w == tctx->cgw)
		return;

	tctx->cgw = w;
	tctx->se.deadline = 0;
	reweight_task(p, tctx, false);
	vref_leave(&tctx->se);
}

/*
 * Bring the contribution of @se up to date with its vruntime.
 *
 *	dV = w_i * dv_i / W
 *
 * EEVDF's identity for the service just delivered, taken against the pack
 * that received it. The division truncates, and a pack heavy enough that
 * w_i * dv_i falls below W would advance by nothing at all and freeze, so
 * carry the remainder. Only the cid the task ran on is touched, so the
 * carry needs no atomic.
 */
static void vref_charge(sched_ent_t *se)
{
	pack_t *pk = se->vpack;
	u64 acc, delta, w;
	s64 dv;

	if (!pk)
		return;

	dv = (s64)(se->vruntime - se->vjoin_v);
	if (dv <= 0)
		return;
	se->vjoin_v = se->vruntime;

	w = pk->vsum_w;
	if (!w)
		return;

	acc = se->vjoin_w * (u64)dv + pk->vref_rem;
	delta = acc / w;
	pk->vref_rem = acc - delta * w;
	if (delta)
		__sync_fetch_and_add(&pk->vref, delta);
}

/*
 * Settle up with the task that is keeping @cid across the end of its
 * slice, see keep_running().
 *
 * A task that goes on running is a task that was picked again, and every
 * reader of @cid has to see it that way: the service it has taken is
 * charged to its vruntime and to its pack, the way ops.stopping() does,
 * and what it is owed from here is published, the way ops.running() does.
 * Without it a cid whose task keeps winning would hold a reference that
 * stands still for as long as the task does, and everything placed or
 * tested against that cid meanwhile is placed against a clock that
 * stopped. @curr_since is what is not touched: it marks the moment the
 * CPU last actually changed hands.
 */
static void keep_charge(struct task_struct *p, s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx = cid_ctx(cid);
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	pack_t *pk;

	if (!tctx)
		return;
	pk = task_pack(tctx, cid);

	tctx->se.vruntime += calc_delta_fair(p, tctx, now - tctx->last_run_at);
	tctx->last_run_at = now;
	vref_charge(&tctx->se);

	pk->curr_dl = task_dl(p, tctx);
	pk->curr_v = tctx->se.vruntime;
	pk->curr_w = task_weight(p, tctx);
	pk->curr_run_at = now;
	pk->curr_request = task_request(p);
	cctx->curr_idle = p->policy == SCHED_IDLE;
}

/*
 * Move @se's vruntime to @vruntime, where it has just been placed against
 * a pack, and decide what becomes of its deadline.
 *
 * A task that slept gets a new request when it wakes: place_entity()
 * issues a fresh deadline, and here the deadline is dropped so that
 * task_dl() issues one from the new vruntime. A task that did not sleep,
 * moved to another cid or queued again after a bounced dispatch or a
 * preemption by a higher class, was partway through a request, and
 * fair.c keeps what is left of it, PLACE_REL_DEADLINE: the deadline is
 * stored relative to the vruntime on the way out of the runqueue,
 *
 *	if (sched_feat(PLACE_REL_DEADLINE) && !task_sleep) {
 *		se->deadline -= se->vruntime;
 *		se->rel_deadline = 1;
 *	}
 *
 * and re-based on the way in,
 *
 *	if (sched_feat(PLACE_REL_DEADLINE) && se->rel_deadline) {
 *		se->deadline += se->vruntime;
 *		se->rel_deadline = 0;
 *		return;
 *	}
 *
 * Without it the task is granted a whole request wherever it lands and
 * sorts behind tasks that were queued after it, once per migration. A
 * deadline the vruntime has already reached is a consumed request, and
 * is dropped either way, as update_deadline() would reissue it.
 */
static void set_vruntime(sched_ent_t *se, u64 vruntime, bool sleep)
{
	u64 rel = 0;

	if (!sleep && !no_place_rel_deadline && se->deadline &&
	    time_before(se->vruntime, se->deadline))
		rel = se->deadline - se->vruntime;

	se->vruntime = vruntime;
	se->deadline = rel ? vruntime + rel : 0;
}

/*
 * Pay off what a task owed the pack it blocked in, with the service that
 * pack has delivered since, which is DELAY_DEQUEUE and DELAY_ZERO.
 *
 * fair.c does not dequeue a task that blocks while it is over-served. It
 * is left in the tree, sched_delayed, still counted in W and still
 * holding its place, so that the reference goes on moving past it while
 * it sleeps: pick_next_entity() dequeues it the moment pick_eevdf()
 * would have run it, which is the moment it becomes eligible, and a
 * wakeup that comes sooner finds it where it was, with the part of the
 * debt that has been paid,
 *
 *	if (se->sched_delayed) {
 *		vlag = max(vlag, se->vlag);
 *		if (sched_feat(DELAY_ZERO))
 *			vlag = min(vlag, 0);
 *	}
 *
 * Either way it never wakes owing more than it did when it blocked, and
 * DELAY_ZERO sees to it that the pack's progress is not turned into
 * credit either. A task that is dequeued at once, as it is here, would
 * carry the whole debt across a sleep of any length and pay it in full
 * on waking, against a pack that may have long since moved on.
 *
 * There is no tree to leave the task in: ops.quiescent() is the end of
 * the kernel's interest in it, and the EDQ holds runnable tasks. So the
 * task leaves its pack, and what is remembered is where the pack stood
 * when it left, @delay_vref, and what the pack weighed without it,
 * @delay_w. When the task is placed again the pack's reference has
 * moved by the service delivered there since, and the delayed task
 * would have seen it move at
 *
 *	dV = w_j * dv_j / (W_o + w_i)
 *
 * with its own weight w_i still in the denominator, where the pack it
 * left advances at w_j * dv_j / W_o: the advance is scaled by
 * W_o / (W_o + w_i), which is exact while the pack keeps its weight and
 * an estimate otherwise. That much is credited to the debt and not a
 * unit more, DELAY_ZERO.
 *
 * A pack that has emptied since forgives the debt whole. That is what
 * pick_next_entity() does the moment the delayed task is the only thing
 * left to pick, and what it would do a moment later anyway, V being the
 * task's own vruntime once nothing else is there.
 *
 * Where the task wakes follows too, see delay_requeue_cid().
 */
static s64 delay_debt(const task_ctx_t *tctx, u64 now)
{
	s32 cid = tctx->delay_cid;
	pack_t *pk = task_pack(tctx, cid);
	s64 adv, lag = tctx->se.vlag;

	if (pk->empty_gen != tctx->delay_gen || lag >= 0)
		return 0;

	adv = (s64)(pack_vref_place(pk, cid_clock_task_at(cid, now)) - tctx->delay_vref);
	if (adv <= 0)
		return lag;
	adv = vdiv(adv * (s64)tctx->delay_w, tctx->delay_w + tctx->se.vw);

	lag += adv;
	return lag > 0 ? 0 : lag;
}

static void delay_settle(task_ctx_t *tctx, u64 now)
{
	if (!cid_valid(tctx->delay_cid))
		return;
	tctx->se.vlag = delay_debt(tctx, now);
	tctx->delay_cid = -1;
}

/*
 * The cid a waking task goes back to without being placed, or -1.
 *
 * ttwu_runnable() runs before select_task_rq(). A delayed task is still on
 * the runqueue it blocked on, so its wakeup requeues it there,
 *
 *	if (task_on_rq_queued(p)) {
 *		if (p->se.sched_delayed)
 *			enqueue_task(rq, p, ENQUEUE_NOCLOCK | ENQUEUE_DELAYED);
 *		if (!task_on_cpu(rq, p))
 *			wakeup_preempt(rq, p, wake_flags);
 *		ttwu_do_wakeup(p);
 *		return 1;
 *	}
 *
 * and no CPU is chosen for it: not the waker's, not an idle one. It runs
 * where it was once it is picked there, or wherever a balance moves it.
 *
 * The task is "still on the runqueue it blocked on" for as long as fair.c
 * would have kept it in the tree: while the pack it left is still there
 * and the debt it owes that pack is not yet paid, see delay_settle(). A
 * task whose debt is paid was dequeued by the pick that would have run
 * it, and wakes through the placement like any other. So is a task whose
 * affinity no longer covers the cid: a change of affinity takes a queued
 * task off its runqueue.
 *
 * The cid is handed back to the kernel and the task reaches ops.enqueue()
 * on it, where place_task() settles what is left of the debt and the
 * wakeup preemption test runs, which is requeue_delayed_entity() followed
 * by wakeup_preempt(). What is skipped is wake_affine() and the idle
 * scan, as ttwu_runnable() skips select_task_rq().
 */
static s32 delay_requeue_cid(const struct task_struct *p,
			     const task_ctx_t *tctx, u64 now)
{
	s32 cid = tctx->delay_cid;

	if (no_delay_requeue || !cid_valid(cid))
		return -1;
	if (is_restricted(p) && !cid_allowed(p, cid))
		return -1;
	if (!delay_debt(tctx, now))
		return -1;

	return cid;
}

/*
 * Place @p on @cid: a task that is not running is put at the cid's
 * reference minus the lag it carries, the way place_entity() does, and
 * either way it becomes a member of @cid's reference.
 *
 * The lag only means something against a pack. place_entity() applies it
 * under
 *
 *	if (sched_feat(PLACE_LAG) && cfs_rq->nr_queued && se->vlag)
 *
 * and skips it on an empty runqueue, where there is nobody to be ahead of
 * or behind: the task is placed at the base with neither credit nor debt,
 * and being the only member it becomes the reference itself. Applying the
 * lag there would only move the cid's clock, since the task's vruntime is
 * the average when it is alone, and a task carrying credit would take it
 * to an idle cid and have it silently absorbed. An idle cid is the
 * preferred wake target, see pick_idle_cid(), so this is the common
 * placement, not a corner of one.
 */
/*
 * Inflate a placement offset so that joining the destination pack does not
 * dilute it. If the pack has weight W and @p has weight w, placing @p at
 * V - offset moves the weighted-average reference to
 *
 *	V' = V - w * offset / (W + w).
 *
 * The lag visible after the join is therefore only W / (W + w) of the
 * requested offset. PLACE_LAG in fair.c compensates by (W + w) / W; write
 * that as offset + offset * w / W here to avoid forming W + w first.
 *
 * A task already in this pack is only being re-placed, not joined, because
 * vref_join() is a no-op for it. Its offset therefore needs no correction.
 */
static s64 compensate_place_offset(pack_t *pk, const sched_ent_t *se,
				   u64 weight, s64 offset)
{
	u64 load = pk->vsum_w;

	if (no_place_lag || !load || se->vpack == pk || !offset)
		return offset;

	return offset + vdiv(offset * (s64)weight, load);
}
static void place_task(s32 cid, const struct task_struct *p,
		       task_ctx_t *tctx, u64 now, bool sleep)
{
	/* The pack's progress is in its own task clock. */
	u64 tnow = cid_valid(cid) ? cid_clock_task_at(cid, now) : now;

	if (!scx_bpf_task_running(p) && cid_valid(cid)) {
		pack_t *pk = task_pack(tctx, cid);
		u64 w = task_weight(p, tctx);
		u64 vruntime = pack_vref_before_join(pk, &tctx->se, w, tnow);

		/*
		 * ops.quiescent() does not run when the kernel migrates a queued
		 * task. Refresh its lag against the pack it is leaving instead of
		 * reusing the value saved at its last sleep.
		 */
		if (!sleep && tctx->se.vpack)
			tctx->se.vlag = task_lag_at(p, tctx, tctx->se.vpack, now);
		delay_settle(tctx, now);
		if (pk->vsum_w) {
			s64 offset = tctx->se.vlag;

			offset = compensate_place_offset(pk, &tctx->se, w, offset);
			vruntime -= offset;
		}
		set_vruntime(&tctx->se, vruntime, sleep);
	}
	task_vref_join(cid, p, tctx);
}

/*
 * Bring the task's lag and deadline over to a new weight.
 *
 * Both are distances in the task's own virtual time, which runs at
 * NICE_0_WEIGHT / weight, so a change of weight changes what they are
 * worth in service. reweight_eevdf() has rescale_entity() carry the two
 * across:
 *
 *	se->vlag = div64_long(se->vlag * old_weight, weight);
 *	...
 *	if (se->rel_deadline)
 *		se->deadline = div64_long(se->deadline * old_weight, weight);
 *
 * so that the lag stays the service it was, w * (V - v), and the deadline
 * stays the request it was issued for, d' = v' + (d - v) * w / w'. Both
 * are called for by the derivation above rescale_entity(), and nothing
 * else about the task is. An entity that is on the runqueue is then
 * placed again from the rescaled lag, v' = V - vl': its vruntime moved at
 * the old rate for as long as it ran, and left where it is it would be
 * off by the whole difference.
 *
 * @dequeued says the task was taken off the runqueue for the change and
 * is about to be put back, which is how set_user_nice() and
 * __setscheduler_params() do it: ops.quiescent() has just taken its lag,
 * fresh, and the vruntime is placed from it here, since a running task's
 * enqueue never reaches ops.enqueue(), see cidland_set_weight(). A queued
 * task is placed once more by place_task() on the enqueue that follows,
 * against the cid it lands on. A sleeping task is only rescaled, what it
 * carries is spent when it wakes.
 */
static void reweight_task(const struct task_struct *p, task_ctx_t *tctx,
			  bool dequeued)
{
	u64 w = task_weight(p, tctx), old = tctx->se.vw;
	s32 cid;

	if (w == old)
		return;
	if (dequeued && tctx->se.vpack)
		tctx->se.vlag = task_lag_at(p, tctx, tctx->se.vpack, scx_bpf_now());
	tctx->se.vw = w;
	if (!old)
		return;

	tctx->se.vlag = vdiv(tctx->se.vlag * (s64)old, w);
	if (tctx->se.deadline && time_before(tctx->se.vruntime, tctx->se.deadline))
		tctx->se.deadline = tctx->se.vruntime +
				 (tctx->se.deadline - tctx->se.vruntime) * old / w;

	if (!dequeued)
		return;
	cid = scx_bpf_task_cid((struct task_struct *)p);
	if (cid_valid(cid)) {
		pack_t *pk = task_pack(tctx, cid);
		u64 now = scx_bpf_now();
		u64 vruntime = pack_vref_place(pk, cid_clock_task_at(cid, now));

		if (pk->vsum_w)
			vruntime -= tctx->se.vlag;
		set_vruntime(&tctx->se, vruntime, false);
	}
}

/*
 * Direct dispatch @p to the local DSQ of @cid from ops.select_cid().
 *
 * Insert with SCX_ENQ_IMMED so that the kernel bounces @p back through
 * ops.enqueue() (and from there into a per-cid EDQ, where the deadline
 * ordering applies) whenever @p can't run on @cid right away. This keeps
 * the local DSQ a pure "run now" fast path instead of an unbounded queue
 * that outranks the deadline-ordered EDQs.
 *
 * @cid is idle here, so the bounce is the exception: the kernel triggers
 * it (rq_is_open() in dispatch_one()) whenever a task is waiting on @cid
 * or a higher scheduling class took it in the meantime. Only call this for
 * a cid that is idle, never to stack @p behind a task that is running: the
 * bounce would be certain and the direct dispatch pure overhead.
 */
static void direct_dispatch_local(struct task_struct *p, task_ctx_t *tctx, s32 cid,
				  u64 now)
{
	/* ops.runnable() follows select_cid(), so refresh before spending lag. */
	cgw_refresh(p, tctx);
	place_task(cid, p, tctx, now, true);
	tctx->direct_placed = true;
	cid_edq_mark_dispatched(tctx);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_request(p), SCX_ENQ_IMMED);
}

/*
 * Return an allowed cid as close to @cid as possible: its LLC first, then
 * its node, then anywhere, or -ENOENT.
 *
 * @cid is one the task is not allowed on. That happens when the affinity
 * of a sleeping task is changed to exclude the CPU it last ran on: the
 * kernel does not migrate a task that is not queued, it leaves task_cpu()
 * stale and relies on the wakeup to land somewhere valid. The cache the
 * task left behind is still where it ran, so the CPUs that share it are
 * the best of the remaining options, which is why select_fallback_rq()
 * walks the node of task_cpu() before anything else.
 */
static s32 nearest_allowed_cid(const struct task_struct *p, s32 cid)
{
	struct cid_topo __arena *topo = cid_topo(cid);
	u32 i;

	bpf_arena_for(i, 0, topo->llc_nr) {
		s32 c = topo->llc_base + i;

		if (cid_allowed(p, c))
			return c;
	}

	if (numa_enabled && topo->node_nr > topo->llc_nr) {
		bpf_arena_for(i, 0, topo->node_nr) {
			s32 c = topo->node_base + i;

			if (cid_allowed(p, c))
				return c;
		}
	}

	bpf_arena_for(i, 0, nr_cids) {
		if (cid_allowed(p, i))
			return i;
	}

	return -ENOENT;
}

s32 BPF_STRUCT_OPS(cidland_select_cid, struct task_struct *p, s32 prev_cid, u64 wake_flags)
{
	bool direct = false;
	s32 cid, target, this_cid = scx_bpf_this_cid();
	task_ctx_t *tctx;
	u64 now;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx || !cid_valid(prev_cid))
		return prev_cid;

	/*
	 * Make sure @prev_cid is usable, otherwise fall back to the closest
	 * cid the task is allowed on. Only a restricted task can fail the
	 * test, so the cpumask lookup stays off the common path.
	 */
	if (is_restricted(p) && !cid_allowed(p, prev_cid)) {
		s32 near = nearest_allowed_cid(p, prev_cid);

		if (!cid_valid(near))
			return prev_cid;
		prev_cid = near;
	}

	now = scx_bpf_now();

	/*
	 * A task that blocked over-served and is still owed to the pack it
	 * left goes back to it, the way ttwu_runnable() requeues a delayed
	 * task on its runqueue before select_task_rq() is ever asked.
	 */
	cid = delay_requeue_cid(p, tctx, now);
	if (cid >= 0) {
		__sync_fetch_and_add(&nr_delay_requeues, 1);
		return cid;
	}

	/*
	 * Follow select_task_rq_fair()'s fast path: wake_affine() computes a
	 * target, then select_idle_sibling() looks around that target. An
	 * affine target is not itself a selection; if it is busy, an idle
	 * previous cid or an idle sibling still wins.
	 */
	target = wake_affine_cid(p, tctx, prev_cid, this_cid, wake_flags, now);

	/*
	 * Try to find an idle cid and dispatch the task directly to it,
	 * without bouncing it through ops.enqueue().
	 */
	cid = select_idle_sibling_cid(p, tctx, prev_cid, target, &direct, now);
	if (cid >= 0) {
		if (direct)
			direct_dispatch_local(p, tctx, cid, now);
		return cid;
	}

	/*
	 * A new task with no idle cid to go to is queued on the cid with the
	 * shortest queue rather than behind its parent.
	 */
	if (wake_flags & SCX_WAKE_FORK) {
		cid = shallowest_queue_cid(p, prev_cid);
		if (cid >= 0)
			return cid;
	}

	/* select_idle_sibling() also returns its target when its scan fails. */
	return target;
}

/*
 * Prepare to queue the task of @tctx on @cid with deadline @dl, and return
 * whether it should be inserted on the local DSQ as a preempting task.
 *
 * An idle cid only has to be told that there is work: the kick makes it
 * dispatch. A busy one is running a task of its own, and what this has to
 * decide is whether that task should be interrupted.
 *
 * This is EEVDF's wakeup preemption. wakeup_preempt_fair() asks what the
 * runqueue would pick now and reschedules when the answer is the task
 * that just woke. When the two tasks ask for the same slice, that pick
 * comes down to what pick_eevdf() opens with:
 *
 *	if (curr && (!curr->on_rq || !entity_eligible(cfs_rq, curr)))
 *		curr = NULL;
 *	if (curr && protect && protect_slice(curr))
 *		return curr;
 *
 * plus the queued task being eligible itself and holding the earlier
 * deadline, which is what makes it the pick. set_protect_slice() protects
 * the running task up to its own deadline, so for its whole request, but
 * that protection is dropped before it is ever tested once the task is no
 * longer eligible: served past the average of its pack, it keeps the CPU
 * only until something that is owed service asks for it.
 *
 * So the protection needs no window of its own. A task just picked is
 * owed service and holds the CPU; it becomes interruptible exactly when
 * it has had the share the pack owes it, which under load is a fraction
 * of the slice, and the woken task waits for that instead of for the
 * slice to end. What the running task gives up is the rest of a slice it
 * is still owed and takes up again, not its place in the order: it keeps
 * the deadline it was picked with, see task_dl().
 *
 * Nothing here reads a reference that is behind: the service the running
 * task has taken since it was picked is folded into both sides of every
 * comparison, see pack_vref_at() and curr_owed_service(), the way
 * wakeup_preempt_fair() calls update_curr_fair() before deciding
 * anything.
 *
 * All of it compares because all of it is in @cid's virtual time: the
 * running task joined that reference in ops.running() and the wakee was
 * placed against it just above. Two cids' references do not compare, which
 * is why the only cid this looks at is the one the task will be queued on.
 *
 * Before any of that, the policies. wakeup_preempt_fair() settles a
 * SCHED_IDLE task on either side without looking at the virtual times:
 *
 *	if (cse_is_idle && !pse_is_idle)
 *		goto preempt;
 *	update_curr_fair(rq);
 *	if (cse_is_idle != pse_is_idle)
 *		goto update;
 *	if (unlikely(!normal_policy(p->policy)))
 *		goto update;
 *
 * A SCHED_IDLE task is interrupted for any task that is not one, before
 * anything is asked about eligibility or deadlines, and a SCHED_IDLE or
 * SCHED_BATCH task never interrupts anything: both are policies for work
 * that gives up latency, not for work that is served less. What the
 * weight of 3 already does for a SCHED_IDLE task is to be interrupted
 * almost at once, since it is owed almost nothing, and to be queued
 * behind everything else; the policy rule is what keeps it from being
 * kicked for at all, and takes the running one off the CPU without
 * waiting for the tick to find it.
 *
 * The @curr_ fields describe the last task of ours to run there and say
 * nothing about a cid running something else. The idle test covers the
 * idle task; for a higher scheduling class the kick costs an IPI and
 * leaves the CPU with the class that owns it, which is where not kicking
 * would have left it too.
 */
static bool queued_cid_should_preempt(s32 cid, const struct task_struct *p,
				      const task_ctx_t *tctx, u64 dl,
				      u64 now)
{
	struct cid_ctx __arena *cctx;
	bool owed, p_idle, has_head;
	u64 head_dl;
	pack_t *pk;

	if (cid_idle_test(cid))
		goto idle;

	cctx = cid_ctx(cid);
	pk = task_pack(tctx, cid);

	if (no_wakeup_preempt)
		goto queued;

	/*
	 * A SCHED_IDLE task running is interrupted for anything else, and a
	 * SCHED_IDLE or SCHED_BATCH task queued interrupts nothing. The three
	 * tests above collapse to these two: once the first has taken the
	 * idle curr with a non-idle wakee, what the second and third turn
	 * away between them is any wakee that is not of a normal policy.
	 */
	p_idle = p->policy == SCHED_IDLE;
	if (cctx->curr_idle && !p_idle)
		goto preempt;
	if (p_idle || p->policy == SCHED_BATCH)
		goto queued;

	/*
	 * The queued task has to be owed service to be a candidate at all:
	 * pick_eevdf() only ever looks at the eligible part of the tree.
	 */
	if (!no_eligibility &&
	    time_after(tctx->se.vruntime, pack_vref_place(pk, now)))
		goto queued;

	/*
	 * PREEMPT_SHORT lets an eligible task with a shorter request override
	 * the running task's protection. fair.c makes it the short buddy so it
	 * is selected next even when another task has an earlier deadline. The
	 * local-DSQ insertion made after this returns is the same one-shot
	 * override when that DSQ is available: it runs before the
	 * deadline-ordered per-cid EDQ. An existing local waiter is not
	 * displaced because the built-in DSQ is FIFO-only; that waiter already
	 * requested rescheduling and the new wakee retains deadline order on
	 * the per-cid EDQ.
	 *
	 * Both requests are already cached. task_dl() recorded the wakee's in
	 * @tctx, and ops.running() or keep_charge() published the current one.
	 * Equal default requests therefore add only this comparison and branch
	 * to the existing wakeup path.
	 */
	if (!no_preempt_short && tctx->se.request < pk->curr_request &&
	    pk->curr_w)
		goto preempt;

	/*
	 * Is the running task still owed service? Once it has run for a
	 * whole request it is past its deadline as well, and either way it
	 * has no protection left. This is the half of the pick that
	 * RUN_TO_PARITY governed, and --no-run-to-parity drops it alone.
	 */
	owed = !no_eligibility && curr_owed_service(pk, now);
	if (owed && !no_run_to_parity)
		goto queued;

	/*
	 * Only a curr that is still owed service is in the running at all:
	 *
	 *	if (curr && (!curr->on_rq || !entity_eligible(cfs_rq, curr)))
	 *		curr = NULL;
	 *
	 * pick_eevdf() drops it before it looks at the tree, so a curr that
	 * has had its share loses to the queued task whatever the deadlines
	 * say. --no-eligibility keeps deciding on the deadlines alone.
	 */
	if ((owed || no_eligibility) && !time_before(dl, pk->curr_dl))
		goto queued;

	/*
	 * The task is only worth interrupting the CPU for if it is what the
	 * CPU would run next. wakeup_preempt_fair() preempts for the woken
	 * task alone,
	 *
	 *	nse = pick_next_entity(rq, ...);
	 *	if (nse == pse)
	 *		goto preempt;
	 *
	 * and a curr that has lost the pick to some other queued task is
	 * left running until its slice ends, or until a wakeup that does win
	 * it. The preemption approximation treats the EDQ head as the next pick,
	 * so the woken task must have a strictly earlier deadline. Selection at
	 * actual dispatch can scan for eligibility, but doing so here changes the
	 * policy using a non-atomic snapshot of current, queue, and virtual-time
	 * state. A task already queued is not displaced by one that ties it. The
	 * insertion is applied once this op returns, so the head seen here is the
	 * one the task is queued against.
	 * A preemption for a task that queues behind others only trades the
	 * running task for the head a slice early, once for
	 * every wakeup that lands in the queue: with sixteen tasks queued per
	 * CPU that was one context switch in three, and perf bench sched
	 * messaging ran at half its speed.
	 */
	has_head = !scx_edq_first_deadline(&pk->edq, &head_dl);
	if (has_head) {
		bool loses = !time_before(dl, head_dl);

		if (loses)
			goto queued;
	}

preempt:
	return true;
queued:
	/*
	 * The task waits behind the running one. See that the running one
	 * is asked again when its deadline comes rather than at the tick
	 * after it, hrtick_update():
	 *
	 *	hrtick_start_fair(rq, donor);
	 */
	hrtick_start(cid, now);
idle:
	/* An op executing on @cid is itself proof that @cid is not idle. */
	if (cid != scx_bpf_this_cid())
		scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
	return false;
}

void BPF_STRUCT_OPS(cidland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cid = scx_bpf_task_cid(p), cid;
	task_ctx_t *tctx;
	bool displaced;
	u64 dl, now, tnow;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx || !cid_valid(prev_cid))
		return;

	now = scx_bpf_now();
	displaced = !(enq_flags & SCX_ENQ_WAKEUP) && scx_bpf_task_running(p);
	if (displaced)
		WRITE_ONCE(cid_ctx(prev_cid)->requeue_pending, 0);

	/*
	 * An idle preferred destination asked @prev_cid for this running task.
	 * The source dispatch validated the request and let its slice expire;
	 * ops.stopping() has charged the service since then. Honor the handoff if
	 * the destination is still idle, otherwise use ordinary placement.
	 */
	cid = tctx->dispatch_migrate_cid;
	tctx->dispatch_migrate_cid = -1;
	if (!(enq_flags & SCX_ENQ_WAKEUP) && cid_valid(cid) && cid != prev_cid &&
	    cid_idle_test(cid) && cid_allowed(p, cid)) {
		cid = claim_idle_cid(p, cid);
		if (cid >= 0) {
			place_task(cid, p, tctx, now, false);
			cid_edq_mark_dispatched(tctx);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid,
					   task_request(p), enq_flags | SCX_ENQ_IMMED);
			__sync_fetch_and_add(&nr_active_balances, 1);
			/* The requeue ops.dispatch() expected went elsewhere. */
			if (displaced)
				cid_queued_check(prev_cid);
			return;
		}
	}

	/*
	 * Attempt to dispatch directly to an idle cid if the task can
	 * migrate.
	 *
	 * A waking task has already been through ops.select_cid(), which
	 * scanned for an idle cid and decided where to put it: that is what
	 * SCX_ENQ_CPU_SELECTED reports, see task_should_migrate(). Scanning
	 * again here would only undo that decision, and on a synchronous
	 * wakeup it would pull the wakee off the waker it was deliberately
	 * stacked on. A task that got here without that scan (the kernel
	 * skips ops.select_cid() for a task that can't migrate, and a
	 * re-enqueue never goes through it) is scanned for.
	 *
	 * A busy @prev_cid is a reason for a re-enqueued task to leave only
	 * when it is busy with someone else. A task that is re-enqueued from
	 * its own CPU at the end of its slice is what @prev_cid is busy with,
	 * and it is giving the CPU up to whoever was waiting for it,
	 * typically a per-CPU kworker that is done a few microseconds later.
	 * Pushing it away at that point turns every such handover into a
	 * migration. Leave it queued instead, the way a task stays on its
	 * runqueue: its own CPU takes it back as soon as it is free again.
	 *
	 * A task re-enqueued from its own CPU with slice left, on the other
	 * hand, was preempted by a higher scheduling class (the kernel
	 * bounces an IMMED task back through ops.enqueue() in that case)
	 * and @prev_cid is taken for an unknown amount of time, so an idle
	 * cid is the better option.
	 *
	 * A busy SMT sibling is not by itself a reason to leave. Asymmetric
	 * active balance records a specific preferred destination before this
	 * point; absent that request, preserve the local EEVDF placement.
	 */
	if ((task_should_migrate(p, enq_flags) && !reenq_immed(p, enq_flags)) ||
	    (reenq_preempted(p, enq_flags) && p->scx.slice && !cid_idle_test(prev_cid))) {
		cid = pick_idle_cid(p, prev_cid, prev_cid);
		if (cid >= 0) {
			place_task(cid, p, tctx, now, enq_flags & SCX_ENQ_WAKEUP);
			cid_edq_mark_dispatched(tctx);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid,
					   task_request(p), enq_flags | SCX_ENQ_IMMED);
			if (displaced)
				cid_queued_check(prev_cid);
			return;
		}
	}

	tnow = cid_clock_task_owned(prev_cid, now);
	place_task(prev_cid, p, tctx, now, enq_flags & SCX_ENQ_WAKEUP);

	/*
	 * A task displaced while it is still curr keeps its vruntime and the
	 * deadline it was picked with, see place_task(), and that deadline
	 * can be the earlier one: the kick that displaced it was issued
	 * because it is no longer owed service, not because it lost on the
	 * deadline. pick_eevdf() would leave it in the tree and skip it as
	 * ineligible. Head-only selection would pick it straight
	 * back and the task that displaced it would wait for the tick.
	 *
	 * Reissue its deadline from where its vruntime has reached, which is
	 * what update_deadline() does once a request is consumed. The
	 * vruntime is current: a running task reaches ops.enqueue() from
	 * put_prev_task_scx(), after ops.stopping() has charged the service
	 * it took, and charging it again here counted its last run twice.
	 * The published view of the cid is of no use for the same reason,
	 * ops.stopping() has cleared it, so the task is tested on its own
	 * vruntime against the reference, which is entity_eligible().
	 */
	if (displaced && !no_eligibility &&
	    time_after(tctx->se.vruntime,
		       pack_vref_place(task_pack(tctx, prev_cid), tnow)))
		tctx->se.deadline = 0;

	dl = task_dl(p, tctx);

	/*
	 * Queue the task for @prev_cid, ordered by deadline unless it wins
	 * wakeup preemption below.
	 *
	 * Any cid of the node can take it from there, but only while
	 * dispatching: if @prev_cid went idle in the meantime and the rest
	 * of the node is idle too, nothing would ever look at it. Kick
	 * @prev_cid, which either wakes it or lets the local insertion interrupt
	 * what it is running, see queued_cid_should_preempt().
	 *
	 * SCX_ENQ_LAST says the task is the only sched_ext work available to a
	 * CPU that is about to run a higher scheduling class. The kernel keeps
	 * it runnable but requires the BPF scheduler to trigger a follow-up
	 * scheduling event. A rejected active-balance handoff can reach this
	 * path, but it is not the only source of the flag.
	 *
	 * If the task is the only waiter, the queue can exist for less than a
	 * tick: the higher-class task blocks, @prev_cid takes its waiter back,
	 * and an idle cid never observes the transient imbalance. Tell one idle
	 * peer at enqueue time. It is also told to ignore hotness for this pull,
	 * since otherwise the one guaranteed dispatch can reject the waiter and
	 * go idle again. Restrict this to a depth of one: deeper queues survive
	 * until the tick path notices them, and wakeup-heavy loads should not pay
	 * an idle scan and a cache-cold migration on every enqueue.
	 *
	 * A preempting wakee is either the EEVDF pick or PREEMPT_SHORT's
	 * one-shot short buddy. Put it directly on the rq-owned local DSQ so
	 * the kernel can expire curr's slice and request rescheduling
	 * synchronously under the rq lock, instead of queueing it here and
	 * delivering an SCX_KICK_PREEMPT later through irq_work.
	 *
	 * Do not combine this with SCX_ENQ_IMMED. A running task can have a
	 * protected slice, in which case the kernel refuses the preemption.
	 * An IMMED insertion would then bounce @p back through ops.enqueue(),
	 * make the same decision, and repeat. Without IMMED, @p stays at the
	 * head of the local DSQ and runs when the protected service ends.
	 *
	 * Use the fast path only while the local DSQ is empty. Built-in DSQs
	 * are FIFO-only, so a second preempting insertion would otherwise go
	 * ahead of the first without comparing their deadlines. The pending
	 * local task has already requested rescheduling; later wakees retain
	 * their deadline order on the per-cid EDQ.
	 */
	if (!displaced &&
	    queued_cid_should_preempt(prev_cid, p, tctx, dl, tnow) &&
	    !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cid)) {
		cid_edq_mark_dispatched(tctx);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cid,
				   task_request(p),
				   enq_flags | SCX_ENQ_PREEMPT);
		__sync_fetch_and_add(&nr_preempts, 1);
		return;
	}

	if (!cid_queue_insert(p, tctx, prev_cid, task_request(p), dl,
			      tctx->se.vruntime, enq_flags)) {
		if (displaced)
			cid_queued_check(prev_cid);
		return;
	}
	cid_queued_set(prev_cid);
	if ((enq_flags & SCX_ENQ_LAST) &&
	    cid_queue_nr(prev_cid) == 1) {
		cid = idle_peer_cid(p, prev_cid);
		if (cid >= 0 && cid != prev_cid) {
			WRITE_ONCE(cid_ctx(cid)->force_steal, 1);
			scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
		}
	}
}

/*
 * newidle_cost(): the budget of an idle pull, sched_balance_newidle()'s.
 *
 * A cid that runs out of work looks for some, and fair.c asks first
 * whether the look is worth it. The rq keeps avg_idle, how long the CPU
 * has been staying idle after a newidle balance, every domain keeps
 * max_newidle_lb_cost, the most a pull at that level has cost, and the
 * balance is skipped before it starts and stopped at the level the
 * budget runs out at:
 *
 *	if (!get_rd_overloaded(this_rq->rd) ||
 *	    this_rq->avg_idle < sd->max_newidle_lb_cost)
 *		goto out;
 *	for_each_domain(this_cpu, sd) {
 *		if (this_rq->avg_idle < curr_cost + sd->max_newidle_lb_cost)
 *			break;
 *		...
 *		domain_cost = t1 - t0;
 *		curr_cost += domain_cost;
 *		update_newidle_cost(sd, domain_cost, ...);
 *	}
 *	if (curr_cost > this_rq->max_idle_balance_cost)
 *		this_rq->max_idle_balance_cost = curr_cost;
 *
 * A CPU whose idle periods are shorter than a scan is one its own wakeups
 * keep bringing back: a task pulled for it comes off a queue whose owner
 * was about to run it, onto a CPU about to have work of its own, and the
 * pull costs more than the idle time it fills. The period is measured
 * from the moment the pull begins, idle_stamp, to the moment the CPU
 * leaves idle, update_rq_avg_idle(), as an average that moves an eighth
 * of the way to every sample and is capped at twice the rq's worst pull,
 * so that one long idle spell does not license scans for the next second
 * of storm:
 *
 *	u64 delta = rq_clock(rq) - rq->idle_stamp;
 *	u64 max = 2*rq->max_idle_balance_cost;
 *	update_avg(&rq->avg_idle, delta);
 *	if (rq->avg_idle > max)
 *		rq->avg_idle = max;
 *
 * A level's cost decays by 1% a second once it stops being raised,
 * update_newidle_cost(), so a spike does not close the budget for good,
 * and the rq's worst pull is refreshed from the sum of the levels when
 * they decay, floored at sysctl_sched_migration_cost. Both start where
 * sched_init() starts them, at twice and once that cost.
 *
 * The levels here are the three an idle cid walks, its LLC, the rest of
 * the node, and the rest of the system (fair.c's top-level sched domain).
 * The climb up the capacity tiers that precedes the first is charged to the LLC.
 * A pull kicked for a specific waiter, see ops.tick(), is not budgeted:
 * that is the idle balancer running for
 * nohz_balancer_kick(), which fair.c does not gate by avg_idle either.
 * The stamp is only read once the cid has gone idle, and every way there
 * passes through the pull, so a stamp left behind by a pull that found
 * something is never read.
 */
#define NEWIDLE_DECAY_NS	1000000000ULL

/*
 * Decay the level costs of @cctx that have not been raised for a second,
 * and refresh its worst pull from them: sched_balance_domains(), which
 * does this from the tick.
 */
static void newidle_decay(struct cid_ctx __arena *cctx, u64 now)
{
	bool decayed = false;
	u64 sum = 0;
	int i;

	for (i = 0; i < NEWIDLE_LEVELS; i++) {
		if (time_after(now, cctx->newidle_decay_at[i] + NEWIDLE_DECAY_NS)) {
			cctx->newidle_cost[i] = cctx->newidle_cost[i] * 253 / 256;
			cctx->newidle_decay_at[i] = now;
			decayed = true;
		}
		sum += cctx->newidle_cost[i];
	}
	if (decayed)
		cctx->max_idle_balance_cost = MAX(migration_cost_ns, sum);
}

/*
 * Charge a pull that cost @cost to level @level of @cctx,
 * update_newidle_cost().
 */
static void update_newidle_cost(struct cid_ctx __arena *cctx, u32 level,
				u64 cost, u64 now)
{
	if (cost > cctx->newidle_cost[level]) {
		cctx->newidle_cost[level] = cost;
		cctx->newidle_decay_at[level] = now;
	} else if (time_after(now, cctx->newidle_decay_at[level] + NEWIDLE_DECAY_NS)) {
		cctx->newidle_cost[level] = cctx->newidle_cost[level] * 253 / 256;
		cctx->newidle_decay_at[level] = now;
	}
}

/*
 * @cctx leaves idle at @now: fold the period since its pull began into
 * the average, update_rq_avg_idle().
 */
static void update_avg_idle(struct cid_ctx __arena *cctx, u64 now)
{
	u64 idle = now - cctx->idle_stamp;
	u64 max = 2 * cctx->max_idle_balance_cost;

	if (idle > cctx->avg_idle)
		cctx->avg_idle += (idle - cctx->avg_idle) / 8;
	else
		cctx->avg_idle -= (cctx->avg_idle - idle) / 8;
	if (cctx->avg_idle > max)
		cctx->avg_idle = max;
	cctx->idle_stamp = 0;
}

/*
 * Periodic tick on a cid that is running an scx task.
 *
 * A queue building up beside an idle CPU is nobody's job to notice, and
 * fair.c has the same problem: an idle CPU that has already been through
 * newidle_balance() will not look again by itself. It is told to, from
 * the tick, by nohz_balancer_kick():
 *
 *	if (rq->nr_running >= 2) {
 *		flags = NOHZ_STATS_KICK | NOHZ_BALANCE_KICK;
 *		goto out;
 *	}
 *
 * and that is the only place the kernel sends it: sched_balance_trigger()
 * has one caller, sched_tick(). Nothing on the enqueue or the wakeup path
 * ever wakes a third CPU to come and pull. Here it is not sent at all,
 * since sched_tick() skips sched_balance_trigger() once sched_ext has
 * taken every task, so this is the whole of it.
 *
 * One task queued beside the running one is @rq->nr_running == 2, the
 * condition above. The task woken for is the head of the queue, the one
 * a scan would take, and only a cid it is allowed on is worth waking:
 * it is that task the woken cid would come to pull, see try_steal_task().
 * One cid is enough, since the scan it wakes into reads every queue of
 * the node anyway.
 *
 * The tick is also the right rate. Scanning on every enqueue instead puts
 * the walk and an IPI on the wakeup path, where they cost more than the
 * idle CPU they are meant to recover, and pulls a wakee off the cid that
 * wake_affine_cid() has just stacked it on.
 */
void BPF_STRUCT_OPS(cidland_tick, struct task_struct *p)
{
	struct cid_topo __arena *topo;
	s32 cid = scx_bpf_this_cid(), peer;
	struct task_struct *head;
	u64 now, tid;

	TOUCH_ARENA();
	now = scx_bpf_now();

	if (!cid_valid(cid))
		return;
	topo = cid_topo(cid);
	if (!no_newidle_cost)
		newidle_decay(cid_ctx(cid), now);
	cid_load_accumulate(cid, now);

	/*
	 * Run wider, less frequent domains first when two happen to be due on
	 * the same tick. Stop after one successfully reserved source rather than
	 * stacking migrations from multiple levels at one scheduling boundary.
	 */
	if (nr_cids > topo->node_nr &&
	    busy_balance_domain(cid, 0, nr_cids, BUSY_BALANCE_SYSTEM, now))
		return;
	if (topo->node_nr > topo->llc_nr &&
	    busy_balance_domain(cid, topo->node_base, topo->node_nr,
				BUSY_BALANCE_NODE, now))
		return;
	if (busy_balance_domain(cid, topo->llc_base, topo->llc_nr,
				BUSY_BALANCE_LLC, now))
		return;
	if (!cid_queue_nr(cid)) {
		/*
		 * nohz_balancer_kick() also wakes an idle balancer when the sole
		 * runnable task is on a lower-priority or undersized CPU. Serialize
		 * that trigger once per placement domain, initially at fair.c's
		 * domain-weight interval. The interval belongs to the idle
		 * destination, as fair.c's balance interval does. Reserve that
		 * destination before the kick so concurrent source ticks cannot
		 * request the same balance.
		 */
		peer = idle_balance_cid(p, cid, now);
		if (peer >= 0 && peer != cid && active_balance_reserve(peer, now)) {
			scx_bpf_kick_cid(peer, SCX_KICK_IDLE);
		}
		return;
	}

	/*
	 * The head is only looked up for idle_peer_cid(), which has nothing
	 * to offer when no cid is idle; that is the common case on a busy
	 * machine, and the lookup is the expensive part of this tick.
	 */
	if (cmask_empty(idle_cids))
		return;
	tid = cid_edq_peek_tid_owned(cid);
	head = tid ? scx_bpf_tid_to_task(tid) : NULL;
	if (!head)
		return;

	peer = idle_peer_cid(head, cid);
	if (peer >= 0 && peer != cid) {
		/*
		 * If the ordinary head pull fails, let the idle cid walk past a
		 * pinned or cache-hot head before considering active balance. The
		 * ordinary pull is not paced; only reserve its active-balance
		 * fallback when the destination interval is due.
		 */
		active_balance_reserve(peer, now);
		scx_bpf_kick_cid(peer, SCX_KICK_IDLE);
	}
}

/*
 * @from gives up the CPU, sched_yield().
 *
 * This is yield_task_fair():
 *
 *	if (unlikely(rq->nr_running == 1))
 *		return;
 *	...
 *	update_curr(cfs_rq);
 *	...
 *	if (entity_eligible(cfs_rq, se)) {
 *		se->vruntime = se->deadline;
 *		update_deadline(cfs_rq, se);
 *	}
 *
 * What a yield costs is the rest of the request the task is in the middle
 * of. Its vruntime is moved up to the deadline it was issued, as if it had
 * run the whole of it, and a deadline is reissued from there. That puts it
 * behind the pack it is in rather than at the back of the queue or nowhere
 * at all: a task that yields in a loop is charged for every request it
 * does not use and falls behind at exactly the rate that says so, and one
 * that yields once has given up one turn.
 *
 * fair.c guards the forfeit with the eligibility test and says why: under
 * core scheduling an ineligible task can be picked, and one that yields
 * every time it is picked would run its vruntime away. The same guard is
 * kept here for the same reason.
 *
 * Whether the CPU changes hands is then the pick's decision, not the
 * yield's: yield_task_fair() ends in schedule(), and pick_eevdf() hands
 * the CPU back to the yielder when, forfeit and all, it is still the
 * eligible task with the earliest deadline. Without this op the kernel
 * zeroes the slice,
 *
 *	if (SCX_HAS_OP(sch, yield))
 *		SCX_CALL_OP_2TASKS_RET(sch, yield, rq, p, NULL);
 *	else
 *		scx_set_task_slice(p, 0);
 *
 * so installing one takes that over, and the slice is ended only when
 * the dispatch would not keep the task, which is the same question
 * keep_running() answers there: a task that would be handed straight
 * back keeps its slice and the schedule() picks it on the cheap path,
 * where a forced slice end cost it a full dispatch for nothing. A task
 * on the local DSQ has already won a preemption and is the pick.
 * yield_task_scx() has already called scx_task_slice_ended(), which
 * drops the %SCX_TASK_PROTECTED that would otherwise refuse the write.
 *
 * @to is a directed yield, yield_to(), and it is refused. fair.c honours
 * one with set_next_buddy(), which pick_next_entity() reads under
 * PICK_BUDDY; there is no buddy here and nothing that would read one.
 * Charging the caller a request for a request that will not be honoured
 * buys nothing, so a directed yield does nothing at all - yield_to() reads
 * false as "not implemented" and skips even the schedule() it would
 * otherwise make, leaving the caller free to try another target.
 */
bool BPF_STRUCT_OPS(cidland_yield, struct task_struct *from,
		    struct task_struct *to)
{
	s32 cid = scx_bpf_this_cid();
	task_ctx_t *tctx;
	u64 now, tnow;

	TOUCH_ARENA();

	if (to || !cid_valid(cid))
		return false;

	/*
	 * Nothing else can run here, so there is nobody the forfeit would
	 * hand the CPU to. This is fair.c's rq->nr_running == 1:
	 *
	 *	if (unlikely(rq->nr_running == 1))
	 *		return;
	 *
	 * and like it this returns before anything else, the slice included:
	 * the schedule() a yield ends in then picks the same task back on the
	 * cheap path. It also has to be about as cheap as fair.c's one load,
	 * since a task that yields in a loop asks this millions of times a
	 * second: the queued bitmap is that load, where a pair of DSQ queries
	 * halved the yield rate of a task running alone. A task on the local
	 * DSQ is not covered; it is the run-now fast path and is drained at
	 * the next dispatch, a slice end away at most.
	 */
	if (!cid_queued_test(cid) && !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL))
		return false;

	tctx = try_lookup_task_ctx(from);
	if (!tctx)
		return false;

	/*
	 * update_curr(), which leaves a deadline ahead of the vruntime
	 * whether or not the one it was issued has been consumed, and the
	 * cid's published view of what it is running up to date with both.
	 * The reference read below is then exact rather than projected.
	 */
	now = scx_bpf_now();
	tnow = cid_clock_task_owned(cid, now);
	keep_charge(from, cid, tnow);

	if (time_after(tctx->se.vruntime,
		       pack_vref_place(task_pack(tctx, cid), tnow)))
		goto pick;

	tctx->se.vruntime = tctx->se.deadline;

	/*
	 * The jump is service as far as the pack is concerned, the way
	 * avg_vruntime() folds curr in at whatever vruntime it is carrying,
	 * and it is a consumed request as far as the deadline is concerned.
	 * Both are what this second settle-up is for.
	 */
	keep_charge(from, cid, tnow);

pick:
	/*
	 * pick_eevdf(): the yielder keeps the CPU only if it is still the
	 * eligible task with the earliest deadline, see keep_running().
	 */
	if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL) || !keep_running(cid, tnow))
		scx_bpf_task_set_slice(from, 0);

	return false;
}

/*
 * Is the task of @tctx, queued on @src_cid, still cache hot there as far as
 * @dst_cid is concerned?
 *
 * Two threads of one core share every cache there is, so a task is never
 * hot between them: moving it costs nothing and leaving one of them idle
 * costs a thread. task_hot() says the same of a domain with
 * SD_SHARE_CPUCAPACITY.
 */
static bool task_hot(const task_ctx_t *tctx, s32 src_cid, s32 dst_cid,
		     u64 now)
{
	if (smt_enabled &&
	    cid_topo(src_cid)->core_base == cid_topo(dst_cid)->core_base)
		return false;

	return time_before(now, tctx->last_stop_at + migration_cost_ns);
}

/*
 * Look at the queued cids of @w, word @k rotated by @s (packed in @ks as
 * k << 16 | s), and return the first one with a task @dst_cid can take, or
 * -1, in the low 32 bits, with the number of queues still allowed in the high
 * 32 bits. A bounded deadline-ordered EDQ prefix is held, revalidated and
 * dispatched here. @ctl packs the number of queues to look at and whether a
 * task still hot on its CPU is skipped. A queue found empty has its bit
 * cleared.
 *
 * A global function: it is verified once, not once per call site and
 * loop iteration, which keeps ops.dispatch() within the verifier's
 * budget.
 */
__noinline u64 steal_from_word(s32 dst_cid, u64 w, u32 ks, u64 now, u32 ctl)
{
	u32 k = ks >> 16, s = ks & 63;
	u32 limit = (ctl >> 8) & 0xff;
	bool check_hot = ctl & 1;
	s32 ret = -1;

	TOUCH_ARENA();

	w = rotr64(w, s);
	while (w && limit && can_loop) {
		enum cid_edq_move_result move;
		s32 cid;

		cid = k * 64 + ((__builtin_ctzll(w) + s) & 63);
		w &= w - 1;
		if (cid == dst_cid || !cid_valid(cid))
			continue;
		limit--;

		move = cid_edq_move_usable_task_to_local(dst_cid, cid, now,
						     check_hot);
		if (move == CID_EDQ_MOVE_MOVED) {
			ret = cid;
			break;
		}
		if (move != CID_EDQ_MOVE_BUSY)
			cid_queued_check(cid);
	}

	return ((u64)limit << 32) | (u32)ret;
}

/*
 * Walk the queued cids of [@base, @base + @nr), restricted to tier @t if
 * @t is not negative, starting after @start and wrapping around, and
 * return the first one @dst_cid can steal from, or -1.
 */
static __always_inline s32
steal_from_range(s32 dst_cid, s32 t, u32 base, u32 nr, u32 start, u64 now,
		 bool check_hot, u32 limit)
{
	u32 first = base / 64, last, kstart, i, span;

	if (!nr)
		return -1;
	last = (base + nr - 1) / 64;
	span = last - first + 1;
	if (start < base || start >= base + nr)
		start = base;
	kstart = start / 64;

	bpf_arena_for(i, 0, span) {
		u32 k = first + (kstart - first + i) % span;
		u64 w, ret;
		s32 cid;

		w = cmask_word(queued_cids, k) & cmask_range_word(queued_cids, k, base, nr);
		if (t >= 0)
			w &= place_tier_word(t, k);
		if (!w)
			continue;
		ret = steal_from_word(dst_cid, w, (k << 16) | (i ? 0 : start & 63),
				      now, (limit << 8) | check_hot);
		cid = (s32)(u32)ret;
		limit = ret >> 32;
		if (cid >= 0)
			return cid;
		if (!limit)
			break;
	}

	return -1;
}

/*
 * Dispatch on @dst_cid a task from its own EDQ or from the EDQ of another
 * cid of the node.
 *
 * @has_prev says the CPU still has the task it was running: @prev is
 * runnable and merely off the EDQ while dispatch decides whether to renew
 * its slice. A cid in that state is busy, not idle, and fair.c draws the
 * line in the same place, in pick_task_fair():
 *
 *	if (!cfs_rq->h_nr_queued)
 *		goto idle;
 *	...
 * idle:
 *	new_tasks = sched_balance_newidle(rq, rf);
 *
 * A task whose slice has expired is still on the runqueue, so no newidle
 * balance is run for it. Taking the slice end for an idle CPU here instead
 * ran a full pull once per slice on every CPU, took a task off a neighbour
 * that had no imbalance to correct, and left that neighbour with nothing to
 * run and nothing cold to take back: under `stress-ng -c 0` that alone kept
 * the CPUs at 99.6% busy where fair.c holds every one of them at 100%.
 *
 * A cid with nothing to run pulls the first task it finds: from the slower
 * cids first, once the task is no longer cache-hot on its previous CPU. This
 * carries queued load up the capacity ladder. Asymmetric packing and misfit
 * balancing separately move a running task when fair.c's active-balance
 * conditions are met; this pull path still leaves cache-hot queued tasks
 * alone. A pull onto a faster core is only attempted when the whole core is
 * idle, as a fast thread sharing its core is no better than a whole slow one
 * and asym_smt_can_pull_tasks() refuses that move too; then the cid scans its
 * own LLC, the rest of the node, and finally the rest of the system with
 * the same hot-task check.
 *
 * The check is given up, on the climb as much as on the scans that
 * follow it, once the cid has come back empty from @cache_nice_tries
 * scans in a row with work queued somewhere it could not take: an idle
 * CPU beside a runnable task is worse than a cold cache, and a
 * preference that never yields is a barrier. This is what
 * can_migrate_task() does with sd->nr_balance_failed, and the counter
 * is cleared as soon as a scan finds something, or finds the system
 * genuinely empty.
 *
 * A cid that has work of its own does not pull. Sampling instantaneous
 * queue depths from busy cids moved tasks back and forth under wakeup-heavy
 * load, where fair.c's busy balancer instead acts periodically on averaged
 * load and a computed imbalance.
 *
 * Only the heads are considered, a queue whose head cannot run on @dst_cid
 * (or is still hot there) is skipped as a whole.
 *
 * Return true if a task has been dispatched, false otherwise.
 */
static bool try_steal_task(s32 dst_cid, bool has_prev, bool keep, u64 now,
			   bool kicked)
{
	struct cid_ctx __arena *cctx = cid_ctx(dst_cid);
	struct cid_topo __arena *topo = cid_topo(dst_cid);
	bool own = !keep && cid_queued_test(dst_cid) && cid_queue_nr(dst_cid);
	bool busy = own || has_prev;
	bool force_steal = !busy && READ_ONCE(cctx->force_steal);
	u32 node_base = numa_enabled ? topo->node_base : 0;
	u32 node_nr = numa_enabled ? topo->node_nr : nr_cids;
	u32 failed = cctx->nr_balance_failed;
	bool budget = false, node_skipped = false, system_skipped = false;
	u64 curr_cost = 0, t0 = 0;
	u32 start;
	s32 src = -1;

	/*
	 * The kick that set this bought one dispatch, and it is spent here
	 * whatever that dispatch finds: the waiter it was sent for is often
	 * taken back by its own cid first, and a permission outliving that
	 * would fire on an unrelated scan later on.
	 */
	if (force_steal)
		WRITE_ONCE(cctx->force_steal, 0);

	/*
	 * A cid that is keeping the task it is running has nothing to pull:
	 * not its own queue, whose head it has just been preferred to, and
	 * not a neighbour's, since anything pulled in would displace it.
	 */
	if (keep)
		goto own;

	if (busy)
		goto own;

	start = cctx->steal_cursor;
	if (start >= nr_cids)
		start = 0;

	/*
	 * sched_balance_newidle(): the idle period is measured from here,
	 * and a cid that has not been staying idle long enough to pay for
	 * a scan of its LLC does not start one, see newidle_cost().
	 *
	 * A cid woken by a balance kick, for a waiter or for an active
	 * balance, is not ending an idle period: fair.c runs the idle
	 * balancer in softirq on the idle task and rq->avg_idle never
	 * hears of it. Stamping here would make the wakeup that does
	 * end the period measure it from the kick, and under a busy
	 * tick that kicks a preferred idle core a hundred times a
	 * second the average collapsed, the budget closed, and the
	 * idle pull stopped: half the steals, 17% off messaging.
	 */
	if (!force_steal && !kicked)
		cctx->idle_stamp = now;
	budget = !no_newidle_cost && !force_steal && !kicked;
	/*
	 * The cost is measured on a fresh clock, sched_clock_cpu() in
	 * sched_balance_newidle(): the rq clock stands still under the
	 * lock and would read every pull as free.
	 */
	if (budget)
		t0 = bpf_ktime_get_ns();
	if (budget && cctx->avg_idle < cctx->newidle_cost[NEWIDLE_LLC]) {
		__sync_fetch_and_add(&nr_newidle_skips, 1);
		return false;
	}

	if (nr_place_tiers > 1 &&
	    (!smt_enabled || core_is_idle(dst_cid))) {
		u32 t;

		/* Less-preferred tiers first, from the last, leaving hot tasks alone. */
		bpf_arena_for(t, 0, nr_place_tiers - topo->place_tier - 1) {
			src = steal_from_range(dst_cid, nr_place_tiers - 1 - t, node_base,
					       node_nr, node_base, now,
					       !force_steal &&
					       failed <= cache_nice_tries,
					       0xff);
			if (src >= 0) {
				cctx->nr_balance_failed = 0;
				goto pick;
			}
		}
	}

	/*
	 * An idle cid walks its own LLC before the rest of the node and then
	 * the system, honouring hotness until it has failed often enough to
	 * stop. With NUMA disabled the node level covers the whole machine.
	 * A domain that is the whole of the next one is not walked twice.
	 */
	src = steal_from_range(dst_cid, -1, topo->llc_base, topo->llc_nr,
			       start + 1, now,
			       !force_steal && failed <= cache_nice_tries,
			       0xff);
	if (budget) {
		u64 t1 = bpf_ktime_get_ns();

		curr_cost = t1 - t0;
		update_newidle_cost(cctx, NEWIDLE_LLC, curr_cost, t1);
		t0 = t1;
		if (node_nr > topo->llc_nr)
			node_skipped = cctx->avg_idle <
				       curr_cost + cctx->newidle_cost[NEWIDLE_NODE];
	}
	if (src < 0 && node_nr > topo->llc_nr && !node_skipped) {
		src = steal_from_range(dst_cid, -1, node_base, node_nr,
				       start + 1, now,
				       !force_steal &&
				       failed <= cache_nice_tries + 1,
				       0xff);
		if (budget) {
			u64 t1 = bpf_ktime_get_ns(), cost = t1 - t0;

			curr_cost += cost;
			update_newidle_cost(cctx, NEWIDLE_NODE, cost, t1);
			t0 = t1;
		}
	}
	if (budget && nr_cids > node_nr)
		system_skipped = node_skipped ||
			cctx->avg_idle <
			curr_cost + cctx->newidle_cost[NEWIDLE_SYSTEM];
	if (src < 0 && nr_cids > node_nr && !system_skipped) {
		src = steal_from_range(dst_cid, -1, 0, nr_cids,
				       start + 1, now,
				       !force_steal &&
				       failed <= cache_nice_tries + 2,
				       0xff);
		if (budget) {
			u64 t1 = bpf_ktime_get_ns(), cost = t1 - t0;

			curr_cost += cost;
			update_newidle_cost(cctx, NEWIDLE_SYSTEM, cost, t1);
		}
	}
	if (curr_cost > cctx->max_idle_balance_cost)
		cctx->max_idle_balance_cost = curr_cost;

	/* Nothing queued anywhere is a balanced system, not a failure. */
	if (src >= 0 || cmask_empty(queued_cids))
		cctx->nr_balance_failed = 0;
	else
		cctx->nr_balance_failed = failed + 1;
	cctx->steal_cursor = src >= 0 ? src : start + 1;

own:
	if (src < 0 && own)
		src = dst_cid;

pick:
	if (src < 0)
		return false;

	/* Remote scans already validated, removed and dispatched one node. */
	if (src == dst_cid) {
		if (!((src == dst_cid && !no_eligible_scan && !no_eligibility) ?
		      move_first_eligible_to_local(src, cid_clock_task_at(src, now)) :
		      cid_queue_move_head_to_local(src))) {
			cid_queued_check(src);
			return false;
		}
	}
	cid_queued_check(src);

	if (src != dst_cid)
		__sync_fetch_and_add(&nr_steals, 1);

	return true;
}

/*
 * Re-arm the idle bit of @cid from the tail of ops.dispatch().
 *
 * A separate function on purpose. Inlined at the tail, the fetching add
 * that moves the bit faulted on an unmapped arena page, with a valid cid
 * and a 32-bit offset that the instructions before it leave no room to
 * be wrong; the fault is silently dropped by the kernel and the cid is
 * then never seen idle again. In a function of its own, with its own
 * setup of the arena base, it does not fault.
 */
__noinline int cid_idle_rearm(s32 cid)
{
	TOUCH_ARENA();

	cid_idle_set(cid);

	return 0;
}

/*
 * Move a task from the bounded deadline-ordered prefix of @src_cid selected by
 * periodic busy balance for @dst_cid, but only once it is the task @dst_cid
 * would pick.
 *
 * attach_task() does not run what it pulls: it enqueues it and lets
 * wakeup_preempt() decide, and pick_eevdf() then runs it only once it is
 * the eligible task with the earliest deadline, the running one and the
 * queued ones included. A task on LOCAL runs before either here, so the
 * pick is taken before the move instead. The task is placed the way
 * ops.running() will place it, at the lag it carries from its pack, with
 * the relative deadline it was queued with, and compared with what
 * keep_running() would keep and with this cid's queue head. With nothing
 * eligible to compete against, the pull wins.
 *
 * Return 1 when the task moved, 0 when the selection is gone, and -EAGAIN
 * when it stands but would not be the pick yet.
 */
static __noinline int
busy_balance_move_to_local(s32 dst_cid, s32 src_cid, bool has_prev,
			   u64 now, u64 tnow)
{
	struct cid_ctx __arena *dst = cid_ctx(dst_cid);
	u64 rival_dl = 0, head_dl = 0;
	bool rival = false;
	bool retry = false;
	u32 nth;

	if (has_prev && curr_pick_dl(cid_pack(dst_cid), tnow, &rival_dl))
		rival = true;
	if (cid_queued_test(dst_cid) &&
	    !scx_edq_first_deadline(&dst->pack.edq, &head_dl) &&
	    (!rival || time_before(head_dl, rival_dl))) {
		rival_dl = head_dl;
		rival = true;
	}
	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		struct task_struct *p;
		s64 lag;
		u64 dl, v, weight;
		int ret;

		ret = cid_edq_try_peek_nth(src_cid, nth, &at);
		if (ret)
			return ret == -EBUSY ? -EAGAIN : 0;
		if (!at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		weight = ((task_ctx_t *)at)->se.vjoin_w;
		if (READ_ONCE(at->state) != CID_EDQ_ENQUEUED ||
		    weight > READ_ONCE(dst->busy_balance_budget) ||
		    task_hot((task_ctx_t *)at, src_cid, dst_cid, now)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		p = scx_bpf_tid_to_task(at->tid);
		if (!p || !cid_allowed(p, dst_cid)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		lag = task_lag_at(p, (task_ctx_t *)at,
				  task_pack((task_ctx_t *)at, src_cid), now);
		v = pack_vref_place(task_pack((task_ctx_t *)at, dst_cid), tnow) - lag;
		dl = v + (at->common.node.deadline -
			  at->common.node.eligibility);
		if (rival && ((!no_eligibility && lag < 0) ||
			      !time_before(dl, rival_dl))) {
			retry = true;
			scx_edq_task_drop(&at->common);
			continue;
		}
		ret = cid_edq_remove_held_to_local(src_cid, dst_cid, at, p);
		if (ret == CID_EDQ_MOVE_BUSY)
			return -EAGAIN;
		if (ret != CID_EDQ_MOVE_MOVED)
			continue;
		dst->busy_balance_budget -= weight;
		return 1;
	}

	return retry ? -EAGAIN : 0;
}

void BPF_STRUCT_OPS(cidland_dispatch, s32 cid, struct task_struct *prev)
{
	bool has_prev, keep = false, active_balance = false;
	s32 migrate_cid = -EBUSY, busy_cid;
	u64 now, tnow;

	TOUCH_ARENA();

	if (!cid_valid(cid))
		return;
	now = scx_bpf_now();
	tnow = cid_clock_task_owned(cid, now);

	/*
	 * Take a task from this cid's queue or from a deeper one on the
	 * node, then fall back to this cid's own EDQ in case the pick raced
	 * with another cid. An idle cid that failed to pull queued work may have
	 * requested this running task through asymmetric active balance. Consume
	 * and validate that one destination before renewing the task; otherwise
	 * ask the task for this CPU again, see keep_running().
	 */
	has_prev = prev && is_task_queued(prev);
	if (READ_ONCE(cid_ctx(cid)->active_balance_pending) == 2 &&
	    __sync_val_compare_and_swap(&cid_ctx(cid)->active_balance_pending,
					    2, 0) == 2) {
		if (has_prev)
			active_balance_complete(cid, ACTIVE_BALANCE_MISS);
		else
			active_balance = true;
	}
	if (has_prev) {
		migrate_cid = active_balance_target(prev, cid, now);
		if (migrate_cid >= 0) {
			task_ctx_t *tctx = try_lookup_task_ctx(prev);

			if (tctx)
				tctx->dispatch_migrate_cid = migrate_cid;
			else
				migrate_cid = -EBUSY;
		}
		if (migrate_cid < 0)
			keep = keep_running(cid, tnow);
	}

	/*
	 * A periodic tick selected this source and an amount of load to move
	 * while it observed an averaged imbalance. At each natural scheduling
	 * boundary, revalidate and remove the exact head under the EDQ lock once
	 * it is the task this cid would pick, see busy_balance_move_to_local().
	 * Enqueue puts @prev back after this callback when the pulled task wins.
	 * A task that is not the pick yet, and a batch with load left to move,
	 * are kept for a later boundary until the original selection expires.
	 */
	busy_cid = READ_ONCE(cid_ctx(cid)->busy_balance_cid);
	if (busy_cid >= 0 &&
	    !time_before(now, READ_ONCE(cid_ctx(cid)->busy_balance_expire))) {
		if (__sync_val_compare_and_swap(&cid_ctx(cid)->busy_balance_cid,
						busy_cid, -1) == busy_cid)
			cid_queued_check(busy_cid);
		busy_cid = -1;
	}
	if (busy_cid >= 0 &&
	    __sync_val_compare_and_swap(&cid_ctx(cid)->busy_balance_cid,
					busy_cid, -1) == busy_cid) {
		int moved;

		if (has_prev)
			WRITE_ONCE(cid_ctx(cid)->requeue_pending, 1);
		moved = busy_balance_move_to_local(cid, busy_cid, has_prev,
						   now, tnow);
		if (moved > 0) {
			cid_queued_check(busy_cid);
			/* Drain no more than the imbalance calculated by the tick. */
			if (READ_ONCE(cid_ctx(cid)->busy_balance_budget) &&
			    cid_queued_test(busy_cid) &&
			    time_before(now,
					READ_ONCE(cid_ctx(cid)->busy_balance_expire)))
				__sync_val_compare_and_swap(
					&cid_ctx(cid)->busy_balance_cid,
					-1, busy_cid);
			__sync_fetch_and_add(&nr_steals, 1);
			__sync_fetch_and_add(&nr_busy_balances, 1);
			/*
			 * The destination found work before asking for a
			 * running task, as the pulls below would have.
			 */
			if (active_balance)
				active_balance_complete(cid, ACTIVE_BALANCE_MOVED);
			return;
		}
		if (has_prev)
			WRITE_ONCE(cid_ctx(cid)->requeue_pending, 0);
		if (moved == -EAGAIN &&
		    time_before(now, READ_ONCE(cid_ctx(cid)->busy_balance_expire)))
			__sync_val_compare_and_swap(&cid_ctx(cid)->busy_balance_cid,
						    -1, busy_cid);
		else
			cid_queued_check(busy_cid);
	}

	/*
	 * If the hand-over below takes the queue's head, @prev is enqueued
	 * back here right after this op returns: tell cid_queued_check()
	 * not to clear the queued bit in between, see there.
	 */
	if (has_prev && !keep)
		WRITE_ONCE(cid_ctx(cid)->requeue_pending, 1);
	if (try_steal_task(cid, has_prev, keep, now, active_balance)) {
		if (active_balance)
			active_balance_complete(cid, ACTIVE_BALANCE_MOVED);
		return;
	}
	if (!keep && ((!no_eligible_scan && !no_eligibility) ?
		     move_first_eligible_to_local(cid, tnow) :
		     cid_queue_move_head_to_local(cid))) {
		cid_queued_check(cid);
		if (active_balance)
			active_balance_complete(cid, ACTIVE_BALANCE_MOVED);
		return;
	}

	/*
	 * The task that was running keeps the CPU: either nothing else
	 * wants it, or what does was asked and lost, see keep_running().
	 * Either way it is given another slice to hold it with, and it is
	 * settled with first, whichever of the two it was.
	 *
	 * A task that goes on running with nothing queued behind it is as
	 * much picked again as one that was asked and won: fair.c runs
	 * update_curr() and reissues the deadline at every pick, so a task
	 * alone on its CPU is charged, and protected afresh, once a slice.
	 * Charged only when it stops, a task that ran alone for a second
	 * leaves its pack's reference a second behind, and a task waking
	 * onto that cid is placed against it: it is then owed everything the
	 * running task took while it slept, and runs uncontested until it
	 * has caught up, where place_entity() would have put it at V. A
	 * burst of 20 ms next to a hog, sleeping 20 ms in between, ran its
	 * whole burst in one piece and took 49% of the CPU where fair.c
	 * gives it 33%.
	 */
	if (has_prev) {
		/* Let ops.stopping() charge it and ops.enqueue() perform the handoff. */
		if (migrate_cid >= 0)
			return;
		/* Nothing to hand over: @prev stays, and no requeue follows. */
		WRITE_ONCE(cid_ctx(cid)->requeue_pending, 0);
		keep_charge(prev, cid, tnow);
		scx_bpf_task_set_slice(prev, task_request(prev));
		if (cid_queued_test(cid))
			hrtick_start(cid, tnow);
		return;
	}

	/*
	 * Nothing to run: the CPU is going idle. ops.update_idle() will not
	 * say so if the cid was claimed and kicked for a task that never
	 * came, since there is no transition then, so re-arm the bit here.
	 * Ordinary queued pulling has already failed. Only now ask a source
	 * for its sole running task, as fair.c's active balance does after
	 * detach_tasks() fails.
	 */
	cid_idle_rearm(cid);
	if (active_balance && request_active_balance(cid, now))
		return;
}

void BPF_STRUCT_OPS(cidland_update_idle, s32 cid, bool idle)
{
	TOUCH_ARENA();

	if (idle) {
		cid_idle_set(cid);
		/*
		 * The tick stops with the CPU: record the empty pack now, or the
		 * idle period is averaged in at the weight of the last tick.
		 */
		cid_load_accumulate(cid, scx_bpf_now());
	} else if (cid_valid(cid)) {
		struct cid_ctx __arena *cctx = cid_ctx(cid);

		/*
		 * The bit is usually gone already, claimed by the wakeup
		 * that is bringing the cid back; the period ends here
		 * either way.
		 */
		cid_idle_claim(cid);
		if (cctx->idle_stamp)
			update_avg_idle(cctx, scx_bpf_now());
	}
}

void BPF_STRUCT_OPS(cidland_quiescent, struct task_struct *p, u64 deq_flags)
{
	cid_edq_task_t *at;
	task_ctx_t *tctx;
	pack_t *pk;
	s64 lag;
	u64 now;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	at = cid_edq_task(tctx);
	if (at)
		WRITE_ONCE(at->state, CID_EDQ_NONE);

	now = scx_bpf_now();
	util_est_update(tctx, now);
	if (wa_weight)
		ravg_accumulate_arena(&tctx->runnable_avg, 0, now);

	/*
	 * Remember how far the task is from the reference as it stops being
	 * runnable, clamped both ways, like update_entity_lag():
	 *
	 *	vlag = avg_vruntime(cfs_rq) - se->vruntime;
	 *	se->vlag = clamp(vlag, -limit, limit);
	 *
	 * What is preserved across a sleep is the position relative to the
	 * reference, not the absolute vruntime. Restoring the vruntime
	 * against the reference alone would hand every task that sleeps long
	 * enough the full credit, no matter whether it had earned it.
	 */
	pk = tctx->se.vpack;
	cid = pk ? pk->cid : scx_bpf_task_cid(p);
	if (cid_valid(cid)) {
		if (!pk)
			pk = task_pack(tctx, cid);
		/*
		 * update_curr() first: dequeue_entity() charges the service
		 * the task has taken before it measures the lag, and this op
		 * runs before ops.stopping() does the charging here. Without
		 * it the lag is taken against a reference that has the last
		 * run projected in, from a vruntime that has not, and comes
		 * out too generous by that run. The charge is real and once;
		 * ops.stopping() finds nothing left to add.
		 */
		if (scx_bpf_task_running(p) && cid == scx_bpf_task_cid(p))
			keep_charge(p, cid, cid_clock_task_owned(cid, now));
		lag = task_lag_at(p, tctx, pk, now);
		tctx->se.vlag = lag;
	}
	vref_leave(&tctx->se);

	/*
	 * A task that blocks over-served is what fair.c keeps in the tree,
	 *
	 *	if (sched_feat(DELAY_DEQUEUE) && delay &&
	 *	    !entity_eligible(cfs_rq, se)) {
	 *		...
	 *		set_delayed(se);
	 *		return false;
	 *	}
	 *
	 * and only for a sleep: a task dequeued for a change of its
	 * parameters is put straight back. Remember what is needed to pay
	 * the debt off with the pack's progress when the task returns, see
	 * delay_settle(). The reference is read after the task has left,
	 * since that is the value that goes on moving.
	 */
	if (!no_delay_dequeue && (deq_flags & SCX_DEQ_SLEEP) && lag < 0 &&
	    pk) {
		tctx->delay_cid = cid;
		tctx->delay_vref = pk->vref;
		tctx->delay_w = pk->vsum_w;
		tctx->delay_gen = pk->empty_gen;
	}
}

void BPF_STRUCT_OPS(cidland_runnable, struct task_struct *p, u64 enq_flags)
{
	task_ctx_t *tctx;
	bool direct_placed;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	direct_placed = tctx->direct_placed;
	tctx->direct_placed = false;
	cgw_refresh(p, tctx);
	if (wa_weight)
		ravg_accumulate_arena(&tctx->runnable_avg, 1, scx_bpf_now());

	/*
	 * Drop out of the pack the task was last a member of. The lag it
	 * carries is what survives the sleep, and place_task() spends it
	 * against the cid the task is about to be queued on, the way
	 * place_entity() does:
	 *
	 *	se->vruntime = vruntime - lag;
	 *
	 * A task that had consumed its share before sleeping comes back
	 * with no credit, while one that was still owed service keeps it.
	 */
	if (!direct_placed)
		vref_leave(&tctx->se);
}

void BPF_STRUCT_OPS(cidland_running, struct task_struct *p)
{
	task_ctx_t *tctx;
	u64 now;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	cid = scx_bpf_task_cid(p);

	/*
	 * The stamp the service is charged from is in the task clock,
	 * update_curr(); the running averages are fractions of wall time
	 * and follow the rq clock, which a task carries across CPUs.
	 */
	now = scx_bpf_now();
	tctx->last_run_at = cid_valid(cid) ? cid_clock_task_owned(cid, now) : now;
	util_set_running(tctx, true, now);
	cid_util_set_running(cid, true, now);
	cid_load_update(cid, now);

	/*
	 * A task that was moved here from another cid's queue, by the
	 * balancer or an idle pull, carries a vruntime that means nothing
	 * against this cid's pack: taken from a pack that was far ahead it
	 * would wait here until the pack climbs past it, seconds under
	 * load. Carry the lag instead, the way a migration does in
	 * place_entity(): how far the task was from the pack it left is how
	 * far it is placed from the pack it joins.
	 */
	if (tctx->se.vpack && cid_valid(cid) &&
	    tctx->se.vpack != task_pack(tctx, cid)) {
		s64 lag = task_lag_at(p, tctx, tctx->se.vpack, now);

		set_vruntime(&tctx->se,
			     pack_vref_place(task_pack(tctx, cid),
					     tctx->last_run_at) - lag,
			     false);
	}

	/*
	 * After the lag has been carried, which reads the pack the task is
	 * leaving, and before the join that snapshots what it weighs.
	 */
	cgw_refresh(p, tctx);
	task_vref_join(cid, p, tctx);

	/*
	 * Publish what this cid is running. A task queued here later is
	 * compared against that deadline to decide whether it is worth
	 * interrupting, see kick_queued_cid().
	 */
	if (cid_valid(cid)) {
		struct cid_ctx __arena *cctx = cid_ctx(cid);
		pack_t *pk = task_pack(tctx, cid);

		pk->curr_dl = task_dl(p, tctx);
		pk->curr_v = tctx->se.vruntime;
		pk->curr_run_at = tctx->last_run_at;
		pk->curr_since = tctx->last_run_at;
		pk->curr_request = task_request(p);
		pk->curr_w = task_weight(p, tctx);
		cctx->curr_idle = p->policy == SCHED_IDLE;

		/*
		 * A pick with company is given an hrtick, set_next_task_fair():
		 *
		 *	if (hrtick_enabled_fair(rq))
		 *		hrtick_start_fair(rq, p);
		 */
		if (cid_queued_test(cid))
			hrtick_start(cid, tctx->last_run_at);
	}

	/*
	 * Refresh cpufreq performance level.
	 */
	update_cpufreq(cid, now);
}

void BPF_STRUCT_OPS(cidland_stopping, struct task_struct *p, bool runnable)
{
	task_ctx_t *tctx;
	u64 slice, tnow;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	cid = scx_bpf_task_cid(p);

	/*
	 * Evaluate the used time slice.
	 */
	/*
	 * The service is charged in the task clock, update_curr(); the stop
	 * stamp cache hotness reads from other CPUs stays on the rq clock.
	 */
	tctx->last_stop_at = scx_bpf_now();
	tnow = cid_valid(cid) ? cid_clock_task_owned(cid, tctx->last_stop_at) :
			       tctx->last_stop_at;
	slice = tnow - tctx->last_run_at;
	util_set_running(tctx, false, tctx->last_stop_at);
	cid_util_set_running(cid, false, tctx->last_stop_at);
	cid_load_update(cid, tctx->last_stop_at);

	/*
	 * The runtime is charged as wall-clock time whatever the CPU it was
	 * spent on. Charging a slow CPU at a discount reads fair, but with
	 * one system-wide reference it isn't: the tasks on the slow CPUs
	 * drift below V without bound while the reference follows the
	 * average, their keys keep getting earlier, and a task waking up on
	 * a slow CPU, placed at V minus a bounded lag, sorts behind all of
	 * them and waits until their vruntime has climbed past it, hundreds
	 * of milliseconds after a second of load. EEVDF charges wall-clock
	 * time and uses the capacity only to balance the load.
	 *
	 * Charge the service just consumed to the task's vruntime, the way
	 * update_curr() does:
	 *
	 *	se->vruntime += calc_delta_fair(delta_exec, se);
	 */
	tctx->se.vruntime += calc_delta_fair(p, tctx, slice);
	vref_charge(&tctx->se);

	/*
	 * The service just charged is in the reference for real now, so
	 * there is nothing left for pack_vref_at() to project on this cid
	 * until ops.running() picks the next task.
	 */
	if (cid_valid(cid))
		task_pack(tctx, cid)->curr_w = 0;

	/*
	 * Update per-cid statistics.
	 */
}

void BPF_STRUCT_OPS(cidland_enable, struct task_struct *p)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	s32 cid = scx_bpf_task_cid(p);

	TOUCH_ARENA();

	if (tctx) {
		scx_bpf_task_set_dsq_vtime(p, (u64)tctx);
		/*
		 * ops.enable() is also called when a task switches back from a
		 * higher scheduling class at run time. Place it at the current
		 * pack reference instead of at the zero used during scheduler
		 * startup; an old pack may have advanced arbitrarily far by then.
		 */
		tctx->se.vruntime = cid_valid(cid) ?
				    pack_vref(task_pack(tctx, cid)) : 0;
		tctx->se.vlag = 0;
		tctx->se.deadline = 0;
		tctx->se.vpack = NULL;
		tctx->delay_cid = -1;
		tctx->recent_used_cid = -1;
		tctx->dispatch_migrate_cid = -1;
		tctx->direct_placed = false;
	}
}

/*
 * The task's weight changed: a nice level, or a policy switched to or from
 * SCHED_IDLE. set_load_weight() gets here through reweight_task_scx() for
 * the sched_ext class as it gets to reweight_task_fair() for the fair
 * class, from inside the dequeue and enqueue set_user_nice() and
 * __setscheduler_params() wrap the change in, with the new static_prio
 * and policy already written, which is what task_weight() reads. @weight
 * itself is on the cgroup scale and too coarse at the light end, see
 * task_weight().
 *
 * A task that was on the runqueue has been dequeued for this, running or
 * not: enqueue_task_scx() sends a restored curr straight to the local
 * queue, so for a running task this is the only callback between the
 * dequeue and ops.running() that sees the change at all. A sleeping task
 * was not dequeued and is only rescaled.
 */
void BPF_STRUCT_OPS(cidland_set_weight, struct task_struct *p, u32 weight)
{
	task_ctx_t *tctx;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	reweight_task(p, tctx, p->on_rq);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cidland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx_ref *ref;
	cid_edq_task_t *at;
	task_ctx_t *tctx;

	ref = bpf_task_storage_get(&task_ctx_stor, p, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ref)
		return -ENOMEM;
	tctx = scx_alloc(&task_ctx_allocator);
	if (!tctx)
		return -ENOMEM;
	at = &tctx->se.edq;
	/*
	 * No memset: LLVM 19 expands one on arena memory through the uncast
	 * pointer and the verifier rejects the program, see
	 * scx_edq_task_init(). Adjacent zero stores can be folded into the
	 * same thing, hence WRITE_ONCE for the two that are.
	 */
	scx_edq_task_init(&at->common);
	at->tid = p->scx.tid;
	at->cid = -1;
	at->state = CID_EDQ_NONE;
	WRITE_ONCE(at->slice, 0);
	WRITE_ONCE(at->enq_flags, 0);
	WRITE_ONCE(tctx->se.vpack, NULL);
	tctx->delay_cid = -1;
	tctx->recent_used_cid = -1;
	tctx->se.vw = task_weight(p, tctx);

	/*
	 * @fork tells a task that is being created apart from one that was
	 * already running when the scheduler was loaded, which is the
	 * distinction ENQUEUE_INITIAL draws: wake_up_new_task() sets it and
	 * nothing else does, see task_dl().
	 */
	tctx->initial = args->fork;
	ref->tctx = tctx;

	return 0;
}

void BPF_STRUCT_OPS(cidland_dequeue, struct task_struct *p, u64 deq_flags)
{
	cid_edq_task_t *at;
	task_ctx_t *tctx;
	u32 state;
	s32 cid;
	int ret;

	TOUCH_ARENA();
	tctx = try_lookup_task_ctx(p);
	at = cid_edq_task(tctx);
	if (!at)
		return;
	cid = at->cid;
	state = READ_ONCE(at->state);
	if (deq_flags & SCX_DEQ_SCHED_CHANGE) {
		/*
		 * A property change ends this enqueue workflow. Publish NONE before
		 * unlinking so a concurrent pop cannot dispatch the old workflow.
		 * Its held intrusive node prevents a later enqueue from reusing the
		 * queue entry until that pop drops its reference.
		 */
		WRITE_ONCE(at->state, CID_EDQ_NONE);
	} else if (state == CID_EDQ_ENQUEUED ||
		   state == CID_EDQ_DISPATCHING) {
		/* The task is leaving BPF custody for a terminal DSQ or execution. */
		WRITE_ONCE(at->state, CID_EDQ_DISPATCHED);
	}
	ret = scx_edq_task_fini(&at->common);
	if (ret < 0) {
		scx_bpf_error("EDQ dequeue failed for pid %d: %d", p->pid, ret);
		return;
	}
	if (ret > 0)
		cid_queued_check(cid);
}

void BPF_STRUCT_OPS(cidland_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx_ref *ref;
	task_ctx_t *tctx;
	int ret;

	TOUCH_ARENA();
	ref = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!ref || !ref->tctx)
		return;
	tctx = ref->tctx;
	ref->tctx = NULL;
	ret = scx_edq_task_detach(&tctx->se.edq.common);
	if (ret) {
		scx_bpf_error("EDQ detach failed for pid %d: %d", p->pid, ret);
		return;
	}
	scx_free(&task_ctx_allocator, tctx);
}

/*
 * A cgroup the cpu controller is putting under this scheduler, either one
 * that already existed when it was loaded or one just created.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(cidland_cpuctl_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgc)
		return -ENOMEM;

	cgc->weight = args->weight;
	cgc->gen = 0;

	return 0;
}

/*
 * Somebody wrote cpu.weight. The weight of every cgroup under @cgrp
 * changed with it and there is no walking down to them from here, so
 * expire every composed weight at once, see cgrp_weight().
 */
void BPF_STRUCT_OPS(cidland_cpuctl_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgrp_ctx *cgc;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc)
		return;

	cgc->weight = weight;
	__sync_fetch_and_add(&cgrp_gen, 1);
}

/*
 * @p is now in another cgroup, so what it carries is no longer its
 * weight. The task is dequeued here; the copy is taken again the next
 * time it is placed, see cgw_refresh().
 */
void BPF_STRUCT_OPS(cidland_cpuctl_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);

	if (tctx)
		tctx->cgw_gen = 0;
}

/*
 * Fill the topology of every cid.
 *
 * Cids are assigned in topological order (node, then LLC, then core), so
 * the cids of a core, an LLC or a node are always contiguous. Walking the
 * cid space backwards means the highest cid of a range is visited first,
 * which is enough to derive the length of the range from its base, the
 * cid scx_bpf_cid_topo() reports for the domain.
 */
static void init_topology(void)
{
	s32 cur_core = -1, cur_llc = -1, cur_node = -1;
	u32 core_nr = 0, llc_nr = 0, node_nr = 0;
	u32 i;

	bpf_arena_for(i, 0, nr_cids) {
		struct scx_cid_topo *ct = &init_topo;
		s32 cid = nr_cids - 1 - i;
		struct cid_topo __arena *topo = cid_topo(cid);
		s32 cpu = scx_bpf_cid_to_cpu(cid);

		cid_ctx(cid)->busy_balance_cid = -1;
		cid_pack(cid)->cid = cid;
		cid_ctx(cid)->active_balance_cid = -1;

		scx_bpf_cid_topo(cid, ct);

		topo->cpu = cpu >= 0 ? cpu : 0;
		if (cpu >= 0 && (u32)cpu < nr_cpu_ids) {
			topo->cap = cpu_cap_in[cpu];
			topo->place_tier = cpu_place_tier_in[cpu];
			topo->capacity_tier = cpu_capacity_tier_in[cpu];
			topo->smt_asym_packing = cpu_smt_asym_in[cpu];
		} else {
			topo->cap = 1;
			topo->place_tier = nr_place_tiers - 1;
			topo->capacity_tier = nr_capacity_tiers - 1;
			topo->smt_asym_packing = 0;
		}

		/*
		 * A cid without topology (a CPU that was offline when the
		 * cid space was built) is a core, an LLC and a node of its
		 * own.
		 */
		if (ct->core_cid < 0 || ct->llc_cid < 0 || ct->node_cid < 0) {
			topo->core_base = cid;
			topo->core_nr = 1;
			topo->llc_base = cid;
			topo->llc_nr = 1;
			topo->node_base = cid;
			topo->node_nr = 1;
			continue;
		}

		if (ct->core_cid != cur_core) {
			cur_core = ct->core_cid;
			core_nr = cid + 1 - ct->core_cid;
		}
		if (ct->llc_cid != cur_llc) {
			cur_llc = ct->llc_cid;
			llc_nr = cid + 1 - ct->llc_cid;
		}
		if (ct->node_cid != cur_node) {
			cur_node = ct->node_cid;
			node_nr = cid + 1 - ct->node_cid;
		}

		topo->core_base = smt_enabled ? ct->core_cid : cid;
		topo->core_nr = smt_enabled ? core_nr : 1;
		topo->llc_base = ct->llc_cid;
		topo->llc_nr = llc_nr;
		topo->node_base = ct->node_cid;
		topo->node_nr = node_nr;
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cidland_init)
{
	struct hrtick *ht;
	u32 cid;
	int err;

	TOUCH_ARENA();

	if (!nr_cids_max) {
		scx_bpf_error("cidland_arena_init() didn't run");
		return -EINVAL;
	}

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * The cids of the CPUs that were online when the cid space was
	 * built come first, [0, nr_online_cids), and are the ones this
	 * scheduler schedules on. The kernel restarts the scheduler on
	 * hotplug, so the range is fixed for the lifetime of this instance.
	 */
	nr_cids = scx_bpf_nr_online_cids();
	if (!nr_cids || nr_cids > nr_cids_max || nr_cpu_ids > nr_cids_max) {
		scx_bpf_error("cid space out of the allocated range: %u cids, %u cpu ids, sized for %u",
			      nr_cids, nr_cpu_ids, nr_cids_max);
		return -E2BIG;
	}

	/*
	 * Frame the masks over the cid space, with the helpers, before any
	 * bit is set.
	 */
	cmask_init(idle_cids, 0, nr_cids);
	cmask_init(idle_core_llcs, 0, nr_cids);
	cmask_init(queued_cids, 0, nr_cids);
	bpf_arena_for(cid, 0, nr_place_tiers)
		cmask_init(place_tier_mask(cid), 0, nr_cids);
	bpf_arena_for(cid, 0, nr_capacity_tiers)
		cmask_init(capacity_tier_mask(cid), 0, nr_cids);

	nr_words = cmask_nr_words(idle_cids);

	init_topology();

	/* sched_init(): the idle pull budget starts open by a migration cost. */
	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_ctx __arena *cctx = cid_ctx(cid);

		cctx->avg_idle = 2 * migration_cost_ns;
		cctx->max_idle_balance_cost = migration_cost_ns;
	}

	/*
	 * fair.c compares an asymmetric scheduling group by its preferred CPU.
	 * The LLC is the child group of the package-level packing domain on the
	 * topologies cidland models, so cache its best tier for parent-domain
	 * source and destination comparisons.
	 */
	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_topo __arena *topo = cid_topo(cid);
		u32 best = nr_place_tiers - 1;
		u32 i;

		bpf_arena_for(i, 0, topo->llc_nr)
			best = MIN(best,
				   cid_topo(topo->llc_base + i)->place_tier);
		topo->llc_place_tier = best;
	}

	/*
	 * Build the packing- and capacity-tier bitmaps and start with every cid
	 * idle, the way the kernel resets its own
	 * idle masks: a CPU that is busy clears its bit as soon as a task
	 * runs there, while a CPU that sits idle from the start never
	 * transitions, and left with its bit clear it would never be
	 * picked, so never transition, for good.
	 */
	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_topo __arena *topo = cid_topo(cid);

		if (topo->place_tier >= nr_place_tiers)
			topo->place_tier = nr_place_tiers - 1;
		if (topo->capacity_tier >= nr_capacity_tiers)
			topo->capacity_tier = nr_capacity_tiers - 1;
		__cmask_set(cid, place_tier_mask(topo->place_tier));
		__cmask_set(cid, capacity_tier_mask(topo->capacity_tier));

		cid_idle_set(cid);

		ht = bpf_map_lookup_elem(&hrticks, &cid);
		if (!ht) {
			scx_bpf_error("no hrtick for cid %d", cid);
			return -ENOENT;
		}
		err = bpf_timer_init(&ht->timer, &hrticks, CLOCK_MONOTONIC);
		if (!err)
			err = bpf_timer_set_callback(&ht->timer, hrtick_fire);
		if (err) {
			scx_bpf_error("failed to set up the hrtick of cid %d: %d", cid, err);
			return err;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(cidland_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Carve @bytes out of the arena pages, @align aligned.
 */
static char __arena *arena_base;
static u64 arena_off, arena_size;

static void __arena *arena_carve(u64 bytes, u64 align)
{
	u64 off = (arena_off + align - 1) & ~(align - 1);

	if (off + bytes > arena_size)
		return NULL;
	arena_off = off + bytes;

	return (void __arena *)(arena_base + off);
}

/*
 * Size the arena for a cid space of @args->nr_cpus and
 * @args->nr_place_tiers packing tiers and @args->nr_capacity_tiers capacity
 * tiers, and carve the tables out of it.
 *
 * Run by user space after load and before attach: the tables have to be
 * in place before ops.init(), and the cid space, num_possible_cpus()
 * wide, is known before the scheduler is.
 */
SEC("syscall")
int cidland_arena_init(struct cidland_arena_args *args)
{
	u64 nr = args->nr_cpus, mask, bytes, pages;
	int ret;

	if (!nr || !args->nr_place_tiers || !args->nr_capacity_tiers)
		return -EINVAL;

	/*
	 * A cmask over the whole cid space, cache line aligned: the helpers
	 * ask for a word past the bits, see CMASK_NR_WORDS().
	 */
	mask = (sizeof(struct scx_cmask) + (u64)CMASK_NR_WORDS(nr) * sizeof(u64) + 63) & ~63ULL;
	bytes = nr * sizeof(struct cid_topo) + nr * sizeof(struct cid_ctx) +
		(3 + args->nr_place_tiers + args->nr_capacity_tiers) * mask +
		nr * (sizeof(u64) + 3 * sizeof(u32)) + 9 * 64;
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	arena_base = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!arena_base)
		return -ENOMEM;
	arena_size = pages * PAGE_SIZE;
	arena_off = 0;

	topos = arena_carve(nr * sizeof(struct cid_topo), 64);
	cctxs = arena_carve(nr * sizeof(struct cid_ctx), 64);
	idle_cids = arena_carve(mask, 64);
	idle_core_llcs = arena_carve(mask, 64);
	queued_cids = arena_carve(mask, 64);
	place_tier_stride = mask;
	place_tier_cids = arena_carve(args->nr_place_tiers * mask, 64);
	capacity_tier_stride = mask;
	capacity_tier_cids = arena_carve(args->nr_capacity_tiers * mask, 64);
	cpu_cap_in = arena_carve(nr * sizeof(u64), 64);
	cpu_place_tier_in = arena_carve(nr * sizeof(u32), 64);
	cpu_capacity_tier_in = arena_carve(nr * sizeof(u32), 64);
	cpu_smt_asym_in = arena_carve(nr * sizeof(u32), 64);
	if (!topos || !cctxs || !idle_cids || !idle_core_llcs || !queued_cids ||
	    !place_tier_cids || !capacity_tier_cids || !cpu_cap_in ||
	    !cpu_place_tier_in || !cpu_capacity_tier_in || !cpu_smt_asym_in)
		return -ENOMEM;
	ret = scx_alloc_init(&task_ctx_allocator, sizeof(struct task_ctx),
			     __alignof__(struct task_ctx));
	if (ret)
		return ret;

	nr_cids_max = nr;
	nr_place_tiers = args->nr_place_tiers;
	nr_capacity_tiers = args->nr_capacity_tiers;
	asym_capacity = args->asym_capacity;
	asym_packing = args->asym_packing;

	return 0;
}

/*
 * Report the capacity and its independent packing and capacity tiers in CPU
 * space. The cid layout is only known once the kernel has built it, so
 * ops.init() translates.
 */
SEC("syscall")
int cidland_set_cpu(struct cidland_cpu_args *args)
{
	u64 cpu = args->cpu;

	TOUCH_ARENA();

	if (!cpu_cap_in || cpu >= nr_cids_max ||
	    args->place_tier >= nr_place_tiers ||
	    args->capacity_tier >= nr_capacity_tiers)
		return -EINVAL;

	cpu_cap_in[cpu] = args->capacity;
	cpu_place_tier_in[cpu] = args->place_tier;
	cpu_capacity_tier_in[cpu] = args->capacity_tier;
	cpu_smt_asym_in[cpu] = args->smt_asym_packing;

	return 0;
}

/*
 * Return the kernel's live SD_ASYM_PACKING state and
 * arch_asym_cpu_priority() value for one CPU. Reading the per-CPU symbols
 * here avoids treating a hardware performance estimate as scheduler policy.
 */
SEC("syscall")
int cidland_get_cpu_priority(struct cidland_cpu_priority_args *args)
{
	struct sched_domain *sd;
	u64 cpu = args->cpu;
	int priority;

	args->priority = 0;
	args->asym_packing = 0;
	args->smt_asym_packing = 0;
	if (cpu > INT_MAX || !&sched_core_priority || !&sd_asym_packing)
		return 0;

	priority = cpu_priority(cpu);
	sd = cpu_asym_packing_dom(cpu);
	if (priority < 0 || !sd)
		return 0;

	args->priority = priority;
	args->asym_packing = 1;
	bpf_repeat(16) {
		int flags;

		if (!sd)
			break;
		flags = BPF_CORE_READ(sd, flags);
		if ((flags & (SD_SHARE_CPUCAPACITY | SD_ASYM_PACKING)) ==
		    (SD_SHARE_CPUCAPACITY | SD_ASYM_PACKING)) {
			args->smt_asym_packing = 1;
			break;
		}
		sd = BPF_CORE_READ(sd, child);
	}
	return 0;
}

SCX_OPS_CID_DEFINE(cidland_ops,
		   .select_cid		= (void *)cidland_select_cid,
		   .enqueue		= (void *)cidland_enqueue,
		   .dequeue		= (void *)cidland_dequeue,
		   .tick		= (void *)cidland_tick,
		   .yield		= (void *)cidland_yield,
		   .dispatch		= (void *)cidland_dispatch,
		   .runnable		= (void *)cidland_runnable,
		   .quiescent		= (void *)cidland_quiescent,
		   .running		= (void *)cidland_running,
		   .stopping		= (void *)cidland_stopping,
		   .update_idle		= (void *)cidland_update_idle,
		   .enable		= (void *)cidland_enable,
		   .set_weight		= (void *)cidland_set_weight,
		   .init_task		= (void *)cidland_init_task,
		   .exit_task		= (void *)cidland_exit_task,
		   .cpuctl_init		= (void *)cidland_cpuctl_init,
		   .cpuctl_set_weight	= (void *)cidland_cpuctl_set_weight,
		   .cpuctl_move		= (void *)cidland_cpuctl_move,
		   .init		= (void *)cidland_init,
		   .exit		= (void *)cidland_exit,
		   .timeout_ms		= 5000,
		   .name		= "cidland");
