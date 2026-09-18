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
 * Schedule the cpu controller's cgroups as groups, each weighing its
 * cpu.weight against its siblings, the way fair.c's group scheduling does.
 * See struct grp_q. On by default; user space turns it off with
 * --disable-cgroups.
 */
const volatile bool cgroup_enabled;

/*
 * Hold the cgroups of the cpu controller to the bandwidth their cpu.max asks
 * for. Rides on @cgroup_enabled, which is what gives a cgroup the queues the
 * bandwidth is accounted on. Off with --disable-cpu-max.
 */
const volatile bool cpu_max_enabled;

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
 * Sample new-idle scans from their observed success and call rates, fair.c's
 * NI_RANDOM and NI_RATE. On by default; user space clears it for
 * --no-newidle-sampling.
 */
const volatile bool newidle_sampling = true;

/*
 * Bound the ordinary LLC idle scan by its averaged utilization, the way
 * fair.c's SIS_UTIL feature uses sched_domain_shared::nr_idle_scan. The
 * hint is refreshed by periodic load balance, never on the wakeup path.
 *
 * On by default, as the feature is in fair.c. User space clears it for
 * --no-sis-util.
 */
const volatile bool sis_util = true;

/*
 * Extend the idle search past the target's LLC to the node and then the
 * machine. By default, match select_idle_sibling(): give up at sd_llc, leave
 * the task on its affine target, and let load balance spread work across LLCs
 * after weighing the migration cost against the idle time it can use.
 */
const volatile bool llc_extend;

/*
 * Do not interrupt a running task for one that wakes up with an earlier
 * deadline, leaving it to run until its slice ends.
 */
const volatile bool no_wakeup_preempt;

/*
 * Send a wakee to the waking cid when both it and its previous cid are
 * busy and the loads say that leaves the two better balanced, the
 * effective-load comparison of wake_affine_weight(), see
 * wake_affine_weight_cid(). The cid load is sampled from the tick and task
 * load reuses its execution-utilization estimate, so the comparison adds no
 * runnable-state accounting. Enabled by default and disabled with
 * --no-wa-weight on systems where its placement decisions perform worse.
 */
const volatile bool wa_weight;
const volatile u32 busy_balance_factor = 16;
#define BUSY_BALANCE_IMBALANCE_PCT	117U
/* Account for capacity unavailable to sched_ext in periodic busy balance. */
const volatile bool capacity_pressure;
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
 * Not __hot_written: these are touched once per periodic LLC balance, a couple
 * of dozen times a second for the whole machine, so they have no business
 * taking a cache line each the way the per-wakeup counters above do.
 */
volatile u64 nr_sis_updates;
volatile u64 sis_scan_sum;

volatile u64 user_util_sum __hot_written;
volatile u64 user_util_snapshot_at __hot_written;

/*
 * Scheduler's exit status.
 */
UEI_DEFINE(uei);

/*
 * Arena pages in use, counted where they are handed out. Every allocator
 * the BPF side uses, the tables carved at init, the library's static and
 * task context pools, ends in bpf_arena_alloc_pages(), and the kernel only
 * started to account arena pages in the map's memlock in 7.3. Loaded and
 * attached only when the usage is reported, --stats: user space turns
 * them on before load, sets @arena_map_id before the first allocation and
 * reads the two counters. Not a hot path: a page is allocated once and
 * then carved for thousands of objects.
 */
u32 arena_map_id;
u64 arena_pages_allocated;
u64 arena_pages_freed;

static bool arena_is_ours(void *map)
{
	return arena_map_id &&
	       BPF_CORE_READ((struct bpf_map *)map, id) == arena_map_id;
}

SEC("?fexit/bpf_arena_alloc_pages")
int BPF_PROG(cidland_arena_alloc_pages, void *map, void *addr, u32 page_cnt,
	     int node_id, u64 flags, void *ret)
{
	if (ret && arena_is_ours(map))
		__sync_fetch_and_add(&arena_pages_allocated, page_cnt);
	return 0;
}

SEC("?fentry/bpf_arena_free_pages")
int BPF_PROG(cidland_arena_free_pages, void *map, void *ptr, u32 page_cnt)
{
	if (arena_is_ours(map))
		__sync_fetch_and_add(&arena_pages_freed, page_cnt);
	return 0;
}

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
 * Group scheduling, fair.c's with a single runqueue: a cgroup's task on a cid
 * is queued, placed and picked in the cid's own pack beside every other task,
 * at an effective weight that is its share of the hierarchy, and the cgroup
 * hierarchy itself only keeps the weights that share is computed from, see
 * commit 85570f10a4c6 ("sched/eevdf: Move to a single runqueue").
 *
 * One struct grp_q per cgroup per cid, the load of fair.c's cfs_rq of the
 * group: @load is the weight of the group's members on the cid, its tasks at
 * their nice weights and its child groups at their shares, and @contrib is
 * what the group adds to its parent's @load there, its shares while it has
 * any member and nothing otherwise. A task's effective weight is its nice
 * weight scaled by shares / load at every level up to the cid's own,
 * __calc_prop_weight() in enqueue_hierarchy(), see grp_h_weight().
 *
 * A cgroup at the root has no queues, its tasks weigh their nice weights. A
 * cgroup nested deeper than GRP_MAX_DEPTH shares its ancestor's at that depth.
 */
#define GRP_MAX_DEPTH	8

struct grp_hdr {
	u64 weight;		/* cpu.weight as a load weight, tg->shares */
	u64 pages;		/* arena pages of this block */
	u64 load_avg;		/* sum of the queues' averaged loads, tg->load_avg */
	u64 nr_avg;		/* sum of their averaged task counts, tg->runnable_avg */
	u64 idle;		/* cpu.idle, see cidland_cpuctl_set_idle() */
	u64 slot;		/* its index in @grp_hdrs */
	u64 next_free;		/* next block to free, see grp_free_defer() */

	/* cpu.max, see cidland_cpuctl_set_bandwidth() */
	u64 quota;		/* what the group may run for in a period, 0 for no limit */
	u64 period;		/* the period, cfs_bandwidth->period */
	u64 burst;		/* what it may carry into one, cfs_bandwidth->burst */
	u64 period_start;	/* when the period it is in began */
	u64 pool;		/* what is left of its bandwidth in it, cfs_b->runtime */
	u64 throttled;		/* whether it has run out, cfs_rq->throttled */
	u64 throttled_at;	/* when it did */
	u64 throttled_ns;	/* how long it has spent out of bandwidth */
	u64 nr_throttled;	/* how often it has run out */
	u64 bw_gen;		/* bumped when cpu.max changes, see grp_bw_charge() */
	u64 bw_slot;		/* its index in @bw_hdrs, BW_MAX_LIMITED for none */
	u64 nr_parked;		/* tasks waiting in @bq */
	struct scx_edq bq;	/* them, see cid_park() */
};

struct grp_q {
	u64 load;
	u64 contrib;
	u64 shares;		/* the group's weight in its parent on this cid */
	u64 nr;			/* tasks queued in the group or below it on this cid */
	struct grp_q __arena *parent;	/* NULL for a child of the root */
	struct grp_hdr __arena *hdr;
	struct ravg_data load_avg;	/* @load averaged, cfs_rq->avg.load_avg */
	struct ravg_data nr_avg;	/* @nr averaged, cfs_rq->avg.runnable_avg */
	u64 load_avg_contrib;	/* what @hdr->load_avg holds of this queue */
	u64 nr_avg_contrib;	/* what @hdr->nr_avg holds of this queue */
	u64 shares_at;		/* when @shares was last computed */
	s64 runtime_remaining;	/* what the cid holds of the group's bandwidth */
	u64 bw_gen;		/* the cpu.max @runtime_remaining was taken under */
	u32 cid;
	u32 avg_lock;		/* serializes the averages, see grp_avg_trylock() */
};

typedef struct grp_q __arena grp_q_t;

/*
 * A cgroup's block: the header, its queues, one per cid, and a bitmap of the
 * cids whose queue still adds to the per-cgroup sums, see grp_sweep().
 */
static __always_inline grp_q_t *grp_ents(struct grp_hdr __arena *hdr)
{
	return (grp_q_t *)((char __arena *)hdr + sizeof(struct grp_hdr));
}

static __always_inline u64 __arena *grp_live(struct grp_hdr __arena *hdr, u32 nr)
{
	return (u64 __arena *)((char __arena *)grp_ents(hdr) +
			       (u64)nr * sizeof(struct grp_q));
}

/*
 * Per-cgroup context: where the cgroup's queues are. @hdr is NULL when
 * @ents is not the cgroup's own.
 */
struct cgrp_ctx {
	grp_q_t *ents;
	struct grp_hdr __arena *hdr;
	u32 depth;
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
 * The one timer cpu.max needs. A cid with nothing to run never reaches
 * ops.dispatch(), so a group whose tasks are all waiting on a period would
 * wait past the end of it with every CPU asleep and nobody to notice. Armed
 * only while something is waiting, for the first period that ends.
 */
struct bw_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct bw_timer);
	__uint(max_entries, 1);
} bw_timers SEC(".maps");

enum fork_child_level {
	FORK_CHILD_NODE,
	FORK_CHILD_LLC,
	FORK_CHILD_CORE,
};

/* fair.c's usual MC and wider-domain imbalance_pct values. */
#define FORK_MC_IMBALANCE_PCT 117
#define FORK_WIDE_IMBALANCE_PCT 125

/*
 * Scratch for fair.c-style SD_BALANCE_FORK group descent. Keep the loop
 * accumulators in per-CPU map memory rather than on the caller's stack so the
 * verifier can merge loop iterations whose idle branches differ.
 * select_cid() cannot race another invocation on the same CPU.
 */
struct fork_pick_env {
	u64 now;
	u64 load;
	u64 util;
	u64 cap;
	u64 best_load;
	u64 best_util;
	u64 best_cap;
	u64 group_recent;
	u64 best_recent;
	u32 runnable;
	u32 best_runnable;
	u32 best_allowed;
	u32 base;
	u32 nr;
	u32 anchor;
	u32 level;
	u32 group_base;
	u32 group_nr;
	u32 group_end;
	u32 group_allowed;
	u32 restricted;
	u32 idle;
	u32 best_idle;
	u32 best_base;
	u32 best_nr;
	u32 best_local;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct fork_pick_env);
	__uint(max_entries, 1);
} fork_pick_scratch SEC(".maps");

/*
 * Bring what @gq and each group above it add to their parents in line with
 * their loads and shares, the sums of enqueue_hierarchy() and
 * dequeue_hierarchy().
 *
 * The loads are changed from whichever cid a task joins or leaves a pack
 * from, without a lock, so a group's @contrib is moved by compare and swap to
 * what its load says it should be, its delta is applied to the parent, and
 * the group is looked at again before going up: whoever changes a load last
 * also leaves the contributions above it matching.
 */
static void grp_contrib_sync(grp_q_t *gq)
{
	bool moved = false;
	int i;

	for (i = 0; i < 4 * GRP_MAX_DEPTH && gq && gq->parent; i++) {
		grp_q_t *parent = gq->parent;
		u64 load = READ_ONCE(gq->load);
		u64 target = load ? READ_ONCE(gq->shares) : 0;
		u64 cur = READ_ONCE(gq->contrib);

		if (cur != target) {
			if (__sync_val_compare_and_swap(&gq->contrib, cur, target) == cur) {
				__sync_fetch_and_add(&parent->load, target - cur);
				moved = true;
			}
			continue;
		}
		if (!moved)
			break;
		gq = parent;
		moved = false;
	}
}

/*
 * Add @delta to the load of @gq and take the change up the hierarchy.
 */
static void grp_load_add(grp_q_t *gq, s64 delta)
{
	__sync_fetch_and_add(&gq->load, delta);
	grp_contrib_sync(gq);
}

/*
 * Fractional bits the effective weight is carried with down the hierarchy,
 * the precision scale_load() gives fair.c's weights on 64-bit.
 */
#define GRP_WEIGHT_SHIFT	10

/*
 * The effective weight of a member of @gq that weighs @w in it: @w scaled by
 * shares / load at every level, __calc_prop_weight(). With @joining, the
 * weight it will have once it has joined, its own weight and those of the
 * groups that join with it counted in.
 *
 * The product is carried in fixed point and rounded once at the end: truncated
 * at every level, a light task in a large or deep hierarchy loses a unit per
 * level off a weight of a few units. Packs keep whole weights, which are
 * multiplied by vruntime distances, so the result still has a floor of 1
 * where fair.c's has MIN_SHARES of a scaled weight.
 */
static u64 grp_h_weight(grp_q_t *gq, u64 w, bool joining)
{
	u64 add = joining ? w : 0, wf = w << GRP_WEIGHT_SHIFT;
	int i;

	for (i = 0; gq && i < GRP_MAX_DEPTH; i++) {
		u64 shares = READ_ONCE(gq->shares);
		u64 load = READ_ONCE(gq->load) + add;

		add = joining && !READ_ONCE(gq->contrib) ? shares : 0;
		wf = wf * shares / MAX(load, 1ULL);
		gq = gq->parent;
	}

	w = (wf + (1ULL << (GRP_WEIGHT_SHIFT - 1))) >> GRP_WEIGHT_SHIFT;
	return MAX(w, 1ULL);
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
 * pages cidland_arena_init() takes. Arena pointers are not range tracked
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
 * Scratch space for scx_bpf_cid_topo(), only used by ops.init(). It has
 * to be readable as a whole at the call, which stack slots that are never
 * read back are not.
 */
static struct scx_cid_topo init_topo;

/*
 * Translate a kernel sched-domain weight into the smallest enclosing topology
 * range cidland represents. The cid topology has core, LLC, node and system
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
 * Count a task in or out of @gq and every group above it on the cid,
 * cfs_rq->h_nr_runnable.
 */
static void grp_nr_add(grp_q_t *gq, s64 delta)
{
	int i;

	for (i = 0; gq && i < GRP_MAX_DEPTH; i++) {
		__sync_fetch_and_add(&gq->nr, delta);
		gq = gq->parent;
	}
}

/*
 * The smallest weight a group can have on a cid, MIN_SHARES.
 */
#define GRP_MIN_SHARES		2

/*
 * How long the per-cgroup sums are left alone after an update, and by how
 * much a queue's average has to move to update them, update_tg_load_avg().
 */
#define GRP_SUM_NS		1000000ULL

/*
 * The averages of a group queue, what they add to the per-cgroup sums, and its
 * bit in the live bitmap are updated by the cid that owns the queue, from its
 * tick, and by grp_sweep() from whichever cid runs it once the queue has gone
 * quiet. fair.c does both under the runqueue's lock; here the two take the
 * queue's own lock and give way to each other rather than wait: the owner's
 * next tick, or the next sweep, does what one skipped.
 */
static bool grp_avg_trylock(grp_q_t *gq)
{
	return !READ_ONCE(gq->avg_lock) &&
	       __sync_val_compare_and_swap(&gq->avg_lock, 0, 1) == 0;
}

static void grp_avg_unlock(grp_q_t *gq)
{
	__sync_val_compare_and_swap(&gq->avg_lock, 1, 0);
}

/*
 * Every cgroup block, indexed by struct grp_hdr's @slot, for grp_sweep() to
 * walk. Allocated by ops.init(), written by the cgroup ops, which the kernel
 * serializes.
 */
#define GRP_MAX_CGROUPS		16384

static u64 __arena *grp_hdrs;
static u32 grp_hdrs_nr;		/* slots ever used */

static u64 grp_sweep_at __hot_written;
static u32 grp_sweep_lock __hot_written;
static u64 grp_sweep_pos;	/* where grp_sweep() goes on from */
static u64 grp_free_head;	/* blocks waiting to be freed, see grp_free_defer() */

/*
 * How often, and over how many queues at most, grp_sweep() runs.
 */
#define GRP_SWEEP_NS		NSEC_PER_MSEC
#define GRP_SWEEP_BUDGET	64

/*
 * cpu.max, the bandwidth the cpu controller gives a cgroup: the group may run
 * for @quota nanoseconds in every @period, plus what it carried over into the
 * period, up to @burst. A group is held to the limits of every group above it
 * as well as its own, so what binds a task is the tightest of them.
 *
 * Most machines set no limit anywhere. @bw_nr_limited counts the cgroups that
 * carry one, so that everything the accounting adds costs a single load until
 * somebody writes a cpu.max. Written by the cgroup ops, which the kernel
 * serializes; read from everywhere.
 */
#define BW_QUOTA_INF		((u64)~0ULL)	/* cpu.max "max", RUNTIME_INF */

static u64 bw_nr_limited;

/*
 * The cgroups that carry a limit, so that a cid looking for tasks to let run
 * again has a handful of blocks to look at rather than every cgroup on the
 * machine. @bw_parked says which of them have tasks waiting, and is what the
 * search reads; @bw_nr_parked keeps it out of the way entirely while nothing
 * is waiting anywhere.
 *
 * The array is written by the cgroup ops, which the kernel serializes, and a
 * cgroup that finds no free slot is accounted but never throttles: enforcing
 * it would need a slot for its backlog to be found again from.
 *
 * @bw_nr_parked keeps the search out of the way entirely while nothing is
 * waiting anywhere, which is every machine that sets no cpu.max and every
 * moment a group is inside its limit.
 */
#define BW_MAX_LIMITED		1024
#define BW_SLOT_NONE		BW_MAX_LIMITED

static u64 bw_hdrs[BW_MAX_LIMITED];		/* struct grp_hdr __arena * */
static u32 bw_hdrs_nr;				/* slots ever used */
static u64 bw_nr_parked;

/*
 * Whether the cgroup of @hdr carries a cpu.max of its own. A cgroup without
 * one still runs under the limits of the groups above it.
 */
static __always_inline bool grp_bw_limited(struct grp_hdr __arena *hdr)
{
	return READ_ONCE(hdr->quota) != 0;
}

/*
 * Whether a cgroup that runs out of bandwidth can be held to it at all:
 * without a slot among the limited cgroups its backlog could not be found
 * again, and the tasks put in it would wait there for good.
 */
static __always_inline bool grp_bw_enforced(struct grp_hdr __arena *hdr)
{
	return hdr->bw_slot < BW_MAX_LIMITED;
}

static __always_inline bool bw_enabled(void)
{
	return cpu_max_enabled && READ_ONCE(bw_nr_limited);
}

/*
 * What a cid takes from its group's bandwidth at a time, and what it keeps in
 * hand once the group is spent: sysctl_sched_cfs_bandwidth_slice, and the
 * millisecond assign_cfs_rq_runtime() leaves a throttled cfs_rq so that the
 * task on its way out is not charged against the next period.
 */
#define BW_SLICE_NS		(5 * NSEC_PER_MSEC)

/*
 * The group has run out of bandwidth for this period. Its tasks keep running
 * until somebody looks at this, see grp_bw_throttled().
 */
static void grp_bw_throttle(struct grp_hdr __arena *hdr, u64 now)
{
	if (!grp_bw_enforced(hdr) || READ_ONCE(hdr->throttled) ||
	    __sync_val_compare_and_swap(&hdr->throttled, 0, 1) != 0)
		return;

	WRITE_ONCE(hdr->throttled_at, now);
	hdr->nr_throttled++;
}

/*
 * The group has bandwidth again, whether because its period turned over or
 * because somebody widened its cpu.max.
 */
static void grp_bw_unthrottle(struct grp_hdr __arena *hdr, u64 now)
{
	if (!READ_ONCE(hdr->throttled))
		return;

	hdr->throttled_ns += now - READ_ONCE(hdr->throttled_at);
	WRITE_ONCE(hdr->throttled, 0);
}

/*
 * Start @hdr's next period if the one it is in has run out,
 * __refill_cfs_bandwidth_runtime(): the group gets its quota back, and keeps
 * what it left unused as long as its burst covers it.
 *
 * Whoever moves @period_start refills; everybody else goes on with what is
 * there. Periods are not aligned to anything, so a group that stops running
 * takes its next one from wherever it starts again, as fair.c's period timer
 * does once it has been let stop.
 */
static void grp_bw_refill(struct grp_hdr __arena *hdr, u64 now)
{
	u64 period = READ_ONCE(hdr->period);
	u64 start = READ_ONCE(hdr->period_start);
	u64 quota, burst, pool;

	if (!period || now - start < period)
		return;
	if (__sync_val_compare_and_swap(&hdr->period_start, start, now) != start)
		return;

	quota = READ_ONCE(hdr->quota);
	burst = READ_ONCE(hdr->burst);
	while (can_loop) {
		pool = READ_ONCE(hdr->pool);
		if (__sync_val_compare_and_swap(&hdr->pool, pool,
						MIN(pool + quota, quota + burst)) == pool)
			break;
	}

	grp_bw_unthrottle(hdr, now);
}

/*
 * Hand a cid that has run out @want of the group's bandwidth, and a slice
 * ahead of it so that it does not come back for every charge,
 * assign_cfs_rq_runtime(). Returns what there was to give.
 */
static u64 grp_bw_assign(struct grp_hdr __arena *hdr, u64 want)
{
	u64 pool, take;

	while (can_loop) {
		pool = READ_ONCE(hdr->pool);
		if (!pool)
			return 0;
		take = MIN(pool, want + BW_SLICE_NS);
		if (__sync_val_compare_and_swap(&hdr->pool, pool, pool - take) == pool)
			return take;
	}

	return 0;
}

/*
 * Charge @delta of runtime to the group of @gq and to every group above it,
 * account_cfs_rq_runtime() at each level of update_curr(): the time a cgroup
 * spends is spent by all of its ancestors too. A level that runs through what
 * its cid was given asks the group's pool for more, and one whose pool is
 * empty throttles itself and everything under it.
 *
 * The cid keeps what it is given across periods, as fair.c has done since it
 * stopped expiring local slices: what a cid holds and does not use is given
 * back when its queue goes quiet, see grp_bw_return().
 *
 * It does not keep it across a change of cpu.max. tg_set_cfs_bandwidth() resets
 * every cfs_rq of the group when the limit moves, and without that a cid could
 * go on spending a slice taken under the old quota: on a machine with hundreds
 * of them, a group that had touched many could overrun a lowered limit by a
 * slice apiece. The generation says which limit a slice was taken under.
 */
static void grp_bw_charge(grp_q_t *gq, u64 delta, u64 now)
{
	int i;

	for (i = 0; gq && i < GRP_MAX_DEPTH; i++, gq = gq->parent) {
		struct grp_hdr __arena *hdr = gq->hdr;
		u64 gen;
		s64 rem;

		if (!hdr || !grp_bw_limited(hdr))
			continue;

		grp_bw_refill(hdr, now);

		gen = READ_ONCE(hdr->bw_gen);
		if (READ_ONCE(gq->bw_gen) != gen) {
			WRITE_ONCE(gq->runtime_remaining, 0);
			WRITE_ONCE(gq->bw_gen, gen);
		}

		rem = READ_ONCE(gq->runtime_remaining) - (s64)delta;
		if (rem < 0)
			rem += grp_bw_assign(hdr, -rem);
		WRITE_ONCE(gq->runtime_remaining, rem);
		if (rem < 0)
			grp_bw_throttle(hdr, now);
	}
}

/*
 * Nothing of the group is left on the cid of @gq: give back what the cid holds
 * of the group's bandwidth, less the millisecond __return_cfs_rq_runtime()
 * keeps behind for whoever runs there next. Without this the time a cid was
 * handed and did not use would sit there for good, and a group that moves
 * around would be held to a fraction of its quota.
 */
static void grp_bw_return(grp_q_t *gq)
{
	struct grp_hdr __arena *hdr = gq->hdr;
	s64 rem = READ_ONCE(gq->runtime_remaining);

	if (!hdr || !grp_bw_limited(hdr) || rem <= (s64)NSEC_PER_MSEC)
		return;

	/* A slice taken under a limit that has since moved is dropped, not
	 * given back: it is not this limit's time to hand out.
	 */
	if (READ_ONCE(gq->bw_gen) != READ_ONCE(hdr->bw_gen)) {
		WRITE_ONCE(gq->runtime_remaining, 0);
		return;
	}

	WRITE_ONCE(gq->runtime_remaining, (s64)NSEC_PER_MSEC);
	__sync_fetch_and_add(&hdr->pool, rem - NSEC_PER_MSEC);
}

/*
 * Give @hdr a slot among the limited cgroups, or leave it without one when
 * they are all taken.
 */
static void grp_bw_register(struct grp_hdr __arena *hdr)
{
	u32 slot;

	if (hdr->bw_slot < BW_MAX_LIMITED)
		return;

	bpf_for(slot, 0, BW_MAX_LIMITED) {
		u32 i = slot & (BW_MAX_LIMITED - 1);

		if (READ_ONCE(bw_hdrs[i]) ||
		    __sync_val_compare_and_swap(&bw_hdrs[i], 0, (u64)hdr))
			continue;
		hdr->bw_slot = i;
		if (i >= bw_hdrs_nr)
			bw_hdrs_nr = i + 1;
		return;
	}
}

/*
 * Give the slot back. Either the cgroup ops or the drain does this, so the
 * entry is exchanged rather than written: the drain is the one that knows a
 * cgroup which has stopped being limited has no tasks left waiting on it.
 */
static void grp_bw_unregister(struct grp_hdr __arena *hdr)
{
	u64 slot = hdr->bw_slot;

	if (slot >= BW_MAX_LIMITED)
		return;

	hdr->bw_slot = BW_SLOT_NONE;
	__sync_val_compare_and_swap(&bw_hdrs[slot & (BW_MAX_LIMITED - 1)],
				    (u64)hdr, 0);
}

/*
 * A task is no longer waiting on the cgroup it was put aside for, because the
 * drain took it out of the backlog or because it left BPF custody from there.
 * Whoever took the node out of the queue does this, exactly once.
 */
static void task_bw_unparked(task_ctx_t *tctx)
{
	struct grp_hdr __arena *hdr = tctx->bw_hdr;

	if (!hdr)
		return;

	tctx->bw_hdr = NULL;
	__sync_fetch_and_sub(&hdr->nr_parked, 1);
	__sync_fetch_and_sub(&bw_nr_parked, 1);
}

/*
 * Set or clear the bit of @gq's cid in its cgroup's live bitmap. By compare
 * and swap: the verifier takes no atomic or/and on arena memory.
 */
static void grp_live_update(grp_q_t *gq, bool live)
{
	u64 __arena *word = &grp_live(gq->hdr, nr_cids)[gq->cid / 64];
	u64 bit = 1ULL << (gq->cid & 63), old;

	while (can_loop) {
		old = READ_ONCE(*word);
		if (!!(old & bit) == live)
			return;
		if (__sync_val_compare_and_swap(word, old,
						live ? old | bit : old & ~bit) == old)
			return;
	}
}

/*
 * Decay the averages of @gq, a queue with no members left on its cid, and
 * take what they add to its cgroup's sums along: update_blocked_averages()
 * for a group whose cfs_rq has gone quiet. The cid that owns the queue only
 * keeps them from its tick while the group runs there, and without this a
 * cid the group has left would hold its last contribution for good, inflating
 * tg_load_avg and shrinking the group's shares everywhere else.
 */
__noinline int grp_decay(grp_q_t *gq __arg_arena, u64 now)
{
	struct grp_hdr __arena *hdr;
	u64 la, na;

	TOUCH_ARENA();

	if (!gq || READ_ONCE(gq->load) || !grp_avg_trylock(gq))
		return 0;
	/* A task may have joined between the look and the lock. */
	if (READ_ONCE(gq->load)) {
		grp_avg_unlock(gq);
		return 0;
	}
	hdr = gq->hdr;

	if (bw_enabled())
		grp_bw_return(gq);

	ravg_accumulate_arena(&gq->load_avg, 0, now);
	ravg_accumulate_arena(&gq->nr_avg, 0, now);
	la = ravg_read_arena(&gq->load_avg, now) >> RAVG_FRAC_BITS;
	na = ravg_read_arena(&gq->nr_avg, now);
	/* A 64th of a task decays to nothing more that matters. */
	if (na < (1ULL << RAVG_FRAC_BITS) / 64)
		na = 0;

	if (la != gq->load_avg_contrib) {
		__sync_fetch_and_add(&hdr->load_avg, (s64)(la - gq->load_avg_contrib));
		gq->load_avg_contrib = la;
	}
	if (na != gq->nr_avg_contrib) {
		__sync_fetch_and_add(&hdr->nr_avg, (s64)(na - gq->nr_avg_contrib));
		gq->nr_avg_contrib = na;
	}

	if (!la && !na)
		grp_live_update(gq, false);
	grp_avg_unlock(gq);

	return 0;
}

/*
 * One step of grp_sweep() from @pos, cgroup slot in the high 32 bits and cid
 * in the low: decay the next live queue at or after it in that cgroup, or
 * move to the next cgroup. Return the position to go on from, or ~0 past the
 * last slot. A global function, so that the walk is a loop over an opaque
 * cursor and verifies once.
 */
__noinline u64 grp_sweep_step(u64 pos, u64 now)
{
	u32 slot = pos >> 32, cid = (u32)pos, words = (nr_cids + 63) / 64, k;
	struct grp_hdr __arena *hdr;
	u64 __arena *live;
	u64 w;

	TOUCH_ARENA();

	if (!grp_hdrs || slot >= grp_hdrs_nr || slot >= GRP_MAX_CGROUPS)
		return ~0ULL;
	hdr = (struct grp_hdr __arena *)grp_hdrs[slot];
	k = cid / 64;
	if (!hdr || k >= words)
		return (u64)(slot + 1) << 32;

	live = grp_live(hdr, nr_cids);
	w = READ_ONCE(live[k]) & (~0ULL << (cid & 63));
	if (!w)
		return (u64)slot << 32 | ((k + 1) * 64);
	cid = k * 64 + __builtin_ctzll(w);
	if (cid >= nr_cids)
		return (u64)(slot + 1) << 32;

	grp_decay(&grp_ents(hdr)[cid], now);
	return (u64)slot << 32 | (cid + 1);
}

/*
 * Hand the block of a removed cgroup over to be freed by the next sweep, when
 * a sweep that may still be looking at it holds grp_sweep_lock and the block
 * cannot be freed from under it. Producers push without a lock and the sweep
 * pops with compare and swap, see grp_free_pop(). A push that cannot complete
 * leaks the block, which is safe.
 */
static void grp_free_defer(struct grp_hdr __arena *hdr)
{
	u64 old;

	while (can_loop) {
		old = READ_ONCE(grp_free_head);
		hdr->next_free = old;
		if (__sync_val_compare_and_swap(&grp_free_head, old, (u64)hdr) == old)
			return;
	}
}

/* Keep reclamation from adding an unbounded amount of work to one tick. */
#define GRP_FREE_BUDGET	8

/*
 * Pop one block from the deferred-free list. The sweep lock serializes
 * consumers, while cgroup exits may still push new blocks concurrently.
 */
__noinline u64 grp_free_pop(void)
{
	u64 head, next;

	TOUCH_ARENA();

	while (can_loop) {
		struct grp_hdr __arena *hdr;

		head = READ_ONCE(grp_free_head);
		if (!head)
			return 0;
		hdr = (struct grp_hdr __arena *)head;
		next = hdr->next_free;
		if (__sync_val_compare_and_swap(&grp_free_head, head, next) == head)
			return head;
	}

	return 0;
}

/*
 * Free a bounded number of blocks grp_free_defer() handed over. Called with
 * grp_sweep_lock held, after the walk: a block pushed during the walk may be
 * the one it looked at, and one pushed later is out of the registry and out
 * of any later walk. Anything left stays linked for a later sweep.
 */
__noinline int grp_free_drain(void)
{
	u32 i;

	TOUCH_ARENA();

	bpf_for(i, 0, GRP_FREE_BUDGET) {
		u64 next = grp_free_pop();
		struct grp_hdr __arena *hdr;

		if (!next)
			break;
		hdr = (struct grp_hdr __arena *)next;
		bpf_arena_free_pages(&arena, hdr, hdr->pages);
	}

	return 0;
}

/*
 * Walk the queues that still add to their cgroup's sums, a few per
 * GRP_SWEEP_NS, and decay the ones that have gone quiet, see grp_decay().
 * One cid at a time does it, from its tick, where fair.c's idle balancer
 * updates the blocked averages of idle CPUs.
 *
 * A global function, verified once rather than in the tick's context.
 */
__noinline int grp_sweep(u64 now)
{
	u64 at = READ_ONCE(grp_sweep_at), pos;
	bool wrapped = false;
	u32 i;

	TOUCH_ARENA();

	if (!grp_hdrs || (!grp_hdrs_nr && !READ_ONCE(grp_free_head)) ||
	    now - at < GRP_SWEEP_NS ||
	    __sync_val_compare_and_swap(&grp_sweep_at, at, now) != at)
		return 0;
	if (__sync_val_compare_and_swap(&grp_sweep_lock, 0, 1))
		return 0;

	pos = READ_ONCE(grp_sweep_pos);
	bpf_for(i, 0, GRP_SWEEP_BUDGET) {
		pos = grp_sweep_step(pos, now);
		if (pos == ~0ULL) {
			if (wrapped)
				break;
			wrapped = true;
			pos = 0;
		}
	}
	WRITE_ONCE(grp_sweep_pos, pos == ~0ULL ? 0 : pos);
	if (READ_ONCE(grp_free_head))
		grp_free_drain();
	WRITE_ONCE(grp_sweep_lock, 0);

	return 0;
}

/*
 * Bring what @gq adds to its cgroup's sums up to date, and recompute the
 * group's shares on the cid, update_cfs_group() with fair.c's default
 * cgroup_mode, "concur", calc_concur_shares():
 *
 *	nr = min(tg_tasks(tg), tg_cpus(tg));
 *	return __calc_smp_shares(cfs_rq, nr * tg_shares, nr * tg_shares);
 *
 * which is the load-proportional share of the group's weight on this cid,
 * the "icky" shares_weight approximation of __calc_smp_shares(),
 *
 *	load   = max(grq->load.weight, grq->avg.load_avg)
 *	shares = tg->weight * load / (tg->load_avg - contrib + load)
 *
 * with the weight scaled by how many CPUs' worth of tasks the group runs.
 * cpu.weight then means the weight per active CPU: a group of one task has
 * its cpu.weight on the cid the task runs on, and a group running a task on
 * every CPU has it on every CPU. Without the scaling, the shares of a group
 * spread over N cids would average 1/N of the weight and nested groups
 * 1/N^depth, which a single runqueue cannot afford. tg_cpus() counts the
 * CPUs of the group's cpuset; the cids of the scheduler stand in for them.
 *
 * The averages are kept from the owner of the cid, where the tick runs, and
 * the sums shared by every cid of the cgroup are written at most once a
 * millisecond per queue, and only for a move of more than a 64th.
 */
static void grp_update_shares(grp_q_t *gq, u64 now)
{
	struct grp_hdr __arena *hdr = gq->hdr;
	u64 load = READ_ONCE(gq->load), la, na, nr, total, tg_load, shares;
	s64 d;

	if (!grp_avg_trylock(gq))
		return;

	ravg_accumulate_arena(&gq->load_avg, load, now);
	ravg_accumulate_arena(&gq->nr_avg, READ_ONCE(gq->nr), now);
	la = ravg_read_arena(&gq->load_avg, now) >> RAVG_FRAC_BITS;
	na = ravg_read_arena(&gq->nr_avg, now);

	if (now - gq->shares_at < GRP_SUM_NS) {
		grp_avg_unlock(gq);
		return;
	}
	gq->shares_at = now;

	d = (s64)(la - gq->load_avg_contrib);
	if ((u64)(d < 0 ? -d : d) > gq->load_avg_contrib / 64) {
		__sync_fetch_and_add(&hdr->load_avg, d);
		gq->load_avg_contrib = la;
	}
	d = (s64)(na - gq->nr_avg_contrib);
	if ((u64)(d < 0 ? -d : d) > gq->nr_avg_contrib / 64) {
		__sync_fetch_and_add(&hdr->nr_avg, d);
		gq->nr_avg_contrib = na;
	}
	if (gq->load_avg_contrib || gq->nr_avg_contrib)
		grp_live_update(gq, true);
	grp_avg_unlock(gq);

	nr = READ_ONCE(hdr->nr_avg) >> RAVG_FRAC_BITS;
	nr = MIN(MAX(nr, 1ULL), (u64)nr_cids);
	total = nr * READ_ONCE(hdr->weight);

	load = MAX(load, la);
	tg_load = READ_ONCE(hdr->load_avg);
	tg_load = (tg_load > gq->load_avg_contrib ? tg_load - gq->load_avg_contrib : 0) +
		  load;
	shares = tg_load ? total * load / tg_load : total;
	shares = MIN(MAX(shares, (u64)GRP_MIN_SHARES), total);

	if (shares != READ_ONCE(gq->shares)) {
		WRITE_ONCE(gq->shares, shares);
		/* Take the new shares to the parent's load. */
		grp_contrib_sync(gq);
	}
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

static u64 cid_clock_task_owned(s32 cid, u64 now);

/*
 * Record whether @cid has sched_ext work which could consume the CPU. A new
 * demand period starts a fresh sample: an old reduced-capacity estimate must
 * not affect placement until current demand has observed the pressure again.
 */
static void cid_demand_set(s32 cid, bool demand, u64 now)
{
	struct cid_ctx __arena *cctx;

	if (!capacity_pressure || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	if (demand == cctx->pressure_demand)
		return;
	cctx->pressure_demand = demand;
	if (demand) {
		/*
		 * Unlike fair's RT PELT, cidland has no clock source while no
		 * sched_ext task wants the cid. Retain short gaps so pressure
		 * cannot attract work straight back, but do not let an old event
		 * suppress this cid forever.
		 */
		if (cctx->pressure_idle_at &&
		    now - cctx->pressure_idle_at >= NSEC_PER_SEC) {
			cctx->pressure_avail = 1024;
			cctx->pressure_migrate_next = 0;
			cctx->pressure_migrate_failed = 0;
			WRITE_ONCE(cctx->busy_balance_cap, cid_topo(cid)->cap);
		}
		cctx->pressure_idle_at = 0;
		cctx->pressure_at = now;
		cctx->pressure_lost_at = cctx->pressure_lost;
		cctx->pressure_clock_off_at = cctx->clock_off;
		cctx->pressure_valid = 0;
	} else {
		cctx->pressure_idle_at = now;
		cctx->pressure_blocked_at = 0;
		cctx->pressure_migrate_next = 0;
		cctx->pressure_migrate_failed = 0;
		cctx->pressure_valid = 0;
		WRITE_ONCE(cctx->busy_balance_cap, cid_topo(cid)->cap);
	}
}

/*
 * A runnable task stopped with slice remaining was displaced by a higher
 * scheduling class or core scheduling. Measure the interval until sched_ext
 * next runs on this cid. Unlike service/wall accounting, this does not count
 * ordinary dispatch and context-switch overhead as unavailable capacity.
 */
static void cid_pressure_displaced(s32 cid, u64 tnow)
{
	struct cid_ctx __arena *cctx;

	if (!capacity_pressure || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	if (cctx->pressure_demand && !cctx->pressure_blocked_at)
		cctx->pressure_blocked_at = tnow;
}

static void cid_pressure_resumed(s32 cid, u64 tnow)
{
	struct cid_ctx __arena *cctx;

	if (!capacity_pressure || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	if (cctx->pressure_blocked_at) {
		cctx->pressure_lost += tnow - cctx->pressure_blocked_at;
		cctx->pressure_blocked_at = 0;
	}
}

#define PRESSURE_EVAL_NS	(32ULL * NSEC_PER_MSEC)

static void update_balance_cap(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx = cid_ctx(cid);
	u64 cap = cid_topo(cid)->cap;
	u64 elapsed, lost, off, available;

	if (!capacity_pressure)
		return;
	if (!cctx->pressure_demand)
		return;
	elapsed = now - cctx->pressure_at;
	if (elapsed < PRESSURE_EVAL_NS)
		return;
	/* Refresh rq_clock - rq_clock_task; its delta is IRQ plus steal time. */
	cid_clock_task_owned(cid, now);
	off = cctx->clock_off;
	lost = cctx->pressure_lost - cctx->pressure_lost_at;
	if (off > cctx->pressure_clock_off_at)
		lost += off - cctx->pressure_clock_off_at;
	available = 1024 - MIN(lost * 1024 / elapsed, 1024ULL);
	if (cctx->pressure_valid)
		cctx->pressure_avail = (3 * cctx->pressure_avail + available) / 4;
	else
		cctx->pressure_avail = available;
	cctx->pressure_at = now;
	cctx->pressure_lost_at = cctx->pressure_lost;
	cctx->pressure_clock_off_at = off;
	cctx->pressure_valid = 1;
	WRITE_ONCE(cctx->busy_balance_cap,
		   MAX(cap * cctx->pressure_avail / 1024, 1ULL));
}

/* fair.c's check_cpu_capacity(), using the domain's imbalance threshold. */
static bool cid_capacity_reduced(s32 cid)
{
	u64 cap;

	if (!capacity_pressure || !cid_valid(cid) ||
	    !READ_ONCE(cid_ctx(cid)->pressure_demand) ||
	    !READ_ONCE(cid_ctx(cid)->pressure_valid))
		return false;
	cap = READ_ONCE(cid_ctx(cid)->busy_balance_cap);
	return cap && cap * BUSY_BALANCE_IMBALANCE_PCT <
		cid_topo(cid)->cap * 100;
}

/*
 * The load of a cid, cpu_load(): what cfs_rq->avg.load_avg is, the weight
 * of the runnable tasks averaged over time, and what wake_affine_weight()
 * compares. The weight is the pack's, @vsum_w, the sum over the running
 * task and the queued ones, and it is sampled into the average from the
 * cid's own CPU. ops.tick() maintains it and ops.update_idle() records the
 * empty pack when the tick stops with the CPU. Updating it at every context
 * switch would be finer grained, but unlike fair's PELT that means entering a
 * BPF running-average state machine twice per switch. A join or a leave from
 * another CPU changes @vsum_w atomically but cannot update a running average
 * that is not owned there, so the sample is at most one tick behind. A read
 * from another CPU is the same unlocked read cid_util() makes.
 */
static __always_inline u64 ravg_read_fast(struct ravg_data __arena *rd, u64 now);

static void cid_load_accumulate(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;

	if (!cid_valid(cid))
		return;
	cctx = cid_ctx(cid);

	ravg_accumulate_arena(&cctx->load_avg, cctx->pack.vsum_w, now);
	cctx->wake_load = ravg_read_fast(&cctx->load_avg, now) >> RAVG_FRAC_BITS;
}

static u64 task_load(const struct task_struct *p, task_ctx_t *tctx, u64 now);

/* ((@a * @b) >> RAVG_FRAC_BITS) without overflowing the intermediate. */
static __always_inline u64 ravg_scale_fast(u64 a, u32 b)
{
	u64 lo = (a & 0xffffffffULL) * b;
	u64 hi = (a >> 32) * b;

	return (lo >> RAVG_FRAC_BITS) + (hi << (32 - RAVG_FRAC_BITS));
}

/*
 * The common ravg_read() case when the last update and this read are in the
 * same 32 ms period. Avoid copying the arena value and running the general
 * period-crossing state machine. Fall back at a boundary, where the general
 * path is needed to fold and decay periods.
 */
static __always_inline u64 ravg_read_fast(struct ravg_data __arena *rd, u64 now)
{
	u64 val, val_at, old, cur, add;
	u32 elapsed, progress;

	/* Match ravg_from_arena()'s snapshot order for concurrent remote reads. */
	val = READ_ONCE(rd->val);
	val_at = READ_ONCE(rd->val_at);
	old = READ_ONCE(rd->old);
	cur = READ_ONCE(rd->cur);
	if (now < val_at || now / UTIL_HALF_LIFE_NS != val_at / UTIL_HALF_LIFE_NS)
		return ravg_read_arena(rd, now);
	elapsed = now % UTIL_HALF_LIFE_NS;
	if (!elapsed)
		return old;

	progress = ravg_normalize_dur(elapsed, UTIL_HALF_LIFE_NS);
	old = ravg_scale_fast(old, (1U << RAVG_FRAC_BITS) - progress / 2);
	if (val && now > val_at) {
		add = val * ravg_normalize_dur(now - val_at,
					       UTIL_HALF_LIFE_NS);
		ravg_add(&cur, add);
	}
	return old + cur / 2;
}

static u64 cid_load(s32 cid, u64 now)
{
	return ravg_read_fast(&cid_ctx(cid)->load_avg, now) >> RAVG_FRAC_BITS;
}

static u64 cid_wake_load(s32 cid)
{
	return READ_ONCE(cid_ctx(cid)->wake_load);
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
static int cid_edq_try_peek_next(s32 cid, scx_edq_cursor_t *cursor,
				 cid_edq_task_t **atp)
{
	u64 task;
	int ret;

	*atp = NULL;
	ret = scx_edq_try_peek_next_hold(&cid_pack(cid)->edq, cursor, &task);
	if (ret) {
		if (ret != -EBUSY)
			scx_bpf_error("EDQ cursor peek failed for cid %d: %d",
				      cid, ret);
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
 * a transiently all-ineligible queue cannot be stranded, unless @strict: the
 * caller has a runnable task to keep instead. Pops again after a failed
 * dispatch, see cid_queue_move_head_to_local().
 */
static __noinline bool cid_edq_move_first_eligible_to_local(s32 cid, u64 vref,
							    bool strict)
{
	struct scx_edq __arena *edq = &cid_pack(cid)->edq;
	cid_edq_task_t *at;

	while (can_loop) {
		at = (cid_edq_task_t *)(strict ?
			scx_edq_pop_first_eligible(edq, vref, true) :
			scx_edq_pop_first_eligible_or_first(edq, vref, true));
		if (!at)
			return false;
		if (cid_edq_dispatch_popped(at, NULL, cid))
			return true;
	}
	return false;
}

static __always_inline bool cid_queue_insert(struct task_struct *p, task_ctx_t *tctx,
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
			      vruntime, tctx->se.request);
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
 *
 * Work in an idle cgroup counts as SCHED_IDLE work here, the way a task
 * under a cfs_rq_is_idle() group counts in rq->cfs.h_nr_idle, see
 * cidland_cpuctl_set_idle(). What @p itself is follows its policy alone, as
 * in choose_sched_idle_rq().
 */
static bool cid_sched_idle_target(const struct task_struct *p, s32 cid)
{
	struct cid_ctx __arena *cctx;

	if (p->policy == SCHED_IDLE || !cid_valid(cid) || cid_idle_test(cid) ||
	    cid_queued_test(cid))
		return false;
	cctx = cid_ctx(cid);

	return cctx->pack.curr_w && cctx->curr_sched_idle;
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

/*
 * Scan a domain for an idle cid, over a window of @nr of its cids counted from
 * @start and wrapping, which is what select_idle_cpu() walks:
 *
 *	for_each_cpu_wrap(cpu, cpus, target + 1)
 *
 * The window matters only when something has bounded it, see sis_idle_scan_nr():
 * a budget spent on the front of the domain every time would leave the cids
 * above it unreachable for as long as the budget lasts, where a window that
 * moves with the target reaches all of them over successive wakeups. With @nr
 * covering the whole domain this is the plain scan, one extra mask per word.
 *
 * @range packs the domain as span:base and @win the window as nr:start, two
 * u32 halves each: a subprogram takes five arguments at most, and this one is
 * verified on its own rather than inside the scan of every tier that calls it,
 * which is what the wakeup path has no room left for.
 */
#define SCAN_WINDOW_RESTRICTED	(1ULL << 0)
#define SCAN_WINDOW_WHOLE_CORE	(1ULL << 1)

__noinline s32 scan_idle_window(struct task_struct *p __arg_trusted, u32 t,
				u64 range, u64 win, u64 flags)
{
	u32 base = (u32)range, span = range >> 32;
	u32 start = (u32)win, nr = win >> 32;
	bool restricted = flags & SCAN_WINDOW_RESTRICTED;
	bool whole_core = flags & SCAN_WINDOW_WHOLE_CORE;
	u32 seg, head;

	TOUCH_ARENA();

	if (!nr || !span)
		return -EBUSY;
	if (start < base || start >= base + span)
		start = base;

	/*
	 * A window that covers the domain is the domain, and is taken in cid
	 * order, which is what this scan has always done. Reading it from the
	 * target instead would move every wakeup's placement on every machine,
	 * which is a change of its own and not one the budget needs.
	 */
	if (nr >= span) {
		start = base;
		nr = span;
	}
	head = MIN(nr, base + span - start);

	/*
	 * A shorter window is taken as the two ranges for_each_cpu_wrap() walks,
	 * in that order: from @start to the end of the domain, then from its
	 * base. Scanning their union in one pass would hand back the lowest cid
	 * of both wherever they share a bitmap word, which is the wrong end of
	 * the window and the opposite of the locality the window is for.
	 */
	bpf_for(seg, 0, 2) {
		u32 sbase = seg ? base : start;
		u32 snr = seg ? nr - head : head;
		u32 k, last;

		if (!snr)
			continue;
		last = (sbase + snr - 1) / 64;
		bpf_arena_for(k, sbase / 64, last + 1) {
			u64 w = cmask_word(idle_cids, k) & capacity_tier_word(t, k) &
				cmask_range_word(idle_cids, k, sbase, snr);
			s32 cid;

			if (!w)
				continue;
			cid = first_idle_cid(p, w, k, restricted, whole_core);
			if (cid >= 0)
				return cid;
		}
	}

	return -EBUSY;
}

static __always_inline u32 sis_idle_scan_nr(s32 cid)
{
	struct cid_topo __arena *topo;

	if (!sis_util || !cid_valid(cid))
		return UINT_MAX;
	topo = cid_topo(cid);
	return READ_ONCE(cid_ctx(topo->llc_base)->sis_idle_scan);
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

/* fair.c's asym_fits_cpu(): asymmetric SMT placement requires an idle core. */
static bool asym_fits_cid(task_ctx_t *tctx, s32 cid, u64 now)
{
	if (!sched_asym_capacity && !force_asym_capacity)
		return true;

	return task_fits_cid(tctx, cid, now) &&
	       (!smt_enabled || core_is_idle(cid));
}

static __always_inline bool cid_in_range(s32 cid, u32 base, u32 nr)
{
	return cid >= 0 && (u32)cid >= base && (u32)cid - base < nr;
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
 * fair.c's select_idle_capacity() searches the asymmetric-capacity domain in
 * CPU-number order, wrapping at @target. It runs before the ordinary LLC idle
 * scan. Cids are topology ordered, so translate the wrapped CPU walk back to
 * cids. A fully idle core is preferred when one exists; the regular tiered
 * picker remains the fallback for capacity misfits.
 */
static __noinline s32
select_idle_capacity_cid(const struct task_struct *p, task_ctx_t *tctx,
			 s32 target, u64 now)
{
	struct cid_topo __arena *target_topo = cid_topo(target);
	bool restricted = is_restricted(p);
	bool has_idle_core = smt_enabled && test_idle_cores(target);
	u32 start_cpu = target_topo->cpu;
	u64 best_cap = 0;
	s32 best = -EBUSY;
	u32 best_rank = 3;
	u32 scan_nr = sis_idle_scan_nr(target);
	u32 off;

	TOUCH_ARENA();
	if ((!sched_asym_capacity && !force_asym_capacity) ||
	    !target_topo->asym_capacity_nr || cmask_empty(idle_cids))
		return -EBUSY;

	bpf_arena_for(off, 0, nr_cpu_ids) {
		u32 cpu = start_cpu + off;
		u64 cap;
		s32 cid;
		u32 rank;
		bool core, fits;

		if (cpu >= nr_cpu_ids)
			cpu -= nr_cpu_ids;
		cid = scx_bpf_cpu_to_cid(cpu);
		if (!cid_valid(cid) ||
		    !cid_in_range(cid, target_topo->asym_capacity_base,
				  target_topo->asym_capacity_nr) ||
		    (restricted && !cid_allowed(p, cid)))
			continue;
		/* select_idle_capacity() spends the hint only without an idle core. */
		if (!has_idle_core && scan_nr != UINT_MAX && !scan_nr--)
			break;
		if (!cid_idle_test(cid))
			continue;
		core = !has_idle_core || core_is_idle(cid);
		fits = task_fits_cid(tctx, cid, now);
		if (core && fits) {
			cid = claim_idle_cid(p, cid);
			if (cid >= 0)
				return cid;
			continue;
		}

		/* Idle-core misfit, fitting SMT thread, then thread misfit. */
		rank = core ? 0 : fits ? 1 : 2;
		cap = cid_topo(cid)->cap;
		if (best < 0 || rank < best_rank ||
		    (rank == best_rank && cap > best_cap)) {
			best = cid;
			best_rank = rank;
			best_cap = cap;
		}
	}

	return best >= 0 ? claim_idle_cid(p, best) : -EBUSY;
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
	u32 scan_nr = whole_core || !llc_only ? UINT_MAX : sis_idle_scan_nr(prev_cid);
	u32 llc_scan_nr;
	u32 t;
	/* Only an asymmetric machine asks task_fits_cid() anything. */
	task_ctx_t *tctx = asym_capacity ? try_lookup_task_ctx(p) : NULL;
	u64 now = asym_capacity ? scx_bpf_now() : 0;

	TOUCH_ARENA();

	if (!cid_valid(prev_cid))
		return -EBUSY;
	prev = cid_topo(prev_cid);
	restricted = is_restricted(p);
	llc_scan_nr = MIN(prev->llc_nr, scan_nr);
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
		best = scan_idle_window(p, t,
					(u64)prev->llc_nr << 32 | prev->llc_base,
					(u64)llc_scan_nr << 32 | (u32)(prev_cid + 1),
					(restricted ? SCAN_WINDOW_RESTRICTED : 0) |
					(whole_core ? SCAN_WINDOW_WHOLE_CORE : 0));
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
 * then any idle CPU. Stop there by default, as select_idle_sibling() does.
 *
 * With @llc_extend, a whole idle core outside the target LLC is taken before
 * a half-busy core inside it. An idle sibling of a busy core is not a free
 * CPU; it is half of a core that is already working, and taking it costs the
 * thread running there about half its throughput for as long as the two
 * overlap. fair.c never has to choose, because select_idle_sibling() stops at
 * the LLC and leaves the rest to the periodic balancer; the extended scan
 * crosses LLCs, so it has to say which it prefers.
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
	u32 flags = (!is_restricted(p) || cid_allowed(p, target) ?
		     PICK_IDLE_PREV_ALLOWED : 0) |
		    (!llc_extend ? PICK_IDLE_LLC_ONLY : 0);
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
		 * With @llc_extend, carry select_idle_sibling() beyond the target
		 * LLC. The extension goes first while a whole idle core is left
		 * anywhere: everything below this settles for an idle sibling
		 * of a busy core, which halves the thread already running on
		 * it. The hint mask has no bit set once no LLC has an idle
		 * core, which is the loaded case this must not slow down.
		 */
		if (llc_extend && smt_whole_core && smt_enabled &&
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
		 * A budget that bounded the scan above has to bound the rest
		 * of the search too, or it decides nothing: every scan below
		 * covers the whole LLC again without one, so the budget would
		 * only add a pass. This is where select_idle_cpu() returns -1
		 * and the task is left on its affine target.
		 */
		if (sis_util &&
		    sis_idle_scan_nr(target) < cid_topo(target)->llc_nr) {
			return -EBUSY;
		}

		/*
		 * The same extension in its original place, still ahead of
		 * taking any idle cid at all, unless the pass above has just
		 * run this scan and failed. With the option on it is reached
		 * when the hint said no LLC had an idle core, and the scan
		 * still runs there because the hint is only a hint.
		 */
		if (llc_extend && smt_enabled && !whole_scanned) {
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

	if (!asym_capacity || !cid_valid(src_cid) || is_pcpu_task(p) ||
	    cmask_empty(idle_cids))
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

static __always_inline void
edq_scan_reset(scx_edq_cursor_t *cursor)
{
	scx_edq_cursor_reset(cursor);
}

/*
 * Fetch the next task in deadline order and advance @cursor past it. A queue
 * mutation cannot invalidate the cursor because it contains the ordering key,
 * not a node pointer. Reaching the end resets the scan so its next bounded
 * pass wraps to the head and tasks inserted before the cursor are eventually
 * considered too.
 */
static __always_inline int
edq_scan_next(s32 src_cid, scx_edq_cursor_t *cursor,
	      cid_edq_task_t **atp)
{
	return cid_edq_try_peek_next(src_cid, cursor, atp);
}

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
	scx_edq_cursor_t *cursor = &cid_ctx(src_cid)->detach_cursor;
	u32 nth;

	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		struct task_struct *p;
		enum cid_edq_move_result move;
		int ret;

		ret = edq_scan_next(src_cid, cursor, &at);
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
	scx_edq_cursor_t *cursor = &cid_ctx(src_cid)->detach_cursor;
	bool pinned = false;
	u32 nth;

	TOUCH_ARENA();
	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		enum cid_edq_move_result move;
		struct task_struct *p;
		bool movable;
		int ret;

		ret = edq_scan_next(src_cid, cursor, &at);
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
 * half, wake_affine_weight(), is enabled by default, see
 * wake_affine_weight_cid(). As in fair.c, affinity is considered for a
 * wakeup when the waking cid is allowed and wake_wide() does not reject the
 * waker/wakee relationship. The sched domain carrying SD_WAKE_AFFINE may be
 * wider than an LLC, so the target is allowed to cross an LLC or NUMA-node
 * boundary; select_idle_sibling_cid() then searches around that target.
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
 * The cid loads are tick-sampled averaged runnable weights. task_load()
 * approximates task_h_load() from the task's already-maintained execution
 * utilization, decayed cheaply over sleep. A waker that runs a little and
 * sleeps a lot therefore weighs little on its cid, so its wakee lands behind
 * a task about to sleep instead of behind a fresh slice on the previous cid.
 * This approximation avoids a second per-task running average and leaves the
 * wakeup path with scalar snapshot reads. The bias is half the domain's
 * imbalance_pct, 117 within an LLC and 110 within a core.
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

	this_eff = cid_wake_load(this_cid);
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
	prev_eff = (s64)cid_wake_load(prev_cid) - (s64)load;
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
	    !cid_in_range(prev_cid, cid_topo(this_cid)->wake_affine_base,
			  cid_topo(this_cid)->wake_affine_nr))
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
static __always_inline s32 select_idle_sibling_cid(const struct task_struct *p, task_ctx_t *tctx,
				   s32 prev_cid, s32 target, bool *direct, u64 now)
{
	s32 cid;
	s32 recent = -1;

	if (cid_idle_test(target) && cid_allowed(p, target) &&
	    asym_fits_cid(tctx, target, now)) {
		cid = claim_idle_cid(p, target);
		if (cid >= 0) {
			*direct = true;
			return cid;
		}
	}
	if (cid_allowed(p, target) && asym_fits_cid(tctx, target, now) &&
	    cid_sched_idle_target(p, target))
		return target;

	if (prev_cid != target &&
	    cid_topo(prev_cid)->llc_base == cid_topo(target)->llc_base &&
	    cid_idle_test(prev_cid) && cid_allowed(p, prev_cid) &&
	    asym_fits_cid(tctx, prev_cid, now)) {
		cid = claim_idle_cid(p, prev_cid);
		if (cid >= 0) {
			*direct = true;
			return cid;
		}
	}
	if (prev_cid != target &&
	    cid_topo(prev_cid)->llc_base == cid_topo(target)->llc_base &&
	    cid_allowed(p, prev_cid) && asym_fits_cid(tctx, prev_cid, now) &&
	    cid_sched_idle_target(p, prev_cid))
		return prev_cid;

	/* Check and rotate p->recent_used_cpu at the same point fair.c does. */
	recent = tctx->recent_used_cid;
	tctx->recent_used_cid = prev_cid;
	if (cid_valid(recent) && recent != prev_cid && recent != target &&
	    cid_topo(recent)->llc_base == cid_topo(target)->llc_base &&
	    cid_idle_test(recent) && cid_allowed(p, recent) &&
	    asym_fits_cid(tctx, recent, now)) {
		cid = claim_idle_cid(p, recent);
		if (cid >= 0) {
			*direct = true;
			return cid;
		}
	}
	if (cid_valid(recent) && recent != prev_cid && recent != target &&
	    cid_topo(recent)->llc_base == cid_topo(target)->llc_base &&
	    cid_allowed(p, recent) && asym_fits_cid(tctx, recent, now) &&
	    cid_sched_idle_target(p, recent))
		return recent;

	if (asym_capacity) {
		cid = select_idle_capacity_cid(p, tctx, target, now);
		if (cid >= 0) {
			*direct = true;
			return cid;
		}
	}

	cid = pick_idle_cid(p, prev_cid, target);
	if (cid >= 0)
		*direct = true;

	return cid;
}

static __always_inline void fork_pick_commit(struct fork_pick_env *env)
{
	u64 imbalance_pct = env->level == FORK_CHILD_CORE ?
		FORK_MC_IMBALANCE_PCT : FORK_WIDE_IMBALANCE_PCT;
	bool best_spare;
	bool local;
	bool spare;

	/* fair.c skips a sched group whose span has no CPU allowed to @p. */
	if (!env->group_nr || !env->group_allowed)
		return;
	local = cid_in_range(env->anchor, env->group_base, env->group_nr);
	/* A disallowed SMT sibling is not spare capacity for this task. */
	spare = env->restricted && env->runnable < env->group_allowed;
	if (env->best_nr) {
		best_spare = env->restricted &&
			env->best_runnable < env->best_allowed;
		if (spare != best_spare) {
			if (!spare)
				return;
			goto commit;
		}
		if (env->idle < env->best_idle)
			return;
		if (env->idle == env->best_idle) {
			if (spare) {
				/* Keep fair.c's local-group preference on an idle tie. */
				if (env->best_local)
					return;
				if (local)
					goto commit;
				/* group_has_spare ties are ordered by group utilization. */
				if (env->util > env->best_util)
					return;
				if (env->util < env->best_util)
					goto commit;
			} else {
				/* Fully busy groups are ordered by load per capacity. */
				if (env->restricted && env->best_local != local) {
					/*
					 * sched_balance_find_dst_group() keeps the
					 * local group unless the remote group is
					 * better by the domain's imbalance margin.
					 */
					if (env->best_local) {
						if (env->best_load * env->cap * 100 <=
						    env->load * env->best_cap *
							    imbalance_pct)
							return;
						goto commit;
					}
					if (env->load * env->best_cap * 100 <=
					    env->best_load * env->cap *
						    imbalance_pct)
						goto commit;
					return;
				}
				if (env->load * env->best_cap >
				    env->best_load * env->cap)
					return;
				if (env->load * env->best_cap <
				    env->best_load * env->cap)
					goto commit;
				if (env->best_local)
					return;
				if (local)
					goto commit;
			}
			if (env->level != FORK_CHILD_CORE ||
			    env->group_recent >= env->best_recent)
				return;
		}
	}

commit:
	env->best_base = env->group_base;
	env->best_nr = env->group_nr;
	env->best_idle = env->idle;
	env->best_load = env->load;
	env->best_util = env->util;
	env->best_cap = env->cap;
	env->best_recent = env->group_recent;
	env->best_runnable = env->runnable;
	env->best_allowed = env->group_allowed;
	env->best_local = local;
}

/* Pick the idlest immediate child group of @range, as fair.c does. */
static __noinline u64
fork_pick_child(const struct task_struct *p, u64 range, s32 anchor, u32 level,
		u64 now)
{
	struct fork_pick_env *env;
	bool restricted = is_restricted(p);
	u32 zero = 0;
	u32 nr = range >> 32;
	u32 i;

	env = bpf_map_lookup_elem(&fork_pick_scratch, &zero);
	if (!env || !nr)
		return range;
	env->base = (u32)range;
	env->nr = nr;
	env->anchor = anchor;
	env->level = level;
	env->now = now;
	env->group_base = 0;
	env->group_nr = 0;
	env->group_end = 0;
	env->group_allowed = 0;
	env->restricted = restricted;
	env->idle = 0;
	env->load = 0;
	env->util = 0;
	env->cap = 0;
	env->group_recent = 0;
	env->runnable = 0;
	env->best_idle = 0;
	env->best_load = 0;
	env->best_util = 0;
	env->best_cap = 1;
	env->best_recent = 0;
	env->best_runnable = 0;
	env->best_allowed = 0;
	env->best_base = 0;
	env->best_nr = 0;
	env->best_local = 0;

	TOUCH_ARENA();
	bpf_arena_for(i, env->base, env->base + nr) {
		if (!cid_valid(i))
			break;
		if (!env->group_nr || i == env->group_end) {
			fork_pick_commit(env);
			if (env->level == FORK_CHILD_NODE) {
				env->group_base = cid_topo(i)->node_base;
				env->group_nr = cid_topo(i)->node_nr;
			} else if (env->level == FORK_CHILD_LLC) {
				env->group_base = cid_topo(i)->llc_base;
				env->group_nr = cid_topo(i)->llc_nr;
			} else {
				env->group_base = cid_topo(i)->core_base;
				env->group_nr = cid_topo(i)->core_nr;
			}
			env->group_end = env->group_base + env->group_nr;
			env->group_allowed = !restricted;
			env->idle = 0;
			env->load = 0;
			env->util = 0;
			env->cap = 0;
			env->runnable = 0;
			env->group_recent = env->level == FORK_CHILD_CORE ?
				READ_ONCE(cid_ctx(env->group_base)->fork_place_at) : 0;
			if (env->group_recent &&
			    (s64)(env->now - env->group_recent) >= UTIL_HALF_LIFE_NS)
				env->group_recent = 0;
		}
		/*
		 * update_sg_wakeup_stats() accumulates load and idleness over
		 * sched_group_span(group) intersected with p->cpus_ptr, while
		 * group_capacity remains the capacity of the whole group.
		 */
		env->cap += MAX(cid_topo(i)->cap, 1ULL);
		if (restricted && !cid_allowed(p, i))
			continue;
		if (restricted) {
			struct pack __arena *pk = cid_pack(i);
			u32 running = READ_ONCE(pk->curr_w) != 0;
			u32 edq_nr = cid_queue_nr(i);
			u32 local_nr = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | i);
			u32 nr = edq_nr + local_nr + running;

			env->group_allowed++;
			/*
			 * DELAY_DEQUEUE can leave the running task represented in a
			 * queue too. The pack has only that task when its total weight
			 * equals the running weight, so do not count the two
			 * representations as two runnable tasks.
			 */
			if (running && (edq_nr || local_nr) &&
			    READ_ONCE(pk->vsum_w) == READ_ONCE(pk->curr_w))
				nr--;
			/* Cover a task between EDQ dispatch and ops.running(). */
			if (!nr && READ_ONCE(pk->vsum_w))
				nr = 1;
			env->runnable += nr;
		}
		if (cid_idle_test(i) && !cid_queued_test(i))
			env->idle++;
		if (restricted) {
			env->load += cid_load(i, now);
			env->util += cid_util(i, now);
		} else {
			env->load += READ_ONCE(cid_pack(i)->vsum_w);
		}
	}
	fork_pick_commit(env);
	return env->best_nr ? (u64)env->best_nr << 32 | env->best_base : range;
}

/* Choose fair.c's shallowest-idle or least-loaded CPU in @range. */
static __noinline s32
fork_pick_cid(const struct task_struct *p, u64 range, u64 now)
{
	bool restricted = is_restricted(p);
	u32 base = range, nr = range >> 32;
	u64 best_idle_load = 0, best_idle_cap = 1, best_idle_stamp = 0;
	u64 best_load = 0, best_cap = 1;
	s32 best_idle = -EBUSY, best = -EBUSY;
	u32 off;

	TOUCH_ARENA();
	bpf_arena_for(off, 0, nr) {
		u64 load, cap;
		s32 cid = base + off;

		if (!cid_valid(cid))
			break;
		if (restricted && !cid_allowed(p, cid))
			continue;
		/*
		 * Keep the fractional running average for an idle cid, which is
		 * ordered on how long it has been idle. A child that ran only
		 * long enough to enter its startup barrier can round down to zero in
		 * cid_util(), making its freshly-idled CPU look unused to the next
		 * fork. Unlike load_avg, run_avg records sub-tick start/stop pairs
		 * even when WA_WEIGHT is disabled.
		 *
		 * A busy cid is ordered by cpu_load(), the weight of what is
		 * runnable on it, the quantity find_idlest_group_cpu() compares
		 * once it has no idle CPU to hand out. run_avg cannot serve there:
		 * it saturates at 1.0 on anything that is running, so every cid of
		 * a busy group ties and the lowest one takes them all.
		 */
		cap = MAX(cid_topo(cid)->cap, 1ULL);
		if (cid_idle_test(cid) && !cid_queued_test(cid)) {
			u64 stamp = READ_ONCE(cid_ctx(cid)->idle_stamp);

			load = ravg_read_arena(&cid_ctx(cid)->run_avg, now);

			if (best_idle < 0 ||
			    load * best_idle_cap < best_idle_load * cap ||
			    (load * best_idle_cap == best_idle_load * cap &&
			     stamp > best_idle_stamp)) {
				best_idle = cid;
				best_idle_load = load;
				best_idle_cap = cap;
				best_idle_stamp = stamp;
			}
			continue;
		}
		load = restricted ? cid_load(cid, now) :
			READ_ONCE(cid_pack(cid)->vsum_w);
		if (best < 0 || load * best_cap < best_load * cap) {
			best = cid;
			best_load = load;
			best_cap = cap;
		}
	}

	return best_idle >= 0 ? best_idle : best;
}

/* Descend fair.c's live SD_BALANCE_FORK domain to an idlest CPU. */
static s32 find_idlest_fork_cid(const struct task_struct *p, s32 anchor,
				u64 now)
{
	struct cid_topo __arena *topo = cid_topo(anchor);
	u64 range = (u64)topo->fork_nr << 32 | topo->fork_base;
	u64 child;
	s32 cid;

	if (topo->fork_nr > topo->node_nr) {
		child = fork_pick_child(p, range, anchor, FORK_CHILD_NODE, now);
		if (child >> 32)
			range = child;
	}
	if (!cid_in_range(anchor, (u32)range, range >> 32))
		anchor = (u32)range;
	topo = cid_topo(anchor);
	if ((range >> 32) > topo->llc_nr) {
		child = fork_pick_child(p, range, anchor, FORK_CHILD_LLC, now);
		if (child >> 32)
			range = child;
	}
	if (!cid_in_range(anchor, (u32)range, range >> 32))
		anchor = (u32)range;
	topo = cid_topo(anchor);
	if ((range >> 32) > topo->core_nr) {
		child = fork_pick_child(p, range, anchor, FORK_CHILD_CORE, now);
		if (child >> 32)
			range = child;
	}
	if (!cid_in_range(anchor, (u32)range, range >> 32))
		anchor = (u32)range;

	cid = fork_pick_cid(p, range, now);
	if (cid >= 0)
		WRITE_ONCE(cid_ctx(cid_topo(cid)->core_base)->fork_place_at, now);
	return cid;
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
/*
 * The capacity-normalized load of the whole range, sds->avg_load, one read
 * per cid like update_sd_lb_stats().
 */
__noinline u64 busy_balance_avg_load(u32 base, u32 nr, u64 now,
				     u64 *sum_util __arg_nonnull)
{
	u64 load = 0, cap = 0, util = 0;
	u32 i;

	TOUCH_ARENA();
	bpf_arena_for(i, base, base + nr) {
		s32 cid = i;
		u64 sample, sample_cap;

		if (!cid_valid(cid))
			break;
		sample = cid_load(cid, now);
		sample_cap = capacity_pressure &&
			READ_ONCE(cid_ctx(cid)->pressure_demand) &&
			READ_ONCE(cid_ctx(cid)->pressure_valid) ?
			READ_ONCE(cid_ctx(cid)->busy_balance_cap) :
			cid_topo(cid)->cap;
		if (!sample_cap)
			sample_cap = cid_topo(cid)->cap;
		/* Group totals below reuse the samples collected by this pass. */
		WRITE_ONCE(cid_ctx(cid)->busy_balance_load, sample);
		WRITE_ONCE(cid_ctx(cid)->busy_balance_scan_cap, sample_cap);
		load += sample;
		cap += sample_cap;
		/* What SIS_UTIL wants, off the walk that is happening anyway. */
		if (sis_util)
			util += cid_util(cid, now);
	}

	*sum_util = util;

	return cap ? load * 1024 / cap : 0;
}

/*
 * update_idle_cpu_scan(): cache how much of an LLC wakeups should search. The
 * utilization it needs is summed by the walk the balance is doing anyway, as
 * update_sd_lb_stats() collects sum_util for it rather than walking again.
 * With x equal to its average utilization per CPU, fair.c computes
 *
 *   y = 1024 - min(x^2 * imbalance_pct^2 / (10000 * 1024), 1024)
 *   nr_idle_scan = llc_weight * y / 1024
 *
 * so the scan shrinks quadratically and reaches zero at 100 / 117, about
 * 85% utilization. This runs only from periodic balance on the LLC owner.
 */
static __noinline void update_sis_idle_scan(u32 base, u32 nr, u64 sum)
{
	u64 x, scaled, y;

	if (!sis_util || !nr)
		return;
	x = sum / nr;
	scaled = x * x * BUSY_BALANCE_IMBALANCE_PCT *
		 BUSY_BALANCE_IMBALANCE_PCT;
	scaled /= 10000 * 1024;
	y = 1024 - MIN(scaled, 1024ULL);
	WRITE_ONCE(cid_ctx(base)->sis_idle_scan, nr * y / 1024);
	__sync_fetch_and_add(&sis_scan_sum, nr * y / 1024);
	__sync_fetch_and_add(&nr_sis_updates, 1);
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
		cap += READ_ONCE(cid_ctx(i)->busy_balance_scan_cap);
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
		cap = MAX(READ_ONCE(cid_ctx(cid)->busy_balance_scan_cap), 1ULL);
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
	scx_edq_cursor_t *cursor = &cid_ctx(src_cid)->busy_scan_cursor;
	u64 budget = MIN(env->local_room, env->source_excess);
	u32 failed = READ_ONCE(cid_ctx(dst_cid)->busy_balance_failed[env->level]);
	u32 nth;

	env->alternate_dst_cid = -1;
	TOUCH_ARENA();
	bpf_for(nth, 0, BALANCE_TASK_SCAN) {
		cid_edq_task_t *at;
		struct task_struct *p;
		u64 candidate_deadline, candidate_seq, candidate_weight;
		s32 move_dst;
		int ret;

		ret = edq_scan_next(src_cid, cursor, &at);
		if (ret)
			return false;
		if (!at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		candidate_weight = ((task_ctx_t *)at)->se.vjoin_w;
		if (READ_ONCE(at->state) != CID_EDQ_ENQUEUED ||
		    (candidate_weight >> MIN(failed, 63U)) > budget ||
		    (task_hot((task_ctx_t *)at, src_cid, dst_cid, now) &&
		     failed <= cache_nice_tries)) {
			scx_edq_task_drop(&at->common);
			continue;
		}
		candidate_deadline = at->common.node.deadline;
		candidate_seq = at->common.node.seq;
		p = scx_bpf_tid_to_task(at->tid);
		move_dst = p ? busy_balance_dst_cid(p, dst_cid) : -1;
		scx_edq_task_drop(&at->common);
		if (move_dst < 0)
			continue;
		/*
		 * can_migrate_task() first drains tasks which can use the
		 * elected destination. LBF_DST_PINNED only revisits an alternate
		 * CPU in the local group if imbalance remains after that scan.
		 * Remember the first such candidate, but keep looking for work
		 * that does not need the redirect.
		 */
		if (move_dst != dst_cid) {
			if (env->alternate_dst_cid < 0) {
				env->alternate_dst_cid = move_dst;
				env->alternate_deadline = candidate_deadline;
				env->alternate_seq = candidate_seq;
			}
			continue;
		}
		env->move_budget = budget;
		env->move_dst_cid = move_dst;
		/* Dispatch must begin at, rather than after, this candidate. */
		env->scan_deadline = candidate_deadline;
		env->scan_seq = candidate_seq;
		env->scan_valid = SCX_EDQ_CURSOR_AT;
		return true;
	}
	if (env->alternate_dst_cid >= 0) {
		env->move_budget = budget;
		env->move_dst_cid = env->alternate_dst_cid;
		env->scan_deadline = env->alternate_deadline;
		env->scan_seq = env->alternate_seq;
		env->scan_valid = SCX_EDQ_CURSOR_AT;
		return true;
	}

	return false;
}

static __always_inline s32
busy_balance_from_range(s32 dst_cid, u32 base, u32 nr, u32 start, u64 now,
			u32 level)
{
	struct busy_balance_env __arena *env = &cid_ctx(dst_cid)->busy_balance_env;
	u64 sum_util = 0;
	s32 cid;

	env->detach_failed = 0;
	if (!nr)
		return -1;
	env->avg_norm = busy_balance_avg_load(base, nr, now, &sum_util);
	if (level == BUSY_BALANCE_LLC)
		update_sis_idle_scan(base, nr, sum_util);
	env->dst_norm = cid_load(dst_cid, now) * 1024 /
			MAX(READ_ONCE(cid_ctx(dst_cid)->busy_balance_scan_cap), 1ULL);
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
	if (!busy_balance_has_movable_task(dst_cid, cid, now)) {
		u32 failed = READ_ONCE(cid_ctx(dst_cid)->busy_balance_failed[level]);

		/*
		 * detach_tasks() progressively relaxes both its migration-size
		 * bound and cache-hotness after a periodic pass found imbalance
		 * but could not detach anything. Without that relaxation, an
		 * imbalance smaller than one task can never be repaired.
		 */
		env->detach_failed = 1;
		WRITE_ONCE(cid_ctx(dst_cid)->busy_balance_failed[level],
			   MIN(failed + 1, 63U));
		return -1;
	}
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
	/*
	 * get_sd_balance_interval() subtracts one tick from a busy interval so
	 * adjacent domains, and periodic activity such as RT runtime, cannot
	 * remain phase-locked to the balance pass.
	 */
	if (min_ms > 1)
		min_ms--;
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
	/* fair resets nr_balance_failed once the domain is balanced again. */
	if (src < 0 && !dst->busy_balance_env.detach_failed)
		WRITE_ONCE(dst->busy_balance_failed[level], 0);
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
		scx_edq_cursor_t *cursor =
			&move->busy_dispatch_cursor;

		cursor->deadline = dst->busy_balance_env.scan_deadline;
		cursor->seq = dst->busy_balance_env.scan_seq;
		cursor->valid = dst->busy_balance_env.scan_valid;
		WRITE_ONCE(move->busy_balance_expire,
			   now + (u64)min_ms * NSEC_PER_MSEC);
		WRITE_ONCE(move->busy_balance_budget,
			   dst->busy_balance_env.move_budget);
		WRITE_ONCE(move->busy_balance_owner, dst_cid);
		WRITE_ONCE(move->busy_balance_level, level);
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
 * A higher scheduling class just displaced @p from @src_cid. Once the
 * measured capacity is materially reduced, choose a less-loaded allowed cid
 * for the now-detached task. ops.enqueue() puts it into that cid's EDQ, where
 * it competes by the ordinary EEVDF rules. This is the sched_ext equivalent
 * of fair's detach_tasks() followed by attach_tasks(), not a forced dispatch.
 */
static __noinline s32
capacity_pressure_target(const struct task_struct *p, s32 src_cid, u64 now)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	u64 src_load, src_cap, src_norm;
	u64 best_load = 0, best_cap = 1;
	u64 move_budget, weight;
	u32 best_smt_rank = 0;
	u32 failed;
	u32 interval_ms;
	s32 best = -1;
	u32 i;

	if (!tctx || !capacity_pressure || !cid_valid(src_cid) ||
	    time_before(now, READ_ONCE(cid_ctx(src_cid)->pressure_migrate_next)) ||
	    !cid_capacity_reduced(src_cid))
		return -1;
	src_cap = READ_ONCE(cid_ctx(src_cid)->busy_balance_cap);
	/* Pace the scan, including misses, at the LLC busy-balance interval. */
	interval_ms = MAX(cid_topo(src_cid)->llc_nr * busy_balance_factor, 1U);
	if (interval_ms > 1)
		interval_ms--;
	WRITE_ONCE(cid_ctx(src_cid)->pressure_migrate_next,
		   now + (u64)interval_ms * NSEC_PER_MSEC);
	src_load = READ_ONCE(cid_pack(src_cid)->vsum_w);
	if (!src_load)
		return -1;

	TOUCH_ARENA();
	bpf_arena_for(i, 0, nr_cids) {
		u64 load, cap;
		u32 smt_rank = 0;
		s32 cid = i;

		if (cid == src_cid || !cid_valid(cid) || !cid_allowed(p, cid))
			continue;
		if (smt_whole_core && smt_enabled) {
			if (core_is_idle(cid))
				smt_rank = 0;
			else if (!cid_idle_test(cid))
				smt_rank = 1;
			else
				smt_rank = 2;
		}
		load = READ_ONCE(cid_pack(cid)->vsum_w);
		cap = READ_ONCE(cid_ctx(cid)->pressure_demand) &&
		      READ_ONCE(cid_ctx(cid)->pressure_valid) ?
			READ_ONCE(cid_ctx(cid)->busy_balance_cap) :
			cid_topo(cid)->cap;
		if (!cap)
			cap = cid_topo(cid)->cap;
		if (best < 0 || smt_rank < best_smt_rank ||
		    (smt_rank == best_smt_rank &&
		     (load * best_cap < best_load * cap ||
		      (load * best_cap == best_load * cap &&
		       smt_prefer(cid, best))))) {
			best = cid;
			best_load = load;
			best_cap = cap;
			best_smt_rank = smt_rank;
		}
	}
	if (best < 0)
		return -1;
	src_norm = src_load * 1024 / src_cap;
	if (src_norm * 100 <= best_load * 1024 / best_cap *
				 BUSY_BALANCE_IMBALANCE_PCT)
		return -1;

	/*
	 * detach_tasks() does not move more load than calculate_imbalance()
	 * requested, and relaxes that bound together with cache hotness after
	 * failed passes. Do the same for this single detached current task.
	 */
	move_budget = (src_load * best_cap - best_load * src_cap) /
		      (src_cap + best_cap);
	weight = tctx->se.vjoin_w;
	failed = READ_ONCE(cid_ctx(src_cid)->pressure_migrate_failed);
	if ((weight >> MIN(failed, 63U)) > move_budget ||
	    (task_hot(tctx, src_cid, best, now) &&
	     failed <= cache_nice_tries)) {
		WRITE_ONCE(cid_ctx(src_cid)->pressure_migrate_failed,
			   MIN(failed + 1, 255U));
		return -1;
	}
	WRITE_ONCE(cid_ctx(src_cid)->pressure_migrate_failed, 0);
	return best;
}

/*
 * The scale cpu.weight is written on: what a cgroup nobody has touched
 * carries.
 */
#define CGROUP_WEIGHT_DFL	100

/*
 * The load weight of a group written @weight in cpu.weight,
 * sched_weight_from_cgroup():
 *
 *	return DIV_ROUND_CLOSEST_ULL(cgrp_weight * 1024, CGROUP_WEIGHT_DFL);
 */
static u64 cgrp_load_weight(u32 weight)
{
	u64 w = ((u64)weight * NICE_0_WEIGHT + CGROUP_WEIGHT_DFL / 2) /
		CGROUP_WEIGHT_DFL;

	return w ? w : 1;
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
 * A task in a cgroup weighs its nice weight against the other members of its
 * group on the cid, and what EEVDF charges and orders it by is its share of
 * the whole hierarchy, cached in @tctx, see task_h_refresh().
 */
static u64 task_nice_weight(const struct task_struct *p)
{
	u32 idx;

	if (p->policy == SCHED_IDLE)
		return WEIGHT_IDLEPRIO;

	idx = p->static_prio - MAX_RT_PRIO;
	return idx < ARRAY_SIZE(prio_to_weight) ? prio_to_weight[idx] :
						   NICE_0_WEIGHT;
}

static u64 task_weight(const struct task_struct *p, const task_ctx_t *tctx)
{
	if (tctx && tctx->grp && tctx->se.vw)
		return tctx->se.vw;

	return task_nice_weight(p);
}

/*
 * Approximate task_h_load() with the execution-utilization average cidland
 * already maintains for capacity placement. A task that sleeps most of the
 * time still weighs less than a CPU-bound task, while WA_WEIGHT adds no second
 * running average to every runnable/quiescent transition. Unlike fair's
 * runnable PELT, execution utilization can understate a task delayed by
 * contention; WA_BIAS and the cid load comparison keep the previous cid
 * preferred in the close cases where that distinction matters.
 */
static u64 task_load(const struct task_struct *p, task_ctx_t *tctx, u64 now)
{
	u64 util = READ_ONCE(tctx->util_est);

	/* Approximate PELT decay while a sleeping task receives no callbacks. */
	if (!scx_bpf_task_running(p) && time_after(now, tctx->last_sleep_at))
		util >>= MIN((now - tctx->last_sleep_at) / UTIL_HALF_LIFE_NS, 63ULL);

	return task_weight(p, tctx) * MIN(util, 1024) / 1024;
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

/* Project the running entity's vruntime to @now. */
static u64 curr_vruntime_at(pack_t *pk, u64 now)
{
	u64 run_at = pk->curr_run_at;

	if (time_before(now, run_at))
		now = run_at;

	return pk->curr_v + (now - run_at) * NICE_0_WEIGHT / pk->curr_w;
}

/*
 * Return @p's virtual service in the coordinate shared by contenders on an
 * SMT core. Core scheduling compares tasks selected independently by two cid
 * runqueues, so their absolute vruntimes are meaningful only relative to the
 * epoch in which their pack has stayed non-empty. Snapshot a new origin after
 * the pack empties; continuous contenders then accumulate service from
 * comparable zeroes, while a task entering a reused cid does not inherit the
 * old pack's coordinate.
 *
 * Unlike fair.c's zero_vruntime_fi, sched_ext is not told when forced idle
 * starts or ends. This is therefore an ABI-free approximation: the empty
 * generation supplies a stable epoch, and the running task is projected to
 * @now because ops.stopping() has not charged its latest service yet.
 */
static u64 core_vruntime(const struct task_struct *p, task_ctx_t *tctx, u64 now)
{
	pack_t *pk = tctx->se.vpack;
	struct core_sched_state __arena *state;
	u64 gen, zero, v = tctx->se.vruntime;

	if (!pk)
		return v;
	state = &core_sched_states[pk->cid];

	gen = READ_ONCE(pk->empty_gen) + 1;
	if (READ_ONCE(state->gen) != gen) {
		WRITE_ONCE(state->vzero, READ_ONCE(pk->vref));
		WRITE_ONCE(state->gen, gen);
	}
	zero = READ_ONCE(state->vzero);

	if (scx_bpf_task_running(p) && READ_ONCE(pk->curr_w))
		v = curr_vruntime_at(pk, cid_clock_task_at(pk->cid, now));

	return v - zero;
}

bool BPF_STRUCT_OPS(cidland_core_sched_before, struct task_struct *a,
			   struct task_struct *b)
{
	task_ctx_t *at, *bt;
	u64 av, bv, now;
	bool ar, br;

	TOUCH_ARENA();
	at = try_lookup_task_ctx(a);
	bt = try_lookup_task_ctx(b);
	if (!at || !bt || !at->se.vpack || !bt->se.vpack) {
		ar = scx_bpf_task_running(a);
		br = scx_bpf_task_running(b);
		if (ar != br)
			return !ar;
		return time_before(a->scx.runnable_at, b->scx.runnable_at);
	}

	now = scx_bpf_now();
	av = core_vruntime(a, at, now);
	bv = core_vruntime(b, bt, now);

	return time_before(av, bv);
}

/*
 * Give the entity just picked the protection set_protect_slice() gives
 * fair.c's current entity. The EDQ augmentation supplies the shortest
 * queued request, so protection is bounded by the smallest competitor
 * instead of always extending to the current entity's deadline.
 */
static void set_protect_slice(pack_t *pk, u64 weight)
{
	u64 slice = pk->curr_request, min_slice;
	u64 vprot = pk->curr_dl;

	if (no_run_to_parity) {
		pk->curr_vprot = pk->curr_v;
		return;
	}

	if (!scx_edq_min_slice(&pk->edq, &min_slice) && min_slice < slice)
		slice = min_slice;
	if (slice != pk->curr_request) {
		u64 limit = pk->curr_v +
			slice * NICE_0_WEIGHT / weight;

		if (time_before(limit, vprot))
			vprot = limit;
	}
	pk->curr_vprot = vprot;
}

/* Never let concurrent wakeups move the protection endpoint forward. */
static void shorten_protect_slice(pack_t *pk, u64 vprot)
{
	u64 old = READ_ONCE(pk->curr_vprot);

	while (time_before(vprot, old) && can_loop) {
		u64 prev = cmpxchg(&pk->curr_vprot, old, vprot);

		if (prev == old)
			return;
		old = prev;
	}
}

/*
 * A wakeup which does not win the pick can still shorten the current
 * entity's protection. fair.c does this after pick_next_entity() returns a
 * different entity: vprot never moves forward, and is clipped to one minimum
 * competing request beyond the current vruntime.
 */
static void update_protect_slice(pack_t *pk, u64 now, u64 wakee_slice,
				 u64 queued_min_slice)
{
	u64 slice = MIN(pk->curr_request, wakee_slice);
	u64 vprot;

	if (no_run_to_parity || no_eligibility || !pk->curr_w)
		return;
	if (queued_min_slice && queued_min_slice < slice)
		slice = queued_min_slice;
	vprot = curr_vruntime_at(pk, now) +
		slice * NICE_0_WEIGHT / pk->curr_w;
	shorten_protect_slice(pk, vprot);
}

static void cancel_protect_slice(pack_t *pk, u64 now)
{
	if (pk->curr_w)
		shorten_protect_slice(pk, curr_vruntime_at(pk, now));
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
	 * The due time is taken on the rq clock itself: the offset is only
	 * sampled when a task stops, and with IRQ time accounted apart it can
	 * be milliseconds stale by now.
	 */
	cctx->hrtick_due = scx_bpf_now() + delta;
	cctx->hrtick_run_at = cctx->pack.curr_run_at;

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
 * company and its hrtick is due, hrtick() in core.c:
 *
 *	rq->donor->sched_class->task_tick(rq, rq->donor, 1);
 *
 * The timer was armed for the deadline of whatever was running when it
 * was armed, or earlier, see hrtick_start(). If it is early for the run it
 * was armed for, or the cid has since picked something else whose deadline
 * is still ahead, arm it again for that, which can be done from here
 * directly, interrupts being on.
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

	/*
	 * The due time stands for the run it was armed for: that run is asked
	 * to reschedule when it comes, whatever its task clock reads by then,
	 * as entity_tick() does for a queued tick. A timer left from another
	 * run, which fair.c would have cancelled at the switch, measures the
	 * running task's own distance to its deadline instead.
	 */
	if (cctx->hrtick_run_at == cctx->pack.curr_run_at)
		delta = (s64)(cctx->hrtick_due - now);
	else
		delta = curr_dl_in(&cctx->pack, now - cctx->clock_off);
	if (delta > (s64)HRTICK_MIN_NS) {
		cctx->hrtick_at = now + delta;
		bpf_timer_start(&ht->timer, delta, 0);
		return 0;
	}

	scx_bpf_kick_cid(cid, SCX_KICK_PREEMPT);
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
static __noinline bool move_first_eligible_to_local(s32 cid, u64 tnow,
						   bool strict)
{
	TOUCH_ARENA();
	return cid_edq_move_first_eligible_to_local(
		cid, pack_vref_place(cid_pack(cid), tnow), strict);
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
 * The deadline of the task @pk would pick from its queue at @now, the
 * earliest one among those eligible, which is what pick_eevdf() searches
 * the tree for:
 *
 *	if (left && vruntime_eligible(cfs_rq,
 *				__node_2_se(left)->min_vruntime)) {
 *		node = left;
 *		continue;
 *	}
 *	se = __node_2_se(node);
 *	if (entity_eligible(cfs_rq, se)) {
 *		best = se;
 *		break;
 *	}
 *
 * or false when nothing queued is eligible. Take the exact eligible pick and
 * minimum slice when the EDQ lock is immediately available. A remote balance
 * operation can hold the independent EDQ lock while this callback owns the
 * runqueue; do not spin behind it. Fall back to the lockless queue head and
 * cached minimum instead. The head can be ineligible, which conservatively
 * suppresses a preemption rather than letting a wakee bypass queued work.
 */
static bool pack_pick_head_dl(pack_t *pk, u64 now, u64 *dlp,
			      u64 *min_slice)
{
	int ret;

	if (no_eligible_scan || no_eligibility) {
		*min_slice = 0;
		return !scx_edq_first_deadline(&pk->edq, dlp);
	}

	ret = scx_edq_try_first_eligible_deadline(&pk->edq,
						pack_vref_place(pk, now), dlp,
						min_slice);
	if (ret == -EBUSY) {
		scx_edq_min_slice(&pk->edq, min_slice);
		return !scx_edq_first_deadline(&pk->edq, dlp);
	}

	return !ret;
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
	u64 dl, head_dl, min_slice;

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
	/* Nothing queued is eligible: pick_eevdf() returns curr. */
	if (!pack_pick_head_dl(pk, now, &head_dl, &min_slice))
		return true;

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
 * Bring the lag and the deadline of @tctx over to the weight @w, the part of
 * reweight_task() that is not about the pack, see there.
 */
static void task_rescale(task_ctx_t *tctx, u64 w)
{
	sched_ent_t *se = &tctx->se;
	u64 old = se->vw;

	if (w == old)
		return;
	se->vw = w;
	if (!old)
		return;

	se->vlag = vdiv(se->vlag * (s64)old, w);
	if (se->deadline && time_before(se->vruntime, se->deadline))
		se->deadline = se->vruntime + (se->deadline - se->vruntime) * old / w;
}

/*
 * The weight the task of @tctx will have in @cid's pack once it has joined
 * it: its nice weight, or its share of its group hierarchy on @cid.
 */
static u64 task_join_weight(const struct task_struct *p, const task_ctx_t *tctx,
			    s32 cid)
{
	u64 w = task_nice_weight(p);

	if (!tctx->grp)
		return w;
	if (tctx->gq == &tctx->grp[cid])
		return grp_h_weight(tctx->gq, tctx->gw, false);

	return grp_h_weight(&tctx->grp[cid], w, true);
}

/*
 * Return true if the task of @tctx is in an idle cgroup or under one,
 * cfs_rq_is_idle() on the way up enqueue_hierarchy(). A group has the same
 * ancestors on every cid, so the chain of the first one stands for all.
 */
static bool task_in_idle_cgroup(const task_ctx_t *tctx)
{
	grp_q_t *gq = tctx->grp;
	int i;

	for (i = 0; gq && i < GRP_MAX_DEPTH; i++) {
		if (READ_ONCE(gq->hdr->idle))
			return true;
		gq = gq->parent;
	}

	return false;
}

/*
 * Charge @delta to the cgroup of @tctx for the time it ran on @cid.
 *
 * @delta is the cid's task clock, what fair.c charges from rq_clock_task, and
 * the period it counts against is wall time: a group is held to its quota of
 * the time it is given, not of the time the CPU spends elsewhere.
 */
static void task_bw_charge(task_ctx_t *tctx, s32 cid, u64 delta)
{
	if (!bw_enabled() || !tctx->grp || !cid_valid(cid) || !delta)
		return;

	grp_bw_charge(&tctx->grp[cid], delta, scx_bpf_now());
}

/*
 * The nearest group at or above the one @tctx is in on @cid that has run out
 * of bandwidth, NULL when none has: a group that is out of bandwidth takes
 * everything under it with it, as a throttled cfs_rq does.
 *
 * Periods turn over here as well as on the charge, so that a group whose tasks
 * are all waiting, and which therefore charges nothing, is found runnable
 * again by the first of them to ask.
 */
static struct grp_hdr __arena *task_bw_throttled(task_ctx_t *tctx, s32 cid, u64 now)
{
	grp_q_t *gq;
	int i;

	if (!bw_enabled() || !tctx->grp || !cid_valid(cid))
		return NULL;

	gq = &tctx->grp[cid];
	for (i = 0; gq && i < GRP_MAX_DEPTH; i++, gq = gq->parent) {
		struct grp_hdr __arena *hdr = gq->hdr;

		if (!hdr || !grp_bw_limited(hdr))
			continue;
		grp_bw_refill(hdr, now);
		if (READ_ONCE(hdr->throttled))
			return hdr;
	}

	return NULL;
}

/*
 * Take @tctx out of its pack's reference and out of its group's load, the
 * two memberships a task has on a cid and gives up together.
 */
static void task_vref_leave(task_ctx_t *tctx)
{
	grp_q_t *gq = tctx->gq;

	vref_leave(&tctx->se);
	if (gq) {
		tctx->gq = NULL;
		grp_load_add(gq, -(s64)tctx->gw);
		grp_nr_add(gq, -1);
	}
}

/*
 * Make @p a member of its pack on @cid, leaving the one it was in, see
 * vref_join(), and of its group's load there. A task in a group joins at the
 * share its group then gives it, and its lag and deadline follow.
 */
static void task_vref_join(s32 cid, const struct task_struct *p,
			   task_ctx_t *tctx)
{
	pack_t *pk = cid_valid(cid) ? task_pack(tctx, cid) : NULL;
	u64 w;

	if (tctx->se.vpack == pk)
		return;
	task_vref_leave(tctx);

	if (!pk)
		return;
	if (tctx->grp) {
		tctx->gw = task_nice_weight(p);
		tctx->gq = &tctx->grp[cid];
		grp_load_add(tctx->gq, tctx->gw);
		grp_nr_add(tctx->gq, 1);
		w = grp_h_weight(tctx->gq, tctx->gw, false);
		task_rescale(tctx, w);
	} else {
		w = task_weight(p, tctx);
	}
	vref_join(pk, &tctx->se, w);
}

/*
 * Bring a member of a pack over to the share its group hierarchy gives it
 * now, which moves with every task that joins or leaves the groups above
 * it on the cid: the entity leaves the pack's reference and joins it again
 * at the new weight with its lag carried over, reweight_eevdf(), which
 * fair.c runs on enqueue, set_next_task() and the tick. @now is on the rq
 * clock.
 */
static void task_h_refresh(task_ctx_t *tctx, u64 now)
{
	sched_ent_t *se = &tctx->se;
	pack_t *pk = se->vpack;
	u64 w, old, tnow, vref;
	s64 lag;

	if (!tctx->gq || !pk)
		return;
	w = grp_h_weight(tctx->gq, tctx->gw, false);
	old = se->vjoin_w;
	if (w == old || !old)
		return;

	tnow = cid_clock_task_at(pk->cid, now);
	vref = pack_vref_place(pk, tnow);
	lag = vdiv((s64)(vref - se->vruntime) * (s64)old, w);
	vref_leave(se);
	task_rescale(tctx, w);
	se->deadline = se->deadline && time_before(se->vruntime, se->deadline) ?
		       vref - lag + (se->deadline - se->vruntime) : 0;
	se->vruntime = vref - lag;
	vref_join(pk, se, w);
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
	u64 delta, weight;
	pack_t *pk;

	if (!tctx)
		return;
	pk = task_pack(tctx, cid);

	delta = now - tctx->last_run_at;
	task_bw_charge(tctx, cid, delta);
	tctx->se.vruntime += calc_delta_fair(p, tctx, delta);
	tctx->last_run_at = now;
	vref_charge(&tctx->se);

	pk->curr_dl = task_dl(p, tctx);
	pk->curr_v = tctx->se.vruntime;
	pk->curr_run_at = now;
	pk->curr_request = task_request(p);
	weight = task_weight(p, tctx);
	set_protect_slice(pk, weight);
	pk->curr_w = weight;
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
		u64 w = task_join_weight(p, tctx, cid);
		u64 vruntime;

		/* The lag is carried at the weight the task is placed with. */
		task_rescale(tctx, w);
		vruntime = pack_vref_before_join(pk, &tctx->se, w, tnow);

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
	u64 w, old = tctx->se.vw;
	s32 cid = scx_bpf_task_cid((struct task_struct *)p);

	/*
	 * A task in a group first changes what it weighs in its group, and
	 * then takes the share that gives it.
	 */
	if (tctx->gq) {
		u64 nice_w = task_nice_weight(p);

		grp_load_add(tctx->gq, (s64)nice_w - (s64)tctx->gw);
		tctx->gw = nice_w;
		w = grp_h_weight(tctx->gq, nice_w, false);
	} else if (tctx->grp && cid_valid(cid)) {
		w = grp_h_weight(&tctx->grp[cid], task_nice_weight(p), true);
	} else {
		w = task_nice_weight(p);
	}

	if (w == old)
		return;
	if (dequeued && tctx->se.vpack)
		tctx->se.vlag = task_lag_at(p, tctx, tctx->se.vpack, scx_bpf_now());
	task_rescale(tctx, w);

	if (!dequeued || !old)
		return;
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
	 * A task whose cgroup is out of bandwidth waits for its next period,
	 * see cid_park(). Nothing below is of any use to it: the shortcuts
	 * here put a task straight onto a cid to run there, and an idle cid
	 * woken for a task that may not run goes back to sleep having done
	 * nothing. Leave it where it is and let ops.enqueue() put it aside.
	 */
	if (task_bw_throttled(tctx, prev_cid, now))
		return prev_cid;

	/*
	 * A task that blocked over-served and is still owed to the pack it
	 * left goes back to it, the way ttwu_runnable() requeues a delayed
	 * task on its runqueue before select_task_rq() is ever asked.
	 */
	cid = delay_requeue_cid(p, tctx, now);
	if (cid >= 0)
		return cid;

	/*
	 * Follow select_task_rq_fair()'s SD_BALANCE_FORK slow path before its
	 * wakeup-only fast path. A fork is placed by load; fair.c never calls
	 * select_idle_sibling() for it. Running the idle scan first made this
	 * fallback unreachable on an idle machine and packed every child near
	 * its parent.
	 */
	if (wake_flags & SCX_WAKE_FORK) {
		cid = find_idlest_fork_cid(p,
					   cid_valid(this_cid) ? this_cid : prev_cid,
					   now);
		if (cid >= 0)
			return cid;
	}

	/*
	 * Follow select_task_rq_fair()'s WF_TTWU fast path: wake_affine()
	 * computes a target, then select_idle_sibling() looks around it. An
	 * affine target is not itself a selection; if it is busy, an idle
	 * previous cid or an idle sibling still wins.
	 */
	target = wake_affine_cid(p, tctx, prev_cid, this_cid, wake_flags, now);
	if (wake_flags & SCX_WAKE_TTWU) {
		cid = select_idle_sibling_cid(p, tctx, prev_cid, target, &direct,
					      now);
		if (cid >= 0) {
			if (direct)
				direct_dispatch_local(p, tctx, cid, now);
			return cid;
		}
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
 * deadline, which is what makes it the pick. set_protect_slice() gives the
 * running task an explicit virtual-time protection bounded by the shortest
 * request in the queue. A normal wakeup that does not win the pick clips the
 * endpoint again through update_protect_slice(), including the new wakee's
 * request even though it has not entered the EDQ yet. The EDQ's augmented
 * minimum makes both operations constant time.
 *
 * Eligibility still comes first: once the current entity has been served
 * past the average of its pack, pick_eevdf() drops it before testing its
 * protection. PREEMPT_SHORT does the inverse for an eligible shorter wakee:
 * it cancels the endpoint before requesting preemption. What the running
 * task gives up is protected service, not its place in the order; it keeps
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
				      u64 now, bool *cancel_protect)
{
	struct cid_ctx __arena *cctx;
	bool owed, p_idle, has_head;
	u64 head_dl, min_slice = 0;
	pack_t *pk;

	if (cid_idle_test(cid))
		goto idle;
	*cancel_protect = false;

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
	if (cctx->curr_idle && !p_idle) {
		*cancel_protect = true;
		goto preempt;
	}
	if (p_idle || p->policy == SCHED_BATCH)
		goto queued;

	/*
	 * Take the eligible head and the queue's shortest request under the
	 * same EDQ lock. Even when the current entity keeps the CPU, the latter
	 * is needed to apply update_protect_slice().
	 */
	has_head = pack_pick_head_dl(pk, now, &head_dl, &min_slice);

	/*
	 * The queued task has to be owed service to be a candidate at all:
	 * pick_eevdf() only ever looks at the eligible part of the tree.
	 */
	if (!no_eligibility &&
	    time_after(tctx->se.vruntime, pack_vref_place(pk, now)))
		goto update;

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
	    pk->curr_w) {
		*cancel_protect = true;
		goto preempt;
	}

	/*
	 * Is the running task still owed service? Once it has run for a
	 * whole request it is past its deadline as well, and either way it
	 * has no protection left. This is the half of the pick that
	 * RUN_TO_PARITY governed, and --no-run-to-parity drops it alone.
	 */
	owed = !no_eligibility && curr_owed_service(pk, now);
	if (owed && !no_run_to_parity &&
	    time_before(curr_vruntime_at(pk, now), pk->curr_vprot))
		goto update;

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
		goto update;

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
	 * it. The next pick is the earliest deadline among the queued tasks that
	 * are eligible, see pack_pick_head_dl(), so the woken task must have a
	 * strictly earlier deadline than that one. An ineligible task with an
	 * earlier deadline is skipped, as pick_eevdf() skips it. A task already
	 * queued is not displaced by one that ties it.
	 * A preemption for a task that queues behind others only trades the
	 * running task for the head a slice early, once for
	 * every wakeup that lands in the queue: with sixteen tasks queued per
	 * CPU that was one context switch in three, and perf bench sched
	 * messaging ran at half its speed.
	 */
	if (has_head) {
		bool loses = !time_before(dl, head_dl);

		if (loses)
			goto update;
	}

preempt:
	return true;
update:
	update_protect_slice(pk, now, tctx->se.request, min_slice);
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

/*
 * How long the timer waits when a group is already owed its tasks back but
 * the drain has not managed it yet.
 */
#define BW_TIMER_MIN_NS		NSEC_PER_MSEC

/*
 * Arm the timer for the first period that ends among the groups with tasks
 * waiting. bpf_timer_start() moves an armed timer, and the earliest deadline
 * is recomputed every time, so this can be called from anywhere that parks a
 * task or refills a group.
 */
static void bw_timer_arm(u64 now)
{
	struct bw_timer *bt;
	u64 next = 0, delta;
	u32 slot, key = 0;
	bool locked;

	/*
	 * The walk reads blocks ops.cpuctl_exit() may be freeing, and the
	 * sweep lock is what keeps one alive across that, see grp_free_defer().
	 * Without it, arm for the shortest wait and work the deadline out on
	 * the next pass rather than touching a block that may be gone.
	 */
	locked = __sync_val_compare_and_swap(&grp_sweep_lock, 0, 1) == 0;
	if (!locked)
		goto arm;

	bpf_for(slot, 0, bw_hdrs_nr) {
		struct grp_hdr __arena *hdr;
		u64 due;

		hdr = (struct grp_hdr __arena *)READ_ONCE(bw_hdrs[slot & (BW_MAX_LIMITED - 1)]);
		if (!hdr || !READ_ONCE(hdr->nr_parked))
			continue;
		due = READ_ONCE(hdr->throttled) ?
		      READ_ONCE(hdr->period_start) + READ_ONCE(hdr->period) : now;
		if (!next || time_before(due, next))
			next = due;
	}
	WRITE_ONCE(grp_sweep_lock, 0);
	if (!next)
		return;

arm:
	bt = bpf_map_lookup_elem(&bw_timers, &key);
	if (!bt)
		return;
	delta = locked && time_before(now, next) ? next - now : BW_TIMER_MIN_NS;
	bpf_timer_start(&bt->timer, MAX(delta, BW_TIMER_MIN_NS), 0);
}

/*
 * Tell one idle cid to go through ops.dispatch(), where the tasks that may run
 * again are let go. Nothing to do when no cid is idle: every one of them
 * dispatches by the end of the slice it is running.
 */
static void bw_kick_idle(void)
{
	u32 words = (nr_cids + 63) / 64, k;

	bpf_for(k, 0, words) {
		u64 w = cmask_word(idle_cids, k);

		if (!w)
			continue;
		scx_bpf_kick_cid(k * 64 + __builtin_ctzll(w), SCX_KICK_IDLE);
		return;
	}
}

/*
 * The first period among the groups with tasks waiting has ended: turn over
 * the ones that are due and see that somebody goes and lets their tasks run.
 */
static int bw_timer_fire(void *map, int *key, struct bw_timer *bt)
{
	u64 now = scx_bpf_now();
	bool runnable = false;
	u32 slot;

	TOUCH_ARENA();

	/* Same blocks, same reason as bw_timer_arm(): come back if it is busy. */
	if (__sync_val_compare_and_swap(&grp_sweep_lock, 0, 1) != 0) {
		struct bw_timer *bt;
		u32 key = 0;

		bt = bpf_map_lookup_elem(&bw_timers, &key);
		if (bt)
			bpf_timer_start(&bt->timer, BW_TIMER_MIN_NS, 0);
		return 0;
	}

	bpf_for(slot, 0, bw_hdrs_nr) {
		struct grp_hdr __arena *hdr;

		hdr = (struct grp_hdr __arena *)READ_ONCE(bw_hdrs[slot & (BW_MAX_LIMITED - 1)]);
		if (!hdr || !READ_ONCE(hdr->nr_parked))
			continue;
		grp_bw_refill(hdr, now);
		if (!READ_ONCE(hdr->throttled))
			runnable = true;
	}
	WRITE_ONCE(grp_sweep_lock, 0);

	if (runnable)
		bw_kick_idle();
	bw_timer_arm(now);

	return 0;
}

/*
 * Put @p aside until the cgroup of @hdr has bandwidth again, which is what
 * dequeue_throttled_task() does to a task whose group has run out.
 *
 * It leaves its pack and its group's load on the way: a task waiting on a
 * period is not competing for the cid, and a weight left behind would move the
 * reference every other task there is measured against for as long as the
 * throttle lasts, and would be counted in the group's load and task count,
 * which its shares everywhere else are computed from.
 *
 * It waits in its cgroup's backlog rather than in the cid's queue: the pick
 * descends an AVL tree by deadline, pruning on the least eligible vruntime of
 * a subtree, and has no way to step over a task, so a task that may not run
 * has to be somewhere else. The backlog is ordered by the vruntime it stopped
 * at, so the least served of the group's tasks is the first to go back.
 */
static bool cid_park(struct task_struct *p, task_ctx_t *tctx,
		     struct grp_hdr __arena *hdr, s32 cid)
{
	cid_edq_task_t *at = cid_edq_task(tctx);
	int ret;

	/*
	 * A node an older workflow still holds, or one already in a queue, is
	 * not ours to move; the task runs this once more and is parked at its
	 * next enqueue.
	 */
	if (!at || READ_ONCE(at->common.holdcnt) ||
	    READ_ONCE(at->state) == CID_EDQ_ENQUEUED)
		return false;

	/*
	 * A task on its way out is not held to a limit. cidland asks for
	 * exiting tasks with SCX_OPS_ENQ_EXITING so that it can get them off
	 * the machine, and making one wait a period for a cgroup it is leaving
	 * anyway works against that. fair.c has nothing to hold back either:
	 * the task is dequeued for good rather than put on a throttled list.
	 */
	if (p->flags & PF_EXITING)
		return false;

	task_vref_leave(tctx);
	/* A debt to a pack it may not come back to for a period is forgiven. */
	tctx->delay_cid = -1;

	at->slice = task_request(p);
	at->enq_flags = 0;
	at->cid = cid;
	WRITE_ONCE(at->state, CID_EDQ_PARKED);
	ret = scx_edq_insert(&hdr->bq, &at->common, tctx->se.vruntime,
			      tctx->se.vruntime, at->slice);
	if (ret) {
		__sync_val_compare_and_swap(&at->state, CID_EDQ_PARKED,
					    CID_EDQ_NONE);
		scx_bpf_error("cpu.max park failed for pid %d: %d", p->pid, ret);
		return false;
	}

	tctx->bw_hdr = hdr;
	__sync_fetch_and_add(&hdr->nr_parked, 1);
	__sync_fetch_and_add(&bw_nr_parked, 1);

	/* Somebody has to come back for it if every cid goes to sleep. */
	bw_timer_arm(scx_bpf_now());

	return true;
}

/*
 * Let one task of @hdr run again: take it out of the backlog and put it
 * through placement and the queue of the cid the kernel has it on, the way a
 * task that slept through the throttle would come back. It is placed as a
 * sleeper, since that is what it was: it was out of the pack for the whole
 * period, and the lag it left with is stale by that much.
 *
 * Returns whether the backlog had anything, not whether the task was requeued:
 * one that left in the meantime is simply gone from it.
 */
static __noinline bool bw_unpark_one(struct grp_hdr __arena *hdr, u64 now)
{
	struct grp_hdr __arena *out;
	struct task_struct *p;
	cid_edq_task_t *at;
	task_ctx_t *tctx;
	s32 cid;

	at = (cid_edq_task_t *)scx_edq_pop(&hdr->bq, true);
	if (!at)
		return false;

	/*
	 * The node is the front of the context that embeds it, so the task it
	 * belongs to is reached without a lookup, and the accounting is settled
	 * by whoever took it out of the queue: here, or ops.dequeue().
	 */
	tctx = (task_ctx_t *)at;
	task_bw_unparked(tctx);

	/* Somebody else ended this enqueue workflow while it waited. */
	if (__sync_val_compare_and_swap(&at->state, CID_EDQ_PARKED,
					CID_EDQ_NONE) != CID_EDQ_PARKED)
		goto drop;

	p = scx_bpf_tid_to_task(at->tid);
	if (!p) {
		scx_bpf_error("cpu.max cannot resolve parked tid %llu", at->tid);
		goto drop;
	}
	if (!is_task_queued(p))
		goto drop;
	cid = scx_bpf_task_cid(p);
	if (!cid_valid(cid))
		goto drop;

	/*
	 * The task waited on the nearest group that had run out, and a group
	 * above that one can have run out since, or still be out. Ask the whole
	 * chain again rather than the one backlog it came from, or a child
	 * would run while an ancestor is throttled until the tick noticed.
	 */
	out = task_bw_throttled(tctx, cid, now);
	if (out) {
		scx_edq_task_drop(&at->common);
		cid_park(p, tctx, out, cid);
		return true;
	}

	/* The node has to be free of holds before it can be queued again. */
	scx_edq_task_drop(&at->common);

	place_task(cid, p, tctx, now, true);
	if (!cid_queue_insert(p, tctx, cid, task_request(p), task_dl(p, tctx),
			      tctx->se.vruntime, 0))
		return true;
	cid_queued_set(cid);
	if (cid != scx_bpf_this_cid())
		scx_bpf_kick_cid(cid, SCX_KICK_IDLE);

	return true;
drop:
	scx_edq_task_drop(&at->common);
	return true;
}


/*
 * How many tasks one pass lets go at a time. A period's worth of them can be
 * waiting, and requeueing all of them from a single dispatch would hold the
 * cid that happened to run it for as long as it takes.
 */
#define BW_UNPARK_BATCH		4

/*
 * Give back the tasks of every group that has bandwidth again.
 *
 * One cid at a time: the walk reads cgroup blocks that ops.cpuctl_exit() may
 * be freeing, and the sweep lock is what keeps a block alive across that, see
 * grp_free_defer(). Whoever does not get it goes on with its own queue and
 * leaves the work to the next dispatch or to the timer.
 */
__noinline int bw_unpark(u64 now)
{
	u32 slot, n = 0;

	TOUCH_ARENA();

	if (!READ_ONCE(bw_nr_parked) ||
	    __sync_val_compare_and_swap(&grp_sweep_lock, 0, 1) != 0)
		return 0;

	bpf_for(slot, 0, bw_hdrs_nr) {
		struct grp_hdr __arena *hdr;

		if (n >= BW_UNPARK_BATCH)
			break;
		hdr = (struct grp_hdr __arena *)READ_ONCE(bw_hdrs[slot & (BW_MAX_LIMITED - 1)]);
		if (!hdr)
			continue;
		if (!READ_ONCE(hdr->nr_parked)) {
			/* Nothing is left waiting on a cpu.max that is gone. */
			if (!grp_bw_limited(hdr))
				grp_bw_unregister(hdr);
			continue;
		}
		grp_bw_refill(hdr, now);
		if (READ_ONCE(hdr->throttled))
			continue;
		while (READ_ONCE(hdr->nr_parked) && n < BW_UNPARK_BATCH && can_loop) {
			if (!bw_unpark_one(hdr, now))
				break;
			n++;
		}
	}

	if (READ_ONCE(grp_free_head))
		grp_free_drain();
	WRITE_ONCE(grp_sweep_lock, 0);

	return 0;
}

void BPF_STRUCT_OPS(cidland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cid = scx_bpf_task_cid(p), cid;
	struct grp_hdr __arena *hdr;
	task_ctx_t *tctx;
	bool displaced, pressure_migrate;
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
	 * A task whose cgroup is out of bandwidth waits for its next period
	 * instead of being queued. This is before every shortcut below, which
	 * all put the task somewhere it would run from.
	 */
	hdr = task_bw_throttled(tctx, prev_cid, now);
	if (hdr && cid_park(p, tctx, hdr, prev_cid)) {
		tctx->dispatch_migrate_cid = -1;
		tctx->pressure_migrate = false;
		if (displaced)
			cid_queued_check(prev_cid);
		return;
	}

	/*
	 * An idle preferred destination asked @prev_cid for this running task.
	 * The source dispatch validated the request and let its slice expire;
	 * ops.stopping() has charged the service since then. Honor the handoff if
	 * the destination is still idle, otherwise use ordinary placement.
	 */
	cid = tctx->dispatch_migrate_cid;
	tctx->dispatch_migrate_cid = -1;
	pressure_migrate = tctx->pressure_migrate;
	tctx->pressure_migrate = false;
	if (!(enq_flags & SCX_ENQ_WAKEUP) && pressure_migrate &&
	    cid_valid(cid) && cid != prev_cid && cid_allowed(p, cid)) {
		place_task(cid, p, tctx, now, false);
		dl = task_dl(p, tctx);
		if (cid_queue_insert(p, tctx, cid, task_request(p), dl,
				     tctx->se.vruntime, enq_flags)) {
			cid_queued_set(cid);
			if (cid_idle_test(cid))
				scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
		}
		if (displaced) {
			cid_queued_check(prev_cid);
			cid_pressure_resumed(prev_cid,
				cid_clock_task_owned(prev_cid, now));
			cid_demand_set(prev_cid, cid_queue_nr(prev_cid) > 0, now);
		}
		return;
	}
	if (!(enq_flags & SCX_ENQ_WAKEUP) && cid_valid(cid) && cid != prev_cid &&
	    cid_idle_test(cid) && cid_allowed(p, cid)) {
		cid = claim_idle_cid(p, cid);
		if (cid >= 0) {
			place_task(cid, p, tctx, now, false);
			cid_edq_mark_dispatched(tctx);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid,
					   task_request(p), enq_flags | SCX_ENQ_IMMED);
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
	    (reenq_preempted(p, enq_flags) && p->scx.slice &&
	     !cid_idle_test(prev_cid))) {
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
	 * deadline. pick_eevdf() leaves it in the tree with the deadline of the
	 * request it has not finished and skips it while it is ineligible, and
	 * so does selection with the eligibility scan. Head-only selection,
	 * --no-eligible-scan, would pick it straight back and the task that
	 * displaced it would wait for the tick.
	 *
	 * There only, reissue its deadline from where its vruntime has reached,
	 * which is what update_deadline() does once a request is consumed. The
	 * vruntime is current: a running task reaches ops.enqueue() from
	 * put_prev_task_scx(), after ops.stopping() has charged the service
	 * it took, and charging it again here counted its last run twice.
	 * The published view of the cid is of no use for the same reason,
	 * ops.stopping() has cleared it, so the task is tested on its own
	 * vruntime against the reference, which is entity_eligible().
	 */
	if (displaced && !no_eligibility && no_eligible_scan &&
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
	if (!displaced) {
		bool cancel_protect = false;

		if (queued_cid_should_preempt(prev_cid, p, tctx, dl, tnow,
					      &cancel_protect) &&
		    !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | prev_cid)) {
			if (cancel_protect)
				cancel_protect_slice(task_pack(tctx, prev_cid),
						     tnow);
			cid_edq_mark_dispatched(tctx);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cid,
					   task_request(p),
					   enq_flags | SCX_ENQ_PREEMPT);
			return;
		}
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
 * Feed one scan result into fair.c's newidle success and call-rate
 * estimator. @success is one for an ordinary scan and its inverse sampling
 * weight for a scan admitted by newidle_should_scan().
 */
static void update_newidle_stats(s32 cid, u32 level, u32 success, u64 now)
{
	struct newidle_stats __arena *stats = &newidle_stats[cid];
	u64 delta, ratio;

	stats->call[level]++;
	stats->success[level] += success;
	if (stats->call[level] < 1024)
		return;

	delta = time_before(now, stats->stamp[level]) ? 0 :
		now - stats->stamp[level];
	stats->stamp[level] = now;

	/* NI_RATE: 4.194 ms between calls contributes one ratio point. */
	ratio = (delta >> 22) + stats->success[level];
	stats->ratio[level] = MIN(1024, ratio);
	stats->call[level] /= 2;
	stats->success[level] /= 2;
}

/*
 * NI_RANDOM: admit a scan in proportion to the success and call-rate ratio.
 * Return the inverse sampling weight used to account a successful scan.
 */
static bool newidle_should_scan(s32 cid, u32 level, u64 now, u32 *weight)
{
	struct newidle_stats __arena *stats = &newidle_stats[cid];
	u32 ratio = stats->ratio[level], sample;

	*weight = 1;
	if (ratio >= 1024)
		return true;

	sample = 1 + ratio;
	if ((bpf_get_prandom_u32() & 1023) > sample) {
		update_newidle_stats(cid, level, 0, now);
		return false;
	}

	*weight = (1024 + sample / 2) / sample;
	return true;
}

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
	bool queued;
	s32 cid = scx_bpf_this_cid(), peer;
	struct task_struct *head;
	u64 now, tid;

	TOUCH_ARENA();
	now = scx_bpf_now();

	if (!cid_valid(cid))
		return;
	topo = cid_topo(cid);

	/*
	 * The share a task's groups give it moves with the tasks that come and
	 * go in them: take the running task over to it, as task_tick_fair()
	 * does through update_cfs_group() and reweight_eevdf(), charging what it
	 * ran at the old weight first.
	 */
	if (cgroup_enabled) {
		task_ctx_t *tctx = try_lookup_task_ctx(p);
		grp_q_t *gq = tctx ? tctx->gq : NULL;
		int i;

		grp_sweep(now);

		/* update_cfs_group() for every level the task runs in. */
		for (i = 0; gq && i < GRP_MAX_DEPTH; i++) {
			grp_update_shares(gq, now);
			gq = gq->parent;
		}

		if (tctx && tctx->gq && tctx->se.vpack &&
		    grp_h_weight(tctx->gq, tctx->gw, false) != tctx->se.vjoin_w) {
			u64 tnow = cid_clock_task_owned(cid, now);

			keep_charge(p, cid, tnow);
			task_h_refresh(tctx, now);
			keep_charge(p, cid, tnow);
		}

		/*
		 * Bring the bandwidth of the groups it runs in up to date and
		 * end its slice if they have run out, entity_tick() asking
		 * check_cfs_rq_runtime(). The dispatch that follows the ended
		 * slice is where the task is actually given up, see
		 * cidland_dispatch(); doing it here only means a task is not
		 * left running a whole slice past a limit it has reached.
		 */
		if (bw_enabled() && tctx) {
			keep_charge(p, cid, cid_clock_task_owned(cid, now));
			if (task_bw_throttled(tctx, cid, now))
				scx_bpf_task_set_slice(p, 0);
		}
	}

	if (!no_newidle_cost)
		newidle_decay(cid_ctx(cid), now);
	cid_load_accumulate(cid, now);
	update_balance_cap(cid, now);

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
	queued = cid_queue_nr(cid);

	/*
	 * update_misfit_status() records the running task even when other work is
	 * queued, and nohz_balancer_kick() asks an idle CPU to run the
	 * group_misfit_task balance when nr_running >= 2. Do the equivalent from
	 * the source tick while @p is exact: a queued, pinned head must not hide a
	 * current task which needs a larger CPU. The destination still consumes
	 * and revalidates the request through active_balance_target(), preserving
	 * the deferred detach used by the other active-balance cases.
	 */
	if (asym_capacity && queued) {
		peer = idle_misfit_cid(p, cid, now);
		if (peer >= 0 && peer != cid && active_balance_reserve(peer, now)) {
			scx_bpf_kick_cid(peer, SCX_KICK_IDLE);
			return;
		}
	}
	if (!queued) {
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
	bool sample_newidle = newidle_sampling && !force_steal && !kicked;
	bool budget = false, node_skipped = false, system_skipped = false;
	bool scanned = false, admitted;
	u64 curr_cost = 0, t0 = 0;
	u32 weight;
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
		return false;
	}

	/*
	 * An idle cid walks its own LLC before the rest of the node and then
	 * the system, honouring hotness until it has failed often enough to
	 * stop. With NUMA disabled the node level covers the whole machine.
	 * A domain that is the whole of the next one is not walked twice.
	 */
	admitted = !sample_newidle ||
		newidle_should_scan(dst_cid, NEWIDLE_LLC, now, &weight);
	if (admitted) {
		u64 t1;

		scanned = true;
		if (nr_place_tiers > 1 &&
		    (!smt_enabled || core_is_idle(dst_cid))) {
			u32 t;

			/* Less-preferred tiers first, leaving hot tasks alone. */
			bpf_arena_for(t, 0, nr_place_tiers - topo->place_tier - 1) {
				src = steal_from_range(dst_cid,
						nr_place_tiers - 1 - t,
						node_base, node_nr, node_base,
						now, !force_steal &&
						failed <= cache_nice_tries,
						0xff);
				if (src >= 0)
					break;
			}
		}
		if (src < 0)
			src = steal_from_range(dst_cid, -1, topo->llc_base,
					       topo->llc_nr, start + 1, now,
					       !force_steal &&
					       failed <= cache_nice_tries,
					       0xff);

		t1 = (budget || sample_newidle) ? bpf_ktime_get_ns() : now;
		if (budget) {
			curr_cost = t1 - t0;
			update_newidle_cost(cctx, NEWIDLE_LLC, curr_cost, t1);
			t0 = t1;
		}
		if (sample_newidle)
			update_newidle_stats(dst_cid, NEWIDLE_LLC,
					     src >= 0 ? weight : 0, t1);
	}
	if (budget && node_nr > topo->llc_nr)
		node_skipped = cctx->avg_idle <
			       curr_cost + cctx->newidle_cost[NEWIDLE_NODE];
	if (src < 0 && node_nr > topo->llc_nr && !node_skipped) {
		admitted = !sample_newidle ||
			newidle_should_scan(dst_cid, NEWIDLE_NODE, now, &weight);
		if (admitted) {
			u64 t1, cost;

			scanned = true;
			src = steal_from_range(dst_cid, -1, node_base, node_nr,
					       start + 1, now,
					       !force_steal &&
					       failed <= cache_nice_tries + 1,
					       0xff);
			t1 = (budget || sample_newidle) ? bpf_ktime_get_ns() : now;
			if (budget) {
				cost = t1 - t0;
				curr_cost += cost;
				update_newidle_cost(cctx, NEWIDLE_NODE, cost, t1);
				t0 = t1;
			}
			if (sample_newidle)
				update_newidle_stats(dst_cid, NEWIDLE_NODE,
						     src >= 0 ? weight : 0, t1);
		}
	}
	if (budget && nr_cids > node_nr)
		system_skipped = node_skipped ||
			cctx->avg_idle <
			curr_cost + cctx->newidle_cost[NEWIDLE_SYSTEM];
	if (src < 0 && nr_cids > node_nr && !system_skipped) {
		admitted = !sample_newidle ||
			newidle_should_scan(dst_cid, NEWIDLE_SYSTEM, now, &weight);
		if (admitted) {
			u64 t1, cost;

			scanned = true;
			src = steal_from_range(dst_cid, -1, 0, nr_cids,
					       start + 1, now,
					       !force_steal &&
					       failed <= cache_nice_tries + 2,
					       0xff);
			t1 = (budget || sample_newidle) ? bpf_ktime_get_ns() : now;
			if (budget) {
				cost = t1 - t0;
				curr_cost += cost;
				update_newidle_cost(cctx, NEWIDLE_SYSTEM, cost, t1);
			}
			if (sample_newidle)
				update_newidle_stats(dst_cid, NEWIDLE_SYSTEM,
						     src >= 0 ? weight : 0, t1);
		}
	}
	if (curr_cost > cctx->max_idle_balance_cost)
		cctx->max_idle_balance_cost = curr_cost;

	if (scanned) {
		/* Nothing queued anywhere is a balanced system, not a failure. */
		if (src >= 0 || cmask_empty(queued_cids))
			cctx->nr_balance_failed = 0;
		else
			cctx->nr_balance_failed = failed + 1;
		cctx->steal_cursor = src >= 0 ? src : start + 1;
	}

own:
	if (src < 0 && own)
		src = dst_cid;

	if (src < 0)
		return false;

	/* Remote scans already validated, removed and dispatched one node. */
	if (src == dst_cid) {
		if (!((src == dst_cid && !no_eligible_scan && !no_eligibility) ?
		      move_first_eligible_to_local(src, cid_clock_task_at(src, now), has_prev) :
		      cid_queue_move_head_to_local(src))) {
			cid_queued_check(src);
			return false;
		}
	}
	cid_queued_check(src);

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
	scx_edq_cursor_t *cursor = &dst->busy_dispatch_cursor;
	u64 rival_dl = 0, head_dl = 0, min_slice;
	s32 owner = READ_ONCE(dst->busy_balance_owner);
	u32 level = READ_ONCE(dst->busy_balance_level);
	u32 failed = cid_valid(owner) && level < BUSY_BALANCE_LEVELS ?
		READ_ONCE(cid_ctx(owner)->busy_balance_failed[level]) : 0;
	bool rival = false;
	bool retry = false;
	u32 nth;

	if (has_prev && curr_pick_dl(cid_pack(dst_cid), tnow, &rival_dl))
		rival = true;
	if (cid_queued_test(dst_cid) &&
	    pack_pick_head_dl(&dst->pack, tnow, &head_dl, &min_slice) &&
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

		ret = edq_scan_next(src_cid, cursor, &at);
		if (ret)
			return ret == -EBUSY ? -EAGAIN : 0;
		if (!at) {
			if (!nth)
				cid_queued_check(src_cid);
			break;
		}
		weight = ((task_ctx_t *)at)->se.vjoin_w;
		if (READ_ONCE(at->state) != CID_EDQ_ENQUEUED ||
		    (weight >> MIN(failed, 63U)) >
			    READ_ONCE(dst->busy_balance_budget) ||
		    (task_hot((task_ctx_t *)at, src_cid, dst_cid, now) &&
		     failed <= cache_nice_tries)) {
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
		if (rival &&
		    ((!no_eligibility && lag < 0) || !time_before(dl, rival_dl))) {
			retry = true;
			scx_edq_task_drop(&at->common);
			continue;
		}
		ret = cid_edq_remove_held_to_local(src_cid, dst_cid, at, p);
		if (ret == CID_EDQ_MOVE_BUSY)
			return -EAGAIN;
		if (ret != CID_EDQ_MOVE_MOVED)
			continue;
		edq_scan_reset(cursor);
		dst->busy_balance_budget = weight >= dst->busy_balance_budget ? 0 :
					   dst->busy_balance_budget - weight;
		return 1;
	}

	return retry ? -EAGAIN : 0;
}

void BPF_STRUCT_OPS(cidland_dispatch, s32 cid, struct task_struct *prev)
{
	bool has_prev, keep = false, active_balance = false, prev_throttled = false;
	s32 migrate_cid = -EBUSY, busy_cid;
	u64 now, tnow;

	TOUCH_ARENA();

	if (!cid_valid(cid))
		return;
	now = scx_bpf_now();
	tnow = cid_clock_task_owned(cid, now);

	/*
	 * Tasks that were waiting on their cgroup's cpu.max go back in the
	 * queues first, so that the pick below sees them and the one it owes
	 * the CPU to wins on its own deadline rather than on having been let
	 * out first.
	 */
	if (READ_ONCE(bw_nr_parked))
		bw_unpark(now);

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
		task_ctx_t *ptctx = bw_enabled() ? try_lookup_task_ctx(prev) : NULL;

		/*
		 * A task whose cgroup has run out of bandwidth may not go on,
		 * whatever it is owed and whether or not anything else is
		 * waiting here: its slice ends and it is handed back through
		 * ops.enqueue(), which puts it aside. What
		 * check_cfs_rq_runtime() does to the task of a cfs_rq that has
		 * run out, and the only way a task that never blocks is ever
		 * asked about its cgroup's limit again.
		 */
		prev_throttled = ptctx && task_bw_throttled(ptctx, cid, now);
		if (prev_throttled)
			scx_bpf_task_set_slice(prev, 0);

		migrate_cid = active_balance_target(prev, cid, now);
		if (migrate_cid >= 0) {
			task_ctx_t *tctx = try_lookup_task_ctx(prev);

			if (tctx)
				tctx->dispatch_migrate_cid = migrate_cid;
			else
				migrate_cid = -EBUSY;
		}
		if (migrate_cid < 0 && !prev_throttled)
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
			s32 owner = READ_ONCE(cid_ctx(cid)->busy_balance_owner);
			u32 level = READ_ONCE(cid_ctx(cid)->busy_balance_level);

			if (cid_valid(owner) && level < BUSY_BALANCE_LEVELS)
				WRITE_ONCE(cid_ctx(owner)->busy_balance_failed[level], 0);
			cid_queued_check(busy_cid);
			/* Drain no more than the imbalance calculated by the tick. */
			if (READ_ONCE(cid_ctx(cid)->busy_balance_budget) &&
			    cid_queued_test(busy_cid) &&
			    time_before(now,
					READ_ONCE(cid_ctx(cid)->busy_balance_expire)))
				__sync_val_compare_and_swap(
					&cid_ctx(cid)->busy_balance_cid,
					-1, busy_cid);
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
		     move_first_eligible_to_local(cid, tnow, has_prev) :
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
		/*
		 * Unless its cgroup is out of bandwidth: leave the slice ended
		 * and let the kernel hand it back. SCX_OPS_ENQ_LAST is what
		 * makes that happen for a task with nothing to follow it, and
		 * without it the CPU would simply go on running the task it
		 * already has, quota or no quota.
		 */
		if (prev_throttled)
			return;
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
		cid_demand_set(cid, false, scx_bpf_now());
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
	if (deq_flags & SCX_DEQ_SLEEP)
		tctx->last_sleep_at = now;

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
	task_vref_leave(tctx);

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
		task_vref_leave(tctx);
}

void BPF_STRUCT_OPS(cidland_running, struct task_struct *p)
{
	task_ctx_t *tctx;
	u64 now, weight;
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
	cid_pressure_resumed(cid, tctx->last_run_at);
	util_set_running(tctx, true, now);
	cid_util_set_running(cid, true, now);
	cid_demand_set(cid, true, now);

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
	task_vref_join(cid, p, tctx);

	/*
	 * A task in a group is picked at the share of the hierarchy it has now,
	 * set_next_task_fair() running reweight_eevdf().
	 */
	if (tctx->gq)
		task_h_refresh(tctx, now);

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
		weight = task_weight(p, tctx);
		set_protect_slice(pk, weight);
		/* Publish a complete current-task snapshot to remote wakeups. */
		pk->curr_w = weight;
		cctx->curr_idle = p->policy == SCHED_IDLE;
		cctx->curr_sched_idle = cctx->curr_idle ||
					(tctx->grp && task_in_idle_cgroup(tctx));

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
	cid_demand_set(cid, runnable ||
			       (cid_valid(cid) && cid_queue_nr(cid) > 0),
		       tctx->last_stop_at);
	if (runnable && p->scx.slice)
		cid_pressure_displaced(cid, tnow);

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

	/* The same service against the bandwidth of the task's cgroup. */
	task_bw_charge(tctx, cid, slice);

	/*
	 * A runnable task stopped with slice left was displaced rather than
	 * yielding at a cidland boundary. Once the measured capacity is reduced,
	 * detach it for requeueing on a less-loaded cid. The enqueue path inserts
	 * it into that cid's EDQ, so this migration does not bypass EEVDF order.
	 */
	if (capacity_pressure && runnable && p->scx.slice && cid_valid(cid)) {
		s32 target = capacity_pressure_target(p, cid, tctx->last_stop_at);

		if (target >= 0) {
			tctx->dispatch_migrate_cid = target;
			tctx->pressure_migrate = true;
			scx_bpf_task_set_slice(p, 0);
		}
	}

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

/*
 * The queues of the cgroup @p is in, NULL for the root cgroup or a kernel
 * without the cpu controller's hooks. From ops.enable(), the first op
 * scx_bpf_task_cgroup() can be asked about @p in; the cgroup of
 * ops.init_task() is not a pointer the verifier trusts.
 */
static grp_q_t *task_cgrp_ents(struct task_struct *p)
{
	struct cgrp_ctx *cgc;
	struct cgroup *cgrp;
	grp_q_t *ents;

	if (!cgroup_enabled)
		return NULL;
	cgrp = scx_bpf_task_cgroup(p);
	if (!cgrp)
		return NULL;
	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	ents = cgc ? cgc->ents : NULL;
	bpf_cgroup_release(cgrp);

	return ents;
}

void BPF_STRUCT_OPS(cidland_enable, struct task_struct *p)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	s32 cid = scx_bpf_task_cid(p);

	TOUCH_ARENA();

	if (tctx) {
		scx_bpf_task_set_dsq_vtime(p, (u64)tctx);
		tctx->grp = task_cgrp_ents(p);
		tctx->gq = NULL;
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
		tctx->pressure_migrate = false;
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

/*
 * The core affinity path already moves a queued or running task whose current
 * CPU is no longer allowed, and every cidland placement and balance handoff
 * reads or revalidates p->cpus_ptr. The one state the core cannot update is a
 * sleeping task's simulated delayed-dequeue membership: unlike fair.c's
 * sched_delayed entity, it is not physically left on the runqueue for the
 * affinity change to dequeue.
 *
 * Stop paying that task's debt when the pack it blocked in is excluded. If
 * the old cid remains allowed, fair leaves the delayed entity there too and
 * there is nothing to do.
 */
void BPF_STRUCT_OPS(cidland_set_cmask, struct task_struct *p,
		    const struct scx_cmask __arena *cmask)
{
	task_ctx_t *tctx;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	cid = tctx->delay_cid;
	if (cid_valid(cid) && !cmask_test(cid, cmask))
		delay_settle(tctx, scx_bpf_now());
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
	WRITE_ONCE(tctx->grp, NULL);
	WRITE_ONCE(tctx->gq, NULL);
	tctx->se.vw = task_nice_weight(p);

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
	if (ret > 0) {
		/*
		 * A task that leaves custody from a cgroup's backlog was taken
		 * out of it here, so it is this side that stops counting it,
		 * see bw_unpark_one() for the other.
		 */
		if (state == CID_EDQ_PARKED)
			task_bw_unparked(tctx);
		else
			cid_queued_check(cid);
	}
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
 * Return true if @cgrp is set cpu.idle. ops.cpuctl_set_idle() only reports
 * changes, and struct scx_cgroup_init_args has no idle state, so a cgroup that
 * was made idle before the scheduler was loaded is read off its task_group,
 * whose css the cpu controller's is.
 */
static bool cgrp_is_idle(struct cgroup *cgrp)
{
	struct task_group *tg;
	int idle = 0;

	if (!bpf_core_field_exists(struct task_group, idle))
		return false;
	tg = (struct task_group *)cgrp->subsys[bpf_core_enum_value(enum cgroup_subsys_id,
								     cpu_cgrp_id)];
	if (!tg)
		return false;
	if (bpf_core_read(&idle, sizeof(idle), &tg->idle))
		return false;

	return idle > 0;
}

/*
 * A cgroup the cpu controller is putting under this scheduler, either one
 * that already existed when it was loaded or one just created, parents
 * before their children: give it a queue on every cid, each adding to its
 * parent's queue on that cid, see struct grp_q.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(cidland_cpuctl_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc, *pcgc = NULL;
	grp_q_t *ents, *pents = NULL;
	struct grp_hdr __arena *hdr;
	struct cgroup *parent;
	u64 bytes, pages;
	u32 depth = 1, cid;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgc)
		return -ENOMEM;
	cgc->ents = NULL;
	cgc->hdr = NULL;
	cgc->depth = 0;
	if (!cgrp->level)
		return 0;

	parent = bpf_cgroup_ancestor(cgrp, cgrp->level - 1);
	if (parent) {
		pcgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, parent, 0, 0);
		bpf_cgroup_release(parent);
	}
	if (pcgc && pcgc->ents) {
		pents = pcgc->ents;
		depth = pcgc->depth + 1;
	}
	if (depth > GRP_MAX_DEPTH) {
		cgc->ents = pents;
		cgc->depth = pcgc->depth;
		return 0;
	}

	bytes = sizeof(struct grp_hdr) + (u64)nr_cids * sizeof(struct grp_q) +
		(u64)((nr_cids + 63) / 64) * sizeof(u64);
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	hdr = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!hdr)
		return -ENOMEM;
	hdr->idle = cgrp_is_idle(cgrp);
	hdr->weight = hdr->idle ? WEIGHT_IDLEPRIO : cgrp_load_weight(args->weight);
	hdr->pages = pages;
	ents = (grp_q_t *)((char __arena *)hdr + sizeof(struct grp_hdr));

	/* Fresh arena pages read as zero: only what is not zero is stored. */
	bpf_for(cid, 0, nr_cids) {
		grp_q_t *gq = &ents[cid];

		gq->hdr = hdr;
		gq->cid = cid;
		gq->shares = hdr->weight;
		if (pents)
			gq->parent = &pents[cid];
	}

	cgc->ents = ents;
	cgc->hdr = hdr;

	/* A slot for grp_sweep(); a cgroup without one is simply not swept. */
	hdr->slot = GRP_MAX_CGROUPS;
	/* One among the limited cgroups is taken only if a cpu.max is set. */
	hdr->bw_slot = BW_SLOT_NONE;
	if (grp_hdrs) {
		u32 slot;

		bpf_for(slot, 0, GRP_MAX_CGROUPS) {
			if (!grp_hdrs[slot]) {
				hdr->slot = slot;
				grp_hdrs[slot] = (u64)hdr;
				if (slot >= grp_hdrs_nr)
					grp_hdrs_nr = slot + 1;
				break;
			}
		}
	}
	cgc->depth = depth;

	return 0;
}

/*
 * The cgroup is going away, or the scheduler is.
 *
 * A cgroup that is removed has no tasks left and nothing adds to its
 * queues, so the memory goes back. The scheduler going away exits every
 * cgroup before any task leaves it, scx_root_disable(), and those tasks
 * still take their weights out of their groups' loads on the way out. The
 * cgroup is still online then, where cgroup_destroy_locked() takes it
 * offline before its controllers are, and the memory goes with the arena.
 */
void BPF_STRUCT_OPS(cidland_cpuctl_exit, struct cgroup *cgrp)
{
	struct grp_hdr __arena *hdr;
	struct cgrp_ctx *cgc;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc || !cgc->hdr)
		return;
	hdr = cgc->hdr;
	cgc->ents = NULL;
	cgc->hdr = NULL;

	/*
	 * Its cpu.max goes with it. Tasks waiting on it are let go rather than
	 * left to wait on a limit nobody will refill: the scheduler being
	 * unloaded exits every cgroup while its tasks are still in them, and
	 * the dequeue each of them is about to get takes them out of the
	 * backlog. A cgroup that is removed is empty before it gets here.
	 */
	if (grp_bw_limited(hdr)) {
		WRITE_ONCE(hdr->quota, 0);
		bw_nr_limited--;
	}
	grp_bw_unthrottle(hdr, scx_bpf_now());
	grp_bw_unregister(hdr);

	/* Out of the registry: no sweep that starts from now on can find it. */
	if (grp_hdrs && hdr->slot < GRP_MAX_CGROUPS)
		WRITE_ONCE(grp_hdrs[hdr->slot], 0);

	if (cgrp->self.flags & CSS_ONLINE)
		return;

	/*
	 * Nothing may still point into the block that is about to go: a task
	 * left waiting in its backlog holds the queue it is in. An empty
	 * cgroup has none, so this only ever leaks the pages of a block the
	 * arena takes back anyway when the scheduler goes.
	 */
	if (READ_ONCE(hdr->nr_parked))
		return;

	/*
	 * A sweep already walking may still hold a pointer to the block. Free
	 * it only with the sweep lock held, or leave it to the sweep, which
	 * frees it once its walk is over, see grp_free_drain().
	 */
	if (__sync_val_compare_and_swap(&grp_sweep_lock, 0, 1) == 0) {
		bpf_arena_free_pages(&arena, hdr, hdr->pages);
		WRITE_ONCE(grp_sweep_lock, 0);
	} else {
		grp_free_defer(hdr);
	}
}

/*
 * Somebody wrote cpu.weight: the shares of the cgroup's groups follow the
 * next time the tick recomputes them, see grp_update_shares().
 */
void BPF_STRUCT_OPS(cidland_cpuctl_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgrp_ctx *cgc;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc || !cgc->hdr)
		return;

	cgc->hdr->weight = cgrp_load_weight(weight);
}

/*
 * Somebody wrote cpu.idle, sched_group_set_idle(): an idle cgroup has the
 * weight of a SCHED_IDLE task, and one that stops being idle goes back to the
 * default weight, not to the cpu.weight it had, which the kernel does not
 * let be written while the cgroup is idle. The shares follow the next time
 * the tick recomputes them, see grp_update_shares().
 *
 * A task under an idle cgroup also counts as SCHED_IDLE work on its cid for
 * placement, see cid_sched_idle_target(). It does not change how the task
 * preempts or is preempted: with a single runqueue, wakeup_preempt_fair()
 * compares the tasks' own policies.
 */
void BPF_STRUCT_OPS(cidland_cpuctl_set_idle, struct cgroup *cgrp, bool idle)
{
	struct cgrp_ctx *cgc;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc || !cgc->hdr)
		return;

	cgc->hdr->weight = idle ? WEIGHT_IDLEPRIO : cgrp_load_weight(CGROUP_WEIGHT_DFL);
	WRITE_ONCE(cgc->hdr->idle, idle);
}

/*
 * Somebody wrote cpu.max, tg_set_bandwidth(): the cgroup may run for
 * @quota_us of every @period_us, and carry what it leaves unused into the next
 * period, up to @burst_us. The kernel keeps "max" as RUNTIME_INF and refuses a
 * quota or a period below a millisecond, so zero stands for no limit here.
 *
 * The limits are kept in nanoseconds, what the rest of the scheduler times in.
 * A cgroup nested deeper than GRP_MAX_DEPTH has no block of its own to keep
 * them in, and runs under the limits of the ancestor whose block it shares.
 */
void BPF_STRUCT_OPS(cidland_cpuctl_set_bandwidth, struct cgroup *cgrp,
		    u64 period_us, u64 quota_us, u64 burst_us)
{
	u64 quota, period, burst, now;
	struct grp_hdr __arena *hdr;
	struct cgrp_ctx *cgc;
	bool was, limited;

	TOUCH_ARENA();

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
	if (!cgc || !cgc->hdr)
		return;
	hdr = cgc->hdr;

	quota = quota_us == BW_QUOTA_INF ? 0 : quota_us * NSEC_PER_USEC;
	period = MAX(period_us * NSEC_PER_USEC, NSEC_PER_MSEC);
	burst = quota ? burst_us * NSEC_PER_USEC : 0;
	now = scx_bpf_now();

	/*
	 * A limit that is new or has moved starts a period of its own, as
	 * tg_set_cfs_bandwidth() refills the group and restarts its timer. The
	 * period and the burst go in before the quota that makes them count.
	 */
	was = grp_bw_limited(hdr);
	if (quota)
		grp_bw_register(hdr);
	WRITE_ONCE(hdr->period, period);
	WRITE_ONCE(hdr->burst, burst);
	WRITE_ONCE(hdr->period_start, now);
	WRITE_ONCE(hdr->pool, quota);
	/* Whatever the cids are holding was taken under the old limit. */
	__sync_fetch_and_add(&hdr->bw_gen, 1);
	WRITE_ONCE(hdr->quota, quota);
	grp_bw_unthrottle(hdr, now);

	limited = quota != 0;
	if (limited != was)
		bw_nr_limited += limited ? 1 : -1;
	/*
	 * A cgroup that is no longer limited keeps its slot until its tasks
	 * have been let go: they wait in a backlog the drain reaches through
	 * it. The unthrottle above is what lets that happen.
	 */
	if (!limited && !READ_ONCE(hdr->nr_parked))
		grp_bw_unregister(hdr);
}

/*
 * @p is now in another cgroup. The task is off its runqueue here: it left its
 * pack and its group's load in ops.quiescent(), and joins the new group's the
 * next time it is placed or runs. A debt it owes the old pack is forgiven.
 */
void BPF_STRUCT_OPS(cidland_cpuctl_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	struct cgrp_ctx *cgc;

	if (!tctx)
		return;
	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, to, 0, 0);
	tctx->grp = cgc ? cgc->ents : NULL;
	tctx->delay_cid = -1;
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
		cid_ctx(cid)->busy_balance_owner = -1;
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
			topo->fork_base = cid;
			topo->fork_nr = 1;
			topo->wake_affine_base = cid;
			topo->wake_affine_nr = 1;
			topo->asym_capacity_base = cid;
			topo->asym_capacity_nr = 1;
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

		{
			u32 fork_span = 0, wake_span = 0, asym_span = 0;
			u64 range;

			if (cpu >= 0 && (u32)cpu < nr_cpu_ids) {
				fork_span = cpu_fork_span_in[cpu];
				wake_span = cpu_wake_span_in[cpu];
				asym_span = cpu_asym_span_in[cpu];
			}
			range = topo_domain_range(topo, fork_span,
						  topo->node_nr);
			topo->fork_base = range;
			topo->fork_nr = range >> 32;
			range = topo_domain_range(topo, wake_span,
						  topo->llc_nr);
			topo->wake_affine_base = range;
			topo->wake_affine_nr = range >> 32;
			if (asym_span || force_asym_capacity) {
				range = topo_domain_range(topo, asym_span,
						  nr_cids);
				topo->asym_capacity_base = range;
				topo->asym_capacity_nr = range >> 32;
			} else {
				topo->asym_capacity_base = 0;
				topo->asym_capacity_nr = 0;
			}
		}
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cidland_init)
{
	struct hrtick *ht;
	u64 now;
	u32 cid, level;
	int err;

	TOUCH_ARENA();

	if (!nr_cids_max) {
		scx_bpf_error("cidland_arena_init() didn't run");
		return -EINVAL;
	}

	if (cgroup_enabled) {
		grp_hdrs = bpf_arena_alloc_pages(&arena, NULL,
						 (GRP_MAX_CGROUPS * sizeof(u64) +
						  PAGE_SIZE - 1) / PAGE_SIZE,
						 NUMA_NO_NODE, 0);
		if (!grp_hdrs)
			return -ENOMEM;
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
	now = bpf_ktime_get_ns();

	/* sched_init(): the idle pull budget starts open by a migration cost. */
	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_ctx __arena *cctx = cid_ctx(cid);
		struct newidle_stats __arena *stats = &newidle_stats[cid];

		cctx->avg_idle = 2 * migration_cost_ns;
		cctx->max_idle_balance_cost = migration_cost_ns;
		cctx->busy_balance_cap = cid_topo(cid)->cap;
		cctx->busy_balance_scan_cap = cid_topo(cid)->cap;
		cctx->pressure_avail = 1024;
		bpf_arena_for(level, 0, NEWIDLE_LEVELS) {
			stats->call[level] = 512;
			stats->success[level] = 256;
			stats->ratio[level] = 512;
			stats->stamp[level] = now;
		}
		if (cid == (s32)cid_topo(cid)->llc_base)
			cctx->sis_idle_scan = cid_topo(cid)->llc_nr;
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

	if (cpu_max_enabled) {
		struct bw_timer *bt;
		u32 key = 0;

		bt = bpf_map_lookup_elem(&bw_timers, &key);
		if (!bt) {
			scx_bpf_error("no cpu.max timer");
			return -ENOENT;
		}
		err = bpf_timer_init(&bt->timer, &bw_timers, CLOCK_MONOTONIC);
		if (!err)
			err = bpf_timer_set_callback(&bt->timer, bw_timer_fire);
		if (err) {
			scx_bpf_error("failed to set up the cpu.max timer: %d", err);
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
		nr * (sizeof(struct core_sched_state) + sizeof(struct newidle_stats) +
		      sizeof(u64) +
		      6 * sizeof(u32)) + 13 * 64;
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	arena_base = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!arena_base)
		return -ENOMEM;
	arena_size = pages * PAGE_SIZE;
	arena_off = 0;

	topos = arena_carve(nr * sizeof(struct cid_topo), 64);
	cctxs = arena_carve(nr * sizeof(struct cid_ctx), 64);
	core_sched_states = arena_carve(nr * sizeof(struct core_sched_state), 64);
	newidle_stats = arena_carve(nr * sizeof(struct newidle_stats), 64);
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
	cpu_fork_span_in = arena_carve(nr * sizeof(u32), 64);
	cpu_wake_span_in = arena_carve(nr * sizeof(u32), 64);
	cpu_asym_span_in = arena_carve(nr * sizeof(u32), 64);
	if (!topos || !cctxs || !core_sched_states || !newidle_stats || !idle_cids ||
	    !idle_core_llcs || !queued_cids ||
	    !place_tier_cids || !capacity_tier_cids || !cpu_cap_in ||
	    !cpu_place_tier_in || !cpu_capacity_tier_in || !cpu_smt_asym_in ||
	    !cpu_fork_span_in || !cpu_wake_span_in || !cpu_asym_span_in)
		return -ENOMEM;
	ret = scx_alloc_init(&task_ctx_allocator, sizeof(struct task_ctx),
			     __alignof__(struct task_ctx));
	if (ret)
		return ret;

	nr_cids_max = nr;
	nr_place_tiers = args->nr_place_tiers;
	nr_capacity_tiers = args->nr_capacity_tiers;
	asym_capacity = args->asym_capacity;
	sched_asym_capacity = args->sched_asym_capacity;
	force_asym_capacity = args->force_asym_capacity;
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
	cpu_fork_span_in[cpu] = args->fork_span;
	cpu_wake_span_in[cpu] = args->wake_affine_span;
	cpu_asym_span_in[cpu] = args->asym_capacity_span;

	return 0;
}

/*
 * Return one CPU's SD_ASYM_PACKING state and arch_asym_cpu_priority().
 * Topology supplies the other scheduler-domain policy; packing has no stable
 * userspace ABI and is deliberately kept separate from CPU capacity.
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

/*
 * The ops, with the prefix the running kernel names the cgroup callbacks
 * with: cpuctl_*, or cgroup_* on a kernel from before the cid form renamed
 * them.
 */
#define CIDLAND_OPS(__cg)						\
	.select_cid		= (void *)cidland_select_cid,		\
	.enqueue		= (void *)cidland_enqueue,		\
	.dequeue		= (void *)cidland_dequeue,		\
	.tick			= (void *)cidland_tick,			\
	.core_sched_before	= (void *)cidland_core_sched_before,	\
	.yield			= (void *)cidland_yield,		\
	.dispatch		= (void *)cidland_dispatch,		\
	.runnable		= (void *)cidland_runnable,		\
	.quiescent		= (void *)cidland_quiescent,		\
	.running		= (void *)cidland_running,		\
	.stopping		= (void *)cidland_stopping,		\
	.update_idle		= (void *)cidland_update_idle,		\
	.enable			= (void *)cidland_enable,		\
	.set_weight		= (void *)cidland_set_weight,		\
	.set_cmask		= (void *)cidland_set_cmask,		\
	.init_task		= (void *)cidland_init_task,		\
	.exit_task		= (void *)cidland_exit_task,		\
	.__cg##_init		= (void *)cidland_cpuctl_init,		\
	.__cg##_exit		= (void *)cidland_cpuctl_exit,		\
	.__cg##_set_weight	= (void *)cidland_cpuctl_set_weight,	\
	.__cg##_set_bandwidth	= (void *)cidland_cpuctl_set_bandwidth,	\
	.__cg##_set_idle	= (void *)cidland_cpuctl_set_idle,	\
	.__cg##_move		= (void *)cidland_cpuctl_move,		\
	.init			= (void *)cidland_init,			\
	.exit			= (void *)cidland_exit,			\
	.timeout_ms		= 5000,					\
	.name			= "cidland"

SCX_OPS_CID_DEFINE(cidland_ops, CIDLAND_OPS(cpuctl));

/*
 * struct sched_ext_ops_cid as a kernel from before the rename declares it,
 * the cgroup callbacks under their cgroup_* names and in the same slots.
 * libbpf matches the members of a struct_ops map to the kernel's by name and
 * drops the ___ suffix from the type name, so this map binds the same
 * programs to the older names. User space creates whichever of the two maps
 * the running kernel matches, see main.rs; members the kernel does not have
 * are left zero and skipped.
 */
struct sched_ext_ops_cid___cgroup {
	s32 (*select_cid)(struct task_struct *, s32, u64);
	void (*enqueue)(struct task_struct *, u64);
	void (*dequeue)(struct task_struct *, u64);
	void (*dispatch)(s32, struct task_struct *);
	void (*tick)(struct task_struct *);
	void (*runnable)(struct task_struct *, u64);
	void (*running)(struct task_struct *);
	void (*stopping)(struct task_struct *, bool);
	void (*quiescent)(struct task_struct *, u64);
	bool (*yield)(struct task_struct *, struct task_struct *);
	bool (*core_sched_before)(struct task_struct *, struct task_struct *);
	void (*set_weight)(struct task_struct *, u32);
	void (*set_cmask)(struct task_struct *, const struct scx_cmask *);
	void (*update_idle)(s32, bool);
	s32 (*init_task)(struct task_struct *, struct scx_init_task_args *);
	void (*exit_task)(struct task_struct *, struct scx_exit_task_args *);
	void (*enable)(struct task_struct *);
	void (*disable)(struct task_struct *);
	void (*dump)(struct scx_dump_ctx *);
	void (*dump_cid)(struct scx_dump_ctx *, s32, bool);
	void (*dump_task)(struct scx_dump_ctx *, struct task_struct *);
	s32 (*cgroup_init)(struct cgroup *, struct scx_cgroup_init_args *);
	void (*cgroup_exit)(struct cgroup *);
	s32 (*cgroup_prep_move)(struct task_struct *, struct cgroup *, struct cgroup *);
	void (*cgroup_move)(struct task_struct *, struct cgroup *, struct cgroup *);
	void (*cgroup_cancel_move)(struct task_struct *, struct cgroup *, struct cgroup *);
	void (*cgroup_set_weight)(struct cgroup *, u32);
	void (*cgroup_set_bandwidth)(struct cgroup *, u64, u64, u64);
	void (*cgroup_set_idle)(struct cgroup *, bool);
	s32 (*sub_attach)(struct scx_sub_attach_args *);
	void (*sub_detach)(struct scx_sub_detach_args *);
	void (*sub_caps_updated)(const struct scx_cmask *, u64);
	void (*sub_ecaps_updated)(s32, u64, u64);
	void (*cid_online)(s32);
	void (*cid_offline)(s32);
	s32 (*init_cids)(void);
	s32 (*init)(void);
	void (*exit)(struct scx_exit_info *);
	u32 dispatch_max_batch;
	u64 flags;
	u32 timeout_ms;
	u32 exit_dump_len;
	u64 hotplug_seq;
	u32 cid_shard_size;
	u32 rescue_bandwidth_ppt;
	u32 rescue_quantum_us;
	u64 sub_cgroup_id;
	char name[128];
	void *priv;
};

SEC(".struct_ops.link")
struct sched_ext_ops_cid___cgroup cidland_ops_cgroup = {
	CIDLAND_OPS(cgroup),
};
