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
 * number of CPUs, cores, LLCs, nodes or capacity tiers.
 */
#include <scx/common.bpf.h>
#include <lib/arena_map.h>
#include <lib/arena_loop.h>
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
 * Thresholds for applying hysteresis to CPU performance scaling:
 *  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
 *  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
 *
 * Values between the two thresholds retain the current smoothed performance level.
 */
#define CPUFREQ_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUFREQ_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

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
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * Default time slice.
 */
const volatile u64 slice_ns = 1000000ULL;

/*
 * Maximum lag, in virtual time, that a task can carry across a sleep.
 */
const volatile u64 slice_lag = 20000000ULL;

/*
 * A task that ran within this long on its CPU is still cache hot there and
 * is not stolen, like task_hot() with sysctl_sched_migration_cost.
 */
const volatile u64 migration_cost_ns = 500000ULL;

/*
 * Do not interrupt a running task for one that wakes up with an earlier
 * deadline, leaving it to run until its slice ends.
 */
const volatile bool no_wakeup_preempt;

/*
 * Interrupt a running task on the deadlines alone, without asking which
 * of the two is owed service, see kick_queued_cid().
 */
const volatile bool no_eligibility;

/*
 * Place tasks and test them for eligibility against the pack reference as
 * it stands, without the service the task running there has taken since
 * it was picked, see cid_vref_at().
 */
const volatile bool no_vref_update;

/*
 * Number of other cids' queues a busy cid looks at on each dispatch for a
 * queue deeper than its own. 0 disables the sampling, leaving a busy cid
 * with its own queue only.
 */
const volatile u32 balance_sample = 2;

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
volatile u64 nr_preempts __hot_written;

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
 * Number of capacity tiers, 0 being the fastest, and whether there is
 * more than one.
 */
static u32 nr_tiers;
static bool asym_capacity;

/*
 * Per-task context.
 */
struct task_ctx {
	u64 last_run_at;
	u64 last_stop_at;
	u64 vruntime;
	u64 deadline;
	s64 vlag;
	s32 vcid;
	u64 vjoin_w;
	u64 vjoin_v;

	/* still owed its first, halved request, see task_dl() */
	bool initial;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Topology of a cid, filled in ops.init() from scx_bpf_cid_topo() and the
 * capacity user space reported for the CPU behind it. All the ranges are
 * in cid space and contiguous.
 */
struct cid_topo {
	u32 cpu;		/* cpu behind this cid, for affinity tests */
	u32 tier;		/* capacity tier, 0 = fastest */
	u64 cap;		/* capacity, 1024 = fastest */
	u32 core_base;		/* first cid of the core */
	u32 core_nr;		/* cids in the core (SMT siblings) */
	u32 llc_base;		/* first cid of the LLC */
	u32 llc_nr;		/* cids in the LLC */
	u32 node_base;		/* first cid of the node */
	u32 node_nr;		/* cids in the node */
};

/*
 * Per-cid scheduling state.
 */
struct cid_ctx {
	u64 last_update;
	u64 perf_lvl;
	u64 last_balance_at;
	u64 vsum_w;
	u64 vref;
	u64 vref_rem;
	u64 curr_dl;		/* deadline of the task running here */
	u64 curr_v;		/* its vruntime when it was picked */
	u64 curr_w;		/* its weight */
	u64 curr_run_at;	/* when it was picked */
	u32 steal_cursor;
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
static struct scx_cmask __arena *queued_cids;	/* one bit per cid with a queued task */
static struct scx_cmask __arena *tier_cids;	/* nr_tiers masks: the cids of a tier */
static u64 tier_stride;				/* bytes from one tier mask to the next */

/*
 * The bitmaps are struct scx_cmask, the type the kernel's cid interfaces
 * take and hand out, framed at cid 0 over the whole cid space, so that a
 * domain or a sub-scheduler can be given one as is, and they are read and
 * written through the cmask helpers throughout: a bit with cmask_set(),
 * cmask_clear() and cmask_test_and_clear(), a word with cmask_word() and
 * cmask_range_word(). What the scans stay away from is the per-cid
 * iterators, not the helpers: a scan reads whole words.
 */
static __always_inline struct scx_cmask __arena *tier_mask(u32 t)
{
	return (struct scx_cmask __arena *)((char __arena *)tier_cids + t * tier_stride);
}
static u64 __arena *cpu_cap_in;		/* cpu space: capacity from user space */
static u32 __arena *cpu_tier_in;	/* cpu space: tier from user space */

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

/*
 * Exponential weighted moving average (EWMA).
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, u64 slice)
{
	u64 now = bpf_ktime_get_ns();
	s32 cid = scx_bpf_task_cid(p);
	struct cid_ctx __arena *cctx;
	u64 perf_lvl, delta_t;

	if (!cpufreq_enabled || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);

	/*
	 * Evaluate dynamic cpuperf scaling factor using the average CPU
	 * utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_t = now - cctx->last_update;
	if (!delta_t)
		return;

	/*
	 * Refresh target performance level.
	 */
	perf_lvl = MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
	cctx->perf_lvl = calc_avg(cctx->perf_lvl, perf_lvl);
	cctx->last_update = now;
}

/*
 * Apply target cpufreq performance level to @cid.
 */
static void update_cpufreq(s32 cid)
{
	struct cid_ctx __arena *cctx;
	u64 perf_lvl;

	if (!cpufreq_enabled || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);

	/*
	 * Apply target performance level to the cpufreq governor.
	 */
	if (cctx->perf_lvl >= CPUFREQ_HIGH_THRESH)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl <= CPUFREQ_LOW_THRESH)
		perf_lvl = SCX_CPUPERF_ONE / 2;
	else
		perf_lvl = cctx->perf_lvl;

	scx_bpf_cidperf_set(cid, perf_lvl);
}

/*
 * Return the DSQ of @cid.
 *
 * Every cid owns a deadline ordered DSQ where the tasks that last ran on
 * it are queued, and a cid that runs out of work pulls from the DSQs of
 * its node (see try_steal_task()). All the keys are built on the same
 * vruntime reference, so the queues behave as a single node-wide deadline
 * queue, without the single lock that a single queue puts in the path of
 * every wakeup.
 */
static inline u64 cid_dsq(s32 cid)
{
	return cid;
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

	if (!cid_valid(cid))
		return false;
	topo = cid_topo(cid);

	return cmask_full_range(idle_cids, topo->core_base, topo->core_nr);
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
	if (cid_valid(cid))
		cmask_set(cid, idle_cids);
}

/*
 * Queued cid tracking.
 *
 * One bit per cid whose DSQ holds at least one task, kept next to the
 * idle bitmap and scanned the same way, so that a cid looking for work
 * to pull walks a word of it instead of peeking at the DSQ of every cid
 * of the node, a kfunc call and a hash lookup each.
 *
 * The bit is set after a task is queued and cleared by whoever finds the
 * DSQ empty, with a second look after the clear in case a task was queued
 * in between. It is a hint: the kernel can dequeue a task behind the
 * scheduler's back, and a bit left set is cleared by the first cid that
 * peeks and finds nothing.
 */
static bool cid_queued_test(s32 cid)
{
	return cid_valid(cid) && __cmask_test(cid, queued_cids);
}

static void cid_queued_set(s32 cid)
{
	if (cid_valid(cid))
		cmask_set(cid, queued_cids);
}

/*
 * Clear the queued bit of @cid if its DSQ is empty, looking again after
 * the clear for a task queued in the meantime.
 */
static void cid_queued_check(s32 cid)
{
	if (!cid_valid(cid) || scx_bpf_dsq_nr_queued(cid_dsq(cid)))
		return;
	cmask_clear(cid, queued_cids);
	if (scx_bpf_dsq_nr_queued(cid_dsq(cid)))
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
 * Return the word @k of the cids of tier @t.
 */
static __always_inline u64 tier_word(u32 t, u32 k)
{
	return cmask_word(tier_mask(t), k);
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

/*
 * Scan the idle cids of tier @t within [@base, @base + @nr) for one @p can
 * take, see first_idle_cid(). The range is contiguous in cid space, so
 * only the words it spans are read.
 */
static __always_inline s32
scan_idle_range(const struct task_struct *p, u32 t, u32 base, u32 nr,
		bool restricted, bool whole_core)
{
	u32 k, last;

	if (!nr)
		return -EBUSY;
	last = (base + nr - 1) / 64;
	bpf_arena_for(k, base / 64, last + 1) {
		u64 w = cmask_word(idle_cids, k) & tier_word(t, k) &
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

/* Flags for pick_idle_cid_ranked() */
enum pick_idle_flags {
	/* @prev_cid is in @p's allowed set and can be returned as is */
	PICK_IDLE_PREV_ALLOWED	= 1 << 0,

	/* Only consider cids whose whole core is idle */
	PICK_IDLE_WHOLE_CORE	= 1 << 1,

	/* Return the cid without claiming it, for a caller that only kicks */
	PICK_IDLE_NO_CLAIM	= 1 << 2,
};

/*
 * Pick an idle cid for @p one capacity tier at a time from the fastest.
 * Only fully idle cores are considered if @whole_core is set, any idle
 * cid otherwise: the caller runs the whole core pass first, across every
 * tier, since sharing a core costs more than the step down to the next
 * tier, the way select_idle_core() looks for a whole core before
 * select_idle_cpu() settles for a thread.
 *
 * Within a tier @prev_cid wins, then a cid in the same LLC, then a cid on
 * the same node, then any cid, to keep the task where its cache is: the
 * order select_idle_sibling() applies within one domain, with the node on
 * top since this scan covers them all. Each domain is a contiguous range,
 * so a wakeup reads the words of its own LLC before anything else.
 *
 * The idle state is claimed only for the cid that is returned. -EAGAIN
 * means a candidate was found but claimed by someone else first. @flags
 * is a mask of PICK_IDLE_*.
 *
 * A global function: verified once rather than at every call site, of
 * which the claim retries make eight.
 */
__noinline s32 pick_idle_cid_ranked(struct task_struct *p __arg_trusted,
				    s32 prev_cid, u32 flags)
{
	bool is_prev_allowed = flags & PICK_IDLE_PREV_ALLOWED;
	bool whole_core = flags & PICK_IDLE_WHOLE_CORE;
	struct cid_topo __arena *prev;
	bool restricted;
	s32 best = -EBUSY;
	u32 t;

	TOUCH_ARENA();

	if (!cid_valid(prev_cid))
		return -EBUSY;
	prev = cid_topo(prev_cid);
	restricted = is_restricted(p);

	bpf_arena_for(t, 0, nr_tiers) {
		if (is_prev_allowed && t == prev->tier && cid_idle_test(prev_cid) &&
		    (!whole_core || core_is_idle(prev_cid))) {
			best = prev_cid;
			break;
		}
		/*
		 * A domain that is the whole of the next one is not scanned
		 * twice.
		 */
		best = scan_idle_range(p, t, prev->llc_base, prev->llc_nr,
				       restricted, whole_core);
		if (best < 0 && numa_enabled && prev->node_nr > prev->llc_nr)
			best = scan_idle_range(p, t, prev->node_base, prev->node_nr,
					       restricted, whole_core);
		if (best < 0 && (numa_enabled ? prev->node_nr : prev->llc_nr) < nr_cids)
			best = scan_idle_range(p, t, 0, nr_cids, restricted,
					       whole_core);
		if (best >= 0)
			break;
	}

	if (best >= 0 && !(flags & PICK_IDLE_NO_CLAIM) && !cid_idle_claim(best))
		best = -EAGAIN;

	return best;
}

/*
 * Scan for an idle cid: fully idle cores first, then any idle cid, from
 * the fastest tier.
 *
 * Return the cid or -EBUSY if no idle cid is found.
 */
static s32 pick_idle_cid(const struct task_struct *p, s32 prev_cid)
{
	u32 flags = !is_restricted(p) || cid_allowed(p, prev_cid) ?
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
		cid = pick_idle_cid_ranked((struct task_struct *)p, prev_cid,
					   flags | (smt_enabled ? PICK_IDLE_WHOLE_CORE : 0));
		if (cid >= 0)
			return cid;
		if (cid != -EAGAIN && smt_enabled)
			cid = pick_idle_cid_ranked((struct task_struct *)p, prev_cid, flags);
		if (cid != -EAGAIN)
			break;
	}

	return cid >= 0 ? cid : -EBUSY;
}

/*
 * Return true if @p should be stacked on the waker's cid @this_cid.
 *
 * On a synchronous wakeup the waker is about to sleep, so its CPU is where
 * the data the two just exchanged stays hot. The waker is still on it,
 * though: @p is not going to run there right away, it is going to wait in
 * that cid's DSQ, ordered by deadline, until the waker blocks.
 *
 * This is wake_affine_idle(), which takes the waker's CPU when the waker
 * is the only runnable task on it (nr_running == 1), and it is consulted
 * only after the idle scan has failed, the way the kernel still runs
 * select_idle_sibling() on the CPU that wake_affine() returned: a CPU that
 * is really idle beats stacking on a busy one.
 */
static bool wake_affine_cid(const struct task_struct *p, s32 prev_cid,
			    s32 this_cid, u64 wake_flags)
{
	return !no_wake_sync && (wake_flags & SCX_WAKE_SYNC) &&
	       cid_valid(this_cid) && cid_allowed(p, this_cid) &&
	       cid_topo(this_cid)->llc_base == cid_topo(prev_cid)->llc_base &&
	       !scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL) &&
	       !cid_queued_test(this_cid);
}

/*
 * Return the cid of the node of @prev_cid with the fewest tasks queued
 * that @p can run on, the fastest one on ties, or -EBUSY.
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
	 * A cid with nothing queued, the fastest one, is the usual answer
	 * and the bitmaps give it without a lookup.
	 */
	bpf_arena_for(t, 0, nr_tiers) {
		bpf_arena_for(k, base / 64, last + 1) {
			u64 w = ~cmask_word(queued_cids, k) & tier_word(t, k) &
				cmask_range_word(queued_cids, k, base, nr);
			s32 cid;

			if (!w)
				continue;
			cid = first_allowed_cid(p, w, k, restricted);
			if (cid >= 0)
				return cid;
		}
	}

	/*
	 * Every queue has something: look for the shallowest, a lookup per
	 * cid. The cid is a kfunc argument, which the verifier tracks
	 * precisely and cannot widen, so a may_goto loop would be unrolled:
	 * this cold path takes the open-coded iterator instead.
	 */
	bpf_for(k, base, base + nr) {
		s32 cid = k, nr_queued;

		if (cid >= nr_cids)
			break;
		if (restricted && !cid_allowed(p, cid))
			continue;
		nr_queued = scx_bpf_dsq_nr_queued(cid_dsq(cid));
		if (best < 0 || nr_queued < best_nr ||
		    (nr_queued == best_nr && cid_topo(cid)->tier < cid_topo(best)->tier)) {
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
 * Fully idle cores first, then any idle cid, from the fastest tier: the
 * ranking pick_idle_cid() applies, since the cid is being woken for one
 * particular task and the best CPU for it is the one a wakeup would have
 * chosen. Every tier is scanned, not only the tiers faster than @cid's:
 * a CPU of the same tier is just as blind to a queue building up next to
 * it, and it is the one that would otherwise stay idle beside a runnable
 * task.
 */
static s32 idle_peer_cid(const struct task_struct *p, s32 cid)
{
	s32 other;

	if (!cid_valid(cid) || is_pcpu_task(p) || cmask_empty(idle_cids))
		return -ENOENT;

	if (smt_enabled) {
		other = pick_idle_cid_ranked((struct task_struct *)p, cid,
					     PICK_IDLE_NO_CLAIM |
					     PICK_IDLE_WHOLE_CORE);
		if (other >= 0)
			return other;
	}

	other = pick_idle_cid_ranked((struct task_struct *)p, cid,
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
#define SCHED_IDLE	5

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
 */
static u64 task_weight(const struct task_struct *p)
{
	u32 idx;

	if (p->policy == SCHED_IDLE)
		return WEIGHT_IDLEPRIO;

	idx = p->static_prio - MAX_RT_PRIO;
	if (idx >= ARRAY_SIZE(prio_to_weight))
		return NICE_0_WEIGHT;

	return prio_to_weight[idx];
}

/*
 * Charge @delta of service to a task of @p's weight, the way
 * calc_delta_fair() does:
 *
 *	delta_fair = delta * NICE_0_LOAD / se->load.weight
 */
static u64 calc_delta_fair(const struct task_struct *p, u64 delta)
{
	return delta * NICE_0_WEIGHT / task_weight(p);
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

static u64 scale_by_dl_weight(const struct task_struct *p, u64 value)
{
	u64 weight = task_weight(p);

	if (weight < MIN_DL_WEIGHT)
		weight = MIN_DL_WEIGHT;

	return value * NICE_0_WEIGHT / weight;
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 * This is EEVDF's virtual deadline, see update_deadline():
 *
 *	vd_i = ve_i + r_i / w_i
 *
 * The request size r_i is the same @slice_ns for everybody, exactly like
 * sysctl_sched_base_slice: the weight does not buy a task a longer time
 * slice, it buys it an earlier deadline, so it runs more often instead of
 * running longer.
 *
 * The deadline is the DSQ key and nothing else. The kernel stores what is
 * passed to scx_bpf_dsq_insert_vtime() in p->scx.dsq_vtime, so the
 * vruntime has to live somewhere the key cannot overwrite it, see
 * task_ctx.vruntime.
 *
 * pick_eevdf() considers only the eligible tasks, v_i <= V, and picks the
 * earliest deadline among them. A DSQ cannot skip a task and its key is
 * fixed at insertion, so the filter is not applied here. It is mostly not
 * needed: a task that is over-served carries the excess in its key and
 * sorts after the under-served tasks of the same weight, and stays there
 * until V has moved past it, which is the wait pick_eevdf() would impose
 * anyway. What is lost is the case of a heavier over-served task, whose
 * r_i / w_i is smaller, sorting ahead of a lighter under-served one: it
 * wins by at most the difference between the two requests, a bounded
 * latency skew, not a fairness leak, since the vruntime is charged all
 * the same.
 *
 * Pushing the ineligible tasks further back with an offset, to apply the
 * filter exactly, would starve them instead. V advances by the service
 * delivered divided by the total weight, so under load it barely moves,
 * and a task waiting for V to cover a fixed offset waits for seconds
 * while every newly woken task keeps being queued ahead of it.
 *
 * The deadline stands until the request it was issued for is consumed,
 * which is the test update_deadline() opens with:
 *
 *	if ((s64)(se->vruntime - se->deadline) < 0)
 *		return;
 *
 * A task queued again without having run for its whole request keeps the
 * deadline it was queued with, instead of being pushed a full request
 * further back for the fraction it did get. Every path that re-enqueues a
 * task today either has it consume the request first (its slice ran out)
 * or re-places its vruntime (a wakeup, a bounced direct dispatch), so
 * this changes nothing as it stands; a task interrupted partway through
 * its request is what needs it.
 *
 * A re-placed vruntime drops the deadline. It is a position in the
 * virtual time of one cid and the packs drift apart, so a deadline
 * carried across would order the task against a reference it was never
 * measured on.
 */
static u64 task_dl(const struct task_struct *p, struct task_ctx *tctx)
{
	u64 slice = slice_ns;

	if (tctx->deadline && time_before(tctx->vruntime, tctx->deadline))
		return tctx->deadline;

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
		slice /= 2;
	}

	tctx->deadline = tctx->vruntime + scale_by_dl_weight(p, slice);

	return tctx->deadline;
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
 * The reference of @cid's pack. Callers pass a cid they have checked; the
 * guard is there so a stray one indexes nothing, and its answer is not
 * meant to be placed against.
 */
static u64 cid_vref(s32 cid)
{
	if (!cid_valid(cid))
		return 0;

	return cid_ctx(cid)->vref;
}

/*
 * The reference of @cid's pack at @now, with the service the task running
 * there has taken since it was picked folded in, see cid_vref().
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
 * request there is nothing worth projecting either - the task is due to
 * be rescheduled and the estimate would be running past what it can know.
 */
static u64 cid_vref_at(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;
	u64 w, sum_w, delta, dv;

	if (!cid_valid(cid))
		return 0;
	cctx = cid_ctx(cid);

	w = cctx->curr_w;
	sum_w = cctx->vsum_w;
	delta = now - cctx->curr_run_at;
	if (!w || !sum_w || delta >= slice_ns)
		return cctx->vref;

	dv = delta * NICE_0_WEIGHT / w;

	return cctx->vref + dv * w / sum_w;
}

/*
 * The reference to place a task against and to test it against, which is
 * cid_vref_at() unless --no-vref-update pins it to the stored value.
 */
static u64 cid_vref_place(s32 cid, u64 now)
{
	return no_vref_update ? cid_vref(cid) : cid_vref_at(cid, now);
}

/*
 * Is the task running on @cid still owed service at @now?
 *
 * Its vruntime is only charged in ops.stopping() too, so the service it
 * has taken since it was picked is added to it here, and to the reference
 * it is measured against by cid_vref_at(). This is what
 * wakeup_preempt_fair() calls update_curr_fair() for before deciding
 * anything. A task that has run for a whole request is past its deadline
 * as well and has no protection left either way.
 */
static bool curr_owed_service(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx = cid_ctx(cid);
	u64 w = cctx->curr_w, delta = now - cctx->curr_run_at;
	u64 dv;

	if (!w || delta >= slice_ns)
		return false;
	dv = delta * NICE_0_WEIGHT / w;

	return !time_after(cctx->curr_v + dv, cid_vref_at(cid, now));
}

/*
 * Drop @tctx out of its pack's reference, see cid_vref().
 */
static void vref_leave(struct task_ctx *tctx)
{
	struct cid_ctx __arena *cctx;
	u64 w;
	s64 d;

	if (!cid_valid(tctx->vcid))
		return;
	cctx = cid_ctx(tctx->vcid);

	w = __sync_fetch_and_sub(&cctx->vsum_w, tctx->vjoin_w);

	/*
	 * V' = V + w_i*(V - v_i) / (W - w_i), and the last one out leaves
	 * the reference standing where it is.
	 */
	if (w > tctx->vjoin_w) {
		d = (s64)(cctx->vref - tctx->vjoin_v);
		__sync_fetch_and_add(&cctx->vref,
				     vdiv((s64)tctx->vjoin_w * d, w - tctx->vjoin_w));
	}

	tctx->vcid = -1;
}

/*
 * Fold @p into @cid's reference, see cid_vref().
 */
static void vref_join(s32 cid, const struct task_struct *p, struct task_ctx *tctx)
{
	struct cid_ctx __arena *cctx;
	u64 w;
	s64 d;

	if (tctx->vcid == cid)
		return;
	vref_leave(tctx);

	if (!cid_valid(cid))
		return;
	cctx = cid_ctx(cid);

	tctx->vjoin_w = task_weight(p);
	tctx->vjoin_v = tctx->vruntime;
	tctx->vcid = cid;

	/*
	 * V' = V + w_i*(v_i - V) / (W + w_i). On an empty pack W is 0 and
	 * the increment is exactly v_i - V, so the first member becomes the
	 * reference, which is what the average of one is.
	 */
	w = __sync_fetch_and_add(&cctx->vsum_w, tctx->vjoin_w);
	d = (s64)(tctx->vruntime - cctx->vref);
	__sync_fetch_and_add(&cctx->vref,
			     vdiv((s64)tctx->vjoin_w * d, w + tctx->vjoin_w));
}

/*
 * Bring the contribution of @tctx up to date with its vruntime.
 *
 *	dV = w_i * dv_i / W
 *
 * EEVDF's identity for the service just delivered, taken against the pack
 * that received it. The division truncates, and a pack heavy enough that
 * w_i * dv_i falls below W would advance by nothing at all and freeze, so
 * carry the remainder. Only the cid the task ran on is touched, so the
 * carry needs no atomic.
 */
static void vref_charge(struct task_ctx *tctx)
{
	struct cid_ctx __arena *cctx;
	u64 acc, delta, w;
	s64 dv;

	if (!cid_valid(tctx->vcid))
		return;
	cctx = cid_ctx(tctx->vcid);

	dv = (s64)(tctx->vruntime - tctx->vjoin_v);
	if (dv <= 0)
		return;
	tctx->vjoin_v = tctx->vruntime;

	w = cctx->vsum_w;
	if (!w)
		return;

	acc = tctx->vjoin_w * (u64)dv + cctx->vref_rem;
	delta = acc / w;
	cctx->vref_rem = acc - delta * w;
	if (delta)
		__sync_fetch_and_add(&cctx->vref, delta);
}

/*
 * Return the total weight of the pack queued on @cid, 0 if it is empty.
 */
static u64 cid_pack_weight(s32 cid)
{
	return cid_valid(cid) ? cid_ctx(cid)->vsum_w : 0;
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
static void place_task(s32 cid, const struct task_struct *p,
		       struct task_ctx *tctx, u64 now)
{
	if (!scx_bpf_task_running(p) && cid_valid(cid)) {
		tctx->vruntime = cid_vref_place(cid, now);
		if (cid_pack_weight(cid))
			tctx->vruntime -= tctx->vlag;
		tctx->deadline = 0;
	}
	vref_join(cid, p, tctx);
}

/*
 * Direct dispatch @p to the local DSQ of @cid from ops.select_cid().
 *
 * Insert with SCX_ENQ_IMMED so that the kernel bounces @p back through
 * ops.enqueue() (and from there into a per-cid DSQ, where the deadline
 * ordering applies) whenever @p can't run on @cid right away. This keeps
 * the local DSQ a pure "run now" fast path instead of an unbounded queue
 * that outranks the deadline-ordered DSQs.
 *
 * @cid is idle here, so the bounce is the exception: the kernel triggers
 * it (rq_is_open() in dispatch_one()) whenever a task is waiting on @cid
 * or a higher scheduling class took it in the meantime. Only call this for
 * a cid that is idle, never to stack @p behind a task that is running: the
 * bounce would be certain and the direct dispatch pure overhead.
 */
static void direct_dispatch_local(struct task_struct *p, struct task_ctx *tctx, s32 cid)
{
	place_task(cid, p, tctx, bpf_ktime_get_ns());
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, SCX_ENQ_IMMED);
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
	s32 cid, this_cid = scx_bpf_this_cid();
	struct task_ctx *tctx;

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

	/*
	 * Try to find an idle cid and dispatch the task directly to it,
	 * without bouncing it through ops.enqueue().
	 */
	cid = pick_idle_cid(p, prev_cid);
	if (cid >= 0) {
		direct_dispatch_local(p, tctx, cid);
		return cid;
	}

	/*
	 * Nothing is idle: on a synchronous wakeup stack the wakee on the
	 * waker's cid. Not as a direct dispatch, the local DSQ is for a task
	 * that can run right away and the waker is still on the CPU: the
	 * wakee goes through ops.enqueue() into that cid's deadline-ordered
	 * DSQ and the CPU takes it once the waker blocks.
	 */
	if (wake_affine_cid(p, prev_cid, this_cid, wake_flags))
		return this_cid;

	/*
	 * A new task with no idle cid to go to is queued on the cid with the
	 * shortest queue rather than behind its parent.
	 */
	if (wake_flags & SCX_WAKE_FORK) {
		cid = shallowest_queue_cid(p, prev_cid);
		if (cid >= 0)
			return cid;
	}

	return prev_cid;
}

/*
 * Kick @cid, on whose DSQ the task of @tctx has just been queued with
 * deadline @dl.
 *
 * An idle cid only has to be told that there is work: the kick makes it
 * dispatch. A busy one is running a task of its own, and what the kick
 * has to decide is whether that task should be interrupted.
 *
 * This is EEVDF's wakeup preemption. wakeup_preempt_fair() asks what the
 * runqueue would pick now and reschedules when the answer is the task
 * that just woke, and with every task asking for the same slice, as they
 * all do here, that pick comes down to what pick_eevdf() opens with:
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
 * comparison, see cid_vref_at() and curr_owed_service(), the way
 * wakeup_preempt_fair() calls update_curr_fair() before deciding
 * anything.
 *
 * All of it compares because all of it is in @cid's virtual time: the
 * running task joined that reference in ops.running() and the queued one
 * was placed against it just above. Two cids' references do not compare,
 * which is why the only cid this looks at is the one the task was queued
 * on.
 *
 * The @curr_ fields describe the last task of ours to run there and say
 * nothing about a cid running something else. The idle test covers the
 * idle task; for a higher scheduling class the kick costs an IPI and
 * leaves the CPU with the class that owns it, which is where not kicking
 * would have left it too.
 */
static void kick_queued_cid(s32 cid, const struct task_ctx *tctx, u64 dl,
			    u64 now)
{
	struct cid_ctx __arena *cctx;

	if (no_wakeup_preempt || cid_idle_test(cid))
		goto idle;

	cctx = cid_ctx(cid);

	/*
	 * Would a pick return the task just queued? It has to hold the
	 * earlier of the two deadlines and to be owed service.
	 */
	if (!time_before(dl, cctx->curr_dl))
		goto idle;
	if (!no_eligibility &&
	    time_after(tctx->vruntime, cid_vref_place(cid, now)))
		goto idle;

	/*
	 * Is the running task still owed service? Once it has run for a
	 * whole request it is past its deadline as well, and either way it
	 * has no protection left.
	 */
	if (!no_eligibility && curr_owed_service(cid, now))
		goto idle;

	scx_bpf_kick_cid(cid, SCX_KICK_PREEMPT);
	__sync_fetch_and_add(&nr_preempts, 1);

	return;
idle:
	scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(cidland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cid = scx_bpf_task_cid(p), cid;
	struct task_ctx *tctx;
	u64 dl, now;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx || !cid_valid(prev_cid))
		return;

	now = bpf_ktime_get_ns();

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
	 * A busy SMT sibling is not a reason to leave. Sharing a core is
	 * avoided when a task is placed, the idle scan prefers a fully idle
	 * core, and never by moving a running task: EEVDF does the same in
	 * select_idle_core(), and leaves a running task where it is.
	 */
	if ((task_should_migrate(p, enq_flags) && !reenq_immed(p, enq_flags)) ||
	    (reenq_preempted(p, enq_flags) && p->scx.slice && !cid_idle_test(prev_cid))) {
		cid = pick_idle_cid(p, prev_cid);
		if (cid >= 0) {
			place_task(cid, p, tctx, now);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid,
					   slice_ns, enq_flags | SCX_ENQ_IMMED);
			return;
		}
	}

	place_task(prev_cid, p, tctx, now);
	dl = task_dl(p, tctx);

	/*
	 * Queue the task on @prev_cid's DSQ, ordered by deadline.
	 *
	 * Any cid of the node can take it from there, but only while
	 * dispatching: if @prev_cid went idle in the meantime and the rest
	 * of the node is idle too, nothing would ever look at it. Kick
	 * @prev_cid, which either wakes it or interrupts what it is running
	 * for this task, see kick_queued_cid().
	 */
	scx_bpf_dsq_insert_vtime(p, cid_dsq(prev_cid), slice_ns, dl, enq_flags);
	cid_queued_set(prev_cid);
	kick_queued_cid(prev_cid, tctx, dl, now);
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
	s32 cid = scx_bpf_this_cid(), peer;
	struct task_struct *head;

	TOUCH_ARENA();

	if (!cid_valid(cid) || !scx_bpf_dsq_nr_queued(cid_dsq(cid)))
		return;

	head = __COMPAT_scx_bpf_dsq_peek(cid_dsq(cid));
	if (!head)
		return;

	peer = idle_peer_cid(head, cid);
	if (peer >= 0 && peer != cid)
		scx_bpf_kick_cid(peer, SCX_KICK_IDLE);
}

/*
 * Is @p, queued on @src_cid, still cache hot there as far as @dst_cid is
 * concerned?
 *
 * Two threads of one core share every cache there is, so a task is never
 * hot between them: moving it costs nothing and leaving one of them idle
 * costs a thread. task_hot() says the same of a domain with
 * SD_SHARE_CPUCAPACITY.
 */
static bool task_hot(struct task_struct *p, s32 src_cid, s32 dst_cid, u64 now)
{
	const struct task_ctx *tctx;

	if (smt_enabled &&
	    cid_topo(src_cid)->core_base == cid_topo(dst_cid)->core_base)
		return false;

	tctx = try_lookup_task_ctx(p);

	return tctx && time_before(now, tctx->last_stop_at + migration_cost_ns);
}

/*
 * Look at the queued cids of @w, word @k rotated by @s (packed in @ks as
 * k << 16 | s), and return the first one whose head @dst_cid can take,
 * or -1, in the low 32 bits, with the number of queues still allowed in
 * the high 32 bits. @ctl packs, from the top, the depth of @dst_cid's
 * own queue, the number of queues to look at and whether a head still
 * hot on its CPU is skipped. A queue found empty has its bit cleared. A
 * busy @dst_cid only takes from a queue more than twice as deep as its
 * own and at least two tasks deeper.
 *
 * A global function: it is verified once, not once per call site and
 * loop iteration, which keeps ops.dispatch() within the verifier's
 * budget.
 */
__noinline u64 steal_from_word(s32 dst_cid, u64 w, u32 ks, u64 now, u32 ctl)
{
	u32 k = ks >> 16, s = ks & 63, own_nr = ctl >> 16;
	u32 limit = (ctl >> 8) & 0xff;
	bool check_hot = ctl & 1;
	s32 ret = -1;

	TOUCH_ARENA();

	w = rotr64(w, s);
	while (w && limit && can_loop) {
		struct task_struct *p;
		s32 cid;

		cid = k * 64 + ((__builtin_ctzll(w) + s) & 63);
		w &= w - 1;
		if (cid == dst_cid || !cid_valid(cid))
			continue;
		limit--;

		if (own_nr) {
			u32 nr = scx_bpf_dsq_nr_queued(cid_dsq(cid));

			if (nr < own_nr + 2 || nr <= 2 * own_nr)
				continue;
		}
		p = __COMPAT_scx_bpf_dsq_peek(cid_dsq(cid));
		if (!p) {
			cid_queued_check(cid);
			continue;
		}
		if (!bpf_cpumask_test_cpu(cid_topo(dst_cid)->cpu, p->cpus_ptr) ||
		    (check_hot && task_hot(p, cid, dst_cid, now)))
			continue;

		ret = cid;
		break;
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
		 bool check_hot, u32 own_nr, u32 limit)
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
			w &= tier_word(t, k);
		if (!w)
			continue;
		ret = steal_from_word(dst_cid, w, (k << 16) | (i ? 0 : start & 63),
				      now, (own_nr << 16) | (limit << 8) | check_hot);
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
 * Dispatch on @dst_cid a task from its own DSQ or from the DSQ of another
 * cid of the node.
 *
 * A cid with nothing queued pulls the first task it finds: from the slower
 * cids first, hot or not, since a task is better off on a faster core than
 * with a warm cache on a slow one (this is what carries the load up the
 * capacity ladder, the way asym packing does), but only when its whole
 * core is idle, as a fast thread sharing its core is no better than a
 * whole slow one and asym_smt_can_pull_tasks() refuses that move too;
 * then from its own LLC, then from the rest of the node, leaving alone a
 * task that ran on its CPU a moment ago, see task_hot(): its home CPU
 * takes it back within a slice, while moving it costs its cache.
 *
 * A cid with work of its own samples @balance_sample other queues, rotating
 * through them across dispatches, and takes the head of one that is more
 * than twice as deep as its own and at least two tasks deeper. Every queue
 * is fed by the wakeups of its own CPU, so this is the only way a pile-up
 * gets spread out, e.g. a hundred children forked on one CPU while every
 * other CPU was busy with a task of its own, the way the load balancer
 * moves tasks off the busiest runqueue. The margin is what keeps CPUs
 * under an even load from trading tasks back and forth (the balancer has
 * its imbalance_pct), and a cid samples at most once per slice, the way
 * the load balancer runs on the tick rather than on every pick: sampling
 * on every dispatch under a wakeup storm moved tasks around faster than
 * they could warm a cache. Otherwise the cid takes its own head: waiting
 * for the owning CPU's slice end is what EEVDF does under RUN_TO_PARITY,
 * and sampling the queues for an earlier deadline instead measured worse
 * on every load.
 *
 * Only the heads are considered, a queue whose head cannot run on @dst_cid
 * (or is still hot there) is skipped as a whole.
 *
 * Return true if a task has been dispatched, false otherwise.
 */
static bool try_steal_task(s32 dst_cid)
{
	struct cid_ctx __arena *cctx = cid_ctx(dst_cid);
	struct cid_topo __arena *topo = cid_topo(dst_cid);
	bool own = cid_queued_test(dst_cid) &&
		   __COMPAT_scx_bpf_dsq_peek(cid_dsq(dst_cid));
	u32 node_base = numa_enabled ? topo->node_base : 0;
	u32 node_nr = numa_enabled ? topo->node_nr : nr_cids;
	u64 now = bpf_ktime_get_ns();
	u32 start, own_nr = 0;
	s32 src = -1;

	if (own) {
		if (time_before(now, cctx->last_balance_at + slice_ns))
			goto own;
		cctx->last_balance_at = now;
		own_nr = scx_bpf_dsq_nr_queued(cid_dsq(dst_cid));
		if (!own_nr)
			goto own;
	}

	start = cctx->steal_cursor;
	if (start >= nr_cids)
		start = 0;

	if (!own && asym_capacity && (!smt_enabled || core_is_idle(dst_cid))) {
		u32 t;

		/*
		 * Slower tiers first, from the slowest, hot or not.
		 */
		bpf_arena_for(t, 0, nr_tiers - topo->tier - 1) {
			src = steal_from_range(dst_cid, nr_tiers - 1 - t, node_base,
					       node_nr, node_base, now, false, 0, 0xff);
			if (src >= 0)
				goto pick;
		}
	}

	if (own) {
		/*
		 * A busy cid samples a few queues of its node, rotating
		 * through them across dispatches.
		 */
		src = steal_from_range(dst_cid, -1, node_base, node_nr, start + 1,
				       now, true, own_nr, balance_sample);
	} else {
		/*
		 * An idle cid walks its own LLC before the rest of the node,
		 * or the rest of the machine when there is nothing to gain by
		 * keeping to a node. A domain that is the whole of the next
		 * one is not walked twice.
		 */
		src = steal_from_range(dst_cid, -1, topo->llc_base, topo->llc_nr,
				       start + 1, now, true, 0, 0xff);
		if (src < 0 && node_nr > topo->llc_nr)
			src = steal_from_range(dst_cid, -1, node_base, node_nr,
					       start + 1, now, true, 0, 0xff);
	}
	cctx->steal_cursor = src >= 0 ? src : start + balance_sample;

own:
	if (src < 0 && own)
		src = dst_cid;

pick:
	if (src < 0)
		return false;

	if (!scx_bpf_dsq_move_to_local(cid_dsq(src), 0)) {
		cid_queued_check(src);
		return false;
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

void BPF_STRUCT_OPS(cidland_dispatch, s32 cid, struct task_struct *prev)
{
	TOUCH_ARENA();

	if (!cid_valid(cid))
		return;

	/*
	 * Take a task from this cid's queue or from a deeper one on the
	 * node, then fall back to this cid's own DSQ in case the pick raced
	 * with another cid.
	 */
	if (try_steal_task(cid))
		return;
	if (scx_bpf_dsq_move_to_local(cid_dsq(cid), 0)) {
		cid_queued_check(cid);
		return;
	}

	/*
	 * If the previous task expired its time slice, but no other task
	 * wants to run on this CPU, give it another time slot.
	 */
	if (prev && is_task_queued(prev)) {
		scx_bpf_task_set_slice(prev, slice_ns);
		return;
	}

	/*
	 * Nothing to run: the CPU is going idle. ops.update_idle() will not
	 * say so if the cid was claimed and kicked for a task that never
	 * came, since there is no transition then, so re-arm the bit here.
	 */
	cid_idle_rearm(cid);
}

void BPF_STRUCT_OPS(cidland_update_idle, s32 cid, bool idle)
{
	TOUCH_ARENA();

	if (idle)
		cid_idle_set(cid);
	else
		cid_idle_claim(cid);
}

void BPF_STRUCT_OPS(cidland_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;
	s64 limit, lag;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

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
	cid = cid_valid(tctx->vcid) ? tctx->vcid : scx_bpf_task_cid(p);
	if (cid_valid(cid)) {
		limit = scale_by_dl_weight(p, slice_lag);
		lag = (s64)(cid_vref_place(cid, bpf_ktime_get_ns()) -
			    tctx->vruntime);
		if (lag > limit)
			lag = limit;
		else if (lag < -limit)
			lag = -limit;
		tctx->vlag = lag;
	}
	vref_leave(tctx);
}

void BPF_STRUCT_OPS(cidland_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

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
	vref_leave(tctx);
}

void BPF_STRUCT_OPS(cidland_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate
	 * the used time slice).
	 */
	tctx->last_run_at = bpf_ktime_get_ns();

	cid = scx_bpf_task_cid(p);

	/*
	 * A task that was moved here from another cid's queue, by the
	 * balancer or an idle pull, carries a vruntime that means nothing
	 * against this cid's pack: taken from a pack that was far ahead it
	 * would wait here until the pack climbs past it, seconds under
	 * load. Carry the lag instead, the way a migration does in
	 * place_entity(): how far the task was from the pack it left is how
	 * far it is placed from the pack it joins.
	 */
	if (cid_valid(tctx->vcid) && tctx->vcid != cid) {
		s64 limit = scale_by_dl_weight(p, slice_lag);
		s64 lag = (s64)(cid_vref_place(tctx->vcid, tctx->last_run_at) -
				tctx->vruntime);

		if (lag > limit)
			lag = limit;
		else if (lag < -limit)
			lag = -limit;
		tctx->vruntime = cid_vref_place(cid, tctx->last_run_at) - lag;
		tctx->deadline = 0;
	}
	vref_join(cid, p, tctx);

	/*
	 * Publish what this cid is running. A task queued here later is
	 * compared against that deadline to decide whether it is worth
	 * interrupting, see kick_queued_cid().
	 */
	if (cid_valid(cid)) {
		struct cid_ctx __arena *cctx = cid_ctx(cid);

		cctx->curr_dl = task_dl(p, tctx);
		cctx->curr_v = tctx->vruntime;
		cctx->curr_w = task_weight(p);
		cctx->curr_run_at = tctx->last_run_at;
	}

	/*
	 * Refresh cpufreq performance level.
	 */
	update_cpufreq(cid);
}

void BPF_STRUCT_OPS(cidland_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 slice;
	s32 cid;

	TOUCH_ARENA();

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	cid = scx_bpf_task_cid(p);

	/*
	 * Evaluate the used time slice.
	 */
	tctx->last_stop_at = bpf_ktime_get_ns();
	slice = tctx->last_stop_at - tctx->last_run_at;

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
	tctx->vruntime += calc_delta_fair(p, slice);
	vref_charge(tctx);

	/*
	 * The service just charged is in the reference for real now, so
	 * there is nothing left for cid_vref_at() to project on this cid
	 * until ops.running() picks the next task.
	 */
	if (cid_valid(cid))
		cid_ctx(cid)->curr_w = 0;

	/*
	 * Update per-cid statistics.
	 */
	update_cpu_load(p, slice);
}

void BPF_STRUCT_OPS(cidland_enable, struct task_struct *p)
{
	struct task_ctx *tctx = try_lookup_task_ctx(p);

	if (tctx) {
		tctx->vruntime = 0;
		tctx->deadline = 0;
		tctx->vcid = -1;
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cidland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	tctx->vcid = -1;

	/*
	 * @fork tells a task that is being created apart from one that was
	 * already running when the scheduler was loaded, which is the
	 * distinction ENQUEUE_INITIAL draws: wake_up_new_task() sets it and
	 * nothing else does, see task_dl().
	 */
	tctx->initial = args->fork;

	return 0;
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

	bpf_for(i, 0, nr_cids) {
		struct scx_cid_topo *ct = &init_topo;
		s32 cid = nr_cids - 1 - i;
		struct cid_topo __arena *topo = cid_topo(cid);
		s32 cpu = scx_bpf_cid_to_cpu(cid);

		scx_bpf_cid_topo(cid, ct);

		topo->cpu = cpu >= 0 ? cpu : 0;
		if (cpu >= 0 && (u32)cpu < nr_cpu_ids) {
			topo->cap = cpu_cap_in[cpu];
			topo->tier = cpu_tier_in[cpu];
		} else {
			topo->cap = 1;
			topo->tier = nr_tiers - 1;
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
	cmask_init(queued_cids, 0, nr_cids);
	bpf_for(cid, 0, nr_tiers)
		cmask_init(tier_mask(cid), 0, nr_cids);

	nr_words = cmask_nr_words(idle_cids);

	init_topology();

	/*
	 * Build the bitmap of each capacity tier, create the per-cid DSQs
	 * and start with every cid idle, the way the kernel resets its own
	 * idle masks: a CPU that is busy clears its bit as soon as a task
	 * runs there, while a CPU that sits idle from the start never
	 * transitions, and left with its bit clear it would never be
	 * picked, so never transition, for good.
	 */
	bpf_for(cid, 0, nr_cids) {
		struct cid_topo __arena *topo = cid_topo(cid);

		if (topo->tier >= nr_tiers)
			topo->tier = nr_tiers - 1;
		__cmask_set(cid, tier_mask(topo->tier));

		err = scx_bpf_create_dsq(cid_dsq(cid), -1);
		if (err) {
			scx_bpf_error("failed to create DSQ for cid %d: %d", cid, err);
			return err;
		}
		cid_idle_set(cid);
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
 * Size the arena for a cid space of @args->nr_cpus and @args->nr_tiers
 * capacity tiers, and carve the tables out of it.
 *
 * Run by user space after load and before attach: the tables have to be
 * in place before ops.init(), and the cid space, num_possible_cpus()
 * wide, is known before the scheduler is.
 */
SEC("syscall")
int cidland_arena_init(struct cidland_arena_args *args)
{
	u64 nr = args->nr_cpus, mask, bytes, pages;

	if (!nr || !args->nr_tiers)
		return -EINVAL;

	/*
	 * A cmask over the whole cid space, cache line aligned: the helpers
	 * ask for a word past the bits, see CMASK_NR_WORDS().
	 */
	mask = (sizeof(struct scx_cmask) + (u64)CMASK_NR_WORDS(nr) * sizeof(u64) + 63) & ~63ULL;
	bytes = nr * sizeof(struct cid_topo) + nr * sizeof(struct cid_ctx) +
		(2 + args->nr_tiers) * mask +
		nr * (sizeof(u64) + sizeof(u32)) + 9 * 64;
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	arena_base = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!arena_base)
		return -ENOMEM;
	arena_size = pages * PAGE_SIZE;
	arena_off = 0;

	topos = arena_carve(nr * sizeof(struct cid_topo), 64);
	cctxs = arena_carve(nr * sizeof(struct cid_ctx), 64);
	idle_cids = arena_carve(mask, 64);
	queued_cids = arena_carve(mask, 64);
	tier_stride = mask;
	tier_cids = arena_carve(args->nr_tiers * mask, 64);
	cpu_cap_in = arena_carve(nr * sizeof(u64), 64);
	cpu_tier_in = arena_carve(nr * sizeof(u32), 64);
	if (!topos || !cctxs || !idle_cids || !queued_cids || !tier_cids ||
	    !cpu_cap_in || !cpu_tier_in)
		return -ENOMEM;

	nr_cids_max = nr;
	nr_tiers = args->nr_tiers;
	asym_capacity = nr_tiers > 1;

	return 0;
}

/*
 * Report the capacity and the tier of one CPU, in cpu space: the cid
 * layout is only known once the kernel has built it, so ops.init()
 * translates.
 */
SEC("syscall")
int cidland_set_cpu(struct cidland_cpu_args *args)
{
	u64 cpu = args->cpu;

	TOUCH_ARENA();

	if (!cpu_cap_in || cpu >= nr_cids_max || args->tier >= nr_tiers)
		return -EINVAL;

	cpu_cap_in[cpu] = args->capacity;
	cpu_tier_in[cpu] = args->tier;

	return 0;
}

SCX_OPS_CID_DEFINE(cidland_ops,
		   .select_cid		= (void *)cidland_select_cid,
		   .enqueue		= (void *)cidland_enqueue,
		   .tick		= (void *)cidland_tick,
		   .dispatch		= (void *)cidland_dispatch,
		   .runnable		= (void *)cidland_runnable,
		   .quiescent		= (void *)cidland_quiescent,
		   .running		= (void *)cidland_running,
		   .stopping		= (void *)cidland_stopping,
		   .update_idle		= (void *)cidland_update_idle,
		   .enable		= (void *)cidland_enable,
		   .init_task		= (void *)cidland_init_task,
		   .init		= (void *)cidland_init,
		   .exit		= (void *)cidland_exit,
		   .timeout_ms		= 5000,
		   .name		= "cidland");
