/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cidland: a topology-aware scheduler built on cids.
 *
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2.
 *
 * This is a cid-form scheduler (struct sched_ext_ops_cid): instead of raw CPU
 * numbers it addresses CPUs by their cid (topological CPU ID), a dense id space
 * where the CPUs of a core, of an LLC and of a NUMA node always occupy
 * contiguous ranges.
 *
 * That property is the whole point of this scheduler: a topology domain is just
 * a (base, len) slice of the cid space, so "is this core fully idle?" and "is
 * there an idle CPU in my LLC?" become plain range scans over a bitmap, with no
 * cpumask allocation and no per-CPU topology lookups in the hot path.
 *
 * Placement follows the topology: a waking task is dispatched directly to an
 * idle cid when one can be found, preferring (in order) a fully idle core, the
 * previous LLC, and finally anything idle in the system. Tasks that don't get
 * an idle cid are queued on the DSQ of the cid they last ran on, ordered by
 * the virtual deadline computed by task_dl(), and every dispatch scans the
 * heads of the other cids' queues for an earlier deadline to take.
 */
#include <scx/common.bpf.h>
#include <lib/arena_map.h>
#include <lib/const-defs.h>
#include <lib/sdt_task.h>
#include "intf.h"

/*
 * cid-form schedulers must provide a BPF arena, which the kernel uses for the
 * per-task cmasks.
 *
 * The cid bitmaps and the task contexts living in the arena need the
 * compiler to cast between arena and kernel pointers on its own. Same
 * requirement the arena allocators in lib/ already carry.
 */
#ifndef __BPF_FEATURE_ADDR_SPACE_CAST
#error "scx_cidland requires a compiler with bpf_addr_space_cast support"
#endif

/*
 * The verifier only associates a program with an arena if the program emits an
 * LD_IMM64 loading the map. The cmask helpers can't do it themselves, since
 * scx/cid.bpf.h is included by schedulers that have no arena at all, so every
 * program that reaches an arena resident cmask has to say so explicitly or its
 * first addr_space_cast is rejected.
 */
#define TOUCH_ARENA()	do { asm volatile("" :: "r"(&arena)); } while (0)

char _license[] SEC("license") = "GPL";

/*
 * Storage for the arena spinlock queue nodes that the allocator behind
 * scx_task_alloc() takes.
 *
 * This normally comes from lib/common.bpf.c, but a translation unit that has
 * __arena globals of its own emits the extern declaration into its own
 * .addr_space.1 as a zero sized definition, which then collides with the real
 * one at link time. Defining it here keeps it to a single definition.
 */
struct arena_qnode __arena __hidden qnodes[_Q_MAX_CPUS][_Q_MAX_NODES];

/*
 * Define struct user_exit_info which is shared between BPF and userspace to
 * communicate the exit status.
 */
UEI_DEFINE(uei);

/*
 * Slack pages added to the arena's static pool on top of what the cid keyed
 * arrays need, for the task context allocator's own bookkeeping. Same
 * granularity ArenaLib uses.
 */
#define STATIC_ALLOC_PAGES	8

/*
 * The verifier only associates a program with an arena if the program emits an
 * LD_IMM64 loading the map. Reaching the arena through a pointer kept in a
 * global doesn't do that, so a program that has no other reason to load the
 * map has to say so explicitly, or its first addr_space_cast is rejected.
 *
 * The cid bitmap helpers do this internally. Keep a local form for programs
 * which access other arena globals without going through those helpers.
 */
#define TOUCH_ARENA()	do { asm volatile("" :: "r"(&arena)); } while (0)

/* Time slice assigned to each task. */
const volatile u64 slice_ns;

/*
 * Maximum lag, in virtual time, that a task can carry across a sleep.
 */
const volatile u64 slice_lag;

/*
 * True when the system has more than one NUMA node and the node ranges are
 * worth walking (see --disable-numa).
 */
const volatile bool numa_enabled;

/*
 * Scheduling statistics.
 */
volatile u64 nr_direct_dispatches, nr_queued, nr_steals;
volatile u64 nr_local_llc, nr_remote_llc;

/*
 * Size of the cid space, initialized in ops.init(). All the valid cids are in
 * [0, nr_cids).
 */
static u32 nr_cids;

/*
 * Width of the cid space that the arena arrays below were sized for,
 * established by cidland_arena_init() from the CPU count userspace hands it.
 */
static u32 nr_cids_max;

/*
 * Number of capacity tiers, 0 being the fastest, and whether there is more
 * than one. Also set by cidland_arena_init().
 */
static u32 nr_tiers;
static bool asym_capacity;

/*
 * Capacity and tier of every CPU, in cpu space, filled by cidland_set_cpu()
 * before attach and consumed once by ops.init(): userspace has no way to know
 * the cid layout, the kernel only builds it at scheduler enable time.
 */
static u64 __arena *cpu_cap_in;
static u32 __arena *cpu_tier_in;

/*
 * Number of words of storage a cmask framed over the cid space needs.
 *
 * CMASK_NR_WORDS() asks for a word beyond the bits themselves, so that a mask
 * based at a cid that isn't word aligned still has room for the word its range
 * spills into. The cmask helpers size their loops off it, so the storage has to
 * match: with one word per 64 cids alone, cmask_init() and cmask_zero() write one word
 * past the allocation.
 */
static u32 nr_cmask_words;

/*
 * Number of possible CPU ids, initialized in ops.init(). Used to detect the
 * tasks that can run on any CPU.
 */
static u32 nr_cpu_ids;

/*
 * Current system virtual time: the reference every task is placed against.
 */
static u64 vtime_now;

/*
 * Total weight of the runnable tasks, EEVDF's \Sum w_i (cfs_rq->sum_weight).
 *
 * Maintained across the ops.runnable() / ops.quiescent() pair, which the core
 * scheduler guarantees to be symmetric, so it converges even when a task is
 * dequeued without ever being consumed by the BPF side.
 */
static u64 sum_weight;

/*
 * Per-task context.
 */
struct task_ctx {
	u64 last_run_at;		/* when the task last started running */
	u64 last_stop_at;		/* when the task last stopped running */
	u64 vruntime;			/* total runtime, scaled by the weight */
	s64 vlag;			/* lag carried across a sleep */
	struct scx_cmask allowed;	/* cids the task is allowed to run on */
};

/* Size of a cmask framed over @nr_words words of bits. */
static u64 cmask_size(u32 nr_words)
{
	return sizeof(struct scx_cmask) + (u64)nr_words * sizeof(u64);
}

/* Size of a task context holding @nr_words words of allowed cids. */
static u64 task_ctx_size(u32 nr_words)
{
	return sizeof(struct task_ctx) + (u64)nr_words * sizeof(u64);
}

/*
 * Task contexts are allocated from the arena so that @allowed is an arena
 * pointer like @all_cids, and the pick loop can take either without caring
 * which one it got.
 *
 * Every ops path that looks a context up runs between ops.init_task() and
 * ops.exit_task(), so this never returns NULL and the callers don't test it.
 * A stray NULL dereference would be caught by the arena, which aborts the
 * scheduler with a backtrace rather than reading whatever is at offset 0.
 */
static struct task_ctx __arena *lookup_task_ctx(const struct task_struct *p)
{
	return scx_task_data((struct task_struct *)p);
}

/*
 * Per-cid topology, initialized in ops.init(). Both ranges are expressed in cid
 * space and are guaranteed to be contiguous.
 */
struct cid_ctx {
	u64 cap;		/* capacity of the CPU behind this cid, 1024 = fastest */
	u32 tier;		/* capacity tier, 0 = fastest */
	u32 core_base;		/* first cid of the core this cid belongs to */
	u32 core_nr;		/* number of cids (SMT siblings) in the core */
	u32 llc_base;		/* first cid of the LLC this cid belongs to */
	u32 llc_nr;		/* number of cids in the LLC */
	u32 node_base;		/* first cid of the NUMA node this cid belongs to */
	u32 node_nr;		/* number of cids in the node */
	u64 vtime_rem;		/* service not yet folded into @vtime_now */
	u64 last_balance_at;	/* when this cid last sampled the other queues */
	u32 steal_cursor;	/* where the last queue scan stopped */
};

/*
 * The topology table lives in the arena the cid form already gives us. Arena
 * pointers aren't range tracked by the verifier, so a cid that's known to be
 * in range can index it directly, instead of going through a bounds checked
 * helper that returns NULL and makes every caller handle a case that can't
 * happen.
 */
static struct cid_ctx __arena *cid_ctxs;

/*
 * Mask with every cid set, handed to the pick loop for the tasks that can run
 * anywhere: it keeps the loop testing a real mask instead of special casing a
 * NULL one, which the verifier can't follow through the inlined tests.
 */
static struct scx_cmask __arena *all_cids;

/*
 * Bitmap of the cids that are currently idle, maintained by ops.update_idle().
 *
 * Since cids are topologically ordered, each word covers 64 CPUs that are
 * close to each other in the system topology.
 */
static struct scx_cmask __arena *idle_cids;

/*
 * Return true if @cid is a cid this scheduler can address.
 *
 * The mask helpers below index the arena without a bounds check, so every cid
 * coming in from the outside has to go through here first.
 */
static bool cid_valid(s32 cid)
{
	return cid >= 0 && (u32)cid < nr_cids;
}

/*
 * Return the topology of @cid.
 *
 * @cid must be valid, see cid_valid().
 */
static struct cid_ctx __arena *cid_ctx(s32 cid)
{
	TOUCH_ARENA();

	return &cid_ctxs[cid];
}

/*
 * Return the DSQ of @cid.
 *
 * Every cid owns a deadline ordered DSQ where the tasks that last ran on it
 * are queued, and every dispatch scans the heads of the other cids' DSQs for
 * the earliest deadline (see try_steal_task()). All the keys are built on the
 * same system-wide vruntime reference, so the queues behave as a single
 * system-wide deadline queue, without the single lock that a single queue puts
 * in the path of every wakeup.
 */
static inline u64 cid_dsq(s32 cid)
{
	return cid;
}

static bool cid_test_idle(s32 cid)
{
	TOUCH_ARENA();

	return __cmask_test(cid, idle_cids);
}

/* Set or clear the idle bit of @cid. */
static void cid_set_idle(s32 cid, bool idle)
{
	TOUCH_ARENA();

	if (idle)
		cmask_set(cid, idle_cids);
	else
		cmask_clear(cid, idle_cids);
}

/*
 * Atomically claim @cid, returning true if this caller is the one that
 * transitioned it out of the idle state.
 *
 * Claiming keeps two tasks queued back to back from aiming at the same cid.
 * It's optimistic: if the claimed cid ends up with nothing to run, its idle bit
 * is re-armed in ops.dispatch(), see cidland_dispatch().
 */
static bool cid_claim_idle(s32 cid)
{
	TOUCH_ARENA();

	return cmask_test_and_clear(cid, idle_cids);
}

/*
 * Return true if all the cids in [@base, @base + @nr) are idle.
 *
 * Used to test whether a whole core is idle: SMT siblings are contiguous in
 * cid space, so a core is just a range.
 */
static bool cid_range_is_idle(u32 base, u32 nr)
{
	TOUCH_ARENA();

	if (!nr)
		return false;

	return cmask_full_range(idle_cids, base, nr);
}

/*
 * Return true if the whole core of @cid is idle, i.e. @cid is idle and so are
 * its SMT siblings, if any.
 */
static bool core_is_idle(s32 cid)
{
	const struct cid_ctx __arena *cctx = cid_ctx(cid);

	return cid_range_is_idle(cctx->core_base, cctx->core_nr);
}

/*
 * Seed @tctx->allowed with the cids @p can currently run on, translating its
 * cpumask into cid space one cpu at a time.
 *
 * ops.set_cmask() keeps the mask in sync from here on, but it's only called on
 * affinity changes and scheduling class switches, so the mask has to be primed
 * when the task first shows up.
 */
static void seed_task_cmask(struct task_struct *p, struct task_ctx __arena *tctx)
{
	TOUCH_ARENA();

	u32 cpu;

	cmask_zero(&tctx->allowed);

	bpf_for(cpu, 0, nr_cpu_ids) {
		s32 cid;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		cid = scx_bpf_cpu_to_cid(cpu);
		if (!cid_valid(cid))
			continue;

		__cmask_set(cid, &tctx->allowed);
	}
}

/*
 * Return true if @p can run on more than one cid.
 *
 * Mirrors the condition the core scheduler uses in select_task_rq() to decide
 * whether to consult the scheduling class at all.
 */
static bool task_can_migrate(const struct task_struct *p)
{
	return p->nr_cpus_allowed > 1 && !is_migration_disabled(p);
}

/*
 * Scan [@base, @base + @nr) for an idle cid of tier @t usable by @p and claim
 * it.
 *
 * If @whole_core is true only cids whose entire core is idle are considered,
 * to avoid stacking tasks on SMT siblings while full cores are available.
 *
 * Return the claimed cid or a negative value if none was found.
 */
static s32 claim_idle_cid_range(const struct scx_cmask __arena *allowed, u32 t,
				u32 base, u32 nr, bool whole_core)
{
	TOUCH_ARENA();

	u32 cid;

	bpf_for(cid, base, base + nr) {
		const struct cid_ctx __arena *cctx;

		if (cid >= nr_cids)
			break;
		if (!cid_test_idle(cid))
			continue;
		cctx = cid_ctx(cid);
		if (cctx->tier != t)
			continue;
		if (whole_core && !core_is_idle(cid))
			continue;
		if (!__cmask_test(cid, allowed))
			continue;
		if (cid_claim_idle(cid))
			return cid;
	}

	return -EBUSY;
}

/*
 * Pick an idle cid for @p one capacity tier at a time, from the fastest.
 *
 * Only fully idle cores are considered if @whole_core is set, any idle cid
 * otherwise: the caller runs the whole core pass first, across every tier,
 * since sharing a core costs more than the step down to the next tier, the way
 * select_idle_core() looks for a whole core before select_idle_cpu() settles
 * for a thread.
 *
 * Within a tier @prev_cid wins, then a cid in the same LLC, then a cid on the
 * same node, then any cid, to keep the task where its cache is: the order
 * select_idle_sibling() applies within one domain, with the node on top since
 * this scan covers them all. Each domain is a contiguous range, so a wakeup
 * reads the cids of its own LLC before anything else.
 *
 * Return the claimed cid or a negative value if nothing idle was found.
 */
static s32 pick_idle_cid_ranked(const struct scx_cmask __arena *allowed,
				const struct cid_ctx __arena *cctx, s32 prev_cid,
				bool whole_core)
{
	u32 t;

	bpf_for(t, 0, nr_tiers) {
		s32 cid;

		if (cctx->tier == t && __cmask_test(prev_cid, allowed) &&
		    cid_test_idle(prev_cid) &&
		    (!whole_core || core_is_idle(prev_cid)) &&
		    cid_claim_idle(prev_cid))
			return prev_cid;

		/*
		 * A domain that is the whole of the next one is not scanned
		 * twice.
		 */
		cid = claim_idle_cid_range(allowed, t, cctx->llc_base, cctx->llc_nr,
					   whole_core);
		if (cid < 0 && numa_enabled && cctx->node_nr > cctx->llc_nr)
			cid = claim_idle_cid_range(allowed, t, cctx->node_base,
						   cctx->node_nr, whole_core);
		if (cid < 0 && (numa_enabled ? cctx->node_nr : cctx->llc_nr) < nr_cids)
			cid = claim_idle_cid_range(allowed, t, 0, nr_cids, whole_core);
		if (cid >= 0)
			return cid;
	}

	return -EBUSY;
}

/*
 * Find an idle cid for @p, preferring topological locality with @prev_cid.
 *
 * Return the claimed cid or a negative value if the whole system is busy.
 */
static s32 pick_idle_cid(const struct task_struct *p, s32 prev_cid,
			 bool from_enqueue, bool core_only)
{
	const struct cid_ctx __arena *cctx;
	const struct scx_cmask __arena *allowed = all_cids;
	s32 cid;

	/*
	 * The core scheduler supplies a valid cid here. Keep the check so an
	 * unexpected value never indexes the cid keyed arena arrays.
	 */
	if (!cid_valid(prev_cid))
		return -EBUSY;
	cctx = cid_ctx(prev_cid);

	/*
	 * Tasks that can't migrate never reach ops.select_cid(): the core
	 * scheduler skips the scheduling class for them (see
	 * select_task_rq()), so they only get here from ops.enqueue(), which
	 * passes the cid they're sitting on as @prev_cid.
	 *
	 * That's their only candidate, so try it and give up, rather than
	 * scanning cids they can't use anyway.
	 */
	if (from_enqueue && !task_can_migrate(p)) {
		if (!cid_claim_idle(prev_cid))
			return -EBUSY;
		__sync_fetch_and_add(&nr_local_llc, 1);
		return prev_cid;
	}

	/*
	 * Only the tasks that can't run everywhere need their allowed mask,
	 * which keeps the task storage lookup out of the wakeup path for all
	 * the others. Checking it once here also beats re-checking the task's
	 * affinity for every candidate cid.
	 */
	if (p->nr_cpus_allowed < nr_cpu_ids)
		allowed = &lookup_task_ctx(p)->allowed;

	/*
	 * Fully idle cores first, across every tier, then any idle cid: a
	 * caller that only wants a whole core stops after the first pass,
	 * since taking an SMT sibling would put the task on a core that is
	 * already running something, which costs more than the wait it saves.
	 */
	cid = pick_idle_cid_ranked(allowed, cctx, prev_cid, true);
	if (cid < 0 && !core_only)
		cid = pick_idle_cid_ranked(allowed, cctx, prev_cid, false);
	if (cid < 0)
		return cid;

	if (cid >= cctx->llc_base && cid < cctx->llc_base + cctx->llc_nr)
		__sync_fetch_and_add(&nr_local_llc, 1);
	else
		__sync_fetch_and_add(&nr_remote_llc, 1);

	return cid;
}

/*
 * Return the cid of the node of @prev_cid with the fewest tasks queued that @p
 * can run on, the fastest one on ties, or -EBUSY.
 *
 * A new task that finds no idle cid would otherwise be queued behind its
 * parent, and a parent forking a hundred workers on a busy system would stack
 * them all on one queue. find_idlest_cpu() spreads forks by load for the same
 * reason.
 */
static s32 shallowest_queue_cid(const struct task_struct *p,
				const struct scx_cmask __arena *allowed,
				const struct cid_ctx __arena *prev)
{
	u32 base = numa_enabled ? prev->node_base : 0;
	u32 nr = numa_enabled ? prev->node_nr : nr_cids;
	s32 best = -EBUSY, best_nr = 0;
	u32 best_tier = 0, cid;

	bpf_for(cid, base, base + nr) {
		const struct cid_ctx __arena *other;
		s32 nr_queued;

		if (cid >= nr_cids)
			break;
		if (!__cmask_test(cid, allowed))
			continue;

		other = cid_ctx(cid);
		nr_queued = scx_bpf_dsq_nr_queued(cid_dsq(cid));
		if (best < 0 || nr_queued < best_nr ||
		    (nr_queued == best_nr && other->tier < best_tier)) {
			best = cid;
			best_nr = nr_queued;
			best_tier = other->tier;
			if (!nr_queued && !best_tier)
				break;
		}
	}

	return best;
}

/*
 * Return an idle cid faster than @cid whose whole core is idle, or -ENOENT.
 * The idle state is not claimed: the caller is expected to kick it.
 *
 * Only a fully idle faster core counts: pulling a task from a whole slow core
 * onto a fast thread whose sibling is busy trades the capacity for a shared
 * core, which is what asym_smt_can_pull_tasks() refuses to do.
 */
static s32 idle_faster_cid(s32 cid)
{
	const struct cid_ctx __arena *cctx;
	u32 tier, c;

	if (!asym_capacity || !cid_valid(cid))
		return -ENOENT;

	cctx = cid_ctx(cid);
	tier = cctx->tier;

	bpf_for(c, 0, nr_cids) {
		const struct cid_ctx __arena *other = cid_ctx(c);

		if (other->tier >= tier || !cid_test_idle(c))
			continue;
		if (!core_is_idle(c))
			continue;

		return c;
	}

	return -ENOENT;
}

/*
 * Floor on the weight used to stretch the request and the lag bound.
 *
 * The scx weight of a nice 19 task is 1, so its request would be a hundred
 * times the base slice and the lag it can carry two hundred times: under a
 * deep backlog V takes many seconds to cover that, well past the watchdog. The
 * vruntime is still charged with the real weight, so the share is what nice
 * asks for; only how far ahead the deadline and the lag can stretch is capped,
 * which update_deadline() itself notes is "probably good enough".
 */
#define MIN_DL_WEIGHT	25

static u64 scale_by_dl_weight(const struct task_struct *p, u64 value)
{
	u64 weight = p->scx.weight;

	if (weight < MIN_DL_WEIGHT)
		weight = MIN_DL_WEIGHT;

	return value * 100 / weight;
}

/*
 * Return the virtual deadline of @p.
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
 */
static u64 task_dl(const struct task_struct *p, const struct task_ctx __arena *tctx)
{
	return tctx->vruntime + scale_by_dl_weight(p, slice_ns);
}

s32 BPF_STRUCT_OPS(cidland_select_cid, struct task_struct *p, s32 prev_cid,
		   u64 wake_flags)
{
	s32 cid;

	cid = pick_idle_cid(p, prev_cid, false, false);
	if (cid < 0) {
		/*
		 * A new task with no idle cid to go to is queued on the cid
		 * with the shortest queue rather than behind its parent.
		 */
		if ((wake_flags & SCX_WAKE_FORK) && cid_valid(prev_cid)) {
			const struct scx_cmask __arena *allowed = all_cids;

			if (p->nr_cpus_allowed < nr_cpu_ids)
				allowed = &lookup_task_ctx(p)->allowed;

			cid = shallowest_queue_cid(p, allowed, cid_ctx(prev_cid));
			if (cid >= 0)
				return cid;
		}

		return prev_cid;
	}

	/*
	 * An idle cid was claimed, dispatch @p directly to it: the local DSQ of
	 * the cid returned from here.
	 *
	 * Insert with SCX_ENQ_IMMED, so that the kernel bounces @p back through
	 * ops.enqueue() (and from there into the deadline-ordered shared queue)
	 * whenever it can't run on the claimed cid right away.
	 *
	 * Claiming an idle cid is optimistic: the idle bitmap is only a hint and
	 * it can say idle for a cid that is already busy (for example when
	 * cidland_dispatch() re-arms the bit right after a task has been queued
	 * to that cid). Without SCX_ENQ_IMMED such a task would just stack on a
	 * busy local DSQ, and since the kernel skips ops.dispatch() entirely
	 * while a local DSQ is not empty, that cid would stop consuming the
	 * shared queue: tasks that only it can run (per-CPU kthreads,
	 * migration-disabled tasks) have no other consumer, as the other cids
	 * walk past them in scx_bpf_dsq_move_to_local(), so they could stall
	 * indefinitely.
	 */
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, SCX_ENQ_IMMED);
	__sync_fetch_and_add(&nr_direct_dispatches, 1);

	return cid;
}

/*
 * Return true if @p should be considered for a migration.
 *
 * Only worth attempting on a wakeup (the task wasn't running) that hasn't
 * already been placed by ops.select_cid().
 */
static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

void BPF_STRUCT_OPS(cidland_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx __arena *tctx;
	s32 cid, prev_cid = scx_bpf_task_cid(p);

	/*
	 * Try to place @p on an idle cid before falling back to the shared
	 * queue.
	 *
	 * Queueing to the shared DSQ and kicking a cid to come and find the
	 * task there costs an enqueue -> kick -> dispatch round trip, and it
	 * makes the deadline ordered queue the path every wakeup takes. Under
	 * load that queue fills with tasks that sleep more than they run, and
	 * since @vtime_now only advances when a task with a larger vruntime
	 * gets to run, anything that accumulates runtime ends up ordered behind
	 * all of them for as long as they keep waking up.
	 *
	 * Dispatching straight to the local DSQ of an idle cid keeps those
	 * tasks out of the queue entirely, which leaves it as the overflow path
	 * it's meant to be.
	 *
	 * The search is skipped when ops.select_cid() has already run and come
	 * up empty, unless @prev_cid is busy: repeating it right away would
	 * just walk the same masks again.
	 *
	 * A busy @prev_cid is a reason to leave only when it is busy with
	 * someone else. A task that is re-enqueued from its own cid at the
	 * end of its slice is what @prev_cid is busy with, and it is giving
	 * the CPU up to whoever was waiting for it, typically a per-CPU
	 * kworker that is done a few microseconds later. Pushing it away at
	 * that point turns every such handover into a migration. Leave it
	 * queued instead, the way a task stays on its runqueue: its own cid
	 * takes it back as soon as it is free again.
	 *
	 * A task re-enqueued from its own cid with slice left, on the other
	 * hand, was preempted by a higher scheduling class (the kernel
	 * bounces an IMMED task back through ops.enqueue() in that case)
	 * and @prev_cid is taken for an unknown amount of time, so an idle
	 * cid is the better option.
	 */
	if (task_should_migrate(p, enq_flags) ||
	    (!cid_test_idle(prev_cid) && (!scx_bpf_task_running(p) || p->scx.slice))) {
		/*
		 * A task that ops.select_cid() already looked at is only moved
		 * onto a fully idle core: it is being re-queued rather than
		 * woken, so stacking it on an SMT sibling would slow down the
		 * core that is already busy without saving it any wait.
		 */
		cid = pick_idle_cid(p, prev_cid, true,
				    !task_should_migrate(p, enq_flags));
		if (cid >= 0) {
			/*
			 * SCX_ENQ_IMMED bounces @p back here if the cid can't
			 * run it right away, so the local DSQ stays a "run now"
			 * fast path instead of a queue that outranks the shared
			 * one, see cidland_select_cid().
			 */
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cid, slice_ns,
					   enq_flags | SCX_ENQ_IMMED);
			__sync_fetch_and_add(&nr_direct_dispatches, 1);
			return;
		}
	}

	tctx = lookup_task_ctx(p);

	/*
	 * Queue the task on @prev_cid's DSQ, ordered by deadline.
	 *
	 * Any other cid can take it from there, but only while dispatching: if
	 * @prev_cid went idle in the meantime and the rest of the system is
	 * idle too, nothing would ever look at it. Kick @prev_cid, which is a
	 * no-op unless it is idle.
	 */
	scx_bpf_dsq_insert_vtime(p, cid_dsq(prev_cid), slice_ns,
				 task_dl(p, tctx), enq_flags);
	__sync_fetch_and_add(&nr_queued, 1);

	scx_bpf_kick_cid(prev_cid, SCX_KICK_IDLE);

	/*
	 * A faster cid sitting idle would never look at this queue on its
	 * own: wake it up so that it pulls the task, see try_steal_task().
	 */
	if (task_can_migrate(p)) {
		s32 cid = idle_faster_cid(prev_cid);

		if (cid >= 0)
			scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
	}
}

/*
 * Return true if @p can keep running on the current cid, instead of being put
 * back on a deadline ordered queue.
 */
static bool keep_running(const struct task_struct *p, s32 cid)
{
	TOUCH_ARENA();

	/* The task doesn't want to run anymore. */
	if (!(p->scx.flags & SCX_TASK_QUEUED))
		return false;

	return true;
}

/*
 * A task that ran within this long on its cid is still cache hot there and is
 * not stolen, like task_hot() with sysctl_sched_migration_cost.
 */
#define MIGRATION_COST_NS	500000ULL

static bool task_hot(struct task_struct *p, u64 now)
{
	const struct task_ctx __arena *tctx = lookup_task_ctx(p);

	return time_before(now, tctx->last_stop_at + MIGRATION_COST_NS);
}

/*
 * Number of other cids' queues a busy cid looks at on each dispatch for a
 * queue deeper than its own.
 */
#define BALANCE_SAMPLE	2

/*
 * Dispatch on @dst_cid a task from its own DSQ or from the DSQ of another cid.
 *
 * A cid with nothing queued pulls the first task it finds: from the slower
 * cids first, hot or not, since a task is better off on a faster core than
 * with a warm cache on a slow one (this is what carries the load up the
 * capacity ladder, the way asym packing does), but only when its whole core is
 * idle, as a fast thread sharing its core is no better than a whole slow one
 * and asym_smt_can_pull_tasks() refuses that move too; then from its own LLC,
 * then from the rest of the node, leaving alone a task that ran on its cid a
 * moment ago, see task_hot(): its home cid takes it back within a slice, while
 * moving it costs its cache.
 *
 * A cid with work of its own samples BALANCE_SAMPLE other queues, rotating
 * through them across dispatches, and takes the head of one that is more than
 * twice as deep as its own and at least two tasks deeper. Every queue is fed
 * by the wakeups of its own cid, so this is the only way a pile-up gets spread
 * out, e.g. a hundred children forked on one cid while every other cid was
 * busy with a task of its own, the way the load balancer moves tasks off the
 * busiest runqueue. The margin is what keeps cids under an even load from
 * trading tasks back and forth (the balancer has its imbalance_pct), and a cid
 * samples at most once per slice, the way the load balancer runs on the tick
 * rather than on every pick: sampling on every dispatch under a wakeup storm
 * moved tasks around faster than they could warm a cache. Otherwise the cid
 * takes its own head: waiting for the owning cid's slice end is what EEVDF
 * does under RUN_TO_PARITY.
 *
 * Only the heads are considered, a queue whose head cannot run on @dst_cid (or
 * is still hot there) is skipped as a whole.
 *
 * Return true if a task has been dispatched, false otherwise.
 */
static bool try_steal_task(s32 dst_cid)
{
	TOUCH_ARENA();

	struct cid_ctx __arena *cctx = cid_ctx(dst_cid);
	struct task_struct *own = __COMPAT_scx_bpf_dsq_peek(cid_dsq(dst_cid));
	u64 now = bpf_ktime_get_ns();
	u32 limit, start, cid, i, own_nr = 0;
	s32 src = -1;

	if (own) {
		if (time_before(now, cctx->last_balance_at + slice_ns))
			goto own;
		cctx->last_balance_at = now;
		own_nr = scx_bpf_dsq_nr_queued(cid_dsq(dst_cid));
	}

	start = cctx->steal_cursor;
	if (start >= nr_cids)
		start = 0;

	if (!own && asym_capacity && core_is_idle(dst_cid)) {
		u32 best_tier = cctx->tier;

		bpf_for(i, 0, nr_cids) {
			const struct cid_ctx __arena *other = cid_ctx(i);
			const struct task_ctx __arena *tctx;
			struct task_struct *p;

			if (other->tier <= best_tier)
				continue;

			p = __COMPAT_scx_bpf_dsq_peek(cid_dsq(i));
			if (!p)
				continue;

			tctx = lookup_task_ctx(p);
			if (!__cmask_test(dst_cid, &tctx->allowed))
				continue;

			best_tier = other->tier;
			src = i;
		}
		if (src >= 0)
			goto pick;
	}

	/*
	 * One extra slot covers @dst_cid itself falling in the sample. An idle
	 * cid walks its own LLC before the rest of the node, so it does two
	 * passes.
	 */
	limit = own ? BALANCE_SAMPLE + 1 : nr_cids;
	bpf_for(i, 0, own ? limit : 2 * limit) {
		const struct cid_ctx __arena *other;
		const struct task_ctx __arena *tctx;
		bool local_pass = !own && i < limit;
		struct task_struct *p;

		cid = start + 1 + (i < limit ? i : i - limit);
		if (cid >= nr_cids)
			cid -= nr_cids;
		if (cid >= nr_cids || cid == dst_cid)
			continue;
		other = cid_ctx(cid);
		if (numa_enabled && !own &&
		    (cid < cctx->node_base || cid >= cctx->node_base + cctx->node_nr))
			continue;
		if (!own && (other->llc_base == cctx->llc_base) != local_pass)
			continue;
		if (own) {
			u32 nr = scx_bpf_dsq_nr_queued(cid_dsq(cid));

			if (nr < own_nr + 2 || nr <= 2 * own_nr)
				continue;
		}

		p = __COMPAT_scx_bpf_dsq_peek(cid_dsq(cid));
		if (!p)
			continue;

		tctx = lookup_task_ctx(p);
		if (!__cmask_test(dst_cid, &tctx->allowed) || task_hot(p, now))
			continue;

		src = cid;
		break;
	}
	start += limit;
	if (start >= nr_cids)
		start -= nr_cids;
	cctx->steal_cursor = start;

own:
	if (src < 0 && own)
		src = dst_cid;

pick:
	if (src < 0)
		return false;

	if (!scx_bpf_dsq_move_to_local(cid_dsq(src), 0))
		return false;

	if (src != dst_cid)
		__sync_fetch_and_add(&nr_steals, 1);

	return true;
}

void BPF_STRUCT_OPS(cidland_dispatch, s32 cid, struct task_struct *prev)
{
	/*
	 * Take a task from this cid's queue or from a deeper one, then fall
	 * back to this cid's own DSQ in case the pick raced with another cid.
	 */
	if (try_steal_task(cid) || scx_bpf_dsq_move_to_local(cid_dsq(cid), 0))
		return;

	/*
	 * Nothing else wants to run here: refill @prev's time slice and let it
	 * continue. Without this, SCX_OPS_ENQ_LAST would send @prev through
	 * ops.enqueue() only to pull it right back from its own queue.
	 */
	if (prev && keep_running(prev, cid)) {
		scx_bpf_task_set_slice(prev, slice_ns);
		return;
	}

	/*
	 * This cid found no work, so it's about to go (back) to idle: re-arm
	 * its idle bit.
	 *
	 * ops.update_idle() only fires on real idle transitions. A cid that is
	 * kicked while idle and finds nothing to run goes back to idle through
	 * pick_task_idle(), which refreshes the kernel's own idle masks but
	 * doesn't notify, so nothing would restore the bit that pick_idle_cid()
	 * claimed. Without this the bit stays cleared until the cid runs
	 * something and goes idle again: on wakeup-heavy workloads the mask
	 * drains to empty within seconds and idle selection quietly stops
	 * working.
	 */
	cid_set_idle(cid, true);
}

void BPF_STRUCT_OPS(cidland_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx __arena *tctx;
	s64 limit, lag;

	__sync_fetch_and_sub(&sum_weight, p->scx.weight);

	tctx = lookup_task_ctx(p);

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
	limit = scale_by_dl_weight(p, slice_lag);
	lag = (s64)(vtime_now - tctx->vruntime);
	if (lag > limit)
		lag = limit;
	else if (lag < -limit)
		lag = -limit;
	tctx->vlag = lag;
}

void BPF_STRUCT_OPS(cidland_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx __arena *tctx;

	__sync_fetch_and_add(&sum_weight, p->scx.weight);

	tctx = lookup_task_ctx(p);

	/*
	 * Place the task back at the lag it had when it went to sleep, the
	 * way place_entity() does:
	 *
	 *	se->vruntime = vruntime - lag;
	 *
	 * A task that had consumed its share before sleeping comes back with
	 * no credit, while one that was still owed service keeps it.
	 */
	tctx->vruntime = vtime_now - tctx->vlag;
}

void BPF_STRUCT_OPS(cidland_running, struct task_struct *p)
{
	struct task_ctx __arena *tctx;

	tctx = lookup_task_ctx(p);

	tctx->last_run_at = bpf_ktime_get_ns();
}

void BPF_STRUCT_OPS(cidland_stopping, struct task_struct *p, bool runnable)
{
	s32 cid = scx_bpf_task_cid(p);
	struct task_ctx __arena *tctx;
	u64 slice, weight;

	tctx = lookup_task_ctx(p);

	tctx->last_stop_at = bpf_ktime_get_ns();
	slice = tctx->last_stop_at - tctx->last_run_at;

	/*
	 * Charge the service just consumed to the task's vruntime, the way
	 * update_curr() does:
	 *
	 *	se->vruntime += calc_delta_fair(delta_exec, se);
	 */
	tctx->vruntime += scale_by_task_weight_inverse(p, slice);

	/*
	 * Advance the system virtual time by the service just delivered.
	 *
	 * EEVDF's reference is the weighted average of the runnable set,
	 *
	 *	V = \Sum (w_i * v_i) / \Sum w_i
	 *
	 * so serving @p for @slice moves it by
	 *
	 *	dV = w_p * dv_p / \Sum w_i = slice * NICE_0 / \Sum w_i
	 *
	 * since dv_p is the slice scaled by the inverse of @p's weight. That
	 * is an identity, not an approximation: what matters is that V rises
	 * with the service handed out no matter who receives it. Deriving it
	 * from the running task's own vruntime instead (the previous
	 * max-of-running rule) stalls the clock exactly when it is needed,
	 * because the tasks that are behind never run and the tasks that do
	 * run barely advance their own vruntime.
	 *
	 * The division truncates, and once the total weight exceeds a
	 * hundred times the length of a burst every burst contributes
	 * nothing: with a few thousand runnable tasks V would stop entirely
	 * and everything queued behind it would starve. Carry the remainder
	 * per cid so that the service is accounted in full.
	 */
	weight = sum_weight;
	if (weight && cid_valid(cid)) {
		struct cid_ctx __arena *cctx = cid_ctx(cid);
		u64 acc = slice * 100 + cctx->vtime_rem;
		u64 delta = acc / weight;

		cctx->vtime_rem = acc - delta * weight;
		if (delta)
			__sync_fetch_and_add(&vtime_now, delta);
	}
}

/*
 * The task's affinity changed: refresh its allowed cids.
 *
 * Unlike the cpu form, which reports a cpumask, the cid form hands us the
 * affinity already translated to cid space, based at cid 0 and covering the
 * whole cid space, so its words map one to one to @tctx->allowed.
 */
void BPF_STRUCT_OPS(cidland_set_cmask, struct task_struct *p,
		    struct scx_cmask __arena *cmask)
{
	TOUCH_ARENA();

	struct task_ctx __arena *tctx;

	tctx = lookup_task_ctx(p);

	/*
	 * cmask_copy() only writes the window the two masks share, so the
	 * cids outside @cmask's range have to be cleared first.
	 */
	cmask_zero(&tctx->allowed);
	cmask_copy(&tctx->allowed, cmask);
}

void BPF_STRUCT_OPS(cidland_update_idle, s32 cid, bool idle)
{
	cid_set_idle(cid, idle);
}

s32 BPF_STRUCT_OPS(cidland_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	TOUCH_ARENA();

	struct task_ctx __arena *tctx;

	tctx = scx_task_alloc(p);
	if (!tctx)
		return -ENOMEM;

	/*
	 * The mask has to be framed before anything touches it, including the
	 * ops.set_cmask() of a task that becomes restricted later on.
	 */
	cmask_init(&tctx->allowed, 0, nr_cids);

	/*
	 * Tasks that can run anywhere never consult their mask, so only build
	 * one for the tasks that are actually restricted. ops.set_cmask() fills
	 * it in if a task becomes restricted later on.
	 */
	if (p->nr_cpus_allowed < nr_cpu_ids)
		seed_task_cmask(p, tctx);

	return 0;
}

/*
 * Task contexts are RCU protected: a lookup fails once the task is gone, and a
 * context that was already looked up stays valid until the end of the RCU
 * section it was looked up in.
 */
void BPF_STRUCT_OPS(cidland_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	scx_task_free_rcu(p);
}

/*
 * A task is starting to be scheduled by this scheduler: give it the current
 * system virtual time, so that it's neither penalized nor over-prioritized.
 */
void BPF_STRUCT_OPS(cidland_enable, struct task_struct *p)
{
	struct task_ctx __arena *tctx = lookup_task_ctx(p);

	tctx->vruntime = vtime_now;
}

/*
 * Scratch space for scx_bpf_cid_topo(), only used by ops.init().
 *
 * It lives in .bss rather than on the stack because the verifier requires the
 * whole struct to be readable at the call, while the stack slots of the fields
 * that are never read back would be dropped as dead.
 */
static struct scx_cid_topo init_topo;

/*
 * Fill @cid_ctxs with the core and LLC ranges of each cid.
 *
 * Cids are assigned in topological order (node, then LLC, then core), so the
 * cids of a core or of an LLC are always contiguous. Walking the cid space
 * backwards means the highest cid of a range is visited first, which is enough
 * to derive the length of the range from its base.
 */
static s32 init_cid_ctxs(void)
{
	s32 cur_core = -1, cur_llc = -1, cur_node = -1;
	u32 core_nr = 0, llc_nr = 0, node_nr = 0;
	u32 i;

	bpf_for(i, 0, nr_cids) {
		struct scx_cid_topo *topo = &init_topo;
		s32 cid = nr_cids - 1 - i;
		struct cid_ctx __arena *cctx = cid_ctx(cid);
		s32 cpu = scx_bpf_cid_to_cpu(cid);

		scx_bpf_cid_topo(cid, topo);

		/*
		 * A cid with no CPU behind it (offline when the cid space was
		 * built) is treated as the slowest thing in the system.
		 */
		if (cpu >= 0 && (u32)cpu < nr_cpu_ids) {
			cctx->cap = cpu_cap_in[cpu];
			cctx->tier = cpu_tier_in[cpu];
		} else {
			cctx->cap = 1;
			cctx->tier = nr_tiers - 1;
		}

		/*
		 * Cids in the no-topo tail (CPUs that were offline when the cid
		 * space was built) report -1 everywhere: treat them as a core,
		 * an LLC and a node of their own.
		 */
		if (topo->core_cid < 0 || topo->llc_cid < 0 || topo->node_cid < 0) {
			cctx->core_base = cid;
			cctx->core_nr = 1;
			cctx->llc_base = cid;
			cctx->llc_nr = 1;
			cctx->node_base = cid;
			cctx->node_nr = 1;
			continue;
		}

		if (topo->core_cid != cur_core) {
			cur_core = topo->core_cid;
			core_nr = cid + 1 - topo->core_cid;
		}
		if (topo->llc_cid != cur_llc) {
			cur_llc = topo->llc_cid;
			llc_nr = cid + 1 - topo->llc_cid;
		}
		if (topo->node_cid != cur_node) {
			cur_node = topo->node_cid;
			node_nr = cid + 1 - topo->node_cid;
		}

		cctx->core_base = topo->core_cid;
		cctx->core_nr = core_nr;
		cctx->llc_base = topo->llc_cid;
		cctx->llc_nr = llc_nr;
		cctx->node_base = topo->node_cid;
		cctx->node_nr = node_nr;
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cidland_init)
{
	s32 err;
	u32 i;

	if (!nr_cids_max) {
		scx_bpf_error("cidland_arena_init() didn't run");
		return -EINVAL;
	}

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	nr_cids = scx_bpf_nr_cids();

	/*
	 * Everything indexed by cid was sized from the CPU count userspace
	 * saw. The cid space is num_possible_cpus() wide, so this should
	 * always hold; bail out rather than run off the end if it doesn't.
	 */
	if (nr_cids > nr_cids_max || nr_cpu_ids > nr_cids_max) {
		scx_bpf_error("cid space grew past what was allocated: %u cids, %u cpu ids, sized for %u",
			      nr_cids, nr_cpu_ids, nr_cids_max);
		return -E2BIG;
	}

	/*
	 * Frame the masks over the cid space before anything sets a bit.
	 */
	cmask_init(all_cids, 0, nr_cids);
	cmask_init(idle_cids, 0, nr_cids);

	/* Handed to the pick loop for the tasks that can run anywhere. */
	cmask_fill(all_cids);

	err = init_cid_ctxs();
	if (err)
		return err;

	/*
	 * Create the per-cid DSQs.
	 */
	bpf_for(i, 0, nr_cids) {
		err = scx_bpf_create_dsq(cid_dsq(i), -1);
		if (err) {
			scx_bpf_error("failed to create DSQ for cid %u: %d", i, err);
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
 * Bring up the arena allocator that backs the per-task contexts.
 *
 * Run from userspace between load and attach, which is all the ordering the
 * allocator needs: it has to be ready before the first ops.init_task().
 */
SEC("syscall")
int cidland_arena_init(struct cidland_arena_args *args)
{
	u64 nr_cpus = args->nr_cpus, bytes;
	s32 err;

	if (!nr_cpus || !args->nr_tiers)
		return -EINVAL;

	nr_cids_max = nr_cpus;
	nr_tiers = args->nr_tiers;
	asym_capacity = nr_tiers > 1;
	nr_cmask_words = CMASK_NR_WORDS(nr_cpus);

	/*
	 * The static allocator hands out of a pool it takes up front, so ask
	 * for what the arrays below need plus a margin for the task context
	 * allocator's own bookkeeping.
	 */
	bytes = nr_cpus * sizeof(struct cid_ctx) +
		2 * cmask_size(nr_cmask_words) +
		nr_cpus * (sizeof(u64) + sizeof(u32));
	err = scx_static_init(div_round_up(bytes, PAGE_SIZE) + STATIC_ALLOC_PAGES);
	if (err)
		return err;

	cid_ctxs = scx_static_alloc(nr_cpus * sizeof(struct cid_ctx), sizeof(u64));
	all_cids = scx_static_alloc(cmask_size(nr_cmask_words), sizeof(u64));
	idle_cids = scx_static_alloc(cmask_size(nr_cmask_words), sizeof(u64));
	cpu_cap_in = scx_static_alloc(nr_cpus * sizeof(u64), sizeof(u64));
	cpu_tier_in = scx_static_alloc(nr_cpus * sizeof(u32), sizeof(u32));

	if (!cid_ctxs || !all_cids || !idle_cids || !cpu_cap_in || !cpu_tier_in)
		return -ENOMEM;

	/*
	 * The masks are framed and @all_cids filled in ops.init(), which is
	 * the first point where the width of the cid space is known.
	 */
	return scx_task_init(task_ctx_size(nr_cmask_words), SCX_CACHELINE_SIZE);
}

/*
 * Report the capacity and the tier of one CPU, in cpu space.
 *
 * Userspace calls this once per CPU after cidland_arena_init() and before
 * attach; ops.init() translates the result to cid space.
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
		   .dispatch		= (void *)cidland_dispatch,
		   .runnable		= (void *)cidland_runnable,
		   .quiescent		= (void *)cidland_quiescent,
		   .running		= (void *)cidland_running,
		   .stopping		= (void *)cidland_stopping,
		   .set_cmask		= (void *)cidland_set_cmask,
		   .update_idle		= (void *)cidland_update_idle,
		   .init_task		= (void *)cidland_init_task,
		   .exit_task		= (void *)cidland_exit_task,
		   .enable		= (void *)cidland_enable,
		   .init		= (void *)cidland_init,
		   .exit		= (void *)cidland_exit,
		   .timeout_ms		= 5000,
		   .name		= "cidland");
