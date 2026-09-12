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
 * an idle cid are queued to a single shared DSQ, ordered by the virtual
 * deadline computed by task_dl().
 */
#include <scx/common.bpf.h>
#include <libarena/common.h>
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
 * Define struct user_exit_info which is shared between BPF and userspace to
 * communicate the exit status.
 */
UEI_DEFINE(uei);

/*
 * Shared queue: all the tasks that can't be dispatched directly to an idle cid
 * are queued here, ordered by their virtual deadline, and consumed by the first
 * cid that runs out of work.
 */
#define SHARED_DSQ	0

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
 * Primary scheduling domain: the cpus that should be preferred when looking
 * for an idle cid (see --primary-domain).
 *
 * Expressed in cpu space, as userspace has no way to know the cid layout: the
 * kernel builds it at scheduler enable time. ops.init() translates it to the
 * @primary_cids mask below. @primary_all short circuits the whole thing when
 * the domain covers everything.
 */
const volatile bool primary_all = true;

/*
 * Primary domain in cpu space, filled by cidland_set_primary_word() before
 * attach and consumed once by ops.init().
 */
static u64 __arena *primary_cpus;

/*
 * Maximum lag, in virtual time, that a task can carry across a sleep.
 */
const volatile u64 slice_lag;

/*
 * Scheduling statistics.
 */
volatile u64 nr_direct_dispatches, nr_shared_enqueues, nr_idle_kicks;
volatile u64 nr_local_llc, nr_remote_llc;

/*
 * Size of the cid space, initialized in ops.init(). All the valid cids are in
 * [0, nr_cids).
 */
static u32 nr_cids;

/*
 * Width of the cid space that the arena arrays below were sized for, and the
 * number of u64 words needed to hold one bit per cid. Both are established by
 * cidland_arena_init() from the CPU count userspace hands it.
 */
static u32 nr_cids_max;
static u32 nr_cid_words;

/*
 * Number of words of storage a cmask framed over the cid space needs.
 *
 * CMASK_NR_WORDS() asks for a word beyond the bits themselves, so that a mask
 * based at a cid that isn't word aligned still has room for the word its range
 * spills into. The cmask helpers size their loops off it, so the storage has to
 * match: with @nr_cid_words alone, cmask_init() and cmask_zero() write one word
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
	u64 vruntime;			/* total runtime, scaled by the weight */
	s64 vlag;			/* lag carried across a sleep */
	struct scx_cmask allowed;	/* cids the task is allowed to run on */
};

/* Size of a cmask framed over @nr_words words of bits. */
static u64 cmask_size(u32 nr_words)
{
	return sizeof(struct scx_cmask) + (u64)nr_words * sizeof(u64);
}

/* Size of a task context holding @nr_cid_words words of allowed cids. */
static u64 task_ctx_size(u32 nr_words)
{
	return sizeof(struct task_ctx) + (u64)nr_words * sizeof(u64);
}

/*
 * Task contexts are allocated from the arena so that @allowed is an arena
 * pointer like @all_cids and @primary_cids, and the pick loop can take either
 * without caring which one it got.
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
	u32 core_base;		/* first cid of the core this cid belongs to */
	u32 core_nr;		/* number of cids (SMT siblings) in the core */
	u32 llc_base;		/* first cid of the LLC this cid belongs to */
	u32 llc_nr;		/* number of cids in the LLC */
	u64 vtime_rem;		/* service not yet folded into @vtime_now */
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
 * Primary domain in cid space, built in ops.init() from @primary_cpus.
 */
static struct scx_cmask __arena *primary_cids;

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
 * Scan [@base, @base + @nr) for an idle cid usable by @p and claim it.
 *
 * If @whole_core is true only cids whose entire core is idle are considered,
 * to avoid stacking tasks on SMT siblings while full cores are available.
 *
 * Return the claimed cid or a negative value if none was found.
 */
static s32 claim_idle_cid_range(const struct scx_cmask __arena *allowed,
				const struct scx_cmask __arena *domain,
				u32 base, u32 nr, bool whole_core)
{
	TOUCH_ARENA();

	u32 cid;

	bpf_for(cid, base, base + nr) {
		if (cid >= nr_cids)
			break;
		if (!cid_test_idle(cid))
			continue;
		if (whole_core) {
			const struct cid_ctx __arena *cctx = cid_ctx(cid);

			if (!cid_range_is_idle(cctx->core_base, cctx->core_nr))
				continue;
		}
		if (!__cmask_test(cid, allowed) || !__cmask_test(cid, domain))
			continue;
		if (cid_claim_idle(cid))
			return cid;
	}

	return -EBUSY;
}

/*
 * Run the idle search within @domain, preferring topological locality with
 * @prev_cid.
 *
 * Return the claimed cid or a negative value if @domain has nothing idle that
 * @allowed permits.
 */
static s32 pick_idle_cid_domain(const struct scx_cmask __arena *allowed,
				const struct scx_cmask __arena *domain,
				const struct cid_ctx __arena *cctx, s32 prev_cid,
				bool core_only)
{
	s32 cid;

	/*
	 * Stay on @prev_cid if its whole core is idle: caches are warm and no
	 * SMT sibling is competing for the core.
	 */
	if (__cmask_test(prev_cid, allowed) && __cmask_test(prev_cid, domain) &&
	    cid_range_is_idle(cctx->core_base, cctx->core_nr) &&
	    cid_claim_idle(prev_cid))
		return prev_cid;

	/* Then any fully idle core in the same LLC. */
	cid = claim_idle_cid_range(allowed, domain, cctx->llc_base, cctx->llc_nr, true);
	if (cid >= 0)
		return cid;

	/*
	 * A caller that only wants a whole core stops here, after one more
	 * look for one anywhere in @domain: taking an SMT sibling would put
	 * the task on a core that is already running something, which costs
	 * more than the wait it saves.
	 */
	if (core_only)
		return claim_idle_cid_range(allowed, domain, 0, nr_cids, true);

	/* Then @prev_cid, even if its SMT sibling is busy. */
	if (__cmask_test(prev_cid, allowed) && __cmask_test(prev_cid, domain) &&
	    cid_claim_idle(prev_cid))
		return prev_cid;

	/* Then any idle cid in the same LLC. */
	cid = claim_idle_cid_range(allowed, domain, cctx->llc_base, cctx->llc_nr, false);
	if (cid >= 0)
		return cid;

	/* Lastly, anything idle in @domain. */
	return claim_idle_cid_range(allowed, domain, 0, nr_cids, false);
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
	 * Search the primary domain first and fall back to the rest of the
	 * system only when it has nothing idle to offer.
	 */
	if (!primary_all)
		cid = pick_idle_cid_domain(allowed, primary_cids, cctx, prev_cid,
					   core_only);
	else
		cid = -EBUSY;

	if (cid < 0)
		cid = pick_idle_cid_domain(allowed, all_cids, cctx, prev_cid,
					   core_only);
	if (cid < 0)
		return cid;

	if (cid >= cctx->llc_base && cid < cctx->llc_base + cctx->llc_nr)
		__sync_fetch_and_add(&nr_local_llc, 1);
	else
		__sync_fetch_and_add(&nr_remote_llc, 1);

	return cid;
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
	return tctx->vruntime + scale_by_task_weight_inverse(p, slice_ns);
}

s32 BPF_STRUCT_OPS(cidland_select_cid, struct task_struct *p, s32 prev_cid,
		   u64 wake_flags)
{
	s32 cid;

	cid = pick_idle_cid(p, prev_cid, false, false);
	if (cid < 0)
		return prev_cid;

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

/*
 * Return true if queueing @p to the shared DSQ needs an explicit cid kick.
 *
 * ops.select_cid() provides the wakeup side effect for the tasks that can run
 * anywhere. Affinity constrained and migration disabled tasks can otherwise be
 * left waiting in the shared queue with no eligible cid looking at it, so
 * always kick the cid they're sitting on.
 */
static bool task_needs_shared_dsq_kick(struct task_struct *p, u64 enq_flags)
{
	return p->nr_cpus_allowed != nr_cpu_ids || is_migration_disabled(p) ||
	       task_should_migrate(p, enq_flags);
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
	 */
	if (task_should_migrate(p, enq_flags) || !cid_test_idle(prev_cid)) {
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

	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, slice_ns, task_dl(p, tctx), enq_flags);
	__sync_fetch_and_add(&nr_shared_enqueues, 1);

	if (task_needs_shared_dsq_kick(p, enq_flags)) {
		scx_bpf_kick_cid(prev_cid, SCX_KICK_IDLE);
		__sync_fetch_and_add(&nr_idle_kicks, 1);
	}
}

/*
 * Return true if @p can keep running on the current cid, instead of being put
 * back on the shared queue.
 */
static bool keep_running(const struct task_struct *p, s32 cid)
{
	TOUCH_ARENA();

	/* The task doesn't want to run anymore. */
	if (!(p->scx.flags & SCX_TASK_QUEUED))
		return false;

	/*
	 * Don't hold a task on a cid outside the primary domain when it could
	 * move: letting it go through the shared queue gives it a chance to
	 * land in the primary domain instead.
	 */
	if (!primary_all && !__cmask_test(cid, primary_cids) && task_can_migrate(p))
		return false;

	return true;
}

void BPF_STRUCT_OPS(cidland_dispatch, s32 cid, struct task_struct *prev)
{
	/*
	 * Give this cid a task from the shared queue, if there's any.
	 */
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ, 0))
		return;

	/*
	 * Nothing else wants to run here: refill @prev's time slice and let it
	 * continue. Without this, SCX_OPS_ENQ_LAST would send @prev through
	 * ops.enqueue() only to pull it right back from the shared queue.
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
	limit = scale_by_task_weight_inverse(p, slice_lag);
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

	slice = bpf_ktime_get_ns() - tctx->last_run_at;

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
	s32 cur_core = -1, cur_llc = -1;
	u32 core_nr = 0, llc_nr = 0;
	u32 i;

	bpf_for(i, 0, nr_cids) {
		struct scx_cid_topo *topo = &init_topo;
		s32 cid = nr_cids - 1 - i;
		struct cid_ctx __arena *cctx = cid_ctx(cid);

		scx_bpf_cid_topo(cid, topo);

		/*
		 * Cids in the no-topo tail (CPUs that were offline when the cid
		 * space was built) report -1 everywhere: treat them as a core
		 * and an LLC of their own.
		 */
		if (topo->core_cid < 0 || topo->llc_cid < 0) {
			cctx->core_base = cid;
			cctx->core_nr = 1;
			cctx->llc_base = cid;
			cctx->llc_nr = 1;
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

		cctx->core_base = topo->core_cid;
		cctx->core_nr = core_nr;
		cctx->llc_base = topo->llc_cid;
		cctx->llc_nr = llc_nr;
	}

	return 0;
}

/*
 * Translate the primary domain from the cpu space userspace gave us to cid
 * space, which is only known once the kernel has built the cid layout.
 */
static void init_primary_cids(void)
{
	TOUCH_ARENA();

	u32 cpu;

	if (primary_all)
		return;

	bpf_for(cpu, 0, nr_cpu_ids) {
		u32 idx = cpu / 64;
		s32 cid;

		if (idx >= nr_cid_words)
			break;
		if (!(primary_cpus[idx] & (1ULL << (cpu & 63))))
			continue;

		cid = scx_bpf_cpu_to_cid(cpu);
		if (!cid_valid(cid))
			continue;

		__cmask_set(cid, primary_cids);
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cidland_init)
{
	s32 err;

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
	cmask_init(primary_cids, 0, nr_cids);
	cmask_init(idle_cids, 0, nr_cids);

	/* Handed to the pick loop for the tasks that can run anywhere. */
	cmask_fill(all_cids);

	err = init_cid_ctxs();
	if (err)
		return err;

	init_primary_cids();

	return scx_bpf_create_dsq(SHARED_DSQ, -1);
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
	u64 nr_cpus = args->nr_cpus;

	if (!nr_cpus)
		return -EINVAL;
	arena_subprog_init();

	nr_cids_max = nr_cpus;
	nr_cid_words = (nr_cpus + 63) / 64;
	nr_cmask_words = CMASK_NR_WORDS(nr_cpus);

	cid_ctxs = arena_calloc(nr_cpus, sizeof(struct cid_ctx));
	all_cids = arena_calloc(1, cmask_size(nr_cmask_words));
	primary_cids = arena_calloc(1, cmask_size(nr_cmask_words));
	idle_cids = arena_calloc(1, cmask_size(nr_cmask_words));
	primary_cpus = arena_calloc(nr_cid_words, sizeof(u64));

	if (!cid_ctxs || !all_cids || !primary_cids || !idle_cids || !primary_cpus)
		return -ENOMEM;

	/*
	 * The masks are framed and @all_cids filled in ops.init(), which is
	 * the first point where the width of the cid space is known.
	 */
	return scx_task_init(task_ctx_size(nr_cmask_words), SCX_CACHELINE_SIZE);
}

/*
 * Feed one word of the primary domain, in cpu space.
 *
 * Userspace calls this once per word after cidland_arena_init() and before
 * attach; ops.init() translates the result to cid space.
 */
SEC("syscall")
int cidland_set_primary_word(struct cidland_primary_args *args)
{
	u64 idx = args->idx;

	TOUCH_ARENA();

	if (!primary_cpus || idx >= nr_cid_words)
		return -EINVAL;

	primary_cpus[idx] = args->word;

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
