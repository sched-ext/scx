/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * A cid-form scheduler (struct sched_ext_ops_cid): a port of the kernel's
 * EEVDF policy to sched_ext, addressing CPUs by their cid - a dense id
 * space ordered by topology, so that the CPUs of a core, of an LLC and of
 * a NUMA node occupy contiguous ranges of it, and a topology domain is a
 * (base, len) slice. Everything sized by the machine lives in a BPF arena
 * allocated before attach, so nothing here caps the number of CPUs, cores,
 * LLCs, nodes or tiers.
 *
 *
 * How the source is laid out
 * --------------------------
 *
 * The scheduler is split by component, and this file is the one the BPF
 * skeleton is built from: it includes the components, the way
 * kernel/sched/build_policy.c includes fair.c and the rest, so that all of
 * it is one translation unit. Every function stays static and the compiler
 * inlines across the whole scheduler exactly as it would have in a single
 * file; the split costs nothing at all. Each component's header holds what
 * its callers need on the hot paths, its .c the rest, and the top of each
 * .c says what that component implements and why:
 *
 *	eevdf.bpf.h	the types, the globals and the cid space itself
 *	cpu.bpf.c	the machine: the arena, the tables, the topology
 *	cgroup.bpf.[ch]	group scheduling, cpu.weight, cpu.idle and cpu.max
 *	load.bpf.[ch]	utilization, load, and the capacity a cid delivers
 *	queue.bpf.[ch]	the per-cid runnable queue, an EDQ per cid
 *	task.bpf.[ch]	EEVDF: weights, vruntimes, deadlines, placement
 *	idle.bpf.[ch]	where a task goes when it wakes, and the idle bitmap
 *	preempt.bpf.[ch] the pick, the protection it gives, and the hrtick
 *	balance.bpf.[ch] periodic and active balance, and ops.tick()
 *	newidle.bpf.[ch] the pull a cid runs when it has nothing left to run
 *
 * They are included in the order they use each other, so no component
 * needs a forward declaration of another.
 *
 *
 * What is left here
 * -----------------
 *
 * The options, the globals, and the two callbacks that belong to no single
 * component because they reach into all of them:
 *
 *   ops.enqueue(p)      the task is runnable and has a cid. In order:
 *                         - its cgroup out of cpu.max?  -> park it
 *                         - a balance handoff waiting for it?
 *                           -> place it on the destination that asked
 *                         - no cid was selected for it (it could not
 *                           migrate, or this is a re-enqueue), or a higher
 *                           class just took its cid?
 *                           -> look for an idle cid now
 *                         - otherwise place it against this cid's
 *                           reference, give it a deadline, and either hand
 *                           the CPU to it (wakeup preemption, through the
 *                           local DSQ so the kernel can expire the running
 *                           task's slice under the rq lock) or queue it in
 *                           the EDQ in deadline order
 *
 *   ops.dispatch(cid)   the CPU needs something to run. In order:
 *                         - let out anything whose cgroup got its
 *                           bandwidth back
 *                         - consume an active-balance request, or drain a
 *                           periodic-balance selection, if either is due
 *                         - if the CPU has nothing of its own: pull from a
 *                           neighbour, under the new-idle budget
 *                         - take the first eligible task of its own EDQ
 *                         - or keep the task that was already running,
 *                           which is what pick_next_entity() does when
 *                           nothing queued has an earlier deadline, and
 *                           give it a fresh slice and a fresh hrtick
 *
 * plus ops.init()/exit() and the two ops tables - one for kernels that
 * name the cgroup callbacks cpuctl_*, one for those that still call them
 * cgroup_*.
 */
#include "eevdf.bpf.h"
#include "balance.bpf.h"
#include "cgroup.bpf.h"
#include "idle.bpf.h"
#include "load.bpf.h"
#include "preempt.bpf.h"
#include "queue.bpf.h"
#include "task.bpf.h"

char _license[] SEC("license") = "GPL";

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
 * wake_affine_weight_cid(). The cid load uses the larger of its tick sample
 * and current runnable weight. Task load reuses its execution-utilization
 * estimate, so the comparison adds no runnable-state accounting. Enabled by
 * default and disabled with
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
 * the weighted-average virtual-time reference. This restores scx_eevdf's
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

/* Per-task allocation counters exposed through the existing stats ABI. */
struct {
	u64 active_allocs;
	u64 alloc_nomem;
} alloc_stats;

/*
 * Cids whose current task counts as SCHED_IDLE work, kept by ops.running()
 * and ops.stopping(). A wakeup asks this before it looks at any cid for
 * cid_sched_idle_target(): the answer is almost always none, and it comes
 * from one word that is only written when such a task starts or stops,
 * where the per-cid test costs reads of two bitmap words and a pack line
 * that every CPU keeps changing.
 */
u32 nr_sched_idle_curr;

static bool arena_is_ours(void *map)
{
	return arena_map_id &&
	       BPF_CORE_READ((struct bpf_map *)map, id) == arena_map_id;
}

SEC("?fexit/bpf_arena_alloc_pages")
int BPF_PROG(eevdf_arena_alloc_pages, void *map, void *addr, u32 page_cnt,
	     int node_id, u64 flags, void *ret)
{
	if (ret && arena_is_ours(map))
		__sync_fetch_and_add(&arena_pages_allocated, page_cnt);
	return 0;
}

SEC("?fentry/bpf_arena_free_pages")
int BPF_PROG(eevdf_arena_free_pages, void *map, void *ptr, u32 page_cnt)
{
	if (arena_is_ours(map))
		__sync_fetch_and_add(&arena_pages_freed, page_cnt);
	return 0;
}

/*
 * The components, in the order they use each other, so that every call is
 * to something already defined and no component needs a forward
 * declaration of another: the machine, then what a cgroup and a cid are
 * worth, then the queue, then the two pulls, then placement, the pick, the
 * balancers, and last the task callbacks, which reach into all of them.
 */
#include "cpu.bpf.c"
#include "cgroup.bpf.c"
#include "load.bpf.c"
#include "queue.bpf.c"
#include "newidle.bpf.c"
#include "idle.bpf.c"
#include "preempt.bpf.c"
#include "balance.bpf.c"
#include "task.bpf.c"

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

void BPF_STRUCT_OPS(eevdf_enqueue, struct task_struct *p, u64 enq_flags)
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
	if (enq_flags & SCX_ENQ_WAKEUP)
		tctx->runnable_at = now;
	displaced = !(enq_flags & SCX_ENQ_WAKEUP) && scx_bpf_task_running(p);
	/*
	 * A direct dispatch that left its placement to ops.running() and was
	 * bounced back here is placed like the wakeup it is.
	 */
	if (tctx->place_pending) {
		tctx->place_pending = false;
		enq_flags |= SCX_ENQ_WAKEUP;
	}
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

void BPF_STRUCT_OPS(eevdf_dispatch, s32 cid, struct task_struct *prev)
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

s32 BPF_STRUCT_OPS_SLEEPABLE(eevdf_init)
{
	struct hrtick *ht;
	u64 now;
	u32 cid, level;
	int err;

	TOUCH_ARENA();

	if (!nr_cids_max) {
		scx_bpf_error("eevdf_arena_init() didn't run");
		return -EINVAL;
	}

	if (cgroup_enabled) {
		grp_hdrs = arena_calloc(GRP_MAX_CGROUPS, sizeof(u64));
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
	err = scx_cid_idle_init_masks(&eevdf_idle, nr_cids, smt_enabled);
	if (err)
		return err;
	cmask_init(queued_cids, 0, nr_cids);
	bpf_arena_for(cid, 0, nr_place_tiers)
		cmask_init(place_tier_mask(cid), 0, nr_cids);
	bpf_arena_for(cid, 0, nr_capacity_tiers)
		cmask_init(capacity_tier_mask(cid), 0, nr_cids);

	nr_words = scx_cid_idle_nr_words(&eevdf_idle);

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
		if (cid == (s32)cid_topo(cid)->ranges.llc_base)
			cctx->sis_idle_scan = cid_topo(cid)->ranges.llc_nr;
	}

	/*
	 * fair.c compares an asymmetric scheduling group by its preferred CPU.
	 * The LLC is the child group of the package-level packing domain on the
	 * topologies scx_eevdf models, so cache its best tier for parent-domain
	 * source and destination comparisons.
	 */
	bpf_arena_for(cid, 0, nr_cids) {
		struct cid_topo __arena *topo = cid_topo(cid);
		u32 best = nr_place_tiers - 1;
		u32 i;

		bpf_arena_for(i, 0, topo->ranges.llc_nr)
			best = MIN(best,
				   cid_topo(topo->ranges.llc_base + i)->place_tier);
		topo->llc_place_tier = best;
	}

	/*
	 * Build the packing- and capacity-tier bitmaps and start with every cid
	 * idle, the way the kernel resets its own
	 * idle masks. A CPU that sits idle from the start never transitions;
	 * left with its bit clear it would never be picked. A busy CPU's
	 * optimistic bit is cleared by the first claim or idle transition.
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

void BPF_STRUCT_OPS(eevdf_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Show whether a stalled task is still in its EDQ and whether it is
 * eligible at the queue's reference. The kernel dump shows BPF custody,
 * but cannot distinguish a queued task from one whose EDQ node was lost.
 */
void BPF_STRUCT_OPS(eevdf_dump_task, struct scx_dump_ctx *dctx,
		    struct task_struct *p)
{
	task_ctx_t *tctx;
	cid_edq_task_t *at;
	pack_t *pk;
	u64 now;
	s32 cid;

	/* Keep the dump small: the watchdog is interested in old waiters. */
	if (dctx->at_jiffies < p->scx.runnable_at ||
	    (dctx->at_jiffies - p->scx.runnable_at) * tick_ns <
		    NSEC_PER_SEC)
		return;
	TOUCH_ARENA();
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	at = cid_edq_task(tctx);
	cid = READ_ONCE(at->cid);
	if (!cid_valid(cid)) {
		scx_bpf_dump("eevdf pid=%d cid=%d state=%u hold=%d\n",
			     p->pid, cid, READ_ONCE(at->state),
			     READ_ONCE(at->common.holdcnt));
		return;
	}
	pk = cid_pack(cid);
	now = cid_clock_task_at(cid, dctx->at_ns);
	scx_bpf_dump("eevdf pid=%d cid=%d state=%u linked=%d hold=%d nr=%llu\n",
		     p->pid, cid, READ_ONCE(at->state),
		     READ_ONCE(at->common.edq) == &pk->edq,
		     READ_ONCE(at->common.holdcnt), READ_ONCE(pk->edq.nr));
	scx_bpf_dump("eevdf v=%llu d=%llu key=%llu elig=%llu V=%llu w=%llu\n",
		     READ_ONCE(tctx->se.vruntime),
		     READ_ONCE(tctx->se.deadline),
		     READ_ONCE(at->common.node.deadline),
		     READ_ONCE(at->common.node.eligibility),
		     pack_vref_place(pk, now), READ_ONCE(tctx->se.vw));
	scx_bpf_dump("eevdf head=%llu W=%llu request=%llu vlag=%lld\n",
		     READ_ONCE(pk->edq.first_deadline), READ_ONCE(pk->vsum_w),
		     READ_ONCE(tctx->se.request), READ_ONCE(tctx->se.vlag));
}

/*
 * The ops, with the prefix the running kernel names the cgroup callbacks
 * with: cpuctl_*, or cgroup_* on a kernel from before the cid form renamed
 * them.
 */
#define EEVDF_OPS(__cg)						\
	.select_cid		= (void *)eevdf_select_cid,		\
	.enqueue		= (void *)eevdf_enqueue,		\
	.dequeue		= (void *)eevdf_dequeue,		\
	.tick			= (void *)eevdf_tick,			\
	.core_sched_before	= (void *)eevdf_core_sched_before,	\
	.yield			= (void *)eevdf_yield,		\
	.dispatch		= (void *)eevdf_dispatch,		\
	.quiescent		= (void *)eevdf_quiescent,		\
	.running		= (void *)eevdf_running,		\
	.stopping		= (void *)eevdf_stopping,		\
	.update_idle		= (void *)eevdf_update_idle,		\
	.enable			= (void *)eevdf_enable,		\
	.set_weight		= (void *)eevdf_set_weight,		\
	.set_cmask		= (void *)eevdf_set_cmask,		\
	.init_task		= (void *)eevdf_init_task,		\
	.exit_task		= (void *)eevdf_exit_task,		\
	.__cg##_init		= (void *)eevdf_cpuctl_init,		\
	.__cg##_exit		= (void *)eevdf_cpuctl_exit,		\
	.__cg##_set_weight	= (void *)eevdf_cpuctl_set_weight,	\
	.__cg##_set_bandwidth	= (void *)eevdf_cpuctl_set_bandwidth,	\
	.__cg##_set_idle	= (void *)eevdf_cpuctl_set_idle,	\
	.__cg##_move		= (void *)eevdf_cpuctl_move,		\
	.init			= (void *)eevdf_init,			\
	.exit			= (void *)eevdf_exit,			\
	.dump_task		= (void *)eevdf_dump_task,		\
	.timeout_ms		= 5000,					\
	.name			= "eevdf"

SCX_OPS_CID_DEFINE(eevdf_ops, EEVDF_OPS(cpuctl));

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
struct sched_ext_ops_cid___cgroup eevdf_ops_cgroup = {
	EEVDF_OPS(cgroup),
};
