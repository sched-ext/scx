/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Where a task goes when it wakes: select_task_rq_fair(), in the order
 * fair.c asks it, and the idle bitmap the search reads.
 *
 *
 * ops.select_cid()
 * ----------------
 *
 *   ops.select_cid(p, prev_cid, wake_flags)
 *     |
 *     +- its cgroup is out of cpu.max?
 *     |     -> leave it where it is; ops.enqueue() will park it, and
 *     |        waking an idle cid for a task that may not run is wasted
 *     |
 *     +- it blocked over-served and still owes that pack?
 *     |     -> back to that cid, no placement and no idle search, the way
 *     |        ttwu_runnable() requeues a delayed task before
 *     |        select_task_rq() is ever reached
 *     |
 *     +- a fork? -> find_idlest_fork_cid()
 *     |     descend the live SD_BALANCE_FORK domain, node -> LLC -> core,
 *     |     taking the idlest child group at each step by fair.c's rules
 *     |     (idle CPUs first, then spare capacity, then load per capacity,
 *     |     with the local group kept unless beaten by imbalance_pct),
 *     |     then the shallowest or least loaded cid inside it. A fork is
 *     |     placed by load: fair.c never calls select_idle_sibling() for
 *     |     one, and running the idle scan first packed every child next
 *     |     to its parent.
 *     |
 *     +- a wakeup:
 *          wake_affine_cid()               which cid to search around
 *            wake_wide()?       -> prev_cid: each of the two wakes many
 *                                  different tasks rather than mostly each
 *                                  other, so there is no pair here whose
 *                                  affinity is worth keeping
 *            waker idle?        -> prev_cid if it is idle too, else here
 *            sync and the waker is about to sleep with nothing queued?
 *                               -> here
 *            WA_WEIGHT          -> the effective-load comparison: which of
 *                                  the two cids is left better balanced by
 *                                  taking the wakee, on averaged and live loads
 *                 |
 *                 v
 *          select_idle_sibling_cid()       the search itself
 *            the target, the previous cid, the recently used cid - each
 *            taken only if idle and, on an asymmetric machine, big enough
 *            a fully idle core in the LLC, if the LLC hint says there is
 *            one; an idle SMT sibling of prev; then any idle cid, over the
 *            word-at-a-time scans in idle.bpf.h, bounded by SIS_UTIL's
 *            nr_idle_scan and walked from the target so successive wakeups
 *            cover the whole domain
 *                 |
 *                 v
 *            claimed one? -> direct dispatch to its local DSQ with
 *                            SCX_ENQ_IMMED: the "run now" path. The kernel
 *                            bounces it back through ops.enqueue() if the
 *                            cid turns out not to be free after all, so
 *                            the local DSQ never becomes a queue that
 *                            outranks the deadline-ordered EDQ.
 *
 *
 * The bitmap
 * ----------
 *
 * Implementing ops.update_idle() turns off the kernel's own idle tracking
 * and its idle CPU selection, whose walk of the topology masks was the
 * single most expensive step of a wakeup and knew nothing of the capacity
 * ordering anyway. What replaces it is one bit per cid, plus one bit per
 * LLC that is known to hold a fully idle core, and the rule that a cid is
 * *claimed* out of the bitmap before it is used:
 *
 *   wakeup A --\
 *               >-- cmask_test_and_clear(cid) -- only one of them wins,
 *   wakeup B --/                                 the loser scans again
 *
 * Without the claim, two wakeups pick the same idle cid, one of them waits
 * behind the other, and whole idle cores sit unused - which is how a burst
 * of forks ends up with both threads of a core busy and the E-cores idle.
 * A cid that was claimed and kicked but found nothing to run goes back to
 * idle without a transition, so ops.dispatch() re-arms the bit on its way
 * out, and ops.running() clears it again for the opposite race.
 */
#include "eevdf.bpf.h"
#include "cgroup.bpf.h"
#include "idle.bpf.h"
#include "load.bpf.h"
#include "queue.bpf.h"
#include "task.bpf.h"

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

/*
 * The wake_wide() half; cid LLC width stands in for sd_llc_size.
 *
 * record_wakee_cid() bumps wakee_flips whenever the task a waker wakes is
 * not the one it woke last, so a high count means that waker spreads its
 * wakeups over many different tasks instead of ping-ponging with one. If
 * the busier of the two counts is at least an LLC's width times the
 * quieter one, and the quieter one is already wider than an LLC, the two
 * are not a producer/consumer pair: waking them onto the same cid buys no
 * locality and only crowds that cid.
 */
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
 * The cid load is the larger of its tick-sampled average and its current
 * runnable weight. A burst of wakeups can build a deep queue between ticks;
 * using only the old sample would keep treating that cid as lightly loaded.
 * task_load() approximates task_h_load() from the task's maintained execution
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

	this_eff = MAX(cid_wake_load(this_cid),
		       READ_ONCE(cid_pack(this_cid)->vsum_w));
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
	prev_eff = (s64)MAX(cid_wake_load(prev_cid),
			    READ_ONCE(cid_pack(prev_cid)->vsum_w)) - (s64)load;
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
				/* Recent forks leave no instantaneous load after they block. */
				if (!env->restricted && env->level == FORK_CHILD_CORE &&
				    env->group_recent != env->best_recent) {
					if (env->group_recent < env->best_recent)
						goto commit;
					return;
				}
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
	u64 best_recent = 0;
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

			load = ravg_read_arena(&cid_ctx(cid)->run_avg, now,
					       UTIL_HALF_LIFE_NS);

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
		/* A short-lived child leaves vsum_w before the next fork. */
		if (best < 0 || load * best_cap < best_load * cap ||
		    (!restricted && load * best_cap == best_load * cap &&
		     READ_ONCE(cid_ctx(cid)->fork_cid_place_at) < best_recent)) {
			best = cid;
			best_load = load;
			best_cap = cap;
			best_recent = READ_ONCE(cid_ctx(cid)->fork_cid_place_at);
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
	if (cid >= 0) {
		WRITE_ONCE(cid_ctx(cid_topo(cid)->core_base)->fork_place_at, now);
		WRITE_ONCE(cid_ctx(cid)->fork_cid_place_at, now);
	}
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

s32 BPF_STRUCT_OPS(eevdf_select_cid, struct task_struct *p, s32 prev_cid, u64 wake_flags)
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
	if (wake_flags & SCX_WAKE_TTWU)
		tctx->runnable_at = now;

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

void BPF_STRUCT_OPS(eevdf_update_idle, s32 cid, bool idle)
{
	TOUCH_ARENA();

	if (idle) {
		u64 now = scx_bpf_now();

		cid_demand_set(cid, false, now);
		cid_idle_set(cid);
		/*
		 * The tick stops with the CPU: record the empty pack now, or the
		 * idle period is averaged in at the weight of the last tick.
		 */
		cid_load_accumulate(cid, now);
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
