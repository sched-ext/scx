/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees. Admission follows
 * user-space CPU pressure, placement floors a wakee's carried lag at a fixed
 * virtual-time credit, a per-pack budget bounds what credited work may take
 * in aggregate, and optional packing sends admitted work to a higher
 * asymmetric-packing tier when no CPU is idle.
 */
#include "latency.bpf.h"
#include "task.bpf.h"

#define USER_EVAL_NS		10000000ULL
#define USER_STALE_EVALS	5
#define USER_STALE_NS		(USER_EVAL_NS * USER_STALE_EVALS)

/* @latency_credit_budget at which a pack lends without limit. */
#define CREDIT_UNBOUNDED	1024

static volatile u64 user_util_sum __hot_written;
static volatile u64 user_util_snapshot_at __hot_written;
static u64 credit_pack_cursor;

/*
 * Refresh the system-wide user-utilization snapshot from the per-cid EWMAs.
 * Only one caller does the bounded scan in each evaluation period, keeping
 * the scan out of the wakeup path. The result is a bounded-age snapshot, not
 * a simultaneous observation. Stale cids contribute zero.
 */
static void update_user_util_snapshot(u64 now)
{
	u64 last = user_util_snapshot_at;
	u64 sum = 0;
	u32 i;

	if (now - last < USER_EVAL_NS)
		return;
	if (__sync_val_compare_and_swap(&user_util_snapshot_at, last, now) != last)
		return;

	bpf_arena_for(i, 0, nr_cids) {
		struct cid_ctx __arena *cctx = cid_ctx(i);

		if (now - cctx->user_eval_at <= USER_STALE_NS)
			sum += cctx->user_util_ewma;
	}
	user_util_sum = sum;
}

/*
 * Charge p->utime deltas from the tick and when the task stops, then fold
 * them every 10ms into an EWMA of the fraction of wall time spent in user
 * space. System time is excluded so syscall-heavy sleep workloads do not
 * enable the credit.
 */
static void update_cid_user(struct task_struct *p, s32 cid,
			    task_ctx_t *tctx, u64 now)
{
	struct cid_ctx __arena *cctx;
	u64 delta, util;

	if (!latency_credit || !latency_credit_user_thresh || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);

	/*
	 * ops.running() resets last_utime, and tick/stopping charge the delta
	 * to the cid on which that run occurred. A migration crosses a
	 * stopping/running pair, so task-global utime does not leak between
	 * cids while a task is queued.
	 */
	cctx->user_acc += p->utime - tctx->last_utime;
	tctx->last_utime = p->utime;

	delta = now - cctx->user_eval_at;
	if (delta < USER_EVAL_NS)
		return;

	util = MIN(cctx->user_acc * 1024 / delta, 1024);
	cctx->user_util_ewma = (cctx->user_util_ewma -
				  (cctx->user_util_ewma >> 2)) + (util >> 2);
	cctx->user_acc = 0;
	cctx->user_eval_at = now;

	if (!cctx->user_busy &&
	    cctx->user_util_ewma >= latency_credit_user_thresh)
		cctx->user_busy = true;
	else if (cctx->user_busy &&
		 cctx->user_util_ewma < latency_credit_user_thresh -
					 latency_credit_user_thresh / 4)
		cctx->user_busy = false;

	/* The aggregate can only change when one of its samples changes. */
	update_user_util_snapshot(now);
}

static bool cid_user_busy(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;
	u64 local = 0, peers;

	if (!latency_credit_user_thresh)
		return true;
	cctx = cid_ctx(cid);
	if (now - cctx->user_eval_at <= USER_STALE_NS) {
		local = cctx->user_util_ewma;
		if (cctx->user_busy)
			return true;
	}

	if (nr_cids <= 1 || now - user_util_snapshot_at > USER_STALE_NS)
		return false;

	/*
	 * The target's utilization can fall when latency-sensitive work
	 * displaces its sole CPU hog. Use the continuous mean utilization of the
	 * other cids as independent evidence that this is a placement hole in
	 * an otherwise user-saturated system. user_util_sum is a periodic
	 * snapshot, while local is the target's latest EWMA, so this is an
	 * intentionally approximate leave-one-out value.
	 */
	peers = user_util_sum;
	if (peers >= local)
		peers -= local;
	else
		peers = 0;

	if (peers >= latency_credit_user_thresh * (nr_cids - 1))
		return true;

	return false;
}

/*
 * The most service a pack lends before it has to earn more, and, negated, the
 * deepest debt one round of lending may leave it in. The ceiling bounds what
 * an idle pack saves up, so the first storm to arrive cannot spend a quiet
 * minute in one round; a credited task's whole burst should fit inside it.
 * The floor bounds how long a pack that lent to a storm stays out of the
 * credit afterwards: without it that is decided by whatever the tasks already
 * admitted go on to consume, which is nothing the budget can name.
 */
static __always_inline s64 credit_burst(void)
{
	return (s64)(slice_ns * 4);
}

/*
 * Move @pk's allowance by @delta, saturating at either end of the burst.
 * Wakeups refill a pack from other CPUs while the cid charges it, so the
 * exchange is retried rather than letting a lost race carry the allowance
 * past a bound it is the whole point of.
 */
static void credit_add(pack_t *pk, s64 delta)
{
	s64 burst = credit_burst();
	s64 old, new;

	while (can_loop) {
		old = READ_ONCE(pk->credit_tokens);
		new = old + delta;
		if (new > burst)
			new = burst;
		else if (new < -burst)
			new = -burst;
		if (new == old || cmpxchg(&pk->credit_tokens, old, new) == old)
			return;
	}
}

/*
 * Grow @pk's allowance by its share of the time the cid has had since the
 * last refill, measured in the cid's task clock: the same clock credited
 * service is charged in, and one that already excludes the interrupt and
 * steal time the CPU never had to give away.
 *
 * That clock does not stand still for idle, so a pack earns while its cid is
 * idle as well as while it runs, and the budget is a share of the CPU rather
 * than of the service the pack happened to deliver. This is deliberate: an
 * idle CPU is where a wakee is cheapest to favour, and a rule that only paid
 * a busy pack would withhold the credit exactly where it costs nothing.
 * @credit_burst() is what keeps a long idle from being spendable at once.
 *
 * Refills are spaced by a quarter slice. The wakeup path is where this runs,
 * and under the storms this exists to bound that is every wakeup on the cid;
 * without the spacing they would serialize on one cacheline to add a few
 * nanoseconds each. A refill that loses the exchange simply lets the winner's
 * interval cover it.
 */
static void credit_refill(pack_t *pk, u64 tnow)
{
	u64 last = READ_ONCE(pk->credit_refill_at);
	s64 delta, gain, tokens, burst, room;
	u64 span;

	/*
	 * Signed: @tnow is an rq clock less an offset another CPU publishes,
	 * see cid_clock_task_at(), so it can step backwards by the interrupt
	 * time that offset grew by between two reads. Unsigned, such a step
	 * reads as an interval of almost 2^64 and buys a full burst.
	 */
	delta = (s64)(tnow - last);
	if (delta < (s64)(slice_ns >> 2))
		return;
	if (cmpxchg(&pk->credit_refill_at, last, tnow) != last)
		return;

	if (!latency_credit_budget)
		return;
	burst = credit_burst();
	tokens = READ_ONCE(pk->credit_tokens);
	room = burst - tokens;
	if (room <= 0)
		return;

	/*
	 * Nothing beyond @room can be earned in one refill, so bound the
	 * interval that buys it before it is scaled. That is also what keeps
	 * the product in range on a pack's first refill, where @last is zero
	 * and the interval is the machine's whole uptime. Both sides are
	 * positive here and the arithmetic is unsigned: BPF has no signed
	 * divide.
	 */
	span = (u64)room * CREDIT_UNBOUNDED / latency_credit_budget;
	if ((u64)delta >= span)
		gain = room;
	else
		gain = (s64)((u64)delta * latency_credit_budget /
			     CREDIT_UNBOUNDED);
	if (gain > 0)
		credit_add(pk, gain);
}

/*
 * Whether @pk has anything left to lend, without refilling it. Packing reads
 * this for every cid it considers, and the placement path refills the cid it
 * lands on, so the value a scan sees is at most a quarter slice stale.
 *
 * A pack that has never refilled holds no tokens yet and is treated as able
 * to lend: it is the first wakee's placement that fills it, and packing has
 * to be able to send that wakee there. Without this a cid that never took a
 * credited wakeup could never be picked to take one.
 */
static __always_inline bool credit_available(pack_t *pk)
{
	if (latency_credit_budget >= CREDIT_UNBOUNDED)
		return true;
	if (!latency_credit_budget)
		return false;

	return !READ_ONCE(pk->credit_refill_at) ||
	       READ_ONCE(pk->credit_tokens) > 0;
}

/*
 * Hand what @cid's pack has counted since the last tick to the totals user
 * space reads. The counters live in the pack, on a line the placement path
 * already owns, so a wakeup pays nothing for them; one exchange per tick is
 * what turns them into a number. Nothing is counted on a cid without a wakee
 * being queued there for it, so a pack with something to fold is a pack whose
 * cid is about to tick.
 */
static void credit_stats_fold(s32 cid)
{
	pack_t *pk;
	u64 v;

	if (latency_credit_budget >= CREDIT_UNBOUNDED || !cid_valid(cid))
		return;
	pk = cid_pack(cid);

	v = __sync_lock_test_and_set(&pk->credit_grants, 0);
	if (v)
		__sync_fetch_and_add(&nr_credit_grants, v);
	v = __sync_lock_test_and_set(&pk->credit_denied, 0);
	if (v)
		__sync_fetch_and_add(&nr_credit_denied, v);
}

/*
 * Charge @delta of service to the budget of @pk, the pack @tctx is credited
 * on. A loan is only ever repaid to the pack that granted it: every arrival
 * in another pack clears the flag, see place_task() and eevdf_running(), so
 * a task that still carries it has not moved since it was placed.
 *
 * What a loan costs the tasks it displaces is the service the credited task
 * takes while it sits ahead of them, not the displacement it was granted:
 * placement is absolute, vruntime = vref - credit on every wakeup and never
 * cumulative, so a thread waking three thousand times a second is granted
 * sixty seconds of virtual time per second and costs a hog only the bursts
 * it actually runs. Charging grants would price that thread out of the
 * credit it was built for, which is what bounding the loan per task already
 * did once, see the aquarium numbers behind the flat credit.
 *
 * So charge consumption. What the budget then says is that uncredited work
 * keeps at least 1 - @latency_credit_budget of the pack, whatever the number
 * of credited sleepers, which is the one thing no per-task rule can promise.
 */
static void credit_charge(pack_t *pk, task_ctx_t *tctx, u64 delta)
{
	if (latency_credit_budget >= CREDIT_UNBOUNDED)
		return;
	if (delta)
		credit_add(pk, -(s64)delta);

	/*
	 * The loan is spent once the task has caught the reference. From here
	 * it is ahead of nobody and what it runs is its own turn, so stop
	 * charging it for a position it no longer holds.
	 */
	if (!time_before(tctx->se.vruntime, pack_vref(pk)))
		tctx->credited = false;
}

/*
 * Return whether @tctx may borrow on @cid. The sleep window is always met by
 * a wakeup; it also defines the current tasks that packing leaves alone.
 */
static __always_inline bool task_credit_admitted(s32 cid,
						 const task_ctx_t *tctx, u64 now)
{
	return latency_credit && cid_user_busy(cid, now) &&
	       now - tctx->last_sleep_at < latency_credit_sleep_ns;
}

/*
 * Return the offset from the destination reference used to place @p: the lag
 * carried out of its old pack, with a minimum of the configured virtual-time
 * credit when latency-credit admission succeeds.
 *
 * The credit is a fixed placement scale rather than a computed minimum needed
 * to cross the current deadline frontier. It is scaled by the task's deadline
 * weight and granted only on a cid with sustained user-space utilization. A
 * CPU busy in the kernel keeps the lag the task earned instead.
 *
 * A pack out of budget places the wakee at the lag it earned, which is
 * ordinary EEVDF: the mechanism turns itself off under exactly the load that
 * exhausts it, rather than letting every wakee conclude on its own that it
 * has earned another loan.
 */
static s64 task_place_offset(s32 cid, pack_t *pk, const struct task_struct *p,
			     task_ctx_t *tctx, u64 now, u64 tnow)
{
	bool bounded = latency_credit_budget < CREDIT_UNBOUNDED;
	s64 credit;

	if (!task_credit_admitted(cid, tctx, now))
		return tctx->se.vlag;

	if (bounded) {
		credit_refill(pk, tnow);
		if (READ_ONCE(pk->credit_tokens) <= 0) {
			__sync_fetch_and_add(&pk->credit_denied, 1);
			return tctx->se.vlag;
		}
	}

	credit = (s64)scale_by_dl_weight(p, tctx, latency_credit_ns);

	/*
	 * A task whose own lag already carries it further than the credit is
	 * not borrowing anything: it is being placed where EEVDF would place
	 * it. Leave it uncredited so the budget is charged for loans only.
	 */
	if (credit <= tctx->se.vlag)
		return tctx->se.vlag;

	tctx->credited = true;
	if (bounded)
		__sync_fetch_and_add(&pk->credit_grants, 1);

	return credit;
}

/*
 * Return the cid an admitted wakee is queued on when the idle scan found
 * nothing: @target, unless a cid of a higher asymmetric-packing priority
 * is running a task that never sleeps.
 *
 * SD_ASYM_PACKING fills the preferred CPUs first, and fair.c's asymmetric
 * active balance pulls a running task up to a preferred CPU only when that
 * CPU is idle. With a hog on every CPU nothing is ever idle, and a task
 * stays wherever its wakeups keep finding it. The WebGL aquarium's render
 * thread sat on an E-core at 2.2 GHz for as long as the hogs ran, at 19
 * fps, while the same thread pinned to a P-core beside its hog made 37 to
 * 46. The credit already lets the wakee win the CPU from a hog wherever it
 * lands, so let it land where the CPU is fastest: the hog there loses its
 * turn, and the balancer finds it a lower-priority CPU in due course. A
 * cid whose current task slept recently is left alone, it is running work
 * of the same kind, and a cursor spreads successive wakees over the tier.
 * A task pinned to one CPU, or one whose target is already in the top
 * tier, is not moved.
 *
 * A cid out of credit budget is left alone too. The move is worth making
 * only because the credit wins the CPU on arrival; without it the wakee is
 * merely queued behind a hog it did not choose, which is worse than the
 * target the wakeup picked for itself.
 */
static s32 credit_pack_cid(const struct task_struct *p, task_ctx_t *tctx,
			   s32 target, u64 now)
{
	u32 tier, t, i, start;
	bool restricted;

	if (!latency_credit || no_latency_credit_pack || !asym_packing ||
	    nr_place_tiers < 2 || !cid_valid(target) || is_pcpu_task(p))
		return target;
	tier = cid_topo(target)->place_tier;
	if (!tier || !task_credit_admitted(target, tctx, now))
		return target;

	restricted = is_restricted(p);
	start = __sync_fetch_and_add(&credit_pack_cursor, 1);
	bpf_arena_for(t, 0, tier) {
		bpf_arena_for(i, 0, nr_cids) {
			s32 cid = (start + i) % nr_cids;

			if (cid_topo(cid)->place_tier != t)
				continue;
			if (READ_ONCE(cid_ctx(cid)->curr_sleeper))
				continue;
			if (!credit_available(cid_pack(cid)))
				continue;
			if (restricted && !cid_allowed(p, cid))
				continue;
			return cid;
		}
	}

	return target;
}
