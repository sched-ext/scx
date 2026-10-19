// SPDX-License-Identifier: GPL-2.0
/*
 * Select scan with slowest plus best sufficient fit for the core.
 *
 * Holds the SSF scan plus the BSF fallback plus the combined best pick
 * plus the single ktime scan tail. The SSF scan takes the slowest
 * sufficient CPU in two node-local phases with a near minimum tiebreak
 * on the CPU minima through a single best plus a locality flag, so
 * light work never takes a fast CPU and close peers win ties with no
 * extra scan. Tied minima on the previous CPU win even past the lower
 * id with no extra scan, so cache stays warm sticky. The BSF fallback
 * takes the best sufficient CPU with the smallest combined drain plus
 * minimum plus prev plus id tiebreak over the next four peers past the
 * SSF window from cursor plus 9, so the two scans
 * cover twelve unique peers with no overlap when the host holds at
 * least twelve CPUs, else the windows wrap and overlap, and symmetric
 * hosts still spread work with no topology walk. Twelve peers cover
 * about one percent on a 1024 CPU host, so large hosts need many passes
 * with the cursor spreading the load and no single pass stall. SSF runs in O(VISIT)
 * with VISIT at most eight peers from the cursor with no hotspot, and
 * BSF adds at most four more from the disjoint window. The shared
 * cursor with dispatch steal advances by two with best effort races
 * and no atomic order. One ktime read serves the previous plus SSF
 * plus BSF checks, and pow2 hosts mask with no divide. Loops run via
 * bpf_loop callbacks with gated pow2 plus node-local paths, so the
 * verifier checks each body once with no unrolled depth. Runs under the
 * caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * struct flow_ssf_iter - SSF loop state for the bpf_loop callback.
 * @p: task to place, typed for the mask gate.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 * @this_cpu: waker CPU skipped as the busy waker.
 * @this_node: waker node for the locality gate.
 * @prev_cpu: previous CPU for the sticky tie preference.
 * @start: scan start below the host count.
 * @n: host count above one and within the bound.
 * @best: best peer id or 0xffffffffU when none meets.
 * @best_units: best capacity in base units.
 * @best_min: best minimum vruntime in nanos.
 * @pow2: true when @n holds exactly one bit, hoisted once.
 * @best_local: true when @best shares the waker node.
 */
struct flow_ssf_iter {
	const struct task_struct *p;
	u64 deadline;
	u64 now;
	u32 this_cpu;
	u32 this_node;
	s32 prev_cpu;
	u32 start;
	u32 n;
	u32 best;
	u32 best_units;
	u64 best_min;
	bool pow2;
	bool best_local;
};
/**
 * struct flow_bsf_iter - BSF loop state for the bpf_loop callback.
 * @p: task to place, typed for the mask gate.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 * @this_cpu: waker CPU skipped as the busy waker.
 * @prev_cpu: previous CPU for the sticky tie preference.
 * @start: disjoint start past the SSF window.
 * @n: host count above one and within the bound.
 * @best: best peer id or 0xffffffffU when none meets.
 * @best_drain: best combined drain in nanos.
 * @best_min: best minimum vruntime in nanos.
 * @pow2: true when @n holds exactly one bit, hoisted once.
 */
struct flow_bsf_iter {
	const struct task_struct *p;
	u64 deadline;
	u64 now;
	u32 this_cpu;
	s32 prev_cpu;
	u32 start;
	u32 n;
	u32 best;
	u64 best_drain;
	u64 best_min;
	bool pow2;
};
/**
 * flow_ssf_step - test one SSF peer via the bpf_loop callback.
 * @idx: offset from the scan start within the eight peer window.
 * @ctx_: pointer to struct flow_ssf_iter with the window plus best.
 *
 * Gates pow2 wrap plus window plus node-local paths with no unrolled
 * depth, so the verifier checks the body once with the same order.
 *
 * Returns: 1 to stop on bound, else 0 to continue.
 */
static int flow_ssf_step(u32 idx, void *ctx_)
{
	struct flow_ssf_iter *c = ctx_;
	u32 peer;
	u32 units;
	u64 pmin;
	bool same;
	if (!c)
		return 1;
	if ((u64)idx >= (u64)c->n)
		return 1;
	if (c->pow2)
		peer = (u32)(((u64)c->start + (u64)idx) & ((u64)c->n - 1ULL));
	else
		peer = (u32)(((u64)c->start + (u64)idx) % (u64)c->n);
	if (peer == c->this_cpu)
		return 0;
	if (!flow_cpu_ok(c->p, (s32)peer))
		return 0;
	if (!flow_cpu_meets(peer, c->deadline, c->now))
		return 0;
	units = flow_cpu_units(peer);
	if (c->best != 0xffffffffU) {
		if ((u64)units + 64ULL < (u64)c->best_units) {
			pmin = flow_cpu_min(peer);
			same = flow_cpu_node(peer) == c->this_node;
			c->best_units = units;
			c->best_min = pmin;
			c->best = peer;
			c->best_local = same;
			return 0;
		}
		if ((u64)units > (u64)c->best_units + 64ULL)
			return 0;
		pmin = flow_cpu_min(peer);
		same = flow_cpu_node(peer) == c->this_node;
		if (same && !c->best_local) {
			c->best_units = units < c->best_units ? units : c->best_units;
			c->best_min = pmin;
			c->best = peer;
			c->best_local = true;
			return 0;
		}
		if (!same && c->best_local)
			return 0;
		if (!flow_time_before(pmin, c->best_min) && pmin != c->best_min)
			return 0;
		/* Sticky prev-CPU tie preference with no extra scan. */
		/* A tied minimum on the previous CPU wins even past the */
		/* lower id, so cache stays warm with no hotspot. */
		if (pmin == c->best_min) {
			bool peer_prev = ((s32)peer == c->prev_cpu);
			bool best_prev = ((s32)c->best == c->prev_cpu);
			if (peer_prev && !best_prev) {
			} else if (!peer_prev && best_prev) {
				return 0;
			} else if (peer >= c->best) {
				return 0;
			}
		}
		c->best_units = units < c->best_units ? units : c->best_units;
		c->best_min = pmin;
		c->best = peer;
		c->best_local = same;
		return 0;
	}
	pmin = flow_cpu_min(peer);
	same = flow_cpu_node(peer) == c->this_node;
	c->best_units = units;
	c->best_min = pmin;
	c->best = peer;
	c->best_local = same;
	return 0;
}
/**
 * flow_bsf_step - test one BSF peer via the bpf_loop callback.
 * @idx: offset from the disjoint start within the four peer window.
 * @ctx_: pointer to struct flow_bsf_iter with the window plus best.
 *
 * Gates pow2 wrap plus drain plus minimum paths with no unrolled
 * depth, so the verifier checks the body once with the same order.
 *
 * Returns: 1 to stop on bound, else 0 to continue.
 */
static int flow_bsf_step(u32 idx, void *ctx_)
{
	struct flow_bsf_iter *c = ctx_;
	u32 peer;
	u64 drain;
	u64 pmin;
	if (!c)
		return 1;
	if ((u64)idx >= (u64)c->n)
		return 1;
	if (c->pow2)
		peer = (u32)(((u64)c->start + (u64)idx) & ((u64)c->n - 1ULL));
	else
		peer = (u32)(((u64)c->start + (u64)idx) % (u64)c->n);
	if (peer == c->this_cpu)
		return 0;
	if (!flow_cpu_ok(c->p, (s32)peer))
		return 0;
	if (!flow_cpu_meets(peer, c->deadline, c->now))
		return 0;
	drain = flow_cpu_drain(peer);
	if (c->best == 0xffffffffU) {
		pmin = flow_cpu_min(peer);
		c->best_drain = drain;
		c->best_min = pmin;
		c->best = peer;
		return 0;
	}
	if (drain < c->best_drain) {
		pmin = flow_cpu_min(peer);
		c->best_drain = drain;
		c->best_min = pmin;
		c->best = peer;
		return 0;
	}
	if (drain != c->best_drain)
		return 0;
	pmin = flow_cpu_min(peer);
	if (pmin != c->best_min && !flow_time_before(pmin, c->best_min))
		return 0;
	/* Sticky prev-CPU tie preference with no extra scan. */
	/* A tied drain plus minimum on the previous CPU wins even past */
	/* the lower id, so cache stays warm with no hotspot. */
	if (pmin == c->best_min) {
		bool peer_prev = ((s32)peer == c->prev_cpu);
		bool best_prev = ((s32)c->best == c->prev_cpu);
		if (peer_prev && !best_prev) {
		} else if (!peer_prev && best_prev) {
			return 0;
		} else if (peer >= c->best) {
			return 0;
		}
	}
	c->best_min = pmin;
	c->best = peer;
	return 0;
}

/**
 * struct flow_scan_tail - scan args for the Outlined SSF plus BSF picks.
 * @p: task to place, typed for the mask gate.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 * @this_cpu: waker CPU skipped as the busy waker.
 * @prev_cpu: previous CPU for the sticky tie preference.
 * @cursor: shared cursor for the scan start.
 *
 * Bundles the live task plus the deadline plus the poll time plus the
 * waker plus the previous CPU plus the shared cursor, so each Outlined
 * pick takes one pointer with no stack args and the two scans share
 * the same single reads.
 */
struct flow_scan_tail {
	const struct task_struct *p;
	u64 deadline;
	u64 now;
	u32 this_cpu;
	s32 prev_cpu;
	u32 cursor;
};
/**
 * flow_ssf_pick - slowest sufficient pick among allowed peers.
 * @t: scan tail with task plus deadline plus time plus waker plus
 * previous plus cursor, hoisted once by the caller with no second poll.
 *
 * Scans at most eight peers from the cursor via a bpf_loop callback
 * with no unrolled depth, so the verifier checks the body once with
 * gated pow2 plus node-local paths. Node-local peers win in the
 * 64-unit window with the same slowest plus near minimum rule, so
 * cache stays close with no extra scan. A tied minimum on the previous
 * CPU wins even past the lower id, so cache stays warm with no extra
 * scan. A local candidate beats a remote best in the window, while a
 * clearly slower peer still wins across phases with wrap safe adds.
 * Peers within 64 units count as near minimum with wrap safe order,
 * so lagging CPUs win ties.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: peer id or 0xffffffffU when no peer meets.
 */
static __noinline u32 flow_ssf_pick(const struct flow_scan_tail *t)
{
	struct flow_ssf_iter it = {
		.p = t->p,
		.deadline = t->deadline,
		.now = t->now,
		.this_cpu = t->this_cpu,
		.this_node = 0,
		.prev_cpu = 0,
		.start = 0,
		.n = 0,
		.best = 0xffffffffU,
		.best_units = 0xffffffffU,
		.best_min = (u64)~0ULL,
		.pow2 = false,
		.best_local = false,
	};
	u64 nr = nr_cpu_ids;
	u32 n;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return it.best;
	n = (u32)nr;
	it.n = n;
	it.this_node = flow_cpu_node(t->this_cpu);
	it.prev_cpu = t->prev_cpu;
	it.pow2 = flow_is_pow2((u64)n);
	if (it.pow2)
		it.start = (u32)(((u64)t->cursor + 1ULL) & ((u64)n - 1ULL));
	else
		it.start = (u32)(((u64)t->cursor + 1ULL) % (u64)n);
	bpf_loop((u32)FLOW_DISPATCH_MAX_VISIT, flow_ssf_step, &it, 0);
	return it.best;
}
/**
 * flow_bsf_pick - best sufficient fallback over the disjoint window.
 * @t: scan tail with task plus deadline plus time plus waker plus
 * previous plus cursor, hoisted once by the caller with no second poll.
 *
 * Scans the next four peers past the SSF window from cursor plus 9 via
 * a bpf_loop callback with no unrolled depth, so the verifier checks
 * the body once with gated pow2 plus minimum paths. Equal drains break
 * toward the smallest minimum with wrap safe order, then the previous
 * CPU on ties, then the smallest peer id, so ties stay sticky with no
 * hotspot. Covers twelve unique peers with SSF on large hosts, so
 * select pays at most 12 checks per pass.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: peer id or 0xffffffffU when no peer meets.
 */
static __noinline u32 flow_bsf_pick(const struct flow_scan_tail *t)
{
	struct flow_bsf_iter it = {
		.p = t->p,
		.deadline = t->deadline,
		.now = t->now,
		.this_cpu = t->this_cpu,
		.prev_cpu = 0,
		.start = 0,
		.n = 0,
		.best = 0xffffffffU,
		.best_drain = (u64)~0ULL,
		.best_min = (u64)~0ULL,
		.pow2 = false,
	};
	u64 nr = nr_cpu_ids;
	u32 n;
	u32 start;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return it.best;
	n = (u32)nr;
	it.n = n;
	it.prev_cpu = t->prev_cpu;
	it.pow2 = flow_is_pow2((u64)n);
	if (it.pow2) {
		start = (u32)(((u64)t->cursor + 1ULL) & ((u64)n - 1ULL));
		it.start = (u32)(((u64)start +
		    (u64)FLOW_DISPATCH_MAX_VISIT) & ((u64)n - 1ULL));
	} else {
		start = (u32)(((u64)t->cursor + 1ULL) % (u64)n);
		it.start = (u32)(((u64)start +
		    (u64)FLOW_DISPATCH_MAX_VISIT) % (u64)n);
	}
	bpf_loop((u32)FLOW_BSF_MAX_PEERS, flow_bsf_step, &it, 0);
	return it.best;
}
/**
 * flow_select_best - slowest plus best sufficient pick in one call.
 * @p: task to place.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 * @this_cpu: waker CPU for the cursor plus the self skip.
 * @prev_cpu: previous CPU for the sticky tie preference.
 *
 * Runs the SSF scan over eight peers from the cursor plus the disjoint
 * BSF fallback over the next four past the SSF window from cursor plus
 * 9, so twelve unique peers hold with no overlap on large hosts. Tied
 * minima on the previous CPU win in both scans with no extra walk, so
 * cache stays warm. The shared cursor with steal advances by two on
 * success with best effort races, so passes spread with no hotspot.
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: peer id or 0xffffffffU when no peer meets.
 */
static __noinline u32 flow_select_best(const struct task_struct *p,
	u64 deadline, u64 now, u32 this_cpu, s32 prev_cpu)
{
	u64 nr = nr_cpu_ids;
	struct flow_cpu_state *wst = flow_cpu(this_cpu);
	u32 cursor = wst ? READ_ONCE(wst->cursor) : 0;
	struct flow_scan_tail tail = {
		.p = p,
		.deadline = deadline,
		.now = now,
		.this_cpu = this_cpu,
		.prev_cpu = prev_cpu,
		.cursor = cursor,
	};
	u32 best;
	u32 bsf;
	u32 n;
	bool pow2;
	u32 start;
	u32 next;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return 0xffffffffU;
	n = (u32)nr;
	pow2 = flow_is_pow2((u64)n);
	if (pow2) {
		start = (u32)(((u64)cursor + 1ULL) & ((u64)n - 1ULL));
		next = (u32)(((u64)start + 1ULL) & ((u64)n - 1ULL));
	} else {
		start = (u32)(((u64)cursor + 1ULL) % (u64)n);
		next = (u32)(((u64)start + 1ULL) % (u64)n);
	}
	(void)start;
	best = flow_ssf_pick(&tail);
	if (best != 0xffffffffU) {
		if (wst)
			__sync_lock_test_and_set(&wst->cursor, next);
		return best;
	}
	bsf = flow_bsf_pick(&tail);
	if (bsf != 0xffffffffU) {
		if (wst)
			__sync_lock_test_and_set(&wst->cursor, next);
		return bsf;
	}
	return 0xffffffffU;
}
/**
 * flow_select_scan - run previous plus SSF plus BSF plus fallback.
 * @p: task to place.
 * @prev_cpu: previous CPU for the meet check plus the fallback.
 * @deadline: absolute deadline, zero meets all.
 * @this_cpu: waker CPU for the cursor plus the self skip.
 *
 * One ktime serves the previous plus SSF plus BSF with no second read.
 * Early exit on the previous CPU avoids both scans when it meets, so
 * the common stay keeps one drain check with no peer walk. Shared SSF
 * plus disjoint BSF run in one Outlined call with no topology signal,
 * so select keeps twelve peer coverage. An empty mask falls through to
 * the machine tier at enqueue.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: picked CPU or @prev_cpu on fallback with gate count.
 */
static __noinline s32 flow_select_scan(const struct task_struct *p,
	s32 prev_cpu, u64 deadline, u32 this_cpu)
{
	u64 now;
	u32 best;
	s32 first;
	/* One ktime serves previous plus SSF plus BSF with no second read. */
	now = flow_now();
	/* Early exit on the previous CPU avoids both scans when it meets, */
	/* so the common stay keeps one drain check with no peer walk. */
	if (flow_cpu_ok(p, prev_cpu)) {
		if (flow_cpu_meets((u32)prev_cpu, deadline, now))
			return prev_cpu;
	}
	/* Shared SSF plus disjoint BSF in one Outlined call with sticky */
	/* prev-CPU ties, so select keeps twelve peer coverage with warm */
	/* cache. */
	best = flow_select_best(p, deadline, now, this_cpu, prev_cpu);
	if (best != 0xffffffffU)
		return (s32)best;
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return prev_cpu;
}
