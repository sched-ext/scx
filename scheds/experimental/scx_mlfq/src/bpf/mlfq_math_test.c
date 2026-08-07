/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Native unit tests for the scx_mlfq pure-logic layer (intf.h). Compiles
 * the same header the BPF code and the Rust bindings use, with MLFQ_CHECK
 * forced on so the invariant predicates are exercised too. Runs on the
 * host with no kernel, BTF or BPF privileges, driven by the Rust unit
 * test in main.rs.
 */

#define MLFQ_CHECK 1
#include "intf.h"

#include <stdio.h>
#include <string.h>

static int nr_failed;

#define TEST_OK(cond, fmt, ...)						\
	do {								\
		if (cond) {						\
			printf("PASS: " fmt "\n", ##__VA_ARGS__);	\
		} else {						\
			printf("FAIL: " fmt "\n", ##__VA_ARGS__);	\
			nr_failed++;					\
		}							\
	} while (0)

/* Virtual time scales as delta * 100 / weight. */
static void test_calc_delta_fair(void)
{
	TEST_OK(calc_delta_fair_bpf(1000000, 100) == 1000000,
		"delta 1ms weight 100 -> 1ms virtual");
	TEST_OK(calc_delta_fair_bpf(1000000, 200) == 500000,
		"delta 1ms weight 200 -> 0.5ms virtual");
	TEST_OK(calc_delta_fair_bpf(1000000, 1) == 100000000,
		"delta 1ms weight 1 -> 100ms virtual");
	TEST_OK(calc_delta_fair_bpf(1000000, 10000) == 10000,
		"delta 1ms weight 10000 -> 10us virtual");
}

static struct queue_ctx make_q(u64 clock, u64 max_slice_ns)
{
	struct queue_ctx q = {
		.clock = clock,
		.max_slice_ns = max_slice_ns,
	};

	return q;
}

static void test_place_entity(void)
{
	struct queue_ctx q;
	struct task_ctx t;

	/* Empty clock at 0, weight 100, Q2 slice: deadline == vslice == 2ms. */
	q = make_q(0, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	TEST_OK(mlfq_place_entity(&q, &t) == 2000000 &&
		t.vruntime == 0 && t.vlag == 0 && t.deadline == 2000000,
		"first placement: vruntime 0, vlag 0, deadline 2ms");

	/*
	 * A task far behind the clock is clamped to clock - limit, the
	 * fair.c bounded-lag property: lag saturates at limit and the
	 * placed vruntime never falls more than one lag bound behind the
	 * service point. limit = 3ms virtual at weight 100.
	 */
	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = 0;
	TEST_OK(mlfq_place_entity(&q, &t) == (1ULL << 40) - 1000000 &&
		t.vruntime == (1ULL << 40) - 3000000 && t.vlag == 3000000,
		"behind task clamped to clock - limit, lag at the bound");

	/*
	 * An ahead task is placed at the clock (fair.c DELAY_ZERO):
	 * leading credit is not carried, so the negative lag case is
	 * collapsed to zero.
	 */
	q = make_q(1000, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = 1ULL << 40;
	TEST_OK(mlfq_place_entity(&q, &t) == 2001000 &&
		t.vruntime == 1000 && t.vlag == 0,
		"ahead task placed at the clock, vlag 0");

	/*
	 * An in-band task (within one lag limit behind the clock) keeps
	 * its vruntime; its lag and deadline follow the placement formulas.
	 */
	q = make_q(1000000, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = 800000;
	TEST_OK(mlfq_place_entity(&q, &t) == 2800000 &&
		t.vruntime == 800000 && t.vlag == 200000 &&
		t.deadline == 2800000,
		"in-band task keeps its vruntime, deadline = vruntime + vslice");

	/* deadline = vruntime_new + vslice, with FIRST_RUN halving once. */
	q = make_q(0, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.flags = MLFQ_TF_FIRST_RUN;
	TEST_OK(mlfq_place_entity(&q, &t) == 1000000,
		"FIRST_RUN deadline is half vslice (1ms)");
	t.flags &= ~MLFQ_TF_FIRST_RUN;
	TEST_OK(mlfq_place_entity(&q, &t) == 2000000,
		"after FIRST_RUN clears the full vslice applies");

	/*
	 * A wrapped deadline that would compute to zero is bumped to one
	 * (the sentinel for a failed placement); the position is identical
	 * in the wrapping order the DSQ rbtree uses.
	 */
	q = make_q(0ULL - 1000000ULL, 1000000);	/* clock one slice before wrap */
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = q.clock;	/* task exactly at the clock, lag 0 */
	TEST_OK(mlfq_place_entity(&q, &t) == 1 && t.deadline == 1,
		"wrapped deadline that would be zero is bumped to 1");
}

/*
 * The lag bound scales with the weight: a weight-1 task may lag up to
 * 100x the request size behind the clock, a weight-10000 task only
 * 1% of it. The clamp holds at both extremes.
 */
static void test_place_entity_weight_edges(void)
{
	struct queue_ctx q;
	struct task_ctx t;

	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 1;
	t.vruntime = 0;
	TEST_OK(mlfq_place_entity(&q, &t) == (1ULL << 40) - 100000000ULL &&
		t.vruntime == (1ULL << 40) - 300000000ULL &&
		t.vlag == 300000000ULL,
		"weight 1: lag clamped to 100x the request size");

	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 10000;
	t.vruntime = 0;
	TEST_OK(mlfq_place_entity(&q, &t) == (1ULL << 40) - 30000ULL + 20000ULL &&
		t.vruntime == (1ULL << 40) - 30000ULL && t.vlag == 30000ULL,
		"weight 10000: lag clamped to 1/100 of the request size");
}

/*
 * Placement, charge and re-placement form the per-queue service loop:
 * the clock advances to the vruntime just charged, and the next
 * placement of the same task measures its lag from the fresh clock.
 */
static void test_place_charge_replacement(void)
{
	struct queue_ctx q;
	struct task_ctx t;

	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = q.clock - 1000000;	/* one ms behind the clock */
	mlfq_place_entity(&q, &t);
	TEST_OK(t.vruntime == q.clock - 1000000 && t.vlag == 1000000,
		"in-band task placed with its lag preserved");

	mlfq_queue_advance_clock(&q, t.vruntime);
	TEST_OK(q.clock == (1ULL << 40),
		"a task behind the clock does not advance it");

	/*
	 * The task runs a full slice: the charge is its vruntime plus
	 * the slice's virtual time, which lands ahead of the clock.
	 */
	t.vruntime += 2000000;
	mlfq_queue_advance_clock(&q, t.vruntime);
	TEST_OK(q.clock == t.vruntime,
		"clock advances to the vruntime charged for a full slice");

	t.vruntime = q.clock - 500000;	/* now only 0.5 ms behind */
	mlfq_place_entity(&q, &t);
	TEST_OK(t.vruntime == q.clock - 500000 && t.vlag == 500000,
		"re-placement measures the lag from the advanced clock");
}

static void test_clock_advance(void)
{
	struct queue_ctx q = make_q(1000, 2000000);

	mlfq_queue_advance_clock(&q, 5000);
	TEST_OK(q.clock == 5000,
		"advance to a larger vruntime advances the clock");
	mlfq_queue_advance_clock(&q, 100);
	TEST_OK(q.clock == 5000,
		"advance to a smaller vruntime is ignored (monotone)");
	mlfq_queue_advance_clock(&q, 5000);
	TEST_OK(q.clock == 5000,
		"equal vruntime leaves the clock unchanged");

	q = make_q(0ULL - 100ULL, 2000000);
	mlfq_queue_advance_clock(&q, 10);
	TEST_OK(q.clock == 10,
		"wrapped advance across the u64 boundary is followed");
}

static void test_ema_climb(void)
{
	TEST_OK(mlfq_ema_climb(0, 250000, 6000000, 3072) == 3000000,
		"0 + 250us run -> half the gauge");
	TEST_OK(mlfq_ema_climb(0, 1000000, 6000000, 3072) == 6000000,
		"0 + 1ms run saturates the gauge (step clamped)");
	TEST_OK(mlfq_ema_climb(3000000, 250000, 6000000, 3072) == 4500000,
		"half gauge + 250us -> three quarters");
	TEST_OK(mlfq_ema_climb(6000000, 1000000, 6000000, 3072) == 6000000,
		"gauge never exceeds budget max");
}

static void test_ema_decay(void)
{
	u64 d;

	TEST_OK(mlfq_ema_decay(6000000, 24000000, 24000000) == 3000000,
		"one half-life halves the gauge");
	TEST_OK(mlfq_ema_decay(6000000, 120000000, 24000000) == 187500,
		"five half-lives divide by 32");
	TEST_OK(mlfq_ema_decay(6000000, 24ULL * 64 * 1000000, 24000000) == 0,
		"64 periods zero the gauge");

	d = mlfq_ema_decay(6000000, 36000000, 24000000); /* 1.5 periods */
	TEST_OK(d < 3000000 && d >= 1500000,
		"1.5-period decay lands between one and two periods");
	TEST_OK(mlfq_ema_decay(6000000, 1000000, 24000000) < 6000000,
		"sub-period Taylor residual decays strictly");
}

static void test_queue_mapping(void)
{
	TEST_OK(mlfq_queue_from_ema(0, 250000, 2000000) == 1,
		"ema 0 -> Q1");
	TEST_OK(mlfq_queue_from_ema(250000, 250000, 2000000) == 1,
		"ema == T_L -> Q1");
	TEST_OK(mlfq_queue_from_ema(250001, 250000, 2000000) == 2,
		"ema just above T_L -> Q2");
	TEST_OK(mlfq_queue_from_ema(1000000, 250000, 2000000) == 2,
		"ema 1ms -> Q2");
	TEST_OK(mlfq_queue_from_ema(2000000, 250000, 2000000) == 3,
		"ema == T_H -> Q3");
	TEST_OK(mlfq_queue_from_ema(5000000, 250000, 2000000) == 3,
		"ema 5ms -> Q3");
}

static void test_promote_hysteresis(void)
{
	struct task_ctx t = { .queue = 2, .ema = 0 };

	TEST_OK(!mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000) &&
		t.wake_cnt == 1 && t.queue == 2,
		"single short sleep does not promote Q2->Q1");
	TEST_OK(mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000) &&
		t.queue == 1 && t.wake_cnt == 0,
		"two short sleeps promote Q2->Q1 and reset wake_cnt");
	mlfq_promote_on_wakeup(&t, 10000000, 250000, 2000000, 4000000);
	TEST_OK(t.wake_cnt == 0 && t.queue == 1,
		"long sleep resets wake_cnt, Q1 stays");

	t.queue = 3;
	t.ema = 0;
	t.wake_cnt = 0;
	mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000);
	TEST_OK(mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000) &&
		t.queue == 2,
		"two short sleeps promote Q3->Q2");

	t.queue = 3;
	t.ema = 1000000;	/* not < T_H/2 */
	t.wake_cnt = 0;
	mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000);
	TEST_OK(!mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000) &&
		t.queue == 3,
		"ema above T_H/2 blocks Q3->Q2 despite two short sleeps");
}

static void test_demote_hysteresis(void)
{
	struct task_ctx t = { .queue = 1, .ema = 500000 };

	mlfq_demote_on_reenq(&t, 2000000);
	TEST_OK(t.reenq_cnt == 1 && t.queue == 1,
		"single run-out with ema > T_L does not demote Q1->Q2");
	mlfq_demote_on_reenq(&t, 2000000);
	TEST_OK(t.reenq_cnt == 2 && t.queue == 1,
		"two run-outs with ema below T_H do not demote Q1->Q2");

	t.queue = 1;
	t.ema = 3000000;	/* > T_H */
	t.reenq_cnt = 0;
	for (int i = 0; i < 7; i++)
		mlfq_demote_on_reenq(&t, 2000000);
	TEST_OK(t.reenq_cnt == 7 && t.queue == 1,
		"seven run-outs with ema > T_H do not demote Q1->Q2");
	TEST_OK(mlfq_demote_on_reenq(&t, 2000000) &&
		t.queue == 2 && t.reenq_cnt == 0,
		"eight run-outs demote Q1->Q2 and reset reenq_cnt");

	t.queue = 2;
	t.ema = 3000000;	/* > T_H */
	t.reenq_cnt = 0;
	for (int i = 0; i < 7; i++)
		mlfq_demote_on_reenq(&t, 2000000);
	TEST_OK(t.reenq_cnt == 7 && t.queue == 2,
		"seven run-outs with ema > T_H do not demote Q2->Q3");
	TEST_OK(mlfq_demote_on_reenq(&t, 2000000) &&
		t.queue == 3 && t.reenq_cnt == 0,
		"eight run-outs demote Q2->Q3 and reset reenq_cnt");
}

static void test_mlfq_check_predicates(void)
{
	TEST_OK(mlfq_check_ema_bounds(6000000, 6000000),
		"ema == budget max is in bounds");
	TEST_OK(!mlfq_check_ema_bounds(6000001, 6000000),
		"ema above budget max is out of bounds");
	TEST_OK(mlfq_check_queue(1) && mlfq_check_queue(3),
		"queues 1 and 3 are valid");
	TEST_OK(!mlfq_check_queue(0) && !mlfq_check_queue(4),
		"queues 0 and 4 are invalid");
	TEST_OK(mlfq_check_weight(1) && !mlfq_check_weight(0),
		"weight >= 1 invariant");
	TEST_OK(mlfq_check_queued_vlag(0) && !mlfq_check_queued_vlag(-1),
		"queued lag >= 0 invariant");
}

static void test_bitmap(void)
{
	struct mlfq_bitmap bm;

	memset(&bm, 0, sizeof(bm));

	mlfq_bitmap_set_cpu(&bm, 0);
	mlfq_bitmap_set_cpu(&bm, 1);
	mlfq_bitmap_set_cpu(&bm, 64);
	mlfq_bitmap_set_cpu(&bm, 1023);
	mlfq_bitmap_set_cpu(&bm, 1024);	/* out of range, ignored */

	TEST_OK(mlfq_bitmap_test_cpu(&bm, 0) && mlfq_bitmap_test_cpu(&bm, 1),
		"bits 0 and 1 set in word 0");
	TEST_OK(mlfq_bitmap_test_cpu(&bm, 64),
		"bit 64 set in word 1");
	TEST_OK(mlfq_bitmap_test_cpu(&bm, 1023),
		"bit 1023 set in word 15");
	TEST_OK(!mlfq_bitmap_test_cpu(&bm, 2),
		"bit 2 not set");
	TEST_OK(!mlfq_bitmap_test_cpu(&bm, 63),
		"bit 63 not set");
	TEST_OK(!mlfq_bitmap_test_cpu(&bm, 1024),
		"out-of-range CPU never tests set");
	TEST_OK(bm.words[0] == 0x3ULL && bm.words[1] == 0x1ULL &&
		bm.words[15] == (1ULL << 63),
		"word layout matches cpu >> 6 / (cpu & 63)");
	TEST_OK(MLFQ_BITMAP_WORDS == (MLFQ_MAX_CPUS + 63) / 64,
		"bitmap word count matches the CPU bound");
}

static void test_ss_boost_allowed(void)
{
	u64 limit = 2000000;	/* MLFQ_SHORT_SLEEP_RATE_LIMIT_NS */
	u64 now = 1000000000;

	TEST_OK(mlfq_ss_boost_allowed(0, now, limit),
		"first boost is always allowed");
	TEST_OK(!mlfq_ss_boost_allowed(now, now, limit),
		"boost at the same instant as the last one is blocked");
	TEST_OK(!mlfq_ss_boost_allowed(now, now + limit - 1, limit),
		"boost within the rate-limit window is blocked");
	TEST_OK(!mlfq_ss_boost_allowed(now, now + limit, limit),
		"boost exactly at the window edge is still blocked");
	TEST_OK(mlfq_ss_boost_allowed(now, now + limit + 1, limit),
		"boost after the window has elapsed is allowed");
	TEST_OK(mlfq_ss_boost_allowed(now - 100000000, now, limit),
		"ancient boost (100ms ago) is allowed");
	TEST_OK(!mlfq_ss_boost_allowed(1000, 2000, limit),
		"tiny offset with a large limit is blocked");
	TEST_OK(!mlfq_ss_boost_allowed(2000, 1000, limit),
		"wrap-around clock: a future boost timestamp blocks");
}

static void test_boost_eligible(void)
{
	u64 win = 1000000;	/* MLFQ_SHORT_SLEEP_NS */

	TEST_OK(mlfq_boost_eligible(0, win, true),
		"I/O wakeup with no sleep is eligible");
	TEST_OK(mlfq_boost_eligible(5000000, win, true),
		"I/O wakeup after a long sleep is eligible");
	TEST_OK(!mlfq_boost_eligible(0, win, false),
		"no sleep and not I/O is not eligible");
	TEST_OK(mlfq_boost_eligible(500000, win, false),
		"short sleep is eligible");
	TEST_OK(!mlfq_boost_eligible(2000000, win, false),
		"long sleep without I/O is not eligible");
	TEST_OK(!mlfq_boost_eligible(win + 1, win, false),
		"sleep just past the window is not eligible");
	TEST_OK(mlfq_boost_eligible(win, win, false),
		"sleep exactly at the window is eligible");
}

int main(void)
{
	test_calc_delta_fair();
	test_place_entity();
	test_place_entity_weight_edges();
	test_place_charge_replacement();
	test_clock_advance();
	test_ema_climb();
	test_ema_decay();
	test_queue_mapping();
	test_promote_hysteresis();
	test_demote_hysteresis();
	test_ss_boost_allowed();
	test_boost_eligible();
	test_mlfq_check_predicates();
	test_bitmap();

	if (nr_failed) {
		printf("%d test(s) FAILED\n", nr_failed);
		return 1;
	}

	printf("All tests passed\n");
	return 0;
}
