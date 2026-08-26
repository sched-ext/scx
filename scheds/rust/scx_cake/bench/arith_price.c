/*
 * arith_price — DIAGNOSTIC, NON-INGESTING. Prices hot-path arithmetic shapes
 * on this silicon so in-cake counter rates can be converted to ns/s. Latency-
 * chained loops (each op's result feeds the next op's input), pinned to one
 * core, median of reps. Not a benchmark arm; records no noise fields.
 *
 *   cc -O2 -o /tmp/arith_price arith_price.c && taskset -c 2 nice -n 19 /tmp/arith_price
 *
 * Shapes priced against cake.bpf.c (§R.24, docs/SWEEP_ARITH_2026-08-03.md):
 *   add        dependency-chained add                (baseline, ~1 cyc)
 *   imul       chained 64-bit multiply               (~3 cyc)
 *   div_small  S/n at fresh-task magnitudes          (S~4e8,  n~3e3)
 *   div_wide   S/n at old-task magnitudes            (S~2e12, n~8e5)
 *   slice_old  task_slice, divide always             (per arm profile)
 *   slice_new  cap/floor cross-mul pre-check, divide only on the mid arm
 *   call       noinline call carrying the add step   (call overhead = call-add)
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ITERS 50000000ull
#define REPS  5

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* task_slice constants, mirrored from intf.h / rodata at typical values. */
#define HANDOFF_MAX 1464ull	   /* cake_handoff_max_ns */
#define CAP	    2083333ull	   /* frame_floor(4.166ms @240Hz) >> 1 */

static volatile uint64_t sink;

static uint64_t chain_add(uint64_t s, uint64_t n)
{
	uint64_t acc = s;
	for (uint64_t i = 0; i < ITERS; i++)
		acc += n ^ (acc >> 7);
	return acc;
}

static uint64_t chain_imul(uint64_t s, uint64_t n)
{
	uint64_t acc = s;
	for (uint64_t i = 0; i < ITERS; i++)
		acc = acc * (n | 1) + (acc >> 7);
	return acc;
}

static uint64_t chain_div(uint64_t s, uint64_t n)
{
	uint64_t S = s, q = 0;
	for (uint64_t i = 0; i < ITERS; i++) {
		q = S / (n | 1);
		S = s + (q & 0xff);	/* dependency: quotient feeds dividend */
	}
	return q;
}

/* Old task_slice: divide every call, then clamp. */
static uint64_t slice_old(uint64_t s, uint64_t n)
{
	uint64_t S = s, w = 0;
	for (uint64_t i = 0; i < ITERS; i++) {
		w = (S / (n | 1)) << 1;
		if (w < HANDOFF_MAX)
			w = HANDOFF_MAX;
		if (w > CAP)
			w = CAP;
		S = s + (w & 0xff);
	}
	return w;
}

/* Candidate: clamp arms decided by cross-multiply, divide only mid-arm. */
static uint64_t slice_new(uint64_t s, uint64_t n)
{
	uint64_t S = s, w = 0;
	for (uint64_t i = 0; i < ITERS; i++) {
		uint64_t nn = n | 1;
		uint64_t s2 = S << 1;

		if (s2 < HANDOFF_MAX * nn)
			w = HANDOFF_MAX;
		else if (s2 > CAP * nn)
			w = CAP;
		else
			w = (S / nn) << 1;
		S = s + (w & 0xff);
	}
	return w;
}

static __attribute__((noinline)) uint64_t callee(uint64_t a, uint64_t b,
						 uint64_t c, uint64_t d,
						 uint64_t e)
{
	return a + (b ^ (a >> 7)) + c + d + e;
}

static uint64_t chain_call(uint64_t s, uint64_t n)
{
	uint64_t acc = s;
	for (uint64_t i = 0; i < ITERS; i++)
		acc = callee(acc, n, 1, 2, 3);
	return acc;
}

static void run(const char *name, uint64_t (*fn)(uint64_t, uint64_t),
		uint64_t s, uint64_t n)
{
	double best = 1e18;
	for (int r = 0; r < REPS; r++) {
		uint64_t t0 = now_ns();
		sink = fn(s, n);
		uint64_t t1 = now_ns();
		double per = (double)(t1 - t0) / (double)ITERS;
		if (per < best)
			best = per;
	}
	printf("%-28s %7.3f ns/op\n", name, best);
}

int main(void)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(2, &set);
	sched_setaffinity(0, sizeof(set), &set);

	printf("arith_price: DIAGNOSTIC, non-ingesting; %llu iters, best of %d\n",
	       ITERS, REPS);
	run("add (baseline)", chain_add, 400000000ull, 3000);
	run("imul", chain_imul, 400000000ull, 3000);
	run("div small (S~4e8,n~3e3)", chain_div, 400000000ull, 3000);
	run("div wide  (S~2e12,n~8e5)", chain_div, 2000000000000ull, 800000);
	run("call noinline(5 args)", chain_call, 400000000ull, 3000);
	/* Arm profiles: floor (2S<<1 under 1464*n), mid, cap. */
	run("slice_old floor-arm", slice_old, 500000ull, 1000);	  /* burst 500ns */
	run("slice_new floor-arm", slice_new, 500000ull, 1000);
	run("slice_old mid-arm", slice_old, 100000000ull, 1000);  /* burst 100us */
	run("slice_new mid-arm", slice_new, 100000000ull, 1000);
	run("slice_old cap-arm", slice_old, 4000000000ull, 1000); /* burst 4ms */
	run("slice_new cap-arm", slice_new, 4000000000ull, 1000);
	return 0;
}
