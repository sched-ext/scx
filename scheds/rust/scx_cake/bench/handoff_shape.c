/* handoff_shape — mutex_handoff's distribution, plus the instrument's own cost.
 * DIAGNOSTIC ONLY. Not a scored binary; prints a histogram, not a score line. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define ITERS 400000
#define WARMUP 5000

static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t c = PTHREAD_COND_INITIALIZER;
static int turn;
static uint64_t t_signal_ns;
static uint64_t deltas[2][ITERS];

static inline uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void *worker(void *arg)
{
	int me = (int)(intptr_t)arg;
	uint64_t *out = deltas[me];
	pthread_mutex_lock(&m);
	for (int i = 0; i < ITERS + WARMUP; i++) {
		while (turn != me)
			pthread_cond_wait(&c, &m);
		uint64_t woke = now_ns();
		if (i >= WARMUP)
			out[i - WARMUP] = woke - t_signal_ns;
		t_signal_ns = now_ns();
		turn = 1 - me;
		pthread_cond_signal(&c);
	}
	pthread_mutex_unlock(&m);
	return NULL;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y;
}

int main(void)
{
	/* 1. instrument cost: the two now_ns() calls that DEFINE the interval */
	uint64_t s = now_ns();
	for (int i = 0; i < 1000000; i++) { uint64_t t = now_ns(); (void)t; }
	uint64_t e = now_ns();
	printf("clock_gettime(CLOCK_MONOTONIC) vDSO: %.1f ns/call -> %.1f ns per measured interval\n",
	       (double)(e - s) / 1e6, 2.0 * (double)(e - s) / 1e6);

	pthread_t t0, t1;
	pthread_create(&t0, NULL, worker, (void *)0);
	pthread_create(&t1, NULL, worker, (void *)(intptr_t)1);
	pthread_join(t0, NULL);
	pthread_join(t1, NULL);

	static uint64_t all[2 * ITERS];
	memcpy(all, deltas[0], sizeof(deltas[0]));
	memcpy(all + ITERS, deltas[1], sizeof(deltas[1]));
	size_t n = 2 * ITERS;
	qsort(all, n, sizeof(uint64_t), cmp_u64);
	printf("p50 %.3f  p90 %.3f  p95 %.3f  p99 %.3f  p999 %.3f us\n",
	       all[n/2]/1000.0, all[(size_t)(n*.90)]/1000.0, all[(size_t)(n*.95)]/1000.0,
	       all[(size_t)(n*.99)]/1000.0, all[(size_t)(n*.999)]/1000.0);

	/* histogram, 100 ns bins to 4 us -- does a SECOND MODE exist? */
	printf("\nhistogram (100ns bins, %% of samples):\n");
	size_t bins[41] = {0};
	for (size_t i = 0; i < n; i++) {
		size_t b = all[i] / 100;
		if (b > 40) b = 40;
		bins[b]++;
	}
	for (size_t b = 0; b < 41; b++) {
		if (!bins[b]) continue;
		double pct = 100.0 * bins[b] / n;
		printf("%5.1f-%5.1f us %7.3f%% %s\n", b/10.0, (b+1)/10.0, pct,
		       pct > 0.05 ? (char[81]){[0 ... 79] = '#', [80] = 0} + (80 - (int)(pct > 80 ? 80 : pct)) : "");
	}
	return 0;
}
