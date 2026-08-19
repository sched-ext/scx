/*
 * qmark_price — DIAGNOSTIC, NON-INGESTING. Prices the G25 steal-ring question on
 * this silicon: what does cake_ring_steal's miss walk actually cost, and what
 * would a single summary word cost instead?
 *
 * Not a benchmark arm. Records no noise fields. Reader-side wallclock only.
 *
 *   cc -O2 -pthread -o /tmp/qmark_price qmark_price.c \
 *      && taskset -c 0-15 nice -n 19 /tmp/qmark_price
 *
 * WHAT IS MODELLED (mirrored from cake.bpf.c as of b607264ad):
 *   cake.qmark[] is struct cake_slot, one per CPU, STATE_SLOT_BYTES = 128 B
 *   apart (cake.bpf.c:246, _Static_assert :241). cake_ring_steal (:1047) walks
 *   up to nr-1 of them testing cake_qmark_test (:287) and exits on the first
 *   hit. The 93-98% case is the FULL MISS WALK: every slot reads zero.
 *
 *   WALK15  — the current design: 15 independent 128 B-strided loads, early
 *             exit on the first nonzero. Loads are independent, so the core's
 *             memory-level parallelism may overlap them; that is exactly the
 *             thing worth measuring rather than assuming.
 *   BITMAP1 — the G25 candidate: ONE u64, mask off self, ffs. One line.
 *
 * WHY THREE WRITER MODES: the walk's cost is coherence, not instruction count.
 * A line nobody dirties stays shared-clean in the reader's L1 and the walk is
 * nearly free; a line an owner keeps invalidating costs a remote fetch every
 * time. qmark uses test-before-store (cake_qmark_set, :273) so real transition
 * rate is UNKNOWN — priced here at three rates so the answer brackets it.
 *
 *   quiet  — no writer. Best case for WALK15, and the honest one if qmark
 *            transitions are as rare as test-before-store implies.
 *   slow   — each owner flips its own slot every ~10 us.
 *   fast   — each owner flips its own slot continuously.
 *
 * The BITMAP1 writers use __atomic_fetch_or / _and on ONE shared word, which is
 * the contention this design trades INTO. That cost must appear in its column
 * or the comparison is rigged.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SLOT_BYTES 128		/* STATE_SLOT_BYTES — cache-isolation stride */
#define NR_CPU	   16		/* nr_cpu_span on this 9800X3D */
#define WALK	   (NR_CPU - 1)	/* cake_ring_steal walks the other 15 */
#define ITERS	   2000000ull
#define REPS	   5

struct slot {
	volatile uint64_t word;
	char pad[SLOT_BYTES - sizeof(uint64_t)];
} __attribute__((aligned(SLOT_BYTES)));

static struct slot qmark[NR_CPU];
static _Atomic uint64_t bitmap __attribute__((aligned(SLOT_BYTES)));
static volatile int writers_go;
static volatile uint64_t sink;

enum wmode { W_QUIET, W_SLOW, W_FAST };
static enum wmode wmode;
static int write_bitmap;	/* writers hit the bitmap instead of qmark[] */
static int dirty_only;		/* writers invalidate the line, leave .word 0 */

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}

/* Owner of slot `id` flips its own line, exactly as cake_qmark_set/_clear do. */
static void *writer(void *arg)
{
	long id = (long)arg;
	uint64_t bit = 1ull << id;
	int on = 0;

	pin((int)id);
	while (writers_go) {
		on = !on;
		if (write_bitmap) {
			if (on)
				atomic_fetch_or(&bitmap, bit);
			else
				atomic_fetch_and(&bitmap, ~bit);
		} else if (dirty_only) {
			/*
			 * Invalidate the owner's line WITHOUT setting the bit
			 * the reader tests. This is the honest miss-walk-under-
			 * invalidation case: the walk still runs its full 15
			 * because every word reads zero, but each line must be
			 * re-fetched. Writing .word instead would let the reader
			 * exit early and silently measure a HIT walk.
			 */
			qmark[id].pad[0] = (char)on;
		} else {
			/* test-before-store, mirrored from cake_qmark_set */
			if (on) {
				if (!qmark[id].word)
					qmark[id].word = 1;
			} else {
				if (qmark[id].word)
					qmark[id].word = 0;
			}
		}
		if (wmode == W_SLOW) {
			struct timespec t = { 0, 10000 };	/* ~10 us */

			nanosleep(&t, NULL);
		}
	}
	return NULL;
}

/* Current design: walk the other 15 slots, exit on first hit. */
static uint64_t walk15(uint32_t self)
{
	uint64_t hits = 0;

	for (uint64_t n = 0; n < ITERS; n++) {
		for (uint32_t i = 0; i < WALK; i++) {
			uint32_t idx = (self + 1 + i) & (NR_CPU - 1);

			if (qmark[idx].word) {
				hits++;
				break;
			}
		}
	}
	return hits;
}

/*
 * The shape G25 shipped BEFORE the snapshot fix: one word, but reloaded on
 * every ring step because the mark test was inlined inside the loop. Prices
 * what 15 coherence misses SERIALISED ON ONE LINE cost, versus WALK15's 15
 * misses spread over 15 lines. Without this arm the "fast" row flatters the
 * bitmap by comparing a 1-load arm to a 15-load arm.
 */
static uint64_t bitmapN(uint32_t self)
{
	uint64_t hits = 0;
	uint64_t mine = 1ull << self;

	for (uint64_t n = 0; n < ITERS; n++) {
		for (uint32_t i = 1; i < NR_CPU; i++) {
			uint32_t idx = (self + i) & (NR_CPU - 1);
			uint64_t w = atomic_load_explicit(&bitmap,
							  memory_order_relaxed);

			if (w & ~mine & (1ull << idx)) {
				hits++;
				break;
			}
		}
	}
	return hits;
}

/* G25 candidate: one word, mask off self, ffs. */
static uint64_t bitmap1(uint32_t self)
{
	uint64_t hits = 0;
	uint64_t mine = 1ull << self;

	for (uint64_t n = 0; n < ITERS; n++) {
		uint64_t w = atomic_load_explicit(&bitmap, memory_order_relaxed);

		w &= ~mine;
		if (w) {
			sink = (uint64_t)__builtin_ctzll(w);
			hits++;
		}
	}
	return hits;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

/* Median ns per operation over REPS. */
static double price(uint64_t (*fn)(uint32_t), uint32_t self)
{
	uint64_t r[REPS];

	for (int i = 0; i < REPS; i++) {
		uint64_t t0 = now_ns();

		sink += fn(self);
		r[i] = now_ns() - t0;
	}
	qsort(r, REPS, sizeof(r[0]), cmp_u64);
	return (double)r[REPS / 2] / (double)ITERS;
}

static void run(const char *label, enum wmode m, int bmap_writers,
		double *out_walk, double *out_bmapn, double *out_bmap)
{
	pthread_t th[NR_CPU];
	long started = 0;

	memset((void *)qmark, 0, sizeof(qmark));
	atomic_store(&bitmap, 0);
	wmode = m;

	if (m != W_QUIET) {
		writers_go = 1;
		write_bitmap = bmap_writers;
		/*
		 * When the reader is WALK15, owners must invalidate their line
		 * WITHOUT setting the tested bit, or the walk exits early and
		 * measures a hit instead of the 93-98% miss case.
		 */
		dirty_only = !bmap_writers;
		for (long i = 1; i < NR_CPU; i++)
			if (pthread_create(&th[i], NULL, writer, (void *)i) == 0)
				started++;
		usleep(50000);	/* let writers reach steady state */
	}

	pin(0);
	if (bmap_writers) {
		*out_bmapn = price(bitmapN, 0);
		*out_bmap = price(bitmap1, 0);
	} else {
		*out_walk = price(walk15, 0);
	}

	if (m != W_QUIET) {
		writers_go = 0;
		for (long i = 1; i <= started; i++)
			pthread_join(th[i], NULL);
	}
	(void)label;
}

#define MAX_ROUNDS 32

static int cmp_dbl(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

static double median_d(const double *v, int n)
{
	double t[MAX_ROUNDS];

	memcpy(t, v, (size_t)n * sizeof(t[0]));
	qsort(t, (size_t)n, sizeof(t[0]), cmp_dbl);
	return n & 1 ? t[n / 2] : 0.5 * (t[n / 2 - 1] + t[n / 2]);
}

/*
 * Rounds alternate arm ORDER (AB, BA, AB, BA …) so each arm holds first
 * position equally often. A fixed A-then-B order lets thermal drift, writer
 * warm-up, or cache state ride on slot position instead of on the arm — the
 * order artifact this project already paid for once on game A/Bs.
 */
int main(int argc, char **argv)
{
	static const char *const MODE[3] = { "quiet", "slow", "fast" };
	static const enum wmode WM[3] = { W_QUIET, W_SLOW, W_FAST };
	double w[3][MAX_ROUNDS], n[3][MAX_ROUNDS], b[3][MAX_ROUNDS], ign;
	int rounds = argc > 1 ? atoi(argv[1]) : 6;

	if (rounds < 1 || rounds > MAX_ROUNDS)
		rounds = 6;

	printf("qmark_price — reader-side ns per dispatch decision\n");
	printf("  WALK15  = %d slots @ %d B stride, full miss walk (current)\n",
	       WALK, SLOT_BYTES);
	printf("  BITMAP1 = 1 u64, mask self, ffs (G25 candidate)\n");
	printf("  %llu iters, median of %d reps, reader pinned to CPU 0\n",
	       (unsigned long long)ITERS, REPS);
	printf("  %d rounds, arm order alternated AB/BA per round\n\n", rounds);

	for (int r = 0; r < rounds; r++) {
		int bfirst = r & 1;

		for (int m = 0; m < 3; m++) {
			if (bfirst) {
				run(MODE[m], WM[m], 1, &ign, &n[m][r], &b[m][r]);
				run(MODE[m], WM[m], 0, &w[m][r], &ign, &ign);
			} else {
				run(MODE[m], WM[m], 0, &w[m][r], &ign, &ign);
				run(MODE[m], WM[m], 1, &ign, &n[m][r], &b[m][r]);
			}
		}
		printf("round %d (%s first): ", r + 1, bfirst ? "BITMAP" : "WALK15");
		for (int m = 0; m < 3; m++)
			printf("%s %.2f/%.2f/%.2f  ", MODE[m], w[m][r],
			       n[m][r], b[m][r]);
		printf("\n");
	}

	printf("\n%-8s %11s %11s %11s %11s %11s\n", "writers",
	       "WALK15", "BITMAP-N", "BITMAP-1", "N vs WALK", "1 vs WALK");
	for (int m = 0; m < 3; m++) {
		double wm = median_d(w[m], rounds), bm = median_d(b[m], rounds);
		double nm = median_d(n[m], rounds);
		double wlo = w[m][0], whi = w[m][0], bhi = b[m][0];

		for (int r = 1; r < rounds; r++) {
			if (w[m][r] < wlo)
				wlo = w[m][r];
			if (w[m][r] > whi)
				whi = w[m][r];
			if (b[m][r] > bhi)
				bhi = b[m][r];
		}
		(void)wlo; (void)whi; (void)bhi;
		printf("%-8s %11.2f %11.2f %11.2f %10.2f%% %10.2f%%\n",
		       MODE[m], wm, nm, bm,
		       100.0 * (nm - wm) / wm, 100.0 * (bm - wm) / wm);
	}
	printf("\nNegative delta = BITMAP1 is faster. Medians across rounds.\n");
	return 0;
}
