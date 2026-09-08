/*
 * storage_price — DIAGNOSTIC, NON-INGESTING. Prices the question "should cake
 * cache a derived per-task value instead of recomputing it", on this silicon.
 *
 * Not a benchmark arm. Records no noise fields. Reader-side wallclock only.
 *
 *   cc -O2 -o .scx_cake_bench/storage_price \
 *      scheds/rust/scx_cake/bench/storage_price.c
 *   taskset -c 2 nice -n 19 .scx_cake_bench/storage_price
 *
 * THE QUESTION
 *   cake_burst_ns() is sum_exec_runtime / (nvcsw | 1). cake computes it TWICE
 *   per wake from identical inputs: cake_task_slice (cake.bpf.c:914) and
 *   cake_cadence_depth (:977). Three ways to remove the second divide:
 *     1. keep recomputing            (today)
 *     2. BPF task storage            (cosmos / pandemonium's answer)
 *     3. per-CPU tagged slot cache   (cake's own §G46 answer)
 *   Whichever costs less than one divide wins; anything costing more is a
 *   regression dressed as a cache.
 *
 * WHAT IS MODELLED
 *   The kernel's task-storage read chain, from the running kernel's own header
 *   (include/linux/bpf_local_storage.h, bpf_local_storage_lookup fast path):
 *
 *     task->bpf_storage -> local_storage->cache[smap->cache_idx]
 *                       -> sdata->smap == smap ? sdata->data : slow path
 *
 *   Three DEPENDENT loads across THREE separate allocations. The kernel marks
 *   sdata ____cacheline_aligned specifically so the value sits on its own line,
 *   so a hit touches 3 lines: task_struct, local_storage, sdata. Allocation
 *   sizes and the 16-entry cache array are mirrored from that header.
 *
 *   NOT modelled: the BPF helper-call boundary into the kernel (task storage
 *   has no map_gen_lookup, so unlike array maps the verifier does not inline
 *   it). This userspace walk does not measure the helper, its slow path,
 *   kernel allocation placement, or actual callback cache residency.
 *
 * WHY A WORKING-SET SWEEP
 *   cake's read hits a task_struct line the scheduler core just wrote in
 *   update_curr. The storage allocations are touched by nothing else on the
 *   path, so their residency depends on how recently this task ran HERE. The
 *   answer is expected to change between L2-resident and DRAM, so all three
 *   residencies are measured rather than one being assumed representative.
 *
 * THE TRAP THIS WALK AVOIDS
 *   A successor chosen as next[f(node)] is a FIXED function of the node, so the
 *   walk is a functional graph and falls into a cycle of expected length
 *   sqrt(N). Choosing by the parity of a running accumulator does not help:
 *   the state is then (node, parity), still a finite functional graph, and the
 *   131072-task "DRAM" arm visited 148 tasks before repeating (review
 *   2026-09-06). Every "working set" measured L2 and the arms walked different
 *   cycles, so the BASE subtraction compared unlike paths.
 *   The successor table is therefore ONE random permutation cycle over all N
 *   tasks, verified by build(), so the walk covers the allocation and every
 *   arm walks the same path. Both successor entries hold the same value, and
 *   the entry is still indexed by the accumulator's parity, which keeps the
 *   loaded value (and the divide) inside the dependency chain.
 *
 *   SLOT models a cache honestly: a hit returns the tagged value, a miss pays
 *   the divide AND writes the slot back, as cake's slot would. STORAGE returns
 *   the value the divide would produce, so every arm computes the same thing.
 *
 * READING THE OUTPUT
 *   Deltas against BASE compare these dependent walks. They are not isolated
 *   instruction/helper latencies or a bound on in-kernel cost. Working-set
 *   labels describe sizes, not measured cache residency. Candidate values and
 *   full-cycle coverage are checked outside timing; SLOT hit/miss counts are
 *   reported for a complete cycle after warmup, including capacity misses.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define REPS		5
#define ITERS		8000000ull
#define CACHE_SIZE	16	/* BPF_LOCAL_STORAGE_CACHE_SIZE */
#define CACHE_IDX	3	/* this map's smap->cache_idx */
#define SLOT_BYTES	128	/* cake STATE_SLOT_BYTES */

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* bpf_local_storage_data: smap pointer plus the map value, on its own line. */
struct sdata {
	void	 *smap;
	uint64_t  data[7];
} __attribute__((aligned(64)));

/* bpf_local_storage: the 16-entry cache array dominates it. */
struct storage {
	struct sdata *cache[CACHE_SIZE];
	void	     *list;
	void	     *owner;
	uint64_t      rcu[2];
	uint64_t      lock;
	uint64_t      mem_charge;
	uint64_t      owner_refcnt;
};

/*
 * Stand-in for task_struct. Only the relative layout matters: the fields cake
 * reads sit together on a line core has already touched, and bpf_storage is a
 * pointer off the same object. Padded to 512 B because task_struct is ~10 KB,
 * so two tasks never share a line.
 */
struct task {
	uint64_t	sum_exec_runtime;
	uint64_t	nvcsw;
	struct storage *bpf_storage;
	uint32_t	next[2];
	uint64_t	pad[57];
} __attribute__((aligned(64)));

/* cake's §G46 shape: one padded per-CPU slot, pid<<32 | value. */
struct slot {
	uint64_t word;
	uint64_t pad[SLOT_BYTES / sizeof(uint64_t) - 1];
} __attribute__((aligned(SLOT_BYTES)));

static struct task  *tasks;
static struct slot  *slots;
static void	    *smap_id = &smap_id;
static uint32_t	     nr_tasks;
static uint32_t	     nr_slots;
static volatile uint64_t sink;

/*
 * BASE — reach the task and follow the chain. Every arm pays this, so it is
 * the subtraction baseline, not a candidate.
 */
static uint64_t arm_base(void)
{
	uint32_t idx = 0;
	uint64_t v = 0, acc = 0;

	for (uint64_t i = 0; i < ITERS; i++) {
		struct task *t = &tasks[idx];

		v = t->sum_exec_runtime;
		acc += v;
		idx = t->next[acc & 1];
	}
	return v + acc;
}

/* HOT — cake today: one divide off a line the task object already owns. */
static uint64_t arm_hot(void)
{
	uint32_t idx = 0;
	uint64_t v = 0, acc = 0;

	for (uint64_t i = 0; i < ITERS; i++) {
		struct task *t = &tasks[idx];

		v = t->sum_exec_runtime / (t->nvcsw | 1);
		acc += v;
		idx = t->next[acc & 1];
	}
	return v + acc;
}

/* STORAGE — the bpf_local_storage_lookup fast path, cache hit. */
static uint64_t arm_storage(void)
{
	uint32_t idx = 0;
	uint64_t v = 0, acc = 0;

	for (uint64_t i = 0; i < ITERS; i++) {
		struct task *t = &tasks[idx];
		struct storage *st = t->bpf_storage;
		struct sdata *sd = st->cache[CACHE_IDX];

		v = (sd && sd->smap == smap_id) ? sd->data[0] : 0;
		acc += v;
		idx = t->next[acc & 1];
	}
	return v + acc;
}

/* SLOT — cake's §G46 shape: one tagged load from a per-CPU slot. */
static inline uint64_t slot_value(uint32_t idx)
{
	struct task *t = &tasks[idx];
	struct slot *sl = &slots[idx & (nr_slots - 1)];
	uint64_t e = sl->word;

	if ((uint32_t)(e >> 32) == idx)
		return (uint32_t)e;
	uint64_t v = t->sum_exec_runtime / (t->nvcsw | 1);

	sl->word = ((uint64_t)idx << 32) | (uint32_t)v;
	return v;
}

static uint64_t arm_slot(void)
{
	uint32_t idx = 0;
	uint64_t v = 0, acc = 0;

	for (uint64_t i = 0; i < ITERS; i++) {
		struct task *t = &tasks[idx];

		v = slot_value(idx);
		acc += v;
		idx = t->next[acc & 1];
	}
	return v + acc;
}

static double run(uint64_t (*fn)(void))
{
	double best = 1e18;

	for (int r = 0; r < REPS; r++) {
		uint64_t t0 = now_ns();

		sink = fn();

		uint64_t t1 = now_ns();
		double per = (double)(t1 - t0) / (double)ITERS;

		if (per < best)
			best = per;
	}
	return best;
}

/*
 * Build one working set. Each storage object and each sdata is a SEPARATE
 * allocation, so they land wherever the allocator puts them rather than in one
 * stride the prefetcher can learn -- the same relationship slab gives the real
 * ones. The successor table is shuffled for the same reason.
 */
static void build(uint32_t n)
{
	for (uint32_t i = 0; i < nr_tasks; i++) {
		free(tasks[i].bpf_storage->cache[CACHE_IDX]);
		free(tasks[i].bpf_storage);
	}
	nr_tasks = n;
	nr_slots = 64;
	while (nr_slots < n && nr_slots < 4096)
		nr_slots <<= 1;

	free(tasks);
	free(slots);
	tasks = aligned_alloc(64, (size_t)n * sizeof(*tasks));
	slots = aligned_alloc(SLOT_BYTES, (size_t)nr_slots * sizeof(*slots));
	if (!tasks || !slots) {
		fprintf(stderr, "storage_price: allocation failed at n=%u\n", n);
		exit(1);
	}
	memset(tasks, 0, (size_t)n * sizeof(*tasks));
	memset(slots, 0, (size_t)nr_slots * sizeof(*slots));

	for (uint32_t i = 0; i < n; i++) {
		/* C aligned_alloc requires size to be a multiple of alignment. */
		struct storage *st = aligned_alloc(64, (sizeof(*st) + 63) & ~(size_t)63);
		struct sdata *sd = aligned_alloc(64, sizeof(*sd));

		if (!st || !sd) {
			fprintf(stderr, "storage_price: alloc failed\n");
			exit(1);
		}
		memset(st, 0, sizeof(*st));
		memset(sd, 0, sizeof(*sd));

		/* Realistic magnitudes: ~100us mean burst over ~3e3 switches. */
		tasks[i].sum_exec_runtime = 300000000ull + i * 977ull;
		tasks[i].nvcsw = 3000 + (i & 511);

		sd->smap = smap_id;
		sd->data[0] = tasks[i].sum_exec_runtime / (tasks[i].nvcsw | 1);
		st->cache[CACHE_IDX] = sd;
		tasks[i].bpf_storage = st;

		/* Populate the bounded cache; collisions evict earlier tags. */
		slots[i & (nr_slots - 1)].word =
			((uint64_t)i << 32) | (uint32_t)sd->data[0];
	}

	/*
	 * One permutation cycle through every task (Fisher-Yates), so the walk
	 * covers the allocation and neither prefetcher nor branch predictor
	 * learns the stride. Both entries hold the successor; see the header.
	 */
	uint32_t *perm = malloc((size_t)n * sizeof(*perm));
	uint8_t *seen = calloc(n, 1);

	if (!perm || !seen) {
		fprintf(stderr, "storage_price: alloc failed\n");
		exit(1);
	}
	for (uint32_t i = 0; i < n; i++)
		perm[i] = i;
	for (uint32_t i = n - 1; i > 0; i--) {
		uint32_t j = (uint32_t)rand() % (i + 1);
		uint32_t t = perm[i];

		perm[i] = perm[j];
		perm[j] = t;
	}
	for (uint32_t k = 0; k < n; k++) {
		uint32_t succ = perm[(k + 1) % n];

		tasks[perm[k]].next[0] = succ;
		tasks[perm[k]].next[1] = succ;
	}

	/* Coverage check: n steps from task 0 visit every task exactly once. */
	uint32_t idx = 0, covered = 0;

	for (uint32_t k = 0; k < n; k++) {
		covered += !seen[idx];
		seen[idx] = 1;
		idx = tasks[idx].next[k & 1];
	}
	if (covered != n || idx != 0) {
		fprintf(stderr, "storage_price: walk covers %u of %u tasks\n",
			covered, n);
		exit(1);
	}
	free(perm);
	free(seen);
}

/* Use the timed SLOT lookup itself, checking both initial and steady cycles.
 * Each task's value must fit the proposed 32-bit cache payload exactly. */
static void validate_values(void)
{
	uint32_t idx = 0, hits = 0;
	uint64_t acc = 0;

	for (uint64_t k = 0; k < 2ull * nr_tasks; k++) {
		struct task *t = &tasks[idx];
		struct sdata *sd = t->bpf_storage->cache[CACHE_IDX];
		uint64_t expected = t->sum_exec_runtime / (t->nvcsw | 1);
		uint64_t cached = slots[idx & (nr_slots - 1)].word;

		if (k >= nr_tasks)
			hits += (uint32_t)(cached >> 32) == idx;
		if (expected > UINT32_MAX || !sd || sd->smap != smap_id ||
		    sd->data[0] != expected || slot_value(idx) != expected) {
			fprintf(stderr, "storage_price: value mismatch at task %u\n", idx);
			exit(1);
		}
		acc += expected;
		idx = t->next[acc & 1];
	}
	printf("    verified %u tasks; SLOT %u slots, steady-cycle hits %u, misses %u\n",
	       nr_tasks, nr_slots, hits, nr_tasks - hits);
}

static void sweep(const char *label, uint32_t n)
{
	double base, hot, storage, slot;
	double kib = (double)n * (sizeof(struct task) + sizeof(struct storage) +
				  sizeof(struct sdata)) / 1024.0;

	build(n);
	validate_values();

	base	= run(arm_base);
	hot	= run(arm_hot);
	storage	= run(arm_storage);
	slot	= run(arm_slot);

	printf("%-12s n=%-7u working set %8.0f KiB\n", label, n, kib);
	printf("    %-26s %7.3f ns/op\n", "BASE (reach task only)", base);
	printf("    %-26s %7.3f ns/op   delta %+7.3f\n",
	       "HOT    divide, today", hot, hot - base);
	printf("    %-26s %7.3f ns/op   delta %+7.3f\n",
	       "STORAGE task storage", storage, storage - base);
	printf("    %-26s %7.3f ns/op   delta %+7.3f\n",
	       "SLOT   per-CPU §G46", slot, slot - base);
	printf("\n");
}

int main(int argc, char **argv)
{
	cpu_set_t set;
	bool check_only = argc == 2 && !strcmp(argv[1], "--check");

	if (argc > 1 && !check_only) {
		fprintf(stderr, "usage: %s [--check]\n", argv[0]);
		return 2;
	}
	srand(1);
	if (check_only) {
		uint32_t sizes[] = {256, 8192, 131072};

		for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
			build(sizes[i]);
			validate_values();
		}
		return 0;
	}

	CPU_ZERO(&set);
	CPU_SET(2, &set);
	sched_setaffinity(0, sizeof(set), &set);

	printf("storage_price: DIAGNOSTIC, non-ingesting; %llu iters, best of %d\n",
	       ITERS, REPS);
	printf("deltas compare userspace walks; they do not measure BPF helper latency.\n\n");

	sweep("small", 256);
	sweep("medium", 8192);
	sweep("large", 131072);
	return 0;
}
