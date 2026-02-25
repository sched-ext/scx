/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

/*
 * Priority Queue Throughput Benchmark
 *
 * Measures concurrent insert/pop throughput for:
 *   - RPQ with c*p queues (MultiQueue, scalable)
 *   - RPQ with 1 queue (single-lock baseline)
 *
 * The single-queue RPQ is effectively a single-lock priority queue:
 * all threads contend on one heap and one lock. Comparing it with
 * the multi-queue RPQ directly shows the MultiQueue scalability
 * benefit.
 *
 * Each benchmark thread calls a SEC("syscall") program via
 * bpf_prog_test_run(). The hot loop runs entirely in BPF with
 * bpf_ktime_get_ns() timing, eliminating userspace jitter.
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>
#include <lib/rpq.h>

/* --- Global shared benchmark state (initialized once) --- */

static rpq_t *bench_rpq_multi;		/* Multi-queue RPQ (scalable) */
static rpq_t *bench_rpq_single;	/* Single-queue RPQ (baseline) */

/* --- Argument structs for SEC("syscall") programs --- */

struct bench_init_args {
	u64 rpq_nr_queues;
	u64 rpq_per_queue_cap;
	u64 prepopulate_count;
};

struct bench_run_args {
	u64 nr_ops;		/* input: operations per thread */
	u64 elapsed_ns;		/* output: wall time in ns */
	u64 inserts_ok;		/* output */
	u64 inserts_fail;	/* output */
	u64 pops_ok;		/* output */
	u64 pops_fail;		/* output */
};

/*
 * Initialize benchmark data structures.
 *
 * Creates two RPQs:
 *   - Multi-queue with the specified nr_queues (for scalability)
 *   - Single-queue (1 heap, 1 lock) as a contention baseline
 *
 * Pre-populates both with random elements for steady-state.
 */
SEC("syscall")
int bench_init(struct bench_init_args *args)
{
	u64 key;
	int ret, i;

	/* Create multi-queue RPQ */
	bench_rpq_multi = rpq_create(args->rpq_nr_queues,
				     args->rpq_per_queue_cap);
	if (!bench_rpq_multi)
		return -ENOMEM;

	/* Create single-queue RPQ (baseline) */
	bench_rpq_single = rpq_create(1, args->rpq_per_queue_cap);
	if (!bench_rpq_single)
		return -ENOMEM;

	/* Pre-populate both with random elements */
	bpf_for(i, 0, args->prepopulate_count) {
		key = bpf_get_prandom_u32();

		ret = rpq_insert(bench_rpq_multi, key, key);
		if (ret && ret != -ENOSPC)
			return ret;

		/*
		 * The single-queue RPQ may fill up before the multi-queue
		 * one since all elements go to the same heap. Ignore ENOSPC.
		 */
		ret = rpq_insert(bench_rpq_single, key, key);
		if (ret && ret != -ENOSPC)
			return ret;
	}

	return 0;
}

/*
 * Multi-queue RPQ throughput benchmark.
 *
 * Runs nr_ops iterations of 50/50 insert/pop on the multi-queue RPQ.
 * Even iterations insert (random key), odd iterations pop.
 * Timed with bpf_ktime_get_ns() for precise in-kernel measurement.
 */
SEC("syscall")
int bench_run_rpq(struct bench_run_args *args)
{
	u64 nr_ops = args->nr_ops;
	u64 inserts_ok = 0, inserts_fail = 0;
	u64 pops_ok = 0, pops_fail = 0;
	u64 start, end;
	u64 elem, key;
	int ret, i;

	if (!bench_rpq_multi)
		return -EINVAL;

	start = bpf_ktime_get_ns();

	bpf_for(i, 0, nr_ops) {
		if (i & 1) {
			ret = rpq_pop(bench_rpq_multi, &elem, &key);
			if (ret == 0)
				pops_ok++;
			else
				pops_fail++;
		} else {
			key = bpf_get_prandom_u32();
			ret = rpq_insert(bench_rpq_multi, key, key);
			if (ret == 0)
				inserts_ok++;
			else
				inserts_fail++;
		}
	}

	end = bpf_ktime_get_ns();

	args->elapsed_ns = end - start;
	args->inserts_ok = inserts_ok;
	args->inserts_fail = inserts_fail;
	args->pops_ok = pops_ok;
	args->pops_fail = pops_fail;

	return 0;
}

/*
 * Single-queue RPQ throughput benchmark (baseline).
 *
 * Same workload as bench_run_rpq but on an RPQ with nr_queues=1,
 * which is effectively a single-lock priority queue. All threads
 * contend on the same heap and lock, showing worst-case contention.
 *
 * Comparing this with the multi-queue RPQ directly demonstrates
 * the MultiQueue scalability advantage.
 */
SEC("syscall")
int bench_run_single(struct bench_run_args *args)
{
	u64 nr_ops = args->nr_ops;
	u64 inserts_ok = 0, inserts_fail = 0;
	u64 pops_ok = 0, pops_fail = 0;
	u64 start, end;
	u64 elem, key;
	int ret, i;

	if (!bench_rpq_single)
		return -EINVAL;

	start = bpf_ktime_get_ns();

	bpf_for(i, 0, nr_ops) {
		if (i & 1) {
			ret = rpq_pop(bench_rpq_single, &elem, &key);
			if (ret == 0)
				pops_ok++;
			else
				pops_fail++;
		} else {
			key = bpf_get_prandom_u32();
			ret = rpq_insert(bench_rpq_single, key, key);
			if (ret == 0)
				inserts_ok++;
			else
				inserts_fail++;
		}
	}

	end = bpf_ktime_get_ns();

	args->elapsed_ns = end - start;
	args->inserts_ok = inserts_ok;
	args->inserts_fail = inserts_fail;
	args->pops_ok = pops_ok;
	args->pops_fail = pops_fail;

	return 0;
}
