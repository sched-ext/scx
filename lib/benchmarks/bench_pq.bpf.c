/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

/*
 * Priority Queue Throughput Benchmark
 *
 * Measures concurrent insert/pop throughput for:
 *   - RPQ with c*p queues (MultiQueue, scalable)
 *   - RPQ with 1 queue (single-lock heap baseline)
 *   - ATQ (single-lock rbtree baseline)
 *
 * Each benchmark thread calls a SEC("syscall") program via
 * bpf_prog_test_run(). The hot loop runs entirely in BPF with
 * bpf_ktime_get_ns() timing, eliminating userspace jitter.
 *
 * All benchmarks use monotonically increasing vtimes with random
 * deltas (vtime += random_delta), matching real scheduler workloads
 * where each task's vtime advances by its consumed CPU time.
 *
 * ATQ operations use __weak wrappers because the ATQ API functions
 * (scx_atq_pop, scx_atq_insert_vtime) are __hidden and call __weak
 * rbtree functions under the arena spinlock. The BPF verifier
 * forbids calling __weak globals from preempt-disabled context in
 * SEC("syscall") programs, but __weak wrappers are verified
 * independently with different rules. The wrappers also prevent
 * the verifier from hitting jump complexity limits when the __hidden
 * ATQ functions are inlined into loops.
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>
#include <lib/rpq.h>
#include <lib/atq.h>

/*
 * Generate monotonically increasing vtime with random delta.
 * Each call advances *vtime by a random amount in [1, 1024),
 * simulating variable CPU time consumption between enqueues.
 */
static __always_inline u64
bench_next_vtime(u64 *vtime)
{
	*vtime += (bpf_get_prandom_u32() & 1023) + 1;
	return *vtime;
}

/* --- Global shared benchmark state (initialized once) --- */

static rpq_t *bench_rpq_multi;		/* Multi-queue RPQ (scalable) */
static rpq_t *bench_rpq_single;	/* Single-queue RPQ (baseline) */
static scx_atq_t *bench_atq;		/* ATQ (single-lock rbtree) */

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
 * ATQ __weak wrappers.
 *
 * Each wrapper is a single ATQ operation verified independently
 * by the BPF verifier. This prevents the __hidden ATQ functions
 * from being inlined into loops (which would blow the verifier's
 * jump complexity limit).
 */

__weak
int bench_atq_do_insert(scx_atq_t __arg_arena *atq,
			scx_task_common __arg_arena *taskc, u64 vtime)
{
	return scx_atq_insert_vtime(atq, taskc, vtime);
}

/*
 * Combined pop+insert for ATQ. Pops one element and re-inserts
 * it with a new monotonically increasing vtime. Each call = 2
 * operations.
 *
 * Returns 0 on success (both pop and insert succeeded),
 * 1 if pop failed (queue empty), negative errno on insert error.
 */
__weak
int bench_atq_pop_insert(scx_atq_t __arg_arena *atq, u64 vtime)
{
	scx_task_common *taskc;
	u64 ptr;

	ptr = scx_atq_pop(atq);
	if (!ptr)
		return 1;

	taskc = (scx_task_common *)ptr;

	return scx_atq_insert_vtime(atq, taskc, vtime);
}

/*
 * Initialize RPQ benchmark data structures.
 */
SEC("syscall")
int bench_init(struct bench_init_args *args)
{
	u64 vtime = 0;
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

	/* Pre-populate RPQs with monotonically increasing vtimes */
	bpf_for(i, 0, args->prepopulate_count) {
		u64 key = bench_next_vtime(&vtime);

		ret = rpq_insert(bench_rpq_multi, key, key);
		if (ret && ret != -ENOSPC)
			return ret;

		ret = rpq_insert(bench_rpq_single, key, key);
		if (ret && ret != -ENOSPC)
			return ret;
	}

	return 0;
}

/*
 * Initialize ATQ benchmark data structure.
 *
 * Separate SEC("syscall") from bench_init to stay within the BPF
 * verifier's jump complexity budget. Uses the __weak
 * bench_atq_do_insert wrapper so the inlined __hidden ATQ code
 * doesn't compound with the loop's branch count.
 */
SEC("syscall")
int bench_init_atq(struct bench_init_args *args)
{
	volatile scx_task_common *taskc;
	u64 vtime = 0;
	int ret, i;

	bench_atq = (scx_atq_t *)scx_atq_create(false);
	if (!bench_atq)
		return -ENOMEM;

	bpf_for(i, 0, args->prepopulate_count) {
		taskc = scx_static_alloc(sizeof(*taskc), 8);
		if (!taskc)
			return -ENOMEM;

		taskc->atq = NULL;
		taskc->state = SCX_TSK_CANRUN;

		ret = bench_atq_do_insert(bench_atq,
					  (scx_task_common *)taskc,
					  bench_next_vtime(&vtime));
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Multi-queue RPQ throughput benchmark.
 */
SEC("syscall")
int bench_run_rpq(struct bench_run_args *args)
{
	u64 nr_ops = args->nr_ops;
	u64 inserts_ok = 0, inserts_fail = 0;
	u64 pops_ok = 0, pops_fail = 0;
	u64 vtime = 0;
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
			key = bench_next_vtime(&vtime);
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
 * Single-queue RPQ throughput benchmark (single-lock heap baseline).
 */
SEC("syscall")
int bench_run_single(struct bench_run_args *args)
{
	u64 nr_ops = args->nr_ops;
	u64 inserts_ok = 0, inserts_fail = 0;
	u64 pops_ok = 0, pops_fail = 0;
	u64 vtime = 0;
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
			key = bench_next_vtime(&vtime);
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

/*
 * ATQ throughput benchmark (single-lock rbtree baseline).
 *
 * Each iteration does a pop+insert cycle (2 operations) via the
 * __weak bench_atq_pop_insert wrapper, using monotonically
 * increasing vtimes. The nr_ops is halved so total operation
 * count matches the RPQ benchmarks.
 */
SEC("syscall")
int bench_run_atq(struct bench_run_args *args)
{
	u64 nr_ops = args->nr_ops;
	u64 inserts_ok = 0, inserts_fail = 0;
	u64 pops_ok = 0, pops_fail = 0;
	u64 vtime = 0;
	u64 start, end;
	int ret, i;

	if (!bench_atq)
		return -EINVAL;

	/*
	 * Each bench_atq_pop_insert call does 1 pop + 1 insert.
	 * Run nr_ops/2 iterations so the total operation count
	 * (pops + inserts) equals nr_ops.
	 */
	start = bpf_ktime_get_ns();

	bpf_for(i, 0, nr_ops / 2) {
		ret = bench_atq_pop_insert(bench_atq,
					   bench_next_vtime(&vtime));
		if (ret == 0) {
			pops_ok++;
			inserts_ok++;
		} else if (ret == 1) {
			/* Pop failed (empty queue) */
			pops_fail++;
		} else {
			/* Insert failed */
			pops_ok++;
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
