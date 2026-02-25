/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

/*
 * Priority Queue Throughput Benchmark
 *
 * Measures concurrent insert/pop throughput and per-op latency for:
 *   - RPQ with configurable (nr_queues, pick-d) parameters
 *   - ATQ (single-lock rbtree baseline)
 *
 * Multiple RPQ configurations can be initialized in parallel via
 * bench_id slots (up to BENCH_RPQ_SLOTS). Each benchmark thread
 * specifies which slot to use via bench_run_args.bench_id.
 *
 * All benchmarks use monotonically increasing vtimes with random
 * deltas, matching real scheduler workloads.
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>
#include <lib/rpq.h>
#include <lib/atq.h>

static __always_inline u64
bench_next_vtime(u64 *vtime)
{
	*vtime += (bpf_get_prandom_u32() & 1023) + 1;
	return *vtime;
}

/* --- Global shared benchmark state --- */

#define BENCH_RPQ_SLOTS 8

static rpq_t *bench_rpqs[BENCH_RPQ_SLOTS];
static scx_atq_t *bench_atq;

/* --- Argument structs for SEC("syscall") programs --- */

struct bench_init_args {
	u64 rpq_nr_queues;
	u64 rpq_per_queue_cap;
	u64 rpq_d;		/* pick-d choices for pop */
	u64 prepopulate_count;
	u64 bench_id;		/* slot index in bench_rpqs[] */
};

struct bench_run_args {
	u64 nr_ops;		/* input: operations per thread */
	u64 bench_id;		/* input: slot index */
	/* outputs: */
	u64 elapsed_ns;
	u64 inserts_ok;
	u64 inserts_fail;
	u64 pops_ok;
	u64 pops_fail;
	u64 max_insert_ns;	/* max single-insert latency */
	u64 max_pop_ns;		/* max single-pop latency */
};

/* --- ATQ __weak wrappers --- */

__weak
int bench_atq_do_insert(scx_atq_t __arg_arena *atq,
			scx_task_common __arg_arena *taskc, u64 vtime)
{
	return scx_atq_insert_vtime(atq, taskc, vtime);
}

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
 * Initialize an RPQ at the given bench_id slot.
 * Called once per configuration from userspace.
 */
SEC("syscall")
int bench_init(struct bench_init_args *args)
{
	u64 vtime = 0;
	u64 slot = args->bench_id;
	u32 d = args->rpq_d;
	int ret, i;

	if (slot >= BENCH_RPQ_SLOTS)
		return -EINVAL;

	bench_rpqs[slot] = rpq_create_d(args->rpq_nr_queues,
					args->rpq_per_queue_cap,
					d ? d : 2);
	if (!bench_rpqs[slot])
		return -ENOMEM;

	bpf_for(i, 0, args->prepopulate_count) {
		u64 key = bench_next_vtime(&vtime);

		ret = rpq_insert(bench_rpqs[slot], key, key);
		if (ret == -ENOSPC)
			continue;
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Initialize ATQ benchmark (separate to avoid verifier complexity).
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
 * RPQ throughput + latency benchmark.
 *
 * Reads bench_id from args to select which RPQ slot to use.
 * Tracks per-op max latency via bpf_ktime_get_ns().
 */
SEC("syscall")
int bench_run_rpq(struct bench_run_args *args)
{
	u64 nr_ops = args->nr_ops;
	u64 inserts_ok = 0, inserts_fail = 0;
	u64 pops_ok = 0, pops_fail = 0;
	u64 max_insert_ns = 0, max_pop_ns = 0;
	u64 vtime = 0;
	u64 start, end, t0, lat;
	u64 elem, key;
	rpq_t *pq;
	int ret, i;

	if (args->bench_id >= BENCH_RPQ_SLOTS)
		return -EINVAL;

	pq = bench_rpqs[args->bench_id];
	if (!pq)
		return -EINVAL;

	start = bpf_ktime_get_ns();

	bpf_for(i, 0, nr_ops) {
		if (i & 1) {
			t0 = bpf_ktime_get_ns();
			ret = rpq_pop(pq, &elem, &key);
			lat = bpf_ktime_get_ns() - t0;

			if (ret == 0)
				pops_ok++;
			else
				pops_fail++;

			if (lat > max_pop_ns)
				max_pop_ns = lat;
		} else {
			key = bench_next_vtime(&vtime);

			t0 = bpf_ktime_get_ns();
			ret = rpq_insert(pq, key, key);
			lat = bpf_ktime_get_ns() - t0;

			if (ret == 0)
				inserts_ok++;
			else
				inserts_fail++;

			if (lat > max_insert_ns)
				max_insert_ns = lat;
		}
	}

	end = bpf_ktime_get_ns();

	args->elapsed_ns = end - start;
	args->inserts_ok = inserts_ok;
	args->inserts_fail = inserts_fail;
	args->pops_ok = pops_ok;
	args->pops_fail = pops_fail;
	args->max_insert_ns = max_insert_ns;
	args->max_pop_ns = max_pop_ns;

	return 0;
}

/*
 * ATQ throughput + latency benchmark (single-lock rbtree baseline).
 */
SEC("syscall")
int bench_run_atq(struct bench_run_args *args)
{
	u64 nr_ops = args->nr_ops;
	u64 inserts_ok = 0, inserts_fail = 0;
	u64 pops_ok = 0, pops_fail = 0;
	u64 max_pop_insert_ns = 0;
	u64 vtime = 0;
	u64 start, end, t0, lat;
	int ret, i;

	if (!bench_atq)
		return -EINVAL;

	start = bpf_ktime_get_ns();

	bpf_for(i, 0, nr_ops / 2) {
		t0 = bpf_ktime_get_ns();
		ret = bench_atq_pop_insert(bench_atq,
					   bench_next_vtime(&vtime));
		lat = bpf_ktime_get_ns() - t0;

		if (ret == 0) {
			pops_ok++;
			inserts_ok++;
		} else if (ret == 1) {
			pops_fail++;
		} else {
			pops_ok++;
			inserts_fail++;
		}

		if (lat > max_pop_insert_ns)
			max_pop_insert_ns = lat;
	}

	end = bpf_ktime_get_ns();

	args->elapsed_ns = end - start;
	args->inserts_ok = inserts_ok;
	args->inserts_fail = inserts_fail;
	args->pops_ok = pops_ok;
	args->pops_fail = pops_fail;
	/* ATQ pop+insert is one combined op; report as both */
	args->max_insert_ns = max_pop_insert_ns;
	args->max_pop_ns = max_pop_insert_ns;

	return 0;
}
