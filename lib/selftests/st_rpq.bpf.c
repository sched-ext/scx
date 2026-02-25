/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/rpq.h>

#include "selftest.h"

/*
 * NOTE: These selftests exercise the RPQ API in a single-threaded context.
 * They verify correctness of the heap operations and API contracts. The
 * concurrent scalability properties (lock contention, power-of-two-choices
 * quality) are not tested here.
 *
 * All helper functions use __arg_arena on the rpq_t parameter so the BPF
 * verifier accepts arena pointers passed from rpq_create().
 */

#define RPQ_TEST_NR_QUEUES	4
#define RPQ_TEST_CAPACITY	64

int scx_selftest_rpq_pop_empty(rpq_t __arg_arena *pq)
{
	u64 elem, key;
	int ret;

	ret = rpq_pop(pq, &elem, &key);
	if (ret != -ENOENT)
		return 1;

	return 0;
}

int scx_selftest_rpq_peek_empty(rpq_t __arg_arena *pq)
{
	u64 elem, key;
	int ret;

	ret = rpq_peek(pq, &elem, &key);
	if (ret != -ENOENT)
		return 1;

	return 0;
}

int scx_selftest_rpq_insert_pop_one(rpq_t __arg_arena *pq)
{
	u64 elem, key;
	int ret;

	ret = rpq_insert(pq, 42, 100);
	if (ret)
		return 1;

	ret = rpq_pop(pq, &elem, &key);
	if (ret)
		return 2;

	if (elem != 42)
		return 3;

	if (key != 100)
		return 4;

	/* Queue should be empty now */
	ret = rpq_pop(pq, &elem, &key);
	if (ret != -ENOENT)
		return 5;

	return 0;
}

int scx_selftest_rpq_ordering(rpq_t __arg_arena *pq)
{
	u64 elem, key;
	int ret, i;

	/*
	 * Insert elements with descending keys so the minimum (key=0)
	 * is inserted last. Due to random queue distribution, exact
	 * global ordering is not guaranteed, but each individual pop
	 * should return a valid element.
	 */
	for (i = 0; i < 16 && can_loop; i++) {
		ret = rpq_insert(pq, (u64)i, (u64)(15 - i));
		if (ret)
			return i + 1;
	}

	/* Pop all 16 elements and verify we get them all back. */
	for (i = 0; i < 16 && can_loop; i++) {
		ret = rpq_pop(pq, &elem, &key);
		if (ret)
			return 100 + i;
	}

	/* Should be empty */
	ret = rpq_pop(pq, &elem, &key);
	if (ret != -ENOENT)
		return 200;

	return 0;
}

int scx_selftest_rpq_size(rpq_t __arg_arena *pq)
{
	int ret, sz, i;

	sz = rpq_size(pq);
	if (sz != 0)
		return 1;

	for (i = 0; i < 10 && can_loop; i++) {
		ret = rpq_insert(pq, (u64)i, (u64)i);
		if (ret)
			return 10 + i;
	}

	sz = rpq_size(pq);
	if (sz != 10)
		return 2;

	return 0;
}

#define SCX_RPQ_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_rpq_ ## suffix, pq)

__weak
int scx_selftest_rpq(void)
{
	rpq_t *pq = rpq_create(RPQ_TEST_NR_QUEUES, RPQ_TEST_CAPACITY);

	if (!pq)
		return 1;

	SCX_RPQ_SELFTEST(pop_empty);
	SCX_RPQ_SELFTEST(peek_empty);
	SCX_RPQ_SELFTEST(insert_pop_one);

	/*
	 * Create a fresh RPQ for the ordering test since the
	 * previous tests may have left elements behind (the size
	 * test intentionally does).
	 */
	pq = rpq_create(RPQ_TEST_NR_QUEUES, RPQ_TEST_CAPACITY);
	if (!pq)
		return 2;

	SCX_RPQ_SELFTEST(ordering);

	pq = rpq_create(RPQ_TEST_NR_QUEUES, RPQ_TEST_CAPACITY);
	if (!pq)
		return 3;

	SCX_RPQ_SELFTEST(size);

	return 0;
}
