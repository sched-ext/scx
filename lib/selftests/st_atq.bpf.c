/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/atq.h>

#include "selftest.h"

struct scx_stk stack;

#define NATQS 16
scx_atq_t *prios[NATQS];
scx_atq_t *fifos[NATQS];

scx_atq_t *prio;
scx_atq_t *fifo;

#define NTASKS 64
struct task_ctx_nonarena {
	u64 pid;
	u64 vtime;
};

typedef struct task_ctx_nonarena __arena task_ctx;

task_ctx *tasks[NTASKS];

__weak
int scx_selftest_atq_create(u64 unused)
{
	int i;

	for (i = 0; i < NATQS && can_loop; i++) {
		prios[i] = (scx_atq_t *)scx_atq_create(false);
		if (!prios[i])
			return -ENOMEM;
	}

	prio = prios[0];

	for (i = 0; i < NATQS && can_loop; i++) {
		fifos[i] = (scx_atq_t *)scx_atq_create(true);
		if (!fifos[i])
			return -ENOMEM;
	}

	fifo = fifos[0];

	return 0;
}

static inline
int scx_selftest_atq_common(bool isfifo)
{
#define NTASKS_IN_QUEUE (32)
	u64 pids[NTASKS_IN_QUEUE];
	scx_atq_t *atq;
	const unsigned int step = 13;
	unsigned int ind;
	task_ctx *taskc;
	int ret, i;
	u64 vtime;

	atq = isfifo ? fifo : prio;

	for (i = 0, ind = 0; i < NTASKS_IN_QUEUE && can_loop; i++ ) {
		tasks[ind]->pid = i;
		tasks[ind]->vtime = ind;

		pids[i] = ind;


		if (isfifo) {
			ret = scx_atq_insert(atq, (u64)tasks[ind]);
			if (ret) {
				bpf_printk("fifo atq insert failed with %d", ret);
				return ret;
			}
		} else {
			ret = scx_atq_insert_vtime(atq, (u64)tasks[ind], tasks[ind]->vtime);
			if (ret) {
				bpf_printk("fifo atq insert failed with %d", ret);
				return ret;
			}
		}

		/*
		 * A step prime to the size of the modulo ring
		 * guarantees we don't revisit indices.
		 */
		ind = (ind + step) % NTASKS_IN_QUEUE;
	}

	vtime = 0;
	for (i = 0; i < NTASKS_IN_QUEUE && can_loop; i++ ) {
		taskc = (task_ctx *)scx_atq_pop(atq);
		if (isfifo && taskc->pid != i) {
			bpf_printk("Popped out unexpected element from FIFO atq (pid %ld, vtime %ld), expected %d", taskc->pid, taskc->vtime, i);
			scx_minheap_dump(atq->heap);
			return -EINVAL;
		} else if (!isfifo && taskc->vtime < vtime) {
			scx_minheap_dump(atq->heap);
			bpf_printk("Popped out unexpected element from PRIO atq (pid %ld, vtime %ld)", taskc->pid, taskc->vtime);
			return -EINVAL;
		}

		vtime = taskc->vtime;
	}

#undef NTASKS_IN_QUEUE

	return 0;
}

__weak
int scx_selftest_atq_fifo(u64 unused)
{
	return scx_selftest_atq_common(true);
}

__weak
int scx_selftest_atq_fail_fifo_with_weight(u64 unused)
{
	if (!scx_atq_insert_vtime(fifo, 0, 0)) {
		bpf_printk("atq PRIO insert on FIFO atq succeeded");
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_atq_vtime(u64 unused)
{
	return scx_selftest_atq_common(false);
}

__weak
int scx_selftest_atq_fail_vtime_without_weight(u64 unused)
{
	if (!scx_atq_insert(prio, 0)) {
		bpf_printk("atq FIFO insert on PRIO atq succeeded");
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_atq_nr_queued(u64 unused)
{
	const int PUSHES_PER_TEST = 5;
	const int POPS_PER_TEST = 2;
	const int TEST_CYCLES = 32;
	scx_atq_t *atq;
	int expected, found;
	int i, j;
	int ret;

	atq = prio;

	for (i = 0; i < TEST_CYCLES && can_loop; i++ ) {

		for (j = 0; j < PUSHES_PER_TEST && can_loop; j++ ) {
			ret = scx_atq_insert_vtime(atq, i, i);
			if (ret) {
				bpf_printk("atq insert failed with %d", ret);
				return ret;
			}

			expected = (PUSHES_PER_TEST - POPS_PER_TEST) * i  + j + 1;
			found = scx_atq_nr_queued(atq);
			if (expected != found) {
				bpf_printk("scx_arnea_atq_nr_queued expected %d, found %d", expected, found);
				return -EINVAL;
			}
		}

		for (j = 0; j < POPS_PER_TEST && can_loop; j++ ) {
			scx_atq_pop(atq);

			expected = (PUSHES_PER_TEST - POPS_PER_TEST) * i  + (PUSHES_PER_TEST - 1 - j);
			found = scx_atq_nr_queued(atq);
			if (expected != found) {
				bpf_printk("scx_atq_nr_queued expected %d, found %d", expected, found);
				return -EINVAL;
			}
		}
	}


	found = scx_atq_nr_queued(atq);
	for (i = 0; i < found && can_loop; i++)
		scx_atq_pop(atq);

	if (scx_atq_nr_queued(atq) > 0) {
		bpf_printk("atq unexpectedly not empty");
		return -EINVAL;
	}

	return 0;
#undef NTASKS_FOR_TEST
}

#define SCX_ATQ_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_atq_ ## suffix, (u64)NULL)

__weak
int scx_selftest_atq_peek_nodestruct(u64 unused)
{
	const u64 elem = 5;
	const int iters = 10;
	u64 found;
	int i;

	found = scx_atq_nr_queued(fifo);
	if (found) {
		bpf_printk("ATQ was not empty");
		return -EINVAL;
	}

	if (scx_atq_insert(fifo, elem)) {
		bpf_printk("ATQ insert failed");
		return -EINVAL;
	}

	for (i = 0; i < iters && can_loop; i++) {
		if (scx_atq_peek(fifo) == elem)
			continue;

		found = scx_atq_nr_queued(fifo);
		if (found != 1) {
			bpf_printk("found %d elems in ATQ", found);
			return -EINVAL;
		}

		bpf_printk("ATQ peek failed");
		return -EINVAL;
	}

	scx_atq_pop(fifo);

	found = scx_atq_nr_queued(fifo);
	if (found) {
		bpf_printk("leaving ATQ nonempty");
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_atq_peek_empty(u64 unused)
{
	u64 found;

	found = scx_atq_nr_queued(fifo);
	if (found) {
		bpf_printk("ATQ was not empty");
		return -EINVAL;
	}

	if (scx_atq_peek(fifo) != (u64)NULL) {
		bpf_printk("ATQ peek did not return NULL");
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_atq_sized(u64 unused)
{
	scx_atq_t *sized_fifo, *sized_vtime;
	int ret;

	sized_fifo = (scx_atq_t *)scx_atq_create_size(true, 1);
	if (!sized_fifo) {
		bpf_printk("ATQ failed to create sized fifo ATQ");
		return -ENOMEM;
	}

	sized_vtime = (scx_atq_t *)scx_atq_create_size(false, 1);
	if (!sized_vtime) {
		bpf_printk("ATQ failed to create sized vtime ATQ");
		return -ENOMEM;
	}

	ret = scx_atq_insert(sized_fifo, 1234);
	if (ret) {
		bpf_printk("ATQ failed to insert into sized fifo ATQ");
		return -EINVAL;
	}

	ret = scx_atq_insert(sized_fifo, 5678);
	if (!ret) {
		bpf_printk("ATQ too many inserts into sized fifo ATQ");
		return -EINVAL;
	}

	ret = scx_atq_insert_vtime(sized_vtime, 1234, 7890);
	if (ret) {
		bpf_printk("ATQ failed to insert into sized vtime ATQ");
		return -EINVAL;
	}

	ret = scx_atq_insert_vtime(sized_vtime, 1111, 2222);
	if (!ret) {
		bpf_printk("ATQ too many inserts into sized vtime ATQ");
		return -EINVAL;
	}


	return 0;
}

__weak
int scx_selftest_atq(void)
{
	int i;

	for (i = 0; i < NTASKS && can_loop; i++) {
		tasks[i] = scx_static_alloc(sizeof(*tasks[i]), 1);
		if (!tasks[i]) {
			bpf_printk("Could not allocate task with index i", i);
			return -ENOMEM;
		}
	}

	SCX_ATQ_SELFTEST(create);
	SCX_ATQ_SELFTEST(fifo);
	SCX_ATQ_SELFTEST(fail_fifo_with_weight);
	SCX_ATQ_SELFTEST(vtime);
	SCX_ATQ_SELFTEST(fail_vtime_without_weight);
	SCX_ATQ_SELFTEST(nr_queued);
	SCX_ATQ_SELFTEST(peek_nodestruct);
	SCX_ATQ_SELFTEST(peek_empty);
	SCX_ATQ_SELFTEST(sized);

	return 0;
}
