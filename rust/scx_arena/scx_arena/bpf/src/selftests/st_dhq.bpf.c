/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Daniel Hodges <hodges.daniel.scott@gmail.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/dhq.h>

#include "selftest.h"

#define NDHQS 8
scx_dhq_t *dhq_prios[NDHQS];
scx_dhq_t *dhq_fifos[NDHQS];

scx_dhq_t *dhq_prio;
scx_dhq_t *dhq_fifo;

#define NTASKS 64

task_ctx *dhq_tasks[NTASKS];

__weak
int scx_selftest_dhq_create(u64 unused)
{
	/* Create priority DHQs with different modes */
	dhq_prios[0] = (scx_dhq_t *)scx_dhq_create(false, SCX_DHQ_MODE_ALTERNATING);
	if (!dhq_prios[0])
		return -ENOMEM;

	dhq_prios[1] = (scx_dhq_t *)scx_dhq_create(false, SCX_DHQ_MODE_PRIORITY);
	if (!dhq_prios[1])
		return -ENOMEM;

	dhq_prios[2] = (scx_dhq_t *)scx_dhq_create(false, SCX_DHQ_MODE_BALANCED);
	if (!dhq_prios[2])
		return -ENOMEM;

	dhq_prio = dhq_prios[0];

	/* Create FIFO DHQs with different modes */
	dhq_fifos[0] = (scx_dhq_t *)scx_dhq_create(true, SCX_DHQ_MODE_ALTERNATING);
	if (!dhq_fifos[0])
		return -ENOMEM;

	dhq_fifos[1] = (scx_dhq_t *)scx_dhq_create(true, SCX_DHQ_MODE_PRIORITY);
	if (!dhq_fifos[1])
		return -ENOMEM;

	dhq_fifos[2] = (scx_dhq_t *)scx_dhq_create(true, SCX_DHQ_MODE_BALANCED);
	if (!dhq_fifos[2])
		return -ENOMEM;

	dhq_fifo = dhq_fifos[0];

	return 0;
}

__weak
int scx_selftest_dhq_fifo_basic(u64 unused)
{
#define NTASKS_IN_QUEUE (16)
	scx_dhq_t *dhq;
	task_ctx *taskc;
	int ret, i;

	dhq = dhq_fifo;

	/* Insert tasks alternating between strands */
	for (i = 0; i < NTASKS_IN_QUEUE && can_loop; i++) {
		task_ctx *task;

		if (i >= NTASKS || !dhq_tasks[i])
			return -EINVAL;

		task = dhq_tasks[i];
		barrier_var(task);

		task->pid = i;
		task->vtime = i;

		ret = scx_dhq_insert(dhq, (u64)task,
				     (i % 2) ? SCX_DHQ_STRAND_A : SCX_DHQ_STRAND_B);
		if (ret) {
			bpf_printk("DHQ fifo insert failed with %d", ret);
			return ret;
		}
	}

	/* Verify total count */
	if (scx_dhq_nr_queued(dhq) != NTASKS_IN_QUEUE) {
		bpf_printk("DHQ expected %d queued, got %d",
			   NTASKS_IN_QUEUE, scx_dhq_nr_queued(dhq));
		return -EINVAL;
	}

	/* Pop all tasks (alternating mode should alternate strands) */
	for (i = 0; i < NTASKS_IN_QUEUE && can_loop; i++) {
		taskc = (task_ctx *)scx_dhq_pop(dhq);
		if (!taskc) {
			bpf_printk("DHQ pop returned NULL at iteration %d", i);
			return -EINVAL;
		}
	}

	/* Should be empty now */
	if (scx_dhq_nr_queued(dhq) != 0) {
		bpf_printk("DHQ should be empty, has %d tasks",
			   scx_dhq_nr_queued(dhq));
		return -EINVAL;
	}

#undef NTASKS_IN_QUEUE
	return 0;
}

__weak
int scx_selftest_dhq_vtime_priority(u64 unused)
{
#define NTASKS_IN_QUEUE (16)
	scx_dhq_t *dhq;
	task_ctx *taskc;
	int ret, i;
	u64 last_vtime = 0;

	/* Use priority mode DHQ */
	dhq = dhq_prios[1];

	/* Insert tasks with varying vtimes into both strands */
	for (i = 0; i < NTASKS_IN_QUEUE && can_loop; i++) {
		task_ctx *task;

		if (i >= NTASKS || !dhq_tasks[i])
			return -EINVAL;

		task = dhq_tasks[i];
		barrier_var(task);

		task->pid = i;
		/* Reverse vtime to test priority ordering */
		task->vtime = NTASKS_IN_QUEUE - i;

		ret = scx_dhq_insert_vtime(dhq, (u64)task, task->vtime,
					   (i % 2) ? SCX_DHQ_STRAND_A : SCX_DHQ_STRAND_B);
		if (ret) {
			bpf_printk("DHQ vtime insert failed with %d", ret);
			return ret;
		}
	}

	/* Pop all tasks - should come out in vtime order (priority mode) */
	for (i = 0; i < NTASKS_IN_QUEUE && can_loop; i++) {
		taskc = (task_ctx *)scx_dhq_pop(dhq);
		if (!taskc) {
			bpf_printk("DHQ pop returned NULL at iteration %d", i);
			return -EINVAL;
		}

		if (taskc->vtime < last_vtime) {
			bpf_printk("DHQ priority violation: vtime %llu after %llu",
				   taskc->vtime, last_vtime);
			return -EINVAL;
		}

		last_vtime = taskc->vtime;
	}

#undef NTASKS_IN_QUEUE
	return 0;
}

__weak
int scx_selftest_dhq_alternating_and_priority_modes(u64 unused)
{
	scx_dhq_t *dhq;
	task_ctx *taskc, *task;
	int ret, i;

	/* Test 1: Alternating mode with minimal operations */
	dhq = dhq_prios[0];  /* ALTERNATING mode */

	task = scx_static_alloc(sizeof(*task), 1);
	if (!task)
		return -ENOMEM;
	task->vtime = 1;
	ret = scx_dhq_insert_vtime(dhq, (u64)task, 1, SCX_DHQ_STRAND_A);
	if (ret)
		return ret;

	task = scx_static_alloc(sizeof(*task), 1);
	if (!task)
		return -ENOMEM;
	task->vtime = 2;
	ret = scx_dhq_insert_vtime(dhq, (u64)task, 2, SCX_DHQ_STRAND_B);
	if (ret)
		return ret;

	/* Verify both strands have tasks */
	if (scx_dhq_nr_queued_strand(dhq, SCX_DHQ_STRAND_A) != 1 ||
	    scx_dhq_nr_queued_strand(dhq, SCX_DHQ_STRAND_B) != 1)
		return -EINVAL;

	/* Pop and verify */
	for (i = 0; i < 2 && can_loop; i++) {
		taskc = (task_ctx *)scx_dhq_pop(dhq);
		if (!taskc)
			return -EINVAL;
	}

	/* Test 2: Priority mode - lowest vtime first */
	dhq = dhq_prios[1];  /* PRIORITY mode */

	/* Insert vtime=2 into strand A */
	task = scx_static_alloc(sizeof(*task), 1);
	if (!task)
		return -ENOMEM;
	task->vtime = 2;
	ret = scx_dhq_insert_vtime(dhq, (u64)task, 2, SCX_DHQ_STRAND_A);
	if (ret)
		return ret;

	/* Insert vtime=1 into strand B */
	task = scx_static_alloc(sizeof(*task), 1);
	if (!task)
		return -ENOMEM;
	task->vtime = 1;
	ret = scx_dhq_insert_vtime(dhq, (u64)task, 1, SCX_DHQ_STRAND_B);
	if (ret)
		return ret;

	/* Pop should return vtime=1 first (from strand B) */
	taskc = (task_ctx *)scx_dhq_pop(dhq);
	if (!taskc || taskc->vtime != 1)
		return -EINVAL;

	/* Then vtime=2 */
	taskc = (task_ctx *)scx_dhq_pop(dhq);
	if (!taskc || taskc->vtime != 2)
		return -EINVAL;

	return 0;
}

__weak
int scx_selftest_dhq_balanced_mode(u64 unused)
{
#define NTASKS_TOTAL (20)
	scx_dhq_t *dhq;
	task_ctx *taskc;
	int ret, i;

	/* Use balanced mode DHQ */
	dhq = dhq_prios[2];

	/* Insert all tasks with auto-balancing */
	for (i = 0; i < NTASKS_TOTAL && can_loop; i++) {
		task_ctx *task;

		if (i >= NTASKS || !dhq_tasks[i])
			return -EINVAL;

		task = dhq_tasks[i];
		barrier_var(task);

		task->pid = i;
		task->vtime = i;

		ret = scx_dhq_insert_vtime(dhq, (u64)task, task->vtime,
					   SCX_DHQ_STRAND_AUTO);
		if (ret) {
			bpf_printk("DHQ auto insert failed with %d", ret);
			return ret;
		}
	}

	/* Check that strands are roughly balanced (within 1 of each other) */
	i = scx_dhq_nr_queued_strand(dhq, SCX_DHQ_STRAND_A) -
	    scx_dhq_nr_queued_strand(dhq, SCX_DHQ_STRAND_B);
	if (i < 0)
		i = -i;

	if (i > 1) {
		bpf_printk("DHQ strands unbalanced: A=%d, B=%d",
			   scx_dhq_nr_queued_strand(dhq, SCX_DHQ_STRAND_A),
			   scx_dhq_nr_queued_strand(dhq, SCX_DHQ_STRAND_B));
		return -EINVAL;
	}

	/* Pop all tasks */
	for (i = 0; i < NTASKS_TOTAL && can_loop; i++) {
		taskc = (task_ctx *)scx_dhq_pop(dhq);
		if (!taskc) {
			bpf_printk("DHQ pop returned NULL at iteration %d", i);
			return -EINVAL;
		}
	}

#undef NTASKS_TOTAL
	return 0;
}

__weak
int scx_selftest_dhq_peek(u64 unused)
{
	scx_dhq_t *dhq;
	task_ctx *taskc_peek, *taskc_pop, *task;
	int ret;

	dhq = dhq_fifo;

	/* Insert one task */
	if (!dhq_tasks[0])
		return -EINVAL;

	task = dhq_tasks[0];
	barrier_var(task);

	task->pid = 42;
	ret = scx_dhq_insert(dhq, (u64)task, SCX_DHQ_STRAND_A);
	if (ret) {
		bpf_printk("DHQ insert failed with %d", ret);
		return ret;
	}

	/* Peek should return the task without removing it */
	taskc_peek = (task_ctx *)scx_dhq_peek(dhq);
	if (!taskc_peek || taskc_peek->pid != 42) {
		bpf_printk("DHQ peek failed");
		return -EINVAL;
	}

	/* Queue should still have 1 task */
	if (scx_dhq_nr_queued(dhq) != 1) {
		bpf_printk("DHQ peek removed task");
		return -EINVAL;
	}

	/* Pop should return same task */
	taskc_pop = (task_ctx *)scx_dhq_pop(dhq);
	if (!taskc_pop || taskc_pop->pid != 42) {
		bpf_printk("DHQ pop failed");
		return -EINVAL;
	}

	/* Queue should now be empty */
	if (scx_dhq_nr_queued(dhq) != 0) {
		bpf_printk("DHQ not empty after pop");
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_dhq_peek_strand(u64 unused)
{
	scx_dhq_t *dhq;
	task_ctx *taskc_a, *taskc_b, *task;
	int ret;

	dhq = dhq_fifo;

	/* Insert into both strands */
	if (!dhq_tasks[0] || !dhq_tasks[1])
		return -EINVAL;

	task = dhq_tasks[0];
	barrier_var(task);
	task->pid = 100;
	ret = scx_dhq_insert(dhq, (u64)task, SCX_DHQ_STRAND_A);
	if (ret) {
		bpf_printk("DHQ insert strand A failed with %d", ret);
		return ret;
	}

	task = dhq_tasks[1];
	barrier_var(task);
	task->pid = 200;
	ret = scx_dhq_insert(dhq, (u64)task, SCX_DHQ_STRAND_B);
	if (ret) {
		bpf_printk("DHQ insert strand B failed with %d", ret);
		return ret;
	}

	/* Peek at each strand individually */
	taskc_a = (task_ctx *)scx_dhq_peek_strand(dhq, SCX_DHQ_STRAND_A);
	if (!taskc_a || taskc_a->pid != 100) {
		bpf_printk("DHQ peek strand A failed");
		return -EINVAL;
	}

	taskc_b = (task_ctx *)scx_dhq_peek_strand(dhq, SCX_DHQ_STRAND_B);
	if (!taskc_b || taskc_b->pid != 200) {
		bpf_printk("DHQ peek strand B failed");
		return -EINVAL;
	}

	/* Clean up */
	scx_dhq_pop(dhq);
	scx_dhq_pop(dhq);

	return 0;
}

__weak
int scx_selftest_dhq_pop_strand(u64 unused)
{
	scx_dhq_t *dhq;
	task_ctx *taskc, *task;
	int ret;

	dhq = dhq_fifo;

	/* Insert into strand A only */
	if (!dhq_tasks[0])
		return -EINVAL;

	task = dhq_tasks[0];
	barrier_var(task);

	task->pid = 111;
	ret = scx_dhq_insert(dhq, (u64)task, SCX_DHQ_STRAND_A);
	if (ret) {
		bpf_printk("DHQ insert failed with %d", ret);
		return ret;
	}

	/* Pop from strand B should return NULL */
	taskc = (task_ctx *)scx_dhq_pop_strand(dhq, SCX_DHQ_STRAND_B);
	if (taskc) {
		bpf_printk("DHQ pop from empty strand returned non-NULL");
		return -EINVAL;
	}

	/* Pop from strand A should return task */
	taskc = (task_ctx *)scx_dhq_pop_strand(dhq, SCX_DHQ_STRAND_A);
	if (!taskc || taskc->pid != 111) {
		bpf_printk("DHQ pop strand A failed");
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_dhq_sized(u64 unused)
{
	scx_dhq_t *sized_dhq;
	int ret;

	sized_dhq = (scx_dhq_t *)scx_dhq_create_size(true, 2, SCX_DHQ_MODE_BALANCED);
	if (!sized_dhq) {
		bpf_printk("DHQ failed to create sized DHQ");
		return -ENOMEM;
	}

	/* Ensure tasks are initialized */
	if (!dhq_tasks[0] || !dhq_tasks[1] || !dhq_tasks[2])
		return -EINVAL;

	/* Insert 2 tasks (at capacity) */
	ret = scx_dhq_insert(sized_dhq, (u64)dhq_tasks[0], SCX_DHQ_STRAND_AUTO);
	if (ret) {
		bpf_printk("DHQ first insert failed");
		return -EINVAL;
	}

	ret = scx_dhq_insert(sized_dhq, (u64)dhq_tasks[1], SCX_DHQ_STRAND_AUTO);
	if (ret) {
		bpf_printk("DHQ second insert failed");
		return -EINVAL;
	}

	/* Third insert should fail (over capacity) */
	ret = scx_dhq_insert(sized_dhq, (u64)dhq_tasks[2], SCX_DHQ_STRAND_AUTO);
	if (!ret) {
		bpf_printk("DHQ insert beyond capacity should have failed");
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_dhq_fail_fifo_with_vtime(u64 unused)
{
	if (!scx_dhq_insert_vtime(dhq_fifo, (u64)dhq_tasks[0], 100, SCX_DHQ_STRAND_A)) {
		bpf_printk("DHQ vtime insert on FIFO dhq succeeded");
		return -EINVAL;
	}

	return 0;
}

__weak
int scx_selftest_dhq_fail_vtime_with_fifo(u64 unused)
{
	if (!scx_dhq_insert(dhq_prio, (u64)dhq_tasks[0], SCX_DHQ_STRAND_A)) {
		bpf_printk("DHQ FIFO insert on vtime dhq succeeded");
		return -EINVAL;
	}

	return 0;
}

#define SCX_DHQ_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_dhq_ ## suffix, (u64)NULL)

__weak
int scx_selftest_dhq(void)
{
	/* Allocate tasks with constant indices for tests */
	dhq_tasks[0] = scx_static_alloc(sizeof(*dhq_tasks[0]), 1);
	if (!dhq_tasks[0])
		return -ENOMEM;

	dhq_tasks[1] = scx_static_alloc(sizeof(*dhq_tasks[1]), 1);
	if (!dhq_tasks[1])
		return -ENOMEM;

	dhq_tasks[2] = scx_static_alloc(sizeof(*dhq_tasks[2]), 1);
	if (!dhq_tasks[2])
		return -ENOMEM;

	dhq_tasks[3] = scx_static_alloc(sizeof(*dhq_tasks[3]), 1);
	if (!dhq_tasks[3])
		return -ENOMEM;

	dhq_tasks[4] = scx_static_alloc(sizeof(*dhq_tasks[4]), 1);
	if (!dhq_tasks[4])
		return -ENOMEM;

	dhq_tasks[5] = scx_static_alloc(sizeof(*dhq_tasks[5]), 1);
	if (!dhq_tasks[5])
		return -ENOMEM;

	dhq_tasks[6] = scx_static_alloc(sizeof(*dhq_tasks[6]), 1);
	if (!dhq_tasks[6])
		return -ENOMEM;

	dhq_tasks[7] = scx_static_alloc(sizeof(*dhq_tasks[7]), 1);
	if (!dhq_tasks[7])
		return -ENOMEM;

	SCX_DHQ_SELFTEST(create);
	SCX_DHQ_SELFTEST(fifo_basic);
	SCX_DHQ_SELFTEST(vtime_priority);
	SCX_DHQ_SELFTEST(alternating_and_priority_modes);
	SCX_DHQ_SELFTEST(balanced_mode);
	SCX_DHQ_SELFTEST(peek);
	SCX_DHQ_SELFTEST(peek_strand);
	SCX_DHQ_SELFTEST(pop_strand);
	SCX_DHQ_SELFTEST(sized);
	SCX_DHQ_SELFTEST(fail_fifo_with_vtime);
	SCX_DHQ_SELFTEST(fail_vtime_with_fifo);

	return 0;
}
