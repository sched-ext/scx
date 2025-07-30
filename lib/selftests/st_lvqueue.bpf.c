#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>
#include <lib/lvqueue.h>

#include "selftest.h"

/*
 * NOTE: These selftests only test for the single-threaded use case, which for
 * Lev-Chase queues is obviously the simplest one. Still, it is important to
 * exercise the API to ensure it passes verification and basic checks.
 */

int scx_selftest_lvqueue_pop_empty(lv_queue_t *lvq)
{
	u64 val;
	int ret;

	ret = lvq_pop(lvq, &val);
	if (ret != -ENOENT)
		return 1;

	return 0;
}

int scx_selftest_lvqueue_steal_empty(lv_queue_t *lvq)
{
	u64 val;
	int ret;

	ret = lvq_steal(lvq, &val);
	if (ret != -ENOENT)
		return 1;

	return 0;
}

int scx_selftest_lvqueue_steal_one(lv_queue_t *lvq)
{
	u64 val, newval;
	int ret, i;

	for (i = 0; i < 10 && can_loop; i++) {
		val = i;

		ret = lvq_push(lvq, val);
		if (ret)
			return 1;

		ret = lvq_steal(lvq, &newval);
		if (ret)
			return 2;

		if (val != newval)
			return 3;
	}

	return 0;
}

int scx_selftest_lvqueue_pop_one(lv_queue_t *lvq)
{
	u64 val, newval;
	int ret, i;

	for (i = 0; i < 10 && can_loop; i++) {
		val = i;

		ret = lvq_push(lvq, val);
		if (ret)
			return 1;

		ret = lvq_pop(lvq, &newval);
		if (ret)
			return 2;

		if (val != newval)
			return 3;
	}

	return 0;
}

int scx_selftest_lvqueue_pop_many(lv_queue_t *lvq)
{
	u64 val, newval;
	int ret, i;

	for (i = 0; i < 10 && can_loop; i++) {
		val = i;

		ret = lvq_push(lvq, val);
		if (ret != -ENOENT)
			return i + 1;
	}

	for (i = 0; i < 2000 && can_loop; i++) {
		ret = lvq_pop(lvq, &newval);
		if (ret != -ENOENT)
			return 2 * i + 2001;

		if (newval != i)
			return 2 * i + 2002;
	}

	return 0;
}


int scx_selftest_lvqueue_steal_many(lv_queue_t *lvq)
{
	u64 val, newval;
	int ret, i;

	for (i = 0; i < 2000 && can_loop; i++) {
		val = i;

		ret = lvq_push(lvq, val);
		if (ret != -ENOENT)
			return i + 1;
	}

	for (i = 0; i < 2000 && can_loop; i++) {
		ret = lvq_steal(lvq, &newval);
		if (ret != -ENOENT)
			return 2 * i + 2001;

		if (newval != 9 - i)
			return 2 * i + 2002;
	}

	return 0;
}

#define SCX_LVQUEUE_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_lvqueue_ ## suffix, lvq)

__weak
int scx_selftest_lvqueue(void)
{
	lv_queue_t *lvq = lvq_create();

	if (!lvq)
		return 1;

	SCX_LVQUEUE_SELFTEST(pop_empty);
	SCX_LVQUEUE_SELFTEST(steal_empty);
	SCX_LVQUEUE_SELFTEST(pop_one);
	SCX_LVQUEUE_SELFTEST(steal_one);

	return 0;
}
