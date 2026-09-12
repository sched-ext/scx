/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/lvqueue.h>

static inline
u64 lv_arr_size(lv_arr_t *lv_arr)
{
	return 1ULL << lv_arr->order;
}

static inline
u64 lv_arr_get(lv_arr_t *lv_arr, u64 ind)
{
	return lv_arr->data[ind % lv_arr_size(lv_arr)];
}

static inline
void lv_arr_put(lv_arr_t *lv_arr, u64 ind, u64 value)
{
	lv_arr->data[ind % lv_arr_size(lv_arr)] = value;
}

static inline
void lv_arr_copy(lv_arr_t *dst, lv_arr_t *src, u64 b, u64 t)
{
	int i;

	for (i = t; i < b && can_loop; i++)
		lv_arr_put(dst, i, lv_arr_get(src, i));
}

static inline
int lvq_order_init(lv_queue_t __arg_arena *lvq, int order)
{
	lv_arr_t *arr = &lvq->arr[order];

	if (unlikely(!lvq))
		return -EINVAL;

	if (order >= LV_ARR_ORDERS)
		return -E2BIG;

	/* Already allocated? */
	if (arr->data)
		return 0;

	arr->data = (u64 __arena *)scx_static_alloc((LV_ARR_BASESZ << order) * sizeof(*arr->data), 1);
	if (!arr->data)
		return -ENOMEM;

	return 0;
}

__weak
int lvq_push(lv_queue_t __arg_arena *lvq, u64 val)
{
	volatile u64 b, t;
	lv_arr_t *newarr;
	lv_arr_t *arr;
	ssize_t sz;
	int ret;

	if (unlikely(!lvq))
		return -EINVAL;

	b = lvq->bottom;
	t = lvq->top;
	arr = lvq->cur;

	sz = b - t;
	if (sz >= lv_arr_size(arr) - 1) {
		ret = lvq_order_init(lvq, arr->order + 1);
		if (ret)
			return ret;

		newarr = &lvq->arr[arr->order + 1];

		lv_arr_copy(newarr, arr, b, t);
		lvq->cur = newarr;
	}

	lv_arr_put(lvq->cur, b, val);
	lvq->bottom += 1;

	return 0;
}


__weak
int lvq_pop(lv_queue_t __arg_arena *lvq, u64 *val)
{
	lv_arr_t *arr;
	volatile u64 b, t;
	ssize_t sz;
	u64 value;

	if (unlikely(!lvq || !val))
		return -EINVAL;

	arr = lvq->cur;

	lvq->bottom -= 1;
	b = lvq->bottom;

	t = lvq->top;
	sz = b - t;
	if (sz < 0) {
		lvq->bottom = t;
		return -ENOENT;
	}

	value = lv_arr_get(arr, b);
	if (sz > 0) {
		/* XXXETSAL Check for shrinking */
		*val = value;
		return 0;
	}

	if (cmpxchg(&lvq->top, t, t + 1) != t)
		return -EAGAIN;

	lvq->bottom = t + 1;

	*val = value;

	return 0;
}

__weak
int lvq_steal(lv_queue_t __arg_arena *lvq, u64 *val)
{
	volatile u64 b, t;
	lv_arr_t *arr;
	ssize_t sz;
	u64 value;

	if (unlikely(!lvq || !val))
		return -EINVAL;

	b = lvq->bottom;
	t = lvq->top;
	arr = lvq->cur;

	sz = b - t;
	if (sz <= 0)
		return -ENOENT;

	value = lv_arr_get(arr, t);

	if (cmpxchg(&lvq->top, t, t + 1) != t)
		return -EAGAIN;

	*val = value;

	return 0;
}


__weak
u64 lvq_create_internal(void)
{
	/* 
	 * Marked as volatile because otherwise the array 
	 * reference in the internal loop gets demoted to 
	 * scalar and the program fails verification.
	 */
	volatile lv_queue_t *lvq;
	int ret, i;

	lvq = scx_static_alloc(sizeof(*lvq), 1);
	if (!lvq)
		return (u64)NULL;

	lvq->bottom = lvq->top = 0;

	for (i = 0; i < LV_ARR_ORDERS && can_loop; i++) {
		lvq->arr[i].data = NULL;
		lvq->arr[i].order = i;
	}

	ret = lvq_order_init((lv_queue_t *)lvq, 0);
	if (ret) {
		/* XXX Free when migrating from the static allocator. */
		return (u64)NULL;
	}

	lvq->cur = &lvq->arr[0];

	return (u64)(lvq);
}

__weak
int lvq_destroy(lv_queue_t __arg_arena *lvq)
{
	if (unlikely(!lvq))
		return -EINVAL;

	return -EOPNOTSUPP;
}
