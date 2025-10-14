#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include "selftest.h"

static const u64 keys[] = { 51, 43,  37, 3, 301,  46, 383, 990, 776, 729, 871, 96, 189, 213,
	376, 167, 131, 939, 626, 119, 374, 700, 772, 154, 883, 620, 641, 5,
	428, 516, 105, 622, 988, 811, 931, 973, 246, 690, 934, 744, 210, 311,
	32, 255, 960, 830, 523, 429, 541, 738, 705, 774, 715, 446, 98, 578,
	777, 191, 279, 91, 767 };

static const u64 morekeys[] = { 173, 636, 1201, 8642, 5957, 3617, 4586, 8053, 6551, 7592, 1748, 1589, 8644, 9918, 6977,
	4448, 5852, 4640, 9717, 2303, 7424, 7695, 2334, 8876, 8618, 5745, 7134, 2178, 5280, 2140, 1138,
	5083, 8922, 1516, 2437, 2488, 4307, 4329, 5088, 8456, 5938, 1441, 1684, 5750, 721, 1107, 2089,
	9737, 4687, 5016, 4849, 8193, 9603, 9147, 5992, 166, 6721, 812, 4144, 6237, 6509, 3466, 9255,
	7767, 3960, 6759, 2968, 6046, 9784, 8395, 2619, 1711, 528, 6424, 9084, 3179, 1342, 5676, 9445,
	5691, 6678, 8487, 1627, 998, 6178, 2229, 1987, 3319, 572, 169, 2161, 3018, 5439, 7287, 7265, 5995,
	5003, 5857, 2836, 5634, 4735, 9261, 8287, 5359, 533, 1406, 9573, 4026, 714, 3956, 1722, 6395,
	9648, 3887, 7185, 470, 4482, 4997, 841, 8913, 9946, 3999, 9357, 9847, 277, 8184, 8704, 6766, 3323,
	5468, 8638, 7905, 8858, 6142, 3685, 3452, 4689, 8878, 8836, 158, 831, 7914, 3031, 8374, 4921,
	4207, 3460, 5547, 3358, 1083, 4619, 7818, 2962, 4879, 4583, 2172, 8819, 9830, 1194, 2666, 9812,
	5704, 8432, 5916, 6007, 6609, 4791, 1985, 3226, 2478, 9605, 5236, 8079, 3042, 1965, 3539, 9704,
	4267, 6416, 760, 9968, 2983, 1190, 1964, 3211, 2870, 3106, 2794, 1542, 6916, 5986, 9096, 441,
	5894, 8353, 7765, 3757, 5732, 88, 3091, 5637, 6042, 8447, 4073, 6923, 5491, 7010, 3663, 5029,
	6162, 822, 4874, 7491, 5100, 3461, 6983, 2170, 1458, 1856, 648, 6272, 4887, 976, 2369, 5909, 4274,
	3324, 6968, 2312, 2271, 8891, 6268, 6581, 1610, 8880, 6194, 6144, 9764, 6915, 829, 3774, 2265,
	1752, 1314, 6377, 8760, 8004, 501, 4912, 9278, 1425, 9578, 7337, 307, 1885, 3151, 9617, 1647,
	2458, 3702, 6091, 8902, 5663, 9378, 7640, 3336, 557, 1644, 6848, 1559, 8821, 266, 4330, 9790,
	5920, 4222, 1143, 6248, 5792, 4847, 9726, 6303, 821, 6839, 6062, 7133, 3649, 9888, 2528, 1966,
	5456, 4914, 3615, 1543, 3206, 3353, 6097, 2800, 1424, 9094, 7920, 7243, 1394, 5464, 1707, 576,
	6524, 4261, 4187, 7889, 5336, 3377, 2921, 7244, 2766, 6584, 5514, 1387, 2957, 2258, 1077, 9979,
	1128, 876, 4056, 4668, 4532, 1982, 7093, 4184, 5460, 7588, 4704, 6717, 61, 3959, 1826, 2294, 18,
	8170, 9394, 8796, 7288, 7285, 7143, 148, 6676, 6603, 1051, 8225, 4169, 3230, 7697, 6971, 3454,
	7501, 9514, 394, 2339, 4993, 5606, 6060, 1297, 8273, 3012, 157, 8181, 6765, 7207, 1005, 8833, 1914,
	7456, 1846, 8375, 2741, 2074, 1712, 5286 };

__weak int scx_selftest_rbtree_find_nonexistent(rbtree_t __arg_arena *rbtree)
{
	u64 key = 0xdeadbeef;
	u64 value = 0;
	int ret;

	if (!rbtree)
		return 1;

	/* Should return -EINVAL */
	ret = rb_find(rbtree, key, &value);
	if (!ret)
		return 2;

	return 0;
}

__weak int scx_selftest_rbtree_insert_existing(rbtree_t __arg_arena *rbtree)
{
	u64 key = 525252;
	u64 value = 24;
	int ret;

	if (!rbtree)
		return 1;

	/* Should return -EINVAL. */
	ret = rb_insert(rbtree, key, value);
	if (ret)
		return 2;

	/* Should return -EALREADY. */
	ret = rb_insert(rbtree, key, value);
	if (ret != -EALREADY) {
		return 3;
	}

	return 0;
}

__weak int scx_selftest_rbtree_update_existing(rbtree_t __arg_arena *rbtree)
{
	u64 key = 33333;
	u64 value;
	int ret;

	if (!rbtree)
		return 1;

	/* Should return -EINVAL. */
	value = 52;
	ret = rb_insert(rbtree, key, value);
	if (ret)
		return 2;

	ret = rb_find(rbtree, key, &value);
	if (ret)
		return 3;

	if (value != 52)
		return 4;

	value = 65;

	/* Should succeed. */
	ret = rb_insert(rbtree, key, value);
	if (ret)
		return 5;

	/* Should be updated. */
	ret = rb_find(rbtree, key, &value);
	if (ret)
		return 6;

	if (value != 65)
		return 7;

	return 0;
}


__weak int scx_selftest_rbtree_insert_one(rbtree_t __arg_arena *rbtree)
{
	u64 key = 202020;
	u64 value = 0xbadcafe;
	int ret;

	ret = rb_insert(rbtree, key, value);
	if (ret)
		return 1;

	ret = rb_find(rbtree, key, &value);
	if (ret)
		return 2;

	if (value != 0xbadcafe)
		return 3;

	return 0;
}

__weak int scx_selftest_rbtree_insert_ten(rbtree_t __arg_arena *rbtree)
{
	u64 key, value;
	int ret, i;

	if (!rbtree)
		return 1;

	for (i = 0; i < 10 && can_loop; i++) {
		key = keys[i];
		ret = rb_insert(rbtree, key, 2 * key);
		if (ret)
			return 2 + 3 * i;

		/* Read it back. */
		ret = rb_find(rbtree, key, &value);
		if (ret)
			return 2 + 3 * i + 1;

		if (value != 2 * key)
			return 2 + 3 * i + 2;
	}

	/* Go find all inserted pairs. */
	for (i = 0; i < 10 && can_loop; i++) {
		key = keys[i];

		ret = rb_find(rbtree, key, &value);
		if (ret)
			return 35 + 2 * i;

		if (value != 2 * key)
			return 35 + 2 * i + 1;
	}

	return 0;
}

__weak int scx_selftest_rbtree_duplicate(rbtree_t __arg_arena *rbtree)
{
	u64 key = 0x121212;
	u64 value;
	int ret, i;

	if (!rbtree)
		return 1;

	for (i = 0; i < 10 && can_loop; i++) {
		ret = rb_insert(rbtree, key, 2 * key);
		if (ret)
			return 2 + 3 * i;

		/* Read it back. */
		ret = rb_find(rbtree, key, &value);
		if (ret)
			return 2 + 3 * i + 1;

		if (value != 2 * key)
			return 2 + 3 * i + 2;
	}
	rb_print(rbtree);

	/* Go find all inserted copies and remove them. */
	for (i = 0; i < 10 && can_loop; i++) {
		ret = rb_find(rbtree, key, &value);
		if (ret) {
			rb_print(rbtree);
			return 35 + 3 * i;
		}

		if (value != 2 * key)
			return 35 + 3 * i + 1;

		ret = rb_remove(rbtree, key);
		if (ret)
			return 35 + 3 * i + 2;
	}

	return 0;
}

__weak int scx_selftest_rbtree_insert_many(rbtree_t __arg_arena *rbtree)
{
	const size_t numkeys = sizeof(keys) / sizeof(keys[0]);
	task_ctx *taskc;
	u64 key, value;
	int ret;
	int i;

	if (!rbtree)
		return 1;

	for (i = 0; i < numkeys && can_loop; i++) {
		key = keys[i];
		if (rbtree->alloc != RB_ALLOC) {
			taskc = scx_static_alloc(sizeof(*taskc), 1);
			if (!taskc) {
				bpf_printk("out of memory");
				return -ENOMEM;
			}
			taskc->rbnode.key = key;
			taskc->rbnode.value = 2 * key;
			ret = rb_insert_node(rbtree, &taskc->rbnode);
		} else {
			ret = rb_insert(rbtree, key, 2 * key);
		}
		if (ret)
			return 2 + 3 * i;

		/* Read it back. */
		ret = rb_find(rbtree, key, &value);
		if (ret)
			return 2 + 3 * i + 1;

		if (value != 2 * key)
			return 2 + 3 * i + 2;
	}

	/* Go find all inserted pairs. */
	for (i = 0; i < numkeys && can_loop; i++) {
		key = keys[i];

		ret = rb_find(rbtree, key, &value);
		if (ret)
			return 302 + 2 * i;

		if (value != 2 * key)
			return 302 + 2 * i + 1;
	}

	return 0;
}

__weak int scx_selftest_rbtree_remove_one(rbtree_t __arg_arena *rbtree)
{
	u64 key = 20, value = 5, newvalue;
	int ret;

	if (!rbtree)
		return 1;

	ret = rb_find(rbtree, key, &newvalue);
	if (!ret)
		return 2;

	ret = rb_insert(rbtree, key, value);
	if (ret)
		return 3;

	ret = rb_find(rbtree, key, &newvalue);
	if (ret || value != newvalue)
		return 4;

	ret = rb_remove(rbtree, key);
	if (ret)
		return 5;

	ret = rb_find(rbtree, key, &newvalue);
	if (!ret)
		return 6;



	return 0;
}

/*
 * This method, but lets us pass verification by encapsulating a bunch
 * of if-else paths within the for loop.
 */
__weak
u64 remove_key(rbtree_t __arg_arena *rbtree, task_ctx __arg_arena *taskc, u64 key, int *ret)
{
	task_ctx *tmp;
	
	if (!ret)
		return (u64)NULL;

	if (rbtree->alloc == RB_ALLOC) {
		*ret = rb_remove(rbtree, key);
		return (u64)NULL;
	}

	if (key != taskc->rbnode.key) {
		*ret = -EINVAL;
		return (u64)NULL;
	}

	tmp = taskc->next->next;
	*ret = rb_remove_node(rbtree, &taskc->rbnode);

	return (u64)tmp;
}

__weak int scx_selftest_rbtree_remove_many(rbtree_t __arg_arena *rbtree)
{
	const size_t numkeys = sizeof(morekeys) / sizeof(morekeys[0]);
	task_ctx *taskc = NULL, *first = NULL, *last = NULL;
	u64 key, value;
	int errval = 1;
	int ret;
	int i;

	if (!rbtree)
		return 1;

	bpf_for(i, 0, numkeys) {
		key = morekeys[i];
		if (rbtree->alloc != RB_ALLOC) {
			taskc = scx_static_alloc(sizeof(*taskc), 1);
			if (!taskc) {
				bpf_printk("out of memory");
				return -ENOMEM;
			}
			taskc->rbnode.key = key;
			taskc->rbnode.value = 2 * key;
			taskc->next = NULL;

			if (!first)
				first = taskc;

			if (last)
				last->next = taskc;
			last = taskc;

			ret = rb_insert_node(rbtree, &taskc->rbnode);
		} else {
			ret = rb_insert(rbtree, key, 2 * key);
		}
		if (ret)
			return errval;

		if (rb_integrity_check(rbtree)) {
			bpf_printk("iteration %d", i);
			return -EINVAL;
		}

		errval += 1;

		/* Read it back. */
		ret = rb_find(rbtree, key, &value);
		if (ret)
			return errval;

		errval += 1;

		if (value != 2 * key)
			return errval;

		errval += 1;
	}

	/* Go find all inserted pairs. */
	bpf_for(i, 0, numkeys) {
		key = morekeys[i];

		ret = rb_find(rbtree, key, &value);
		if (ret)
			return errval;

		errval += 1;

		if (value != 2 * key)
			return errval;

		errval += 1;
	}

	errval = 10000;

	/* Remove half of them. */
	for (i = 0; i < numkeys && can_loop; i += 2) {
		key = morekeys[i];

		first = (task_ctx *)remove_key(rbtree, first, key, &ret);
		if (ret) {
			bpf_printk("Failed to remove %ld", key);
			return errval;
		}

		errval += 1;

		/* Read it back. */
		ret = rb_find(rbtree, key, &value);
		if (!ret)
			return errval;

		errval += 1;
	}

	/* Ensure removed pairs are missing and added pairs are present. */
	for (i = 0; i < numkeys && can_loop; i += 2) {
		/* Even keys should be missing */
		key = morekeys[i];
		ret = rb_find(rbtree, key, &value);
		if (!ret)
			return errval;

		if (i + 1 >= numkeys)
			break;

		key = morekeys[i + 1];

		ret = rb_find(rbtree, key, &value);
		if (ret)
			return errval;

		errval += 1;

		if (value != 2 * key)
			return errval;

		errval += 1;

	}

	/* Odd keys should still be present. */
	for (i = 1; i < numkeys && can_loop; i += 2) {
		key = morekeys[i];
		ret = rb_find(rbtree, key, &value);
		if (ret)
			return errval;

		if (value != 2 * key)
			return errval;
	}

	return 0;
}

__weak int scx_selftest_rbtree_add_remove_circular(rbtree_t __arg_arena *rbtree)
{
	const size_t iters = 60;
	const size_t prefill = 10;
	const size_t numkeys = 50;
	const size_t prefix = 400000;
	u64 value, rmval;
	int errval = 1;
	u64 key;
	int ret;
	int i;

	if (!rbtree)
		return 1;

	bpf_for(i, 0, prefill) {
		ret = rb_insert(rbtree, prefix + (i % numkeys), i);
		if (ret)
			return errval;

		errval += 1;
	}

	errval = 2 * 1000 * 1000;

	bpf_for(i, 0, prefill) {
		/* Read it back. */
		ret = rb_find(rbtree, prefix + (i % numkeys), &value);
		if (ret)
			return errval;

		if (value != i)
			return errval;
	}

	errval = 3 * 1000 * 1000;

	bpf_for(i, prefill, iters) {
		key = prefix + (i % numkeys);

		ret = rb_find(rbtree, key, &value);
		if (!ret) {
			bpf_printk("Key %d already present", key);
			return errval;
		}

		errval += 1;

		ret = rb_insert(rbtree, key, i);
		if (ret) {
			bpf_printk("ITERATION %d", i);
			rb_print(rbtree);
			return errval;
		}

		rmval = i - prefill;

		errval += 1;

		ret = rb_find(rbtree, prefix + (rmval % numkeys), &value);
		if (ret)
			return errval;

		errval += 1;

		if (value != rmval)
			return errval;

		errval += 1;

		ret = rb_remove(rbtree, prefix + (rmval % numkeys));
		if (ret) {
			bpf_printk("ITERATION %d", i);
			return errval;
		}

		errval += 1;
	}

	bpf_for(i, 0, numkeys) {
		rb_remove(rbtree, prefix + i);
	}

	return 0;
}

__weak int scx_selftest_rbtree_add_remove_circular_reverse(rbtree_t __arg_arena *rbtree)
{
	const size_t iters = 110;
	const size_t prefill = 10;
	const size_t numkeys = 50;
	const size_t prefix = 500000;
	u64 value, rmval;
	int errval = 1;
	u64 key;
	int ret;
	int i;

	if (!rbtree)
		return 1;

	bpf_for(i, 0, prefill) {
		ret = rb_insert(rbtree, prefix - (i % numkeys), i);
		if (ret)
			return errval;

		errval += 1;
	}

	errval = 2 * 1000 * 1000;

	bpf_for(i, 0, prefill) {
		/* Read it back. */
		ret = rb_find(rbtree, prefix - (i % numkeys), &value);
		if (ret)
			return errval;

		if (value != i)
			return errval;
	}

	errval = 3 * 1000 * 1000;

	bpf_for(i, prefill, iters) {
		key = prefix - (i % numkeys);

		ret = rb_find(rbtree, key, &value);
		if (!ret) {
			bpf_printk("Key %d already present", key);
			return errval;
		}

		errval += 1;

		ret = rb_insert(rbtree, key, i);
		if (ret) {
			bpf_printk("error %d on insert", ret);
			rb_print(rbtree);
			return errval;
		}

		rmval = i - prefill;

		errval += 1;

		ret = rb_find(rbtree, prefix - (rmval % numkeys), &value);
		if (ret)
			return errval;

		errval += 1;

		if (value != rmval)
			return errval;

		errval += 1;

		ret = rb_remove(rbtree, prefix - (rmval % numkeys));
		if (ret)
			return errval;

		errval += 1;
	}


	errval = 4 * 1000 * 1000;
	bpf_for(i, 0, prefill) {
		ret = rb_remove(rbtree, prefix - i);
		if (ret) {
			bpf_printk("Did not remove %d, error %d", prefix - i, ret);
			return errval + i;
		}
	}

	return 0;
}

__weak int scx_selftest_rbtree_least_pop(rbtree_t __arg_arena *rbtree)
{
	const size_t keys = 10;
	u64 key, value;
	int errval = 1;
	int ret, i;

	bpf_for(i, 0, keys / 2) {
		ret = rb_insert(rbtree, i, i);
		if (ret)
			return errval;

		errval += 1;

		ret = rb_insert(rbtree, keys - 1 - i, keys - 1 - i);
		if (ret)
			return errval;

		errval += 1;

		ret = rb_least(rbtree, &key, &value);
		if (ret)
			return errval;

		errval += 1;

		if (key != 0 || value != 0)
			return errval;

		errval += 1;
	}

	errval = 1000;

	bpf_for(i, 0, keys) {
		ret = rb_least(rbtree, &key, &value);
		if (ret)
			return errval;

		errval += 1;

		if (key != i || value != i)
			return errval;

		ret = rb_pop(rbtree, &key, &value);
		if (ret)
			return errval;

		errval += 1;

		if (key != i || value != i)
			return errval;
	}

	return 0;
}

__weak int scx_selftest_rbtree_alloc_check(rbtree_t __arg_arena *rbtree)
{
	rbtree_t *alloc, *noalloc;
	rbnode_t *node;

	alloc = rb_create(RB_ALLOC, RB_DEFAULT);
	if (!alloc)
		return 1;

	noalloc = rb_create(RB_NOALLOC, RB_DEFAULT);
	if (!noalloc)
		return 2;

	/* 
	 * Can't allocate a node for a tree that allocates it itself. 
	 * Ditto for noalloc.
	 */
	node = rb_node_alloc(alloc, 0, 0);
	if (node)
		return 3;

	node = rb_node_alloc(noalloc, 0, 0);
	if (!node)
		return 4;

	/* 
	 * RB_ALLOC trees can use rb_insert, RB_NOALLOC trees can
	 * use rb_insert_node. RB_ALLOC and RB_NOALLOC trees cannot 
	 * use each other's APIs. 
	 *
	 * NOTE: This begs the question, why not different types? We
	 * want to partially share the API and that would require us
	 * to duplicate it.
	 */
	if (rb_insert(alloc, 0, 0))
		return 5;

	if (!rb_insert_node(alloc, node))
		return 6;

	if (!rb_remove_node(alloc, node))
		return 7;

	if (rb_remove(alloc, 0))
		return 8;


	if (rb_insert_node(noalloc, node))
		return 9;

	if (!rb_insert(noalloc, 0, 0))
		return 10;

	if (!rb_remove(noalloc, 0))
		return 11;

	if (rb_remove_node(noalloc, node))
		return 12;

	return 0;
}

__weak int scx_selftest_rbtree_print(rbtree_t __arg_arena *rbtree)
{
	rb_print(rbtree);
	return 0;
}

#define SCX_RBTREE_SELFTEST(suffix, rbtree) SCX_SELFTEST(scx_selftest_rbtree_ ## suffix, (rbtree))

__weak
int scx_selftest_rbtree(void)
{
	rbtree_t *standard, *update, *duplicate, *noalloc;

	standard = rb_create(RB_ALLOC, RB_DEFAULT);
	if (!standard)
		return -ENOMEM;

	update = rb_create(RB_ALLOC, RB_UPDATE);
	if (!update)
		return -ENOMEM;

	duplicate = rb_create(RB_ALLOC, RB_DUPLICATE);
	if (!duplicate)
		return -ENOMEM;

	noalloc = rb_create(RB_NOALLOC, RB_DUPLICATE);
	if (!standard)
		return -ENOMEM;

	SCX_RBTREE_SELFTEST(find_nonexistent, standard);
	SCX_RBTREE_SELFTEST(insert_one, update);
	SCX_RBTREE_SELFTEST(print, update);
	SCX_RBTREE_SELFTEST(insert_existing, standard);
	SCX_RBTREE_SELFTEST(update_existing, update);
	SCX_RBTREE_SELFTEST(duplicate, duplicate);
	SCX_RBTREE_SELFTEST(insert_ten, update);
	SCX_RBTREE_SELFTEST(insert_many, update);
	SCX_RBTREE_SELFTEST(insert_many, noalloc);
	SCX_RBTREE_SELFTEST(remove_one, standard);
	SCX_RBTREE_SELFTEST(remove_many, update);
	SCX_RBTREE_SELFTEST(remove_many, noalloc);
	SCX_RBTREE_SELFTEST(add_remove_circular_reverse, update);
	SCX_RBTREE_SELFTEST(add_remove_circular, update);
	SCX_RBTREE_SELFTEST(alloc_check, standard);

	return 0;
}
