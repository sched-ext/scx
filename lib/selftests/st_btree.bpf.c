#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/btree.h>

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

__weak int scx_selftest_btree_find_nonexistent(btree_t __arg_arena *btree)
{
	u64 key = 0xdeadbeef;
	u64 value = 0;
	int ret;

	if (!btree)
		return 1;

	/* Should return -EINVAL */
	ret = bt_find(btree, key, &value);
	if (!ret)
		return 2;

	return 0;
}

__weak int scx_selftest_btree_insert_existing(btree_t __arg_arena *btree)
{
	u64 key = 525252;
	u64 value = 24;
	int ret;

	if (!btree)
		return 1;

	/* Should return -EINVAL. */
	ret = bt_insert(btree, key, value, false);
	if (ret)
		return 2;

	/* Should return -EALREADY. */
	ret = bt_insert(btree, key, value, false);
	if (ret != -EALREADY) {
		return 3;
	}

	return 0;
}

__weak int scx_selftest_btree_update_existing(btree_t __arg_arena *btree)
{
	u64 key = 33333;
	u64 value;
	int ret;

	if (!btree)
		return 1;

	/* Should return -EINVAL. */
	value = 52;
	ret = bt_insert(btree, key, value, true);
	if (ret)
		return 2;

	ret = bt_find(btree, key, &value);
	if (ret)
		return 3;

	if (value != 52)
		return 4;

	value = 65;

	/* Should succeed. */
	ret = bt_insert(btree, key, value, true);
	if (ret)
		return 5;

	/* Should be updated. */
	ret = bt_find(btree, key, &value);
	if (ret)
		return 6;

	if (value != 65)
		return 7;

	return 0;
}


__weak int scx_selftest_btree_insert_one(btree_t __arg_arena *btree)
{
	u64 key = 202020;
	u64 value = 0xbadcafe;
	int ret;

	ret = bt_insert(btree, key, value, true);
	if (ret)
		return 1;

	ret = bt_find(btree, key, &value);
	if (ret)
		return 2;

	if (value != 0xbadcafe)
		return 3;

	return 0;
}

__weak int scx_selftest_btree_insert_ten(btree_t __arg_arena *btree)
{
	u64 key, value;
	int ret, i;

	if (!btree)
		return 1;

	for (i = 0; i < 10 && can_loop; i++) {
		key = keys[i];
		ret = bt_insert(btree, key, 2 * key, true);
		if (ret)
			return 2 + 3 * i;

		/* Read it back. */
		ret = bt_find(btree, key, &value);
		if (ret)
			return 2 + 3 * i + 1;

		if (value != 2 * key)
			return 2 + 3 * i + 2;
	}

	/* Go find all inserted pairs. */
	for (i = 0; i < 10 && can_loop; i++) {
		key = keys[i];

		ret = bt_find(btree, key, &value);
		if (ret)
			return 35 + 2 * i;

		if (value != 2 * key)
			return 35 + 2 * i + 1;
	}

	return 0;
}

__weak int scx_selftest_btree_insert_many(btree_t __arg_arena *btree)
{
	const size_t numkeys = sizeof(keys) / sizeof(keys[0]);
	u64 key, value;
	int ret;
	int i;

	if (!btree)
		return 1;

	for (i = 0; i < numkeys && can_loop; i++) {
		key = keys[i];
		ret = bt_insert(btree, key, 2 * key, true);
		if (ret)
			return 2 + 3 * i;

		/* Read it back. */
		ret = bt_find(btree, key, &value);
		if (ret)
			return 2 + 3 * i + 1;

		if (value != 2 * key)
			return 2 + 3 * i + 2;
	}

	/* Go find all inserted pairs. */
	for (i = 0; i < numkeys && can_loop; i++) {
		key = keys[i];

		ret = bt_find(btree, key, &value);
		if (ret)
			return 302 + 2 * i;

		if (value != 2 * key)
			return 302 + 2 * i + 1;
	}

	return 0;
}

__weak int scx_selftest_btree_remove_one(btree_t __arg_arena *btree)
{
	u64 key = 20, value = 5, newvalue;
	int ret;

	if (!btree)
		return 1;

	ret = bt_find(btree, key, &newvalue);
	if (!ret)
		return 2;

	ret = bt_insert(btree, key, value, false);
	if (ret)
		return 3;

	ret = bt_find(btree, key, &newvalue);
	if (ret || value != newvalue)
		return 4;

	ret = bt_remove(btree, key);
	if (ret)
		return 5;

	ret = bt_find(btree, key, &newvalue);
	if (!ret)
		return 6;



	return 0;
}

__weak int scx_selftest_btree_remove_many(btree_t __arg_arena *btree)
{
	const size_t numkeys = sizeof(morekeys) / sizeof(morekeys[0]);
	u64 key, value;
	int errval = 1;
	int ret;
	int i;

	if (!btree)
		return 1;

	for (i = 0; i < numkeys && can_loop; i++) {
		key = morekeys[i];
		ret = bt_insert(btree, key, 2 * key, true);
		if (ret)
			return errval;

		errval += 1;

		/* Read it back. */
		ret = bt_find(btree, key, &value);
		if (ret)
			return errval;

		errval += 1;

		if (value != 2 * key)
			return errval;

		errval += 1;
	}

	/* Go find all inserted pairs. */
	for (i = 0; i < numkeys && can_loop; i++) {
		key = morekeys[i];

		ret = bt_find(btree, key, &value);
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
		ret = bt_remove(btree, key);
		if (ret) {
			bpf_printk("Failed to remove %ld", key);
			return errval;
		}

		errval += 1;

		/* Read it back. */
		ret = bt_find(btree, key, &value);
		if (!ret)
			return errval;

		errval += 1;
	}


	/* Ensure removed pairs are missing and added pairs are present. */
	for (i = 0; i < numkeys && can_loop; i += 2) {
		/* Even keys should be missing */
		key = morekeys[i];
		ret = bt_find(btree, key, &value);
		if (!ret)
			return errval;

		if (i + 1 >= numkeys)
			break;

		key = morekeys[i + 1];

		ret = bt_find(btree, key, &value);
		if (ret)
			return errval;

		errval += 1;

		if (value != 2 * key)
			return errval;

		errval += 1;

	}

	return 0;
}


#define SCX_BTREE_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_btree_ ## suffix, btree)

__weak
int scx_selftest_btree(void)
{
	btree_t __arg_arena *btree;

	btree = bt_create();
	if (!btree)
		return -ENOMEM;

	/* Keep it in to check for verification failures. */
	bt_print(btree);

	SCX_BTREE_SELFTEST(find_nonexistent);
	SCX_BTREE_SELFTEST(insert_one);
	SCX_BTREE_SELFTEST(insert_existing);
	SCX_BTREE_SELFTEST(update_existing);
	SCX_BTREE_SELFTEST(insert_ten);
	SCX_BTREE_SELFTEST(insert_ten);
	SCX_BTREE_SELFTEST(insert_many);
	SCX_BTREE_SELFTEST(remove_one);
	SCX_BTREE_SELFTEST(remove_many);

	return 0;
}
