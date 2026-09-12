/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/btree.h>

#define BTREE_MAX_DEPTH (20)

/*
 * Temporary replacements for memcpy/arrzero, which the BPF
 * LLVM backend does not support.
 */

int btnode_print(u64 depth, u64 ind, bt_node __arg_arena *btn);
int btnode_print_path(bt_node __arg_arena *btn);

__weak int arrzero(u64 __arg_arena __arena *arr, size_t nelems)
{
	int i;

	for (i = 0; i < nelems && can_loop; i++)
		arr[i] = 0ULL;

	return 0;
}

__weak int arrcpy(u64 __arg_arena __arena *dst, u64 __arg_arena __arena *src, size_t nelems)
{
	int i;

	for (i = 0; i < nelems && can_loop; i++) {
		if (src < dst)
			dst[nelems - 1 - i] = src[nelems - 1 - i];
		else
			dst[i] = src[i];
	}

	return 0;
}

static bt_node *btnode_alloc(btree_t *btree, bt_node __arg_arena *parent, u64 flags)
{
	bt_node *btn;

	do  {
		btn = btree->freelist;
		if (!btn)
			break;

	} while (cmpxchg(&btree->freelist, btn, btn->parent) != btn && can_loop);

	if (!btn)
		btn = scx_static_alloc(sizeof(*btn), 1);
	if (!btn)
		return NULL;

	arrzero(&btn->keys[0], BT_LEAFSZ);

	btn->flags = flags;
	btn->parent = parent;

	return btn;
}

static inline void btnode_free(btree_t *btree, bt_node *btn)
{
	bt_node *old;

	do {
		old = btree->freelist;
		btn->parent = old;
	} while (cmpxchg(&btree->freelist, old, btn) != old && can_loop);
}

static inline bool btnode_isroot(bt_node *btn)
{
	return btn->parent == NULL;
}

static inline bool btnode_isleaf(bt_node *btn)
{
	return btn->flags & BT_F_LEAF;
}

__weak
u64 bt_create_internal(void)
{
	btree_t __arg_arena *btree;

	btree = scx_static_alloc(sizeof(*btree), 1);
	if (!btree)
		return (u64)NULL;

	btree->root = btnode_alloc(btree, NULL, BT_F_LEAF);
	if (!btree->root) {
		/* XXX Fix once we use the buddy allocator. */
		//scx_buddy_free(buddy, btree);
		return (u64)NULL;
	}

	return (u64)btree;
}

__weak
u64 btn_node_index_by_key(bt_node __arg_arena *btn, u64 key)
{
	int i;

	for (i = 0; i < btn->numkeys && can_loop; i++) {
		/*
		 * It's strict inequality because we
		 * want nodes equal to the key to be to
		 * the _right_ of the key.
		 */
		if (key < btn->keys[i])
			return i;
	}

	return btn->numkeys;
}

static
u64 btn_node_index_by_val(bt_node *btn, bt_node *val)
{
	int i;

	for (i = 0; i <= btn->numkeys && can_loop; i++) {
		if (btn->values[i] == (u64)val)
			return i;
	}

	return btn->numkeys + 1;
}

__weak u64 btn_leaf_index(bt_node __arg_arena *btn, u64 key)
{
	int i;

	for (i = 0; i < btn->numkeys && can_loop; i++) {
		if (key <= btn->keys[i])
			break;
	}

	return i;
}

static bt_node *bt_find_leaf(btree_t __arg_arena *btree, u64 key)
{
	bt_node *btn = btree->root;
	u64 ind;

	while (!btnode_isleaf(btn) && can_loop) {
		ind = btn_node_index_by_key(btn, key);
		btn = (bt_node *)btn->values[ind];
	}

	return btn;
}

__weak
int btnode_remove_internal(bt_node __arg_arena *btn, u64 ind)
{
	volatile u64 __arena *tmp;
	u64 nelems;

	/* We can have to btn->numkeys - 1 keys and btn->numkeys values.*/
	if (unlikely(ind > btn->numkeys)) {
		bpf_printk("internal removal overflow (%ld, %ld)", ind, btn->numkeys - 1);
		return -EINVAL;
	}

	/* If we're removing the rightmost value, we don't need shifting. */
	if (ind < btn->numkeys) {
		nelems = btn->numkeys - ind;

		arrcpy(&btn->keys[ind], &btn->keys[ind + 1], nelems - 1);
		arrcpy(&btn->values[ind], &btn->values[ind + 1], nelems);
	}

	/*
	 * XXXETSAL The verifier currently complains when doing complex pointer
	 * arithmetic. Break the computation down to help it along.
	 */
	tmp = (u64 __arena *)&btn->keys;
	tmp[btn->numkeys - 1] = 0;
	tmp = (u64 __arena *)&btn->values;
	tmp[btn->numkeys] = 0;

	btn->numkeys -= 1;

	return 0;
}

/* The variable "lower" denotes whether the key is the upper or the lower bound for the value. 1*/
__weak
int btnode_add_internal(bt_node __arg_arena *btn, u64 ind, u64 key, bt_node __arg_arena *value, bool lower)
{
	u64 nelems;

	/* We can have up to BT_LEAFSZ - 1 keys and BT_LEAFSZ values.*/
	if (unlikely(ind > btn->numkeys || btn->numkeys >= BT_LEAFSZ - 1))  {
		bpf_printk("internal add overflow (%ld, %ld)", ind, btn->numkeys);
		btnode_print_path(btn);
		return -EINVAL;
	}

	if (ind < btn->numkeys) {
		nelems = btn->numkeys - ind;
		arrcpy(&btn->keys[ind + 1], &btn->keys[ind], nelems);
	}

	btn->keys[ind] = key;

	/* If the key is the upper bound of the new node, add the node to its right. */
	if (lower)
		ind += 1;

	if (ind <= btn->numkeys + 1) {
		nelems = btn->numkeys + 1 - ind;
		arrcpy(&btn->values[ind + 1], &btn->values[ind], nelems);
	}

	btn->values[ind] = (u64)value;

	btn->numkeys += 1;

	return 0;
}

static int btnode_remove_leaf(bt_node *btn, u64 ind)
{
	u64 nelems;

	if (unlikely(ind >= btn->numkeys)) {
		bpf_printk("leaf remove overflow (%ld, %ld)", ind, btn->numkeys);
		return -EINVAL;
	}

	nelems = btn->numkeys - ind;

	/* Overwrite the key with the rest of the array. */
	arrcpy(&btn->keys[ind], &btn->keys[ind + 1], nelems);
	arrcpy(&btn->values[ind], &btn->values[ind + 1], nelems);

	btn->keys[btn->numkeys] = 0;
	btn->values[btn->numkeys] = 0;
	btn->numkeys -= 1;

	return 0;
}


static int btnode_add_leaf(bt_node *btn, u64 ind, u64 key, u64 value)
{
	u64 nelems;

	if (unlikely(ind > btn->numkeys)) {
		bpf_printk("leaf add overflow (%ld,  %ld)", ind, btn->numkeys);
		return -EINVAL;
	}

	nelems = btn->numkeys - ind;

	/* Scooch the keys over and add the new one. */
	arrcpy(&btn->keys[ind + 1], &btn->keys[ind], nelems);
	arrcpy(&btn->values[ind + 1], &btn->values[ind], nelems);

	btn->keys[ind] = key;
	btn->values[ind] = value;
	btn->numkeys += 1;

	return 0;
}

u64 btnode_split_leaf(bt_node __arg_arena *btn_new, bt_node __arg_arena *btn_old)
{
	u64 off, nelems;
	u64 key;

	off = (BT_LEAFSZ / 2);
	nelems = BT_LEAFSZ - off;

	key = btn_old->keys[off];

	/* Copy the data over and wipe them from the previous node. */
	arrcpy(&btn_new->keys[0], &btn_old->keys[off], nelems);
	arrcpy(&btn_new->values[0], &btn_old->values[off], nelems);
	btn_new->numkeys = nelems;

	arrzero(&btn_old->keys[off], nelems);
	arrzero(&btn_old->values[off], nelems);
	btn_old->numkeys = off;

	return key;
}

__weak
u64 btnode_split_internal(bt_node __arg_arena *btn_new, bt_node __arg_arena *btn_old)
{
	bt_node *btn_child;
	u64 keycopies;
	u64 off;
	u64 key;
	int i;

	off = BT_LEAFSZ / 2;
	key = btn_old->keys[off];
	keycopies = BT_LEAFSZ - off - 1;

	/* We have numkeys + 1 values. */
	arrcpy(&btn_new->keys[0], &btn_old->keys[off + 1], keycopies);
	arrcpy(&btn_new->values[0], &btn_old->values[off + 1], keycopies + 1);
	btn_new->numkeys = keycopies - 1;

	/* Update the parent pointer for the children of the new node. */
	for (i = 0; i <= keycopies && can_loop; i++) {
		btn_child = (bt_node *)btn_new->values[i];
		btn_child->parent = btn_new;
	}

	/* Wipe away the removed and copied keys. */
	arrzero(&btn_old->keys[off], keycopies + 1);
	arrzero(&btn_old->values[off + 1], keycopies);
	btn_old->numkeys = off;

	return key;
}

__weak
int bt_split(btree_t __arg_arena *btree, bt_node __arg_arena *btn_old)
{
	bt_node *btn_new, *btn_root, *btn_parent;
	u64 key, ind;
	int ret;
	int i;

	/* Bounded loop to avoid spurious can_loop-related breaks. */
	bpf_for (i, 0, BTREE_MAX_DEPTH) {

		btn_parent = btn_old->parent;
		btn_new = btnode_alloc(btree, btn_parent, btn_old->flags);
		if (!btn_new)
			return -ENOMEM;

		if (btn_old->flags & BT_F_LEAF)
			key = btnode_split_leaf(btn_new, btn_old);
		else
			key = btnode_split_internal(btn_new, btn_old);

		if (btnode_isroot(btn_old)) {
			btn_root = btnode_alloc(btree, NULL, 0);
			if (!btn_root) {
				btnode_free(btree, btn_new);
				return -ENOMEM;
			}

			btn_root->keys[0] = key;
			btn_root->values[0] = (u64)btn_old;
			btn_root->values[1] = (u64)btn_new;
			btn_root->numkeys = 1;

			btn_old->parent = btn_root;
			btn_new->parent = btn_root;

			btree->root = btn_root;

			return 0;
		}

		ind = btn_node_index_by_key(btn_parent, key);

		ret = btnode_add_internal(btn_parent, ind, key, btn_new, true);
		if (ret) {
			btnode_free(btree, btn_new);
			return ret;
		}

		btn_old = btn_old->parent;
		if (btn_old->numkeys < BT_LEAFSZ - 1)
			break;
	}

	if (btn_old->numkeys >= BT_LEAFSZ - 1) {
		bpf_printk("POST SPLIT NODE IS FULL");
		return -E2BIG;
	}

	return 0;
}

__weak
int bt_insert(btree_t __arg_arena *btree, u64 key, u64 value, bool update)
{
	bt_node *btn;
	u64 ind;
	int ret;

	btn = bt_find_leaf(btree, key);
	if (!btn)
		return -EINVAL;

	/* Update in place. */
	ind = btn_leaf_index(btn, key);
	if (ind < btn->numkeys && btn->keys[ind] == key) {
		if (!update)
			return -EALREADY;

		btn->keys[ind] = key;
		btn->values[ind] = value;
		return 0;
	}

	/* Integrity check, node splitting should prevent this. */
	if (unlikely(btn->numkeys >= BT_LEAFSZ)) {
		bpf_printk("node overflow");
		return -EINVAL;
	}

	ret = btnode_add_leaf(btn, ind, key, value);
	if (ret)
		return ret;

	if (btn->numkeys < BT_LEAFSZ)
		return 0;

	return bt_split(btree, btn);
}

static inline int bt_balance_left(bt_node *parent, int ind, bt_node *left, bt_node *right)
{
	u64 key = left->keys[left->numkeys - 1];
	bt_node *value = (bt_node *)left->values[left->numkeys];
	int ret;

	ret = btnode_remove_internal(left, left->numkeys);
	if (unlikely(ret))
		return ret;

	ret = btnode_add_internal(right, 0, parent->keys[ind], value, false);
	if (unlikely(ret))
		return ret;

	value->parent = right;
	parent->keys[ind] = key;

	return 0;
}

static inline int bt_balance_right(bt_node *parent, int ind, bt_node *left, bt_node *right)
{
	u64 key = right->keys[0];
	bt_node *value = (bt_node *)right->values[0];
	int ret;

	ret = btnode_remove_internal(right, 0);
	if (unlikely(ret))
		return ret;

	ret = btnode_add_internal(left, left->numkeys, parent->keys[ind], value, true);
	if (unlikely(ret))
		return ret;

	value->parent = left;
	parent->keys[ind] = key;

	return 0;
}

static inline bool bt_balance(bt_node __arg_arena *btn, bt_node __arg_arena *parent, int ind)
{
	volatile bt_node **tmp;
	bt_node *sibling;
	int ret;

	/* Try to steal from the left sibling node to avoid merging. */

	if (ind == 0)
		goto steal_right;

	sibling = (bt_node *)parent->values[ind - 1];
	if (sibling->numkeys - 1 < BT_LEAFSZ / 2)
		goto steal_right;

	if (!bt_balance_left(parent, ind - 1, sibling, btn)) {
		if (unlikely(sibling->numkeys >= BT_LEAFSZ - 1 || btn->numkeys >= BT_LEAFSZ - 1))
			bpf_printk("BTREE ERROR: FULL NODE AFTER LEFT BALANCING");

		return true;
	}

steal_right:

	/* Failed to steal from the left node, look for the right node. */
	if (ind >= parent->numkeys)
		return false;

	tmp = (volatile bt_node **)parent->values;
	sibling = (bt_node *)tmp[ind + 1];
	if (sibling->numkeys - 1 < BT_LEAFSZ / 2)
		return false;

	ret = bt_balance_right(parent, ind, btn, sibling);
	if (unlikely(sibling->numkeys >= BT_LEAFSZ - 1 || btn->numkeys >= BT_LEAFSZ - 1))
		bpf_printk("BTREE ERROR: FULL NODE AFTER LEFT BALANCING");

	return ret == 0;
}

static inline int bt_merge(btree_t *btree, bt_node *btn, bt_node *parent, int ind)
{
	volatile u64 __arena *tmp;
	bt_node *left, *right;
	bt_node *child;
	u64 key;
	int i;

	/*
	 * Merge with our left neighbor, unless we're the leftmost node.
	 * Index is always that of the left node.
	 */
	if (ind > 0)
		ind -= 1;

	left = (bt_node *)parent->values[ind];
	right = (bt_node *)parent->values[ind + 1];
	key = parent->keys[ind];

	/* We need the internal node to still have available keys. */
	if (left->numkeys + right->numkeys + 1 >= BT_LEAFSZ - 1)
		return 0;

	left->keys[left->numkeys] = key;
	arrcpy(&left->keys[left->numkeys + 1], right->keys, right->numkeys);

	for (i = 0; i <= right->numkeys && can_loop; i++) {
		child = (bt_node *)right->values[i];
		child->parent = left;

		tmp = left->values;
		tmp[left->numkeys + 1 + i] = (u64)child;
	}

	left->numkeys += right->numkeys + 1;

	btnode_remove_internal(parent, ind + 1);
	btnode_free(btree, right);

	if (unlikely(left->numkeys == BT_LEAFSZ - 1))
		bpf_printk("BTREE ERROR: FULL NODE AFTER MERGING");

	return 0;
}

__weak
int bt_rebalance(btree_t __arg_arena *btree, bt_node __arg_arena *parent, bt_node __arg_arena *btn)
{
	int ret;
	int ind;

	ind = btn_node_index_by_val(parent, btn);
	if (unlikely(ind > parent->numkeys))
		return -EINVAL;

	/* Try to avoid merging. */
	if (bt_balance(btn, parent, ind))
		return 0;

	ret = bt_merge(btree, btn, parent, ind);
	if (ret)
		return ret;

	if (unlikely(btn->numkeys >= BT_LEAFSZ - 1))
		bpf_printk("BTREE ERROR: FULL INTERNAL NODE AFTER REBALANCE");

	return 0;
}

__weak
int bt_remove(btree_t __arg_arena *btree, u64 key)
{
	bt_node *btn, *parent;
	u64 ind;
	int ret;

	btn = bt_find_leaf(btree, key);
	if (!btn)
		return -EINVAL;

	/* Update in place. */
	ind = btn_leaf_index(btn, key);
	if (unlikely(ind >= btn->numkeys))
		return -ENOENT;

	ret = btnode_remove_leaf(btn, ind);
	if (ret)
		return ret;

	/* Do not load balance leaves. */
	if (btn->numkeys || btnode_isroot(btn))
		return 0;

	parent = btn->parent;
	ind = btn_node_index_by_val(parent, btn);
	if (unlikely(ind > parent->numkeys || parent->values[ind] != (u64)btn))
		return -EINVAL;

	ret = btnode_remove_internal(parent, ind);
	if (unlikely(ret))
		return ret;

	btnode_free(btree, btn);

	btn = parent;

	while (!btnode_isroot(btn) && btn->numkeys < BT_LEAFSZ / 2 && can_loop) {
		parent = btn->parent;

		ret = bt_rebalance(btree, parent, btn);
		if (ret)
			return ret;

		btn = parent;
	}

	/* Root switch if the root has a single child. */
	if (btnode_isroot(btn) && !btnode_isleaf(btn) && !btn->numkeys) {
		btree->root = (bt_node *)btn->values[0];
		btree->root->parent = NULL;
		btnode_free(btree, btn);

	}

	return 0;
}

__weak
int bt_find(btree_t __arg_arena *btree, u64 key, u64 *value)
{
	bt_node *btn = bt_find_leaf(btree, key);
	u64 ind;

	if (unlikely(!value))
		return -EINVAL;

	ind = btn_leaf_index(btn, key);
	if (ind == btn->numkeys || btn->keys[ind] != key)
		return -EINVAL;

	*value = btn->values[ind];

	return 0;
}

__weak
int bt_destroy(btree_t __arg_arena *btree)
{
	return -EOPNOTSUPP;
}

__weak
int btnode_print(u64 depth, u64 ind, bt_node __arg_arena *btn)
{
	bool isleaf = btnode_isleaf(btn);

	bpf_printk("==== [%ld/%ld] BTREE %s %p PARENT %p====", depth, ind,
			isleaf ? "LEAF" : "NODE", btn, btn->parent);

	/* Hardcode it for now make it nicer once we use streams. */
	_Static_assert(BT_LEAFSZ == 10, "Unexpected btree fanout");

	bpf_printk("[KEY] %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld",
			btn->keys[0], btn->keys[1], btn->keys[2],
			btn->keys[3], btn->keys[4], btn->keys[5],
			btn->keys[6], btn->keys[7], btn->keys[8],
			btn->keys[9]);
	if (isleaf) {
		bpf_printk("[VAL] %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld",
				btn->values[0], btn->values[1], btn->values[2],
				btn->values[3], btn->values[4], btn->values[5],
				btn->values[6], btn->values[7], btn->values[8],
				btn->values[9]);
	} else {
		/*
		 * We're typecasting to pointers to actually get the value we
		 * see during execution.
		 */
		bpf_printk("[VAL] 0x%p 0x%p 0x%p 0x%p 0x%p 0x%p 0x%p 0x%p 0x%p 0x%p",
				(bt_node *)btn->values[0], (bt_node *)btn->values[1],
				(bt_node *)btn->values[2], (bt_node *)btn->values[3],
				(bt_node *)btn->values[4], (bt_node *)btn->values[5],
				(bt_node *)btn->values[6], (bt_node *)btn->values[7],
				(bt_node *)btn->values[8], (bt_node *)btn->values[9]);
	}

	bpf_printk("");

	return 0;
}

__weak
int btnode_print_path(bt_node __arg_arena *btn)
{
	int i;

	for (i = 0; btn && can_loop; i++) {
		btnode_print(i, 0, btn);
		btn = btn->parent;
	}

	return 0;
}

__weak
int bt_print(btree_t __arg_arena *btree)
{
	const int BT_PRINT_MAXITER = 100;
	bt_node *btn = btree->root;
	u8 stack[BT_MAXLVL_PRINT];
	u8 depth;
	int i, j;
	u8 ind;

	depth = 0;
	ind = 0;

	bpf_printk("=== BPF PRINTK START ===");

	btnode_print(depth, ind, btn);

	/* Even with can_loop, the verifier doesn't like infinite loops. */
	bpf_for(i, 0, BT_PRINT_MAXITER) {
		/* If we can, go to the next unvisited child. */
		if (!btnode_isleaf(btn) && ind <= btn->numkeys) {

			if (btn->numkeys == 0)
				break;

			if (depth < 0 || depth >= BT_MAXLVL_PRINT)
				return 0;

			btn = (bt_node *)btn->values[ind];
			btnode_print(depth, ind, btn);

			stack[depth++] = ind + 1;
			ind = 0;

			if (depth >= BT_MAXLVL_PRINT) {
				bpf_printk("Max level reached, aborting btree print.");
				return 0;
			}

			continue;
		}

		/* Otherwise, go as far up as possible. */
		bpf_for (j, 0, BT_MAXLVL_PRINT) {
			if (!btnode_isleaf(btn) && ind <= btn->numkeys)
				break;

			depth -= 1;
			if (depth < 0 || depth >= BT_MAXLVL_PRINT)
				return 0;

			ind = stack[depth];
			btn = btn->parent;

		}
	}

	bpf_printk("=== BPF PRINTK END ===");

	return 0;
}
