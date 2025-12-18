/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include <lib/sdt_task.h>
#include <lib/rbtree.h>

int rb_integrity_check(rbtree_t __arg_arena *rbtree);
void rbnode_print(size_t depth, rbnode_t *rbn);
static int rbnode_replace(rbtree_t *rbtree, rbnode_t *existing, rbnode_t *replacement);

#define INTEGRITY_CHECK(rbtree) do {						\
	int ret = rb_integrity_check(rbtree);					\
	if (ret) {								\
		bpf_printk("%s:%d integrity failure", __func__, __LINE__);	\
		rb_print(rbtree);						\
		return -EINVAL;							\
	}									\
} while (0)

u64 rb_create_internal(enum rbtree_alloc alloc, enum rbtree_insert_mode insert)
{
	rbtree_t *rbtree;

	rbtree = (rbtree_t *)scx_static_alloc(sizeof(*rbtree), 1);
	if (!rbtree)
		return (u64)NULL;

	rbtree->root = NULL;
	rbtree->alloc = alloc;
	rbtree->insert = insert;

	return (u64)rbtree;
}

__weak
int rb_destroy(rbtree_t *rbtree)
{
	int ret;

	while (rbtree->root && can_loop) {
		ret = rb_remove(rbtree, rbtree->root->key);
		if (ret)
			return ret;
	}

	return 0;
}

static inline int rbnode_dir(rbnode_t *node)
{
	/* Arbitrarily choose a direction for the root. */
	if (unlikely(!node->parent))
		return 0;

	return (node->parent->left == node) ? 0 : 1;
}

int rbnode_rotate(rbtree_t __arg_arena *rbtree, rbnode_t __arg_arena *node, int dir)
{
	rbnode_t *tmp, *parent;
	int parentdir;

	parent = node->parent;
	if (parent)
		parentdir = rbnode_dir(node);

	/* If we're doing a root change, are we the root? */
	if (unlikely(!parent && rbtree->root != node))
		return -EINVAL;

	/*
	 * Does the node we're turning into the root into exist?
	 * Note that the new root is on the opposite side of the
	 * rotation's direction.
	 */
	tmp = node->child[1 - dir];
	if (unlikely(!tmp))
		return -EINVAL;

	/* Steal the closest child of the new root. */
	node->child[1 - dir] = tmp->child[dir];
	if (node->child[1 - dir])
		node->child[1 - dir]->parent = node;

	/* Put the node below the new root.*/
	tmp->child[dir] = node;
	node->parent = tmp;

	tmp->parent = parent;
	if (parent)
		parent->child[parentdir] = tmp;
	else
		rbtree->root = tmp;

	return 0;
}

static
rbnode_t *rbnode_find(rbnode_t *subtree, u64 key)
{
	rbnode_t *node = subtree;
	int dir;

	if (!subtree)
		return NULL;

	while (can_loop) {
		if (node->key == key)
			break;

		dir = (key < node->key) ? 0 : 1;

		if (!node->child[dir])
			break;

		node = node->child[dir];
	}

	return node;
}

static
rbnode_t *rbnode_least_upper_bound(rbnode_t *subtree, uint64_t key)
{
	rbnode_t *node = subtree;
	int dir;

	if (!subtree)
		return NULL;

	while (can_loop) {
		dir = (key <= node->key) ? 0 : 1;

		if (!node->child[dir])
			break;

		node = node->child[dir];
	}

	return node;
}

__weak
int rb_find(rbtree_t __arg_arena *rbtree, u64 key, u64 *value)
{
	rbnode_t *node = rbnode_find(rbtree->root, key);

	if (unlikely(!rbtree))
		return -EINVAL;

	if (unlikely(!value))
		return -EINVAL;

	if (!node || node->key != key)
		return -EINVAL;

	*value = node->value;

	return 0;
}

static inline rbnode_t *rb_node_alloc_common(rbtree_t __arg_arena *rbtree, u64 key, u64 value)
{
	rbnode_t *rbnode;
	volatile rbnode_t *node;

	/* We can't allocate an node for an rbtree that does the allocations itself. */

	do  {
		rbnode = rbtree->freelist;
		if (!rbnode)
			break;

	} while (cmpxchg(&rbtree->freelist, rbnode, rbnode->parent) != rbnode && can_loop);

	if (!rbnode)
		rbnode = (rbnode_t *)scx_static_alloc(sizeof(*rbnode), 1);
	if (!rbnode)
		return NULL;

	/*
	 * XXXETSAL:  Use a second volatile variable because the verifier demotes
	 * the rbnode variable to a scalar during cmpxchg.
	 */

	node = (rbnode_t *)rbnode;

	node->left = NULL;
	node->right = NULL;
	node->parent = NULL;

	node->key = key;
	node->value = value;
	node->is_red = true;

	return rbnode;
}

__weak
u64 rb_node_alloc_internal(rbtree_t __arg_arena *rbtree, u64 key, u64 value)
{
	if (rbtree->alloc == RB_ALLOC)
		return (u64)NULL;

	return (u64)rb_node_alloc_common(rbtree, key, value);
}

__weak __attribute__((always_inline))
int rb_node_free(rbtree_t __arg_arena *rbtree, rbnode_t __arg_arena *rbnode)
{
	rbnode_t *old;

	do {
		old = rbtree->freelist;
		rbnode->parent = old;
	} while (cmpxchg(&rbtree->freelist, old, rbnode) != old && can_loop);

	return 0;
}

static __attribute__((always_inline))
int rb_node_insert(rbtree_t __arg_arena *rbtree, rbnode_t __arg_arena *node)
{
	rbnode_t *grandparent, *parent = rbtree->root;
	u64 key = node->key;
	rbnode_t *uncle;
	int dir;
	int ret;

	if (unlikely(!rbtree))
		return -EINVAL;

	if (!parent) {
		rbtree->root = node;
		return 0;
	}

	if (rbtree->insert != RB_DUPLICATE)
		parent = rbnode_find(parent, key);
	else
		parent = rbnode_least_upper_bound(parent, key);

	if (key == parent->key && rbtree->insert != RB_DUPLICATE) {
		if (rbtree->insert == RB_UPDATE) {
			/*
			 * Replace the old node with the new one.
			 * Free up the old node.
			 */

			ret = rbnode_replace(rbtree, parent, node);
			if (ret)
				return ret;

			/* Only free if called from rb_insert_node. */
			if (rbtree->alloc == RB_ALLOC)
				rb_node_free(rbtree, parent);

			return 0;
		}

		/* Otherwise it's RB_DEFAULT. */
		return -EALREADY;
	}

	node->parent = parent;
	/* Also works if key == parent->key. */
	if (key <= parent->key)
		parent->left = node;
	else
		parent->right = node;

	while (can_loop) {
		parent = node->parent;
		if (!parent)
			return 0;

		if (!parent->is_red)
			return 0;

		grandparent = parent->parent;
		if (!grandparent) {
			parent->is_red = false;
			return 0;
		}

		dir = rbnode_dir(parent);
		uncle = grandparent->child[1 - dir];

		if (!uncle || !uncle->is_red) {
			if (node == parent->child[1 - dir]) {
				rbnode_rotate(rbtree, parent, dir);
				node = parent;
				parent = grandparent->child[dir];
			}

			rbnode_rotate(rbtree, grandparent, 1 - dir);
			parent->is_red = false;
			grandparent->is_red = true;

			return 0;
		}

		/* Uncle is red. */

		parent->is_red = false;
		uncle->is_red = false;
		grandparent->is_red = true;

		node = grandparent;
	}

	return 0;
}

int rb_insert_node(rbtree_t __arg_arena *rbtree, rbnode_t __arg_arena *node)
{
	volatile int i = 0;

	if (unlikely(!rbtree))
		return -EINVAL;

	if (unlikely(rbtree->alloc == RB_ALLOC))
		return -EINVAL;

	node->is_red = true;
	/* XXXETSAL: Variable i is not used. It is only there to 
	 * prevent the compiler from causing verification failures 
	 * in its attempt to optimize the series of assignments
	 * to the rbnode_t * into a single operation.
	 */

	node->left = NULL;
	i += 1;
	node->right = NULL;
	i += 1;
	node->parent = NULL;

	return rb_node_insert(rbtree, node);
}

__weak
int rb_insert(rbtree_t __arg_arena *rbtree, u64 key, u64 value)
{
	rbnode_t *node;
	int ret;

	if (unlikely(!rbtree))
		return -EINVAL;

	if (unlikely(rbtree->alloc != RB_ALLOC))
		return -EINVAL;

	node = rb_node_alloc_common(rbtree, key, value);
	if (!node)
		return -ENOMEM;

	ret = rb_node_insert(rbtree, node);
	if (ret) {
		rb_node_free(rbtree, node);
		return ret;
	}

	return 0;
}

static inline rbnode_t *rbnode_least(rbnode_t *subtree)
{
	while (subtree->left && can_loop)
		subtree = subtree->left;

	return subtree;
}

__weak int rb_least(rbtree_t __arg_arena *rbtree, u64 *key, u64 *value)
{
	rbnode_t *least;
	if (!rbtree->root)
		return -ENOENT;

	least = rbnode_least(rbtree->root);
	if (key)
		*key = least->key;
	if (value)
		*value = least->value;

	return 0;
}


/*
 * If we are referencing ourselves, a and b have a parent-child relation,
 * and we should be pointing at the other node instead.
 */
static inline void rbnode_fixup_pointers(rbnode_t *a, rbnode_t *b)
{
#define fixup(n1, n2, member) do { if (n1->member == n1) n1->member = n2; } while (0)
	fixup(a, b, left);
	fixup(a, b, right);
	fixup(a, b, parent);
#undef fixup
}

static inline void rbnode_swap_values(rbnode_t *a, rbnode_t *b)
{
#define swap(n1, n2, tmp) do { (tmp) = (n1); (n1) = (n2); (n2) = (tmp); } while (0)
	rbnode_t *tmpnode;
	u64 tmp;

	/* Swap the pointers. */
	swap(a->is_red, b->is_red, tmp);

	swap(a->left, b->left, tmpnode);
	swap(a->right, b->right, tmpnode);
	swap(a->parent, b->parent, tmpnode);
#undef swap

	/* Account for the nodes being parent and child. */
	rbnode_fixup_pointers(b, a);
	rbnode_fixup_pointers(a, b);
}

static inline void rbnode_adjust_neighbors(rbtree_t *rbtree, rbnode_t *node, int dir)
{
	if (node->left)
		node->left->parent = node;
	if (node->right)
		node->right->parent = node;

	if (node->parent) {
		node->parent->child[dir] = node;
		return;
	}

	rbtree->root = node;
}

/*
 * Directly replace an existing node with a replacement. The replacement node
 * should not already be in the tree.
 */
static int rbnode_replace(rbtree_t *rbtree, rbnode_t *existing, rbnode_t *replacement)
{
	int dir = 0;

	if (unlikely(replacement->parent || replacement->left || replacement->right))
		return -EINVAL;

	if (existing->parent)
		dir = rbnode_dir(existing);

	replacement->is_red = existing->is_red;
	replacement->left = existing->left;
	replacement->right = existing->right;
	replacement->parent = existing->parent;

	/* Fix up the new node's neighbors. */
	rbnode_adjust_neighbors(rbtree, replacement, dir);

	return 0;
}

/*
 * Switch two nodes in the tree in place. This is useful during node deletion.
 * This is more involved than switching the values of the two nodes because we
 * must update all tree pointers.
 */
static void rbnode_switch(rbtree_t *rbtree, rbnode_t *a, rbnode_t *b)
{
	int adir = 0, bdir = 0;

	/*
	 * Store the direction in the parent because we will not
	 * be able to recompute it once we start swapping values.
	 */
	if (a->parent)
		adir = rbnode_dir(a);

	if (b->parent)
		bdir = rbnode_dir(b);

	rbnode_swap_values(a, b);

	/*
	 * Fix up the pointers from the children/parent to the
	 * new nodes.
	 */
	rbnode_adjust_neighbors(rbtree, a, bdir);
	rbnode_adjust_neighbors(rbtree, b, adir);
}

static inline int rbnode_remove_node_single_child(rbtree_t *rbtree, rbnode_t *node, bool free)
{
	rbnode_t *child;
	int dir;

	if (unlikely(node->is_red)) {
		bpf_printk("Node unexpectedly red");
		return -EINVAL;
	}

	child = node->left ? node->left : node->right;
	if (unlikely(!child->is_red)) {
		bpf_printk("Only child is black");
		return -EINVAL;
	}

	/*
	 * Since it's the immediate child, we can just
	 * remove the parent.
	 */
	child->parent = node->parent;

	if (node->parent) {
		dir = rbnode_dir(node);
		node->parent->child[dir] = child;
	} else {
		rbtree->root = child;
	}

	/* Color the child black. */
	child->is_red = false;

	/* Only free if called from rb_remove. */
	if (free)
		rb_node_free(rbtree, node);

	return 0;
}

static inline bool rbnode_has_red_children(rbnode_t *node)
{
	if (node->left && node->left->is_red)
		return true;

	return node->right && node->right->is_red;
}

static __attribute__((always_inline))
int rb_node_remove(rbtree_t __arg_arena *rbtree, rbnode_t __arg_arena *node, bool free)
{
	rbnode_t *parent, *sibling, *close_nephew, *distant_nephew;
	rbnode_t *replace, *initial;
	bool is_red;
	int dir;

	/* Both children present, replace with next largest key. */
	if (node->left && node->right) {
		/*
		 * Swap the node itself instead of just the
		 * key/value pair to account for nodes embedded
		 * in other structs.
		 */

		replace = rbnode_least(node->right);
		rbnode_switch(rbtree, replace, node);

		/*
		 * FALLTHROUGH: We moved the node we are removing to
		 * the leftmost position of the subtree. We can now
		 * remove it as if it was always where we moved it to.
		 */
	}

	initial = node;

	/* Only one child present, replace with child and paint it black. */
	if (!node->left != !node->right)
		return rbnode_remove_node_single_child(rbtree, node, free);

	/* (!node->left && !node->right) */

	parent = node->parent;
	if (!parent) {
		rbtree->root = NULL;
		if (free)
			rb_node_free(rbtree, node);
		return 0;
	}

	dir = rbnode_dir(node);
	parent->child[dir] = NULL;
	is_red = node->is_red;

	if (free)
		rb_node_free(rbtree, node);

	/* If we removed a red node, we did not unbalance the tree.*/
	if (is_red)
		return 0;

	sibling = parent->child[1 - dir];
	if (unlikely(!sibling)) {
		bpf_printk("rbtree: removed black node has no sibling");
		return -EINVAL;
	}

	/*
	 * We removed a black node, causing a change in path
	 * weight. Start rebalancing. The invariant is that
	 * all paths going through the node are shortened
	 * by one, and the current node is black.
	 */
	while (can_loop) {

		/* Balancing reached the root, there can be no imbalance. */
		if (!parent)
			return 0;

		/*
		 * We already determined the dir, either above or
		 * at the end of the loop.
		 */

		/*
		 * If we have no sibling, the tree was
		 * already unbalanced.
		 */
		sibling = parent->child[1 - dir];
		if (unlikely(!sibling)) {
			bpf_printk("rbtree: removed black node has no sibling");
			return -EINVAL;
		}

		/* Sibling is red, turn it into the grandparent. */
		if (sibling->is_red) {
			/*
			 * Sibling is red. Transform the tree to turn
			 * the sibling into the parent's position, and
			 * repaint them. This does not balance the tree
			 * but makes it so we know the sibling is black
			 * and so can use the transformations to balance.
			 */
			rbnode_rotate(rbtree, parent, dir);
			parent->is_red = true;
			sibling->is_red = false;

			/* Our new sibling is now the close nephew. */
			sibling = parent->child[1 - dir];
			/* If sibling has any red siblings, break out. */
			if (rbnode_has_red_children(sibling))
				break;

			/* We can repaint the sibling and parent, we're done. */
			sibling->is_red = true;
			parent->is_red = false;

			return 0;
		}

		/* Sibling guaranteed to be black. If it has red children, break out. */
		if (rbnode_has_red_children(sibling))
			break;

		/*
		 * Both sibling and children are black. If parent is red, swap
		 * colors with the sibling. Otherwise
		 */
		if (parent->is_red) {
			parent->is_red = false;
			sibling->is_red = true;
			return 0;
		}

		/*
		 * Parent, sibling, and all its children are black. Repaint the sibling.
		 * This shortens the paths through it, so pop up a level in the
		 * tree and repeat the balancing.
		 */
		sibling->is_red = true;
		node = parent;
		parent = node->parent;
		dir = rbnode_dir(node);
	}

	if (node != initial) {
		dir = rbnode_dir(node);
		parent = node->parent;
		sibling = parent->child[1-dir];
	}
	/*
	 * Almost there. We know between the parent, sibling,
	 * and nephews only one or two of the nephews are red. If
	 * it is the close one, rotate it to the sibling position,
	 * paint it black, and paint the previous sibling red.
	 */

	close_nephew = sibling->child[dir];
	distant_nephew = sibling->child[1 - dir];

	/*
	 * If the distant red nephew is not red, rotate
	 * and repaint. We need the distant nephew
	 * to be red. We know the close nephew is red
	 * because at least one of them are, so the
	 */
	if (!distant_nephew || !distant_nephew->is_red) {
		rbnode_rotate(rbtree, sibling, 1 - dir);
		sibling->is_red = true;
		close_nephew->is_red = false;
		distant_nephew = sibling;
		sibling = close_nephew;
	}

	/*
	 * We now know it's the close nephew that's red.
	 * Rotate the sibling into our parent's position and paint
	 * both black.
	 */

	rbnode_rotate(rbtree, parent, dir);
	sibling->is_red = parent->is_red;
	parent->is_red = false;
	distant_nephew->is_red = false;

	return 0;
}

__weak
int rb_remove_node(rbtree_t __arg_arena *rbtree, rbnode_t __arg_arena *node)
{
	if (unlikely(!rbtree))
		return -EINVAL;

	if (unlikely(rbtree->alloc == RB_ALLOC))
		return -EINVAL;

	return rb_node_remove(rbtree, node, false);
}

__weak
int rb_remove(rbtree_t __arg_arena *rbtree, u64 key)
{
	rbnode_t *node;

	if (unlikely(!rbtree))
		return -EINVAL;

	if (unlikely(rbtree->alloc != RB_ALLOC))
		return -EINVAL;

	if (!rbtree->root)
		return -ENOENT;

	node = rbnode_find(rbtree->root, key);
	if (!node || node->key != key)
		return -ENOENT;

	return rb_node_remove(rbtree, node, true);
}

__weak
int rb_pop(rbtree_t __arg_arena *rbtree, u64 *key, u64 *value)
{
	rbnode_t *node;

	if (unlikely(!rbtree))
		return -EINVAL;

	if (!rbtree->root)
		return -ENOENT;

	node = rbnode_least(rbtree->root);
	if (unlikely(!node))
		return -ENOENT;

	if (key)
		*key = node->key;
	if (value)
		*value = node->value;

	return rb_remove_node(rbtree, node);
}

inline void rbnode_print(size_t depth, rbnode_t *rbn)
{
	bpf_printk("[DEPTH %d] %p (%s) PARENT %p", depth, rbn, rbn->is_red ? "red" : "black", rbn->parent);
	bpf_printk("\tKV (%ld, %ld) LEFT %p RIGHT %p]\n", rbn->key, rbn->value, rbn->left, rbn->right);
}

enum rb_print_state {
	RB_NONE_VISITED,
	RB_LEFT_VISITED,
	RB_RIGHT_VISITED,
};

__weak
enum rb_print_state rb_print_next_state(rbnode_t __arg_arena *rbnode, enum rb_print_state state, rbnode_t **next)
{
	if (unlikely(!next))
		return RB_NONE_VISITED;

	switch (state) {
	case RB_NONE_VISITED:
		if (rbnode->left) {
			*next = rbnode->left;
			state = RB_LEFT_VISITED;
			break;
		}

		/* FALLTHROUGH */

	case RB_LEFT_VISITED:
		if (rbnode->right) {
			*next = rbnode->right;
			state = RB_RIGHT_VISITED;
			break;
		}

		/* FALLTHROUGH */

	default:
		*next = NULL;
		state = RB_RIGHT_VISITED;
	}

	return state;
}

/*
 * Pass everything by reference. This is to avoid arcane verification failures
 * caused by embedding this code in the main rb_print call.
 */
__weak
int rb_print_pop_up(rbnode_t **rbnode, u8 *depthp, enum rb_print_state (*stack)[RB_MAXLVL_PRINT], enum rb_print_state *state)
{
	/*
	 * XXXETSAL If we do marked as volatile, the compiler reorders
	 * the assignment to depth to be after the comparison by reusing
	 * *depthp. This in turn relaxes the range of depth's values
	 * enough to fail verification.
	 */
	volatile u8 depth;
	int j;

	if (unlikely(!rbnode || !depthp || !stack || !state))
		return -EINVAL;

	depth = *depthp;

	bpf_for (j, 0, RB_MAXLVL_PRINT) {
		if (*state != RB_RIGHT_VISITED)
			break;

		depth -= 1;
		if (depth < 0 || depth >= RB_MAXLVL_PRINT)
			break;

		*state = (*stack)[depth % RB_MAXLVL_PRINT];
		*rbnode = (*rbnode)->parent;
	}

	*depthp = depth;

	return 0;
}

__weak
int rb_print(rbtree_t __arg_arena *rbtree)
{
	enum rb_print_state stack[RB_MAXLVL_PRINT];
	rbnode_t *rbnode = rbtree->root;
	enum rb_print_state state;
	rbnode_t *next;
	u8 depth;
	int ret;

	if (unlikely(!rbtree))
		return -EINVAL;

	depth = 0;
	state = RB_NONE_VISITED;

	bpf_printk("=== BPF PRINTK START ===");

	/* Even with can_loop, the verifier doesn't like infinite loops. */
	while (can_loop) {
		if (state == RB_NONE_VISITED)
			rbnode_print(depth, rbnode);

		/* Find which child to traverse next. */
		state = rb_print_next_state(rbnode, state, &next);

		/* Child found. Store the node state and go on. */
		if (next) {
			if (depth < 0 || depth >= RB_MAXLVL_PRINT)
				return 0;

			stack[depth++] = state;

			rbnode = next;
			state = RB_NONE_VISITED;

			continue;
		}

		/* Otherwise, go as far up as possible. */
		ret = rb_print_pop_up(&rbnode, &depth, &stack, &state);
		if (ret)
			return -EINVAL;

		if (depth < 0 || depth >= RB_MAXLVL_PRINT) {
			bpf_printk("=== BPF PRINTK END (depth %d)===", depth);
			return 0;
		}

	}

	bpf_printk("=== BPF PRINTK END ===");

	return 0;
}

__weak
int rb_integrity_check(rbtree_t __arg_arena *rbtree)
{
	enum rb_print_state stack[RB_MAXLVL_PRINT];
	rbnode_t *rbnode = rbtree->root;
	enum rb_print_state state;
	rbnode_t *next;
	u8 depth;
	int ret;

	if (unlikely(!rbtree))
		return -EINVAL;

	if (!rbtree->root)
		return 0;

	depth = 0;
	state = RB_NONE_VISITED;

	/* Even with can_loop, the verifier doesn't like infinite loops. */
	while (can_loop) {
		if (rbnode->parent && rbnode->parent->left != rbnode
			&& rbnode->parent->right != rbnode) {
			bpf_printk("WARNING: Inconsistent tree. Parent %p has no child %p", rbnode->parent, rbnode);
			return -EINVAL;
		}

		if (rbnode->parent == rbnode) {
			bpf_printk("WARNING: Inconsistent tree, node %p is its own parent", rbnode);
			return -EINVAL;
		}

		if (rbnode->left == rbnode) {
			bpf_printk("WARNING: Inconsistent tree, node %p is its own left child", rbnode);
			return -EINVAL;
		}

		if (rbnode->right == rbnode) {
			bpf_printk("WARNING: Inconsistent tree, node %p is its own right child", rbnode);
			return -EINVAL;
		}

		if (rbnode->is_red) {
			if (rbnode->left && rbnode->left->is_red) {
				bpf_printk("WARNING: Inconsistent tree. Parent has %p has red child %p", rbnode, rbnode->left);
				return -EINVAL;
			}
			if (rbnode->right && rbnode->right->is_red) {
				bpf_printk("WARNING: Inconsistent tree. Parent has %p has red child %p", rbnode, rbnode->right);
				return -EINVAL;
			}
		} else if (rbnode->parent && rbnode->parent->child[1 - rbnode_dir(rbnode)] == NULL) {
			bpf_printk("WARNING: Inconsistent tree. Black node %p has no sibling", rbnode);
			return -EINVAL;
		}

		/* Find which child to traverse next. */
		state = rb_print_next_state(rbnode, state, &next);

		/* Child found. Store the node state and go on. */
		if (next) {
			if (depth < 0 || depth >= RB_MAXLVL_PRINT)
				return 0;

			stack[depth++] = state;

			rbnode = next;
			state = RB_NONE_VISITED;

			continue;
		}

		/* Otherwise, go as far up as possible. */
		ret = rb_print_pop_up(&rbnode, &depth, &stack, &state);
		if (ret)
			return -EINVAL;

		if (depth < 0 || depth >= RB_MAXLVL_PRINT) {
			return 0;
		}

	}

	return 0;
}
