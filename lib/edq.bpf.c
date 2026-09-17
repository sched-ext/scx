// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Eligible Deadline Queue: an arena-backed intrusive augmented AVL tree.
 */
#include <scx/common.bpf.h>
#include <lib/edq.h>

static __always_inline scx_edq_task_t *node_task(scx_edq_node_t *node)
{
	return (scx_edq_task_t *)((u64)node -
				   offsetof(struct scx_edq_task, node));
}

static __always_inline u32 node_height(scx_edq_node_t *node)
{
	return node ? node->height : 0;
}

static __always_inline bool node_less(scx_edq_node_t *a,
				      scx_edq_node_t *b)
{
	if (a->deadline != b->deadline)
		return time_before(a->deadline, b->deadline);
	return a->seq < b->seq;
}

static __always_inline bool is_eligible(u64 eligibility, u64 cutoff)
{
	return time_before_eq(eligibility, cutoff);
}

/*
 * Clear the links of @node. Written as three plain stores, LLVM 19 folds
 * them into one zeroing operation on the arena pointer and emits that
 * without the address space cast the verifier needs, which rejects the
 * program with "invalid mem access 'scalar'". Volatile stores are not
 * folded and each one is cast. lib/rbtree.bpf.c works around the same
 * thing with a dummy counter between its stores.
 */
static __always_inline void node_clear_links(scx_edq_node_t *node)
{
	WRITE_ONCE(node->parent, NULL);
	WRITE_ONCE(node->left, NULL);
	WRITE_ONCE(node->right, NULL);
}

static __always_inline void node_update(scx_edq_node_t *node)
{
	u32 lh = node_height(node->left), rh = node_height(node->right);
	u64 min_eligibility = node->eligibility;
	u64 min_slice = node->slice;

	node->height = (lh > rh ? lh : rh) + 1;
	if (node->left && time_before(node->left->min_eligibility, min_eligibility))
		min_eligibility = node->left->min_eligibility;
	if (node->right && time_before(node->right->min_eligibility, min_eligibility))
		min_eligibility = node->right->min_eligibility;
	node->min_eligibility = min_eligibility;
	if (node->left && node->left->min_slice < min_slice)
		min_slice = node->left->min_slice;
	if (node->right && node->right->min_slice < min_slice)
		min_slice = node->right->min_slice;
	node->min_slice = min_slice;
}

static __always_inline s32 node_balance(scx_edq_node_t *node)
{
	return (s32)node_height(node->left) - (s32)node_height(node->right);
}

static __always_inline void replace_child(scx_edq_t *edq,
					  scx_edq_node_t *parent,
					  scx_edq_node_t *old,
					  scx_edq_node_t *new)
{
	if (!parent)
		edq->root = new;
	else if (parent->left == old)
		parent->left = new;
	else
		parent->right = new;
	if (new)
		new->parent = parent;
}

static __always_inline scx_edq_node_t *rotate_left(scx_edq_t *edq,
						     scx_edq_node_t *node)
{
	scx_edq_node_t *pivot = node->right;
	scx_edq_node_t *parent = node->parent;

	replace_child(edq, parent, node, pivot);
	node->right = pivot->left;
	if (node->right)
		node->right->parent = node;
	pivot->left = node;
	node->parent = pivot;
	node_update(node);
	node_update(pivot);
	return pivot;
}

static __always_inline scx_edq_node_t *rotate_right(scx_edq_t *edq,
						      scx_edq_node_t *node)
{
	scx_edq_node_t *pivot = node->left;
	scx_edq_node_t *parent = node->parent;

	replace_child(edq, parent, node, pivot);
	node->left = pivot->right;
	if (node->left)
		node->left->parent = node;
	pivot->right = node;
	node->parent = pivot;
	node_update(node);
	node_update(pivot);
	return pivot;
}

/*
 * Recompute the cached height and minimum eligibility from @node up to the
 * root, rotating where the AVL balance is lost. With @may_exit the walk
 * stops at the first node whose cached values did not change and that was
 * not rotated: nothing above it can change either. That holds only when
 * the cached values of every node on the path are the pre-change ones, so a
 * caller that has already refreshed a node on the path passes false.
 */
static __noinline int rebalance_from(scx_edq_t __arg_arena *edq,
				     scx_edq_node_t __arg_arena *node,
				     bool may_exit)
{
	while (node && can_loop) {
		scx_edq_node_t *root = node;
		u64 old_min_eligibility = node->min_eligibility;
		u64 old_min_slice = node->min_slice;
		u32 old_height = node->height;
		s32 balance;
		bool rotated = false;

		node_update(node);
		balance = node_balance(node);
		if (balance > 1) {
			if (node_balance(node->left) < 0)
				rotate_left(edq, node->left);
			root = rotate_right(edq, node);
			rotated = true;
		} else if (balance < -1) {
			if (node_balance(node->right) > 0)
				rotate_right(edq, node->right);
			root = rotate_left(edq, node);
			rotated = true;
		}
		if (may_exit && !rotated && node->height == old_height &&
		    node->min_eligibility == old_min_eligibility &&
		    node->min_slice == old_min_slice)
			return 0;
		node = root->parent;
	}
	return node ? -E2BIG : 0;
}

static __noinline scx_edq_node_t *leftmost(scx_edq_node_t __arg_arena *node)
{
	while (node && node->left && can_loop)
		node = node->left;
	return node && node->left ? NULL : node;
}

/* Return the in-order successor of @node. The caller holds the EDQ lock. */
static __noinline scx_edq_node_t *next_node(scx_edq_node_t __arg_arena *node)
{
	if (node->right)
		return leftmost(node->right);
	while (node->parent && node == node->parent->right && can_loop)
		node = node->parent;
	return node->parent && node == node->parent->right ? NULL : node->parent;
}

static __noinline int remove_locked(scx_edq_t __arg_arena *edq,
				    scx_edq_task_t __arg_arena *task,
				    bool dead)
{
	scx_edq_node_t *node = &task->node;
	scx_edq_node_t *next_first = NULL;
	scx_edq_node_t *rebalance;
	bool may_exit = true;
	int ret;

	if (task->edq != edq)
		return -EINVAL;
	if (edq->first == node) {
		if (node->right) {
			next_first = leftmost(node->right);
			if (!next_first)
				return -E2BIG;
		} else {
			/* The global leftmost node is its parent's left child. */
			next_first = node->parent;
		}
	}

	if (!node->left || !node->right) {
		scx_edq_node_t *child = node->left ? node->left : node->right;

		rebalance = node->parent;
		replace_child(edq, node->parent, node, child);
	} else {
		scx_edq_node_t *successor = leftmost(node->right);
		scx_edq_node_t *old_parent;

		if (!successor)
			return -E2BIG;
		old_parent = successor->parent;
		if (old_parent != node) {
			replace_child(edq, old_parent, successor, successor->right);
			successor->right = node->right;
			successor->right->parent = successor;
			rebalance = old_parent;
		} else {
			rebalance = successor;
		}
		replace_child(edq, node->parent, node, successor);
		successor->left = node->left;
		successor->left->parent = successor;
		/*
		 * The successor now stands where @node stood, with a height and
		 * a minimum of its own that @node's parent has not seen, and
		 * the nodes between its old parent and here have cached values
		 * that still count it below them. The walk has to update every
		 * one of them: its early exit compares against cached values
		 * and would stop at the successor, whose cache is refreshed
		 * here, or below it, and leave the parent with @node's minimum.
		 */
		node_update(successor);
		may_exit = false;
	}

	edq->nr--;
	if (edq->first == node) {
		edq->first = next_first;
		edq->first_deadline = next_first ? next_first->deadline : 0;
	}
	node_clear_links(node);
	node->height = 1;
	node->min_eligibility = node->eligibility;
	node->min_slice = node->slice;

	ret = rebalance_from(edq, rebalance, may_exit);
	WRITE_ONCE(edq->min_slice,
		   edq->root ? edq->root->min_slice : 0);
	/*
	 * Publish reusable membership last. Insertions into another EDQ take the
	 * destination lock, not this one, and can claim a NULL membership
	 * immediately. Publishing it before the node cleanup and rebalance would
	 * let the old removal overwrite an already reinserted intrusive node.
	 */
	smp_store_release(&task->edq,
			  dead ? (scx_edq_t *)SCX_EDQ_DEAD : NULL);
	return ret;
}

__weak
int scx_edq_insert(scx_edq_t __arg_arena *edq,
		    scx_edq_task_t __arg_arena *task,
		    u64 deadline, u64 eligibility, u64 slice)
{
	scx_edq_node_t *node = &task->node;
	scx_edq_node_t *parent = NULL;
	scx_edq_node_t *cur;
	scx_edq_t *old;
	int ret;

	ret = scx_edq_lock(edq);
	if (ret)
		return ret;
	old = cmpxchg(&task->edq, 0, edq);
	if (old) {
		scx_edq_unlock(edq);
		return old == (scx_edq_t *)SCX_EDQ_DEAD ? -ECANCELED : -EALREADY;
	}

	node_clear_links(node);
	node->deadline = deadline;
	node->eligibility = eligibility;
	node->min_eligibility = eligibility;
	node->slice = slice;
	node->min_slice = slice;
	node->seq = edq->seq++;
	node->height = 1;

	cur = edq->root;
	while (cur && can_loop) {
		parent = cur;
		cur = node_less(node, cur) ? cur->left : cur->right;
	}
	if (cur) {
		task->edq = NULL;
		scx_edq_unlock(edq);
		return -E2BIG;
	}

	node->parent = parent;
	if (!parent)
		edq->root = node;
	else if (node_less(node, parent))
		parent->left = node;
	else
		parent->right = node;
	if (!edq->first || node_less(node, edq->first)) {
		edq->first = node;
		edq->first_deadline = deadline;
	}
	edq->nr++;

	ret = rebalance_from(edq, parent, true);
	WRITE_ONCE(edq->min_slice,
		   edq->root ? edq->root->min_slice : 0);
	scx_edq_unlock(edq);
	return ret;
}

__weak
int scx_edq_remove(scx_edq_t __arg_arena *edq,
		    scx_edq_task_t __arg_arena *task)
{
	int ret;

	ret = scx_edq_lock(edq);
	if (ret)
		return ret;
	ret = remove_locked(edq, task, false);
	scx_edq_unlock(edq);
	return ret;
}

__weak
int scx_edq_try_remove(scx_edq_t __arg_arena *edq,
			scx_edq_task_t __arg_arena *task)
{
	int ret;

	ret = scx_edq_trylock(edq);
	if (ret)
		return ret;
	ret = remove_locked(edq, task, false);
	scx_edq_unlock(edq);
	return ret;
}

static __noinline scx_edq_node_t *first_eligible(
					scx_edq_t __arg_arena *edq, u64 cutoff)
{
	scx_edq_node_t *node = edq->root;

	if (!node || !is_eligible(node->min_eligibility, cutoff))
		return NULL;
	while (node && can_loop) {
		if (node->left && is_eligible(node->left->min_eligibility, cutoff)) {
			node = node->left;
			continue;
		}
		if (is_eligible(node->eligibility, cutoff))
			return node;
		if (node->right && is_eligible(node->right->min_eligibility, cutoff)) {
			node = node->right;
			continue;
		}
		return NULL;
	}
	return NULL;
}

static __noinline u64 pop_node_locked(scx_edq_t __arg_arena *edq,
				      scx_edq_node_t __arg_arena *node,
				      bool hold)
{
	scx_edq_task_t *task;
	int ret;

	if (!node)
		return (u64)NULL;
	task = node_task(node);
	if (hold)
		scx_edq_task_hold(task);
	ret = remove_locked(edq, task, false);
	if (ret) {
		scx_edq_node_t *parent = node->parent;

		if (hold)
			scx_edq_task_drop(task);
		/*
		 * @node came out of this queue's own tree with the lock held,
		 * so remove_locked() should have found it a member. -EINVAL
		 * says the membership and the tree disagree, which is a
		 * corruption rather than a race: every writer of task->edq
		 * that unlinks holds this lock, and the two that do not,
		 * scx_edq_insert() and scx_edq_task_detach(), only claim a
		 * membership that is already NULL. Say enough to tell the two
		 * shapes apart - a stale edq->first, whose node is unlinked
		 * and whose task->edq reads 0 or SCX_EDQ_DEAD, against a
		 * membership that names some other queue.
		 */
		scx_bpf_error("EDQ remove failed: %d edq %llx task->edq %llx linked %d holdcnt %d nr %llu",
			      ret, (u64)edq, (u64)task->edq,
			      parent ? (parent->left == node ||
					parent->right == node) :
				       (edq->root == node),
			      READ_ONCE(task->holdcnt), edq->nr);
		return (u64)NULL;
	}
	return (u64)task;
}

__weak
u64 scx_edq_pop(scx_edq_t __arg_arena *edq, bool hold)
{
	u64 task = 0;
	int ret;

	ret = scx_edq_lock(edq);
	if (ret)
		return 0;
	task = pop_node_locked(edq, edq->first, hold);
	scx_edq_unlock(edq);
	return task;
}

__weak
u64 scx_edq_pop_first_eligible(scx_edq_t __arg_arena *edq, u64 cutoff,
				 bool hold)
{
	u64 task = 0;
	int ret;

	ret = scx_edq_lock(edq);
	if (ret)
		return 0;
	task = pop_node_locked(edq, first_eligible(edq, cutoff), hold);
	scx_edq_unlock(edq);
	return task;
}

__weak
u64 scx_edq_pop_first_eligible_or_first(scx_edq_t __arg_arena *edq,
					 u64 cutoff, bool hold)
{
	scx_edq_node_t *node;
	u64 task = 0;
	int ret;

	ret = scx_edq_lock(edq);
	if (ret)
		return 0;
	node = first_eligible(edq, cutoff);
	if (!node)
		node = edq->first;
	task = pop_node_locked(edq, node, hold);
	scx_edq_unlock(edq);
	return task;
}

/*
 * Return the deadline of the earliest-deadline task whose eligibility is at
 * or before @cutoff and the shortest slice in the queue, without removing
 * anything. -ENOENT when no queued task is eligible, -EBUSY when the queue is
 * contended: the caller decides without it.
 */
__weak
int scx_edq_try_first_eligible_deadline(scx_edq_t __arg_arena *edq, u64 cutoff,
					 u64 *deadline __arg_nonnull,
					 u64 *min_slice __arg_nonnull)
{
	scx_edq_node_t *node;
	int ret;

	*deadline = 0;
	*min_slice = 0;
	ret = scx_edq_trylock(edq);
	if (ret)
		return ret;
	if (edq->root)
		*min_slice = edq->root->min_slice;
	node = first_eligible(edq, cutoff);
	if (node)
		*deadline = node->deadline;
	else
		ret = -ENOENT;
	scx_edq_unlock(edq);
	return ret;
}

__weak
u64 scx_edq_peek_hold(scx_edq_t __arg_arena *edq)
{
	scx_edq_task_t *task = NULL;
	int ret;

	ret = scx_edq_lock(edq);
	if (ret)
		return 0;
	if (edq->first) {
		task = node_task(edq->first);
		scx_edq_task_hold(task);
	}
	scx_edq_unlock(edq);
	return (u64)task;
}

__weak
int scx_edq_try_peek_hold(scx_edq_t __arg_arena *edq, u64 *taskp __arg_nonnull)
{
	scx_edq_task_t *task = NULL;
	int ret;

	*taskp = 0;
	ret = scx_edq_trylock(edq);
	if (ret)
		return ret;
	if (edq->first) {
		task = node_task(edq->first);
		scx_edq_task_hold(task);
	}
	scx_edq_unlock(edq);
	*taskp = (u64)task;
	return 0;
}

/*
 * Return and hold the @nth task in deadline order without removing it. This
 * is an advisory, bounded-scan primitive: callers must still validate the
 * task and use scx_edq_try_remove() to claim the exact node.
 */
__weak
int scx_edq_try_peek_nth_hold(scx_edq_t __arg_arena *edq, u32 nth,
			       u64 *taskp __arg_nonnull)
{
	scx_edq_node_t *node;
	scx_edq_task_t *task = NULL;
	int ret;

	*taskp = 0;
	ret = scx_edq_trylock(edq);
	if (ret)
		return ret;
	node = edq->first;
	while (node && nth && can_loop) {
		node = next_node(node);
		nth--;
	}
	if (node && nth) {
		ret = -E2BIG;
	} else if (node) {
		task = node_task(node);
		scx_edq_task_hold(task);
	}
	scx_edq_unlock(edq);
	*taskp = (u64)task;
	return ret;
}

/*
 * Return and hold the next task in deadline order and advance @cursor. This
 * lets a caller resume a bounded scan even when the nodes it inspected have
 * since left the tree. Updating the cursor under the queue lock serializes
 * multiple destinations scanning the same source.
 */
__weak
int scx_edq_try_peek_next_hold(scx_edq_t __arg_arena *edq,
			       scx_edq_cursor_t __arg_arena *cursor,
			       u64 *taskp __arg_nonnull)
{
	scx_edq_node_t *node, *next = NULL;
	scx_edq_task_t *task = NULL;
	int ret;

	*taskp = 0;
	ret = scx_edq_trylock(edq);
	if (ret)
		return ret;
	if (!cursor->valid) {
		next = edq->first;
	} else {
		bool include = cursor->valid == SCX_EDQ_CURSOR_AT;

		node = edq->root;
		while (node && can_loop) {
			bool key_before;

			key_before = cursor->deadline != node->deadline ?
				time_before(cursor->deadline, node->deadline) :
				cursor->seq < node->seq ||
				(include && cursor->seq == node->seq);
			if (key_before) {
				next = node;
				node = node->left;
			} else {
				node = node->right;
			}
		}
		if (node)
			ret = -E2BIG;
	}
	if (!ret && next) {
		task = node_task(next);
		scx_edq_task_hold(task);
		cursor->deadline = next->deadline;
		cursor->seq = next->seq;
		cursor->valid = SCX_EDQ_CURSOR_AFTER;
	} else if (!ret) {
		cursor->valid = 0;
	}
	scx_edq_unlock(edq);
	*taskp = (u64)task;
	return ret;
}

__weak
u64 scx_edq_nr_queued(scx_edq_t __arg_arena *edq)
{
	return READ_ONCE(edq->nr);
}

/*
 * Bring a freshly allocated @task to the state of one that is in no queue
 * and held by nobody. Field by field rather than a memset: LLVM 19 expands
 * a memset of arena memory through the uncast pointer, see
 * node_clear_links(), and the caller's pointer is the scalar an allocator
 * returns.
 */
__weak
int scx_edq_task_init(scx_edq_task_t __arg_arena *task)
{
	node_clear_links(&task->node);
	WRITE_ONCE(task->node.deadline, 0);
	WRITE_ONCE(task->node.eligibility, 0);
	WRITE_ONCE(task->node.min_eligibility, 0);
	WRITE_ONCE(task->node.slice, 0);
	WRITE_ONCE(task->node.min_slice, 0);
	WRITE_ONCE(task->node.seq, 0);
	WRITE_ONCE(task->node.height, 0);
	WRITE_ONCE(task->holdcnt, 0);
	WRITE_ONCE(task->edq, NULL);
	return 0;
}

__weak
int scx_edq_task_fini(scx_edq_task_t __arg_arena *task)
{
	scx_edq_t *edq;
	int ret;

	while (can_loop) {
		edq = task->edq;
		if (!edq || edq == (scx_edq_t *)SCX_EDQ_DEAD)
			return 0;
		ret = scx_edq_remove(edq, task);
		if (ret == -EINVAL)
			continue;
		return ret ? ret : 1;
	}
	return -E2BIG;
}

__weak
int scx_edq_task_detach(scx_edq_task_t __arg_arena *task)
{
	volatile int holdcnt;
	scx_edq_t *edq;
	int ret;

	while (can_loop) {
		edq = task->edq;
		if (edq == (scx_edq_t *)SCX_EDQ_DEAD)
			break;
		if (!edq) {
			if (!cmpxchg(&task->edq, 0,
				     (scx_edq_t *)SCX_EDQ_DEAD))
				break;
			continue;
		}
		ret = scx_edq_lock(edq);
		if (ret)
			return ret;
		if (task->edq != edq) {
			scx_edq_unlock(edq);
			continue;
		}
		ret = remove_locked(edq, task, true);
		scx_edq_unlock(edq);
		if (ret)
			return ret;
		break;
	}
	while ((holdcnt = READ_ONCE(task->holdcnt)) > 0 && can_loop)
		cpu_relax();
	return holdcnt > 0 ? -E2BIG : 0;
}
