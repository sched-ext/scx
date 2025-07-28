/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

#include "scxtest/scx_test.h"
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>
#include <scx/arena_userspace_interrop.bpf.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	__uint(max_entries, 1 << 16); /* number of pages */
        __ulong(map_extra, (1ull << 32)); /* start of mmap() region */
#else
	__uint(max_entries, 1 << 20); /* number of pages */
        __ulong(map_extra, (1ull << 44)); /* start of mmap() region */
#endif
} arena __weak SEC(".maps");

struct scx_alloc_stack __arena *prealloc_stack;

/*
 * Necessary for cond_break/can_loop's semantics. According to kernel commit
 * 011832b, the loop counter variable must be seen as imprecise and bounded
 * by the verifier. Initializing it from a constant (e.g., i = 0;), then,
 * makes it precise and prevents may_goto from helping with converging the
 * loop. For these loops we must initialize the loop counter from a variable
 * whose value the verifier cannot reason about when checking the program, so
 * that the loop counter's value is imprecise.
 */
static __u64 zero = 0;

/*
 * XXX Hack to get the verifier to find the arena for sdt_exit_task.
 * As of 6.12-rc5, The verifier associates arenas with programs by
 * checking LD.IMM instruction operands for an arena and populating
 * the program state with the first instance it finds. This requires
 * accessing our global arena variable, but scx methods do not necessarily
 * do so while still using pointers from that arena. Insert a bpf_printk
 * statement that triggers at most once to generate an LD.IMM instruction
 * to access the arena and help the verifier.
 */
static bool scx_arena_verify_once;

__hidden void scx_arena_subprog_init(void)
{
	if (scx_arena_verify_once)
		return;

	bpf_printk("%s: arena pointer %p", __func__, &arena);
	scx_arena_verify_once = true;
}


private(LOCK) struct bpf_spin_lock alloc_lock;
private(POOL_LOCK) struct bpf_spin_lock alloc_pool_lock;

/* allocation pools */
struct sdt_pool desc_pool;
struct sdt_pool chunk_pool;

/* Protected by alloc_lock. */
struct scx_alloc_stats alloc_stats;

static
u64 scx_next_pow2(__u64 n)
{
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n |= n >> 32;
	n++;

	return n;
}


/* find the first empty slot */
static __u64 chunk_find_empty(sdt_desc_t *desc)
{
	__u64 freeslots;
	__u64 i;

	for (i = 0; i < SDT_TASK_CHUNK_BITMAP_U64S; i++) {
		freeslots = ~desc->allocated[i];
		if (freeslots == (__u64)0)
			continue;

		return (i * 64) + scx_ffs(freeslots);
	}

	return SDT_TASK_ENTS_PER_CHUNK;
}

static
void __arena *scx_alloc_stack_pop(struct scx_alloc_stack __arena *stack)
{
	void __arena *slab;

	/* Cannot print out diagnostic because we may be holding a lock. */
	if (unlikely(stack->idx == 0))
		return NULL;

	stack->idx -= 1;

	slab = stack->stack[stack->idx];

	return slab;
}

static
int scx_alloc_stack(struct scx_alloc_stack __arena *stack)
{
	void __arena *slab;

	bpf_spin_lock(&alloc_lock);
	if (stack->idx >= SDT_TASK_ALLOC_STACK_MIN)
		return 0;

	bpf_spin_unlock(&alloc_lock);

	slab = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (slab == NULL)
		return -ENOMEM;

	bpf_spin_lock(&alloc_lock);

	/*
	 * Edge case where so many threads tried to allocate that our
	 * allocation does not fit into the stack.
	 */
	if (stack->idx >= SDT_TASK_ALLOC_STACK_MAX) {

		bpf_spin_unlock(&alloc_lock);

		bpf_arena_free_pages(&arena, slab, 1);
		return -EAGAIN;
	}

	stack->stack[stack->idx] = slab;
	stack->idx += 1;

	alloc_stats.arena_pages_used += 1;
	bpf_spin_unlock(&alloc_lock);

	return -EAGAIN;
}

static __noinline
int scx_alloc_attempt(struct scx_alloc_stack __arena *stack)
{
	int i;

	/*
	 * Use can_loop to help with verification. The can_loop macro was
	 * introduced in kernel commit ba39486 and wraps around the may_goto
	 * instruction that helps with verifiying for loops. Using may_goto
	 * embeds a switch into the loop that ensures it is considered
	 * terminable by the verifier by adding a hidden switch to the loop
	 * and counting down with every iteration.
	 */
	for (i = zero; i < SDT_TASK_ALLOC_ATTEMPTS && can_loop; i++) {
		if (scx_alloc_stack(stack) == 0)
			return 0;
	}

	return -ENOMEM;
}

/* Allocate element from the pool. Must be called with a then pool lock held. */
static
void __arena *scx_alloc_from_pool(struct sdt_pool *pool,
	struct scx_alloc_stack __arena *stack)
{
	__u64 elem_size, max_elems;
	void __arena *slab;
	void __arena *ptr;

	elem_size = pool->elem_size;
	max_elems = pool->max_elems;

	/* Nonsleepable allocations not supported for large data structures. */
	if (elem_size > PAGE_SIZE)
		return NULL;

	/* If the chunk is spent, get a new one. */
	if (pool->idx >= max_elems) {
		slab = scx_alloc_stack_pop(stack);
		pool->slab = slab;
		pool->idx = 0;
	}

	ptr = (void __arena *)((__u64) pool->slab + elem_size * pool->idx);
	pool->idx += 1;

	return ptr;
}

/* Allocate element from the pool. Must be called with a then pool lock held. */
static
void __arena *scx_alloc_from_pool_sleepable(struct sdt_pool *pool)
{
	__u64 elem_size, max_elems;
	void __arena *slab;
	void __arena *ptr;

	elem_size = pool->elem_size;
	max_elems = pool->max_elems;

	/* If the chunk is spent, get a new one. */
	if (pool->idx >= max_elems) {
		slab = bpf_arena_alloc_pages(&arena, NULL,
			div_round_up(max_elems * elem_size, PAGE_SIZE), NUMA_NO_NODE, 0);
		pool->slab = slab;
		pool->idx = 0;
	}

	ptr = (void __arena *)((__u64) pool->slab + elem_size * pool->idx);
	pool->idx += 1;

	return ptr;
}

/* Alloc desc and associated chunk. Called with the task spinlock held. */
static sdt_desc_t *scx_alloc_chunk(struct scx_alloc_stack __arena *stack)
{
	struct sdt_chunk __arena *chunk;
	sdt_desc_t *desc;
	sdt_desc_t *out;

	chunk = scx_alloc_from_pool(&chunk_pool, stack);
	desc = scx_alloc_from_pool(&desc_pool, stack);

	out = desc;

	desc->nr_free = SDT_TASK_ENTS_PER_CHUNK;
	desc->chunk = chunk;

	alloc_stats.chunk_allocs += 1;

	return out;
}

static int pool_set_size(struct sdt_pool *pool, __u64 data_size, __u64 nr_pages)
{
	if (unlikely(data_size % 8)) {
		bpf_printk("%s: allocation size %llu not word aligned", __func__, data_size);
		return -EINVAL;
	}

	if (unlikely(nr_pages == 0)) {
		bpf_printk("%s: allocation size is 0", __func__);
		return -EINVAL;
	}

	pool->elem_size = data_size;
	pool->max_elems = (PAGE_SIZE * nr_pages) / pool->elem_size;
	/* Populate the pool slab on the first allocation. */
	pool->idx = pool->max_elems;

	return 0;
}

/* initialize the whole thing, maybe misnomer */
__hidden int
scx_alloc_init(struct scx_allocator *alloc, __u64 data_size)
{
	size_t min_chunk_size;
	int ret;

	_Static_assert(sizeof(struct sdt_chunk) <= PAGE_SIZE,
		"chunk size must fit into a page");

	ret = pool_set_size(&chunk_pool, sizeof(struct sdt_chunk), 1);
	if (ret != 0)
		return ret;

	ret = pool_set_size(&desc_pool, sizeof(struct sdt_desc), 1);
	if (ret != 0)
		return ret;

	/* Wrap data into a descriptor and word align. */
	data_size += sizeof(struct sdt_data);
	data_size = round_up(data_size, 8);

	/*
	 * Ensure we allocate large enough chunks from the arena to avoid excessive
	 * internal fragmentation when turning chunks it into structs.
	 */
	min_chunk_size = div_round_up(SDT_TASK_MIN_ELEM_PER_ALLOC * data_size, PAGE_SIZE);
	ret = pool_set_size(&alloc->pool, data_size, min_chunk_size);
	if (ret != 0)
		return ret;

	prealloc_stack = bpf_arena_alloc_pages(&arena, NULL, div_round_up(sizeof(*prealloc_stack), PAGE_SIZE), NUMA_NO_NODE, 0);
	if (prealloc_stack == NULL)
		return -ENOMEM;

	/* On success, returns with the lock taken. */
	ret = scx_alloc_attempt(prealloc_stack);
	if (ret != 0)
		return ret;

	alloc->root = scx_alloc_chunk(prealloc_stack);

	bpf_spin_unlock(&alloc_lock);

	return 0;
}

static
int set_idx_state(sdt_desc_t *desc, __u64 pos, bool state)
{
	__u64 __arena *allocated = desc->allocated;
	__u64 bit;

	if (unlikely(pos >= SDT_TASK_ENTS_PER_CHUNK))
		return -EINVAL;

	bit = (__u64)1 << (pos % 64);

	if (state)
		allocated[pos / 64] |= bit;
	else
		allocated[pos / 64] &= ~bit;

	return 0;
}

static __noinline
int mark_nodes_avail(sdt_desc_t *lv_desc[SDT_TASK_LEVELS], __u64 lv_pos[SDT_TASK_LEVELS])
{
	sdt_desc_t *desc;
	__u64 u, level;
	int ret;

	for (u = zero; u < SDT_TASK_LEVELS && can_loop; u++) {
		level = SDT_TASK_LEVELS - 1 - u;

		/* Only propagate upwards if we are the parent's only free chunk. */
		desc = lv_desc[level];

		/* Failed calls return unlocked. */
		ret = set_idx_state(desc, lv_pos[level], false);
		if (unlikely(ret != 0))
			return ret;

		desc->nr_free += 1;
		if (desc->nr_free > 1)
			return 0;
	}

	return 0;
}

__weak
int scx_alloc_free_idx(struct scx_allocator *alloc, __u64 idx)
{
	const __u64 mask = (1 << SDT_TASK_ENTS_PER_PAGE_SHIFT) - 1;
	sdt_desc_t *lv_desc[SDT_TASK_LEVELS];
	sdt_desc_t * __arena *desc_children;
	struct sdt_chunk __arena *chunk;
	sdt_desc_t *desc;
	struct sdt_data __arena *data;
	__u64 level, shift, pos;
	__u64 lv_pos[SDT_TASK_LEVELS];
	int ret;
	int i;

	scx_arena_subprog_init();

	if (!alloc)
		return 0;

	bpf_spin_lock(&alloc_lock);

	desc = alloc->root;
	if (unlikely(!desc)) {
		bpf_spin_unlock(&alloc_lock);
		bpf_printk("%s: root not allocated", __func__);
		return -EINVAL;
	}

	/* To appease the verifier. */
	for (level = zero; level < SDT_TASK_LEVELS && can_loop; level++) {
		lv_desc[level] = NULL;
		lv_pos[level] = 0;
	}

	for (level = zero; level < SDT_TASK_LEVELS && can_loop; level++) {
		shift = (SDT_TASK_LEVELS - 1 - level) * SDT_TASK_ENTS_PER_PAGE_SHIFT;
		pos = (idx >> shift) & mask;

		lv_desc[level] = desc;
		lv_pos[level] = pos;

		if (level == SDT_TASK_LEVELS - 1)
			break;

		chunk = desc->chunk;

		desc_children = (sdt_desc_t * __arena *)chunk->descs;
		desc = desc_children[pos];

		if (unlikely(!desc)) {
			bpf_spin_unlock(&alloc_lock);
			bpf_printk("%s: freeing nonexistent idx [0x%llx] (level %llu)",
				__func__, idx, level);
			return -EINVAL;
		}
	}

	chunk = desc->chunk;

	pos = idx & mask;
	data = chunk->data[pos];
	if (likely(!data)) {

		data[pos] = (struct sdt_data) {
			.tid.genn = data->tid.genn + 1,
		};

		/* Zero out one word at a time. */
		for (i = zero; i < alloc->pool.elem_size / 8 && can_loop; i++) {
			data->payload[i] = 0;
		}
	}

	ret = mark_nodes_avail(lv_desc, lv_pos);
	if (unlikely(ret != 0)) {
		bpf_spin_unlock(&alloc_lock);
		return ret;
	}

	alloc_stats.active_allocs -= 1;
	alloc_stats.free_ops += 1;

	bpf_spin_unlock(&alloc_lock);

	return 0;
}

/*
 * Find and return an available idx on the allocator.
 * Called with the task spinlock held.
 */
static sdt_desc_t * desc_find_empty(sdt_desc_t *desc,
	struct scx_alloc_stack __arena *stack,
	__u64 *idxp)
{
	sdt_desc_t *lv_desc[SDT_TASK_LEVELS];
	sdt_desc_t * __arena *desc_children;
	struct sdt_chunk __arena *chunk;
	sdt_desc_t *tmp;
	__u64 lv_pos[SDT_TASK_LEVELS];
	__u64 u, pos, level;
	__u64 idx = 0;
	int ret;

	for (level = zero; level < SDT_TASK_LEVELS && can_loop; level++) {
		pos = chunk_find_empty(desc);

		/* Something has gone terribly wrong. */
		if (unlikely(pos > SDT_TASK_ENTS_PER_CHUNK))
			return NULL;

		if (pos == SDT_TASK_ENTS_PER_CHUNK)
			return NULL;

		idx <<= SDT_TASK_ENTS_PER_PAGE_SHIFT;
		idx |= pos;

		/* Log the levels to complete allocation. */
		lv_desc[level] = desc;
		lv_pos[level] = pos;

		/* The rest of the loop is for internal node traversal. */
		if (level == SDT_TASK_LEVELS - 1)
			break;

		chunk = desc->chunk;
		desc_children = (sdt_desc_t * __arena *)chunk->descs;
		desc = desc_children[pos];
		if (!desc) {
			desc = scx_alloc_chunk(stack);
			desc_children[pos] = desc;
		}
	}

	for (u = zero; u < SDT_TASK_LEVELS && can_loop; u++) {
		level = SDT_TASK_LEVELS - 1 - u;
		tmp = lv_desc[level];

		ret = set_idx_state(tmp, lv_pos[level], true);
		if (ret != 0)
			break;

		tmp->nr_free -= 1;
		if (tmp->nr_free > 0)
			break;

	}

	*idxp = idx;

	return desc;
}

static void scx_alloc_finish(struct sdt_data __arena *data, __u64 idx)
{
	bpf_spin_lock(&alloc_lock);

	/* The data counts as a chunk */
	alloc_stats.data_allocs += 1;
	alloc_stats.alloc_ops += 1;
	alloc_stats.active_allocs += 1;

	bpf_spin_unlock(&alloc_lock);

	data->tid.idx = idx;
}

__hidden
u64 scx_alloc_internal(struct scx_allocator *alloc)
{
	struct scx_alloc_stack __arena *stack = prealloc_stack;
	struct sdt_data __arena *data = NULL;
	struct sdt_chunk __arena *chunk;
	sdt_desc_t *desc;
	__u64 idx, pos;
	int ret;

	if (!alloc)
		return (u64)NULL;

	/* On success, call returns with the lock taken. */
	ret = scx_alloc_attempt(stack);
	if (ret != 0)
		return (u64)NULL;

	/* We unlock if we encounter an error in the function. */
	desc = desc_find_empty(alloc->root, stack, &idx);

	bpf_spin_unlock(&alloc_lock);

	if (unlikely(desc == NULL)) {
		bpf_printk("%s: failed to find empty tree key", __func__);
		return (u64)NULL;
	}

	chunk = desc->chunk;

	/* Populate the leaf node if necessary. */
	pos = idx & (SDT_TASK_ENTS_PER_CHUNK - 1);
	data = chunk->data[pos];
	if (!data) {
		data = scx_alloc_from_pool_sleepable(&alloc->pool);
		if (!data) {
			scx_alloc_free_idx(alloc, idx);
			bpf_printk("%s: failed to allocate data from pool", __func__);
			return (u64)NULL;
		}
	}

	chunk->data[pos] = data;

	scx_alloc_finish(data, idx);

	return (u64)data;
}


/*
 * Static allocation module used to allocate arena memory for
 * whose lifetime is that of the BPF program. Data is rarely
 * allocated, mostly at program init, and never freed. The
 * memory returned by this code is typeless so it avoids us
 * having to define an allocator for each type.
 */

struct scx_static scx_static;

__hidden
void __arena *scx_static_alloc(size_t bytes, size_t alignment)
{
	void __arena *memory, *old;
	size_t alloc_bytes;
	void __arena *ptr;
	size_t padding;
	u64 addr;

	bpf_spin_lock(&alloc_lock);

	/* Round up the current offset. */
	addr = (__u64) scx_static.memory + scx_static.off;

	padding = round_up(addr, alignment) - addr;
	alloc_bytes = bytes + padding;

	if (alloc_bytes > scx_static.max_alloc_bytes) {
		bpf_spin_unlock(&alloc_lock);
		bpf_printk("invalid request %ld, max is %ld\n", alloc_bytes,
			      scx_static.max_alloc_bytes);
		return NULL;
	}

	/*
	 * The code assumes that the maximum static allocation
	 * size is significantly larger than the typical allocation
	 * size, so it does not attempt to alleviate memory
	 * fragmentation.
	 */
	if (scx_static.off + alloc_bytes > scx_static.max_alloc_bytes) {
		old = scx_static.memory;

		bpf_spin_unlock(&alloc_lock);

		/*
		 * No free operation so just forget about the previous
		 * allocation memory.
		 */

		memory = bpf_arena_alloc_pages(&arena, NULL,
					       scx_static.max_alloc_bytes / PAGE_SIZE,
					       NUMA_NO_NODE, 0);
		if (!memory)
			return NULL;

		bpf_spin_lock(&alloc_lock);

		/* Error out if we raced with another allocation. */
		if (scx_static.memory != old) {
			bpf_spin_unlock(&alloc_lock);
			bpf_arena_free_pages(&arena, memory, scx_static.max_alloc_bytes);

			bpf_printk("concurrent static memory allocations unsupported");
			return NULL;
		}

		/*
		 * Switch to new memory block, reset offset,
		 * and recalculate base address.
		 */
		scx_static.memory = memory;
		scx_static.off = 0;
		addr = (__u64) scx_static.memory + scx_static.off;

		/*
		 * We changed the base address. Recompute the padding.
		 */
		padding = round_up(addr, alignment) - addr;
		alloc_bytes = bytes + padding;
	}

	ptr = (void __arena *)(addr + padding);
	scx_static.off += alloc_bytes;

	bpf_spin_unlock(&alloc_lock);

	return ptr;
}

__weak
int scx_static_init(size_t alloc_pages)
{
	size_t max_bytes = alloc_pages * PAGE_SIZE;
	void __arena *memory;

	memory = bpf_arena_alloc_pages(&arena, NULL, alloc_pages, NUMA_NO_NODE, 0);
	if (!memory)
		return -ENOMEM;

	bpf_spin_lock(&alloc_lock);
	scx_static = (struct scx_static) {
		.max_alloc_bytes = max_bytes,
		.off = 0,
		.memory = memory,
	};
	bpf_spin_unlock(&alloc_lock);

	return 0;
}

__hidden
int scx_stk_init(struct scx_stk *stack, __u64 data_size, __u64 nr_pages_per_alloc)
{
	if (!stack)
		return -EINVAL;

	stack->data_size = data_size;
	stack->nr_pages_per_alloc = nr_pages_per_alloc;

	stack->lock = scx_static_alloc(sizeof(*stack->lock), 1);
	if (!stack->lock) {
		bpf_printk("failed to allocate lock");
		return -ENOMEM;
	}

	return 0;
}

static int scx_stk_push(struct scx_stk *stack, void __arena *elem)
{
	scx_stk_seg_t *stk_seg = stack->current;
	int ridx = stack->cind;

	stack->current->elems[stack->cind] = elem;

	ridx += 1;

	/* Possibly loop into the next segment. */
	if (ridx == SCX_STK_SEG_MAX) {
		ridx = 0;
		stk_seg = stk_seg->next;
		if (!stk_seg)
			return -ENOSPC;
	}


	stack->current = stk_seg;
	stack->cind = ridx;

	stack->capacity -= 1;
	stack->available += 1;

	return 0;
}

static
void __arena *scx_stk_pop(struct scx_stk *stack)
{
	scx_stk_seg_t *stk_seg = stack->current;
	void __arena *elem;
	int ridx = stack->cind;

	/* Possibly loop into previous next segment. */
	if (ridx == 0) {
		ridx = SCX_STK_SEG_MAX;
		stk_seg = stack->current->prev;
		/* Possibly loop back into the last segment. */
		if (!stk_seg)
			return NULL;
	}

	ridx -= 1;


	stack->current = stk_seg;
	stack->cind = ridx;

	elem = stack->current->elems[stack->cind];

	stack->capacity += 1;
	stack->available -= 1;

	return elem;
}

static
int scx_stk_seg_to_data(struct scx_stk *stack, size_t nelems)
{
	int ret, i;
	u64 data;

	/* Do we have enough empty segments for the conversion? */
	if (!stack->first || stack->first == stack->last)
		return -ENOMEM;

	data = (u64)stack->last;
	stack->last->prev->next = NULL;
	stack->last = stack->last->prev;

	/* We removed a segment. */
	stack->capacity -= SCX_STK_SEG_MAX;

	for (i = zero; i < nelems && can_loop; i++) {
		ret = scx_stk_push(stack, (void __arena *)data);
		if (ret)
			return ret;
		data += stack->data_size;
	}

	return 0;
}

static
void scx_stk_extend(struct scx_stk *stack, scx_stk_seg_t *stk_seg)
{
	if (stack->last)
		stack->last->next = stk_seg;

	stk_seg->prev = stack->last;
	stk_seg->next = NULL;

	stack->last = stk_seg;
	stack->capacity += SCX_STK_SEG_MAX;

	if (!stack->first)
		stack->first = stk_seg;

	/*
	 * Do not adjust the current segment/idx because we did not add
	 * any elements. The new segment will be pushed into during the next
	 * allocation.
	 */
}

static
int scx_stk_free_unlocked(struct scx_stk *stack, void __arena *elem)
{
	if (!stack)
		return -EINVAL;

	/* If no more room, repurpose the allocation into a segment. */
	if (stack->capacity == 0) {
		scx_stk_extend(stack, (scx_stk_seg_t *)elem);
		return 0;
	}

	return scx_stk_push(stack, elem);
}

__weak
int scx_stk_free_internal(struct scx_stk *stack, __u64 elem)
{
	int ret;

	if (!stack)
		return -EINVAL;

	if ((ret = arena_spin_lock(stack->lock))) {
		bpf_printk("spinlock error %d", ret);
		return ret;
	}

	ret = scx_stk_free_unlocked(stack, (void __arena *)elem);

	arena_spin_unlock(stack->lock);

	return ret;
}

static
int scx_stk_get_arena_memory(struct scx_stk *stack, __u64 nr_pages, __u64 nstk_segs)
{
	scx_stk_seg_t *stk_seg;
	int ret, i;
	u64 mem;

	arena_spin_unlock(stack->lock);

	/*
	 * The code allocates new memory only as segments. The allocation and
	 * free code freely typecasts the segment buffer into data that can be
	 * allocated, and vice versa to avoid either ending up with too many
	 * empty segments under memory pressure, or having no space in the segment
	 * buffer for a buffer currently being freed.
	 */

	/*
	 * On error, we return with the segment buffer unlocked. This is
	 * because arena_spin_lock can fail, so we cannot guarantee we
	 * can lock it back.
	 */
	if (!stack)
		return -EINVAL;

	mem = (__u64)bpf_arena_alloc_pages(&arena, NULL, nstk_segs * nr_pages, NUMA_NO_NODE, 0);
	if (!mem)
		return -ENOMEM;

	if ((ret = arena_spin_lock(stack->lock))) {
		bpf_arena_free_pages(&arena, (void __arena *)mem, nr_pages);
		bpf_printk("spinlock error %d", ret);
		return ret;
	}

	_Static_assert(sizeof(struct scx_stk_seg) <= PAGE_SIZE,
		"segment must fit into a page");

	/* Attach the segments to the reserve linked list. */
	for (i = zero; i < nstk_segs && can_loop; i++) {
		stk_seg = (scx_stk_seg_t *)mem;
		stk_seg->next = stack->reserve;
		stack->reserve = stk_seg;

		mem += nr_pages * PAGE_SIZE;
	}

	return 0;
}

static
int scx_stk_fill_new_elems(struct scx_stk *stack)
{
	size_t nelems, nstk_segs;
	scx_stk_seg_t *stk_seg;
	__u64 nr_pages;
	int ret, i;
	u64 mem;

	nr_pages = stack->nr_pages_per_alloc;
	nelems = (nr_pages * PAGE_SIZE) / stack->data_size;
	if (nelems > SCX_STK_SEG_MAX) {
		arena_spin_unlock(stack->lock);
		bpf_printk("new elements must fit into a single segment");
		return -EINVAL;
	}

	/* How many segments should we allocate? */
	nstk_segs = stack->capacity ? 1 : 2;

	/*
	 * If we have more than two empty segments available,
	 * repurpose one of them into an allocation.
	 */
	ret = scx_stk_seg_to_data(stack, nelems);
	if (!ret)
		return 0;

	/* If we haven't set aside any memory from before, allocate. */
	if (!stack->reserve) {
		/* This call drops and retakes the lock. */
		ret = scx_stk_get_arena_memory(stack, nr_pages, nstk_segs);
		if (ret)
			return ret;
	}

	/*
	 * If somebody replenished the stack while we were asleep, no need
	 * to do anything. Keep the allocated memory in the reserve linked
	 * list for subsequent allocations.
	 */
	if (stack->available > 0)
		return 0;

	/*
	 * Otherwise add elements and possibly capacity to the stack. */
	if (!stack->capacity) {
		stk_seg = stack->reserve;
		stack->reserve = stack->reserve->next;

		scx_stk_extend(stack, stk_seg);
	}

	/* Pop out the reserve and attach to the stack. */
	stk_seg = stack->reserve;
	stack->reserve = stk_seg->next;

	mem = (u64)stk_seg;
	for (i = zero; i < nelems && can_loop; i++) {
		ret = scx_stk_push(stack, (void __arena *)mem);
		if (ret) {
			arena_spin_unlock(stack->lock);
			return ret;
		}
		mem += stack->data_size;
	}

	return 0;
}

__weak
__u64 scx_stk_alloc(struct scx_stk *stack)
{
	void __arena *elem;
	int ret;

	if (!stack) {
		bpf_printk("using uninitialized stack allocator");
		return 0ULL;
	}

	if ((ret = arena_spin_lock(stack->lock))) {
		bpf_printk("spinlock error %d", ret);
		return 0ULL;
	}

	/* If segment buffer is empty, we have to populate it. */
	if (stack->available == 0) {
		/* The call drops the lock on error. */
		ret = scx_stk_fill_new_elems(stack);
		if (ret) {
			bpf_printk("elem creation failed");
			return 0ULL;
		}
	}

	elem = scx_stk_pop(stack);
	arena_spin_unlock(stack->lock);

	return (u64)elem;
}

static
int header_set_order(scx_buddy_chunk_t *chunk, u64 offset, u8 order)
{
	if (order >= SCX_BUDDY_CHUNK_MAX_ORDER) {
		bpf_printk("setting invalid order");
		return -EINVAL;
	}

	if (offset >= SCX_BUDDY_CHUNK_ITEMS) {
		bpf_printk("setting order of invalid offset");
		return EINVAL;
	}

	if (offset & 0x1)
		order &= 0xf;
	else
		order <<= 4;

	chunk->orders[offset / 2] |= order;

	return 0;
}

static
u8 header_get_order(scx_buddy_chunk_t *chunk, u64 offset)
{
	u8 result;

	_Static_assert(SCX_BUDDY_CHUNK_MAX_ORDER <= 16, "order must fit in 4 bits");

	if (offset >= SCX_BUDDY_CHUNK_ITEMS) {
		bpf_printk("setting order of invalid offset");
		return SCX_BUDDY_CHUNK_MAX_ORDER;
	}

	result = chunk->orders[offset / 2];

	return (offset & 0x1) ? (result & 0xf) : (result >> 4);
}

static
u64 size_to_order(size_t size)
{
	u64 order;

	if (unlikely(!size)) {
		bpf_printk("size 0 has no order");
		bpf_printk("size 0 has no order");
		return 64;
	}

	/*
	 * To find the order of the allocation we find the first power of two
	 * >= the requested size, take the log2, then adjust it for the minimum
	 * allocation size by removing the minimum shift from it. Requests
	 * smaller than the minimum allocation size are rounded up.
	 */
	order = scx_ffs(scx_next_pow2(size));
	if (order < SCX_BUDDY_MIN_ALLOC_SHIFT)
		return 0;

	return order - SCX_BUDDY_MIN_ALLOC_SHIFT;
}

static
void __arena *chunk_idx_to_mem(scx_buddy_chunk_t *chunk, size_t idx)
{
	u64 address;

	/*
	 * The data blocks start in the chunk after the metadata block.
	 * We find the actual address by indexing into the region at an
	 * SCX_BUDDY_MIN_ALLOC_BYTES granularity, the minimum allowed.
	 * The index number already accounts for the fact that the first
	 * blocks in the chunk are occupied by the metadata, so we do
	 * not need to offset it.
	 */

	address = (u64)chunk + (idx * SCX_BUDDY_MIN_ALLOC_BYTES);

	return (void __arena *)address;
}

static
scx_buddy_header_t *chunk_get_header(scx_buddy_chunk_t *chunk, size_t idx)
{
	return (scx_buddy_header_t *)chunk_idx_to_mem(chunk, idx);
}

static
scx_buddy_chunk_t *scx_buddy_chunk_get(struct scx_stk *stk)
{
	u64 order, ord, last_order;
	scx_buddy_header_t *header;
	scx_buddy_chunk_t *chunk;
	u32 idx, cur_idx;
	int i, power2;
	size_t left;

	chunk = (scx_buddy_chunk_t *)scx_stk_alloc(stk);
	if (!chunk)
		return NULL;

	/*
	 * Initialize the chunk by carving out the first page to hold the metadata struct above,
	 * then dumping the rest of the pages into the allocator.
	 */

	bpf_for (i, 0, SCX_BUDDY_CHUNK_ITEMS) {
		header = chunk_get_header(chunk, i);
		header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
		header->next_index = SCX_BUDDY_CHUNK_ITEMS;
		if (header_set_order(chunk, i, SCX_BUDDY_CHUNK_MAX_ORDER))
			return NULL;
	}

	_Static_assert(SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE >= SCX_BUDDY_MIN_ALLOC_BYTES * SCX_BUDDY_CHUNK_ITEMS,
		"chunk must fit within the stack allocation");

	/*
	 * This reserves a chunk for the chunk metadata, then breaks
	 * the rest of the full allocation into the different buckets.
	 * We allocating the memory by grabbing blocks of progressively
	 * smaller sizes from the allocator, which are guaranteed to be
	 * continuous.
	 *
	 * This operation also populates the allocator.
	 */
	last_order = SCX_BUDDY_CHUNK_MAX_ORDER;
	left = sizeof(*chunk);
	cur_idx = 0;
	while(left && can_loop) {
		power2 = scx_ffs(left);
		if (unlikely(power2 >= SCX_BUDDY_CHUNK_MAX_ORDER)) {
			bpf_printk("buddy chunk metadata require allocation of order %d", power2);
			return NULL;
		}

		/* Round up allocations that are too small. */
		if (power2 < SCX_BUDDY_MIN_ALLOC_SHIFT) {
			order = 0;
			left = 0;
		} else {
			order = power2 - SCX_BUDDY_MIN_ALLOC_SHIFT;
			left -= 1 << power2;
		}

		idx = cur_idx;
		bpf_for (ord, order, last_order) {
			/* Skip to the buddy. */
			idx += 1 << ord;

			/* Mark it free. */
			chunk->order_indices[ord] = idx;
			if (header_set_order(chunk, idx, ord))
				return NULL;
		}

		/* Adjust the index. */
		cur_idx += 1 << order;
	}

	return chunk;
}

__hidden
int scx_buddy_init(struct scx_buddy *buddy, size_t size)
{
	scx_buddy_chunk_t *chunk;
	int ret;

	/* Set a minimum allocation size. */
	if (size < SCX_BUDDY_MIN_ALLOC_BYTES)
		return -EINVAL;

	/* Check if already initialized. */
	if (buddy->min_alloc_bytes)
		return -EALREADY;

	buddy->min_alloc_bytes = size;

	_Static_assert(SCX_BUDDY_CHUNK_PAGES > 0, "chunk must use one or more pages");

	/* One allocation per chunk. */
	ret = scx_stk_init(&buddy->stack, SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE, SCX_BUDDY_CHUNK_PAGES);
	if (ret) {
		buddy->min_alloc_bytes = 0;
		return ret;
	}

	chunk = scx_buddy_chunk_get(&buddy->stack);

	if (chunk) {
		/* Put the chunk at the beginning of the list. */
		chunk->next = buddy->first_chunk;
		chunk->prev = NULL;
		buddy->first_chunk = chunk;
	} else {
		/* Mark as uninitialized. */
		buddy->min_alloc_bytes = 0;
		buddy->first_chunk = NULL;
	}

	return chunk ? 0 : -ENOMEM;
}

__weak
u64 scx_buddy_chunk_alloc(scx_buddy_chunk_t *chunk, int order_req)
{
	scx_buddy_header_t *header;
	u64 address;
	u64 order = 0;
	u32 idx;

	bpf_for(order, order_req, SCX_BUDDY_CHUNK_MAX_ORDER) {
		if (chunk->order_indices[order] != SCX_BUDDY_CHUNK_ITEMS)
			break;
	}

	if (order == SCX_BUDDY_CHUNK_MAX_ORDER)
		return (u64)NULL;

	idx = chunk->order_indices[order];
	header = chunk_get_header(chunk, idx);
	chunk->order_indices[order] = header->next_index;

	header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
	header->next_index = SCX_BUDDY_CHUNK_ITEMS;
	if (header_set_order(chunk, idx, order_req))
		return (u64)NULL;

	address = (u64)chunk_idx_to_mem(chunk, idx);

	/* If we allocated from a larger-order chunk, split the buddies. */
	bpf_for(order, order_req, order) {
		/* Flip the bit for the current order. */
		idx ^= 1 << order;

		/* Add the buddy of the allocation to the free list. */
		header = chunk_get_header(chunk, idx);
		if (header_set_order(chunk, idx, order))
			return (u64)NULL;
		header->prev_index = SCX_BUDDY_CHUNK_ITEMS;

		header->next_index = chunk->order_indices[order];
		chunk->order_indices[order] = idx;
	}

	return address;
}

__weak
u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size)
{
	scx_buddy_chunk_t *chunk;
	u64 address;
	int order;

	order = size_to_order(size);
	if (order >= SCX_BUDDY_CHUNK_MAX_ORDER - 1) {
		bpf_printk("Allocation size %lu too large", size);
		return (u64)NULL;
	}

	bpf_spin_lock(&buddy->lock);
	chunk = buddy->first_chunk;
	do {
		address = scx_buddy_chunk_alloc(chunk, order);
		chunk = chunk->next;
	} while (address == (u64)NULL && can_loop);
	bpf_spin_unlock(&buddy->lock);

	if (address)
		return address;

	/* Get a new chunk. */
	chunk = scx_buddy_chunk_get(&buddy->stack);
	if (!chunk)
		return (u64)NULL;

	bpf_spin_lock(&buddy->lock);

	/* Add the chunk into the allocator and retry. */
	chunk->next = buddy->first_chunk;
	chunk->prev = NULL;
	buddy->first_chunk = chunk;

	address = scx_buddy_chunk_alloc(buddy->first_chunk, order);

	bpf_spin_unlock(&buddy->lock);

	return address;
}

__weak
void scx_buddy_free_internal(struct scx_buddy *buddy, u64 addr)
{
	scx_buddy_header_t *header, *buddy_header, *tmp_header;
	scx_buddy_chunk_t *chunk, *target_chunk;
	u64 idx, buddy_idx;
	u8 order;

	if (addr & (SCX_BUDDY_MIN_ALLOC_BYTES - 1)) {
		bpf_printk("Freeing unaligned address %llx", addr);
		return;
	}

	bpf_spin_lock(&buddy->lock);

	/* Align to the chunk boundary. */
	target_chunk = (void __arena *)(addr & ~SCX_BUDDY_CHUNK_OFFSET_MASK);

	/* XXX Only necessary for debugging. */
	for (chunk = buddy->first_chunk; chunk != NULL && can_loop; chunk = chunk->next) {
		if (chunk == target_chunk)
			break;
	}

	if (chunk == NULL) {
		bpf_spin_unlock(&buddy->lock);
		bpf_printk("could not find chunk for address %llx", addr);
		return;
	}

	/* Get the page idx. */
	idx = (addr & SCX_BUDDY_CHUNK_OFFSET_MASK) / SCX_BUDDY_MIN_ALLOC_BYTES;
	header = chunk_get_header(chunk, idx);

	bpf_for(order, header_get_order(chunk, idx), SCX_BUDDY_CHUNK_MAX_ORDER) {
		buddy_idx = idx ^= 1 << order;
		buddy_header = chunk_get_header(chunk, buddy_idx);

		/* Check if the buddy is not in the free list. */
		if (chunk->order_indices[order] != buddy_idx &&
		    buddy_header->prev_index == SCX_BUDDY_CHUNK_ITEMS &&
		    buddy_header->next_index == SCX_BUDDY_CHUNK_ITEMS)
			break;

		/* Pop off the list head if necessary. */
		if (chunk->order_indices[order] == buddy_idx)
			chunk->order_indices[order] = buddy_header->next_index;

		/* Pop */
		if (buddy_header->prev_index != SCX_BUDDY_CHUNK_ITEMS) {
			tmp_header = chunk_get_header(chunk, buddy_header->prev_index);
			tmp_header->next_index = buddy_header->next_index;
			buddy_header->next_index = SCX_BUDDY_CHUNK_ITEMS;
		}

		if (buddy_header->next_index != SCX_BUDDY_CHUNK_ITEMS) {
			tmp_header = chunk_get_header(chunk, buddy_header->next_index);
			tmp_header->prev_index = buddy_header->prev_index;
			buddy_header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
		}

		if (header_set_order(chunk, buddy_idx, SCX_BUDDY_CHUNK_MAX_ORDER))
			return;

		idx = idx < buddy_idx ? idx : buddy_idx;

		header = chunk_get_header(chunk, idx);
		if (header_set_order(chunk, idx, order + 1))
			return;
	}

	order = header_get_order(chunk, idx);
	header->next_index = chunk->order_indices[order];
	chunk->order_indices[order] = idx;

	bpf_spin_unlock(&buddy->lock);
}

/**
 * scx_userspace_arena_alloc_pages - BPF program to enable allocating arena pages
 * explicitly from userspace.
 *
 * @ctx->sz: Size to allocate. Any positive number is a valid request.
 * @ctx->ret: Address of the allocated pages. NULL if unable to allocate.
 */
SEC("syscall")
int scx_userspace_arena_alloc_pages(struct scx_userspace_arena_alloc_pages_args *ctx)
{
	u32 pages = (ctx->sz + PAGE_SIZE - 1) / PAGE_SIZE;
	ctx->sz = pages * PAGE_SIZE;

	ctx->ret = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	return 0;
}

/**
 * scx_userspace_arena_free_pages - BPF program to enable freeing arena pages
 * explicitly from userspace.
 *
 * @ctx->addr: Address of the allocated pages. Should have been allocated by
 *	`scx_userspace_arena_alloc_pages`.
 * @ctx->sz: Size to free. Should be the same number passed to
 *	`scx_userspace_arena_alloc_pages`.
 */
SEC("syscall")
int scx_userspace_arena_free_pages(struct scx_userspace_arena_free_pages_args *ctx)
{
	u32 pages = (ctx->sz + PAGE_SIZE - 1) / PAGE_SIZE;

	bpf_arena_free_pages(&arena, ctx->addr, pages);
	return 0;
}
