/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
#ifdef __TARGET_ARCH_arm64
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

static int scx_ffs(__u64 word)
{
	unsigned int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}

	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}

	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}

	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}

	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}

	if ((word & 0x1) == 0) {
		num += 1;
		word >>= 1;
	}

	return num;
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
		scx_bpf_error("%s: allocation size %llu not word aligned", __func__, data_size);
		return -EINVAL;
	}

	if (unlikely(nr_pages == 0)) {
	      scx_bpf_error("%s: allocation size is 0", __func__);
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
	data_size = div_round_up(data_size, 8) * 8;

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
		scx_bpf_error("%s: root not allocated", __func__);
		return 0;
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
			scx_bpf_error("%s: freeing nonexistent idx [0x%llx] (level %llu)",
				__func__, idx, level);
			return 0;
		}
	}

	chunk = desc->chunk;

	pos = idx & mask;
	data = chunk->data[pos];
	if (likely(!data)) {

		data[pos] = (struct sdt_data) {
			.tid.gen = data->tid.gen + 1,
		};

		/* Zero out one word at a time. */
		for (i = zero; i < alloc->pool.elem_size / 8 && can_loop; i++) {
			data->payload[i] = 0;
		}
	}

	ret = mark_nodes_avail(lv_desc, lv_pos);
	if (unlikely(ret != 0)) {
		bpf_spin_unlock(&alloc_lock);
		return 0;
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

__weak
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
void __arena *scx_static_alloc(size_t bytes)
{
	void __arena *memory, *old;
	void __arena *ptr;

	bpf_spin_lock(&alloc_lock);
	if (bytes > scx_static.max_alloc_bytes) {
		bpf_spin_unlock(&alloc_lock);
		scx_bpf_error("invalid request %ld, max is %ld\n", bytes,
			      scx_static.max_alloc_bytes);
		return NULL;
	}

	/*
	 * The code assumes that the maximum static allocation
	 * size is significantly larger than the typical allocation
	 * size, so it does not attempt to alleviate memory
	 * fragmentation.
	 */
	if (scx_static.off + bytes  > scx_static.max_alloc_bytes) {
		old = scx_static.memory;

		bpf_spin_unlock(&alloc_lock);

		/*
		 * No free operation so just forget about the previous
		 * allocation memory.
		 */

		memory = bpf_arena_alloc_pages(&arena, NULL,
					       scx_static.max_alloc_bytes / PAGE_SIZE,
					       NUMA_NO_NODE, 0);
		if (!scx_static.memory)
			return NULL;

		bpf_spin_lock(&alloc_lock);

		/* Error out if we raced with another allocation. */
		if (scx_static.memory != old) {
			bpf_spin_unlock(&alloc_lock);
			bpf_arena_free_pages(&arena, memory, scx_static.max_alloc_bytes);

			scx_bpf_error("concurrent static memory allocations unsupported");
			return NULL;
		}
	}

	ptr = (void __arena *)((__u64) scx_static.memory + scx_static.off);
	scx_static.off += bytes;

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

	stack->lock = scx_static_alloc(sizeof(*stack->lock));
	if (!stack->lock) {
		scx_bpf_error("failed to allocate lock");
		return -ENOMEM;
	}

	return 0;
}

static void scx_stk_push(struct scx_stk *stack, void __arena *elem)
{
	scx_ring_t *ring = stack->current;
	int ridx = stack->cind;

	stack->current->elems[stack->cind] = elem;

	ridx += 1;

	/* Possibly loop into the next ring. */
	if (ridx == SCX_RING_MAX) {
		ridx = 0;
		ring = ring->next;
	}

	/* Possibly loop back into the first ring. */
	if (!ring)
		ring = stack->first;

	stack->current = ring;
	stack->cind = ridx;

	stack->capacity -= 1;
	stack->available += 1;
}

static
void __arena *scx_stk_pop(struct scx_stk *stack)
{
	scx_ring_t *ring = stack->current;
	void __arena *elem;
	int ridx = stack->cind;

	/* Possibly loop into previous next ring. */
	if (ridx == 0) {
		ridx = SCX_RING_MAX;
		ring = stack->current->prev;
	}

	ridx -= 1;

	/* Possibly loop back into the last ring. */
	if (!ring)
		ring = stack->last;

	stack->current = ring;
	stack->cind = ridx;

	elem = stack->current->elems[stack->cind];

	stack->capacity += 1;
	stack->available -= 1;

	return elem;
}

static
int scx_stk_ring_to_data(struct scx_stk *stack, size_t nelems)
{
	u64 data;
	int i;

	/* Do we have enough empty rings for the conversion? */
	if (!stack->first || stack->first == stack->last)
		return -ENOMEM;

	data = (u64)stack->last;
	stack->last->prev->next = NULL;
	stack->last = stack->last->prev;

	/* We removed a ring. */
	stack->capacity -= SCX_RING_MAX;

	for (i = zero; i < nelems && can_loop; i++) {
		scx_stk_push(stack, (void __arena *)data);
		data += stack->data_size;
	}

	return 0;
}

static
void scx_stk_extend(struct scx_stk *stack, scx_ring_t *ring)
{
	if (stack->last)
		stack->last->next = ring;

	ring->prev = stack->last;
	ring->next = NULL;

	stack->last = ring;
	stack->capacity += SCX_RING_MAX;

	if (!stack->first)
		stack->first = ring;

	/*
	 * Do not adjust the current ring/index because we did not add
	 * any elements. The new ring will be pushed into during the next
	 * allocation.
	 */
}

static
int scx_stk_free_unlocked(struct scx_stk *stack, void __arena *elem)
{
	if (!stack)
		return -EINVAL;

	/* If no more room, repurpose the allocation into a ring. */
	if (stack->capacity == 0) {
		scx_stk_extend(stack, (scx_ring_t *)elem);
		return 0;
	}

	scx_stk_push(stack, elem);

	return 0;
}

__weak
int scx_stk_free_internal(struct scx_stk *stack, __u64 elem)
{
	int ret;

	if (!stack)
		return -EINVAL;

	if ((ret = arena_spin_lock(stack->lock))) {
		scx_bpf_error("spinlock error %d", ret);
		return 0;
	}

	ret = scx_stk_free_unlocked(stack, (void __arena *)elem);

	arena_spin_unlock(stack->lock);

	return ret;
}

static
int scx_stk_get_arena_memory(struct scx_stk *stack, __u64 nr_pages, __u64 nrings)
{
	scx_ring_t *ring;
	int ret, i;
	u64 mem;

	arena_spin_unlock(stack->lock);

	/*
	 * The code allocates new memory only as rings. The allocation and
	 * free code freely typecasts the ring buffer into data that can be
	 * allocated, and vice versa to avoid either ending up with too many
	 * empty rings under memory pressure, or having no space in the ring
	 * buffer for a buffer currently being freed.
	 */

	/*
	 * On error, we return with the ring buffer unlocked. This is
	 * because arena_spin_lock can fail, so we cannot guarantee we
	 * can lock it back.
	 */
	if (!stack)
		return -EINVAL;

	/*
	 * We may alocate 2x the allocation size to ensure that a single
	 * rings allocation to handle a completely empty stack that has
	 * neither rings nor elements.
	 */
	mem = (__u64)bpf_arena_alloc_pages(&arena, NULL, nrings * nr_pages, NUMA_NO_NODE, 0);
	if (!mem)
		return -ENOMEM;

	if ((ret = arena_spin_lock(stack->lock))) {
		bpf_arena_free_pages(&arena, (void __arena *)mem, nr_pages);
		scx_bpf_error("spinlock error %d", ret);
		return ret;
	}

	_Static_assert(sizeof(struct scx_ring) <= PAGE_SIZE,
		"ring must fit into a page");

	/* Attach the rings to the reserve linked list. */
	for (i = zero; i < nrings && can_loop; i++) {
		ring = (scx_ring_t *)mem;
		ring->next = stack->reserve;
		stack->reserve = ring;

		mem += nr_pages * PAGE_SIZE;
	}

	return 0;
}

static
int scx_stk_fill_new_elems(struct scx_stk *stack)
{
	size_t nelems, nrings;
	scx_ring_t *ring;
	__u64 nr_pages;
	int ret, i;
	u64 mem;

	nr_pages = stack->nr_pages_per_alloc;
	nelems = (nr_pages * PAGE_SIZE) / stack->data_size;
	if (nelems > SCX_RING_MAX) {
		scx_bpf_error("new elements must fit into a single ring");
		return -EINVAL;
	}

	/* How many rings should we allocate? */
	nrings = stack->capacity ? 1 : 2;

	/*
	 * If we have more than two empty rings available,
	 * repurpose one of them into an allocation.
	 */
	ret = scx_stk_ring_to_data(stack, nelems);
	if (!ret)
		return 0;

	/* If we haven't set aside any memory from before, allocate. */
	if (!stack->reserve) {
		/* This call drops and retakes the lock.  */
		ret = scx_stk_get_arena_memory(stack, nr_pages, nrings);
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
		ring = stack->reserve;
		stack->reserve = stack->reserve->next;

		scx_stk_extend(stack, ring);
	}

	/* Pop out the reserve and attach to the stack. */
	ring = stack->reserve;
	stack->reserve = ring->next;

	mem = (u64)ring;
	for (i = zero; i < nelems && can_loop; i++) {
		scx_stk_push(stack, (void __arena *)mem);
		mem += stack->data_size;
	}

	return 0;
}

__weak
__u64 scx_stk_alloc(struct scx_stk *stack)
{
	void __arena *elem;
	int ret;

	if (!stack)
		return 0ULL;

	if ((ret = arena_spin_lock(stack->lock))) {
		scx_bpf_error("spinlock error %d", ret);
		return 0ULL;
	}

	/* If ring buffer is empty, we have to populate it. */
	if (stack->available == 0) {
		/* The call drops the lock on error. */
		ret = scx_stk_fill_new_elems(stack);
		if (ret) {
			scx_bpf_error("elem creation failed");
			return 0ULL;
		}
	}

	elem = scx_stk_pop(stack);

	arena_spin_unlock(stack->lock);

	if (!elem)
		scx_bpf_error("returning NULL");

	return (u64)elem;
}

static
void header_set_order(scx_buddy_chunk_t *chunk, u64 offset, u8 order)
{
	if (order >= SCX_BUDDY_CHUNK_ORDERS) {
		scx_bpf_error("setting invalid order");
		return;
	}

	if (offset >= SCX_BUDDY_CHUNK_ITEMS) {
		scx_bpf_error("setting order of invalid offset");
		return;
	}

	if (offset & 0x1)
		order &= 0xf;
	else
		order <<= 4;

	chunk->orders[offset / 2] |= order;
}

static
u8 header_get_order(scx_buddy_chunk_t *chunk, u64 offset)
{
	u8 result;

	if (offset >= SCX_BUDDY_CHUNK_ITEMS) {
		scx_bpf_error("setting order of invalid offset");
		return SCX_BUDDY_CHUNK_ORDERS;
	}

	result = chunk->orders[offset / 2];

	return (offset & 0x1) ? (result & 0xf) : (result >> 4);
}

static
scx_buddy_header_t *chunk_get_header(scx_buddy_chunk_t *chunk, u8 offset)
{
	return &chunk->headers[offset];
}

static
scx_buddy_chunk_t *scx_buddy_chunk_get(struct scx_stk *stk)
{
	scx_buddy_chunk_t *chunk;
	scx_buddy_header_t *header;
	u8 index;
	u64 order;
	int i;

	_Static_assert(sizeof(struct scx_buddy_chunk) <= PAGE_SIZE, "chunk must fit into a page");

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
		header_set_order(chunk, i, SCX_BUDDY_CHUNK_ORDERS);
	}


	/*
	 * This reserves the first page for the scx_buddy_chunk then breaks the
	 * full allocation into the different buckets.
	 */
	index = 0;
	bpf_for (order, 0, SCX_BUDDY_CHUNK_ORDERS - 1) {
		index += 1 << order;
		chunk->order_indices[order] = index;
		header_set_order(chunk, index, order);
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

	bpf_spin_lock(&buddy->lock);
	/* Check if already initialized. */
	if (buddy->min_alloc_bytes) {
		bpf_spin_unlock(&buddy->lock);
		return -EALREADY;
	}

	buddy->min_alloc_bytes = size;
	bpf_spin_unlock(&buddy->lock);

	/* One allocation per chunk. */
	ret = scx_stk_init(&buddy->stack, SCX_BUDDY_CHUNK_PAGES * PAGE_SIZE, SCX_BUDDY_CHUNK_PAGES);
	if (ret) {
		bpf_spin_lock(&buddy->lock);
		buddy->min_alloc_bytes = 0;
		bpf_spin_unlock(&buddy->lock);
		return ret;
	}

	chunk = scx_buddy_chunk_get(&buddy->stack);

	bpf_spin_lock(&buddy->lock);

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

	bpf_spin_unlock(&buddy->lock);

	return chunk ? 0 : -ENOMEM;
}

__weak
u64 scx_buddy_chunk_alloc(scx_buddy_chunk_t *chunk, int order_req)
{
	scx_buddy_header_t *header;
	u64 address;
	u64 order;
	u8 index;

	bpf_for(order, order_req, SCX_BUDDY_CHUNK_ORDERS) {
		if (chunk->order_indices[order] != SCX_BUDDY_CHUNK_ITEMS)
			break;
	}

	if (order == SCX_BUDDY_CHUNK_ORDERS)
		return (u64)NULL;

	index = chunk->order_indices[order];
	header = chunk_get_header(chunk, index);
	chunk->order_indices[order] = header->next_index;

	header->prev_index = SCX_BUDDY_CHUNK_ITEMS;
	header->next_index = SCX_BUDDY_CHUNK_ITEMS;
	header_set_order(chunk, index, order_req);

	address = (u64)chunk + PAGE_SIZE + (index * SCX_BUDDY_MIN_ALLOC_BYTES);

	/* If we allocated from a larger-order chunk, split the buddies. */
	bpf_for(order, order_req, order) {
		/* Flip the bit for the current order. */
		index ^= 1 << order;

		/* Add the buddy of the allocation to the free list. */
		header = chunk_get_header(chunk, index);
		header_set_order(chunk, index, order);
		header->prev_index = SCX_BUDDY_CHUNK_ITEMS;

		header->next_index = chunk->order_indices[order];
		chunk->order_indices[order] = index;
	}

	return address;
}

__weak
u64 scx_buddy_alloc_internal(struct scx_buddy *buddy, size_t size)
{
	scx_buddy_chunk_t *chunk;
	u64 address;
	int order;

	order = 1 << (63 - scx_ffs(size / PAGE_SIZE));
	if (order >= SCX_BUDDY_CHUNK_ORDERS - 1) {
		scx_bpf_error("Allocation size %lu too large", size);
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
	u64 index, buddy_index;
	u8 order;

	if (addr & (PAGE_SIZE - 1)) {
		scx_bpf_error("Freeing non-page aligned address %llx", addr);
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
		scx_bpf_error("could not find chunk for address %llx", addr);
		return;
	}

	/* Get the page index. */
	index = (addr & SCX_BUDDY_OFFSET_MASK) >> 12;
	header = chunk_get_header(chunk, index);

	bpf_for(order, header_get_order(chunk, index), SCX_BUDDY_CHUNK_ORDERS) {
		buddy_index = index ^= 1 << order;
		buddy_header = chunk_get_header(chunk, buddy_index);

		/* Check if the buddy is not in the free list. */
		if (chunk->order_indices[order] != buddy_index &&
		    buddy_header->prev_index == SCX_BUDDY_CHUNK_ITEMS &&
		    buddy_header->next_index == SCX_BUDDY_CHUNK_ITEMS)
			break;

		/* Pop off the list head if necessary. */
		if (chunk->order_indices[order] == buddy_index)
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

		header_set_order(chunk, buddy_index, SCX_BUDDY_CHUNK_ORDERS);

		index = index < buddy_index ? index : buddy_index;

		header = chunk_get_header(chunk, index);
		header_set_order(chunk, index, order + 1);
	}

	order = header_get_order(chunk, index);
	header->next_index = chunk->order_indices[order];
	chunk->order_indices[order] = index;

	bpf_spin_unlock(&buddy->lock);
}
