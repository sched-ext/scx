/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 Emil Tsalapatis <etsal@meta.com>
 */

#include <scx/common.bpf.h>

#include "sdt_task.h"

char _license[] SEC("license") = "GPL";

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

struct sdt_alloc_stack __arena *prealloc_stack;

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
static bool sdt_verify_once;

#define SDT_TASK_FN_ATTRS	inline __attribute__((unused, always_inline))

__hidden void sdt_subprog_init_arena(void)
{
	if (sdt_verify_once)
		return;

	bpf_printk("%s: arena pointer %p", __func__, &arena);
	sdt_verify_once = true;
}


private(LOCK) struct bpf_spin_lock sdt_lock;
private(POOL_LOCK) struct bpf_spin_lock sdt_pool_alloc_lock;

/* allocation pools */
struct sdt_pool sdt_desc_pool;
struct sdt_pool sdt_chunk_pool;

/* Protected by sdt_lock. */
struct sdt_stats sdt_stats;

static SDT_TASK_FN_ATTRS int sdt_ffs(__u64 word)
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
static SDT_TASK_FN_ATTRS __u64 sdt_chunk_find_empty(sdt_desc_t *desc)
{
	__u64 freeslots;
	__u64 i;

	cast_kern(desc);

	for (i = 0; i < SDT_TASK_CHUNK_BITMAP_U64S; i++) {
		freeslots = ~desc->allocated[i];
		if (freeslots == (__u64)0)
			continue;

		return (i * 64) + sdt_ffs(freeslots);
	}

	return SDT_TASK_ENTS_PER_CHUNK;
}

static SDT_TASK_FN_ATTRS
void __arena *sdt_alloc_stack_pop(struct sdt_alloc_stack __arena *stack)
{
	void __arena *slab;

	cast_kern(stack);

	/* Cannot print out diagnostic because we may be holding a lock. */
	if (unlikely(stack->idx == 0))
		return NULL;

	stack->idx -= 1;

	slab = stack->stack[stack->idx];

	return slab;
}

static SDT_TASK_FN_ATTRS
int sdt_alloc_stack(struct sdt_alloc_stack __arena *stack)
{
	void __arena *slab;

	cast_kern(stack);

	bpf_spin_lock(&sdt_lock);
	if (stack->idx >= SDT_TASK_ALLOC_STACK_MIN)
		return 0;

	bpf_spin_unlock(&sdt_lock);

	slab = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (slab == NULL)
		return -ENOMEM;

	bpf_spin_lock(&sdt_lock);

	/*
	 * Edge case where so many threads tried to allocate that our
	 * allocation does not fit into the stack.
	 */
	if (stack->idx >= SDT_TASK_ALLOC_STACK_MAX) {

		bpf_spin_unlock(&sdt_lock);

		bpf_arena_free_pages(&arena, slab, 1);
		return -EAGAIN;
	}

	stack->stack[stack->idx] = slab;
	stack->idx += 1;

	sdt_stats.arena_pages_used += 1;
	bpf_spin_unlock(&sdt_lock);

	return -EAGAIN;
}

static __noinline
int sdt_alloc_attempt(struct sdt_alloc_stack __arena *stack)
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
		if (sdt_alloc_stack(stack) == 0)
			return 0;
	}

	return -ENOMEM;
}

/* Allocate element from the pool. Must be called with a then pool lock held. */
static SDT_TASK_FN_ATTRS
void __arena *sdt_alloc_from_pool(struct sdt_pool *pool,
	struct sdt_alloc_stack __arena *stack)
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
		slab = sdt_alloc_stack_pop(stack);
		pool->slab = slab;
		pool->idx = 0;
	}

	ptr = (void __arena *)((__u64) pool->slab + elem_size * pool->idx);
	pool->idx += 1;

	return ptr;
}

/* Allocate element from the pool. Must be called with a then pool lock held. */
static SDT_TASK_FN_ATTRS
void __arena *sdt_alloc_from_pool_sleepable(struct sdt_pool *pool)
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
static SDT_TASK_FN_ATTRS
sdt_desc_t *sdt_alloc_chunk(struct sdt_alloc_stack __arena *stack)
{
	struct sdt_chunk __arena *chunk;
	sdt_desc_t *desc;
	sdt_desc_t *out;

	chunk = sdt_alloc_from_pool(&sdt_chunk_pool, stack);
	desc = sdt_alloc_from_pool(&sdt_desc_pool, stack);

	out = desc;

	cast_kern(desc);

	desc->nr_free = SDT_TASK_ENTS_PER_CHUNK;
	desc->chunk = chunk;

	sdt_stats.chunk_allocs += 1;

	return out;
}

static SDT_TASK_FN_ATTRS int sdt_pool_set_size(struct sdt_pool *pool, __u64 data_size, __u64 nr_pages)
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
sdt_alloc_init(struct sdt_allocator *alloc, __u64 data_size)
{
	size_t min_chunk_size;
	int ret;

	_Static_assert(sizeof(struct sdt_chunk) <= PAGE_SIZE,
		"chunk size must fit into a page");

	ret = sdt_pool_set_size(&sdt_chunk_pool, sizeof(struct sdt_chunk), 1);
	if (ret != 0)
		return ret;

	ret = sdt_pool_set_size(&sdt_desc_pool, sizeof(struct sdt_desc), 1);
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
	ret = sdt_pool_set_size(&alloc->pool, data_size, min_chunk_size);
	if (ret != 0)
		return ret;

	prealloc_stack = bpf_arena_alloc_pages(&arena, NULL, div_round_up(sizeof(*prealloc_stack), PAGE_SIZE), NUMA_NO_NODE, 0);
	if (prealloc_stack == NULL)
		return -ENOMEM;

	/* On success, returns with the lock taken. */
	ret = sdt_alloc_attempt(prealloc_stack);
	if (ret != 0)
		return ret;

	alloc->root = sdt_alloc_chunk(prealloc_stack);

	bpf_spin_unlock(&sdt_lock);

	return 0;
}

static SDT_TASK_FN_ATTRS
int sdt_set_idx_state(sdt_desc_t *desc, __u64 pos, bool state)
{
	__u64 __arena *allocated = desc->allocated;
	__u64 bit;

	cast_kern(allocated);

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
int sdt_mark_nodes_avail(sdt_desc_t *lv_desc[SDT_TASK_LEVELS], __u64 lv_pos[SDT_TASK_LEVELS])
{
	sdt_desc_t *desc;
	__u64 u, level;
	int ret;

	for (u = zero; u < SDT_TASK_LEVELS && can_loop; u++) {
		level = SDT_TASK_LEVELS - 1 - u;

		/* Only propagate upwards if we are the parent's only free chunk. */
		desc = lv_desc[level];

		/* Failed calls return unlocked. */
		ret = sdt_set_idx_state(desc, lv_pos[level], false);
		if (unlikely(ret != 0))
			return ret;

		cast_kern(desc);

		desc->nr_free += 1;
		if (desc->nr_free > 1)
			return 0;
	}

	return 0;
}

__weak
int sdt_free_idx(struct sdt_allocator *alloc, __u64 idx)
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

	sdt_subprog_init_arena();

	if (!alloc)
		return 0;

	bpf_spin_lock(&sdt_lock);

	desc = alloc->root;
	if (unlikely(!desc)) {
		bpf_spin_unlock(&sdt_lock);
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

		cast_kern(desc);

		chunk = desc->chunk;
		cast_kern(chunk);

		desc_children = (sdt_desc_t * __arena *)chunk->descs;
		desc = desc_children[pos];

		if (unlikely(!desc)) {
			bpf_spin_unlock(&sdt_lock);
			scx_bpf_error("%s: freeing nonexistent idx [0x%llx] (level %llu)",
				__func__, idx, level);
			return 0;
		}
	}

	cast_kern(desc);

	chunk = desc->chunk;
	cast_kern(chunk);

	pos = idx & mask;
	data = chunk->data[pos];
	if (likely(!data)) {
		cast_kern(data);

		data[pos] = (struct sdt_data) {
			.tid.genn = data->tid.genn + 1,
		};

		/* Zero out one word at a time. */
		for (i = zero; i < alloc->pool.elem_size / 8 && can_loop; i++) {
			data->payload[i] = 0;
		}
	}

	ret = sdt_mark_nodes_avail(lv_desc, lv_pos);
	if (unlikely(ret != 0)) {
		bpf_spin_unlock(&sdt_lock);
		return 0;
	}

	sdt_stats.active_allocs -= 1;
	sdt_stats.free_ops += 1;

	bpf_spin_unlock(&sdt_lock);

	return 0;
}

/*
 * Find and return an available idx on the allocator.
 * Called with the task spinlock held.
 */
static SDT_TASK_FN_ATTRS
sdt_desc_t * sdt_find_empty(sdt_desc_t *desc,
	struct sdt_alloc_stack __arena *stack,
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
		pos = sdt_chunk_find_empty(desc);

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

		cast_kern(desc);

		chunk = desc->chunk;
		cast_kern(chunk);

		desc_children = (sdt_desc_t * __arena *)chunk->descs;
		desc = desc_children[pos];
		if (!desc) {
			desc = sdt_alloc_chunk(stack);
			desc_children[pos] = desc;
		}
	}

	for (u = zero; u < SDT_TASK_LEVELS && can_loop; u++) {
		level = SDT_TASK_LEVELS - 1 - u;
		tmp = lv_desc[level];

		cast_kern(tmp);
		ret = sdt_set_idx_state(tmp, lv_pos[level], true);
		if (ret != 0)
			break;

		tmp->nr_free -= 1;
		if (tmp->nr_free > 0)
			break;

	}

	*idxp = idx;

	return desc;
}

static SDT_TASK_FN_ATTRS
void sdt_alloc_finish(struct sdt_data __arena *data, __u64 idx)
{
	bpf_spin_lock(&sdt_lock);

	/* The data counts as a chunk */
	sdt_stats.data_allocs += 1;
	sdt_stats.alloc_ops += 1;
	sdt_stats.active_allocs += 1;

	bpf_spin_unlock(&sdt_lock);

	cast_kern(data);
	data->tid.idx = idx;
}

__weak
u64 sdt_alloc_internal(struct sdt_allocator *alloc)
{
	struct sdt_alloc_stack __arena *stack = prealloc_stack;
	struct sdt_data __arena *data = NULL;
	struct sdt_chunk __arena *chunk;
	sdt_desc_t *desc;
	__u64 idx, pos;
	int ret;

	if (!alloc)
		return (u64)NULL;

	/* On success, call returns with the lock taken. */
	ret = sdt_alloc_attempt(stack);
	if (ret != 0)
		return (u64)NULL;

	/* We unlock if we encounter an error in the function. */
	desc = sdt_find_empty(alloc->root, stack, &idx);

	bpf_spin_unlock(&sdt_lock);

	if (unlikely(desc == NULL)) {
		bpf_printk("%s: failed to find empty tree key", __func__);
		return (u64)NULL;
	}

	cast_kern(desc);

	chunk = desc->chunk;
	cast_kern(chunk);

	/* Populate the leaf node if necessary. */
	pos = idx & (SDT_TASK_ENTS_PER_CHUNK - 1);
	data = chunk->data[pos];
	if (!data) {
		data = sdt_alloc_from_pool_sleepable(&alloc->pool);
		if (!data) {
			sdt_free_idx(alloc, idx);
			bpf_printk("%s: failed to allocate data from pool", __func__);
			return (u64)NULL;
		}
	}

	chunk->data[pos] = data;

	sdt_alloc_finish(data, idx);

	return (u64)data;
}


/*
 * Static allocation module used to allocate arena memory for
 * whose lifetime is that of the BPF program. Data is rarely
 * allocated, mostly at program init, and never freed. The
 * memory returned by this code is typeless so it avoids us
 * having to define an allocator for each type.
 */

struct sdt_static sdt_static;

__hidden
void __arena *sdt_static_alloc(size_t bytes)
{
	void __arena *memory, *old;
	void __arena *ptr;

	bpf_spin_lock(&sdt_lock);
	if (bytes > sdt_static.max_alloc_bytes) {
		bpf_spin_unlock(&sdt_lock);
		scx_bpf_error("invalid request %ld, max is %ld\n", bytes,
			      sdt_static.max_alloc_bytes);
		return NULL;
	}

	/*
	 * The code assumes that the maximum static allocation
	 * size is significantly larger than the typical allocation
	 * size, so it does not attempt to alleviate memory
	 * fragmentation.
	 */
	if (sdt_static.off + bytes  > sdt_static.max_alloc_bytes) {
		old = sdt_static.memory;

		bpf_spin_unlock(&sdt_lock);

		/*
		 * No free operation so just forget about the previous
		 * allocation memory.
		 */

		memory = bpf_arena_alloc_pages(&arena, NULL,
					       sdt_static.max_alloc_bytes / PAGE_SIZE,
					       NUMA_NO_NODE, 0);
		if (!memory)
			return NULL;

		bpf_spin_lock(&sdt_lock);

		/* Error out if we raced with another allocation. */
		if (sdt_static.memory != old) {
			bpf_spin_unlock(&sdt_lock);
			bpf_arena_free_pages(&arena, memory, sdt_static.max_alloc_bytes);

			scx_bpf_error("concurrent static memory allocations unsupported");
			return NULL;
		}

		/* Switch to new memory block, reset offset. */
		sdt_static.memory = memory;
		sdt_static.off = 0;

	}

	ptr = (void __arena *)((__u64) sdt_static.memory + sdt_static.off);
	sdt_static.off += bytes;

	bpf_spin_unlock(&sdt_lock);

	return ptr;
}

__weak
int sdt_static_init(size_t alloc_pages)
{
	size_t max_bytes = alloc_pages * PAGE_SIZE;
	void __arena *memory;

	memory = bpf_arena_alloc_pages(&arena, NULL, alloc_pages, NUMA_NO_NODE, 0);
	if (!memory)
		return -ENOMEM;

	bpf_spin_lock(&sdt_lock);
	sdt_static = (struct sdt_static) {
		.max_alloc_bytes = max_bytes,
		.off = 0,
		.memory = memory,
	};
	bpf_spin_unlock(&sdt_lock);

	return 0;
}
