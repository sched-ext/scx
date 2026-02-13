/*
 * sim_sdt_stubs.c - Simulator implementations of BPF arena / SDT task storage
 *
 * In the real kernel, scx_task_alloc/data/free use BPF arena memory and
 * task-local storage maps for per-task scheduler context. In the simulator,
 * we use malloc and a simple hash table keyed by task_struct pointer.
 *
 * These are strong definitions that override the __weak stubs in
 * lib/scxtest/overrides.c.
 *
 * This file does NOT include vmlinux.h or BPF headers to avoid type
 * conflicts. It only needs opaque pointers and basic types.
 */

/* Forward-declare libc functions to avoid header conflicts with vmlinux.h */
extern void *calloc(unsigned long nmemb, unsigned long size);
extern void *malloc(unsigned long size);
extern void free(void *ptr);
extern void *memset(void *s, int c, unsigned long n);

/* Use kern_types.h for basic types (u32, u64, etc.) */
#include "kern_types.h"

/* Opaque — we only handle pointers, never dereference task_struct here */
struct task_struct;

/*
 * Hash table for mapping task_struct* → allocated per-task context.
 *
 * Open-addressing with linear probing. Sized for up to 1024 tasks
 * with ~50% load factor.
 */
#define SDT_HASH_SLOTS 2048
#define SDT_HASH_MASK (SDT_HASH_SLOTS - 1)

struct sdt_entry {
	struct task_struct *key; /* NULL = empty slot */
	void *data;             /* malloc'd per-task context */
};

static struct sdt_entry sdt_table[SDT_HASH_SLOTS];
static u64 sdt_data_size;
static int sdt_initialized;

static unsigned long sdt_hash_ptr(const void *p)
{
	/* Multiplicative hash — golden ratio constant */
	unsigned long v = (unsigned long)p;
	v ^= v >> 16;
	v *= 0x9e3779b97f4a7c15UL;
	v ^= v >> 32;
	return v & SDT_HASH_MASK;
}

static struct sdt_entry *sdt_find_slot(struct task_struct *p)
{
	unsigned long idx = sdt_hash_ptr(p);
	for (unsigned long i = 0; i < SDT_HASH_SLOTS; i++) {
		unsigned long slot = (idx + i) & SDT_HASH_MASK;
		if (sdt_table[slot].key == p || sdt_table[slot].key == (void *)0)
			return &sdt_table[slot];
	}
	return (void *)0; /* table full — should never happen */
}

/*
 * Initialize the per-task allocator. Called once during scheduler init.
 *
 * In the real kernel, this sets up the radix-tree allocator with arena
 * pages. In the simulator, we just record the data size for malloc.
 */
int scx_task_init(u64 data_size)
{
	sdt_data_size = data_size;
	memset(sdt_table, 0, sizeof(sdt_table));
	sdt_initialized = 1;
	return 0;
}

/*
 * Allocate per-task scheduler context for a task.
 *
 * Returns a pointer to zero-initialized memory of sdt_data_size bytes,
 * or NULL on failure.
 */
void *scx_task_alloc(struct task_struct *p)
{
	struct sdt_entry *entry;
	void *data;

	if (!sdt_initialized || !p)
		return (void *)0;

	data = calloc(1, sdt_data_size);
	if (!data)
		return (void *)0;

	entry = sdt_find_slot(p);
	if (!entry) {
		free(data);
		return (void *)0;
	}

	/* If slot already occupied by this key, free old data */
	if (entry->key == p && entry->data)
		free(entry->data);

	entry->key = p;
	entry->data = data;
	return data;
}

/*
 * Look up existing per-task context for a task.
 *
 * Returns NULL if the task has no allocated context.
 */
void *scx_task_data(struct task_struct *p)
{
	struct sdt_entry *entry;

	if (!sdt_initialized || !p)
		return (void *)0;

	entry = sdt_find_slot(p);
	if (!entry || entry->key != p)
		return (void *)0;

	return entry->data;
}

/*
 * Free per-task context when a task exits.
 */
void scx_task_free(struct task_struct *p)
{
	struct sdt_entry *entry;

	if (!sdt_initialized || !p)
		return;

	entry = sdt_find_slot(p);
	if (!entry || entry->key != p)
		return;

	free(entry->data);
	entry->key = (void *)0;
	entry->data = (void *)0;
}

/*
 * Arena subprogram initialization — no-op in the simulator.
 *
 * In the kernel, this works around a BPF verifier limitation by
 * forcing an LD.IMM instruction referencing the arena. Not needed
 * in userspace.
 */
void scx_arena_subprog_init(void)
{
}
