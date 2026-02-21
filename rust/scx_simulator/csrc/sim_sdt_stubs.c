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

/* Declared in sim_task.c — gets PID from task pointer */
extern int sim_task_get_pid(struct task_struct *p);

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

/*
 * Hash a task's PID for deterministic hash table placement.
 *
 * We hash by PID rather than pointer address because pointer addresses
 * are not deterministic between simulation runs (calloc returns different
 * addresses depending on heap state). Using PID ensures the hash table
 * lookup path is identical across runs, enabling deterministic instruction
 * counts.
 */
static unsigned long sdt_hash_pid(int pid)
{
	/* Multiplicative hash — golden ratio constant */
	unsigned long v = (unsigned long)pid;
	v ^= v >> 16;
	v *= 0x9e3779b97f4a7c15UL;
	v ^= v >> 32;
	return v & SDT_HASH_MASK;
}

/*
 * Find a slot in the hash table for the given task.
 *
 * Uses PID-based hashing for deterministic probe sequences, but stores
 * and matches by task_struct pointer for correctness (PIDs are unique
 * per-task but the pointer is the actual key).
 */
static struct sdt_entry *sdt_find_slot(struct task_struct *p)
{
	int pid = p ? sim_task_get_pid(p) : 0;
	unsigned long idx = sdt_hash_pid(pid);
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

/*
 * Reset global state to allow deterministic re-runs.
 *
 * The simulator binary links sim_sdt_stubs.c into the main executable,
 * so its static variables persist across simulation runs. This function
 * resets the SDT hash table state to what it would be after a fresh
 * scx_task_init() call with the same data_size.
 *
 * NOTE: This does NOT reset sdt_initialized to 0 because scx_task_init()
 * is only called during scheduler load (lavd_setup), not at the start of
 * each simulation run. If we set sdt_initialized=0, scx_task_alloc would
 * fail. Instead, we clear the hash table while keeping the initialization
 * state intact.
 */
void sim_sdt_reset(void)
{
	/* Clear the hash table to the same state as after scx_task_init().
	 * memset is deterministic (same instruction count regardless of
	 * current table contents), unlike iterating and checking each slot. */
	memset(sdt_table, 0, sizeof(sdt_table));
	/* Note: sdt_initialized and sdt_data_size are NOT reset here.
	 * They are set during scheduler load (scx_task_init) and must
	 * persist across simulation runs with the same scheduler. */
}
