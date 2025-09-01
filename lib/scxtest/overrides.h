#pragma once

/*
 * This is meant to override certain things we don't need to have for our tests.
 *
 * Stub structs should all go into scheds/include/arch/test/vmlinux.h.
 *
 * This is only meant for things/functionality that we are explicitly disabling,
 * basically if it's a
 *
 * #define some_special_macro(x) do_some_stuff
 *
 * that we want to get rid of that belongs here.
 */
#define __builtin_preserve_field_info(x,y) 1
#define __builtin_preserve_enum_value(x,y) 1

#define bpf_addr_space_cast(var, dst_as, src_as)

#define MEMBER_VPTR(base, member) \
	(typeof((base) member) *)(&((base)member))

#define ARRAY_ELEM_PTR(arr, i, n) \
	(typeof(arr[i]) *)((char *)(arr) + (i) * sizeof(typeof(*(arr))))

/* This is a static helper for some reason, so we have to define it here. */
#define bpf_get_prandom_u32() 0

/* Arena spinlock stubs for unittest environment */
#define arena_spin_lock(lock) 0
#define arena_spin_unlock(lock) do { (void)(lock); } while(0)

/* Define arena_spinlock_t as simple int for unittest environment */
#define arena_spinlock_t int

/* Stub out __arena for unittest environment */
#define __arena



/* Function declarations for BPF functions overridden in overrides.c */
struct task_struct;
void *scx_task_data(struct task_struct *p);
void *scx_minheap_alloc(unsigned int nr_elems);
int scx_minheap_insert(void *heap_ptr, unsigned long long key, unsigned long long value);
struct scx_minheap_elem;
int scx_minheap_pop(void *heap_ptr, struct scx_minheap_elem *helem);
unsigned long long scx_atq_create_internal(int fifo, unsigned long capacity);
int scx_atq_insert(void *atq_ptr, unsigned long long taskc_ptr);
int scx_atq_insert_vtime(void *atq, unsigned long long taskc_ptr, unsigned long long vtime);
int scx_atq_nr_queued(void *atq);
unsigned long long scx_atq_pop(void *atq);
unsigned long long scx_atq_peek(void *atq);
void *scx_task_alloc(struct task_struct *p);
void scx_task_free(struct task_struct *p);
#define scx_atq_create_size(fifo, capacity) scx_atq_create_internal((fifo), (capacity))


