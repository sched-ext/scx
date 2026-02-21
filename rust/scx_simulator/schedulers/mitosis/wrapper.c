/*
 * mitosis_wrapper.c - Wrapper to compile scx_mitosis as userspace C
 *
 * This file includes the simulator wrapper infrastructure and then
 * the actual scheduler source. The header guards in common.bpf.h
 * prevent re-inclusion, so our overridden macros take effect.
 *
 * NOTE: This file is compiled with -Dconst= to strip const qualifiers.
 * BPF schedulers declare globals as "const volatile" (patched by the
 * BPF loader). Stripping const makes them writable from Rust.
 *
 * Map strategy: BPF ARRAY maps pre-allocate all entries (zeroed).
 * The scx_test_map infrastructure uses sparse dynamic storage with a
 * void** indexing bug for values > 8 bytes. We bypass it entirely
 * by using static arrays for all ARRAY/PERCPU_ARRAY maps and a
 * PID-indexed array for task storage.
 */
#include "sim_wrapper.h"
#include "sim_task.h"

/* Forward declarations for libc functions */
extern void *memset(void *s, int c, unsigned long n);

/* ---------------------------------------------------------------------------
 * Macro overrides (defined after sim_wrapper.h, before mitosis.bpf.c)
 * ---------------------------------------------------------------------------*/

/*
 * Force scx_bpf_select_cpu_dfl fallback -- avoids needing
 * scx_bpf_select_cpu_and which isn't implemented in the simulator.
 */
#undef bpf_ksym_exists
#define bpf_ksym_exists(sym) (0)

/*
 * The simulator always calls select_cpu before enqueue, so the
 * CPU is always selected.
 */
#undef __COMPAT_is_enq_cpu_selected
#define __COMPAT_is_enq_cpu_selected(enq_flags) (true)

/*
 * is_migration_disabled: use the simulator's task_struct accessor.
 *
 * The kernel's is_migration_disabled() checks p->migration_disabled with
 * special handling for migration_disabled == 1 (ambiguous because BPF
 * prolog increments it). In the simulator, we use a simpler check:
 * migration_disabled > 0 means disabled.
 */
extern unsigned short sim_task_get_migration_disabled(struct task_struct *p);
#undef is_migration_disabled
#define is_migration_disabled(p) (sim_task_get_migration_disabled(p) > 0)

/* ---------------------------------------------------------------------------
 * Per-CPU context override
 *
 * Route bpf_map_lookup_percpu_elem to a static cpu_ctx array.
 * Forward-declared here; defined after the scheduler source since
 * struct cpu_ctx is defined there.
 * ---------------------------------------------------------------------------*/
static struct cpu_ctx *mitosis_lookup_percpu_elem(int cpu);
#undef bpf_map_lookup_percpu_elem
#define bpf_map_lookup_percpu_elem(map, key, cpu) mitosis_lookup_percpu_elem(cpu)

/* ---------------------------------------------------------------------------
 * bpf_map_lookup_elem override
 *
 * Routes all ARRAY map lookups to static arrays, bypassing the
 * scx_test_map infrastructure entirely. This avoids a void** stride
 * bug in scx_test_map_lookup_elem for values > 8 bytes.
 * ---------------------------------------------------------------------------*/
static void *mitosis_map_lookup_elem(void *map, const void *key);
#undef bpf_map_lookup_elem
#define bpf_map_lookup_elem(map, key) mitosis_map_lookup_elem(map, key)

/* ---------------------------------------------------------------------------
 * Task storage override
 *
 * Override bpf_task_storage_get to use a PID-indexed static array
 * instead of the scx_test_map infrastructure.
 * ---------------------------------------------------------------------------*/
static void *mitosis_task_storage_get(void *map, void *task, void *value,
				      unsigned long flags);
#undef bpf_task_storage_get
#define bpf_task_storage_get(map, task, value, flags) \
	mitosis_task_storage_get(map, task, value, flags)

/* ---------------------------------------------------------------------------
 * Cgroup storage override
 *
 * bpf_cgroup_from_id, bpf_cgroup_ancestor, and scx_bpf_task_cgroup are
 * now handled by the simulator's general kfuncs. Only per-cgroup local
 * storage needs a scheduler-specific override.
 * ---------------------------------------------------------------------------*/

/*
 * bpf_cgrp_storage_get: per-cgroup local storage.
 * Not overridden by scx_test_map.h, so we provide our own
 * implementation keyed by cgroup pointer.
 */
static void *mitosis_cgrp_storage_get(void *map, void *cgrp, void *value,
				      unsigned long flags);
#undef bpf_cgrp_storage_get
#define bpf_cgrp_storage_get(map, cgrp, value, flags) \
	mitosis_cgrp_storage_get(map, cgrp, value, flags)

/* ---------------------------------------------------------------------------
 * BPF timer overrides
 *
 * bpf_timer_set_callback stores the callback pointer.
 * bpf_timer_start calls sim_timer_start() (Rust kfunc) to schedule
 * a TimerFired event in the simulator's event queue.
 * mitosis_fire_timer() invokes the stored callback from the engine.
 * ---------------------------------------------------------------------------*/
static int (*mitosis_timer_cb)(void *, int *, struct bpf_timer *);
static struct bpf_timer *mitosis_timer_ptr;
static void *mitosis_timer_map;

extern void sim_timer_start(unsigned long long nsecs);

#undef bpf_timer_init
#define bpf_timer_init(timer, map, flags) \
	(mitosis_timer_map = (void *)(map), 0)

#undef bpf_timer_set_callback
#define bpf_timer_set_callback(timer, cb) \
	(mitosis_timer_cb = (typeof(mitosis_timer_cb))(cb), \
	 mitosis_timer_ptr = (struct bpf_timer *)(timer), 0)

#undef bpf_timer_start
#define bpf_timer_start(timer, nsecs, flags) \
	(sim_timer_start(nsecs), 0)

/* ---------------------------------------------------------------------------
 * RAII cleanup neutralization
 *
 * The upstream mitosis BPF code uses gcc cleanup attributes for automatic
 * resource management (RAII). The pattern is:
 *   struct cgroup *cgrp __free(cgroup) = bpf_cgroup_from_id(id);
 *
 * This calls __free_cgroup(cgrp) when the scope exits, which calls
 * bpf_cgroup_release(). In the simulator, we don't do reference counting,
 * so we neutralize these macros.
 *
 * The macros are defined in cleanup.bpf.h which is included via mitosis.bpf.h.
 * We include cleanup.bpf.h FIRST to let it define its macros, then we
 * override them with our neutralized versions.
 * ---------------------------------------------------------------------------*/

/*
 * RCU read lock stubs - must be defined before cleanup.bpf.h since it
 * references them. The simulator doesn't have real RCU.
 */
#undef bpf_rcu_read_lock
#define bpf_rcu_read_lock() ((void)0)

#undef bpf_rcu_read_unlock
#define bpf_rcu_read_unlock() ((void)0)

/* Include cleanup.bpf.h to let it define its RAII framework first */
#include "cleanup.bpf.h"

/* Now override the RAII macros with neutralized versions */

/* Strip __free() cleanup attributes - simulator manages resources manually */
#undef __free
#define __free(x)

/* no_free_ptr just returns the pointer unchanged */
#undef no_free_ptr
#define no_free_ptr(p) (p)

/* bpf_kptr_xchg: atomically exchange pointer, return old value */
static inline void *sim_kptr_xchg(void **kptr, void *new_val) {
	void *old = *kptr;
	*kptr = new_val;
	return old;
}
#undef bpf_kptr_xchg
#define bpf_kptr_xchg(kptr, val) sim_kptr_xchg((void **)(kptr), (void *)(val))

/* Cgroup acquire/release - simulator doesn't do reference counting */
static inline struct cgroup *sim_cgroup_acquire(struct cgroup *cgrp) {
	return cgrp;
}
#undef bpf_cgroup_acquire
#define bpf_cgroup_acquire(cgrp) sim_cgroup_acquire(cgrp)

#undef bpf_cgroup_release
#define bpf_cgroup_release(cgrp) ((void)0)

/*
 * cpumask acquire/release:
 * - acquire: just return the cpumask (no refcounting)
 * - release: must actually free since bpf_cpumask_create allocates
 *
 * Note: bpf_cpumask_release is already handled by scx_test_map.h or
 * we need to provide our own implementation that calls sim_cpumask_release.
 */

/* ---------------------------------------------------------------------------
 * Include mitosis source
 * ---------------------------------------------------------------------------*/
#include "intf.h"
#include "mitosis.bpf.c"

/* ---------------------------------------------------------------------------
 * Implementations (after mitosis.bpf.c, so struct types are available)
 * ---------------------------------------------------------------------------*/

/*
 * Static arrays for all maps.
 *
 * BPF ARRAY maps pre-allocate all entries (zeroed at map creation).
 * We model this with static BSS arrays, which are zero-initialized
 * by the C runtime. The mitosis_setup() function re-zeroes them
 * so the scheduler can be re-loaded within the same process.
 */
#define MAX_SIM_CPUS 128
#define MAX_SIM_TASKS 4096

/* cpu_ctxs: PERCPU_ARRAY, 1 entry per CPU */
static struct cpu_ctx percpu_ctx[MAX_SIM_CPUS];

/* cell_cpumasks: ARRAY, MAX_CELLS entries */
static struct cell_cpumask_wrapper cell_cpumasks_arr[MAX_CELLS];

/* cells: ARRAY, MAX_CELLS entries */
static struct cell cells_arr[MAX_CELLS];

/* debug_events: ARRAY, DEBUG_EVENTS_BUF_SIZE entries */
static struct debug_event debug_events_arr[DEBUG_EVENTS_BUF_SIZE];

/* update_timer: ARRAY, 1 entry */
static struct update_timer update_timer_arr[1];

/* cgrp_init_percpu_cpumask: PERCPU_ARRAY, MAX_CPUMASK_ENTRIES per CPU */
static struct cpumask_entry cgrp_init_cpumask_arr[MAX_SIM_CPUS][MAX_CPUMASK_ENTRIES];

/* task_ctxs: TASK_STORAGE, indexed by PID */
static struct task_ctx task_ctx_arr[MAX_SIM_TASKS];
static bool task_ctx_in_use[MAX_SIM_TASKS];

/* ---------------------------------------------------------------------------
 * Per-CPU context lookup
 * ---------------------------------------------------------------------------*/

static struct cpu_ctx *mitosis_lookup_percpu_elem(int cpu)
{
	if (cpu < 0 || cpu >= MAX_SIM_CPUS)
		return NULL;
	return &percpu_ctx[cpu];
}

/* ---------------------------------------------------------------------------
 * Map lookup: route each map to its static array
 * ---------------------------------------------------------------------------*/

static void *mitosis_map_lookup_elem(void *map, const void *key)
{
	u32 idx = *(const u32 *)key;

	if (map == &cpu_ctxs) {
		int cpu = sim_bpf_get_smp_processor_id();
		if (cpu < 0 || cpu >= MAX_SIM_CPUS)
			return NULL;
		return &percpu_ctx[cpu];
	}
	if (map == &cell_cpumasks) {
		if (idx >= MAX_CELLS)
			return NULL;
		return &cell_cpumasks_arr[idx];
	}
	if (map == &cells) {
		if (idx >= MAX_CELLS)
			return NULL;
		return &cells_arr[idx];
	}
	if (map == &debug_events) {
		if (idx >= DEBUG_EVENTS_BUF_SIZE)
			return NULL;
		return &debug_events_arr[idx];
	}
	if (map == (void *)&update_timer) {
		if (idx >= 1)
			return NULL;
		return &update_timer_arr[idx];
	}
	if (map == &cgrp_init_percpu_cpumask) {
		/* PERCPU_ARRAY: bpf_map_lookup_elem returns current CPU's entry */
		int cpu = sim_bpf_get_smp_processor_id();
		if (cpu < 0 || cpu >= MAX_SIM_CPUS ||
		    idx >= MAX_CPUMASK_ENTRIES)
			return NULL;
		return &cgrp_init_cpumask_arr[cpu][idx];
	}
	/* Unknown map -- should not happen */
	return NULL;
}

/* ---------------------------------------------------------------------------
 * Task storage: PID-indexed static array
 * ---------------------------------------------------------------------------*/

#ifndef BPF_LOCAL_STORAGE_GET_F_CREATE
#define BPF_LOCAL_STORAGE_GET_F_CREATE (1ULL << 0)
#endif

static void *mitosis_task_storage_get(void *map, void *task, void *value,
				      unsigned long flags)
{
	struct task_struct *p = (struct task_struct *)task;
	int pid;

	(void)map;
	(void)value;

	if (!p)
		return NULL;

	pid = p->pid;
	if (pid < 0 || pid >= MAX_SIM_TASKS)
		return NULL;

	if (task_ctx_in_use[pid])
		return &task_ctx_arr[pid];

	if (flags & BPF_LOCAL_STORAGE_GET_F_CREATE) {
		task_ctx_in_use[pid] = true;
		memset(&task_ctx_arr[pid], 0, sizeof(struct task_ctx));
		return &task_ctx_arr[pid];
	}

	return NULL;
}

/*
 * Cgroup storage: simple array mapping cgroup pointers to cgrp_ctx values.
 * Since we only have the root cgroup, a small array suffices.
 */
#define MAX_CGRP_STORAGE_ENTRIES 64

struct mitosis_cgrp_storage_entry {
	void *cgrp;
	struct cgrp_ctx ctx;
	bool in_use;
};

static struct mitosis_cgrp_storage_entry
	cgrp_storage_entries[MAX_CGRP_STORAGE_ENTRIES];

static void *mitosis_cgrp_storage_get(void *map, void *cgrp, void *value,
				      unsigned long flags)
{
	int i;
	(void)map;
	(void)value;

	/* Look up existing entry */
	for (i = 0; i < MAX_CGRP_STORAGE_ENTRIES; i++) {
		if (cgrp_storage_entries[i].in_use &&
		    cgrp_storage_entries[i].cgrp == cgrp)
			return &cgrp_storage_entries[i].ctx;
	}

	/* Create if requested */
	if (flags & BPF_LOCAL_STORAGE_GET_F_CREATE) {
		for (i = 0; i < MAX_CGRP_STORAGE_ENTRIES; i++) {
			if (!cgrp_storage_entries[i].in_use) {
				cgrp_storage_entries[i].in_use = true;
				cgrp_storage_entries[i].cgrp = cgrp;
				memset(&cgrp_storage_entries[i].ctx, 0,
				       sizeof(struct cgrp_ctx));
				return &cgrp_storage_entries[i].ctx;
			}
		}
	}

	return NULL;
}

/* ---------------------------------------------------------------------------
 * fire_timer: called from the Rust engine when a TimerFired event fires.
 * ---------------------------------------------------------------------------*/
void mitosis_fire_timer(void)
{
	int key = 0;
	if (mitosis_timer_cb && mitosis_timer_ptr)
		mitosis_timer_cb(mitosis_timer_map, &key, mitosis_timer_ptr);
}

/* ---------------------------------------------------------------------------
 * Setup function called from Rust before mitosis_init().
 *
 * Sets global variables, populates the all_cpus bitmask, and clears
 * all static map arrays so the scheduler starts with clean state.
 * ---------------------------------------------------------------------------*/
void mitosis_setup(unsigned int num_cpus)
{
	unsigned int i;

	/* Clear all static map arrays */
	memset(percpu_ctx, 0, sizeof(percpu_ctx));
	memset(cell_cpumasks_arr, 0, sizeof(cell_cpumasks_arr));
	memset(cells_arr, 0, sizeof(cells_arr));
	memset(debug_events_arr, 0, sizeof(debug_events_arr));
	memset(update_timer_arr, 0, sizeof(update_timer_arr));
	memset(cgrp_init_cpumask_arr, 0, sizeof(cgrp_init_cpumask_arr));
	memset(task_ctx_arr, 0, sizeof(task_ctx_arr));
	memset(task_ctx_in_use, 0, sizeof(task_ctx_in_use));
	memset(cgrp_storage_entries, 0, sizeof(cgrp_storage_entries));

	/* Clear timer state from previous runs */
	mitosis_timer_cb = NULL;
	mitosis_timer_ptr = NULL;
	mitosis_timer_map = NULL;

	/* Set globals to safe simulator values */
	nr_possible_cpus = num_cpus;
	smt_enabled = false;
	slice_ns = 20000000;   /* 20ms */
	root_cgid = 1;
	debug_events_enabled = false;
	exiting_task_workaround_enabled = false;
	cpu_controller_disabled = true;
	reject_multicpu_pinning = false;

	/* Populate all_cpus bitmask for each simulated CPU */
	memset((void *)all_cpus, 0, sizeof(all_cpus));
	for (i = 0; i < num_cpus && i < MAX_CPUS; i++)
		((volatile unsigned char *)all_cpus)[i / 8] |=
			(unsigned char)(1 << (i % 8));
}
