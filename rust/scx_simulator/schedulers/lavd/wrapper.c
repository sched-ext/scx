/*
 * lavd_wrapper.c - Wrapper to compile scx_lavd as userspace C
 *
 * This file includes the simulator wrapper infrastructure and then
 * all LAVD BPF source files as a single translation unit. Header
 * guards prevent re-inclusion of common headers.
 *
 * NOTE: Compiled with -Dconst= to strip const qualifiers so BPF
 * "const volatile" globals become writable from Rust.
 */
#include "sim_wrapper.h"
#include "sim_task.h"

/*
 * =================================================================
 * LAVD-specific macro overrides
 * (after sim_wrapper.h, before LAVD source)
 * =================================================================
 */

/*
 * __hidden: BPF internal visibility attribute. Defined in libbpf's
 * bpf_helpers.h which may not be available. Provide a fallback.
 */
#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

/*
 * bpf_strncmp has reversed argument order vs C strncmp.
 *   BPF: bpf_strncmp(s1, n, s2) -- compares s1[0..n] against s2
 *   C:   strncmp(s1, s2, n)
 * Use __builtin_strncmp to avoid declaration issues with -Dconst=.
 */
#undef bpf_strncmp
#define bpf_strncmp(s1, n, s2) __builtin_strncmp(s1, s2, n)

/*
 * Ring buffer stubs -- introspection is not needed in simulation.
 * bpf_ringbuf_reserve/submit are static function pointers from
 * bpf_helper_defs.h, so #undef + #define is safe.
 */
#undef bpf_ringbuf_reserve
#define bpf_ringbuf_reserve(map, sz, flags) ((void *)0)
#undef bpf_ringbuf_submit
#define bpf_ringbuf_submit(data, flags) do {} while(0)

/*
 * bpf_per_cpu_ptr -- kernel per-CPU variables don't exist in the
 * simulator. Return NULL so callers skip the code path.
 */
#undef bpf_per_cpu_ptr
#define bpf_per_cpu_ptr(ptr, cpu) ((typeof(ptr))0)

/*
 * bpf_get_current_pid_tgid -- no meaningful PID in the simulator.
 * Static function pointer in bpf_helper_defs.h, safe to override.
 */
#undef bpf_get_current_pid_tgid
#define bpf_get_current_pid_tgid() ((u64)0)

/*
 * bpf_ksym_exists -- kernel symbol existence check.
 * Return 0 (absent) to disable kfunc probing paths.
 */
#undef bpf_ksym_exists
#define bpf_ksym_exists(sym) (0)

/*
 * __builtin_memcpy_inline fallback for non-Clang or older versions.
 */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif
#if !__has_builtin(__builtin_memcpy_inline)
#define __builtin_memcpy_inline(dst, src, sz) __builtin_memcpy(dst, src, sz)
#endif

/*
 * The simulator always calls select_cpu before enqueue.
 */
#undef __COMPAT_is_enq_cpu_selected
#define __COMPAT_is_enq_cpu_selected(enq_flags) (true)

/*
 * migration_disabled is not modeled in the simulator.
 */
#undef is_migration_disabled
#define is_migration_disabled(p) ((void)(p), false)

/*
 * =================================================================
 * Per-CPU context and map infrastructure
 * =================================================================
 */
#define MAX_SIM_CPUS 128

/*
 * Forward declaration for per-CPU lookup.
 * Defined after LAVD source since struct cpu_ctx is needed.
 */
static struct cpu_ctx *lavd_lookup_percpu_elem(int cpu);
#undef bpf_map_lookup_percpu_elem
#define bpf_map_lookup_percpu_elem(map, key, cpu) lavd_lookup_percpu_elem(cpu)

/*
 * BPF timer overrides for periodic system stat updates.
 * Store the callback pointer so the simulator engine can fire it.
 */
static int (*lavd_timer_cb)(void *, int *, struct bpf_timer *);
static struct bpf_timer *lavd_timer_ptr;
static void *lavd_timer_map;
extern void sim_timer_start(unsigned long long nsecs);

#undef bpf_timer_set_callback
#define bpf_timer_set_callback(timer, cb) \
	(lavd_timer_cb = (typeof(lavd_timer_cb))(cb), \
	 lavd_timer_ptr = (struct bpf_timer *)(timer), 0)

#undef bpf_timer_start
#define bpf_timer_start(timer, nsecs, flags) \
	(sim_timer_start(nsecs), 0)

/*
 * Map lookup override.
 *
 * LAVD uses bpf_map_lookup_elem for two maps:
 *   cpu_ctx_stor (PERCPU_ARRAY) -- routed to our static per-CPU array
 *   update_timer (ARRAY)        -- routed to static backing storage
 *
 * Pointers are set in lavd_register_maps() after the source is included.
 */
static void *lavd_cpu_ctx_stor_ptr;
static void *lavd_update_timer_map_ptr;
static char lavd_update_timer_buf[256];

extern unsigned int sim_bpf_get_smp_processor_id(void);

/*
 * Forward declaration -- definition after LAVD source where struct cpu_ctx
 * is available.
 */
static void *lavd_map_lookup(void *map, const void *key);

#undef bpf_map_lookup_elem
#define bpf_map_lookup_elem(map, key) lavd_map_lookup((void *)(map), key)

/*
 * __COMPAT_scx_bpf_cpu_curr override.
 * Return actual running task or a synthetic idle task.
 */
extern struct task_struct *scx_bpf_cpu_curr(int cpu);
static struct task_struct sim_lavd_idle_task;
static bool sim_lavd_idle_init;

static struct task_struct *lavd_cpu_curr(int cpu)
{
	struct task_struct *p = scx_bpf_cpu_curr(cpu);
	if (p)
		return p;
	if (!sim_lavd_idle_init) {
		__builtin_memset(&sim_lavd_idle_task, 0,
				 sizeof(sim_lavd_idle_task));
		sim_lavd_idle_task.flags = PF_IDLE;
		sim_lavd_idle_init = true;
	}
	return &sim_lavd_idle_task;
}

#undef __COMPAT_scx_bpf_cpu_curr
#define __COMPAT_scx_bpf_cpu_curr(cpu) lavd_cpu_curr(cpu)

/*
 * Division-by-zero protection: provided by sim_sigfpe.c (separate TU
 * to avoid signal.h / vmlinux.h type conflicts).
 */
extern void sim_install_sigfpe_handler(void);

/*
 * =================================================================
 * Include LAVD source files
 * =================================================================
 *
 * All 10 LAVD BPF source files are included as a single translation
 * unit. Header guards prevent re-inclusion. Order: utilities and
 * subsystems first, main last.
 *
 * NOTE: bpf_experimental.h declares kfuncs (bpf_task_from_pid,
 * bpf_cgroup_from_id, bpf_cgroup_release) as extern __ksym.
 * We must NOT use macro overrides for these -- instead we provide
 * weak function stubs after the includes.
 */
/*
 * sdt_task_defs.h is conditionally included under #ifdef __BPF__ in
 * sdt_task.h, but its constants (SDT_TASK_ENTS_PER_CHUNK) are used
 * unconditionally. Include it explicitly for the simulator.
 */
#include "sdt_task_defs.h"

#include "intf.h"

#include "util.bpf.c"
#include "power.bpf.c"
#include "sys_stat.bpf.c"
#include "lock.bpf.c"
#include "balance.bpf.c"
#include "idle.bpf.c"
#include "lat_cri.bpf.c"
#include "preempt.bpf.c"
#include "introspec.bpf.c"
#include "main.bpf.c"

/*
 * =================================================================
 * Post-include definitions
 * =================================================================
 */

/*
 * Per-CPU context array and map lookup (struct cpu_ctx now available).
 */
static struct cpu_ctx percpu_ctx[MAX_SIM_CPUS];

static void *lavd_map_lookup(void *map, const void *key)
{
	if (map == lavd_cpu_ctx_stor_ptr && lavd_cpu_ctx_stor_ptr) {
		int cpu = sim_bpf_get_smp_processor_id();
		if (cpu >= 0 && cpu < MAX_SIM_CPUS)
			return &percpu_ctx[cpu];
		return NULL;
	}
	if (map == lavd_update_timer_map_ptr && lavd_update_timer_map_ptr)
		return lavd_update_timer_buf;
	return scx_test_map_lookup_elem(map, key);
}

/*
 * Per-CPU context lookup (definition after struct cpu_ctx is available).
 */
static struct cpu_ctx *lavd_lookup_percpu_elem(int cpu)
{
	if (cpu < 0 || cpu >= MAX_SIM_CPUS)
		return NULL;
	return &percpu_ctx[cpu];
}

/*
 * Register BPF maps with the test map infrastructure.
 */
static struct scx_test_map cpu_ctx_test_map;

void lavd_register_maps(void)
{
	scx_test_map_clear_all();

	INIT_SCX_TEST_MAP(&cpu_ctx_test_map, cpu_ctx_stor);
	scx_test_map_register(&cpu_ctx_test_map, &cpu_ctx_stor);

	lavd_cpu_ctx_stor_ptr = (void *)&cpu_ctx_stor;
	lavd_update_timer_map_ptr = (void *)&update_timer;
	lavd_timer_map = (void *)&update_timer;
}

/*
 * Fire the stored BPF timer callback.
 * Called from the Rust engine when a TimerFired event is processed.
 */
void lavd_fire_timer(void)
{
	int key = 0;
	if (lavd_timer_cb && lavd_timer_ptr)
		lavd_timer_cb(lavd_timer_map, &key, lavd_timer_ptr);
}

/*
 * =================================================================
 * Kfunc stubs for BPF experimental functions
 * =================================================================
 *
 * These functions are declared as extern __ksym in bpf_experimental.h.
 * Macro overrides would corrupt the declarations, so we provide
 * function implementations instead.
 */

/* Task lookup by PID -- not modeled in simulation */
struct task_struct *bpf_task_from_pid(s32 pid)
{
	(void)pid;
	return NULL;
}

/* Cgroup lookup by ID -- not modeled */
struct cgroup *bpf_cgroup_from_id(u64 cgroupid)
{
	(void)cgroupid;
	return NULL;
}

/* Cgroup reference release -- no-op */
void bpf_cgroup_release(struct cgroup *cgrp)
{
	(void)cgrp;
}

/*
 * =================================================================
 * Cgroup bandwidth stubs
 * =================================================================
 *
 * With enable_cpu_bw = false, all cgroup ops short-circuit before
 * calling these. Provide stubs to satisfy the linker.
 */
__attribute__((weak)) int scx_cgroup_bw_lib_init(
	struct scx_cgroup_bw_config *config)
{
	(void)config;
	return 0;
}

__attribute__((weak)) int scx_cgroup_bw_init(
	struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
	(void)cgrp; (void)args;
	return 0;
}

__attribute__((weak)) int scx_cgroup_bw_exit(struct cgroup *cgrp)
{
	(void)cgrp;
	return 0;
}

__attribute__((weak)) int scx_cgroup_bw_set(
	struct cgroup *cgrp, u64 period, u64 quota, u64 burst)
{
	(void)cgrp; (void)period; (void)quota; (void)burst;
	return 0;
}

__attribute__((weak)) int scx_cgroup_bw_throttled(struct cgroup *cgrp)
{
	(void)cgrp;
	return 0;
}

__attribute__((weak)) int scx_cgroup_bw_consume(
	struct cgroup *cgrp, u64 runtime)
{
	(void)cgrp; (void)runtime;
	return 0;
}

__attribute__((weak)) int scx_cgroup_bw_put_aside(
	struct task_struct *p, u64 taskc, u64 vtime, struct cgroup *cgrp)
{
	(void)p; (void)taskc; (void)vtime; (void)cgrp;
	return 0;
}

__attribute__((weak)) int scx_cgroup_bw_reenqueue(void)
{
	return 0;
}

__attribute__((weak)) int scx_cgroup_bw_cancel(u64 taskc)
{
	(void)taskc;
	return 0;
}

/*
 * =================================================================
 * Setup function
 * =================================================================
 *
 * Called from Rust before lavd_init() to initialize globals,
 * register maps, and install the SIGFPE handler.
 */
void lavd_setup(unsigned int num_cpus)
{
	unsigned int cpu;

	/* Install SIGFPE handler for BPF div-by-zero semantics */
	sim_install_sigfpe_handler();

	/* Register maps */
	lavd_register_maps();

	/* Core globals */
	nr_cpus_onln = num_cpus;
	nr_cpu_ids = num_cpus;
	nr_llcs = 1;
	is_smt_active = false;

	/* Disable complex features for initial simulation */
	enable_cpu_bw = false;
	is_autopilot_on = false;
	no_core_compaction = true;
	no_freq_scaling = true;
	no_preemption = false;
	no_wake_sync = false;
	no_slice_boost = false;
	verbose = 0;

	/* Per-CPU topology: uniform capacity, no big/little, no SMT */
	for (cpu = 0; cpu < num_cpus && cpu < LAVD_CPU_ID_MAX; cpu++) {
		cpu_capacity[cpu] = 1024;
		cpu_big[cpu] = 0;
		cpu_turbo[cpu] = 0;
		cpu_sibling[cpu] = cpu;
	}

	/*
	 * Set up a single compute domain with all CPUs.
	 * lavd_init() will call init_cpdoms() to create DSQs.
	 */
	{
		struct cpdom_ctx *cpdomc = &cpdom_ctxs[0];
		__builtin_memset(cpdomc, 0, sizeof(*cpdomc));
		cpdomc->id = 0;
		cpdomc->alt_id = 0;
		cpdomc->numa_id = 0;
		cpdomc->llc_id = 0;
		cpdomc->is_big = 0;
		cpdomc->is_valid = 1;
		cpdomc->nr_active_cpus = num_cpus;
		cpdomc->cap_sum_active_cpus = num_cpus * 1024;

		for (cpu = 0; cpu < num_cpus && cpu < LAVD_CPU_ID_MAX; cpu++)
			cpdomc->__cpumask[cpu / 64] |=
				(1ULL << (cpu % 64));
	}
}
