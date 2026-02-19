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
 * __COMPAT_scx_bpf_dsq_peek -- override the compat wrapper to directly
 * call scx_bpf_dsq_peek which is implemented in kfuncs.rs. The compat
 * wrapper normally falls through to bpf_iter_scx_dsq_* when bpf_ksym_exists
 * returns 0, but those iterators aren't implemented in the simulator.
 */
extern struct task_struct *scx_bpf_dsq_peek(u64 dsq_id);
#define __COMPAT_scx_bpf_dsq_peek(dsq_id) scx_bpf_dsq_peek(dsq_id)

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
 * Per-task arena storage initialization (sim_sdt_stubs.c).
 * Must be called before any scx_task_alloc() calls.
 */
extern int scx_task_init(u64 data_size);

/*
 * Kernel symbols that LAVD references but are not available in userspace.
 *
 * nr_cpu_ids: kernel global variable for number of possible CPUs.
 * Declared as "const extern volatile u32" in lavd.bpf.h; with -Dconst=
 * it becomes "extern volatile u32" (just a declaration). We provide the
 * definition here and lavd_setup() sets the value.
 *
 * cpufreq_cpu_data / hw_pressure: __ksym kernel symbols referenced in
 * power.bpf.c. Provide zero-initialized definitions to satisfy the linker.
 */
volatile u32 nr_cpu_ids;
struct cpufreq_policy *cpufreq_cpu_data;
unsigned long hw_pressure;

/*
 * bpf_probe_read_kernel override for LAVD.
 *
 * The generic sim_wrapper.h implementation does memcpy(dst, src, sz) which
 * is normally fine. However, update_effective_capacity() in power.bpf.c
 * uses &cpufreq_cpu_data as an array base and indexes by CPU id. In BPF,
 * &cpufreq_cpu_data is NULL when the ksym doesn't exist, making the read
 * fail. In userspace, &cpufreq_cpu_data is always non-NULL, and reading
 * base[cpu] for cpu > 0 reads beyond the single variable into garbage
 * memory, causing SIGSEGV when the resulting pointer is dereferenced.
 *
 * Since there is no kernel memory in the simulator, bpf_probe_read_kernel
 * should always fail. This is safe — the only caller in LAVD is in
 * update_effective_capacity's cpufreq path which gracefully handles failure.
 */
#undef bpf_probe_read_kernel
#define bpf_probe_read_kernel(dst, sz, src) \
	(__builtin_memset((dst), 0, (sz)), (long)(-14))
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

/*
 * Pre-include bpf_experimental.h to trigger its include guard, then
 * override can_loop and __cond_break which it defines using BPF-only
 * inline asm (.byte 0xe5 / may_goto). bpf_arena_common.bpf.h already
 * defines these correctly for SCX_BPF_UNITTEST but bpf_experimental.h
 * unconditionally redefines them.
 *
 * Also override the IRQ/NMI context checks (get_preempt_count,
 * bpf_in_hardirq, bpf_in_nmi, bpf_in_serving_softirq) which access
 * per-CPU kernel variables via bpf_this_cpu_ptr/bpf_core_field_exists.
 * The simulator never runs in interrupt context.
 */
#include <bpf_experimental.h>
#undef can_loop
#define can_loop true
#undef __cond_break
#define __cond_break(expr) expr
#define get_preempt_count() (0)
#define bpf_in_hardirq() (0)
#define bpf_in_nmi() (0)
#define bpf_in_serving_softirq() (0)
#define bpf_in_interrupt() (0)

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

/*
 * bpf_task_from_pid — provided by the Rust kfuncs (kfuncs.rs).
 * The extern __ksym declaration from bpf_experimental.h resolves
 * to the simulator's real PID→task_struct lookup at runtime.
 */

/*
 * Cgroup lookup by ID -- delegates to the Rust cgroup registry.
 * Returns the struct cgroup pointer for the given cgroup ID,
 * or NULL if no registry is installed or the ID is not found.
 */
extern void *sim_cgroup_lookup_by_id(u64 cgid);

struct cgroup *bpf_cgroup_from_id(u64 cgroupid)
{
	return (struct cgroup *)sim_cgroup_lookup_by_id(cgroupid);
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

	/* Initialize per-task arena storage for task_ctx */
	scx_task_init(sizeof(struct task_ctx));

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
	no_use_em = true; /* no kernel energy model in the simulator */
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

/*
 * =================================================================
 * Multi-domain setup for load balancing coverage
 * =================================================================
 *
 * Reconfigures the compute domain topology created by lavd_setup()
 * into multiple domains with neighbor relationships. This enables
 * cross-domain migration code paths in balance.bpf.c.
 *
 * Must be called AFTER lavd_setup() and BEFORE lavd_init().
 *
 * Parameters:
 *   nr_domains: number of compute domains to create (must be >= 2)
 *
 * CPUs are split evenly across domains. Remaining CPUs go to the
 * last domain. All domains are neighbors of each other at distance 0.
 */
void lavd_setup_multi_domain(unsigned int nr_domains)
{
	unsigned int cpus_per_domain, cpu, d, i;

	if (nr_domains < 2 || nr_domains > LAVD_CPDOM_MAX_NR)
		return;
	if (nr_cpus_onln < nr_domains)
		return;

	cpus_per_domain = nr_cpus_onln / nr_domains;

	/* Clear domain 0 that lavd_setup() created */
	__builtin_memset(&cpdom_ctxs[0], 0, sizeof(cpdom_ctxs[0]));

	/* Create nr_domains domains with disjoint CPU sets */
	for (d = 0; d < nr_domains; d++) {
		struct cpdom_ctx *cpdomc = &cpdom_ctxs[d];
		unsigned int first_cpu = d * cpus_per_domain;
		unsigned int last_cpu = (d == nr_domains - 1)
			? nr_cpus_onln
			: first_cpu + cpus_per_domain;

		cpdomc->id = d;
		cpdomc->alt_id = (d == 0) ? 1 : 0;
		cpdomc->numa_id = d;
		cpdomc->llc_id = d;
		cpdomc->is_big = 0;
		cpdomc->is_valid = 1;
		cpdomc->nr_active_cpus = last_cpu - first_cpu;
		cpdomc->cap_sum_active_cpus =
			cpdomc->nr_active_cpus * 1024;

		/* Set cpumask for this domain's CPUs */
		for (cpu = first_cpu;
		     cpu < last_cpu && cpu < LAVD_CPU_ID_MAX;
		     cpu++) {
			cpdomc->__cpumask[cpu / 64] |=
				(1ULL << (cpu % 64));
		}

		/*
		 * All other domains are neighbors at distance 0.
		 * This enables cross-domain task stealing.
		 */
		cpdomc->nr_neighbors[0] = nr_domains - 1;
		i = 0;
		for (unsigned int n = 0; n < nr_domains; n++) {
			if (n == d)
				continue;
			cpdomc->neighbor_ids[0 * LAVD_CPDOM_MAX_NR + i] = n;
			i++;
		}
	}

	/*
	 * Enable core compaction so do_core_compaction() runs during
	 * update_sys_stat() and keeps nr_active_cpdoms up to date.
	 */
	no_core_compaction = false;
}

/*
 * =================================================================
 * Configuration setters for DSQ and migration modes
 * =================================================================
 *
 * These set globals that control balance.bpf.c code paths.
 * Must be called AFTER lavd_setup() and BEFORE lavd_init().
 */

/* Enable per-CPU DSQ mode: tasks enqueue to per-CPU DSQs. */
void lavd_set_per_cpu_dsq(unsigned int val)
{
	per_cpu_dsq = !!val;
}

/* Set pinned_slice_ns: dual-DSQ mode (both per-CPU and per-cpdom). */
void lavd_set_pinned_slice_ns(unsigned long long val)
{
	pinned_slice_ns = val;
}

/* Set mig_delta_pct: fixed migration threshold percentage. */
void lavd_set_mig_delta_pct(unsigned int val)
{
	mig_delta_pct = (u8)val;
}

/* Enable/disable the is_monitored flag (introspection latency tracking). */
void lavd_set_is_monitored(unsigned int val)
{
	is_monitored = !!val;
}

/* Enable/disable core compaction. */
void lavd_set_no_core_compaction(unsigned int val)
{
	no_core_compaction = !!val;
}

/*
 * =================================================================
 * Probe functions — exported accessors for scheduler-internal state
 * =================================================================
 *
 * These are called from Rust via dlsym to sample LAVD state during
 * simulation. Each returns 0/default if the context is not available.
 */

/* Per-task probes: access task_ctx fields via get_task_ctx(). */

u16 lavd_probe_lat_cri(struct task_struct *p)
{
	struct task_ctx *taskc = get_task_ctx(p);
	return taskc ? taskc->lat_cri : 0;
}

u64 lavd_probe_wait_freq(struct task_struct *p)
{
	struct task_ctx *taskc = get_task_ctx(p);
	return taskc ? taskc->wait_freq : 0;
}

u64 lavd_probe_wake_freq(struct task_struct *p)
{
	struct task_ctx *taskc = get_task_ctx(p);
	return taskc ? taskc->wake_freq : 0;
}

u64 lavd_probe_avg_runtime(struct task_struct *p)
{
	struct task_ctx *taskc = get_task_ctx(p);
	return taskc ? taskc->avg_runtime : 0;
}

u16 lavd_probe_lat_cri_waker(struct task_struct *p)
{
	struct task_ctx *taskc = get_task_ctx(p);
	return taskc ? taskc->lat_cri_waker : 0;
}

u16 lavd_probe_lat_cri_wakee(struct task_struct *p)
{
	struct task_ctx *taskc = get_task_ctx(p);
	return taskc ? taskc->lat_cri_wakee : 0;
}

/* System-wide probes: access global sys_stat. */

u32 lavd_probe_sys_avg_lat_cri(void)
{
	return sys_stat.avg_lat_cri;
}

u32 lavd_probe_sys_thr_lat_cri(void)
{
	return sys_stat.thr_lat_cri;
}

u64 lavd_probe_sys_nr_sched(void)
{
	return sys_stat.nr_sched;
}

u64 lavd_probe_sys_nr_lat_cri(void)
{
	return sys_stat.nr_lat_cri;
}

u64 lavd_probe_sys_avg_sc_util(void)
{
	return sys_stat.avg_sc_util;
}

int lavd_probe_calc_nr_active(void)
{
	return calc_nr_active_cpus();
}

u32 lavd_probe_sys_nr_active(void)
{
	return sys_stat.nr_active;
}

u32 lavd_probe_sys_nr_cpus_onln(void)
{
	return nr_cpus_onln;
}

/*
 * Direct setter for sys_stat.nr_active.
 * Used by tests to force the dispatch compaction path
 * (use_full_cpus() returns false when nr_active < nr_cpus_onln).
 */
void lavd_set_sys_nr_active(u32 val)
{
	sys_stat.nr_active = val;
}

/*
 * Direct setter for sys_stat.nr_active_cpdoms.
 */
void lavd_set_sys_nr_active_cpdoms(u32 val)
{
	sys_stat.nr_active_cpdoms = val;
}

/*
 * =================================================================
 * Direct compaction control
 * =================================================================
 *
 * Force compaction state after lavd_init() has run (cpumasks allocated).
 * Sets nr_active, marks first nr_active_cpus CPUs as active, rest as
 * inactive. Uses the PCO ordering table for CPU order.
 *
 * Pure memory operations (no kfuncs), safe to call outside sim context.
 */
void lavd_force_compaction(int nr_active_cpus)
{
	struct bpf_cpumask *active_mask = active_cpumask;
	struct bpf_cpumask *ovrflw_mask = ovrflw_cpumask;
	const volatile u16 *cpu_order;
	int i, cpu;

	if (!active_mask || !ovrflw_mask)
		return;

	cpu_order = get_cpu_order();

	for (i = 0; i < (int)nr_cpu_ids && i < LAVD_CPU_ID_MAX; i++) {
		cpu = cpu_order[i];
		if (cpu >= LAVD_CPU_ID_MAX)
			break;

		if (i < nr_active_cpus) {
			bpf_cpumask_set_cpu(cpu, active_mask);
			bpf_cpumask_clear_cpu(cpu, ovrflw_mask);
		} else {
			bpf_cpumask_clear_cpu(cpu, active_mask);
			bpf_cpumask_clear_cpu(cpu, ovrflw_mask);
		}
	}

	sys_stat.nr_active = nr_active_cpus;
}

/*
 * =================================================================
 * Diagnostic probes for core compaction debugging
 * =================================================================
 */

u8 lavd_probe_no_core_compaction(void)
{
	return (u8)no_core_compaction;
}

u8 lavd_probe_active_cpumask_null(void)
{
	return (u8)(active_cpumask == NULL);
}

u8 lavd_probe_ovrflw_cpumask_null(void)
{
	return (u8)(ovrflw_cpumask == NULL);
}

u8 lavd_probe_cpuc_is_online(int cpu)
{
	if (cpu < 0 || cpu >= MAX_SIM_CPUS)
		return 0;
	return (u8)percpu_ctx[cpu].is_online;
}

u32 lavd_probe_cpuc_eff_cap(int cpu)
{
	if (cpu < 0 || cpu >= MAX_SIM_CPUS)
		return 0;
	return percpu_ctx[cpu].effective_capacity;
}
