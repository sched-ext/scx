/*
 * cosmos_wrapper.c - Wrapper to compile scx_cosmos as userspace C
 *
 * This file includes the simulator wrapper infrastructure and then
 * the actual scheduler source. The header guards in common.bpf.h
 * prevent re-inclusion, so our overridden macros take effect.
 *
 * NOTE: This file is compiled with -Dconst= to strip const qualifiers.
 * BPF schedulers declare globals as "const volatile" (patched by the
 * BPF loader). Stripping const makes them writable from Rust.
 */
#include "sim_wrapper.h"
#include "sim_task.h"

/*
 * COSMOS-specific macro overrides (defined after sim_wrapper.h,
 * before main.bpf.c).
 */

/*
 * Enable scx_bpf_select_cpu_and — implemented in the simulator.
 * With flat_idle_scan=false, COSMOS will use this instead of flat scan.
 */
#undef bpf_ksym_exists
#define bpf_ksym_exists(sym) (1)

/*
 * The simulator always calls select_cpu before enqueue, so the
 * CPU is always selected.
 */
#undef __COMPAT_is_enq_cpu_selected
#define __COMPAT_is_enq_cpu_selected(enq_flags) (true)

/*
 * Simulated task_struct doesn't have migration_disabled field;
 * bpf_core_field_exists override would make the real function
 * try to access it.
 */
#undef is_migration_disabled
#define is_migration_disabled(p) ((void)(p), false)

/*
 * Override __COMPAT_scx_bpf_cpu_curr to return actual running tasks.
 *
 * The default sim_wrapper.h override returns NULL, which makes
 * is_cpu_idle() always return false (with scx_bpf_error).
 * We need proper idle detection for deferred wakeups and PMU routing.
 *
 * For idle CPUs (scx_bpf_cpu_curr returns NULL), we return a synthetic
 * idle task with PF_IDLE set so is_cpu_idle() returns true.
 */
extern struct task_struct *scx_bpf_cpu_curr(int cpu);
static struct task_struct sim_idle_task;
static bool sim_idle_task_init;

static struct task_struct *cosmos_cpu_curr(int cpu)
{
	struct task_struct *p = scx_bpf_cpu_curr(cpu);
	if (p)
		return p;
	/* Return synthetic idle task for idle CPUs */
	if (!sim_idle_task_init) {
		__builtin_memset(&sim_idle_task, 0, sizeof(sim_idle_task));
		sim_idle_task.flags = PF_IDLE;
		sim_idle_task_init = true;
	}
	return &sim_idle_task;
}
#undef __COMPAT_scx_bpf_cpu_curr
#define __COMPAT_scx_bpf_cpu_curr(cpu) cosmos_cpu_curr(cpu)

/*
 * Route bpf_map_lookup_percpu_elem to a static cpu_ctx array.
 * Forward-declared here; defined after the scheduler source since
 * struct cpu_ctx is defined there.
 */
#define MAX_SIM_CPUS 128
static struct cpu_ctx *cosmos_lookup_percpu_elem(int cpu);
#undef bpf_map_lookup_percpu_elem
#define bpf_map_lookup_percpu_elem(map, key, cpu) cosmos_lookup_percpu_elem(cpu)

/*
 * Simulated perf counters.
 *
 * Use scx_bpf_now() as a monotonic counter. start_counters() records
 * the baseline at task start; stop_counters() reads the current value
 * at task stop. Delta = task runtime in nanoseconds.
 *
 * Tasks with runtime > perf_threshold are classified as "event heavy"
 * and routed to the least-busy-event CPU.
 */
extern u64 scx_bpf_now(void);

static long sim_perf_event_read(void *map, u32 key,
				struct bpf_perf_event_value *val, u32 size)
{
	(void)map; (void)key; (void)size;
	val->counter = scx_bpf_now();
	val->enabled = 1;
	val->running = 1;
	return 0;
}
#undef bpf_perf_event_read_value
#define bpf_perf_event_read_value(map, key, val, size) \
	sim_perf_event_read(map, key, val, size)

/*
 * BPF timer overrides for deferred wakeups.
 *
 * bpf_timer_set_callback stores the callback pointer.
 * bpf_timer_start calls sim_timer_start() (Rust kfunc) to schedule
 * a TimerFired event in the simulator's event queue.
 * cosmos_fire_timer() invokes the stored callback from the engine.
 */
static int (*cosmos_timer_cb)(void *, int *, struct bpf_timer *);
static struct bpf_timer *cosmos_timer_ptr;
static void *cosmos_timer_map;

extern void sim_timer_start(unsigned long long nsecs);

#undef bpf_timer_set_callback
#define bpf_timer_set_callback(timer, cb) \
	(cosmos_timer_cb = (typeof(cosmos_timer_cb))(cb), \
	 cosmos_timer_ptr = (struct bpf_timer *)(timer), 0)

#undef bpf_timer_start
#define bpf_timer_start(timer, nsecs, flags) \
	(sim_timer_start(nsecs), 0)

/*
 * Per-CPU start_readings storage.
 *
 * The BPF start_readings map is PERCPU_ARRAY — each CPU needs its own
 * baseline. Override bpf_map_lookup_elem to route start_readings lookups
 * to this array; all other maps fall through to scx_test_map_lookup_elem.
 *
 * start_readings_map_ptr is set in cosmos_register_maps() after
 * main.bpf.c is included (where start_readings is defined).
 */
static struct bpf_perf_event_value start_readings_percpu[MAX_SIM_CPUS];
static void *start_readings_map_ptr;
static void *wakeup_timer_map_ptr;

/*
 * Static wakeup_timer backing storage.
 * The struct bpf_timer inside is opaque to us — we just need to provide
 * memory for bpf_map_lookup_elem to return. The bpf_timer fields aren't
 * accessed; our macros intercept bpf_timer_init/set_callback/start.
 * Size is generous to accommodate any struct wakeup_timer layout.
 */
static char sim_wakeup_timer_buf[256];

static void *cosmos_map_lookup(void *map, const void *key)
{
	if (map == start_readings_map_ptr && start_readings_map_ptr != NULL) {
		int cpu = bpf_get_smp_processor_id();
		if (cpu >= 0 && cpu < MAX_SIM_CPUS)
			return &start_readings_percpu[cpu];
		return NULL;
	}
	if (map == wakeup_timer_map_ptr && wakeup_timer_map_ptr != NULL)
		return sim_wakeup_timer_buf;
	return scx_test_map_lookup_elem(map, key);
}
#undef bpf_map_lookup_elem
#define bpf_map_lookup_elem(map, key) cosmos_map_lookup((void *)(map), key)

/*
 * Include COSMOS interface header, then the scheduler source.
 * common.bpf.h is already included (header guard set), so our
 * BPF_STRUCT_OPS and SCX_OPS_DEFINE overrides are in effect.
 *
 * We include a patched copy of main.bpf.c (generated by config.mk)
 * that guards against division-by-zero in update_freq(). BPF
 * division-by-zero returns 0; native C crashes with SIGFPE.
 */
#include "intf.h"
#include "cosmos_main_patched.c"

/*
 * Static per-CPU context array, defined after the scheduler source
 * so that struct cpu_ctx is available.
 */
static struct cpu_ctx percpu_ctx[MAX_SIM_CPUS];

static struct cpu_ctx *cosmos_lookup_percpu_elem(int cpu)
{
	if (cpu < 0 || cpu >= MAX_SIM_CPUS)
		return NULL;
	return &percpu_ctx[cpu];
}

/*
 * Register the COSMOS BPF maps with the test map infrastructure.
 *
 * Both task_ctx_stor (TASK_STORAGE) and cpu_node_map (HASH) are
 * registered here; cpu_ctx_stor (PERCPU_ARRAY) is handled by the
 * static array above.
 */
static struct scx_test_map task_ctx_map;
static struct scx_test_map cpu_node_test_map;

void cosmos_register_maps(void)
{
	scx_test_map_clear_all();

	INIT_SCX_TEST_MAP_FROM_TASK_STORAGE(&task_ctx_map, task_ctx_stor);
	scx_test_map_register(&task_ctx_map, &task_ctx_stor);

	INIT_SCX_TEST_MAP(&cpu_node_test_map, cpu_node_map);
	scx_test_map_register(&cpu_node_test_map, &cpu_node_map);

	start_readings_map_ptr = (void *)&start_readings;
	wakeup_timer_map_ptr = (void *)&wakeup_timer;
	cosmos_timer_map = (void *)&wakeup_timer;
}

/*
 * Fire the stored BPF timer callback.
 * Called from the Rust engine when a TimerFired event is processed.
 */
void cosmos_fire_timer(void)
{
	int key = 0;
	if (cosmos_timer_cb && cosmos_timer_ptr)
		cosmos_timer_cb(cosmos_timer_map, &key, cosmos_timer_ptr);
}

/*
 * Combined setup function called from Rust before cosmos_init().
 * Sets global variables to disable complex features, registers maps,
 * and enables CPU 0 in the primary domain.
 */
void cosmos_setup(unsigned int num_cpus)
{
	struct cpu_arg arg = { .cpu_id = 0 };

	smt_enabled = true;
	avoid_smt = true;
	primary_all = true;
	flat_idle_scan = false;
	preferred_idle_scan = false;
	cpufreq_enabled = true;
	numa_enabled = false;
	nr_node_ids = 1;
	mm_affinity = true;
	perf_enabled = true;
	deferred_wakeups = true;
	slice_ns = 20000000;   /* 20ms */
	slice_lag = 20000000;  /* 20ms */
	busy_threshold = 1;   /* system "not busy" → flat idle scan path */

	cosmos_register_maps();
	enable_primary_cpu(&arg);
}

/*
 * Configure NUMA topology after setup.
 * Populates cpu_node_map with sequential grouping:
 * CPUs [0, cpus_per_node) → node 0, etc.
 * Enables NUMA-aware scheduling in COSMOS.
 */
void cosmos_configure_numa(unsigned int num_cpus, unsigned int nr_nodes)
{
	unsigned int cpus_per_node, cpu, node;

	if (nr_nodes <= 1)
		return;  /* leave numa_enabled=false */

	cpus_per_node = num_cpus / nr_nodes;
	for (cpu = 0; cpu < num_cpus; cpu++) {
		node = cpu / cpus_per_node;
		if (node >= nr_nodes)
			node = nr_nodes - 1;
		bpf_map_update_elem(&cpu_node_map, &cpu, &node, 0);
	}

	numa_enabled = true;
	nr_node_ids = nr_nodes;
}
