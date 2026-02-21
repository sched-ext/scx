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
 * Simulated PMU kfunc stubs.
 *
 * The new COSMOS API uses scx_pmu_read() kfunc instead of the old
 * start_readings map + bpf_perf_event_read_value() approach.
 *
 * We simulate PMU counters using scx_bpf_now() as a monotonic counter.
 * The delta between event_start and event_stop represents task runtime
 * in nanoseconds, which serves as a simulated "event count".
 *
 * Tasks with runtime > perf_threshold are classified as "event heavy"
 * and routed to the least-busy-event CPU.
 */
extern u64 scx_bpf_now(void);

/* Per-task PMU baseline storage (indexed by task pointer hash) */
#define PMU_TASK_HASH_SIZE 1024
static u64 pmu_task_baseline[PMU_TASK_HASH_SIZE];

static inline unsigned int pmu_task_hash(struct task_struct *p)
{
	return ((unsigned long)p >> 4) % PMU_TASK_HASH_SIZE;
}

/*
 * scx_pmu_install - Install a PMU event for tracking.
 * In simulation, this is a no-op since we use scx_bpf_now() as counter.
 */
int scx_pmu_install(u64 event)
{
	(void)event;
	return 0;
}

/*
 * scx_pmu_uninstall - Uninstall a PMU event.
 * No-op in simulation.
 */
int scx_pmu_uninstall(u64 event)
{
	(void)event;
	return 0;
}

/*
 * scx_pmu_task_init - Initialize per-task PMU tracking.
 * No-op in simulation.
 */
int scx_pmu_task_init(struct task_struct *p)
{
	(void)p;
	return 0;
}

/*
 * scx_pmu_task_fini - Finalize per-task PMU tracking.
 * No-op in simulation.
 */
int scx_pmu_task_fini(struct task_struct *p)
{
	(void)p;
	return 0;
}

/*
 * scx_pmu_event_start - Record baseline counter when task starts running.
 * Stores current scx_bpf_now() value as baseline.
 */
int scx_pmu_event_start(struct task_struct *p, bool update)
{
	(void)update;
	pmu_task_baseline[pmu_task_hash(p)] = scx_bpf_now();
	return 0;
}

/*
 * scx_pmu_event_stop - Mark end of PMU event tracking for task.
 * The actual reading happens in scx_pmu_read().
 */
int scx_pmu_event_stop(struct task_struct *p)
{
	(void)p;
	return 0;
}

/*
 * scx_pmu_read - Read PMU counter delta for a task.
 *
 * Returns the difference between current time and baseline (task runtime).
 * If clear=true, resets the baseline for the next measurement.
 */
int scx_pmu_read(struct task_struct *p, u64 event, u64 *value, bool clear)
{
	unsigned int hash = pmu_task_hash(p);
	u64 now = scx_bpf_now();
	u64 baseline = pmu_task_baseline[hash];

	(void)event;

	/* Return delta since event_start */
	if (now >= baseline)
		*value = now - baseline;
	else
		*value = 0;

	if (clear)
		pmu_task_baseline[hash] = now;

	return 0;
}

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
 * Static wakeup_timer backing storage.
 * The struct bpf_timer inside is opaque to us — we just need to provide
 * memory for bpf_map_lookup_elem to return. The bpf_timer fields aren't
 * accessed; our macros intercept bpf_timer_init/set_callback/start.
 * Size is generous to accommodate any struct wakeup_timer layout.
 */
static char sim_wakeup_timer_buf[256];
static void *wakeup_timer_map_ptr;

static void *cosmos_map_lookup(void *map, const void *key)
{
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
	perf_config = 1;  /* Enable PMU tracking (any non-zero value) */
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
