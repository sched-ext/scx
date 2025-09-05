#include <scx_test.h>
#include <scx_test_map.h>
#include <scx_test_cpumask.h>

#include <string.h>

#include <scx/common.bpf.h>
#include <lib/sdt_task_defs.h>

#include "main.bpf.c"

// per thread globals because the Rust test driver has multiple threads
static __thread struct scx_percpu_test_map *cpu_ctxs_map = NULL;
static __thread struct scx_test_map llc_ctxs_map = { 0 };
static __thread struct scx_test_map task_masks_map = { 0 };

static void setup_task_wrapper(struct task_struct *p, struct cpumask *cpumask)
{
	struct mask_wrapper *wrapper;

	wrapper = bpf_task_storage_get(&task_masks, p, NULL,
				       BPF_LOCAL_STORAGE_GET_F_CREATE);
	scx_test_assert(wrapper);
	wrapper->mask = cpumask;
}

static void setup_llc(u64 dsqid, u32 id, u32 nr_cpus, struct cpumask *mask)
{
	struct llc_ctx my_llcx = { 0 };
	my_llcx.id = id;
	my_llcx.dsq = dsqid;
	my_llcx.nr_cpus = nr_cpus;
	my_llcx.cpumask = mask;

	scx_test_assert(scx_test_map_update_elem(&llc_ctxs, &id, &my_llcx,
						 BPF_ANY) == 0);
}

/*
 * Runs at the start of each test and operates on per-thread globals. No need
 * for locking but check if already initialised.
 */
static void init_p2dq_test(void)
{
	if (cpu_ctxs_map)
		return;

	cpu_ctxs_map = scx_alloc_percpu_test_map(NR_CPUS);
	INIT_SCX_PERCPU_TEST_MAP(cpu_ctxs_map, cpu_ctxs);

	INIT_SCX_TEST_MAP(&llc_ctxs_map, llc_ctxs);
	INIT_SCX_TEST_MAP_FROM_TASK_STORAGE(&task_masks_map, task_masks);

	scx_test_map_register(&llc_ctxs_map, &llc_ctxs);
	scx_test_map_register(&task_masks_map, &task_masks);
	scx_register_percpu_test_map(cpu_ctxs_map, &cpu_ctxs);
}

SCX_TEST(test_pick_idle_cpu)
{
	struct task_struct p = { 0 };
	task_ctx my_taskc = { 0 };
	struct cpumask llc_cpumask = { 0 };
	s32 idle_cpu;
	bool is_idle = false;

	init_p2dq_test();

	my_taskc.llc_id = 1;
	my_taskc.dsq_id = 1;

	setup_llc(1, 1, NR_CPUS, &llc_cpumask);
	setup_task_wrapper(&p, &llc_cpumask);

	for (int i = 0; i < NR_CPUS; i++) {
		scx_test_set_all_cpumask(i);
		scx_test_cpumask_set(i, &llc_cpumask);
	}

	idle_cpu = pick_idle_cpu(&p, &my_taskc, 0, 0, &is_idle);
	scx_test_assert(idle_cpu >= 0);
	scx_test_assert(idle_cpu < NR_CPUS);

	/* Set 3 as the only idle CPU */
	is_idle = false;
	scx_test_set_idle_cpumask(3);
	scx_test_set_idle_smtmask(3);
	idle_cpu = pick_idle_cpu(&p, &my_taskc, 0, 0, &is_idle);
	scx_test_assert(idle_cpu == 3);
	scx_test_assert(is_idle);
}

SCX_TEST(test_lookup_cpu_ctx)
{
	struct cpu_ctx *my_cpuc = NULL;
	struct cpu_ctx cpuc = { 0 };
	u32 index = 0;

	init_p2dq_test();

	for (int i = 0; i < NR_CPUS; i++) {
		cpuc.id = i;
		cpuc.llc_id = i % 4;
		scx_test_assert(scx_test_map_update_percpu_elem(&cpu_ctxs, &index, &cpuc, i, BPF_ANY) == 0);
	}

	for (int i = 0; i < NR_CPUS; i++) {
		my_cpuc = lookup_cpu_ctx(i);
		cpuc.id = i;
		cpuc.llc_id = i % 4;
		scx_test_assert(my_cpuc != NULL);
		scx_test_assert(!memcmp(my_cpuc, &cpuc, sizeof(struct cpu_ctx)));
	}

	/*
	 * When we specify a negative number we lookup the current CPU, which
	 * for the test implementation is just cpu 0, so validate this matches
	 * cpu 0.
	 */
	my_cpuc = lookup_cpu_ctx(-1);
	scx_test_assert(my_cpuc != NULL);
	cpuc.id = 0;
	cpuc.llc_id = llc_ids[0];
	scx_test_assert(!memcmp(my_cpuc, &cpuc, sizeof(struct cpu_ctx)));
}

SCX_TEST(test_is_interactive)
{
	task_ctx my_taskc = {
		.dsq_index = 0,
	};

	init_p2dq_test();

	scx_test_assert(is_interactive(&my_taskc));
	my_taskc.dsq_index = 1;
	scx_test_assert(!is_interactive(&my_taskc));
}
