#include <scx_test.h>
#include <scx_test_map.h>

#include <string.h>

#include "main.bpf.c"

static struct scx_percpu_test_map *cpu_ctxs_map = NULL;

static void test_lookup_cpu_ctx(void)
{
	struct cpu_ctx *my_cpuc = NULL;
	struct cpu_ctx cpuc = { 0 };
	u32 index = 0;

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

static void test_is_interactive(void)
{
	task_ctx my_taskc = {
		.dsq_index = 0,
	};

	scx_test_assert(is_interactive(&my_taskc));
	my_taskc.dsq_index = 1;
	scx_test_assert(!is_interactive(&my_taskc));
}

int main(int argc, char **argv)
{
	cpu_ctxs_map = scx_alloc_percpu_test_map(NR_CPUS);
	INIT_SCX_PERCPU_TEST_MAP(cpu_ctxs_map, cpu_ctxs);
	scx_register_percpu_test_map(cpu_ctxs_map, &cpu_ctxs);
	test_is_interactive();
	test_lookup_cpu_ctx();
}
