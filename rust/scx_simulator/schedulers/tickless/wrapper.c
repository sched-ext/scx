/*
 * tickless_wrapper.c - Wrapper to compile scx_tickless as userspace C
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

/* Include tickless interface header, then the scheduler source.
 * common.bpf.h is already included (header guard set), so our
 * BPF_STRUCT_OPS and SCX_OPS_DEFINE overrides are in effect. */
#include "intf.h"
#include "main.bpf.c"

/*
 * Register the tickless BPF maps with the test map infrastructure.
 *
 * The test infrastructure needs maps registered before they can be
 * used by bpf_map_lookup_elem / bpf_task_storage_get. This function
 * should be called before tickless_init().
 */
static struct scx_test_map task_ctx_map;
static struct scx_test_map cpu_ctx_map;

void tickless_register_maps(void)
{
	scx_test_map_clear_all();

	INIT_SCX_TEST_MAP_FROM_TASK_STORAGE(&task_ctx_map, task_ctx_stor);
	scx_test_map_register(&task_ctx_map, &task_ctx_stor);

	INIT_SCX_TEST_MAP(&cpu_ctx_map, cpu_ctx_stor);
	scx_test_map_register(&cpu_ctx_map, &cpu_ctx_stor);
}

/*
 * Combined setup function called from Rust before tickless_init().
 * Sets global variables, registers maps, and enables CPU 0.
 * struct cpu_arg is defined in intf.h (included above).
 */
void tickless_setup(unsigned int num_cpus)
{
	unsigned int i;
	struct cpu_arg arg = { .cpu_id = 0 };

	nr_cpu_ids = num_cpus;
	smt_enabled = false;
	slice_ns = 20000000;  /* 20ms default slice */
	tick_freq = 250;

	for (i = 0; i < num_cpus && i < 1024; i++)
		preferred_cpus[i] = i;

	tickless_register_maps();
	enable_primary_cpu(&arg);
}
