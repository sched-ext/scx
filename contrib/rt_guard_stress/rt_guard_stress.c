// SPDX-License-Identifier: GPL-2.0
/*
 * rt_guard_stress.c — 60s soak: RT + EXT on same CPU; zero watchdog exit.
 * Extends rt_stall.c (Layer 1 ext_server + Layer 2/3 validation).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "scx_test.h"
#include "../kselftest.h"
#include "rt_guard_stress.bpf.skel.h"

#define CORE_ID 1
#define SOAK_SEC 60

static void busy_loop(void)
{
	while (1)
		for (volatile unsigned long i = 0; i < 10000000UL; i++)
			;
}

static void pin_cpu(int cpu)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask) != 0) {
		perror("sched_setaffinity");
		exit(EXIT_FAILURE);
	}
}

static enum scx_test_status setup(void **ctx)
{
	struct rt_guard_stress *skel;

	if (!__COMPAT_struct_has_field("rq", "ext_server")) {
		fprintf(stderr, "SKIP: ext DL server not supported\n");
		return SCX_TEST_SKIP;
	}

	skel = rt_guard_stress__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(rt_guard_stress__load(skel), "Failed to load skel");
	*ctx = skel;
	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct rt_guard_stress *skel = ctx;
	struct bpf_link *link;
	int rt_pid, ext_pid;
	time_t start = time(NULL);

	ksft_print_header();
	ksft_set_plan(1);

	memset(&skel->data->uei, 0, sizeof(skel->data->uei));
	link = bpf_map__attach_struct_ops(skel->maps.rt_guard_stress_ops);
	SCX_FAIL_IF(!link, "Failed to attach scheduler");

	ext_pid = fork();
	if (ext_pid == 0) {
		pin_cpu(CORE_ID);
		busy_loop();
		exit(0);
	}
	SCX_FAIL_IF(ext_pid < 0, "fork ext");

	rt_pid = fork();
	if (rt_pid == 0) {
		struct sched_param param = { .sched_priority = 40 };
		pin_cpu(CORE_ID);
		if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
			perror("sched_setscheduler");
			exit(EXIT_FAILURE);
		}
		busy_loop();
		exit(0);
	}
	SCX_FAIL_IF(rt_pid < 0, "fork rt");

	while (time(NULL) - start < SOAK_SEC) {
		if (skel->data->uei.kind != EXIT_KIND(SCX_EXIT_NONE)) {
			ksft_test_result_fail("scheduler exited early kind=%llu\n",
					      (unsigned long long)skel->data->uei.kind);
			goto out;
		}
		sleep(1);
	}

	ksft_test_result_pass("60s soak with RT+EXT on CPU %d — no watchdog exit\n", CORE_ID);

out:
	kill(ext_pid, SIGKILL);
	kill(rt_pid, SIGKILL);
	waitpid(ext_pid, NULL, 0);
	waitpid(rt_pid, NULL, 0);
	SCX_EQ(skel->data->uei.kind, EXIT_KIND(SCX_EXIT_NONE));
	bpf_link__destroy(link);
	return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	rt_guard_stress__destroy(ctx);
}

struct scx_test rt_guard_stress = {
	.name = "rt_guard_stress",
	.description = "60s RT+EXT soak — zero watchdog stall (rt_guard + ext_server)",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&rt_guard_stress)
