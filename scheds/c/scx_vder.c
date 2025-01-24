/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_vder: Virtual Deadline with Execution Runtime.
 *
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_vder.bpf.skel.h"

const char help_fmt[] =
"A sched_ext demo scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-s NUM] [-f] [-v]\n"
"\n"
"  -s SLICE_US   Override slice duration\n"
"  -c CPU        Override the central CPU (default: 0)\n"
"  -f HZ         Override the default HZ (default: CONFIG_HZ)\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int num)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	cpu_set_t *cpuset;
	struct scx_vder *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(vder_ops, scx_vder);

	skel->rodata->central_cpu = 0;
	skel->rodata->nr_cpu_ids = libbpf_num_possible_cpus();
	skel->rodata->slice_ns = __COMPAT_ENUM_OR_ZERO("scx_public_consts", "SCX_SLICE_DFL");

	while ((opt = getopt(argc, argv, "s:c:f:pvh")) != -1) {
		switch (opt) {
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'c': {
			u32 central_cpu = strtoul(optarg, NULL, 0);
			if (central_cpu >= skel->rodata->nr_cpu_ids) {
				fprintf(stderr, "invalid central CPU id value, %u given (%u max)\n", central_cpu, skel->rodata->nr_cpu_ids);
				return -1;
			}
			skel->rodata->central_cpu = (s32)central_cpu;
			break;
		}
		case 'f':
			skel->rodata->config_hz = strtoull(optarg, NULL, 0);
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	RESIZE_ARRAY(skel, data, idle_cpus, skel->rodata->nr_cpu_ids);
	RESIZE_ARRAY(skel, data, cpu_started_at, skel->rodata->nr_cpu_ids);

	SCX_OPS_LOAD(skel, vder_ops, scx_vder, uei);

	cpuset = CPU_ALLOC(skel->rodata->nr_cpu_ids);
	SCX_BUG_ON(!cpuset, "Failed to allocate cpuset");
	CPU_ZERO_S(CPU_ALLOC_SIZE(skel->rodata->nr_cpu_ids), cpuset);
	CPU_SET(skel->rodata->central_cpu, cpuset);
	SCX_BUG_ON(sched_setaffinity(0, sizeof(*cpuset), cpuset),
		   "Failed to affinitize to central CPU %d (max %d)",
		   skel->rodata->central_cpu, skel->rodata->nr_cpu_ids - 1);
	CPU_FREE(cpuset);

	link = SCX_OPS_ATTACH(skel, vder_ops, scx_vder);

	fprintf(stderr, "scx_vder is running\n");
	fflush(stderr);

	while (!exit_req && !UEI_EXITED(skel, uei))
		sleep(1);

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_vder__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;

	return 0;
}
