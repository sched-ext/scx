/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_joule.bpf.skel.h"

const char help_fmt[] =
"A sched_ext scheduler that periodically shuts down the device for \n"
"optimal power usage."
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s  [-s SLICE_US] [-r DCYCLE_US] [-i DCYCLE_US] [-v] [-h]\n"
"\n"
"  -s SLICE_US   Override slice duration (default 1ms)\n"
"  -r DCYCLE_US  Override interval duration for when tasks are active (default 8ms)\n"
"  -i DCYCLE_US  Override interval duration for when tasks are idle (default 14ms)\n"
"  -v            Print libbpf debug messages\n"
"  -h            Print help message and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int joule)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_joule *skel;
	struct bpf_link *link;
	__u32 opt, cnt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(joule_ops, scx_joule);

	while ((opt = getopt(argc, argv, "s:d:vh")) != -1) {
		switch (opt) {
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'r':
			skel->rodata->dcycle_run_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'i':
			skel->rodata->dcycle_idle_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}
	skel->rodata->nr_cpu_ids = libbpf_num_possible_cpus();

	SCX_OPS_LOAD(skel, joule_ops, scx_joule, uei);
	link = SCX_OPS_ATTACH(skel, joule_ops, scx_joule);

	cnt = 0;
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		printf("%u\n", cnt++);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_joule__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
