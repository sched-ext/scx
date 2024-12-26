/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_vder: Virtual Deadline with Execution Runtime.
 *
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
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
"  -s NUM        Set default task time slice (in us), default is 20ms\n"
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
	struct scx_vder *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(vder_ops, scx_vder);

	skel->rodata->slice_ns = __COMPAT_ENUM_OR_ZERO("scx_public_consts", "SCX_SLICE_DFL");

	while ((opt = getopt(argc, argv, "s:vh")) != -1) {
		switch (opt) {
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, vder_ops, scx_vder, uei);
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
