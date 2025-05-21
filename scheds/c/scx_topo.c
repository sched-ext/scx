/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_topo.bpf.skel.h"

const char help_fmt[] =
"🐭\nUsage: %s [-v]\n"
"\n"
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
	struct scx_topo *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(topo_ops, scx_topo);

	while ((opt = getopt(argc, argv, "vh")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, topo_ops, scx_topo, uei);
	link = SCX_OPS_ATTACH(skel, topo_ops, scx_topo);

	printf("scx_topo is running\n");
	fflush(stdout);

	while (!exit_req && !UEI_EXITED(skel, uei))
		sleep(1);

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_topo__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;

	return 0;
}
