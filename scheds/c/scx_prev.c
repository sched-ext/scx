/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025, Oracle and/or its affiliates.
 * Copyright (c) 2025, Daniel Jordan <daniel.m.jordan@oracle.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>

#include "scx_prev.bpf.skel.h"

const char help_fmt[] =
"A variation on scx_simple with CPU selection that prioritizes an idle\n"
"previous CPU over finding a fully idle core.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-i sec] [-v]\n"
"\n"
"  -h            Display this help and exit\n"
"  -i            Sampling interval for statistics in seconds\n"
"  -v            Print libbpf debug messages\n";

static bool verbose;
static unsigned stat_interval = 1;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int unused)
{
	exit_req = 1;
}

static void read_stats(struct scx_prev *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	assert(nr_cpus > 0);
	__u64 cnts[4][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 4);

	for (idx = 0; idx < 4; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_prev *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(prev_ops, scx_prev);

	while ((opt = getopt(argc, argv, "hi:v")) != -1) {
		switch (opt) {
		case 'i':
			stat_interval = strtoull(optarg, NULL, 0);
			if (!stat_interval)
				stat_interval = 1;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, prev_ops, scx_prev, uei);
	link = SCX_OPS_ATTACH(skel, prev_ops, scx_prev);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[4];

		read_stats(skel, stats);
		printf("local=%llu select_fail=%llu prev_cpu=%llu idle_cpu=%llu\n",
		       stats[0], stats[1], stats[2], stats[3]);
		fflush(stdout);
		sleep(stat_interval);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_prev__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
