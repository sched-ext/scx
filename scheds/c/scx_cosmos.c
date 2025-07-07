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
#include "scx_cosmos.bpf.skel.h"
#include "scx_cosmos.h"

/*
 * Default time slice (in ns).
 */
#define SLICE_US	10ULL

static int *cpu_list = NULL;
static int nr_cpus = 0;

const char help_fmt[] =
"Lightweight sched_ext scheduler emphasizing optimal CPU placement.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-v]\n"
"\n"
"  -c CPU1,CPU2,... Specify a list of CPUs to prioritize\n"
"  -s SLICE_US      Override slice duration in us (default: 10us)\n"
"  -s NUM           Specify the task's time slice (in us)\n"
"  -v               Print libbpf debug messages\n"
"  -h               Display this help and exit\n";

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

static int enable_primary_cpu(struct scx_cosmos *skel, int cpu)
{
	struct cpu_arg ctx = {
		.cpu_id = cpu,
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr,
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);
	int prog_fd = bpf_program__fd(skel->progs.enable_primary_cpu);

	return bpf_prog_test_run_opts(prog_fd, &tattr);
}

static int parse_cpu_list(const char *optarg, int *cpus, int max_cpus)
{
	char *token, *str, *tofree;
	int count = 0;

	tofree = str = strdup(optarg);
	if (!str)
		return -1;

	while ((token = strsep(&str, ",")) != NULL) {
		if (count >= max_cpus) {
			fprintf(stderr, "Too many CPUs specified (max %d)\n", max_cpus);
			free(tofree);
			return -1;
		}
		cpus[count++] = atoi(token);
	}

	free(tofree);
	return count;
}

int main(int argc, char **argv)
{
	struct scx_cosmos *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;
	int err, i, max_cpus;

	max_cpus = libbpf_num_possible_cpus();
	if (max_cpus < 0) {
		fprintf(stderr, "Failed to get number of possible CPUs: %d\n", max_cpus);
		return 1;
	}

	cpu_list = calloc(max_cpus, sizeof(int));
	if (!cpu_list) {
		perror("calloc");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(cosmos_ops, scx_cosmos);

	skel->rodata->slice_ns = SLICE_US * 1000ULL;

	while ((opt = getopt(argc, argv, "vhc:s:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'c':
			nr_cpus = parse_cpu_list(optarg, cpu_list, max_cpus);
			if (nr_cpus < 0) {
				fprintf(stderr, "Invalid CPU list: %s\n", optarg);
				free(cpu_list);
				return 1;
			}
			break;
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			free(cpu_list);
			return opt != 'h';
		}
	}

	skel->rodata->primary_all = !nr_cpus;

	SCX_OPS_LOAD(skel, cosmos_ops, scx_cosmos, uei);

	if (nr_cpus > 0)
		fprintf(stdout, "Primary CPUs: [");
	for (i = 0; i < nr_cpus; i++) {
		fprintf(stdout, "%d, ", cpu_list[i]);
		err = enable_primary_cpu(skel, cpu_list[i]);
		if (err) {
			fprintf(stderr, "\nFailed to enable CPU %d: %s\n",
			        cpu_list[i], strerror(-err));
			scx_cosmos__destroy(skel);
			free(cpu_list);

			return err;
		}
	}
	if (nr_cpus > 0)
		fprintf(stdout, "\b\b]\n");

	link = SCX_OPS_ATTACH(skel, cosmos_ops, scx_cosmos);

	fprintf(stdout, "scheduler is running (CTRL+C to stop)\n");
	fflush(stdout);

	while (!exit_req && !UEI_EXITED(skel, uei))
		sleep(1);

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_cosmos__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	free(cpu_list);

	return 0;
}
