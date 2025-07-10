/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_cosmos.bpf.skel.h"
#include "scx_cosmos.h"

/*
 * Track global CPU utilization.
 *
 * If the CPU utilization exceeds the busy threshold the scheduler
 * automatially switches to a deadline-based policy, otherwise the
 * scheduler operates in a round-robin fashion to reduce overhead.
 */
struct cpu_util {
	u64 user;
	u64 nice;
	u64 total;
};

/*
 * Default time slice (in us).
 */
#define SLICE_US	10ULL

/*
 * Default polling time to evaluate CPU utilization (in us)
 */
#define POLLING_US	(250 * 1000ULL)

static u64 polling_us = POLLING_US;

static int *cpu_list = NULL;
static int nr_cpus = 0;

const char help_fmt[] =
"Lightweight sched_ext scheduler emphasizing optimal CPU placement.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-s TIME_US] [-m CPU1,CPU2,...] [-c PERC] [-p TIME_US] [-n] [-v] [-h]\n"
"\n"
"  -s TIME_US       Override slice duration in us (default: 10us)\n"
"  -m CPU1,CPU2,... Specify a list of CPUs to prioritize\n"
"  -c PERC          Specify utilization threshold %% to consider the system busy (default 75%%)\n"
"  -p TIME_MS       Specify the polling period to evaluate CPU utilization (default 250ms, 0 = disabled)\n"
"  -n               Enable NUMA optimizations\n"
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
	const char *s;
	char *token, *str, *tofree, *p;
	int count = 0;

	/*
	 * Validate CPU list.
	 */
	for (s = optarg; *s; s++) {
		if (!isdigit(*s) && *s != '-' && *s != ',') {
			fprintf(stderr, "Invalid character in CPU list: '%c'\n", *s);
			return -1;
		}
	}

	/*
	 * Translate CPU range list into an array.
	 */
	tofree = str = strdup(optarg);
	if (!str)
		return -1;

	for (p = str; *p; p++)
		if (*p == ' ')
			*p = '\t';

	while ((token = strsep(&str, ",")) != NULL) {
		char *dash, *endptr;
		int start, end, i;

		while (*token == ' ' || *token == '\t')
			token++;
		endptr = token + strlen(token) - 1;

		while (endptr > token && (*endptr == ' ' || *endptr == '\t')) {
			*endptr = '\0';
			endptr--;
		}

		dash = strchr(token, '-');
		if (dash) {
			*dash = '\0';
			dash++;

			start = atoi(token);
			end = atoi(dash);

			if (start > end) {
				fprintf(stderr, "Invalid CPU range: %d-%d\n", start, end);
				free(tofree);

				return -1;
			}

			for (i = start; i <= end; i++) {
				if (count >= max_cpus) {
					fprintf(stderr, "Too many CPUs specified (max %d)\n", max_cpus);
					free(tofree);
					return -1;
				}
				cpus[count++] = i;
			}
		} else {
			int cpu = atoi(token);

			if (count >= max_cpus) {
				fprintf(stderr, "Too many CPUs specified (max %d)\n", max_cpus);
				free(tofree);
				return -1;
			}
			cpus[count++] = cpu;
		}
	}
	free(tofree);

	return count;
}

static int read_cpu_times(struct cpu_util *util)
{
	char line[4096];
	u64 fields[8];
	int matched, i;
	FILE *file;

	file = fopen("/proc/stat", "r");
	if (!file)
		return 0;

	if (fgets(line, sizeof(line), file) == NULL) {
		fclose(file);
		return 0;
	}
	fclose(file);

	if (strncmp(line, "cpu ", 4) != 0)
		return 0;

	matched = sscanf(line + 4, "%lu %lu %lu %lu %lu %lu %lu %lu",
			 &fields[0], &fields[1], &fields[2], &fields[3],
			 &fields[4], &fields[5], &fields[6], &fields[7]);

	if (matched < 2)
		return 0;

	util->user = fields[0];
	util->nice = fields[1];

	util->total = 0;
	for (i = 0; i < matched; i++)
		util->total += fields[i];

	return 1;
}

static int compute_user_cpu_pct(const struct cpu_util *prev,
				const struct cpu_util *curr, u64 *result)
{
	u64 total_diff = (curr->total > prev->total) ?
				(curr->total - prev->total) : 0;
	u64 user_diff = ((curr->user + curr->nice) > (prev->user + prev->nice)) ?
				(curr->user + curr->nice - prev->user - prev->nice) : 0;

	if (total_diff > 0) {
		*result = (user_diff * 1024 + total_diff / 2) / total_diff;
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct cpu_util prev, curr;
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

	fprintf(stdout, ">> ");
	for (i = 0; i < argc; i++)
		printf("%s ", argv[i]);
	fprintf(stdout, "\n");

restart:
	skel = SCX_OPS_OPEN(cosmos_ops, scx_cosmos);

	skel->rodata->slice_ns = SLICE_US * 1000ULL;
	skel->rodata->busy_threshold = 75 * 1024 / 100;
	skel->rodata->numa_enabled = false;

	while ((opt = getopt(argc, argv, "vhnm:s:p:c:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'm':
			nr_cpus = parse_cpu_list(optarg, cpu_list, max_cpus);
			if (nr_cpus < 0) {
				fprintf(stderr, "Invalid CPU list: %s\n", optarg);
				free(cpu_list);
				return 1;
			}
			break;
		case 'n':
			skel->rodata->numa_enabled = true;
			break;
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 'c':
			skel->rodata->busy_threshold = strtoull(optarg, NULL, 0) * 1024 / 100;
			break;
		case 'p':
			polling_us = strtoull(optarg, NULL, 0) * 1000ULL;
			if (polling_us == 0)
				polling_us = -1ULL;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			free(cpu_list);
			return opt != 'h';
		}
	}

	skel->rodata->primary_all = !nr_cpus;

	/*
	 * Set scheduler flags.
	 */
	skel->struct_ops.cosmos_ops->flags = SCX_OPS_ENQ_EXITING |
					     SCX_OPS_ENQ_MIGRATION_DISABLED |
					     SCX_OPS_ENQ_LAST |
					     SCX_OPS_ALLOW_QUEUED_WAKEUP;
	if (skel->rodata->numa_enabled)
		skel->struct_ops.cosmos_ops->flags |= SCX_OPS_BUILTIN_IDLE_PER_NODE;

	fprintf(stdout, "flags: %#llx\n", skel->struct_ops.cosmos_ops->flags);

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

	if (!read_cpu_times(&prev)) {
		fprintf(stderr, "Failed to read CPU utilization\n");
		return 1;
	}

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		u64 user_pct;

		usleep(polling_us);

		if (!read_cpu_times(&curr)) {
			fprintf(stderr, "Failed to read CPU utilization\n");
			return 1;
		}

		if (compute_user_cpu_pct(&prev, &curr, &user_pct)) {
			skel->bss->cpu_util = user_pct;
			if (verbose) {
				bool is_busy = user_pct >= skel->rodata->busy_threshold;

				fprintf(stdout, "CPUs: %.2f%% %s\n",
				       (float)user_pct * 100.0f / 1024.0f, is_busy ? "[busy]" : "");
				fflush(stdout);
			}
		}

		prev = curr;
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_cosmos__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	free(cpu_list);

	return 0;
}
