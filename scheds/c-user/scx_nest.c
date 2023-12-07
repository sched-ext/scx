/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2023 David Vernet <dvernet@meta.com>
 * Copyright (c) 2023 Tejun Heo <tj@kernel.org>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>

#include "scx_nest.bpf.skel.h"
#include "scx_nest.h"

#define SAMPLING_CADENCE_S 2

const char help_fmt[] =
"A Nest sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-p] [-d DELAY] [-m <max>] [-i ITERS]\n"
"\n"
"  -d DELAY_US   Delay (us), before removing an idle core from the primary nest (default 2000us / 2ms)\n"
"  -m R_MAX      Maximum number of cores in the reserve nest (default 5)\n"
"  -i ITERS      Number of successive placement failures tolerated before trying to aggressively expand primary nest (default 2), or 0 to disable\n"
"  -s SLICE_US   Override slice duration in us (default 20000us / 20ms)\n"
"  -D R_SCHED    Override the number of times that a core may be scheduled for compaction before having compaction happen immediately (default 5)\n"
"  -I            First try to find a fully idle core, and then any idle core, when searching nests. Default behavior is to ignore hypertwins and check for any idle core.\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;

static void sigint_handler(int nest)
{
	exit_req = 1;
}

struct nest_stat {
        const char *label;
        enum nest_stat_group group;
        enum nest_stat_idx idx;
};

#define NEST_ST(__stat, __grp, __desc) {	\
	.label = #__stat,		\
	.group = __grp,			\
	.idx = NEST_STAT(__stat)		\
},
static struct nest_stat nest_stats[NEST_STAT(NR)] = {
#include "scx_nest_stats_table.h"
};
#undef NEST_ST

static void read_stats(struct scx_nest *skel, u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	u64 cnts[NEST_STAT(NR)][nr_cpus];
	u32 idx;

	memset(stats, 0, sizeof(stats[0]) * NEST_STAT(NR));

	for (idx = 0; idx < NEST_STAT(NR); idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

static void print_underline(const char *str)
{
	char buf[64];
	size_t len;

	len = strlen(str);
	memset(buf, '-', len);
	buf[len] = '\0';
	printf("\n\n%s\n%s\n", str, buf);
}

static void print_stat_grp(enum nest_stat_group grp)
{
	const char *group;

	switch (grp) {
		case STAT_GRP_WAKEUP:
			group = "Wakeup stats";
			break;
		case STAT_GRP_NEST:
			group = "Nest stats";
			break;
		case STAT_GRP_CONSUME:
			group = "Consume stats";
			break;
		default:
			group = "Unknown stats";
			break;
	}

	print_underline(group);
}

static void print_active_nests(const struct scx_nest *skel)
{
	u64 primary = skel->bss->stats_primary_mask;
	u64 reserved = skel->bss->stats_reserved_mask;
	u64 other = skel->bss->stats_other_mask;
	u64 idle = skel->bss->stats_idle_mask;
	u32 nr_cpus = skel->rodata->nr_cpus, cpu;
	int idx;
	char cpus[nr_cpus + 1];

	memset(cpus, 0, nr_cpus + 1);
	print_underline("Masks");
	for (idx = 0; idx < 4; idx++) {
		const char *mask_str;
		u64 mask, total = 0;

		memset(cpus, '-', nr_cpus);
		if (idx == 0) {
			mask_str = "PRIMARY";
			mask = primary;
		} else if (idx == 1) {
			mask_str = "RESERVED";
			mask = reserved;
		} else if (idx == 2) {
			mask_str = "OTHER";
			mask = other;
		} else {
			mask_str = "IDLE";
			mask = idle;
		}
		for (cpu = 0; cpu < nr_cpus; cpu++) {
			if (mask & (1ULL << cpu)) {
				cpus[cpu] = '*';
				total++;
			}
		}
		printf("%-9s(%2lu): | %s |\n", mask_str, total, cpus);
	}
}

int main(int argc, char **argv)
{
	struct scx_nest *skel;
	struct bpf_link *link;
	__u32 opt;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_nest__open();
	SCX_BUG_ON(!skel, "Failed to open skel");

	skel->rodata->nr_cpus = libbpf_num_possible_cpus();
	skel->rodata->sampling_cadence_ns = SAMPLING_CADENCE_S * 1000 * 1000 * 1000;

	while ((opt = getopt(argc, argv, "hId:D:m:i:s:")) != -1) {
		switch (opt) {
		case 'd':
			skel->rodata->p_remove_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		case 'D':
			skel->rodata->r_depth = strtoull(optarg, NULL, 0);
			break;
		case 'm':
			skel->rodata->r_max = strtoull(optarg, NULL, 0);
			break;
		case 'i':
			skel->rodata->r_impatient = strtoull(optarg, NULL, 0);
			break;
		case 'I':
			skel->rodata->find_fully_idle = true;
			break;
		case 's':
			skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_BUG_ON(scx_nest__load(skel), "Failed to load skel");

	link = bpf_map__attach_struct_ops(skel->maps.nest_ops);
	SCX_BUG_ON(!link, "Failed to attach struct_ops");

	while (!exit_req && !uei_exited(&skel->bss->uei)) {
		u64 stats[NEST_STAT(NR)];
		enum nest_stat_idx i;
		enum nest_stat_group last_grp = -1;

		read_stats(skel, stats);
		for (i = 0; i < NEST_STAT(NR); i++) {
			struct nest_stat *nest_stat;

			nest_stat = &nest_stats[i];
			if (nest_stat->group != last_grp) {
				print_stat_grp(nest_stat->group);
				last_grp = nest_stat->group;
			}
			printf("%s=%lu\n", nest_stat->label, stats[nest_stat->idx]);
		}
		printf("\n");
		print_active_nests(skel);
		printf("\n");
		printf("\n");
		printf("\n");
		fflush(stdout);
		sleep(SAMPLING_CADENCE_S);
	}

	bpf_link__destroy(link);
	uei_print(&skel->bss->uei);
	scx_nest__destroy(skel);
	return 0;
}
