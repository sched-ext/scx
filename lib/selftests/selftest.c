/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <sys/resource.h>
#include <sys/sysinfo.h>

#include <scx/common.h>
#include <scx/bpf_arena_common.h>

#include "selftest.h"

#include <lib/atq.h>
#include <lib/arena.h>
#include <lib/sdt_task.h>

#include "selftest.skel.h"

struct bpf_prog_stream_read_opts {
	size_t sz;
	size_t :0;
};

extern int bpf_prog_stream_read(int prog_fd, __u32 stream_id, void *buf, __u32 buf_len, struct bpf_prog_stream_read_opts *opts) __attribute__((weak));

char *topo_command = "lscpu --all --parse \
		      | cut -f 1,2,4,9 -d ',' \
		      | tail -n +5";

#define TOPO_LEVELS 5
#define CPUMASK_MAX_SIZE 64
#define TOPO_MAX_CPU (64  * CPUMASK_MAX_SIZE)
#define TOPO_MAX_ID (4096)

u64 topo_top[CPUMASK_MAX_SIZE];
u64 topology[TOPO_LEVELS - 1][TOPO_MAX_ID][CPUMASK_MAX_SIZE];
u64 topo_max_offset[TOPO_LEVELS];

#define VALIDATE_PERROR(errval, perrstr) do { \
	if (!errval) \
		break; \
	if (perrstr) \
		perror(perrstr); \
	fprintf(stderr, "%s:%d %s\n", __func__, __LINE__, strerror(errval)); \
	exit(0); \
} while (0)

#define VALIDATE(errval) VALIDATE_PERROR((errval), NULL)

#define CRASHOUT() do { fprintf(stderr, "%s:%d [fail]\n", __func__, __LINE__); exit(0); } while (0)

static int
selftest_arena_init(struct selftest *skel)
{
	struct bpf_test_run_opts opts;
	struct arena_init_args args;
	int prog_fd;
	int progret;
	int ret;

	args = (struct arena_init_args) {
		.static_pages = 512,
		.task_ctx_size = sizeof(struct task_ctx_nonarena),
	};

	memset(&opts, 0, sizeof(opts));
	opts = (struct bpf_test_run_opts) {
		.sz = sizeof(opts),
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	};

	prog_fd = bpf_program__fd(skel->progs.arena_init);
	assert(prog_fd >= 0 && "no program found");

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	VALIDATE(ret);

	if (opts.retval) {
		fprintf(stderr, "error %d in %s", opts.retval, __func__);
		CRASHOUT();
	}

	return 0;
}


int selftest_alloc_mask(struct selftest *skel, u64 **maskp)
{
	struct bpf_test_run_opts opts;
	struct arena_alloc_mask_args args;
	int prog_fd;
	int progret;
	int ret;

	args = (struct arena_alloc_mask_args) {
		.bitmap = 0ULL,
	};

	memset(&opts, 0, sizeof(opts));
	opts =  (struct bpf_test_run_opts) {
		.sz = sizeof(opts),
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	};

	prog_fd = bpf_program__fd(skel->progs.arena_alloc_mask);
	assert(prog_fd >= 0 && "no program found");

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	VALIDATE(ret);

	if (opts.retval) {
		fprintf(stderr, "error %d in %s", opts.retval, __func__);
		CRASHOUT();
	}

	*maskp = (u64 *)args.bitmap;

	return 0;
}

int selftest_topology_node_init(struct selftest *skel, u64 *mask)
{
	struct bpf_test_run_opts opts;
	struct arena_topology_node_init_args args;
	int prog_fd;
	int progret;
	int ret;

	args = (struct arena_topology_node_init_args) {
		.bitmap = (u64)mask,
		.data_size = 0,
		.id = 0,
	};

	memset(&opts, 0, sizeof(opts));
	opts =  (struct bpf_test_run_opts) {
		.sz = sizeof(opts),
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	};

	prog_fd = bpf_program__fd(skel->progs.arena_topology_node_init);
	assert(prog_fd >= 0 && "no program found");

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	VALIDATE(ret);

	if (opts.retval) {
		fprintf(stderr, "error %d in %s", opts.retval, __func__);
		CRASHOUT();
	}

	return 0;
}

static bool cpumask_empty(unsigned int level, unsigned int id)
{
	u64 *mask;
	int i;

	assert(level < TOPO_LEVELS && "invalid topology level");
	assert(id < TOPO_MAX_ID && "invalid topology id");

	for (i = 0; i < CPUMASK_MAX_SIZE; i++) {
		if (topology[level][id][i])
			return false;
	}

	return true;
}

static int
selftest_topology_single(struct selftest *skel, u64 *src)
{
	u64 *dst;
	int ret;

	ret = selftest_alloc_mask(skel, &dst);
	assert(!ret && "failed to allocate mask");

	memcpy(dst, src, topo_max_offset[3] + 63 / 64);

	ret = selftest_topology_node_init(skel, dst);
	assert(!ret && "failed to initialize topology node");

	return 0;
}

static int
selftest_topology_init(struct selftest *skel)
{
	int cpu, node, core, llc;
	int level, id;
	FILE *fp;

	int ret;
	fp = popen(topo_command, "r");
	while ((ret = fscanf(fp, "%d,%d,%d,%d\n", &cpu, &core, &node, &llc) == 4)) {
		assert( cpu  < TOPO_MAX_ID &&
			core < TOPO_MAX_ID &&
			llc  < TOPO_MAX_ID && 
			node < TOPO_MAX_ID &&
			"topology ID out of bounds");
		topology[0][node][cpu / 64] |= 1ULL << (cpu % 64);
		topo_max_offset[0] = topo_max_offset[0] > node ? topo_max_offset[0] : node;

		topology[1][llc ][cpu / 64] |= 1ULL << (cpu % 64);
		topo_max_offset[1] = topo_max_offset[1] > llc ? topo_max_offset[1] : llc;

		topology[2][core][cpu / 64] |= 1ULL << (cpu % 64);
		topo_max_offset[2] = topo_max_offset[2] > core ? topo_max_offset[2] : core;

		topology[3][cpu ][cpu / 64] |= 1ULL << (cpu % 64);
		topo_max_offset[3] = topo_max_offset[3] > cpu ? topo_max_offset[3] : cpu;

		topo_top[cpu / 64] |= 1ULL << (cpu % 64);
	}

	/* Topology top. */
	selftest_topology_single(skel, (u64 *)topo_top);

	for (level = 0; level < 4; level++) {
		for (id = 0; id <= topo_max_offset[level]; id++) {
			if (cpumask_empty(level, id))
				continue;

			selftest_topology_single(skel, (u64 *)topology[level][id]);
		}
	}

	return 0;
}

static int
selftest(struct selftest *skel)
{
	struct bpf_test_run_opts opts;
	struct arena_init_args args;
	char buf[1024];
	int prog_fd;
	int progret;
	int ret;

	memset(&opts, 0, sizeof(opts));
	prog_fd = bpf_program__fd(skel->progs.arena_selftest);
	assert(prog_fd >= 0 && "no program found");

	opts.sz = sizeof(opts);

	ret = bpf_prog_test_run_opts(prog_fd, &opts);
	VALIDATE(ret);

	if (opts.retval)
		fprintf(stderr, "error %d in %s\n", opts.retval, __func__);

	if (!bpf_prog_stream_read) {
		fprintf(stderr, "[BPF Streams Unavailable]\n");
		return 0;
	}
	printf("BPF stdout:\n");
	while ((ret = bpf_prog_stream_read(prog_fd, 1, buf, 1024, NULL)) > 0)
		printf("%.*s", ret, buf);

	VALIDATE(ret);

	printf("BPF stderr:\n");
	while ((ret = bpf_prog_stream_read(prog_fd, 2, buf, 1024, NULL)) > 0)
		printf("%.*s", ret, buf);

	VALIDATE(ret);

	return 0;
}

int bump_rlimit(void)
{
	int ret;

	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	ret = setrlimit(RLIMIT_MEMLOCK, &rlim);
	VALIDATE_PERROR(ret, "setrlimit");

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char *argv[])
{
	struct selftest *skel;
	int ret;

	libbpf_set_print(libbpf_print_fn);

	ret = bump_rlimit();
	VALIDATE(ret);

	skel = selftest__open();
	assert(skel && "no skeleton generated");

	skel->rodata->nr_cpu_ids = get_nprocs();

	ret = selftest__load(skel);
	VALIDATE(ret);

	ret = selftest__attach(skel);
	VALIDATE(ret);

	selftest_arena_init(skel);
	selftest_topology_init(skel);

	selftest(skel);

	printf("Tests complete");

	return 0;
}
