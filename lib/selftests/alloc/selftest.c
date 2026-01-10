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

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>

#include <scx/common.h>
#include <scx/bpf_arena_common.h>

#include "selftest.h"

#include <lib/arena.h>
#include <lib/alloc/asan.h>

#include <alloc/static.h>
#include <alloc/stack.h>
#include <alloc/buddy.h>

#include "selftest.skel.h"

static bool verbose = false;

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

typedef int (*selftest_func)(struct selftest *);

static int
selftest_fd(int prog_fd, struct bpf_test_run_opts *calleropts)
{
	struct bpf_test_run_opts opts, *argopts;
	char buf[1024];
	int progret;
	int ret;

	argopts = calleropts;
	if (!argopts) {
		memset(&opts, 0, sizeof(opts));
		opts.sz = sizeof(opts);
		argopts = &opts;
	}

	ret = bpf_prog_test_run_opts(prog_fd, argopts);
	VALIDATE(ret);

	if (argopts->retval)
		fprintf(stderr, "error %d in %s\n", argopts->retval, __func__);

	printf("BPF stdout:\n");
	while ((ret = bpf_prog_stream_read(prog_fd, 1, buf, 1024, NULL)) > 0)
		printf("%.*s", ret, buf);

	VALIDATE(ret);

	if (verbose) {
		printf("BPF stderr:\n");
		while ((ret = bpf_prog_stream_read(prog_fd, 2, buf, 1024, NULL)) > 0)
			printf("%.*s", ret, buf);
	}

	VALIDATE(ret);

	return 0;
}

static int
selftest_arena_alloc_reserve(struct selftest *skel)
{
	int prog_fd;
	int ret;

	printf("===START arena_alloc_reserve START===\n");
	prog_fd = bpf_program__fd(skel->progs.arena_alloc_reserve);
	assert(prog_fd >= 0 && "no program found");

	ret = selftest_fd(prog_fd, NULL);
	fprintf(stderr, "====END arena_alloc_reserve END=====\n\n");

	return ret;
}

static int
selftest_arena_base(struct selftest *skel, void **arena_base)
{
	struct bpf_test_run_opts opts;
	struct arena_base_args args;
	u64 globals_pages;
	int prog_fd;
	int ret;

	args = (struct arena_base_args) {
		.arena_base = NULL
	};

	opts = (struct bpf_test_run_opts) {
		.sz = sizeof(opts),
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	};

	prog_fd = bpf_program__fd(skel->progs.arena_base);
	assert(prog_fd >= 0 && "no program found");

	ret = selftest_fd(prog_fd, &opts);
	if (ret)
		return ret;

	*arena_base = args.arena_base;

	return 0;
}

static int
selftest_globals_pages(struct selftest *skel, size_t arena_all_pages, u64 *globals_pages)
{
	size_t pgsize = sysconf(_SC_PAGESIZE);
	void *arena_base;
	u64 pages;
	u8 *vec;
	int ret;
	int i;

	ret = selftest_arena_base(skel, &arena_base);
	if (ret)
		return ret;

	if (!arena_base)
		return -EINVAL;

	vec = calloc(arena_all_pages, sizeof(*vec));
	if (!vec)
		return -ENOMEM;

	if (mincore(arena_base, arena_all_pages * pgsize, vec)) {
		perror("mincore");
		free(vec);
		return -1;
	}

	/* Find the first nonresident page. */
	pages = 0;
	for (i = arena_all_pages - 1; i >= 0; i--) {
		if (!(vec[i] & 0x1))
			break;

		pages += 1;
	}

	free(vec);

	*globals_pages = pages;

	return 0;
}

static int
selftest_asan_init(struct selftest *skel)
{
	struct bpf_test_run_opts opts;
	size_t arena_all_pages = 1ULL << 20;
	struct asan_init_args args;
	u64 globals_pages;
	int prog_fd;
	int ret;

	ret = selftest_globals_pages(skel, arena_all_pages, &globals_pages);
	if (ret)
		return ret;

	/* Taken from the arena map header. */
	args = (struct asan_init_args) {
		.arena_all_pages = arena_all_pages,
		.arena_globals_pages = globals_pages,
	};

	opts = (struct bpf_test_run_opts) {
		.sz = sizeof(opts),
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	};

	prog_fd = bpf_program__fd(skel->progs.asan_init);
	assert(prog_fd >= 0 && "no program found");
	return selftest_fd(prog_fd, &opts);
}

static int
selftest_alloc(struct selftest *skel)
{
	int prog_fd;
	int ret;

	ret = selftest_arena_alloc_reserve(skel);
	if (ret)
		return ret;

	ret = selftest_asan_init(skel);
	if (ret)
		return ret;

	printf("===START alloc_selftest START===\n");
	prog_fd = bpf_program__fd(skel->progs.alloc_selftest);
	assert(prog_fd >= 0 && "no program found");

	ret = selftest_fd(prog_fd, NULL);
	printf("====END alloc_selftest END=====\n\n");

	return ret;
}

static int
selftest_asan(struct selftest *skel)
{
	int prog_fd;
	int ret;

	ret = selftest_arena_alloc_reserve(skel);
	if (ret)
		return ret;

	ret = selftest_asan_init(skel);
	if (ret)
		return ret;

	printf("===START asan_test START===\n");
	prog_fd = bpf_program__fd(skel->progs.asan_test);
	assert(prog_fd >= 0 && "no program found");
	ret = selftest_fd(prog_fd, NULL);
	printf("===END  asan_test END===\n\n");

	return ret;
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

int run_test(selftest_func func)
{
	struct selftest *skel;
	int ret;

	libbpf_set_print(libbpf_print_fn);

	ret = bump_rlimit();
	VALIDATE(ret);

	skel = selftest__open();
	assert(skel && "no skeleton generated");

	ret = selftest__load(skel);
	VALIDATE(ret);

	ret = selftest__attach(skel);
	VALIDATE(ret);

	func(skel);

	printf("Tests complete\n");

	return 0;
}

int main(int argc, char *argv[])
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
			verbose = true;
	}

	run_test(selftest_alloc);
	run_test(selftest_asan);

	return 0;
}
