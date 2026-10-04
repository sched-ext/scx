// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include "bitops.skel.h"

static unsigned char packet[64] = {0};
static struct bitops *skel;
static struct bpf_program *programs[5];
static const char *names[] = { "sw_ctz", "hw_ctz", "sw_pop", "hw_pop", "control" };

static void fail(const char *msg)
{
	fprintf(stderr, "%s: %s\n", msg, strerror(errno));
	exit(1);
}

static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts))
		fail("clock_gettime");
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static uint64_t random64(uint64_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 7;
	*s ^= *s << 17;
	return *s;
}

/* Deliberately independent reference algorithms, without compiler builtins. */
static uint64_t reference(unsigned int op, uint64_t x)
{
	uint64_t n = 0;
	if (op == 4)
		return x;
	if (op < 2) {
		if (!x)
			return 64;
		while (!(x & 1)) {
			n++;
			x >>= 1;
		}
	} else {
		while (x) {
			n += x & 1;
			x >>= 1;
		}
	}
	return n;
}

static uint64_t expected(unsigned int op)
{
	uint64_t x = skel->bss->seed, sum = 0;
	for (unsigned int i = 0; i < skel->bss->iterations; i++) {
		uint64_t v = reference(op, x);
		sum += v;
		x += 0x9e3779b97f4a7c15ULL + (skel->bss->dependent ? v : 0);
	}
	return sum ^ skel->bss->salt[0] ^ (skel->bss->salt[1] + 3) ^
		(skel->bss->salt[2] * 5) ^ (skel->bss->salt[3] >> 7);
}

static uint64_t run(unsigned int op, unsigned int repeat, unsigned int *duration)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = packet, .data_size_in = sizeof(packet), .repeat = repeat);
	uint64_t want = expected(op), start, elapsed;
	skel->bss->processed = 0;
	skel->bss->checksum = ~want;
	start = now_ns();
	if (bpf_prog_test_run_opts(bpf_program__fd(programs[op]), &opts))
		fail("BPF_PROG_TEST_RUN");
	elapsed = now_ns() - start;
	if (opts.retval || skel->bss->processed != skel->bss->iterations ||
	    skel->bss->checksum != want) {
		fprintf(stderr, "FAIL %s input=%016" PRIx64 " n=%u chain=%u got=%016"
			PRIx64 " want=%016" PRIx64 " retval=%u processed=%u\n",
			names[op], (uint64_t)skel->bss->seed, skel->bss->iterations,
			skel->bss->dependent, (uint64_t)skel->bss->checksum, want,
			opts.retval, skel->bss->processed);
		exit(1);
	}
	*duration = opts.duration;
	return elapsed;
}

static void dump_program(unsigned int op, const char *dir)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	char path[4096];
	void *jit, *xlated;
	FILE *f;
	int fd = bpf_program__fd(programs[op]);
	if (bpf_obj_get_info_by_fd(fd, &info, &len))
		fail("program info");
	if (!info.jited_prog_len || !info.xlated_prog_len) {
		fprintf(stderr, "Native/translated bytes unavailable for %s; refusing evidence run\n", names[op]);
		exit(1);
	}
	jit = calloc(1, info.jited_prog_len);
	xlated = calloc(1, info.xlated_prog_len);
	if (!jit || !xlated)
		fail("allocate dump");
	/* Query one advertises other array lengths too. Do not request those
	 * arrays without buffers in query two (map IDs, line info, symbols).
	 */
	info = (struct bpf_prog_info) {
		.jited_prog_len = info.jited_prog_len,
		.xlated_prog_len = info.xlated_prog_len,
		.jited_prog_insns = (__u64)(uintptr_t)jit,
		.xlated_prog_insns = (__u64)(uintptr_t)xlated,
	};
	if (bpf_obj_get_info_by_fd(fd, &info, &len))
		fail("retrieve program bytes");
	if (!info.jited_prog_len || !info.xlated_prog_len) {
		fprintf(stderr, "Kernel withheld instruction bytes for %s\n", names[op]);
		exit(1);
	}
	for (unsigned int kind = 0; kind < 2; kind++) {
		int n = snprintf(path, sizeof(path), "%s/%s.%s", dir, names[op], kind ? "bpf.bin" : "jit.bin");
		if (n < 0 || (size_t)n >= sizeof(path)) {
			errno = ENAMETOOLONG;
			fail("dump path");
		}
		f = fopen(path, "wbx");
		if (!f)
			fail("open dump");
		size_t size = kind ? info.xlated_prog_len : info.jited_prog_len;
		if (fwrite(kind ? xlated : jit, 1, size, f) != size || fclose(f))
			fail("write dump");
	}
	printf("{\"type\":\"program\",\"name\":\"%s\",\"id\":%u,\"jit_bytes\":%u,\"bpf_bytes\":%u}\n",
	       names[op], info.id, info.jited_prog_len, info.xlated_prog_len);
	free(jit);
	free(xlated);
}

int main(int argc, char **argv)
{
	unsigned int repeat = 10000, blocks = 12, duration;
	uint64_t rng = 0xd1b54a32d192ed03ULL;
	struct utsname uts;
	bool check_only = false;
	int cpu = sched_getcpu();
	cpu_set_t affinity;
	const char *dir;

	if (argc < 2 || argc > 5) {
		fprintf(stderr, "Usage: %s NEW_OUTPUT_DIRECTORY [--check-only | REPEAT [BLOCKS [CPU]]]\n", argv[0]);
		return 2;
	}
	dir = argv[1];
	if (argc > 2 && !strcmp(argv[2], "--check-only"))
		check_only = true;
	else if (argc > 2)
		repeat = strtoul(argv[2], NULL, 10);
	if (argc > 3)
		blocks = strtoul(argv[3], NULL, 10);
	if (argc > 4)
		cpu = strtol(argv[4], NULL, 10);
	if (!repeat || repeat > 1000000 || !blocks || blocks > 100 || cpu < 0 || cpu >= CPU_SETSIZE)
		return 2;
	CPU_ZERO(&affinity);
	CPU_SET(cpu, &affinity);
	if (sched_setaffinity(0, sizeof(affinity), &affinity))
		fail("pin CPU");
	if (mkdir(dir, 0755))
		fail("create new output directory");
	if (uname(&uts))
		fail("uname");
	printf("{\"type\":\"environment\",\"kernel\":\"%s\",\"cpu\":%d,\"repeat\":%u,\"blocks\":%u,\"check_only\":%s}\n",
	       uts.release, cpu, repeat, blocks, check_only ? "true" : "false");
	skel = bitops__open_and_load();
	if (!skel) {
		fprintf(stderr, "Load failed. Requires the patched kernel and BPF permissions; nothing was attached.\n");
		return 1;
	}
	programs[0] = skel->progs.sw_ctz;
	programs[1] = skel->progs.hw_ctz;
	programs[2] = skel->progs.sw_pop;
	programs[3] = skel->progs.hw_pop;
	programs[4] = skel->progs.control;
	for (unsigned int op = 0; op < 5; op++)
		dump_program(op, dir);

	/* Every single bit and its complement, boundaries, then random values. */
	for (unsigned int t = 0; t < 1156; t++) {
		uint64_t x;
		if (t < 64)
			x = 1ULL << t;
		else if (t < 128)
			x = ~(1ULL << (t - 64));
		else if (t == 128)
			x = 0;
		else if (t == 129)
			x = UINT64_MAX;
		else if (t == 130)
			x = 0xaaaaaaaaaaaaaaaaULL;
		else if (t == 131)
			x = 0x5555555555555555ULL;
		else
			x = random64(&rng);
		skel->bss->seed = x;
		skel->bss->iterations = t < 132 ? 1 : 17;
		skel->bss->dependent = t & 1;
		for (unsigned int k = 0; k < 4; k++)
			skel->bss->salt[k] = random64(&rng);
		for (unsigned int op = 0; op < 5; op++)
			run(op, 1, &duration);
	}
	printf("{\"type\":\"correctness\",\"vectors\":1156,\"program_runs\":5780,\"mismatches\":0}\n");
	if (check_only)
		goto out;
	for (unsigned int chain = 0; chain < 2; chain++) {
		skel->bss->dependent = chain;
		for (unsigned int n = 64; n <= 1024; n *= 4) {
			skel->bss->iterations = n;
			for (unsigned int block = 0; block < blocks; block++) {
				skel->bss->seed = random64(&rng);
				for (unsigned int family = 0; family < 2; family++) {
					/* Alternate ABBA/BAAB blocks; identical inputs within a block. */
					for (unsigned int slot = 0; slot < 4; slot++) {
						unsigned int arm = ((slot == 1 || slot == 2) ^ (block & 1));
						unsigned int op = family * 2 + arm;
						uint64_t elapsed;
						run(op, 8, &duration);
						elapsed = run(op, repeat, &duration);
						printf("{\"type\":\"timing\",\"name\":\"%s\",\"chain\":%u,\"batch\":%u,\"block\":%u,\"slot\":%u,\"repeat\":%u,\"wall_ns\":%" PRIu64 ",\"kernel_ns_per_run\":%u,\"seed\":\"%016" PRIx64 "\",\"checksum\":\"%016" PRIx64 "\"}\n",
						       names[op], chain, n, block, slot, repeat, elapsed, duration,
						       (uint64_t)skel->bss->seed, (uint64_t)skel->bss->checksum);
					}
				}
				uint64_t elapsed = run(4, repeat, &duration);
				printf("{\"type\":\"control\",\"chain\":%u,\"batch\":%u,\"block\":%u,\"repeat\":%u,\"wall_ns\":%" PRIu64 ",\"kernel_ns_per_run\":%u}\n",
				       chain, n, block, repeat, elapsed, duration);
			}
		}
	}
out:
	bitops__destroy(skel);
	return 0;
}
