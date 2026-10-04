/* SPDX-License-Identifier: GPL-2.0 */
/* Userspace dependency/throughput probes, not BPF or scheduler timings. */
#define _GNU_SOURCE
#include <inttypes.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef uint64_t u64;
typedef u64 (*probe_fn)(u64, u64);

#define CHAIN(NAME, BODY) \
static __attribute__((noinline)) u64 NAME(u64 count, u64 seed) \
{ \
	u64 result; \
	asm volatile("mov %[seed], %%r8\n1:\n.rept 256\n" BODY \
		     ".endr\ndec %%rcx\njnz 1b\nmov %%r8, %%rax\n" \
		     : "=a"(result), "+c"(count) : [seed] "r"(seed) : "r8", "cc"); \
	return result; \
}

CHAIN(chain_add, "add $1, %%r8\n")
CHAIN(chain_ctz, "tzcnt %%r8, %%r8\n")
CHAIN(chain_clz, "lzcnt %%r8, %%r8\n")
CHAIN(chain_popcnt, "popcnt %%r8, %%r8\n")
CHAIN(chain_ctz_mask, "tzcnt %%r8, %%r8\nand $63, %%r8\n")
CHAIN(chain_clz_mask, "lzcnt %%r8, %%r8\nand $63, %%r8\n")

#define PARALLEL(NAME, OP) \
static __attribute__((noinline)) u64 NAME(u64 count, u64 seed) \
{ \
	u64 result; \
	asm volatile("mov %[seed], %%r8\nmov %%r8, %%r9\nmov %%r8, %%r10\n" \
		     "mov %%r8, %%r11\nmov %%r8, %%r12\nmov %%r8, %%r13\n" \
		     "mov %%r8, %%r14\nmov %%r8, %%r15\n1:\n.rept 32\n" \
		     OP " %%r8, %%r8\n" OP " %%r9, %%r9\n" \
		     OP " %%r10, %%r10\n" OP " %%r11, %%r11\n" \
		     OP " %%r12, %%r12\n" OP " %%r13, %%r13\n" \
		     OP " %%r14, %%r14\n" OP " %%r15, %%r15\n" \
		     ".endr\ndec %%rcx\njnz 1b\nmov %%r8, %%rax\n" \
		     : "=a"(result), "+c"(count) : [seed] "r"(seed) \
		     : "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc"); \
	return result; \
}

PARALLEL(parallel_ctz, "tzcnt")
PARALLEL(parallel_clz, "lzcnt")
PARALLEL(parallel_popcnt, "popcnt")

static __attribute__((noinline)) u64 chain_mulhi(u64 count, u64 seed)
{
	u64 result;

	asm volatile("movabs $0xd2b74407b1ce6e93, %%rsi\n1:\n.rept 256\n"
		     "mov %%rdi, %%rax\nmul %%rsi\nmov %%rdx, %%rax\n"
		     "mov %%rax, %%rdi\nadd $1, %%rdi\n.endr\n"
		     "dec %%rcx\njnz 1b\n"
		     : "=a"(result), "+c"(count), "+D"(seed)
		     : : "rsi", "rdx", "cc");
	return result;
}

static u64 now(void)
{
	struct timespec value;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &value))
		abort();
	return (u64)value.tv_sec * 1000000000 + value.tv_nsec;
}

static int counter(u64 config, int group)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_HARDWARE,
		.size = sizeof(attr),
		.config = config,
		.disabled = group < 0,
		.pinned = group < 0,
		.exclude_kernel = 1,
		.exclude_hv = 1,
		.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
			       PERF_FORMAT_TOTAL_TIME_RUNNING,
	};
	int fd = syscall(SYS_perf_event_open, &attr, 0, -1, group, 0);

	if (fd < 0) {
		perror("perf_event_open");
		exit(1);
	}
	return fd;
}

int main(int argc, char **argv)
{
	const char *names[] = {"add_dependency", "ctz_dependency", "clz_dependency",
		"popcnt_dependency", "ctz_mask_dependency", "clz_mask_dependency",
		"ctz_8_chains", "clz_8_chains", "popcnt_8_chains", "mulhi_3insn_plus_feedback"};
	probe_fn probes[] = {chain_add, chain_ctz, chain_clz, chain_popcnt,
		chain_ctz_mask, chain_clz_mask, parallel_ctz, parallel_clz,
		parallel_popcnt, chain_mulhi};
	const u64 loops = 62500, operations = loops * 256;
	cpu_set_t mask;
	int cpu = argc == 2 ? atoi(argv[1]) : 15;

	if (cpu < 0 || cpu >= CPU_SETSIZE)
		return 2;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask)) {
		perror("sched_setaffinity");
		return 1;
	}
	int cycles = counter(PERF_COUNT_HW_CPU_CYCLES, -1);
	int instructions = counter(PERF_COUNT_HW_INSTRUCTIONS, cycles);
	/* Every probe warmed; alternate forward/reverse order across ten rounds. */
	for (unsigned int i = 0; i < 10; i++)
		probes[i](1000, 0x8f1329af517b6801ULL);
	for (unsigned int round = 0; round < 10; round++)
		for (unsigned int i = 0; i < 10; i++) {
			unsigned int p = round & 1 ? 9 - i : i;
			struct { u64 nr, enabled, running, values[2]; } counts = {};
			struct rusage before, after;
			u64 begin, end, result;

			getrusage(RUSAGE_THREAD, &before);
			if (ioctl(cycles, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) ||
			    ioctl(cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP))
				return 1;
			begin = now();
			result = probes[p](loops, 0x8f1329af517b6801ULL + round);
			end = now();
			if (ioctl(cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP))
				return 1;
			getrusage(RUSAGE_THREAD, &after);
			if (read(cycles, &counts, sizeof(counts)) != sizeof(counts) ||
			    counts.nr != 2 || !counts.running)
				return 1;
			printf("{\"round\":%u,\"probe\":\"%s\",\"cpu\":%d,\"operations\":%" PRIu64
			       ",\"wall_ns\":%" PRIu64 ",\"cycles\":%" PRIu64 ",\"instructions\":%" PRIu64
			       ",\"enabled_ns\":%" PRIu64 ",\"running_ns\":%" PRIu64
			       ",\"context_switches\":%ld,\"checksum\":%" PRIu64 "}\n",
			       round, names[p], sched_getcpu(), operations, end - begin,
			       counts.values[0], counts.values[1], counts.enabled, counts.running,
			       after.ru_nvcsw + after.ru_nivcsw - before.ru_nvcsw - before.ru_nivcsw,
			       result);
		}
	close(instructions);
	close(cycles);
	return 0;
}
