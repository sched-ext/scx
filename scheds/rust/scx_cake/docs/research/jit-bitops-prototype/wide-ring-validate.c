/* SPDX-License-Identifier: GPL-2.0 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;

struct trace {
	u32 attempted[1024], words[18];
	u64 values[18];
	u32 attempts, reads, steps;
};

static struct trace observed;
static u64 masks[16], mutation_seed;
static u32 stop_at;
static u64 cases, total_linear, total_skip;

static u64 mix(u64 value)
{
	value ^= value >> 30;
	value *= 0xbf58476d1ce4e5b9ULL;
	value ^= value >> 27;
	value *= 0x94d049bb133111ebULL;
	return value ^ (value >> 31);
}

static u64 read_word(u32 wi)
{
	u32 n = observed.reads++;
	u64 word = masks[wi];

	if (wi >= 16 || n >= 18)
		abort();
	if (mutation_seed)
		word ^= mix(mutation_seed + n * 16 + wi);
	observed.words[n] = wi;
	observed.values[n] = word;
	return word;
}

static int try_cpu(u32 cpu)
{
	if (cpu >= 1024 || observed.attempts >= 1024)
		abort();
	observed.attempted[observed.attempts++] = cpu;
	return observed.attempts == stop_at;
}

static u32 ctz(u64 value)
{
	if (!value)
		abort();
	return __builtin_ctzll(value);
}

#define STEP() (observed.steps++)
#include "wide-ring-scan.h"

static void check(u32 cpu, u32 nr)
{
	struct trace reference;
	int a, b;

	memset(&observed, 0, sizeof(observed));
	a = ring_linear(cpu, nr);
	reference = observed;
	memset(&observed, 0, sizeof(observed));
	b = ring_ctz_skip(cpu, nr);
	if (a != b || reference.attempts != observed.attempts ||
	    reference.reads != observed.reads ||
	    memcmp(reference.attempted, observed.attempted, sizeof(reference.attempted)) ||
	    memcmp(reference.words, observed.words, sizeof(reference.words)) ||
	    memcmp(reference.values, observed.values, sizeof(reference.values)) ||
	    observed.steps > nr - 1 || reference.steps > nr - 1) {
		fprintf(stderr, "Mismatch case=%llu cpu=%u nr=%u stop=%u mutation=%llu\n",
			(unsigned long long)cases, cpu, nr, stop_at,
			(unsigned long long)mutation_seed);
		exit(1);
	}
	cases++;
	total_linear += reference.steps;
	total_skip += observed.steps;
}

int main(void)
{
	u64 random = 0x374cd6510085fa27ULL;

	/* Every mask, source CPU and early-success position on up to 10 CPUs. */
	for (u32 nr = 1; nr <= 10; nr++)
		for (u64 bits = 0; bits < (1ULL << nr); bits++)
			for (u32 cpu = 0; cpu < nr; cpu++)
				for (stop_at = 0; stop_at <= nr; stop_at++) {
					masks[0] = bits;
					check(cpu, nr);
				}
	u64 exhaustive = cases;
	/* All supported spans/sources: empty, full, self-only and boundary bits. */
	for (u32 nr = 1; nr <= 1024; nr++)
		for (u32 cpu = 0; cpu < nr; cpu++)
			for (u32 pattern = 0; pattern < 4; pattern++) {
				memset(masks, pattern == 1 ? 255 : 0, sizeof(masks));
				if (pattern == 2)
					masks[cpu >> 6] = 1ULL << (cpu & 63);
				if (pattern == 3)
					for (u32 w = 0; w < 16; w++)
						masks[w] = 0x8000000000000001ULL;
				stop_at = 0;
				check(cpu, nr);
			}
	u64 boundaries = cases - exhaustive;
	/* Per-word-read mutation and arbitrary early success, including holes. */
	for (u32 n = 0; n < 200000; n++) {
		random = mix(random);
		u32 nr = (random & 1023) + 1;
		u32 cpu = (random >> 10) % nr;

		stop_at = (random >> 32) % (nr + 1);
		mutation_seed = n & 1 ? random : 0;
		for (u32 w = 0; w < 16; w++) {
			random = mix(random);
			masks[w] = random;
		}
		check(cpu, nr);
	}
	printf("{\"cases\":%llu,\"exhaustive\":%llu,\"boundaries\":%llu,"
	       "\"random_mutation\":200000,\"mismatches\":0,"
	       "\"linear_iterations\":%llu,\"skip_iterations\":%llu}\n",
	       (unsigned long long)cases, (unsigned long long)exhaustive,
	       (unsigned long long)boundaries, (unsigned long long)total_linear,
	       (unsigned long long)total_skip);
	/* Fixed examples count source-level loop iterations, never cycles. */
	mutation_seed = 0;
	stop_at = 0;
	for (u32 full = 0; full < 2; full++) {
		memset(masks, full ? 255 : 0, sizeof(masks));
		check(0, 1024);
		printf("example full=%u nr=1024 source=0 linear=1023 skip=%u reads=%u attempts=%u\n",
		       full, observed.steps, observed.reads, observed.attempts);
	}
	return 0;
}
