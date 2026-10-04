/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifdef CAKE_TEST_NATIVE_MULHI
#define CAKE_QUOTIENT_MULHI(x, y) ((u64)(((__uint128_t)(x) * (y)) >> 64))
#endif
#include "quotient.bpf.h"

static u64 checks;

static void check(u64 a, u64 d)
{
	u64 expected = d ? a / d : 0;
	u64 got = cake_udiv64_recip(a, d);

	if (got != expected) {
		fprintf(stderr, "quotient mismatch: a=%llu d=%llu got=%llu expected=%llu\n",
			(unsigned long long)a, (unsigned long long)d,
			(unsigned long long)got, (unsigned long long)expected);
		assert(got == expected);
	}
	if (d) {
		assert((__uint128_t)got * d <= a);
		assert(a - got * d < d);
	}
	checks++;
}

static u64 random64(u64 *state)
{
	*state ^= *state << 13;
	*state ^= *state >> 7;
	*state ^= *state << 17;
	return *state;
}

int main(void)
{
	u64 state = 0xd1b54a32d192ed03ULL;
	const u64 edges[] = {0, 1, 2, 3, 4, 5, 7, 8, 9, 31, 32, 33,
		65535, 65536, 65537, 0xffffffffULL, 0x100000000ULL,
		0x100000001ULL, (1ULL << 63) - 1, 1ULL << 63,
		(1ULL << 63) + 1, ~0ULL - 1, ~0ULL};

	for (u32 i = 0; i < 256; i++)
		assert(cake_recip_seed[i] == ((1U << 19) - 3 * (1U << 8)) / (256 + i));
	for (u64 d = 0; d < 1024; d++)
		for (u64 a = 0; a < 1024; a++)
			check(a, d);
	for (u32 i = 0; i < sizeof(edges) / sizeof(*edges); i++)
		for (u32 j = 0; j < sizeof(edges) / sizeof(*edges); j++)
			check(edges[i], edges[j]);
	for (u32 bit = 0; bit < 64; bit++) {
		u64 power = 1ULL << bit;

		for (int delta = -2; delta <= 2; delta++) {
			u64 d = power + delta;

			for (u32 i = 0; i < sizeof(edges) / sizeof(*edges); i++)
				check(edges[i], d);
			for (u32 q = 0; q < 1024 && d; q++) {
				__uint128_t product = (__uint128_t)d * q;

				if (product > ~0ULL)
					break;
				u64 a = (u64)product;

				check(a, d);
				if (a)
					check(a - 1, d);
				if (a != ~0ULL)
					check(a + 1, d);
			}
		}
	}
	for (u32 prefix = 256; prefix < 512; prefix++) {
		u64 lo = (u64)prefix << 55, hi = lo | ((1ULL << 55) - 1);
		u64 values[] = {lo, lo + 1, lo + 2, hi - 2, hi - 1, hi};

		for (u32 i = 0; i < sizeof(values) / sizeof(*values); i++) {
			u64 d = values[i];
			u64 expected = (u64)((~(__uint128_t)0) / d - ((__uint128_t)1 << 64));

			assert(cake_reciprocal64(d) == expected);
		}
	}
	for (u32 i = 0; i < 2000000; i++) {
		u64 a = random64(&state), b = random64(&state);
		u64 d = (b >> (i & 63)) | 1;
		u64 normalized = b | (1ULL << 63);
		u64 expected = (u64)((~(__uint128_t)0) / normalized - ((__uint128_t)1 << 64));

		assert(cake_mulhi64_portable(a, b) == (u64)(((__uint128_t)a * b) >> 64));
		assert(cake_reciprocal64(normalized) == expected);
		check(a, d);
		check(a, b);
		check(~0ULL, d);
	}
	printf("PASS: %llu exact quotient cases, 2001536 reciprocal cases, "
	       "2000000 portable MULHI cases; zero mismatches\n",
	       (unsigned long long)checks);
	return 0;
}
