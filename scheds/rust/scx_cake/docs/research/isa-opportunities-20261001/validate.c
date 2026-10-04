/* SPDX-License-Identifier: GPL-2.0 */
/* Offline correctness tests, not timing or kernel-verifier tests. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define CAKE_QUOTIENT_MULHI(x, y) ((u64)(((__uint128_t)(x) * (y)) >> 64))
#include "quotient.snapshot.h"

static u64 state = 0x42fedcba98765431ULL;
static u64 rnd(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

static u64 finish_native(u64 a, u64 hi, u32 shift)
{
	u64 top;
	u32 count = 64 - shift;
	asm volatile("xor %[top], %[top]\n\t"
		     "add %[hi], %[low]\n\t"
		     "adc $0, %[top]\n\t"
		     "shrd %%cl, %[top], %[low]"
		     : [low] "+&r"(a), [top] "=&r"(top)
		     : [hi] "r"(hi), "c"(count) : "cc");
	return a;
}

static u64 finish_shld(u64 a, u64 hi, u32 shift)
{
	u64 carry = 0;
	asm volatile("add %[hi], %[low]\n\t"
		     "setc %b[carry]\n\t"
		     "shld %%cl, %[low], %[carry]"
		     : [low] "+&r"(a), [carry] "+&q"(carry)
		     : [hi] "r"(hi), "c"(shift) : "cc");
	return carry;
}

static u64 candidate_quotient(u64 numerator, u64 divisor)
{
	u64 normalized, reciprocal, hi, quotient, remainder;
	u32 shift;
	if (!divisor || numerator < divisor) return 0;
	if (divisor == 1) return numerator;
	shift = (u32)__builtin_clzll(divisor) & 63;
	if (!shift) return 1;
	if (!(divisor & (divisor - 1))) return numerator >> (63 - shift);
	normalized = divisor << shift;
	reciprocal = cake_reciprocal64(normalized);
	hi = CAKE_QUOTIENT_MULHI(numerator, reciprocal);
	quotient = finish_native(numerator, hi, shift);
	remainder = numerator - quotient * divisor;
	return quotient + (remainder >= divisor);
}

static u32 band_loop(u64 ns, u32 shift, u32 bands)
{
	u64 v = ns >> shift;
	u32 b = 0;
	while (b < bands - 1 && (v >> (b + 1))) b++;
	return b;
}
static u32 band_clz(u64 ns, u32 shift, u32 bands)
{
	u32 b = 63 - __builtin_clzll((ns >> shift) | 1);
	return b < bands - 1 ? b : bands - 1;
}

static u32 bit_native(u64 *word, u32 bit, int clear)
{
	unsigned char old;
	u64 bounded = bit & 63;
	if (clear)
		asm volatile("lock btrq %[bit], %[word]\n\tsetc %b[old]"
			: [word] "+m"(*word), [old] "=q"(old)
			: [bit] "r"(bounded) : "cc", "memory");
	else
		asm volatile("lock btsq %[bit], %[word]\n\tsetc %b[old]"
			: [word] "+m"(*word), [old] "=q"(old)
			: [bit] "r"(bounded) : "cc", "memory");
	return old;
}

static unsigned long long finish_cases, quotient_cases, histogram_cases, atomic_cases, mulhi_cases;
static void check_mulhi_preserves_rdx(u64 x, u64 y)
{
	u64 expected = (u64)(((__uint128_t)x * y) >> 64);
	u64 sentinel = rnd(), saved = sentinel, result;
	/* Two-argument BPF fastcall may scratch R1/RDI but must preserve R3/RDX. */
	asm volatile("mov %%rdi, %%rax\n\t"
		     "mov %%rdx, %%rdi\n\t"
		     "mul %%rsi\n\t"
		     "mov %%rdx, %%rax\n\t"
		     "mov %%rdi, %%rdx"
		     : "=&a"(result), "+D"(x), "+d"(saved)
		     : "S"(y) : "cc");
	if (result != expected || saved != sentinel) abort();
	mulhi_cases++;
}
static void check_finish(u64 a, u64 h)
{
	for (u32 s = 1; s < 64; s++) {
		u64 sum = a + h;
		u64 orig = (sum >> (64-s)) | ((u64)(sum < a) << s);
		u64 wide = (u64)(((__uint128_t)a+h) >> (64-s));
		if (orig != wide || finish_native(a,h,s) != wide ||
		    finish_shld(a,h,s) != wide) abort();
		finish_cases++;
	}
}
static void check_q(u64 a, u64 d)
{
	u64 expected = d ? a/d : 0;
	if (cake_udiv64_recip(a,d) != expected || candidate_quotient(a,d) != expected) abort();
	quotient_cases++;
}
static void check_band(u64 n)
{
	if (band_loop(n,10,8) != band_clz(n,10,8)) abort();
	if (band_loop(n,8,16) != band_clz(n,8,16)) abort();
	histogram_cases += 2;
}

int main(void)
{
	u64 edge[] = {0,1,2,3,7,8,63,64,UINT32_MAX,1ULL<<32,(1ULL<<63)-1,1ULL<<63,UINT64_MAX-1,UINT64_MAX};
	for (u32 i=0; i<sizeof(edge)/sizeof(edge[0]); i++) {
		check_band(edge[i]);
		for (u32 j=0; j<sizeof(edge)/sizeof(edge[0]); j++) {
			check_finish(edge[i],edge[j]);
			check_q(edge[i],edge[j]);
			check_mulhi_preserves_rdx(edge[i],edge[j]);
		}
	}
	for (u32 i=0;i<64;i++) {
		u64 b=1ULL<<i;
		check_band(b-1); check_band(b); check_band(b+1);
		for (u32 j=0;j<200;j++) {
			u64 a=rnd();
			check_q(a,b-1); check_q(a,b); check_q(a,b+1);
		}
	}
	for (u64 n=0;n<(1ULL<<20);n++) check_band(n);
	for (u32 i=0;i<200000;i++) {
		u64 a=rnd(), d=rnd();
		check_q(a,d); check_q(a,(u32)d); check_band(a);
		check_mulhi_preserves_rdx(a,d);
		if(i<10000) check_finish(a,d);
	}
	for (u32 bit=0;bit<64;bit++) for(u32 i=0;i<512;i++) {
		u64 before=rnd(), mask=1ULL<<bit;
		for (int clear=0;clear<=1;clear++) {
			u64 word=before;
			u32 old=bit_native(&word,bit,clear);
			if(old != !!(before&mask) || word != (clear ? before&~mask : before|mask)) abort();
			atomic_cases++;
		}
	}
	printf("{\"finish_cases\":%llu,\"quotient_cases\":%llu,\"histogram_cases\":%llu,\"atomic_single_thread_cases\":%llu,\"mulhi_preservation_cases\":%llu,\"mismatches\":0,\"performance_measured\":false}\n",
		finish_cases,quotient_cases,histogram_cases,atomic_cases,mulhi_cases);
}
