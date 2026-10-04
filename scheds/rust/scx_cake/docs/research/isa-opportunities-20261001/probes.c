/* SPDX-License-Identifier: GPL-2.0 */
/* Standalone compiler probes; these are not loadable Cake programs. */
typedef unsigned long long u64;
typedef unsigned int u32;
#define NOINLINE __attribute__((noinline))
#ifdef __bpf__
#define FAST __attribute__((bpf_fastcall))
#else
#define FAST
#endif

extern u64 scalar_plain(u64);
extern u64 scalar_fast(u64) FAST;
extern u64 binary_plain(u64, u64);
extern u64 binary_fast(u64, u64) FAST;
extern u64 clz_native(u64);

#define UNARY_PROBE(name, call) \
NOINLINE u64 name(u64 a, u64 b, u64 c, u64 d, u64 e) \
{ \
	u64 v = call(a); \
	asm volatile("" : "+r"(b), "+r"(c), "+r"(d), "+r"(e)); \
	return v + b + c + d + e; \
}
UNARY_PROBE(unary_plain, scalar_plain)
UNARY_PROBE(unary_fast, scalar_fast)

#define BINARY_PROBE(name, call) \
NOINLINE u64 name(u64 a, u64 b, u64 c, u64 d, u64 e) \
{ \
	u64 v = call(a, b); \
	asm volatile("" : "+r"(c), "+r"(d), "+r"(e)); \
	return v + c + d + e; \
}
BINARY_PROBE(mul_plain, binary_plain)
BINARY_PROBE(mul_fast, binary_fast)

/* Caller contract: shift is in [1, 63]. */
NOINLINE u64 quotient_finish_bpf(u64 a, u64 hi, u32 shift)
{
	u64 sum = a + hi;
	return (sum >> (64 - shift)) | ((u64)(sum < a) << shift);
}

#ifndef __bpf__
/* Native bodies to inspect for the proposed copy-and-validate inliner.
 * These are userspace compiler probes, not kernel-configured kfunc objects. */
NOINLINE u64 body_clz(u64 x)
{
	return x ? __builtin_clzll(x) : 64;
}
NOINLINE u64 body_popcnt(u64 x)
{
	return __builtin_popcountll(x);
}
NOINLINE u64 body_mulhi(u64 x, u64 y)
{
	return (u64)(((__uint128_t)x * y) >> 64);
}
NOINLINE u64 quotient_finish_wide(u64 a, u64 hi, u32 shift)
{
	return (u64)(((__uint128_t)a + hi) >> (64 - shift));
}
#endif

NOINLINE u32 bit_set_fetch(u64 *word, u32 bit)
{
	u64 mask = 1ULL << (bit & 63);
	return !!(__atomic_fetch_or(word, mask, __ATOMIC_SEQ_CST) & mask);
}

NOINLINE u32 bit_clear_fetch(u64 *word, u32 bit)
{
	u64 mask = 1ULL << (bit & 63);
	return !!(__atomic_fetch_and(word, ~mask, __ATOMIC_SEQ_CST) & mask);
}

NOINLINE u64 whole_word_fetch_or(u64 *word, u64 mask)
{
	return __atomic_fetch_or(word, mask, __ATOMIC_SEQ_CST);
}

NOINLINE void bit_set_no_fetch(u64 *word, u32 bit)
{
	__atomic_fetch_or(word, 1ULL << (bit & 63), __ATOMIC_RELAXED);
}

#define HIST_PROBES(tag, shift, bands) \
NOINLINE u32 hist_loop_##tag(u64 ns) \
{ \
	u64 v = ns >> shift; \
	u32 b = 0; \
	while (b < bands - 1 && (v >> (b + 1))) b++; \
	return b; \
} \
NOINLINE u32 hist_builtin_##tag(u64 ns) \
{ \
	u32 b = 63 - __builtin_clzll((ns >> shift) | 1); \
	return b < bands - 1 ? b : bands - 1; \
} \
NOINLINE u32 hist_kfunc_##tag(u64 ns) \
{ \
	u32 b = 63 - ((u32)clz_native((ns >> shift) | 1) & 63); \
	return b < bands - 1 ? b : bands - 1; \
}
HIST_PROBES(release, 10, 8)
HIST_PROBES(general, 8, 16)
