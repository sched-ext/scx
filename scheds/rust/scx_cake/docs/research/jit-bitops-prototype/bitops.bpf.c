// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

extern __u64 bpf_ctz64(__u64 x) __ksym;
extern __u64 bpf_popcnt64(__u64 x) __ksym;

volatile __u64 seed;
volatile __u64 salt[4];
volatile __u32 iterations;
volatile __u32 dependent;
__u64 checksum;
__u32 processed;

static __always_inline __u64 software_ctz(__u64 x)
{
	return x ? __builtin_ctzll(x) : 64;
}

static __always_inline __u64 software_pop(__u64 x)
{
	return __builtin_popcountll(x);
}

static __always_inline __u64 identity(__u64 x)
{
	return x;
}

/* Keep four live inputs across the calls as well as the changing operand. */
#define BITOPS_RUN(NAME, OP) \
SEC("tc") \
int NAME(struct __sk_buff *skb) \
{ \
	__u64 x = seed, sum = 0; \
	__u64 a = salt[0], b = salt[1], c = salt[2], d = salt[3]; \
	__u32 n = iterations, chain = dependent; \
	int i; \
	(void)skb; \
	if (!n || n > 4096) \
		return 1; \
	bpf_for(i, 0, n) { \
		__u64 value = OP(x); \
		sum += value; \
		x += 0x9e3779b97f4a7c15ULL + (chain ? value : 0); \
	} \
	checksum = sum ^ a ^ (b + 3) ^ (c * 5) ^ (d >> 7); \
	processed = n; \
	return 0; \
}

BITOPS_RUN(sw_ctz, software_ctz)
BITOPS_RUN(hw_ctz, bpf_ctz64)
BITOPS_RUN(sw_pop, software_pop)
BITOPS_RUN(hw_pop, bpf_popcnt64)
BITOPS_RUN(control, identity)

char LICENSE[] SEC("license") = "GPL";
