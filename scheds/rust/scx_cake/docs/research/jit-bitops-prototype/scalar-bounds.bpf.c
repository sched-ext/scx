// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern __u64 bpf_ctz64(__u64 x) __ksym __attribute__((bpf_fastcall));
extern __u64 bpf_clz64(__u64 x) __ksym __attribute__((bpf_fastcall));
extern __u64 bpf_popcnt64(__u64 x) __ksym __attribute__((bpf_fastcall));
extern __u64 bpf_mulhi64(__u64 x, __u64 y) __ksym;

struct array64 { __u64 values[64]; };
struct array65 { __u64 values[65]; };
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct array64);
} table64 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct array65);
} table65 SEC(".maps");

volatile __u64 input;

#define INDEX_TEST(name, size, expression, guard) \
SEC("syscall") int name(void *ctx) \
{ \
	__u32 key = 0; \
	struct array##size *table = bpf_map_lookup_elem(&table##size, &key); \
	__u64 x = input; \
	(void)x; \
	if (!table || (guard)) \
		return 0; \
	return table->values[(expression)]; \
}

INDEX_TEST(ok_ctz_unknown, 65, bpf_ctz64(x), 0)
INDEX_TEST(ok_clz_unknown, 65, bpf_clz64(x), 0)
INDEX_TEST(ok_popcnt_unknown, 65, bpf_popcnt64(x), 0)
INDEX_TEST(ok_ctz_nonzero, 64, bpf_ctz64(x), !x)
INDEX_TEST(ok_clz_nonzero, 64, bpf_clz64(x), !x)
INDEX_TEST(ok_ctz_or1, 64, bpf_ctz64(x | 1), 0)
INDEX_TEST(ok_clz_or1, 64, bpf_clz64(x | 1), 0)
INDEX_TEST(ok_ctz_topbit, 64, bpf_ctz64(x | (1ULL << 63)), 0)
INDEX_TEST(ok_clz_topbit, 64, bpf_clz64(x | (1ULL << 63)), 0)
INDEX_TEST(ok_ctz_signed, 64, bpf_ctz64(x), (__s64)x >= 0)
INDEX_TEST(ok_clz_signed, 64, bpf_clz64(x), (__s64)x >= 0)
INDEX_TEST(ok_ctz_zero, 65, bpf_ctz64(0), 0)
INDEX_TEST(ok_clz_zero, 65, bpf_clz64(0), 0)
INDEX_TEST(ok_popcnt_full, 65, bpf_popcnt64(~0ULL), 0)
INDEX_TEST(control_ctz, 64, bpf_ctz64(x) & 63, 0)
INDEX_TEST(control_clz, 64, bpf_clz64(x) & 63, 0)
INDEX_TEST(control_popcnt, 64, bpf_popcnt64(x) & 63, 0)

INDEX_TEST(bad_ctz_unknown, 64, bpf_ctz64(x), 0)
INDEX_TEST(bad_clz_unknown, 64, bpf_clz64(x), 0)
INDEX_TEST(bad_popcnt_unknown, 64, bpf_popcnt64(x), 0)
INDEX_TEST(bad_ctz_zero, 64, bpf_ctz64(0), 0)
INDEX_TEST(bad_clz_zero, 64, bpf_clz64(0), 0)
INDEX_TEST(bad_popcnt_full, 64, bpf_popcnt64(~0ULL), 0)
INDEX_TEST(bad_ctz_plus1, 64, bpf_ctz64(x) + 1, !x)
INDEX_TEST(bad_clz_plus1, 64, bpf_clz64(x) + 1, !x)
INDEX_TEST(bad_popcnt_plus1, 65, bpf_popcnt64(x) + 1, 0)
INDEX_TEST(bad_mulhi, 65, bpf_mulhi64(x, ~0ULL), 0)
INDEX_TEST(bad_other_helper, 65, bpf_get_prandom_u32(), 0)

#define PRUNING_TEST(name, function) \
SEC("syscall") __naked int name(void) \
{ \
	asm volatile ( \
		"r1 = %[table64] ll; r2 = r10; r2 += -8;" \
		"*(u64 *)(r2 + 0) = 0; call %[bpf_map_lookup_elem];" \
		"if r0 == 0 goto done_%=; r6 = r0;" \
		"r1 = %[input] ll; r1 = *(u64 *)(r1 + 0);" \
		"if r1 == 0 goto zero_%=; r1 = 1; goto join_%=;" \
		"zero_%=: r1 = 0; join_%=: goto +0;" \
		"call " #function "; r0 <<= 3; r6 += r0;" \
		"r0 = *(u64 *)(r6 + 0); done_%=: exit;" \
		: : __imm_addr(table64), __imm_addr(input), \
		    __imm(bpf_map_lookup_elem) : __clobber_all); \
}

PRUNING_TEST(bad_ctz_pruning, bpf_ctz64)
PRUNING_TEST(bad_clz_pruning, bpf_clz64)

char LICENSE[] SEC("license") = "GPL";
