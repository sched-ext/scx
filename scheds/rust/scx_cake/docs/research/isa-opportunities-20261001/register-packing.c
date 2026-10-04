/* SPDX-License-Identifier: GPL-2.0 */
/* Scalar register-packing compiler probes. No kernel or scheduler activation. */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
#define NOINLINE __attribute__((noinline))
#ifdef __bpf__
#define FAST __attribute__((bpf_fastcall))
#else
#define FAST
#endif
extern u64 scalar_plain(u64);
extern u64 scalar_fast(u64) FAST;

NOINLINE u64 nibble_get_fixed(u64 word) { return (word >> 8) & 15; }
NOINLINE u64 nibble_nonzero_fixed(u64 word) { return !!(word & 0xf00); }
NOINLINE u64 nibble_replace_fixed(u64 word, u64 value)
{
	return (word & ~0xf00ULL) | ((value & 15) << 8);
}
NOINLINE u64 nibble_get_variable(u64 word, u32 field)
{
	return (word >> ((field & 15) * 4)) & 15;
}
NOINLINE u64 nibble_replace_variable(u64 word, u32 field, u64 value)
{
	u32 shift = (field & 15) * 4;
	u64 mask = 15ULL << shift;
	return (word & ~mask) | ((value & 15) << shift);
}
NOINLINE u64 nibble_increment_wrap_fixed(u64 word)
{
	return (word & ~0xf00ULL) | ((word + 0x100) & 0xf00);
}
NOINLINE u64 nibble_increment_saturate_fixed(u64 word)
{
	return (word & 0xf00) == 0xf00 ? word : word + 0x100;
}

NOINLINE u64 lanes_increment_saturate_swar(u64 word)
{
	const u64 ones = 0x1111111111111111ULL;
	u64 full = word & (word >> 1) & (word >> 2) & (word >> 3) & ones;
	/* A full lane gets +0; every other lane gets +1, so no carry crosses lanes. */
	return word + (ones ^ full);
}

NOINLINE u64 lanes_increment_saturate_scalar(u64 word)
{
	u64 result = 0;
#pragma clang loop unroll(full)
	for (u32 lane=0; lane<16; lane++) {
		u64 n = (word >> (lane*4)) & 15;
		result |= (n < 15 ? n+1 : n) << (lane*4);
	}
	return result;
}

NOINLINE u64 lanes_increment_saturate_loop(u64 word)
{
	u64 result = 0;
#pragma clang loop unroll(disable)
	for (u32 lane=0; lane<16; lane++) {
		u64 n = (word >> (lane*4)) & 15;
		result |= (n < 15 ? n+1 : n) << (lane*4);
	}
	return result;
}

/* Deliberately consume all six fields after an unknown call. This is a
 * pressure probe, not an approximation of a particular Cake callback. */
static inline u64 mix(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f, u64 t)
{
	return (a + t) ^ (b * t) ^ (c << (t & 7)) ^
	       (d * (t + 3)) ^ (e << ((t >> 3) & 7)) ^ (f + (t >> 1));
}
#define UNPACKED(name, call) \
NOINLINE u64 name(const u8 *p, u64 x) \
{ \
	u64 a=p[0]&15, b=p[1]&15, c=p[2]&15; \
	u64 d=p[3]&15, e=p[4]&15, f=p[5]&15; \
	u64 t=call(x); \
	return mix(a,b,c,d,e,f,t); \
}
UNPACKED(six_unpacked_plain, scalar_plain)
UNPACKED(six_unpacked_fast, scalar_fast)

#define PACKED(name, call, barrier) \
NOINLINE u64 name(const u8 *p, u64 x) \
{ \
	u64 word=(u64)(p[0]&15) | ((u64)(p[1]&15)<<4) | \
		 ((u64)(p[2]&15)<<8) | ((u64)(p[3]&15)<<12) | \
		 ((u64)(p[4]&15)<<16) | ((u64)(p[5]&15)<<20); \
	u64 t=call(x); \
	barrier; \
	return mix(word&15,(word>>4)&15,(word>>8)&15, \
		   (word>>12)&15,(word>>16)&15,(word>>20)&15,t); \
}
PACKED(six_packed_plain, scalar_plain, (void)0)
PACKED(six_packed_opaque, scalar_plain, asm volatile("" : "+r"(word)))
PACKED(six_packed_fast, scalar_fast, (void)0)

#ifdef PACKING_TEST
#include <stdio.h>
#include <stdlib.h>
NOINLINE u64 scalar_plain(u64 x) { return __builtin_popcountll(x); }
u64 scalar_fast(u64 x) { return scalar_plain(x); }
static u64 seed=0x427feed123ULL;
static u64 random64(void)
{
	seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
	return seed;
}
int main(void)
{
	u64 field_cases=0, call_cases=0, swar_cases=0;
	for (u32 i=0; i<100000; ++i) {
		u64 word=random64(), value=random64();
		for (u32 field=0; field<16; ++field) {
			u32 shift=field*4;
			u64 mask=15ULL<<shift;
			u64 changed=nibble_replace_variable(word,field,value);
			if(nibble_get_variable(word,field)!=((word>>shift)&15) ||
			   nibble_get_variable(changed,field)!=(value&15) ||
			   (changed&~mask)!=(word&~mask)) abort();
			field_cases++;
		}
		u64 n=(word>>8)&15;
		if(nibble_get_fixed(word)!=n || nibble_nonzero_fixed(word)!=!!n ||
		   nibble_replace_fixed(word,value)!=nibble_replace_variable(word,2,value) ||
		   nibble_increment_wrap_fixed(word)!=nibble_replace_fixed(word,(n+1)&15) ||
		   nibble_increment_saturate_fixed(word)!=nibble_replace_fixed(word,n<15?n+1:n)) abort();
		field_cases++;
		if(lanes_increment_saturate_swar(word)!=lanes_increment_saturate_scalar(word) ||
		   lanes_increment_saturate_swar(word)!=lanes_increment_saturate_loop(word)) abort();
		swar_cases++;
		u8 p[6]; for(u32 j=0;j<6;j++) p[j]=(u8)random64();
		u64 expected=mix(p[0]&15,p[1]&15,p[2]&15,p[3]&15,p[4]&15,p[5]&15,scalar_plain(value));
		if(six_unpacked_plain(p,value)!=expected || six_unpacked_fast(p,value)!=expected ||
		   six_packed_plain(p,value)!=expected || six_packed_opaque(p,value)!=expected ||
		   six_packed_fast(p,value)!=expected) abort();
		call_cases++;
	}
	for(u64 n=0;n<16;n++) {
		u64 word=n*0x1111111111111111ULL;
		if(lanes_increment_saturate_swar(word)!=lanes_increment_saturate_scalar(word) ||
		   lanes_increment_saturate_swar(word)!=lanes_increment_saturate_loop(word)) abort();
		swar_cases++;
	}
	printf("{\"field_cases\":%llu,\"call_input_cases\":%llu,\"swar_cases\":%llu,\"mismatches\":0,\"performance_measured\":false}\n",field_cases,call_cases,swar_cases);
}
#endif
