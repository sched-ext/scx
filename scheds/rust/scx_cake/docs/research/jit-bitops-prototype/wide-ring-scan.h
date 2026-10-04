/* SPDX-License-Identifier: GPL-2.0 */
/* Research body: callers supply types, read_word(), try_cpu(), ctz(), STEP(). */
#ifndef CAKE_WIDE_RING_SCAN_H
#define CAKE_WIDE_RING_SCAN_H

static __attribute__((always_inline)) inline int ring_linear(u32 cpu, u32 nr)
{
	u32 cw = (u32)-1;
	u64 word = 0;

	for (u32 i = 1; i < 1024; i++) {
		u32 idx = cpu + i, wi;

		if (i >= nr)
			break;
		STEP();
		if (idx >= nr)
			idx -= nr;
		wi = (idx >> 6) & 15;
		if (wi != cw) {
			cw = wi;
			word = read_word(wi);
		}
		if (!(word & (1ULL << (idx & 63))))
			continue;
		if (try_cpu(idx))
			return 1;
	}
	return 0;
}

static __attribute__((always_inline)) inline int ring_ctz_skip(u32 cpu, u32 nr)
{
	u32 cw = (u32)-1, distance = 1;
	u64 word = 0;

	for (u32 i = 0; i < 1024; i++) {
		u32 idx = cpu + distance, end, width, wi, skip;
		u64 pending;

		if (distance >= nr)
			break;
		STEP();
		if (idx >= nr)
			idx -= nr;
		wi = (idx >> 6) & 15;
		if (wi != cw) {
			cw = wi;
			word = read_word(wi);
		}
		end = (idx | 63) + 1;
		if (end > nr)
			end = nr;
		if (idx < cpu && end > cpu)
			end = cpu;
		width = end - idx;
		pending = word >> (idx & 63);
		if (width < 64)
			pending &= (1ULL << width) - 1;
		if (!pending) {
			distance += width;
			continue;
		}
		skip = ctz(pending) & 63;
		distance += skip + 1;
		if (try_cpu(idx + skip))
			return 1;
	}
	return 0;
}

#endif
