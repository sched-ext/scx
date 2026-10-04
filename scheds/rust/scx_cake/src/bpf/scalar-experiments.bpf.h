/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CAKE_SCALAR_EXPERIMENTS_BPF_H
#define __CAKE_SCALAR_EXPERIMENTS_BPF_H

static __always_inline u64 cake_ring_rotate(u64 marks, u32 cpu)
{
	u32 shift = (cpu + 1) & 63;

	return (marks >> shift) | (marks << ((64 - shift) & 63));
}

static __always_inline u32 cake_ring_next(u64 rotated, u32 cpu)
{
	return (cake_ctz64(rotated) + cpu + 1) & 63;
}

static __always_inline u32 cake_band_native(u64 ns, u32 shift, u32 bands)
{
	u32 band = 63 - cake_clz64((ns >> shift) | 1);

	return band < bands ? band : bands - 1;
}

#endif /* __CAKE_SCALAR_EXPERIMENTS_BPF_H */
