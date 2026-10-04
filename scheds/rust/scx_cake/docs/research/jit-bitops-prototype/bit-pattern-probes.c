/* SPDX-License-Identifier: GPL-2.0 */
typedef unsigned long long u64;

u64 clear_lowest(u64 word)
{
	return word & (word - 1);
}

u64 exclude_mask(u64 word, u64 excluded)
{
	return word & ~excluded;
}

u64 rotate_ring(u64 word, unsigned int cpu)
{
	unsigned int shift = (cpu + 1) & 63;

	return (word >> shift) | (word << ((64 - shift) & 63));
}
