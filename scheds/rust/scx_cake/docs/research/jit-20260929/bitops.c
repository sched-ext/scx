/* Standalone code-generation probes, never loaded or attached to the kernel. */
typedef unsigned long long u64;

__attribute__((noinline)) u64 ctz_nonzero(u64 x)
{
	return __builtin_ctzll(x);
}

__attribute__((noinline)) u64 ctz_defined(u64 x)
{
	return x ? __builtin_ctzll(x) : 64;
}

__attribute__((noinline)) u64 popcount(u64 x)
{
	return __builtin_popcountll(x);
}

__attribute__((noinline)) u64 clz_defined(u64 x)
{
	return x ? __builtin_clzll(x) : 64;
}

__attribute__((noinline)) u64 lowest_bit(u64 x)
{
	return x & -x;
}

__attribute__((noinline)) u64 rotate(u64 x, u64 n)
{
	n &= 63;
	return (x << n) | (x >> ((64 - n) & 63));
}
