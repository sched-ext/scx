#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>

#include "selftest.h"

static
int scx_selftest_bitmap_clear()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_bitmap_and()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_bitmap_empty()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_bitmap_copy()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_bitmap_from_bpf()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_bitmap_subset()
{
	return -EOPNOTSUPP;
}

static
int scx_selftest_bitmap_intersects()
{
	return -EOPNOTSUPP;
}

#define SCX_BITMAP_SELFTEST(suffix) SCX_SELFTEST(scx_selftest_bitmap_ ## suffix)

__weak
int scx_selftest_bitmap(void)
{
	SCX_BITMAP_SELFTEST(clear);
	SCX_BITMAP_SELFTEST(and);
	SCX_BITMAP_SELFTEST(empty);
	SCX_BITMAP_SELFTEST(copy);
	SCX_BITMAP_SELFTEST(from_bpf);
	SCX_BITMAP_SELFTEST(subset);
	SCX_BITMAP_SELFTEST(intersects);

	return 0;
}
