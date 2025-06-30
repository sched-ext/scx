#include <stdio.h>
#include <stdlib.h>

#include "scx_test.h"

void __fail_assert(const char *condition, const char *file, int line)
{
	fprintf(stderr, "Assertion failed: %s, file %s, line %d\n", condition, file, line);
	abort();
}
