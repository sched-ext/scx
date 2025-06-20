#pragma once

#ifdef TEST

#ifndef __weak
#define __weak __attribute__((weak))
#endif /* __weak */

#include "overrides.h"

void __fail_assert(const char *condition, const char *file, int line) __attribute__((noreturn));

#define scx_test_assert(condition) \
	do { \
		if (!(condition)) \
			__fail_assert(#condition, __FILE__, __LINE__); \
	} while (0)

#endif /* TEST */
