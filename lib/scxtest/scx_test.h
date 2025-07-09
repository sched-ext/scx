#pragma once

#ifdef TEST

#ifndef __weak
#define __weak __attribute__((weak))
#endif /* __weak */

#include "overrides.h"

#include <setjmp.h>

extern __thread jmp_buf scxtest_bail_jmp;

void __fail_assert(const char *condition, const char *file, int line) __attribute__((noreturn));

#define scx_test_assert(condition) \
	do { \
		if (!(condition)) \
			__fail_assert(#condition, __FILE__, __LINE__); \
	} while (0)

#define SCX_TEST(name) \
	static __always_inline void name##_scxtest_impl(void);	\
	__attribute__((used))					\
	__attribute__((section(".scxtest")))			\
	int name(void) {					\
		int rc = setjmp(scxtest_bail_jmp);		\
		if (!rc)					\
			name##_scxtest_impl();			\
		return rc;					\
	}							\
	static __always_inline void name##_scxtest_impl(void)

#endif /* TEST */
