/* DIME-specific extensions to the check library */

#ifndef CHECK_DIME_H
#define CHECK_DIME_H

#include "check-compat.h"

static inline void suite_add_test(Suite *s, const char *name, TFun func) {

	TCase *tc = tcase_create(name);
	tcase_add_test(tc, func);
	suite_add_tcase(s, tc);
}
#define suite_add_testfunc(s, func) \
	suite_add_test(s, #func, func)

#endif
