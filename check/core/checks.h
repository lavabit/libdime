#include "../check-compat.h"

extern void suite_add_test(Suite *s, const char *name, TFun func);
#define suite_add_testfunc(s, func) \
	suite_add_test(s, #func, func)

extern Suite *suite_check_classify(void);
extern Suite *suite_check_compare(void);
extern Suite *suite_check_memory(void);
