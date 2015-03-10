#include <stdlib.h>
#include "checks.h"

void suite_add_test(Suite *s, const char *name, TFun func) {

	TCase *tc = tcase_create(name);
	tcase_add_test(tc, func);
	suite_add_tcase(s, tc);
}

int main(void) {

	SRunner *sr = srunner_create(suite_check_classify());
	srunner_add_suite(sr, suite_check_compare());
	srunner_add_suite(sr, suite_check_memory());

	srunner_run_all(sr, CK_ENV);
	int nr_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return nr_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
