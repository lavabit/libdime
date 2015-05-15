#include <stdlib.h>
#include "checks.h"

int main(void) {

	SRunner *sr = srunner_create(suite_check_keys());
	srunner_add_suite(sr, suite_check_signet());

	srunner_run_all(sr, CK_ENV);
	int nr_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return nr_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
