#include <stdlib.h>
#include "common/checks.h"
#include "core/checks.h"
#include "dime/checks.h"
#include "dmessage/checks.h"
#include "signet/checks.h"

int main(void) {
	// common
	SRunner *sr = srunner_create(suite_check_errorapi());
	srunner_add_suite(sr, suite_check_misc());
	srunner_add_suite(sr, suite_check_crypto());
	srunner_add_suite(sr, suite_check_error());

	// core
	srunner_add_suite(sr, suite_check_classify());
	srunner_add_suite(sr, suite_check_compare());
	srunner_add_suite(sr, suite_check_memory());
	srunner_add_suite(sr, suite_check_host_folder());
	srunner_add_suite(sr, suite_check_hash());
	srunner_add_suite(sr, suite_check_mail_counters());

	// dime
	srunner_add_suite(sr, suite_check_ssl());

	// dmessage
	srunner_add_suite(sr, suite_check_dmsg());
	srunner_add_suite(sr, suite_check_parser());

	// signet
	srunner_add_suite(sr, suite_check_keys());
	srunner_add_suite(sr, suite_check_signet());

	// publish test results in TAP format
	srunner_set_tap(sr, "test_results.tap");

	srunner_run_all(sr, CK_ENV);
	int nr_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return nr_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
