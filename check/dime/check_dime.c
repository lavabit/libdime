#include <stdlib.h>
#include "../check-compat.h"
#include "check_ssl.h"

int main(void) {

	SRunner *sr = srunner_create(suite_check_ssl());

	srunner_run_all(sr, CK_ENV);
	int nr_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return nr_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
