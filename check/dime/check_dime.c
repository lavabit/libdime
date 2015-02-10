#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include <check.h>

#include "../../check/dime/check_ssl.h"


unsigned char *gen_random_data(size_t minlen, size_t maxlen, size_t *outlen) {

	unsigned char *result;
	static int seeded = 0;
	int rval;
	size_t rlen, i;

	if (!seeded) {
		srand(time(NULL) ^ getpid());
		seeded = 1;
	}

	rval = rand();

	if (minlen == maxlen) {
		rlen = minlen;
	} else {
		rlen = minlen + (rval % (maxlen - minlen + 1));
	}

	if (!(result = malloc(rlen))) {
		perror("malloc");
		return NULL;
	}

	*outlen = rlen;
	memset(result, 0, rlen);

	for (i = 0; i < rlen; i++) {
		result[i] = rand() % 256;
	}

	return result;
}


START_TEST (test_name)
{
	printf("Testing 1!\n");
	printf("Testing 2!\n");
}
END_TEST


Suite * test_suite(void) {

	Suite *s;
	TCase *tcase;

	s = suite_create("test");
	tcase = tcase_create("core");

	tcase_add_test(tcase, test_name);
	suite_add_tcase(s, tcase);

	return s;
}


int main(int argc, char *argv[]) {

	SRunner *sr;
//	int nr_failed;

	sr = srunner_create(test_suite());
	srunner_add_suite(sr, suite_check_ssl());

	fprintf(stderr, "Running tests ...\n");

	srunner_run_all(sr, CK_SILENT);
	//srunner_run_all(sr, CK_NORMAL);
//	nr_failed = srunner_ntests_failed(sr);
	// CK_VERBOSE
	srunner_print(sr, CK_VERBOSE);
	srunner_free(sr);

	fprintf(stderr, "Finished.\n");

	//ck_assert
	//ck_assert_msg

	return 0;
}
