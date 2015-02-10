#include <check.h>

#define RUN_TEST_CASE_TIMEOUT	100


#define testcase(s, tc, name, func) tcase_add_test((tc = tcase_create(name)), func); tcase_set_timeout(tc, RUN_TEST_CASE_TIMEOUT); suite_add_tcase(s, tc)


unsigned char *gen_random_data(size_t minlen, size_t maxlen, size_t *outlen);
