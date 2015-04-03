#ifndef DIME_CHECK_COMMON_H
#define DIME_CHECK_COMMON_H

#include "../check-dime.h"

#define RUN_TEST_CASE_TIMEOUT	100

#define N_SERIALIZATION_TESTS	20
#define N_SIGNATURE_TIER_TESTS	5

Suite * suite_check_crypto(void);
Suite * suite_check_error(void);
Suite * suite_check_misc(void);

unsigned char *gen_random_data(size_t minlen, size_t maxlen, size_t *outlen);

#endif
