#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include <openssl/rand.h>
#include <common/error.h>
#include "checks.h"

#ifdef ERROR_API_FINISHED
/** @brief Compute positive sum of two non-negative ints or raise errinfo error.
 * @param a first addend
 * @param b second addend
 * @return the sum if both addends and the sum are positive; else return -1 and
 * raise errinfo error.  */
int
calc_nonnegative_sum(int a, int b)
{
	/* cleanup error stack if needed */
	BEGIN_PUBLIC_FUNC
	if (a < 0)
		RET_INT_ERROR_EX(CMN_ERRCODE_BADARG, "`a' is negative");
	if (b < 0)
		RET_INT_ERROR_EX(CMN_ERRCODE_BADARG, "'b' is negative");
	const int res = a + b;
	if (res < 0)
		RET_INT_ERROR(CMN_ERRCODE_INTOVERFLOW);
	return res;
}

START_TEST(errinfo_test)
{
	/* static checks of error codes and texts */
	ck_assert_int_ne(CMN_ERRCODE_BADARG, 0);
	ck_assert_int_ne(CMN_ERRCODE_INTOVERFLOW, 0);
	ck_assert_str_eq(get_error_string(0), "no error");
	ck_assert_str_eq(get_error_string(CMN_ERRCODE_BADARG), "invalid argument");
	ck_assert_str_eq(get_error_string(CMN_ERRCODE_INTOVERFLOW), "int overflow");

	/* "no error" check */
	ck_assert_int_eq(calc_nonnegative_sum(1, 2), 3);
	ck_assert_int_eq(get_last_error_code(), 0);
	ck_assert_int_eq(get_first_error(), 0);
	ck_assert_int_eq(pop_last_error(), 0);

	/* "bad argument" error checks */
	ck_assert_int_eq(calc_nonnegative_sum(-1, 2), -1);
	ck_assert_int_eq(get_last_error_code(), CMN_ERRCODE_BADARG);
	ck_assert_int_ne(get_first_error(), 0);
	ck_assert_int_eq(get_error_code(get_first_error()), CMN_ERRCODE_BADARG);
	ck_assert_str_eq(get_error_msg(get_first_error()), "`a' is negative");

	ck_assert_int_eq(calc_nonnegative_sum(-1, -2), -1);
	ck_assert_int_eq(get_last_error_code(), CMN_ERRCODE_BADARG);
	ck_assert_int_ne(get_first_error(), 0);
	ck_assert_int_eq(get_error_code(get_first_error()), CMN_ERRCODE_BADARG);
	ck_assert_str_eq(get_error_msg(get_first_error()), "`a' is negative");

	ck_assert_int_eq(calc_nonnegative_sum(1, -2), -1);
	ck_assert_int_eq(get_last_error_code(), CMN_ERRCODE_BADARG);
	ck_assert_int_ne(get_first_error(), 0);
	ck_assert_int_eq(get_error_code(get_first_error()), CMN_ERRCODE_BADARG);
	ck_assert_str_eq(get_error_msg(get_first_error()), "`b' is negative");

	/* int overflow checks */
	ck_assert_int_eq(calc_nonnegative_sum(INT_MAX, INT_MAX), -1);
	ck_assert_int_eq(get_last_error_code(), CMN_ERRCODE_INTOVERFLOW);
	ck_assert_int_ne(get_first_error(), 0);
	ck_assert_int_eq(get_error_code(get_first_error()), CMN_ERRCODE_INTOVERFLOW);
	ck_assert(get_error_msg(get_first_error()) == NULL);
}
END_TEST
#endif /* ERROR_API_FINISHED */

Suite *suite_check_errorapi(void) {

	Suite *s = suite_create("error-api");
#ifdef ERROR_API_FINISHED
	suite_add_testfunc(s, errinfo_test);
#endif /* ERROR_API_FINISHED */

	return s;
}
