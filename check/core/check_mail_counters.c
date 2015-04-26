#include <core/magma.h>
#include "checks.h"

START_TEST(test_mail_header_end) {
	ck_assert_int_eq(14, mail_header_end(CONSTANT("From: author\n\nbody")));
	ck_assert_int_eq(15, mail_header_end(CONSTANT("From: author\n\r\nbody")));
	ck_assert_int_eq(20, mail_header_end(CONSTANT("From: author\n\r\r\nbody")));
	ck_assert_int_eq(18, mail_header_end(CONSTANT("From: author\r\rbody")));
}
END_TEST

Suite *suite_check_mail_counters(void) {

	Suite *s = suite_create("mail/counters");
	suite_add_testfunc(s, test_mail_header_end);
	return s;
}
