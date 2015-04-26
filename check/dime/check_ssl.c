#include <signet-resolver/signet-ssl.h>
#include "checks.h"

START_TEST(test_domain_wildcard_check) {

	ck_assert_int_eq(1, _domain_wildcard_check("www.google.com", "www.google.com"));
	ck_assert_int_eq(1, _domain_wildcard_check("*.google.com", "abc.google.com"));
	ck_assert_int_eq(1, _domain_wildcard_check("*.google.com", "abc.def.google.com"));
	ck_assert_int_eq(0, _domain_wildcard_check("*.google.com", "google.com"));
}
END_TEST

Suite *suite_check_ssl(void) {
	Suite *s = suite_create("dime/ssl");
	suite_add_testfunc(s, test_domain_wildcard_check);
	return s;
}
