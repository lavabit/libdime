#include <core/magma.h>
#include "checks.h"

START_TEST (test_chr_alphanumeric)
{
	ck_assert(chr_alphanumeric('X'));
	ck_assert(chr_alphanumeric('x'));
	ck_assert(chr_alphanumeric('0'));
	ck_assert(chr_alphanumeric('9'));
	ck_assert(!chr_alphanumeric(' '));
	ck_assert(!chr_alphanumeric('\t'));
	ck_assert(!chr_alphanumeric('\n'));
}
END_TEST

START_TEST (test_chr_ascii)
{
}
END_TEST

START_TEST (test_chr_blank)
{
}
END_TEST

START_TEST (test_chr_lower)
{
}
END_TEST

START_TEST (test_chr_numeric)
{
}
END_TEST

START_TEST (test_chr_printable)
{
}
END_TEST

START_TEST (test_chr_punctuation)
{
}
END_TEST

START_TEST (test_chr_upper)
{
}
END_TEST

START_TEST (test_chr_whitespace)
{
}
END_TEST

START_TEST (test_chr_is_class)
{
}
END_TEST

Suite *suite_check_classify(void) {

	Suite *s = suite_create("Classify");
	suite_add_testfunc(s, test_chr_alphanumeric);
	suite_add_testfunc(s, test_chr_ascii);
	suite_add_testfunc(s, test_chr_blank);
	suite_add_testfunc(s, test_chr_lower);
	suite_add_testfunc(s, test_chr_numeric);
	suite_add_testfunc(s, test_chr_printable);
	suite_add_testfunc(s, test_chr_punctuation);
	suite_add_testfunc(s, test_chr_upper);
	suite_add_testfunc(s, test_chr_whitespace);
	suite_add_testfunc(s, test_chr_is_class);
	return s;
}
