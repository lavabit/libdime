#include <core/magma.h>
#include "checks.h"

static stringer_t *mkstringer(const char *s) {

	stringer_t *st = st_import(s, strlen(s) + 1);
	ck_assert_ptr_ne(NULL, st);
	return st;
}

START_TEST(test_st_cmp_ci_ends)
{
	stringer_t *empty = mkstringer("");
	stringer_t *whatever = mkstringer("whatever");
	stringer_t *whatever_uc = mkstringer("WHATEVER");

	ck_assert_int_eq(st_cmp_ci_ends(empty, empty), 0);
	ck_assert_int_lt(st_cmp_ci_ends(empty, whatever), 0);
	ck_assert_int_eq(st_cmp_ci_ends(whatever, empty), 0); /*- not symmetric */
	ck_assert_int_eq(st_cmp_ci_ends(whatever, whatever_uc), 0);

	st_free(empty);
	st_free(whatever);
	st_free(whatever_uc);
}
END_TEST

// int_t st_cmp_cs_ends(stringer_t *s, stringer_t *ends);
START_TEST(test_st_cmp_cs_ends)
{
}
END_TEST

// int_t mm_cmp_ci_eq(void *a, void *b, size_t len);
START_TEST(test_mm_cmp_ci_eq)
{
}
END_TEST

// int_t mm_cmp_cs_eq(void *a, void *b, size_t len);
START_TEST(test_mm_cmp_cs_eq)
{
}
END_TEST

// int_t st_cmp_ci_eq(stringer_t *a, stringer_t *b);
START_TEST(test_st_cmp_ci_eq)
{
}
END_TEST

// int_t st_cmp_cs_eq(stringer_t *a, stringer_t *b);
START_TEST(test_st_cmp_cs_eq)
{
}
END_TEST

// bool_t st_search_ci(stringer_t *haystack, stringer_t *needle, size_t *location);
START_TEST(test_st_search_ci)
{
}
END_TEST

// bool_t st_search_cs(stringer_t *haystack, stringer_t *needle, size_t *location);
START_TEST(test_st_search_cs)
{
}
END_TEST

// bool_t st_search_chr(stringer_t *haystack, chr_t needle, size_t *location);
START_TEST(test_st_search_chr)
{
}
END_TEST

// int_t st_cmp_ci_starts(stringer_t *s, stringer_t *starts);
START_TEST(test_st_cmp_ci_starts)
{
}
END_TEST

// int_t st_cmp_cs_starts(stringer_t *s, stringer_t *starts);
START_TEST(test_st_cmp_cs_starts)
{
}
END_TEST

Suite *suite_check_compare(void) {

	Suite *s = suite_create("Compare");
	suite_add_testfunc(s, test_st_cmp_ci_ends);
	suite_add_testfunc(s, test_st_cmp_cs_ends);
	suite_add_testfunc(s, test_mm_cmp_ci_eq);
	suite_add_testfunc(s, test_mm_cmp_cs_eq);
	suite_add_testfunc(s, test_st_cmp_ci_eq);
	suite_add_testfunc(s, test_st_cmp_cs_eq);
	suite_add_testfunc(s, test_st_search_ci);
	suite_add_testfunc(s, test_st_search_cs);
	suite_add_testfunc(s, test_st_search_chr);
	suite_add_testfunc(s, test_st_cmp_ci_starts);
	suite_add_testfunc(s, test_st_cmp_cs_starts);
	return s;
}
