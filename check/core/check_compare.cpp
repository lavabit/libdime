extern "C" {
#include "dime/core/magma.h"
}
#include "gtest/gtest.h"

static stringer_t *mkstringer(const char *s) {

	stringer_t *st = st_import(s, strlen(s) + 1);
	EXPECT_TRUE(NULL != st);
	return st;
}

TEST(DIME, test_st_cmp_ci_ends)
{
	stringer_t *empty = mkstringer("");
	stringer_t *whatever = mkstringer("whatever");
	stringer_t *whatever_uc = mkstringer("WHATEVER");

	ASSERT_EQ(0, st_cmp_ci_ends(empty, empty));
	ASSERT_LT(st_cmp_ci_ends(empty, whatever), 0);
	ASSERT_EQ(0, st_cmp_ci_ends(whatever, empty)); /*- not symmetric */
	ASSERT_EQ(0, st_cmp_ci_ends(whatever, whatever_uc));

	st_free(empty);
	st_free(whatever);
	st_free(whatever_uc);
}

// int_t st_cmp_cs_ends(stringer_t *s, stringer_t *ends);
TEST(DIME, DISABLED_test_st_cmp_cs_ends)
{
}

// int_t mm_cmp_ci_eq(void *a, void *b, size_t len);
TEST(DIME, DISABLED_test_mm_cmp_ci_eq)
{
}

// int_t mm_cmp_cs_eq(void *a, void *b, size_t len);
TEST(DIME, DISABLED_test_mm_cmp_cs_eq)
{
}

// int_t st_cmp_ci_eq(stringer_t *a, stringer_t *b);
TEST(DIME, DISABLED_test_st_cmp_ci_eq)
{
}

// int_t st_cmp_cs_eq(stringer_t *a, stringer_t *b);
TEST(DIME, DISABLED_test_st_cmp_cs_eq)
{
}

// bool_t st_search_ci(stringer_t *haystack, stringer_t *needle, size_t *location);
TEST(DIME, DISABLED_test_st_search_ci)
{
}

// bool_t st_search_cs(stringer_t *haystack, stringer_t *needle, size_t *location);
TEST(DIME, DISABLED_test_st_search_cs)
{
}

// bool_t st_search_chr(stringer_t *haystack, chr_t needle, size_t *location);
TEST(DIME, DISABLED_test_st_search_chr)
{
}

// int_t st_cmp_ci_starts(stringer_t *s, stringer_t *starts);
TEST(DIME, DISABLED_test_st_cmp_ci_starts)
{
}

// int_t st_cmp_cs_starts(stringer_t *s, stringer_t *starts);
TEST(DIME, DISABLED_test_st_cmp_cs_starts)
{
}
