#include <core/magma.h>
#include "checks.h"

// size_t align(size_t alignment, size_t len);
START_TEST(test_align) {

	ck_assert_uint_eq(0x01, align(0x01, 0x01));
	ck_assert_uint_eq(0x02, align(0x02, 0x01));
	ck_assert_uint_eq(0x04, align(0x04, 0x01));
	ck_assert_uint_eq(0x08, align(0x08, 0x01));
	ck_assert_uint_eq(0x10, align(0x10, 0x01));

	ck_assert_uint_eq(0x00, align(0x08, 0x00));
	ck_assert_uint_eq(0x08, align(0x08, 0x01));
	ck_assert_uint_eq(0x08, align(0x08, 0x07));
	ck_assert_uint_eq(0x08, align(0x08, 0x08));
}
END_TEST

// uint_t bits_count(uint64_t value);
START_TEST(test_bits_count) {

	ck_assert_uint_eq(0, bits_count(0x0000000000000000ULL));
	ck_assert_uint_eq(1, bits_count(0x0000000000000001ULL));
	ck_assert_uint_eq(1, bits_count(0x8000000000000000ULL));
	ck_assert_uint_eq(32, bits_count(0x5555555555555555ULL));
	ck_assert_uint_eq(64, bits_count(-1));
}
END_TEST

Suite *suite_check_memory(void) {

	Suite *s = suite_create("Memory");
	suite_add_testfunc(s, test_align);
	suite_add_testfunc(s, test_bits_count);
	return s;
}
