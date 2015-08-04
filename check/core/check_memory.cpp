extern "C" {
#include "dime/core/magma.h"
}
#include "gtest/gtest.h"

// size_t align(size_t alignment, size_t len);
TEST(DIME, test_align) {

    ASSERT_EQ(0x01U, align(0x01, 0x01));
    ASSERT_EQ(0x02U, align(0x02, 0x01));
    ASSERT_EQ(0x04U, align(0x04, 0x01));
    ASSERT_EQ(0x08U, align(0x08, 0x01));
    ASSERT_EQ(0x10U, align(0x10, 0x01));

    ASSERT_EQ(0x00U, align(0x08, 0x00));
    ASSERT_EQ(0x08U, align(0x08, 0x01));
    ASSERT_EQ(0x08U, align(0x08, 0x07));
    ASSERT_EQ(0x08U, align(0x08, 0x08));
}

// uint_t bits_count(uint64_t value);
TEST(DIME, test_bits_count) {

    ASSERT_EQ(0U, bits_count(0x0000000000000000ULL));
    ASSERT_EQ(1U, bits_count(0x0000000000000001ULL));
    ASSERT_EQ(1U, bits_count(0x8000000000000000ULL));
    ASSERT_EQ(32U, bits_count(0x5555555555555555ULL));
    ASSERT_EQ(64U, bits_count(-1));
}
