extern "C" {
#include <core/magma.h>
}
#include "gtest/gtest.h"

TEST(DIME, test_chr_alphanumeric)
{
	ASSERT_TRUE(chr_alphanumeric('X'));
	ASSERT_TRUE(chr_alphanumeric('x'));
	ASSERT_TRUE(chr_alphanumeric('0'));
	ASSERT_TRUE(chr_alphanumeric('9'));
	ASSERT_TRUE(!chr_alphanumeric(' '));
	ASSERT_TRUE(!chr_alphanumeric('\t'));
	ASSERT_TRUE(!chr_alphanumeric('\n'));
}

TEST(DIME, DISABLED_test_chr_ascii)
{
}

TEST(DIME, DISABLED_test_chr_blank)
{
}

TEST(DIME, DISABLED_test_chr_lower)
{
}

TEST(DIME, DISABLED_test_chr_numeric)
{
}

TEST(DIME, DISABLED_test_chr_printable)
{
}

TEST(DIME, DISABLED_test_chr_punctuation)
{
}

TEST(DIME, DISABLED_test_chr_upper)
{
}

TEST(DIME, DISABLED_test_chr_whitespace)
{
}

TEST(DIME, DISABLED_test_chr_is_class)
{
}
