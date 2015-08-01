extern "C" {
#include "dime/core/magma.h"
}
#include "gtest/gtest.h"

TEST(DIME, test_mail_header_end) {
	ASSERT_EQ(14U, mail_header_end(CONSTANT("From: author\n\nbody")));
	ASSERT_EQ(15U, mail_header_end(CONSTANT("From: author\n\r\nbody")));
	ASSERT_EQ(20U, mail_header_end(CONSTANT("From: author\n\r\r\nbody")));
	ASSERT_EQ(18U, mail_header_end(CONSTANT("From: author\r\rbody")));
}
