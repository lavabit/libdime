#include <core/magma.h>
#include "checks.h"

/* Reference implementation from RFC 1950 */
static uint32_t rfc1950_adler32(const uchr_t *buf, size_t len) {
	uint32_t BASE = 65221;
	uint32_t adler = 1;
	uint32_t s1 = adler & 0xffff;
	uint32_t s2 = (adler >> 16) & 0xffff;

	for (size_t n = 0; n < len; n++) {
		s1 = (s1 + buf[n]) % BASE;
		s2 = (s2 + s1) % BASE;
	}
	return (s2 << 16) + s1;
}

static void ck_assert_adler(const void *buf, size_t buflen) {
	ck_assert_int_eq(rfc1950_adler32(buf, buflen), hash_adler32((uchr_t *)buf, buflen));
}

START_TEST(test_hash_adler) {
	unsigned char buf[] = { 0xfe, 0xff };

	ck_assert_adler(buf, 0);
	ck_assert_adler(buf, 1);
	ck_assert_adler(buf + 1, 1);
	ck_assert_adler(buf, 2);
}
END_TEST

Suite *suite_check_hash(void) {

	Suite *s = suite_create("hash");
	suite_add_testfunc(s, test_hash_adler);
	return s;
}
