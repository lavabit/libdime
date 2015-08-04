extern "C" {
#include "dime/core/magma.h"
}
#include "gtest/gtest.h"

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

static void ASSERT_ADLER(uchr_t const *buf, size_t buflen) {
    ASSERT_EQ(rfc1950_adler32(buf, buflen), hash_adler32(buf, buflen));
}

TEST(DIME, test_hash_adler) {
    unsigned char buf[] = { 0xfe, 0xff };

    ASSERT_ADLER(buf, 0);
    ASSERT_ADLER(buf, 1);
    ASSERT_ADLER(buf + 1, 1);
    ASSERT_ADLER(buf, 2);
}
