#include <stdio.h>

#include "../../check/common/check_common.h"
#include "misc.h"




/* 24 void set_dbg_level(unsigned int level);
 25 unsigned int get_dbg_level(void);
 26 int str_printf(char **sbuf, char *fmt, ...);
 27 size_t mem_append(unsigned char **buf, size_t *blen, const unsigned char *data, size_t dlen);
 28 void ptr_chain_free(void *buf);
 29 void * ptr_chain_add(void *buf, const void *addr);
 30 char *get_chr_date(time_t time, int local);
 31 unsigned char * base64_decode(const char *buf, size_t len, size_t *outlen);
 32 char * base64_encode(const unsigned char *buf, size_t len);
 33 void dump_buf(const unsigned char *buf, size_t len, int all_hex);
 34 void dump_buf_outer(const unsigned char *buf, size_t len, size_t nouter, int all_hex);
 35 void dbgprint(unsigned int dbglevel, const char *fmt, ...);
 36 int compute_sha_hash(size_t nbits, const unsigned char *buf, size_t blen, unsigned char *outbuf);
 37 RSA * decode_rsa_pubkey(unsigned char *data, size_t dlen);
 38 unsigned char *encode_rsa_pubkey(RSA *pubkey, size_t *enclen);
 39 int get_x509_cert_sha_hash(X509 *cert, size_t nbits, unsigned char *out); */


START_TEST (check_debug_level)
{
	unsigned int i;

	for (i = 0; i < 100; i++) {
		set_dbg_level(i);
		ck_assert_uint_eq(i, get_dbg_level());
	}
}
END_TEST

START_TEST(check_base64_macros)
{
	ck_assert_uint_eq(0, B64_ENCODED_LEN(0));
	ck_assert_uint_eq(4, B64_ENCODED_LEN(1));
	ck_assert_uint_eq(4, B64_ENCODED_LEN(2));
	ck_assert_uint_eq(4, B64_ENCODED_LEN(3));
	ck_assert_uint_eq(40, B64_ENCODED_LEN(30));
	ck_assert_uint_eq(44, B64_ENCODED_LEN(31));
	ck_assert_uint_eq(40, B64_ENCODED_LEN(10 + 10 + 10));

	ck_assert_uint_eq(0, BASE64_DECODED_LEN(0));
	ck_assert_uint_eq(1, BASE64_DECODED_LEN(2));
	ck_assert_uint_eq(2, BASE64_DECODED_LEN(3));
	ck_assert_uint_eq(3, BASE64_DECODED_LEN(4));
	ck_assert_uint_eq(57, BASE64_DECODED_LEN(76));
	ck_assert_uint_eq(30 + 30 + 30, BASE64_DECODED_LEN(40 + 40 + 40));
}
END_TEST


Suite * suite_check_misc(void) {

	Suite *s;
	TCase *tc;

	s = suite_create("misc");
	testcase(s, tc, "Debug Level Check", check_debug_level);
	testcase(s, tc, "Base64 Macros", check_base64_macros);

	return s;
}
