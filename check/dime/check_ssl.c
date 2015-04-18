#include "../check-compat.h"
#include "check_dime.h"
#include <signet-resolver/signet-ssl.h>
#include "check_ssl.h"

/* void ssl_initialize(void);
 19 void ssl_shutdown(void);
 20 SSL * ssl_starttls(int fd);
 21 SSL * ssl_connect_host(const char *hostname, unsigned short port, int force_family);
 22 void ssl_disconnect(SSL *handle);
 23 int do_x509_validation(X509 *cert, STACK_OF(X509) *chain);
 25 int do_ocsp_validation(SSL *connection, int *fallthrough);
 26 char * get_cert_subject_cn(X509 *cert);
 27
 29 int _validate_self_signed(X509 *cert);
 32 X509_STORE * _get_cert_store(void);
 33 int _verify_certificate_callback(int ok, X509_STORE_CTX *ctx);
 34 int _ocsp_response_callback(SSL *s, void *arg);
 35 void _destroy_ocsp_response_cb(void *record);
 36 char * _get_cache_ocsp_id(X509 *cert, OCSP_CERTID *cid, char *buf, size_t blen);
 37 void _dump_ocsp_response_cb(FILE *fp, void *record, int brief);
 38 void * _deserialize_ocsp_response_cb(void *data, size_t len);
 39 void * _serialize_ocsp_response_cb(void *record, size_t *outlen); */

START_TEST (check_domain_wildcard)
{
	ck_assert_int_eq(1, _domain_wildcard_check("www.google.com", "www.google.com"));
	ck_assert_int_eq(1, _domain_wildcard_check("*.google.com", "abc.google.com"));
	ck_assert_int_eq(1, _domain_wildcard_check("*.google.com", "abc.def.google.com"));
	ck_assert_int_eq(0, _domain_wildcard_check("*.google.com", "google.com"));
}
END_TEST


Suite * suite_check_ssl(void) {

	TCase *tc;

	Suite *s = suite_create("ssl");
	testcase(s, tc, "Domain Wildcard Check", check_domain_wildcard);
	return s;
}
