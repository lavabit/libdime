#include "dmessage/dmsg_parse.h"
#include "checks.h"

START_TEST(check_parser_envelope)
{
	char const
		*usrsgnt1 = "nDjalkzxpqmviqwnrPIOSDFnasdfkadsdfa",
		*orgfp1 = "fasdlk;otrhnvgauisgfa;nmdg;iajgio;ewj;kaji8jetioajwetiewhyenbns",
		*usrsgnt2 = "newtiuanhdgfnaietnnastawetpoajweothqwtyqmvdigta",
		*orgfp2 = "netuiafnmadi9tawejasd'as;djgtai9wejtianmsdgna;sgaklsnqqsdkfathbnvfadsfa";
	dmime_envelope_object_t *envelope = NULL;
	int res;
	stringer_t
		*usrid1 = CONSTANT("abcdeffedcba"),
		*orgid1 = CONSTANT("NKDLASIDFK12d"),
		*usrid2 = CONSTANT("1sdfkasd@fpioasdwq"),
		*orgid2 = CONSTANT("vapsdqwpiorqwrpndkd"),
		*formatted = NULL;

	formatted = dime_prsr_envelope_format(usrid1, orgid1, usrsgnt1, orgfp1, CHUNK_TYPE_ORIGIN);
	ck_assert_msg(formatted != NULL, "Failed to format origin chunk data.\n");

	envelope = dime_prsr_envelope_parse((const unsigned char *)st_data_get(formatted), st_length_get(formatted), CHUNK_TYPE_DESTINATION);
	ck_assert_msg(envelope == NULL, "Was able to parse an origin chunk as a destination.\n");
	_clear_error_stack();

	envelope = dime_prsr_envelope_parse((const unsigned char *)st_data_get(formatted), st_length_get(formatted), CHUNK_TYPE_ORIGIN);
	ck_assert_msg(envelope != NULL, "Was unable to parse an origin chunk.\n");

	res = st_cmp_cs_eq(usrid1, envelope->auth_recp);
	ck_assert_msg(res == 0, "Data was corrupted during formatting and parsing.\n");

	res = st_cmp_cs_eq(orgid1, envelope->dest_orig);
	ck_assert_msg(res == 0, "Data was corrupted during formatting and parsing.\n");

	res = memcmp(usrsgnt1, st_char_get(envelope->auth_recp_fp), strlen(usrsgnt1));
	ck_assert_msg(res == 0, "Data was corrupted during formatting and parsing.\n");

	res = memcmp(orgfp1, st_char_get(envelope->dest_orig_fp), strlen(orgfp1));
	ck_assert_msg(res == 0, "Data was corrupted during formatting and parsing.\n");

	st_free(formatted);
	dime_prsr_envelope_destroy(envelope);

	formatted = dime_prsr_envelope_format(usrid2, orgid2, usrsgnt2, orgfp2, CHUNK_TYPE_DESTINATION);
	ck_assert_msg(formatted != NULL, "Failed to format destination chunk data.\n");

	envelope = dime_prsr_envelope_parse((const unsigned char *)st_data_get(formatted), st_length_get(formatted), CHUNK_TYPE_ORIGIN);
	ck_assert_msg(envelope == NULL, "Was able to parse an destination chunk as a origin.\n");
	_clear_error_stack();

	envelope = dime_prsr_envelope_parse((const unsigned char *)st_data_get(formatted), st_length_get(formatted), CHUNK_TYPE_DESTINATION);
	ck_assert_msg(envelope != NULL, "Was unable to parse an destination chunk.\n");
	
	res = st_cmp_cs_eq(usrid2, envelope->auth_recp);
	ck_assert_msg(res == 0, "Data was corrupted during formatting and parsing.\n");

	res = st_cmp_cs_eq(orgid2, envelope->dest_orig);
	ck_assert_msg(res == 0, "Data was corrupted during formatting and parsing.\n");

	res = memcmp(usrsgnt2, st_char_get(envelope->auth_recp_fp), strlen(usrsgnt2));
	ck_assert_msg(res == 0, "Data was corrupted during formatting and parsing.\n");

	res = memcmp(orgfp2, st_char_get(envelope->dest_orig_fp), strlen(orgfp2));
	ck_assert_msg(res == 0, "Data was corrupted during formatting and parsing.\n");

	st_free(formatted);
	dime_prsr_envelope_destroy(envelope);

	formatted = dime_prsr_envelope_format(usrid2, orgid2, usrsgnt2, orgfp2, CHUNK_TYPE_EPHEMERAL);
	ck_assert_msg(formatted == NULL, "Failed to format destination chunk data.\n");

	fprintf(stderr, "DMIME envelope parsing complete.\n");
}
END_TEST

START_TEST(check_parser_header) {

	dmime_common_headers_t *header1, *header2;
	int res = 0;
	size_t outsize;
	unsigned char *formatted;

	header1 = dime_prsr_headers_create();
	header1->headers[HEADER_TYPE_DATE] = st_import("11:34:12 AM March 12, 2004", 26);
	header1->headers[HEADER_TYPE_TO] = st_import("abc@hello.com", 13);
	header1->headers[HEADER_TYPE_CC] = st_import("a312@goodbye.com", 16);
	header1->headers[HEADER_TYPE_FROM] = st_import("author@authorplace.com", 22);
	header1->headers[HEADER_TYPE_ORGANIZATION] = st_import("Cool people organization", 24);
	header1->headers[HEADER_TYPE_SUBJECT] = st_import("here's stuff", 12);

	formatted = dime_prsr_headers_format(header1, &outsize);
	ck_assert_msg(formatted != NULL, "Failed to format common headers.\n");

	header2 = dime_prsr_headers_parse(formatted, outsize);
	ck_assert_msg(header2 != NULL, "Failed to parse common headers.\n");

	res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_DATE], header2->headers[HEADER_TYPE_DATE]);
	ck_assert_msg(res == 0, "Date header was corrupted.\n");

	res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_TO], header2->headers[HEADER_TYPE_TO]);
	ck_assert_msg(res == 0, "To header was corrupted.\n");

	res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_CC], header2->headers[HEADER_TYPE_CC]);
	ck_assert_msg(res == 0, "CC header was corrupted.\n");

	res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_FROM], header2->headers[HEADER_TYPE_FROM]);
	ck_assert_msg(res == 0, "From header was corrupted.\n");

	res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_ORGANIZATION], header2->headers[HEADER_TYPE_ORGANIZATION]);
	ck_assert_msg(res == 0, "Organization header was corrupted.\n");

	res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_SUBJECT], header2->headers[HEADER_TYPE_SUBJECT]);
	ck_assert_msg(res == 0, "Subject header was corrupted.\n");

	dime_prsr_headers_destroy(header1);
	dime_prsr_headers_destroy(header2);
	free(formatted);

	fprintf(stderr, "DMIME common header parsing complete.\n");
}
END_TEST

Suite *suite_check_parser(void) {

	Suite *s = suite_create("\nDMIME parsing");
	suite_add_test(s, "Envelope parsing", check_parser_envelope);
	suite_add_test(s, "Header parsing", check_parser_header);
	return s;
}
