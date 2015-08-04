extern "C" {
#include "dime/dmessage/parse.h"
}
#include "gtest/gtest.h"

TEST(DIME, check_parser_envelope)
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
    ASSERT_TRUE(formatted != NULL) << "Failed to format origin chunk data.";

    envelope = dime_prsr_envelope_parse((const unsigned char *)st_data_get(formatted), st_length_get(formatted), CHUNK_TYPE_DESTINATION);
    ASSERT_TRUE(envelope == NULL) << "Was able to parse an origin chunk as a destination.";

    envelope = dime_prsr_envelope_parse((const unsigned char *)st_data_get(formatted), st_length_get(formatted), CHUNK_TYPE_ORIGIN);
    ASSERT_TRUE(envelope != NULL) << "Was unable to parse an origin chunk.";

    res = st_cmp_cs_eq(usrid1, envelope->auth_recp);
    ASSERT_EQ(0, res) << "Data was corrupted during formatting and parsing.";

    res = st_cmp_cs_eq(orgid1, envelope->dest_orig);
    ASSERT_EQ(0, res) << "Data was corrupted during formatting and parsing.";

    res = memcmp(usrsgnt1, st_char_get(envelope->auth_recp_fp), strlen(usrsgnt1));
    ASSERT_EQ(0, res) << "Data was corrupted during formatting and parsing.";

    res = memcmp(orgfp1, st_char_get(envelope->dest_orig_fp), strlen(orgfp1));
    ASSERT_EQ(0, res) << "Data was corrupted during formatting and parsing.";

    st_free(formatted);
    dime_prsr_envelope_destroy(envelope);

    formatted = dime_prsr_envelope_format(usrid2, orgid2, usrsgnt2, orgfp2, CHUNK_TYPE_DESTINATION);
    ASSERT_TRUE(formatted != NULL) << "Failed to format destination chunk data.";

    envelope = dime_prsr_envelope_parse((const unsigned char *)st_data_get(formatted), st_length_get(formatted), CHUNK_TYPE_ORIGIN);
    ASSERT_TRUE(envelope == NULL) << "Was able to parse an destination chunk as a origin.";

    envelope = dime_prsr_envelope_parse((const unsigned char *)st_data_get(formatted), st_length_get(formatted), CHUNK_TYPE_DESTINATION);
    ASSERT_TRUE(envelope != NULL) << "Was unable to parse an destination chunk.";

    res = st_cmp_cs_eq(usrid2, envelope->auth_recp);
    ASSERT_EQ(0, res) << "Data was corrupted during formatting and parsing.";

    res = st_cmp_cs_eq(orgid2, envelope->dest_orig);
    ASSERT_EQ(0, res) << "Data was corrupted during formatting and parsing.";

    res = memcmp(usrsgnt2, st_char_get(envelope->auth_recp_fp), strlen(usrsgnt2));
    ASSERT_EQ(0, res) << "Data was corrupted during formatting and parsing.";

    res = memcmp(orgfp2, st_char_get(envelope->dest_orig_fp), strlen(orgfp2));
    ASSERT_EQ(0, res) << "Data was corrupted during formatting and parsing.";

    st_free(formatted);
    dime_prsr_envelope_destroy(envelope);

    formatted = dime_prsr_envelope_format(usrid2, orgid2, usrsgnt2, orgfp2, CHUNK_TYPE_EPHEMERAL);
    ASSERT_TRUE(formatted == NULL) << "Failed to format destination chunk data.";
}

TEST(DIME, check_parser_header) {

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
    ASSERT_TRUE(formatted != NULL) << "Failed to format common headers.";

    header2 = dime_prsr_headers_parse(formatted, outsize);
    ASSERT_TRUE(header2 != NULL) << "Failed to parse common headers.";

    res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_DATE], header2->headers[HEADER_TYPE_DATE]);
    ASSERT_EQ(0, res) << "Date header was corrupted.";

    res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_TO], header2->headers[HEADER_TYPE_TO]);
    ASSERT_EQ(0, res) << "To header was corrupted.";

    res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_CC], header2->headers[HEADER_TYPE_CC]);
    ASSERT_EQ(0, res) << "CC header was corrupted.";

    res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_FROM], header2->headers[HEADER_TYPE_FROM]);
    ASSERT_EQ(0, res) << "From header was corrupted.";

    res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_ORGANIZATION], header2->headers[HEADER_TYPE_ORGANIZATION]);
    ASSERT_EQ(0, res) << "Organization header was corrupted.";

    res = st_cmp_cs_eq(header1->headers[HEADER_TYPE_SUBJECT], header2->headers[HEADER_TYPE_SUBJECT]);
    ASSERT_EQ(0, res) << "Subject header was corrupted.";

    dime_prsr_headers_destroy(header1);
    dime_prsr_headers_destroy(header2);
    free(formatted);
}
