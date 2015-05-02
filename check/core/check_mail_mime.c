#include <core/magma.h>
#include "checks.h"

START_TEST(test_mail_mime_encode_part__1) {
	stringer_t *str = mail_mime_encode_part(CONSTANT("data"), CONSTANT("filename-without-extension"), CONSTANT("boundary"));
	ck_assert_str_eq(
		"--------------boundary\r\n"
		"Content-Type: application/octet-stream;\r\n"
		"Content-Transfer-Encoding: base64\r\n"
		"Content-Disposition: attachment; filename=\"filename-without-extension\"\r\n"
		"\r\n"
		"ZGF0YQ==\r\n",
		st_char_get(str));
	st_free(str);
}
END_TEST

START_TEST(test_mail_mime_encode_part__2) {
	stringer_t *str = mail_mime_encode_part(CONSTANT("data"), CONSTANT("image.jpg"), CONSTANT("boundary"));
	ck_assert_str_eq(
		"--------------boundary\r\n"
		"Content-Type: image/jpeg;\r\n"
		"Content-Transfer-Encoding: base64\r\n"
		"Content-Disposition: attachment; filename=\"image.jpg\"\r\n"
		"\r\n"
		"ZGF0YQ==\r\n",
		st_char_get(str));
	st_free(str);
}
END_TEST

START_TEST(test_mail_mime_encode_part__3) {
	stringer_t *str = mail_mime_encode_part(CONSTANT("data"), CONSTANT("image.jpg.gz"), CONSTANT("boundary"));
	ck_assert_str_eq(
		"--------------boundary\r\n"
		"Content-Type: application/gzip;\r\n"
		"Content-Transfer-Encoding: base64\r\n"
		"Content-Disposition: attachment; filename=\"image.jpg.gz\"\r\n"
		"\r\n"
		"ZGF0YQ==\r\n",
		st_char_get(str));
	st_free(str);
}
END_TEST

Suite *suite_check_mail_mime(void) {

	Suite *s = suite_create("mail/mime");
	suite_add_testfunc(s, test_mail_mime_encode_part__1);
	suite_add_testfunc(s, test_mail_mime_encode_part__2);
	suite_add_testfunc(s, test_mail_mime_encode_part__3);
	return s;
}
