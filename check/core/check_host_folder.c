#include "core/magma.h"
#include "checks.h"

static stringer_t *mkstringer(const char *s) {

	stringer_t *st = st_import(s, strlen(s) + 1);
	ck_assert_ptr_ne(NULL, st);
	return st;
}

START_TEST(test_folder_exists__rootdir) {
	stringer_t *rootdir = mkstringer("/");
	ck_assert_int_eq(0, folder_exists(rootdir, false));
	st_free(rootdir);
}
END_TEST

START_TEST(test_folder_exists__nonexistent) {
	stringer_t *nonex = mkstringer("/nonexistent");
	ck_assert_int_eq(-1, folder_exists(nonex, false));
	ck_assert_int_eq(-1, folder_exists(nonex, true));
	st_free(nonex);
}
END_TEST

START_TEST(test_folder_exists__tmpdir) {
	stringer_t *tmpdir = mkstringer("/tmp/check_host_folder.d");
	ck_assert_int_eq(-1, folder_exists(tmpdir, false));
	ck_assert_int_eq(1, folder_exists(tmpdir, true));
	rmdir(st_data_get(tmpdir));
	st_free(tmpdir);
}
END_TEST

START_TEST(test_folder_exists__nested) {
	stringer_t *deepdir = mkstringer("/tmp/deeply/nested/dir");
	ck_assert_int_eq(-1, folder_exists(deepdir, false));
	ck_assert_int_eq(-1, folder_exists(deepdir, true));
	st_free(deepdir);
}
END_TEST

Suite *suite_check_host_folder(void) {

	Suite *s = suite_create("host/folder");
	suite_add_testfunc(s, test_folder_exists__rootdir);
	suite_add_testfunc(s, test_folder_exists__nonexistent);
	suite_add_testfunc(s, test_folder_exists__tmpdir);
	suite_add_testfunc(s, test_folder_exists__nested);
	return s;
}
