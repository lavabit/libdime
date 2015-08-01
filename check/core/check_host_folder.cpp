extern "C" {
#include "dime/core/magma.h"
}
#include "gtest/gtest.h"

static stringer_t *mkstringer(const char *s) {

	stringer_t *st = st_import(s, strlen(s) + 1);
	EXPECT_TRUE(NULL != st);
	return st;
}

TEST(DIME, test_folder_exists_rootdir) {
	stringer_t *rootdir = mkstringer("/");
	ASSERT_EQ(0, folder_exists(rootdir, false));
	st_free(rootdir);
}

TEST(DIME, test_folder_exists_nonexistent) {
	stringer_t *nonex = mkstringer("/nonexistent");
	ASSERT_EQ(-1, folder_exists(nonex, false));
	ASSERT_EQ(-1, folder_exists(nonex, true));
	st_free(nonex);
}

TEST(DIME, test_folder_exists_tmpdir) {
	stringer_t *tmpdir = mkstringer("/tmp/check_host_folder.d");
	ASSERT_EQ(-1, folder_exists(tmpdir, false));
	ASSERT_EQ(1, folder_exists(tmpdir, true));
	rmdir(static_cast<char const *>(st_data_get(tmpdir)));
	st_free(tmpdir);
}

TEST(DIME, test_folder_exists_nested) {
	stringer_t *deepdir = mkstringer("/tmp/deeply/nested/dir");
	ASSERT_EQ(-1, folder_exists(deepdir, false));
	ASSERT_EQ(-1, folder_exists(deepdir, true));
	st_free(deepdir);
}
