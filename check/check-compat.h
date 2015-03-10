#include <check.h>
#include <stdint.h>
#include <inttypes.h>

/* check <= 0.9.9 doesn't have the ck_assert_uint_* macros, and the ck_assert_int_* only applied to int, not to intmax_t. */
#if CHECK_MAJOR_VERSION * 10000 + CHECK_MINOR_VERSION * 100 + CHECK_PATCH_VERSION < 0 * 10000 + 9 * 100 + 10 * 1

#undef _ck_assert_int
#define _ck_assert_int(X, OP, Y) do { \
  intmax_t _ck_x = (X); \
  intmax_t _ck_y = (Y); \
  ck_assert_msg(_ck_x OP _ck_y, "Assertion '" #X " " #OP " " #Y "' failed: "#X"==%d, "#Y"==%d", _ck_x, _ck_y); \
} while (0)

#define ck_assert_uint(X, OP, Y) do { \
  uintmax_t _ck_x = (X); \
  uintmax_t _ck_y = (Y); \
  ck_assert_msg(_ck_x OP _ck_y, "Assertion '" #X " " #OP " " #Y "' failed: "#X"==%d, "#Y"==%d", _ck_x, _ck_y); \
} while (0)
#define ck_assert_uint_eq(X, Y) ck_assert_uint(X, ==, Y)
#define ck_assert_uint_ne(X, Y) ck_assert_uint(X, !=, Y)
#define ck_assert_uint_lt(X, Y) ck_assert_uint(X, <, Y)
#define ck_assert_uint_le(X, Y) ck_assert_uint(X, <=, Y)
#define ck_assert_uint_gt(X, Y) ck_assert_uint(X, >, Y)
#define ck_assert_uint_ge(X, Y) ck_assert_uint(X, >=, Y)

#endif
