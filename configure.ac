# Note that this has not been extensively tested with various autoconf
# versions.  TODO - determine the minimum autoconf version we will support
AC_PREREQ([2.63])

AC_INIT([libdime], [0.1])

# Look for macros in the m4 directory
AC_CONFIG_MACRO_DIR([m4])

# Try to find dependencies using pkg-config
PKG_CHECK_MODULES([CHECK], [check >= 0.9])
# TODO - pin down min supported openssl version
PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.8])

# Sanity check to make sure the specified srcdir actually contains the source
AC_CONFIG_SRCDIR([include/signet/signet.h])

# Auxiliary autotools files go here
AC_CONFIG_AUX_DIR([build-aux])

# Initialize Automake
#
# The foreign option prevents automake from requiring the GNU-specific project
# files like AUTHORS, COPYING, etc.
#
# The subdir-objects option allows source files in subdirectories.
#
# nostdinc disables including srcdir (-I.)
AM_INIT_AUTOMAKE([foreign subdir-objects nostdinc])

# Instruct configure to create Makefile using Makefile.am
AC_CONFIG_FILES([Makefile])

# Find and probe C compiler (use "current" standard)
AC_PROG_CC_STDC

# Find and probe C++ compiler
AC_PROG_CXX

# Find ranlib
AC_PROG_RANLIB

# Define _GNU_SOURCE
AC_GNU_SOURCE

## Handle pthreads (See
## http://stackoverflow.com/questions/17055279/autotools-for-pthreads-not-setting-correct-linker-flags)
#AX_PTHREAD([
#			AC_DEFINE([HAVE_PTHREAD],[1], [Define if you have pthreads.])
#			LIBS="$PTHREAD_LIBS $LIBS"
#			CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
#			LDFLAGS="$LDFLAGS $PTHREAD_CFLAGS"
#			CC="$PTHREAD_CC"], [])

#AC_DEFINE([HAVE_NS_TYPE])

WARNINGS="\
	-Wfatal-errors \
	-Werror \
	-Wall \
	-Wextra \
	-Wformat=2 \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-Wwrite-strings \
	"
#CWARNS += "-Wstrict-overflow=5"

if `$CC -v 2>&1 | grep 'clang version' > /dev/null 2>&1`; then
	WARNINGS+="\
		-ferror-limit=5 \
		-Weverything \
		-Wno-bad-function-cast \
		-Wno-cast-align \
		-Wno-conditional-uninitialized \
		-Wno-conversion \
		-Wno-covered-switch-default \
		-Wno-disabled-macro-expansion \
		-Wno-documentation \
		-Wno-documentation-unknown-command \
		-Wno-float-equal \
		-Wno-gnu-designator \
		-Wno-packed \
		-Wno-padded \
		-Wno-pedantic \
		-Wno-shorten-64-to-32 \
		-Wno-sign-conversion \
		-Wno-switch-enum \
		-Wno-unreachable-code \
		"
fi

AC_SUBST(WARNINGS)

# Include support for TAP test output
AC_REQUIRE_AUX_FILE([tap-driver.sh])

AC_OUTPUT
