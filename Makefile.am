

# Add/remove libdime source files here!
LIBDIME_SOURCES = \
	libs/dime_ctx.c \
	libs/error_codes.c \
	libs/common/crypto.c \
	libs/common/crypto_pub.c \
	libs/common/error.c \
	libs/common/misc.c \
	libs/common/misc_pub.c \
	libs/common/network.c \
	libs/common/network_pub.c \
	libs/dmessage/dmsg.c \
	libs/dmessage/parser.c \
	libs/dmtp/commands.c \
	libs/signet/general.c \
	libs/signet/keys.c \
	libs/signet/signet.c \
	libs/signet-resolver/cache.c \
	libs/signet-resolver/cache_pub.c \
	libs/signet-resolver/dmtp.c \
	libs/signet-resolver/dmtp_pub.c \
	libs/signet-resolver/dns.c \
	libs/signet-resolver/dns_pub.c \
	libs/signet-resolver/mrec.c \
	libs/signet-resolver/mrec_pub.c \
	libs/signet-resolver/ssl.c \
	libs/signet-resolver/ssl_pub.c \
	libs/util/encoding.c \
	libs/util/encrypt.c

# Add/remove test source files here!
LIBDIME_TESTS = \
	check/dime/check_ssl.cpp \
	check/dmessage/check_dmsg.cpp \
	check/dmessage/check_parser.cpp \
	check/dmtp/check_commands.cpp \
	check/common/check_common.cpp \
	check/common/check_crypto.cpp \
	check/common/check_error.cpp \
	check/common/check_misc.cpp \
	check/signet/check_keys.cpp \
	check/signet/check_signet.cpp

# Use m4 macros from m4
ACLOCAL_AMFLAGS = -I m4 --install
EXTRA_DIST = m4/NOTES

AM_CFLAGS = @WARNINGS@ @CWARNINGS@ -std=gnu99
AM_CXXFLAGS = @WARNINGS@ 

COMMON_CPPFLAGS = \
	-DDIME_BUILD="\"$(shell cat .dime_build)\"" \
	-DDIME_STAMP="\"$(shell cat .dime_stamp)\"" \
	-I$(top_srcdir)/include

DONNA_CPPFLAGS = \
	-I$(top_srcdir)/bundle/ed25519-donna

SDS_CPPFLAGS = \
	-I$(top_srcdir)/bundle/sds

lib_LTLIBRARIES = \
	libdime.la

libdime_la_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS) \
	$(SDS_CPPFLAGS)
libdime_la_SOURCES = \
	$(LIBDIME_SOURCES)
libdime_la_LIBADD = \
	libsds.la \
	libdonna.la

commonincludedir = \
	$(includedir)/dime/common
commoninclude_HEADERS = \
	include/dime/common/dcrypto.h \
	include/dime/common/error.h \
	include/dime/common/misc.h \
	include/dime/common/network.h
dmessageincludedir = \
	$(includedir)/dime/dmessage
dmessageinclude_HEADERS = \
	include/dime/dmessage/common.h \
	include/dime/dmessage/crypto.h \
	include/dime/dmessage/parse.h
signetincludedir = \
	$(includedir)/dime/signet
signetinclude_HEADERS = \
	include/dime/signet/common.h \
	include/dime/signet/keys.h \
	include/dime/signet/signet.h
signetresolverincludedir = \
	$(includedir)/dime/signet-resolver
signetresolverinclude_HEADERS = \
	include/dime/signet-resolver/cache.h \
	include/dime/signet-resolver/dmtp.h \
	include/dime/signet-resolver/dns.h \
	include/dime/signet-resolver/mrec.h \
	include/dime/signet-resolver/signet-ssl.h

bin_PROGRAMS = \
	dime \
	signet \
	genrec

noinst_LTLIBRARIES = \
	libsds.la \
	libdonna.la

dime_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
dime_CFLAGS = \
	$(AM_CFLAGS) \
	@OPENSSL_CFLAGS@ \
	@PTHREAD_CFLAGS@
dime_LDADD = \
	libdime.la \
	-lresolv \
	@OPENSSL_LIBS@ \
	@PTHREAD_LIBS@
dime_SOURCES = \
	tools/dime/dime.c

signet_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
signet_CFLAGS = \
	$(AM_CFLAGS) \
	@OPENSSL_CFLAGS@ \
	@PTHREAD_CFLAGS@
signet_LDADD = \
	libdime.la \
	-lresolv \
	@OPENSSL_LIBS@ \
	@PTHREAD_LIBS@
signet_SOURCES = \
	tools/signet/signet.c

genrec_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
genrec_CFLAGS = \
	$(AM_CFLAGS) \
	@OPENSSL_CFLAGS@ \
	@PTHREAD_CFLAGS@
genrec_LDADD = \
	libdime.la \
	-lresolv \
	@OPENSSL_LIBS@ \
	@PTHREAD_LIBS@
genrec_SOURCES = \
	tools/genrec/genrec.c

libsds_la_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	-I$(top_srcdir)/bundle/sds
libsds_la_CFLAGS = \
	-Wall \
	-std=c99 \
	-pedantic
libsds_la_SOURCES = \
	bundle/sds/sds.c

libdonna_la_CPPFLAGS = \
	$(DONNA_CPPFLAGS)
libdonna_la_SOURCES = \
	bundle/ed25519-donna/ed25519.c

check: gtest
	@$(top_builddir)/gtest --gtest_output=xml
check_PROGRAMS = gtest
check_LIBRARIES = libgtest.a

# Note that googletest is compiled with the *same* flags we use to build
# everything else.  This is the reason googletest encourages bundling in the
# first place.
libgtest_a_CPPFLAGS = \
	-I$(top_srcdir)/bundle/googletest \
	-I$(top_srcdir)/bundle/googletest/include
libgtest_a_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	-Wno-missing-field-initializers
libgtest_a_SOURCES = \
	bundle/googletest/src/gtest-all.cc

gtest_CPPFLAGS = \
	-DGTEST_HAS_PTHREAD=@GTEST_HAS_PTHREAD@ \
	-DGTEST_TAP_PRINT_TO_STDOUT \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS) \
	$(SDS_CPPFLAGS) \
	-I$(top_srcdir)/bundle/googletest/include \
	-I$(top_srcdir)/bundle/gtest-tap-listener/src \
	-I$(top_srcdir)/check
gtest_CFLAGS = \
	$(AM_CFLAGS) \
	@OPENSSL_CFLAGS@ \
	@PTHREAD_CFLAGS@
gtest_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	@OPENSSL_CFLAGS@ \
	@PTHREAD_CFLAGS@
gtest_LDADD = \
	libdime.la \
	-lresolv \
	libgtest.a \
	@OPENSSL_LIBS@ \
	@PTHREAD_LIBS@
gtest_SOURCES = \
	check/gtest.cpp \
	$(LIBDIME_TESTS)

# Targets to build before we start compiling
BUILT_SOURCES = git_stamp date_stamp

git_stamp:
	@NEW_GIT_STAMP=`git log --format="%H" -n 1 | cut -c33-40`; \
	if test ! -f $(top_builddir)/.dime_build; then \
		echo "$$NEW_GIT_STAMP" > $(top_builddir)/.dime_build; \
	else \
		OLD_GIT_STAMP=`cat $(top_builddir)/.dime_build`; \
		if test "$$OLD_GIT_STAMP" != "$$NEW_GIT_STAMP" ; then \
			echo "$$NEW_GIT_STAMP" > $(top_builddir)/.dime_build; \
		fi \
	fi

date_stamp:
	@NEW_DATE_STAMP=`date +'%Y%m%d'`; \
	if test ! -f $(top_builddir)/.magma_stamp; then \
		echo "$$NEW_DATE_STAMP" > $(top_builddir)/.dime_stamp; \
	else \
		OLD_DATE_STAMP=`cat $(top_builddir)/.dime_stamp`; \
		if test "$$OLD_DATE_STAMP" != "$$NEW_DATE_STAMP" ; then \
			echo "$$NEW_DATE_STAMP" > $(top_builddir)/.dime_stamp; \
		fi \
	fi

.PHONY: git_stamp date_stamp
