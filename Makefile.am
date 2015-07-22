# Use m4 macros from m4
ACLOCAL_AMFLAGS = -I m4 --install
EXTRA_DIST = m4/NOTES

AM_CFLAGS = @WARNINGS@ @CWARNINGS@ -std=gnu99
AM_CXXFLAGS = @WARNINGS@ -std=c++11

# Note that we specify the include directories for the bundled dependencies
# here.
COMMON_CPPFLAGS = \
	-DDIME_BUILD="\"$(shell cat .dime_build)\"" \
	-DDIME_STAMP="\"$(shell cat .dime_stamp)\"" \
	-I$(top_srcdir)/include

DONNA_CPPFLAGS = \
	-I$(top_srcdir)/bundle/ed25519-donna

noinst_LIBRARIES = \
	libcore.a \
	libcommon.a \
	libdmessage.a \
	libsignet.a \
	libsignet_resolver.a \
	libdonna.a

libdonna_a_CPPFLAGS = \
	$(DONNA_CPPFLAGS)
libdonna_a_CFLAGS =
libdonna_a_SOURCES = \
	bundle/ed25519-donna/ed25519.c

libcore_a_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libcore_a_SOURCES = \
	libs/core/buckets/arrays.c \
	libs/core/buckets/pool.c \
	libs/core/buckets/stacked.c \
	libs/core/classify/ascii.c \
	libs/core/compare/ends.c \
	libs/core/compare/equal.c \
	libs/core/compare/search.c \
	libs/core/compare/starts.c \
	libs/core/encodings/base64.c \
	libs/core/encodings/hex.c \
	libs/core/encodings/mappings.c \
	libs/core/encodings/qp.c \
	libs/core/encodings/url.c \
	libs/core/encodings/zbase32.c \
	libs/core/global.c \
	libs/core/hash/adler.c \
	libs/core/hash/crc.c \
	libs/core/hash/fletcher.c \
	libs/core/hash/murmur.c \
	libs/core/host/files.c \
	libs/core/host/folder.c \
	libs/core/host/host.c \
	libs/core/host/mappings.c \
	libs/core/host/process.c \
	libs/core/host/spool.c \
	libs/core/indexes/cursors.c \
	libs/core/indexes/hashed.c \
	libs/core/indexes/inx.c \
	libs/core/indexes/linked.c \
	libs/core/log/log.c \
	libs/core/mail/counters.c \
	libs/core/mail/headers.c \
	libs/core/mail/mime.c \
	libs/core/memory/align.c \
	libs/core/memory/bits.c \
	libs/core/memory/memory.c \
	libs/core/memory/secure.c \
	libs/core/other.c \
	libs/core/parsers/case.c \
	libs/core/parsers/formats/nvp.c \
	libs/core/parsers/line.c \
	libs/core/parsers/numbers/digits.c \
	libs/core/parsers/numbers/numbers.c \
	libs/core/parsers/special/bracket.c \
	libs/core/parsers/time.c \
	libs/core/parsers/token.c \
	libs/core/parsers/trim.c \
	libs/core/strings/allocation.c \
	libs/core/strings/data.c \
	libs/core/strings/info.c \
	libs/core/strings/length.c \
	libs/core/strings/multi.c \
	libs/core/strings/nuller.c \
	libs/core/strings/opts.c \
	libs/core/strings/print.c \
	libs/core/strings/replace.c \
	libs/core/strings/shortcuts.c \
	libs/core/strings/validate.c \
	libs/core/thread/keys.c \
	libs/core/thread/mutex.c \
	libs/core/thread/rwlock.c \
	libs/core/thread/thread.c \
	libs/core/type.c

libcommon_a_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libcommon_a_SOURCES = \
	libs/common/crypto.c \
	libs/common/crypto_pub.c \
	libs/common/error.c \
	libs/common/misc.c \
	libs/common/misc_pub.c \
	libs/common/network.c \
	libs/common/network_pub.c

libdmessage_a_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libdmessage_a_SOURCES = \
	libs/dmessage/dmsg.c \
	libs/dmessage/parser.c

libsignet_a_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libsignet_a_SOURCES = \
	libs/signet/general.c \
	libs/signet/keys.c \
	libs/signet/signet.c

libsignet_resolver_a_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libsignet_resolver_a_SOURCES = \
	libs/signet-resolver/cache.c \
	libs/signet-resolver/cache_pub.c \
	libs/signet-resolver/dmtp.c \
	libs/signet-resolver/dmtp_pub.c \
	libs/signet-resolver/dns.c \
	libs/signet-resolver/dns_pub.c \
	libs/signet-resolver/mrec.c \
	libs/signet-resolver/mrec_pub.c \
	libs/signet-resolver/ssl.c \
	libs/signet-resolver/ssl_pub.c

LOG_DRIVER = \
	env AM_TAP_AWK='$(AWK)' \
	$(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
TESTS = gtest
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
	libdmessage.a \
	libsignet_resolver.a \
	libsignet.a \
	libcommon.a \
	libcore.a \
	-lresolv \
	libdonna.a \
	libgtest.a \
	@OPENSSL_LIBS@ \
	@PTHREAD_LIBS@
gtest_SOURCES = \
	check/gtest.cpp \
	check/dime/check_ssl.cpp \
	check/dmessage/check_dmsg.cpp \
	check/dmessage/check_parser.cpp

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
