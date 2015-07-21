# Use m4 macros from m4
ACLOCAL_AMFLAGS = -I m4 --install
EXTRA_DIST = m4/NOTES

AM_CFLAGS = $(WARNINGS) -std=gnu99

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

TEST_LOG_DRIVER = \
	env AM_TAP_AWK='$(AWK)' \
	$(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
TESTS = tests
check_PROGRAMS = tests
check_LIBRARIES = libgtest.a

# Note that googletest is compiled with the *same* flags we use to build
# everything else.  This is the reason googletest encourages bundling in the
# first place.
libgtest_a_CPPFLAGS = \
	-I$(top_srcdir)/bundle/googletest \
	-I$(top_srcdir)/bundle/googletest/include
libgtest_a_SOURCES = \
	bundle/googletest/src/gtest-all.cc

tests_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS) \
	-I$(top_srcdir)/check
tests_CFLAGS = \
	@CHECK_CFLAGS@ \
	@OPENSSL_CFLAGS@
tests_LDADD = \
	libdmessage.a \
	libsignet_resolver.a \
	libsignet.a \
	libcommon.a \
	libcore.a \
	-lresolv \
	libdonna.a \
	@CHECK_LIBS@ \
	@OPENSSL_LIBS@
tests_SOURCES = \
	check/common/check_common.c \
	check/common/check_crypto.c \
	check/common/check_error.c \
	check/common/check_misc.c \
	check/core/check_classify.c \
	check/core/check_compare.c \
	check/core/check_hash.c \
	check/core/check_host_folder.c \
	check/core/check_mail_counters.c \
	check/core/check_memory.c \
	check/dime/check_ssl.c \
	check/dmessage/check_dmsg.c \
	check/dmessage/check_parser.c \
	check/signet/check_keys.c \
	check/signet/check_signet.c \
	check/tests.c

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
