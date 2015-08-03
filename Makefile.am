# Use m4 macros from m4
ACLOCAL_AMFLAGS = -I m4 --install
EXTRA_DIST = m4/NOTES

AM_CFLAGS = @WARNINGS@ @CWARNINGS@ -std=gnu99
AM_CXXFLAGS = @WARNINGS@ -std=c++11

COMMON_CPPFLAGS = \
	-DDIME_BUILD="\"$(shell cat .dime_build)\"" \
	-DDIME_STAMP="\"$(shell cat .dime_stamp)\"" \
	-I$(top_srcdir)/include

DONNA_CPPFLAGS = \
	-I$(top_srcdir)/bundle/ed25519-donna

lib_LTLIBRARIES = \
	libdime.la
libdime_la_SOURCES =
libdime_la_LIBADD = \
	libsds.la \
	libcore.la \
	libcommon.la \
	libdmessage.la \
	libsignet.la \
	libsignet_resolver.la \
	libdonna.la
commonincludedir = \
	$(includedir)/dime/common
commoninclude_HEADERS = \
	include/dime/common/dcrypto.h \
	include/dime/common/error.h \
	include/dime/common/misc.h \
	include/dime/common/network.h
coreincludedir = \
	$(includedir)/dime/core
coreinclude_HEADERS = \
	include/dime/core/buckets.h \
	include/dime/core/classify.h \
	include/dime/core/compare.h \
	include/dime/core/config.h \
	include/dime/core/core.h \
	include/dime/core/encodings.h \
	include/dime/core/formats.h \
	include/dime/core/hash.h \
	include/dime/core/host.h \
	include/dime/core/indexes.h \
	include/dime/core/log.h \
	include/dime/core/magma.h \
	include/dime/core/mail.h \
	include/dime/core/memory.h \
	include/dime/core/mime.h \
	include/dime/core/numbers.h \
	include/dime/core/other.h \
	include/dime/core/parsers.h \
	include/dime/core/smtp.h \
	include/dime/core/special.h \
	include/dime/core/strings.h \
	include/dime/core/thread.h
dmessageincludedir = \
	$(includedir)/dime/dmessage
dmessageinclude_HEADERS = \
	include/dime/dmessage/dmsg_common.h \
	include/dime/dmessage/dmsg_crypto.h \
	include/dime/dmessage/dmsg_parse.h
signetincludedir = \
	$(includedir)/dime/signet
signetinclude_HEADERS = \
	include/dime/signet/sgnt_common.h \
	include/dime/signet/sgnt_keys.h \
	include/dime/signet/sgnt_signet.h
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
	signet

noinst_LTLIBRARIES = \
	libsds.la \
	libcore.la \
	libcommon.la \
	libdmessage.la \
	libsignet.la \
	libsignet_resolver.la \
	libdonna.la

dime_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
dime_SOURCES = \
	tools/dime/dime.c
dime_LDADD = \
	libsds.la \
	libdmessage.la \
	libsignet_resolver.la \
	libsignet.la \
	libcommon.la \
	libcore.la \
	-lresolv \
	libdonna.la \
	@OPENSSL_LIBS@

signet_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
signet_SOURCES = \
	tools/signet/signet.c
signet_LDADD = \
	libsds.la \
	libdmessage.la \
	libsignet_resolver.la \
	libsignet.la \
	libcommon.la \
	libcore.la \
	-lresolv \
	libdonna.la \
	@OPENSSL_LIBS@

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

libcore_la_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libcore_la_SOURCES = \
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

libcommon_la_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libcommon_la_SOURCES = \
	libs/common/crypto.c \
	libs/common/crypto_pub.c \
	libs/common/error.c \
	libs/common/misc.c \
	libs/common/misc_pub.c \
	libs/common/network.c \
	libs/common/network_pub.c

libdmessage_la_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libdmessage_la_SOURCES = \
	libs/dmessage/dmsg.c \
	libs/dmessage/parser.c

libsignet_la_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libsignet_la_SOURCES = \
	libs/signet/general.c \
	libs/signet/keys.c \
	libs/signet/signet.c

libsignet_resolver_la_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(DONNA_CPPFLAGS)
libsignet_resolver_la_SOURCES = \
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
	libsds.la \
	libdmessage.la \
	libsignet_resolver.la \
	libsignet.la \
	libcommon.la \
	libcore.la \
	-lresolv \
	libdonna.la \
	libgtest.a \
	@OPENSSL_LIBS@ \
	@PTHREAD_LIBS@
gtest_SOURCES = \
	check/gtest.cpp \
	check/dime/check_ssl.cpp \
	check/dmessage/check_dmsg.cpp \
	check/dmessage/check_parser.cpp \
	check/common/check_common.cpp \
	check/common/check_crypto.cpp \
	check/common/check_error.cpp \
	check/common/check_misc.cpp \
	check/core/check_classify.cpp \
	check/core/check_compare.cpp \
	check/core/check_hash.cpp \
	check/core/check_host_folder.cpp \
	check/core/check_mail_counters.cpp \
	check/core/check_memory.cpp \
	check/signet/check_keys.cpp \
	check/signet/check_signet.cpp

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
