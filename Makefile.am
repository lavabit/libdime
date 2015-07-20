# Use m4 macros from m4
ACLOCAL_AMFLAGS = -I m4 --install
EXTRA_DIST = m4/NOTES

AM_CFLAGS = $(WARNINGS)

# Note that we specify the include directories for the bundled dependencies
# here.
COMMON_CPPFLAGS = \
	-DDIME_BUILD="\"$(shell cat .dime_build)\"" \
	-DDIME_STAMP="\"$(shell cat .dime_stamp)\"" \
	-I$(top_srcdir)/include

BUNDLED_CPPFLAGS = \
	-I$(top_srcdir)/deps/sources/donna \
	-I$(top_srcdir)/deps/sources/openssl/include

noinst_LIBRARIES = \
	libcore.a \
	libcommon.a

libcore_a_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	$(BUNDLED_CPPFLAGS)
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

#TESTS = $(top_srcdir)/check/runner.sh
#check_PROGRAMS = tests
#tests_CPPFLAGS = -I$(top_srcdir)/check $(COMMON_CPPFLAGS)
#tests_SOURCES = \
#		check/magma_check.c \
#		check/core/base64_check.c \
#		check/core/bitwise_check.c \
#		check/core/core_check.c \
#		check/core/hashed_check.c \
#		check/core/hex_check.c \
#		check/core/inx_check.c \
#		check/core/linked_check.c \
#		check/core/nbo_check.c \
#		check/core/qp_check.c \
#		check/core/qsort_check.c \
#		check/core/string_check.c \
#		check/core/system_check.c \
#		check/core/tree_check.c \
#		check/core/url_check.c \
#		check/core/zbase32_check.c \
#		check/network/address_check.c \
#		check/network/network_check.c \
#		check/objects/objects_check.c \
#		check/providers/compress_check.c \
#		check/providers/dspam_check.c \
#		check/providers/ecies_check.c \
#		check/providers/hash_check.c \
#		check/providers/hmac_check.c \
#		check/providers/provide_check.c \
#		check/providers/rand_check.c \
#		check/providers/scramble_check.c \
#		check/providers/stacie_check.c \
#		check/providers/symmetric_check.c \
#		check/providers/tank_check.c \
#		check/providers/virus_check.c \
#		check/users/users_check.c
#tests_CFLAGS = @CHECK_CFLAGS@
#tests_LDADD = libmagma.a -ldl -lrt @CHECK_LIBS@
#
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
	@NEW_DATE_STAMP=`date +'%Y%m%d.%H%M'`; \
	if test ! -f $(top_builddir)/.magma_stamp; then \
		echo "$$NEW_DATE_STAMP" > $(top_builddir)/.dime_stamp; \
	else \
		OLD_DATE_STAMP=`cat $(top_builddir)/.dime_stamp`; \
		if test "$$OLD_DATE_STAMP" != "$$NEW_DATE_STAMP" ; then \
			echo "$$NEW_DATE_STAMP" > $(top_builddir)/.dime_stamp; \
		fi \
	fi

.PHONY: git_stamp date_stamp
