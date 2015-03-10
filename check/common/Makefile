checks_SOURCES		= check_common.c check_misc.c check_crypto.c
checks_CFLAGS		= $(DONNA_CFLAGS) $(LIBCOMMON_CFLAGS) $(OPENSSL_CFLAGS) -DTESTDATADIR=\"$(srcdir)/testdata\"
checks_LDADD		= $(DONNA_LIBS) $(LIBCOMMON_LIBS) $(OPENSSL_LIBS)

include ../../check.mk
