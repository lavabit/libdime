# This must be run first. It stores the absolute path to the DIME directory. 
topdir 	:= $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Tools
dime			:= $(topdir)/tools/dime
signet			:= $(topdir)/tools/signet
tools			:= $(signet) $(dime)

# Legacy Tools
cachedump		:= $(topdir)/tools/cachedump
dmtp			:= $(topdir)/tools/dmtp
ed25519			:= $(topdir)/tools/ed25519
genrec			:= $(topdir)/tools/genrec
x			:= $(topdir)/tools/x
legacy-tools		:= $(cachedump) $(dmtp) $(ed25519) $(genrec) $(x)

# Libraries
libcore			:= $(topdir)/libs/core
libcommon		:= $(topdir)/libs/common
libsignet		:= $(topdir)/libs/signet
libdmessage		:= $(topdir)/libs/dmessage
libsignet-resolver	:= $(topdir)/libs/signet-resolver
libs			:= $(libcore) $(libcommon) $(libsignet) $(libdmessage) $(libsignet-resolver)

# Foreign Dependencies
libdonna		:= $(topdir)/deps/sources/donna
libopenssl		:= $(topdir)/deps/sources/openssl
foreign			:= # $(libopenssl) $(libdonna)

checks			:= $(topdir)/check/common $(topdir)/check/core $(topdir)/check/dime $(topdir)/check/signet $(topdir)/check/dmessage

.PHONY: all check clean $(libs) $(tools) $(legacy-tools) $(checks)

all: $(libs) $(tools)

clean:
	@$(foreach dir, $(libs) $(tools) $(legacy-tools) $(checks), $(MAKE) --directory=$(dir) clean; )

$(libs) $(tools) $(legacy-tools) $(checks):
	$(MAKE) --jobs=8 --directory=$@ $(TARGET)
	$(if $(TARGET), $(MAKE) $(TARGET))

check: $(checks)

$(checks): all

libsignet-resolver: libsignet $(libsignet-resolver)
libdmessage: libsignet $(libdmessage)
libsignet: libcommon $(libsignet)
libcommon: libcore $(libcommon)
libcore: $(libcore)
libs: $(libs)

dime: libs $(dime)
signet: libs $(signet)
tools: $(dime) $(signet)

uncrustify:
	find include libs check -type f -name '*.[ch]' -print \
	| uncrustify -c uncrustify.cfg -F- --no-backup -l C
