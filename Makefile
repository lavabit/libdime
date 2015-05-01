# This must be run first. It stores the absolute path to the DIME directory. 
topdir			:= $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Tools
dime			:= $(topdir)/tools/dime
signet			:= $(topdir)/tools/signet
tools			:= $(signet) $(dime)

# Legacy Tools
cachedump		:= $(topdir)/tools/cachedump
dmtp			:= # $(topdir)/tools/dmtp
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

checks			:= $(topdir)/check/common $(topdir)/check/core $(topdir)/check/dime $(topdir)/check/signet $(topdir)/check/dmessage

.PHONY: all check clean uncrustify doxygen coverage $(libs) $(tools) $(legacy-tools) $(checks)

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
legacy-tools: $(legacy-tools)

uncrustify:
	@find check include libs tools -type f -name '*.[ch]' -print \
	| uncrustify -c uncrustify.cfg -F- --no-backup -l C

coverage:
	@$(MAKE) -s clean
	@$(MAKE) -s check CDEBUG="-O0 -g --coverage"
	@mkdir -p ~/public_html/libdime-coverage
	@gcovr -r . --branches --html --html-details -o ~/public_html/libdime-coverage/index.html
	@$(MAKE) -s clean

doxygen:
	@doxygen
