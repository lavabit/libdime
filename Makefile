
# This must be run first. It stores the absolute path to the DIME directory. 
DIME_PROJECT_ROOT 	:= $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
DIME_PROJECT_OUTPUT 	:= $(DIME_PROJECT_ROOT)/output

# Tools
dime			:= $(DIME_PROJECT_ROOT)/tools/dime
signet			:= $(DIME_PROJECT_ROOT)/tools/signet
tools			:= $(signet) $(dime)

# Legacy Tools
cachedump		:= $(DIME_PROJECT_ROOT)/tools/cachedump
dmtp			:= $(DIME_PROJECT_ROOT)/tools/dmtp
ed25519			:= $(DIME_PROJECT_ROOT)/tools/ed25519
genrec			:= $(DIME_PROJECT_ROOT)/tools/genrec
x			:= $(DIME_PROJECT_ROOT)/tools/x
legacy-tools		:= $(cachedump) $(dmtp) $(ed25519) $(genrec) $(x)

# Libraries
libcore			:= $(DIME_PROJECT_ROOT)/libs/core
libcommon		:= $(DIME_PROJECT_ROOT)/libs/common
libsignet		:= $(DIME_PROJECT_ROOT)/libs/signet
libsignet-resolver	:= $(DIME_PROJECT_ROOT)/libs/signet-resolver
libs			:= $(libcore) $(libcommon) $(libsignet) $(libsignet-resolver)

# Foreign Dependencies
libdonna		:= $(DIME_PROJECT_ROOT)/deps/sources/donna
libopenssl		:= $(DIME_PROJECT_ROOT)/deps/sources/openssl
foreign			:= # $(libopenssl) $(libdonna)


.PHONY: all clean $(libcore) $(libcommon) $(libsignet) $(libsignet-resolver) $(libs) $(dime) $(signet) $(tools) $(legacy-tools)

all: $(libs) $(tools) $(legacy-tools)

clean:
	$(MAKE) --directory=$(cachedump) clean
	$(MAKE) --directory=$(dime) clean
	$(MAKE) --directory=$(dmtp) clean
	$(MAKE) --directory=$(ed25519) clean
	$(MAKE) --directory=$(genrec) clean
	$(MAKE) --directory=$(signet) clean
	$(MAKE) --directory=$(x) clean
	$(MAKE) --directory=$(libsignet-resolver) clean
	$(MAKE) --directory=$(libsignet) clean
	$(MAKE) --directory=$(libcommon) clean
	$(MAKE) --directory=$(libcore) clean

$(dime) $(signet) $(libsignet-resolver) $(libsignet) $(libcommon) $(libcore):
	$(MAKE) --jobs=8 --directory=$@ $(TARGET)
	$(if $(TARGET), $(MAKE) $(TARGET))

libsignet-resolver: libsignet $(libsignet-resolver)
libsignet: libcommon $(libsignet)
libcommon: libcore $(libcommon) 
libcore: $(libcore)
libs: $(libsignet-resolver) $(libsignet) $(libcommon) $(libcore)

dime: libs $(dime)
signet: libs $(signet)
tools: $(dime) $(signet)

