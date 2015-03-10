
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

checks			:= $(DIME_PROJECT_ROOT)/check/common $(DIME_PROJECT_ROOT)/check/dime $(DIME_PROJECT_ROOT)/check/signet

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
libsignet: libcommon $(libsignet)
libcommon: libcore $(libcommon)
libcore: $(libcore)
libs: $(libs)

dime: libs $(dime)
signet: libs $(signet)
tools: $(dime) $(signet)
