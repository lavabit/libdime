
# This must be run first. It stores the absolute path to the DIME directory. 
DIME_PROJECT_ROOT 	:= $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
DIME_PROJECT_OUTPUT 	:= $(DIME_PROJECT_ROOT)/output

# Tools
dime			:= $(DIME_PROJECT_ROOT)/tools/dime
signet			:= $(DIME_PROJECT_ROOT)/tools/signet
tools			:= $(dime) $(signet)

# Libraries
libcore			:= $(DIME_PROJECT_ROOT)/libs/core
libcommon		:= $(DIME_PROJECT_ROOT)/libs/common
libsignet		:= $(DIME_PROJECT_ROOT)/libs/signet
libsignet-resolver	:= $(DIME_PROJECT_ROOT)/libs/signet-resolver
libs			:= $(libsignet-resolver) $(libsignet) $(libcommon)

# Foreign Dependencies
libdonna		:= $(DIME_PROJECT_ROOT)/deps/donna
libopenssl		:= $(DIME_PROJECT_ROOT)/deps/openssl
foreign			:= $(libopenssl) $(libdonna)


.PHONY: all clean $(libcore)

all: $(libcore)

clean:
	$(MAKE) --directory=$(libcore) clean


$(libcore):
	$(MAKE) --directory=$@ $(TARGET)
	$(if $(TARGET), $(MAKE) $(TARGET))

	
$(tools): $(libs)

$(libs): $(libsignet-resolver)

$(libsignet-resolver): $(libsignet)

$(libsignet): $(libcommon)

$(libcommon): $(foreign)





