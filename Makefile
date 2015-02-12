
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
libs			:= $(libsignet-resolver) $(libsignet)

# Foreign Dependencies
libdonna		:= $(DIME_PROJECT_ROOT)/deps/sources/donna
libopenssl		:= $(DIME_PROJECT_ROOT)/deps/sources/openssl
foreign			:= $(libopenssl) $(libdonna)


.PHONY: all clean $(libcore) $(libcommon)

all: $(libcore) $(libcommon)

clean:
	$(MAKE) --directory=$(libcore) clean
	$(MAKE) --directory=$(libcommon) clean

$(libcommon) $(libcore):
	$(MAKE) --directory=$@ $(TARGET)
	$(if $(TARGET), $(MAKE) $(TARGET))

	
$(tools): $(libs)

$(libs): $(libsignet-resolver)

$(libsignet-resolver): $(libsignet)

#$(libsignet): $(libcommon)

#$(libcommon): $(foreign)





