
# Tool name
TOOL			:= signet

# Source files
SRCFILES := signet.c

# Static Library Locations
DIMEDIR			:= ../../libs/
DEPSDIR			:= ../../deps/sources/

# Static Library Archives
STATIC			:= $(DEPSDIR)zlib/libz.a
STATIC			+= $(DEPSDIR)openssl/libcrypto.a 
STATIC			+= $(DEPSDIR)openssl/libssl.a
STATIC			+= $(DEPSDIR)donna/ed25519.o
STATIC			+= $(DIMEDIR)core/libcore.a
STATIC			+= $(DIMEDIR)common/libcommon.a 
STATIC			+= $(DIMEDIR)signet/libsignet.a
STATIC			+= $(DIMEDIR)signet-resolver/libsignet-resolver.a 

# Dynamic Libraries
DYNAMIC			:= -lc -lrt -ldl -lpthread -lresolv
 
# Include paths
INCLUDES		:= -I../../include/ -I../../include/core/ -I../../include/signet/ -I../../include/common/ -I../../deps/sources/donna -I../../deps/sources/openssl/include

include ../../tool.mk
