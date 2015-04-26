TOOL		= x
SRCFILES	= x.c

# Static Library Locations
DIMEDIR		= ../../libs/
DEPSDIR		= ../../deps/sources/

# Static Library Archives
STATIC		= $(DEPSDIR)zlib/libz.a
STATIC		+= $(DEPSDIR)openssl/libcrypto.a
STATIC		+= $(DEPSDIR)openssl/libssl.a
STATIC		+= $(DEPSDIR)donna/ed25519.o
STATIC		+= $(DIMEDIR)core/libcore.a
STATIC		+= $(DIMEDIR)common/libcommon.a 
STATIC		+= $(DIMEDIR)signet/libsignet.a
STATIC		+= $(DIMEDIR)signet-resolver/libsignet-resolver.a 

# Dynamic Libraries
DYNAMIC		= -lc -lrt -ldl -pthread -lresolv

INCLUDES	= -I../../include/ -I../../deps/sources/donna -I../../deps/sources/openssl/include

include ../../tool.mk
