include Makefile.common

DYNLIB				= libcommon.so
DYNLIBPATH			= ../$(DYNLIB)
STATLIB_STUB			= libcommon.a.stub
STATLIB				= libcommon.a
STATLIBPATH			= ../$(STATLIB)
SSLLIB				= ../providers/sources/openssl/libssl.a
CRYPTOLIB			= ../providers/sources/openssl/libcrypto.a
DONNA				= ../providers/sources/donna/ed25519.o
ADDL_INC			= -I../providers/sources/donna/
ALL_INC_CCOPT = $(INC) $(ADDL_INC)

SRCFILES    	= crypto.c misc.c network.c error.c crypto_pub.c misc_pub.c network_pub.c

include Makefile.vars

.PHONY	: all objs lib dynlib statlib clean

all: lib

lib:	objs dynlib statlib

dynlib: $(DYNLIBPATH)

statlib: $(STATLIBPATH)

objs:	$(OBJFILES)

$(DYNLIBPATH):	$(OBJFILES)
	@echo "Creating the shared library..."
	gcc -shared -Wl,-soname,$(DYNLIB) -o ../$(DYNLIB) $(OBJFILES)

$(STATLIBPATH): $(OBJFILES) $(SSLLIB) $(CRYPTOLIB) $(DONNA)
	@echo "Creating the static archive file..."
	ar rcs ../$(STATLIB_STUB) $(OBJFILES) $(DONNA)
	../mk-static.sh
	@if test -f ../$(STATLIB_STUB); then echo rm ../$(STATLIB_STUB); rm ../$(STATLIB_STUB); fi 

clean:
		@echo "Cleaning up the build artifacts..."
		@for f in $(OBJFILES); do \
			if test -f "$$f"; then echo rm $$f; rm $$f; fi; \
		done 
		@if test -d $(OBJDIRNAME); then echo rmdir $(OBJDIRNAME); rmdir $(OBJDIRNAME); fi
		@for f in $(DEPFILES); do \
			rm -vf $$f $$f.tmp ; \
		done 
		@if test -d $(DEPDIRNAME); then echo rmdir $(DEPDIRNAME); rmdir $(DEPDIRNAME); fi
		@if test -f ../$(DYNLIB); then echo rm ../$(DYNLIB); rm ../$(DYNLIB); fi
		@if test -f ../$(STATLIB_STUB); then echo rm ../$(STATLIB_STUB); rm ../$(STATLIB_STUB); fi 
		@if test -f ../$(STATLIB); then echo rm ../$(STATLIB); rm ../$(STATLIB); fi 

include Makefile.rules
