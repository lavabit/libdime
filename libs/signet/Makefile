include Makefile.common

DYNLIB      = libsignet.so
STATLIB = libsignet.a
OBJDIRNAME  = .objs

SRCFILES    = general.c keys.c keys_pub.c signet.c signet_pub.c
OBJFILES    = $(OBJDIRNAME)/general.o $(OBJDIRNAME)/keys.o $(OBJDIRNAME)/keys_pub.o $(OBJDIRNAME)/signet.o $(OBJDIRNAME)/signet_pub.o

all:		lib

lib:		objs dynlib statlib

libsignet.a:	statlib
libsignet.so:	dynlib

# Shouldn't each object file be an target? This is probably why everything has to be recompiled every time. 
objs:		$(SRCFILES)
		test -d $(OBJDIRNAME) || mkdir $(OBJDIRNAME)
		$(CC) $(CFLAGS) -fPIC $(INC) -c general.c -o $(OBJDIRNAME)/general.o
		$(CC) $(CFLAGS) -fPIC $(INC) -c keys.c -o $(OBJDIRNAME)/keys.o
		$(CC) $(CFLAGS) -fPIC $(INC) -c keys_pub.c -o $(OBJDIRNAME)/keys_pub.o
		$(CC) $(CFLAGS) -fPIC $(INC) -c signet.c -o $(OBJDIRNAME)/signet.o
		$(CC) $(CFLAGS) -fPIC $(INC) -c signet_pub.c -o $(OBJDIRNAME)/signet_pub.o

# Shouldn't this be using ld instead?
dynlib:		objs
		@echo "Creating the shared library..."
		gcc -shared -Wl,-soname,$(DYNLIB) -o ../$(DYNLIB) $(OBJFILES)

statlib:	objs
		@echo "Creating the static archive file..."
		ar rcs ../$(STATLIB) $(OBJFILES)

clean:
		@echo "Cleaning up the build artifacts..."
		@for f in $(OBJFILES); do \
	 		if test -f "$$f"; then echo rm $$f; rm $$f; fi; \
		done 
		@if test -d $(OBJDIRNAME); then echo rmdir $(OBJDIRNAME); rmdir $(OBJDIRNAME); fi
		@if test -f ../$(DYNLIB); then echo rm ../$(DYNLIB); rm ../$(DYNLIB); fi
		@if test -f ../$(STATLIB); then echo rm ../$(STATLIB); rm ../$(STATLIB); fi 

.PHONY:	all lib objs dynlib statlib clean

