include ../Makefile.common

DYNLIB				= libdime.so
STATLIB				= libdime.a
OBJDIRNAME			= .objs

SRCFILES    	= cache.c dmtp.c dns.c mrec.c ssl.c cache_pub.c dmtp_pub.c dns_pub.c mrec_pub.c ssl_pub.c
OBJFILES    	= $(OBJDIRNAME)/cache.o $(OBJDIRNAME)/dmtp.o $(OBJDIRNAME)/dns.o $(OBJDIRNAME)/mrec.o $(OBJDIRNAME)/ssl.o $(OBJDIRNAME)/cache_pub.o $(OBJDIRNAME)/dmtp_pub.o $(OBJDIRNAME)/dns_pub.o $(OBJDIRNAME)/mrec_pub.o $(OBJDIRNAME)/ssl_pub.o

all: lib

lib:	objs dynlib statlib

libdime.a:	statlib
libdime.so:	dynlib

objs:	$(SRCFILES)
	test -d $(OBJDIRNAME) || mkdir $(OBJDIRNAME)
	$(CC) $(CFLAGS) $(INC) -fPIC -c cache.c -o $(OBJDIRNAME)/cache.o
	$(CC) $(CFLAGS) $(INC) -fPIC -c dmtp.c -o $(OBJDIRNAME)/dmtp.o
	$(CC) $(CFLAGS) $(INC) -fPIC -c dns.c -o $(OBJDIRNAME)/dns.o
	$(CC) $(CFLAGS) $(INC) -fPIC -c mrec.c -o $(OBJDIRNAME)/mrec.o
	$(CC) $(CFLAGS) $(INC) $(SSLINC) -fPIC -c ssl.c -o $(OBJDIRNAME)/ssl.o
	$(CC) $(CFLAGS) $(INC) $(SSLINC) -fPIC -c cache_pub.c -o $(OBJDIRNAME)/cache_pub.o
	$(CC) $(CFLAGS) $(INC) $(SSLINC) -fPIC -c dmtp_pub.c -o $(OBJDIRNAME)/dmtp_pub.o
	$(CC) $(CFLAGS) $(INC) $(SSLINC) -fPIC -c dns_pub.c -o $(OBJDIRNAME)/dns_pub.o
	$(CC) $(CFLAGS) $(INC) $(SSLINC) -fPIC -c mrec_pub.c -o $(OBJDIRNAME)/mrec_pub.o
	$(CC) $(CFLAGS) $(INC) $(SSLINC) -fPIC -c ssl_pub.c -o $(OBJDIRNAME)/ssl_pub.o

dynlib:	$(OBJFILES)
	@echo "Creating the shared library..."
	gcc -shared -Wl,-soname,$(DYNLIB) -o ../$(DYNLIB) $(OBJFILES)

statlib: $(OBJFILES)
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
