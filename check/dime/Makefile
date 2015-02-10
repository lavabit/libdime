include ../Makefile.common

SRCFILES = check_dime.c check_ssl.c
OBJFILES = $(OBJDIRNAME)/check_ssl.o
OBJDIRNAME = .objs

LIBS := -lcheck $(LIBS)

all:	dime.check objs check

objs:	$(SRCFILES)
	test -d $(OBJDIRNAME) || mkdir $(OBJDIRNAME)
	$(CC) $(CFLAGS) $(INC) -c check_ssl.c -o $(OBJDIRNAME)/check_ssl.o

dime.check: objs
	@echo "Creating the check executable..."
	$(CC) $(CFLAGS) $(INC) -o ../dime.check check_dime.c $(OBJFILES) ../libdime.a ../../libsignet/libsignet.a $(LIBS)

check: dime.check
	@echo "Running the unit tests..."
	@../dime.check
	
clean:
	@echo "Cleaning up the build artifacts..."
	@for f in $(OBJFILES); do \
		if test -f "$$f"; then echo rm $$f; rm $$f; fi; \
	done 
	@if test -d $(OBJDIRNAME); then echo rmdir $(OBJDIRNAME); rmdir $(OBJDIRNAME); fi
	@if test -f ../dime.check; then echo rm ../dime.check; rm ../dime.check; fi 

.PHONY: all objs check clean
