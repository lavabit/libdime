include ../Makefile.common

SRCFILES = check_common.c check_misc.c check_crypto.c
OBJDIRNAME = .objs
DONNA_INC = ../providers/sources/donna/
PROVIDER_INC = $(DONNA_INC)
ADDL_INC_CCOPT			= $(patsubst %,-I%,$(PROVIDER_INC))
ALL_INC_CCOPT = $(INC) $(ADDL_INC_CCOPT)
LIBS := -lcheck $(LIBS)

include ../Makefile.vars

.PHONY: all objs common.check check clean

all:	common.check objs check

objs:	$(OBJFILES)

common.check: objs
	@echo "Creating the check executable..."
	$(CC) -o ../common.check $(OBJFILES) $(LIBS)

check: common.check
	@echo "Running the unit tests..."
	@../common.check
	
clean:
	@echo "Cleaning up the build artifacts..."
	@for f in $(OBJFILES); do \
		if test -f "$$f"; then echo rm $$f; rm $$f; fi; \
	done 
	@if test -d $(OBJDIRNAME); then echo rmdir $(OBJDIRNAME); rmdir $(OBJDIRNAME); fi
	@for f in $(DEPFILES); do \
		rm -vf $$f $$f.tmp; \
	done
	@if test -f ../common.check; then echo rm ../common.check; rm ../common.check; fi 

include ../Makefile.rules
