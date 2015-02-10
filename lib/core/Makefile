include Makefile.common

DYNLIB				= libcore.so
STATLIB				= libcore.a

RM := rm -rf

-include subdir.mk
-include mail/subdir.mk
-include core/subdir.mk
-include thread/subdir.mk
-include strings/subdir.mk
-include parsers/subdir.mk
-include parsers/special/subdir.mk
-include parsers/numbers/subdir.mk
-include parsers/formats/subdir.mk
-include memory/subdir.mk
-include log/subdir.mk
-include indexes/subdir.mk
-include host/subdir.mk
-include hash/subdir.mk
-include encodings/subdir.mk
-include compare/subdir.mk
-include classify/subdir.mk
-include buckets/subdir.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

# Add inputs and outputs from these tool invocations to the build variables 

all: lib

lib: dynlib statlib

dynlib: $(OBJS)
	@echo "Creating the shared library..."
	gcc -shared -Wl,-soname,$(DYNLIB) -o ../../$(DYNLIB) $(OBJDIR)/*.o

statlib: $(OBJS)
	@echo "Creating the static archive file..."
	ar rcs ../../$(STATLIB) $(OBJDIR)/*.o

clean:
	@echo "Cleaning up the build artifacts..."
	-$(RM) $(OBJDIR)/*.o $(DEPDIR)/*.d
	@if test -d $(OBJDIR); then echo rmdir $(OBJDIR); rmdir $(OBJDIR); fi
	@if test -d $(DEPDIR); then echo rmdir $(DEPDIR); rmdir $(DEPDIR); fi
	@if test -f ../../$(DYNLIB); then echo rm ../../$(DYNLIB); rm ../../$(DYNLIB); fi
	@if test -f ../../$(STATLIB); then echo rm ../../$(STATLIB); rm ../../$(STATLIB); fi 


.PHONY: all clean dependents
.SECONDARY: main-build
