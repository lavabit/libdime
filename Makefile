#!/usr/bin/make
#
# The Magma Makefile
#
#########################################################################

# Identity of this package.
PACKAGE_NAME			= libdime
PACKAGE_TARNAME			= libdime
PACKAGE_VERSION			= 0.2
PACKAGE_STRING			= $(PACKAGE_NAME) $(PACKAGE_VERSION)
PACKAGE_BUGREPORT		= support@lavabit.com
PACKAGE_URL				= https://lavabit.com

TOPDIR					= $(realpath .)

DIME_SRCDIR				= tools/dime
DIME_PROGRAM			= dime$(EXEEXT)

SIGNET_SRCDIR			= tools/signet
SIGNET_PROGRAM			= signet$(EXEEXT)

GENREC_SRCDIR			= tools/genrec
GENREC_PROGRAM			= genrec$(EXEEXT)

DIME_CHECK_SRCDIR		= check/dime
DIME_CHECK_PROGRAM		= dime.check$(EXEEXT)
DIME_CHECK_GTEST		= lib/sources/googtest/lib/.libs/libgtest.a
DIME_CHECK_INCLUDES		= -Icheck/dime -Isrc/dime -Ilib/sources/googtest/include/ -Ilib/sources/googtest/ -Ilib/sources/googtap/src/

LIBDIME_SRCDIR			= src/providers
LIBDIME_SHARED			= libdime$(DYNLIBEXT)
LIBDIME_STATIC			= libdime$(STATLIBEXT)

LIBDIME_OBJFILES		= $(call OBJFILES, $(call SRCFILES, src check tools)) $(call OBJFILES, $(call CPPFILES, src check tools))
LIBDIME_DEPFILES		= $(call DEPFILES, $(call SRCFILES, src check tools)) $(call DEPFILES, $(call CPPFILES, src check tools))
LIBDIME_PROGRAMS		= $(DIME_PROGRAM) $(SIGNET_PROGRAM) $(GENREC_PROGRAM)
LIBDIME_STRIPPED		= libdime-stripped$(STATLIBEXT) libdime-stripped$(DYNLIBEXT) dime-stripped$(EXEEXT) signet-stripped$(EXEEXT) genrec-stripped$(EXEEXT)
LIBDIME_DEPENDENCIES	= lib/local/lib/libz$(STATLIBEXT) lib/local/lib/libssl$(STATLIBEXT) lib/local/lib/libcrypto$(STATLIBEXT)

# Because the ed25519 folder has been dropped into the src tree, we need to explicitly exclude the fuzz files from compilation.
LIBDIME_FILTERED		= src/providers/dime/ed25519/test.c src/providers/dime/ed25519/test-internals.c src/providers/dime/ed25519/fuzz/curve25519-ref10.c \
 src/providers/dime/ed25519/fuzz/ed25519-donna-sse2.c  src/providers/dime/ed25519/fuzz/fuzz-curve25519.c src/providers/dime/ed25519/fuzz/ed25519-donna.c \
 src/providers/dime/ed25519/fuzz/ed25519-ref10.c       src/providers/dime/ed25519/fuzz/fuzz-ed25519.c

LIBDIME_REPO				= $(shell which git &> /dev/null && git log &> /dev/null && echo 1) 
ifneq ($(strip $(LIBDIME_REPO)),1)
	LIBDIME_VERSION			:= $(PACKAGE_VERSION)
	LIBDIME_COMMIT			:= "NONE"
else
	LIBDIME_VERSION			:= $(PACKAGE_VERSION).$(shell git log --format='%H' | wc -l)
	LIBDIME_COMMIT			:= $(shell git log --format="%H" -n 1 | cut -c33-40)
endif
LIBDIME_TIMESTAMP			= $(shell date +'%Y%m%d.%H%M')

# Dependency Files
DEPDIR					= .deps
DEPFILES				= $(patsubst %.cpp, $(DEPDIR)/%.d, $(patsubst %.cc, $(DEPDIR)/%.d, $(patsubst %.c, $(DEPDIR)/%.d, $(1))))

# Object Files
OBJDIR					= .objs
OBJFILES				= $(patsubst %.cpp, $(OBJDIR)/%.o, $(patsubst %.cc, $(OBJDIR)/%.o, $(patsubst %.c, $(OBJDIR)/%.o, $(1))))

# Source Files
SRCDIRS					= $(shell find $(1) -type d -print)
CCFILES					= $(foreach dir, $(call SRCDIRS, $(1)), $(wildcard $(dir)/*.cc))
CPPFILES				= $(foreach dir, $(call SRCDIRS, $(1)), $(wildcard $(dir)/*.cpp))
SRCFILES				= $(foreach dir, $(call SRCDIRS, $(1)), $(wildcard $(dir)/*.c))

# Setup the Defines
DEFINES					+= -D_REENTRANT -DFORTIFY_SOURCE=2 -DDIME_BUILD=$(LIBDIME_VERSION) -DDIME_STAMP=$(LIBDIME_TIMESTAMP)

INCLUDES				= -Isrc -Isrc/providers -Ilib/local/include -I/usr/include
WARNINGS				= -Wfatal-errors -Werror -Wall -Wextra  -Wformat=2 -Wwrite-strings -Wno-format-nonliteral 

# C Compiler
CC						= gcc
CFLAGS					= $(DEFINES) $(CWARNINGS) $(WARNINGS) -std=gnu99 -O0 -ggdb3 -rdynamic -fPIC -c -MMD 

# CPP Compiler
CPP						= g++
CPPFLAGS				= -std=c++0x $(WARNINGS) -Wno-unused-parameter $(DEFINES) -DGTEST_TAP_PRINT_TO_STDOUT -DGTEST_HAS_PTHREAD=1 -pthread -g3 

# Linker
LD						= gcc
LDFLAGS					= -rdynamic

# Archiver Parameters
AR						= ar
ARFLAGS					= rcs

# Strip Parameters
STRIP					= strip
STRIPFLAGS				= --strip-debug

# Other External programs
MV						= mv --force
RM						= rm --force
RMDIR					= rmdir --parents --ignore-fail-on-non-empty
MKDIR					= mkdir --parents
RANLIB					= ranlib

# Text Coloring
RED						= $$(tput setaf 1)
BLUE					= $$(tput setaf 4)
GREEN					= $$(tput setaf 2)
WHITE					= $$(tput setaf 7)
YELLOW					= $$(tput setaf 3)

# Text Weighting
BOLD					= $$(tput bold)
NORMAL					= $$(tput sgr0)

ifeq ($(OS),Windows_NT)
    HOSTTYPE 			:= Windows
    DYNLIBEXT			:= .dll
    STATLIBEXT			:= .lib
    EXEEXT 				:= .exe
else
    HOSTTYPE			:= $(shell uname -s)
    DYNLIBEXT			:= .so
    STATLIBEXT			:= .a
    EXEEXT				:= 
endif

ifeq ($(VERBOSE),yes)
RUN						=
else
RUN						= @
VERBOSE					= no
endif

# So we can tell the user what happened
ifdef MAKECMDGOALS
TARGETGOAL				+= $(MAKECMDGOALS)
else
TARGETGOAL				= $(.DEFAULT_GOAL)
endif

all: config warning $(LIBDIME_SHARED) $(LIBDIME_STATIC) $(LIBDIME_PROGRAMS) $(LIBDIME_STRIPPED) finished

stripped: config warning $(LIBDIME_STRIPPED) finished

check: config warning $(DIME_CHECK_PROGRAM)
	@./dime.check --gtest_output=xml:.out/test_detail.xml
ifeq ($(VERBOSE),no)
	@echo 'Finished' $(BOLD)$(GREEN)$(TARGETGOAL)$(NORMAL)
endif

warning:
ifeq ($(VERBOSE),no)
	@echo 
	@echo 'For a more verbose output' 
	@echo '  make '$(GREEN)'VERBOSE=yes' $(NORMAL)$(TARGETGOAL)
	@echo 
endif

config:
	@echo 
	@echo 'TARGET' $(TARGETGOAL)
	@echo 'VERBOSE' $(VERBOSE)
	@echo 
	@echo 'VERSION ' $(LIBDIME_VERSION)
	@echo 'COMMIT '$(LIBDIME_COMMIT)
	@echo 'DATE ' $(LIBDIME_TIMESTAMP)
	@echo 'HOST ' $(HOSTTYPE)

finished:
ifeq ($(VERBOSE),no)
	@echo 'Finished' $(BOLD)$(GREEN)$(TARGETGOAL)$(NORMAL)
endif
	
# Alias the target names on Windows to the equivalent target without the exe extension.
ifeq ($(HOSTTYPE),Windows)

$(basename %): $(LIBDIME_PROGRAMS)

endif

# Delete the compiled program along with the generated object and dependency files
clean:
	$(RUN)$(RM) $(LIBDIME_PROGRAMS) $(LIBDIME_STRIPPED) $(DIME_CHECK_PROGRAM) 
	$(RUN)$(RM) $(LIBDIME_SHARED) $(LIBDIME_STATIC)
	$(RUN)$(RM) $(LIBDIME_OBJFILES) $(LIBDIME_DEPFILES)
	@for d in $(sort $(dir $(LIBDIME_OBJFILES))); do if test -d "$$d"; then $(RMDIR) "$$d"; fi; done
	@for d in $(sort $(dir $(LIBDIME_DEPFILES))); do if test -d "$$d"; then $(RMDIR) "$$d"; fi; done
	@echo 'Finished' $(BOLD)$(GREEN)$(TARGETGOAL)$(NORMAL)

$(LIBDIME_DEPENDENCIES): res/scripts/build.dimedeps.sh res/scripts/build.dimedeps.params.sh
ifeq ($(VERBOSE),no)
	@echo 'Running' $(RED)$(<F)$(NORMAL)
else
	@echo 
endif
	$(RUN)res/scripts/build.dimedeps.sh all

$(LIBDIME_STRIPPED): $(LIBDIME_SHARED) $(LIBDIME_STATIC) $(LIBDIME_PROGRAMS)
ifeq ($(VERBOSE),no)
	@echo 'Creating' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(STRIP) $(STRIPFLAGS) --output-format=$(shell objdump -p "$(subst -stripped,,$@)" | grep "file format" | head -1 | \
	awk -F'file format' '{print $$2}' | tr --delete  [:space:]) -o "$@" "$(subst -stripped,,$@)"

# Construct the dime check executable
$(DIME_CHECK_PROGRAM): $(LIBDIME_DEPENDENCIES) $(call OBJFILES, $(call CPPFILES, $(DIME_CHECK_SRCDIR))) $(call OBJFILES, $(call CCFILES, $(DIME_CHECK_SRCDIR))) $(call OBJFILES, $(call SRCFILES, $(DIME_CHECK_SRCDIR))) $(LIBDIME_STATIC)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) --output='$@' $(call OBJFILES, $(call CPPFILES, $(DIME_CHECK_SRCDIR))) \
	 $(call OBJFILES, $(call CCFILES, $(DIME_CHECK_SRCDIR))) $(call OBJFILES, $(call SRCFILES, $(DIME_CHECK_SRCDIR))) \
	-Wl,--start-group,--whole-archive $(LIBDIME_DEPENDENCIES) $(LIBDIME_STATIC) $(DIME_CHECK_GTEST) -Wl,--no-whole-archive,--end-group \
	-lresolv -ldl -lm -lstdc++ -lpthread

# Construct the dime executable
$(DIME_PROGRAM): $(LIBDIME_DEPENDENCIES) $(call OBJFILES, $(call SRCFILES, $(DIME_SRCDIR))) $(LIBDIME_STATIC)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) --output='$@' $(call OBJFILES, $(call SRCFILES, $(DIME_SRCDIR))) \
	-Wl,--start-group,--whole-archive $(LIBDIME_DEPENDENCIES) $(LIBDIME_STATIC) -Wl,--no-whole-archive,--end-group -lresolv -ldl

# Construct the signet executable
$(SIGNET_PROGRAM): $(LIBDIME_DEPENDENCIES) $(call OBJFILES, $(call SRCFILES, $(SIGNET_SRCDIR))) $(LIBDIME_STATIC)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) --output='$@' $(call OBJFILES, $(call SRCFILES, $(SIGNET_SRCDIR))) \
	-Wl,--start-group,--whole-archive  $(LIBDIME_DEPENDENCIES) $(LIBDIME_STATIC) -Wl,--no-whole-archive,--end-group -lresolv -ldl

# Construct the genrec executable
$(GENREC_PROGRAM): $(LIBDIME_DEPENDENCIES) $(call OBJFILES, $(call SRCFILES, $(GENREC_SRCDIR))) $(LIBDIME_STATIC)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) --output='$@' $(call OBJFILES, $(call SRCFILES, $(GENREC_SRCDIR))) \
	-Wl,--start-group,--whole-archive $(LIBDIME_DEPENDENCIES) $(LIBDIME_STATIC) -Wl,--no-whole-archive,--end-group -lresolv -ldl

# Create the static libdime archive
$(LIBDIME_STATIC): $(LIBDIME_DEPENDENCIES) $(call OBJFILES, $(filter-out $(LIBDIME_FILTERED), $(call SRCFILES, $(LIBDIME_SRCDIR))))
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(AR) $(ARFLAGS) '$@' $(call OBJFILES, $(filter-out $(LIBDIME_FILTERED), $(call SRCFILES, $(LIBDIME_SRCDIR))))

# Create the libdime shared object
$(LIBDIME_SHARED): $(LIBDIME_DEPENDENCIES) $(call OBJFILES, $(filter-out $(LIBDIME_FILTERED), $(call SRCFILES, $(LIBDIME_SRCDIR))))
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) -o '$@' -shared $(call OBJFILES, $(filter-out $(LIBDIME_FILTERED), $(call SRCFILES, $(LIBDIME_SRCDIR)))) \
	-ggdb3 -fPIC -Wl,-Bsymbolic,--start-group,--whole-archive $(LIBDIME_DEPENDENCIES) -Wl,--no-whole-archive,--end-group -lresolv -ldl

# Compile Source
$(OBJDIR)/src/%.o: src/%.c 
ifeq ($(VERBOSE),no)
	@echo 'Building' $(YELLOW)$<$(NORMAL)
endif
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	$(RUN)$(CC) $(CFLAGS) $(CFLAGS.$(<F)) $(DEFINES) $(DEFINES.$(<F)) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" "$<"

$(OBJDIR)/check/dime/%.o: check/dime/%.c
ifeq ($(VERBOSE),no)
	@echo 'Building' $(YELLOW)$<$(NORMAL)
endif
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	$(RUN)$(CC) $(CFLAGS) $(CFLAGS.$(<F)) $(DEFINES) $(DEFINES.$(<F)) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" "$<"

$(OBJDIR)/tools/%.o: tools/%.c
ifeq ($(VERBOSE),no)
	@echo 'Building' $(YELLOW)$<$(NORMAL)
endif
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	$(RUN)$(CC) $(CFLAGS) $(CFLAGS.$(<F)) $(DEFINES) $(DEFINES.$(<F)) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" "$<"

$(OBJDIR)/%.o: %.cpp 
ifeq ($(VERBOSE),no)
	@echo 'Building' $(YELLOW)$<$(NORMAL)
endif
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	$(RUN)$(CPP) $(CPPFLAGS) $(CPPFLAGS.$(<F)) $(DEFINES) $(DEFINES.$(<F)) $(INCLUDES) $(DIME_CHECK_INCLUDES) -MF"$(<:%.cpp=$(DEPDIR)/%.d)" -MD -MP  -MT"$@" -c -o"$@" "$<"

# If we've already generated dependency files, use them to see if a rebuild is required
-include $(LIBDIME_DEPFILES)

# Special Make Directives
.SUFFIXES: .c .cc .cpp .o 
.NOTPARALLEL: warning conifg $(LIBDIME_DEPENDENCIES)
.PHONY: warning config finished all check stripped


# vim:set softtabstop=4 shiftwidth=4 tabstop=4: