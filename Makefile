#!/usr/bin/make
#
# The Magma Makefile
#
#########################################################################

TOPDIR					= $(realpath .)
MFLAGS					=
MAKEFLAGS				= --output-sync=target --jobs=6

# Identity of this package.
PACKAGE_NAME			= libdime
PACKAGE_TARNAME			= libdime
PACKAGE_VERSION			= 0.2
PACKAGE_STRING			= $(PACKAGE_NAME) $(PACKAGE_VERSION)
PACKAGE_BUGREPORT		= support@lavabit.com
PACKAGE_URL				= https://lavabit.com

#MAGMA_PROGRAM			= $(addsuffix $(EXEEXT), magmad)
#CHECK_PROGRAM			= $(addsuffix $(EXEEXT), magmad.check)

LIBDIME_REPO				= $(shell which git &> /dev/null && git log &> /dev/null && echo 1) 
ifneq ($(strip $(LIBDIME_REPO)),1)
	LIBDIME_VERSION			:= $(PACKAGE_VERSION)
	LIBDIME_COMMIT			:= "NONE"
else
	LIBDIME_VERSION			:= $(PACKAGE_VERSION).$(shell git log --format='%H' | wc -l)
	LIBDIME_COMMIT			:= $(shell git log --format="%H" -n 1 | cut -c33-40)
endif
LIBDIME_TIMESTAMP			= $(shell date +'%Y%m%d.%H%M')

# Source Files
#MAGMA_SRCDIRS			= $(shell find src -type d -print)
#MAGMA_SRCFILES			= $(filter-out src/engine/status/build.c, $(foreach dir,$(MAGMA_SRCDIRS), $(wildcard $(dir)/*.c)))

#CHECK_SRCDIRS			= $(shell find check -type d -print)
#CHECK_SRCFILES			= $(foreach dir,$(CHECK_SRCDIRS), $(wildcard $(dir)/*.c))

# Bundled Dependency Include Paths
#MAGMA_INCDIRS			= spf2/src/include clamav/libclamav mysql/include openssl/include lzo/include xml2/include \
		zlib bzip2 tokyocabinet memcached dkim/libopendkim dspam/src jansson/src gd png jpeg freetype/include \
		utf8proc
#CHECK_INCDIRS			= checker/src

CFLAGS					= -std=gnu99 -O0 -fPIC -fmessage-length=0 -ggdb3 -rdynamic -c $(CFLAGS_WARNINGS) -MMD 
CFLAGS_WARNINGS			= -Wall -Werror -Winline -Wformat-security -Warray-bounds
CFLAGS_PEDANTIC			= -Wextra -Wpacked -Wunreachable-code -Wformat=2

#MAGMA_CINCLUDES			= -Isrc $(addprefix -I,$(MAGMA_INCLUDE_ABSPATHS))
#CHECK_CINCLUDES			= -Icheck -Isrc -I$(TOPDIR)/lib/local/include $(addprefix -I,$(MAGMA_INCLUDE_ABSPATHS)) 


#MAGMA_DYNAMIC			= -lrt -ldl -lpthread
#CHECK_DYNAMIC			= $(MAGMA_DYNAMIC) -lm

#MAGMA_STATIC			= 
#CHECK_STATIC			= $(TOPDIR)/lib/local/lib/libcheck.a

#INCDIR					= $(TOPDIR)/lib/sources


# Resolve the External Include Directory Paths
INCLUDE_DIR_VPATH		= $(INCDIR) /usr/include /usr/local/include
INCLUDE_DIR_SEARCH 		= $(firstword $(wildcard $(addsuffix /$(1),$(subst :, ,$(INCLUDE_DIR_VPATH)))))

# Generate the Absolute Directory Paths for Include
MAGMA_INCLUDE_ABSPATHS	+= $(foreach target,$(MAGMA_INCDIRS), $(call INCLUDE_DIR_SEARCH,$(target)))
CHECK_INCLUDE_ABSPATHS	+= $(foreach target,$(CHECK_INCDIRS), $(call INCLUDE_DIR_SEARCH,$(target)))

DIME_SRCDIR				= tools/dime
DIME_PROGRAM			= dime$(EXEEXT)
DIME_PROGRAM_STRIP		= dime-stripped$(EXEEXT)

SIGNET_SRCDIR			= tools/signet
SIGNET_PROGRAM			= signet$(EXEEXT)
SIGNET_PROGRAM_STRIP	= signet-stripped$(EXEEXT)

GENREC_SRCDIR			= tools/genrec
GENREC_PROGRAM			= genrec$(EXEEXT)
GENREC_PROGRAM_STRIP	= genrec-stripped$(EXEEXT)

DIME_CHECK_SRCDIR		= check/dime
DIME_CHECK_PROGRAM		= dime.check$(EXEEXT)

LIBDIME_SHARED			= libdime$(DYNLIBEXT)
LIBDIME_SHARED_STRIP	= libdime-stripped$(DYNLIBEXT)
LIBDIME_STATIC			= libdime$(STATLIBEXT)
LIBDIME_STATIC_STRIP	= libdime-stripped$(STATLIBEXT)
LIBDIME_SRCDIR			= src/dime

LIBDIME_OBJFILES		= $(call OBJFILES, $(call SRCFILES, src check tools))
LIBDIME_DEPFILES		= $(call DEPFILES, $(call SRCFILES, src check tools))
LIBDIME_PROGRAMS		= $(DIME_PROGRAM) $(SIGNET_PROGRAM) $(GENREC_PROGRAM)
LIBDIME_STRIPPED		= $(LIBDIME_SHARED_STRIP) $(LIBDIME_STATIC_STRIP) $(DIME_PROGRAM_STRIP) $(SIGNET_PROGRAM_STRIP) $(GENREC_PROGRAM_STRIP)
LIBDIME_DEPENDENCIES	= lib/local/lib/libz$(STATLIBEXT) lib/local/lib/libssl$(STATLIBEXT) lib/local/lib/libcrypto$(STATLIBEXT)

LIBDIME_FILTERED		= src/dime/ed25519/test.c src/dime/ed25519/test-internals.c src/dime/ed25519/fuzz/curve25519-ref10.c \
 src/dime/ed25519/fuzz/ed25519-donna-sse2.c  src/dime/ed25519/fuzz/fuzz-curve25519.c src/dime/ed25519/fuzz/ed25519-donna.c \
 src/dime/ed25519/fuzz/ed25519-ref10.c       src/dime/ed25519/fuzz/fuzz-ed25519.c

# Dependency Files
DEPDIR					= .deps
DEPFILES				= $(patsubst %.c,$(DEPDIR)/%.d,$(1))

# Object Files
OBJDIR					= .objs
OBJFILES				= $(patsubst %.c,$(OBJDIR)/%.o,$(1))

# Source Files
SRCDIRS					= $(shell find $(1) -type d -print)
SRCFILES				= $(foreach dir, $(call SRCDIRS, $(1)), $(wildcard $(dir)/*.c))

# Setup the Defines
DEFINES					+= "-D_REENTRANT "
DEFINES					+= "-DFORTIFY_SOURCE=2 "
DEFINES					+= "-DDIME_BUILD=$(LIBDIME_VERSION)"
DEFINES					+= "-DDIME_STAMP=$(LIBDIME_TIMESTAMP)" 

# Setup the Compiler Warnings
#WARNINGS				+= "-Wall "
#WARNINGS				+= "-Wextra "
#WARNINGS				+= "-Werror "
#WARNINGS				+= "-Wfatal-errors "
#WARNINGS				+= "-Wformat=2 "
#WARNINGS				+= "-Wwrite-strings "
#WARNINGS				+= "-Wno-format-nonliteral "
#WARNINGS				+= "-fmessage-length=0 "
#CWARNINGS				+= "-Wstrict-prototypes "
#CWARNINGS				+= "-Wmissing-prototypes "
#CWARNINGS				+= "-Wno-pointer-sign "

INCLUDES				= -Isrc -Ilib/local/include -I/usr/include
WARNINGS				= -Werror -Wall -Wextra -Wfatal-errors -Wformat=2 -Wwrite-strings -Wno-format-nonliteral 

# C Compiler
CC						= gcc
CFLAGS					= $(DEFINES) $(CWARNINGS) $(WARNINGS) -std=gnu99 -O0 -ggdb3 -rdynamic -fPIC -c -MMD 

# CPP Compiler
CPP						= g++
CPPFLAGS				= $(DEFINES) $(WARNINGS) -std=c++0x -O0 -ggdb3 -rdynamic -fPIC -c -MMD 

# Linker
LD						= gcc
LDFLAGS					= -rdynamic

# Archiver Parameters
AR						= ar
ARFLAGS					= rcs

# Strip Parameters
STRIP					= strip
STRIPFLAGS				= --strip-unneeded --strip-debug

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

check: config warning $(LIBDIME_SHARED) $(LIBDIME_STATIC) $(LIBDIME_PROGRAMS) $(DIME_CHECK_PROGRAM) finished

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
	
# Alias the target names on Windows to the equivalent without the exe extension.
ifeq ($(HOSTTYPE),Windows)

#$(basename $(MAGMA_PROGRAM)): $(MAGMA_PROGRAM)

endif

# Delete the compiled program along with the generated object and dependency files
clean:
	@$(RM) $(LIBDIME_PROGRAMS) $(LIBDIME_STATIC) $(LIBDIME_SHARED) $(LIBDIME_STRIPPED) $(DIME_CHECK_PROGRAM) $(LIBDIME_OBJFILES) $(LIBDIME_DEPFILES)
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

%-stripped$(DYNLIBEXT) %-stripped$(STATLIBEXT) %-stripped$(EXEEXT): $(LIBDIME_SHARED) $(LIBDIME_STATIC) $(LIBDIME_PROGRAMS)
ifeq ($(VERBOSE),no)
	@echo 'Creating' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(STRIP) $(STRIPFLAGS) -o "$@" "$<"

# Construct the dime executable
$(DIME_PROGRAM): $(call OBJFILES, $(call SRCFILES, $(DIME_SRCDIR))) $(LIBDIME_STATIC) $(LIBDIME_DEPENDENCIES)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) --output='$@' $(call OBJFILES, $(call SRCFILES, $(DIME_SRCDIR))) \
	-Wl,--start-group,--whole-archive $(LIBDIME_DEPENDENCIES) $(LIBDIME_STATIC) -Wl,--no-whole-archive,--end-group -lresolv -ldl

# Construct the signet executable
$(SIGNET_PROGRAM): $(call OBJFILES, $(call SRCFILES, $(SIGNET_SRCDIR))) $(LIBDIME_STATIC) $(LIBDIME_DEPENDENCIES)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) --output='$@' $(call OBJFILES, $(call SRCFILES, $(SIGNET_SRCDIR))) \
	-Wl,--start-group,--whole-archive  $(LIBDIME_DEPENDENCIES) $(LIBDIME_STATIC) -Wl,--no-whole-archive,--end-group -lresolv -ldl

# Construct the genrec executable
$(GENREC_PROGRAM): $(call OBJFILES, $(call SRCFILES, $(GENREC_SRCDIR))) $(LIBDIME_STATIC) $(LIBDIME_DEPENDENCIES)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) --output='$@' $(call OBJFILES, $(call SRCFILES, $(GENREC_SRCDIR))) \
	-Wl,--start-group,--whole-archive $(LIBDIME_DEPENDENCIES) $(LIBDIME_STATIC) -Wl,--no-whole-archive,--end-group -lresolv -ldl

# Create the static libdime archive
$(LIBDIME_STATIC): $(call OBJFILES, $(filter-out $(LIBDIME_FILTERED), $(call SRCFILES, $(LIBDIME_SRCDIR)))) $(LIBDIME_DEPENDENCIES)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(AR) $(ARFLAGS) '$@' $(call OBJFILES, $(filter-out $(LIBDIME_FILTERED), $(call SRCFILES, $(LIBDIME_SRCDIR))))

# Create the libdime shared object
$(LIBDIME_SHARED): $(call OBJFILES, $(filter-out $(LIBDIME_FILTERED), $(call SRCFILES, $(LIBDIME_SRCDIR)))) $(LIBDIME_DEPENDENCIES)
ifeq ($(VERBOSE),no)
	@echo 'Constructing' $(RED)$@$(NORMAL)
else
	@echo 
endif
	$(RUN)$(LD) $(LDFLAGS) -o '$@' -shared $(call OBJFILES, $(filter-out $(LIBDIME_FILTERED), $(call SRCFILES, $(LIBDIME_SRCDIR)))) \
	-ggdb3 -fPIC -Wl,-Bsymbolic,--start-group,--whole-archive $(LIBDIME_DEPENDENCIES) -Wl,--no-whole-archive,--end-group -lresolv -ldl

# Compile Source
$(OBJDIR)/%.o: %.c
ifeq ($(VERBOSE),no)
	@echo 'Building' $(YELLOW)$<$(NORMAL)
endif
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	$(RUN)$(CC) $(CFLAGS) $(CFLAGS.$(<F)) $(DEFINES) $(DEFINES.$(<F)) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" "$<"

# If we've already generated dependency files, use them to see if a rebuild is required
-include $(LIBDIME_DEPFILES)

# Special Make Directives
.NOTPARALLEL: warning conifg
.PHONY: warning config finished all check

# vim:set softtabstop=4 shiftwidth=4 tabstop=4:
