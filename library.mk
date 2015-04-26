topdir = $(dir $(lastword $(MAKEFILE_LIST)))
include $(topdir)/common.mk

# Defines
DEFINES			:= -D_REENTRANT -D_GNU_SOURCE -DFORTIFY_SOURCE=2

# Compiler Flags
CFLAGS			:= $(CWARNS) $(CDEBUG) -std=gnu99 -fPIC -rdynamic -fmessage-length=0 -MMD

# Archiver Flags
ARFLAGS			:= rcs

# External programs
AR			:= ar
LD			:= gcc
CC			:= gcc
MV			:= mv -f
RM			:= rm -f
RMDIR			:= rmdir --parents --ignore-fail-on-non-empty
MKDIR			:= mkdir -p
RANLIB			:= ranlib

# Hidden directories for generated files
OBJDIR			= .objs
DEPDIR			= .deps

# Build the list of object and dependancy files using the list of source files
OBJFILES		= $(patsubst %.c,$(OBJDIR)/%.o,$(SRCFILES))
DEPFILES		= $(patsubst %.c,$(DEPDIR)/%.d,$(SRCFILES))

# So we can tell the user what happened
ifdef MAKECMDGOALS
TARGETGOAL		= $(MAKECMDGOALS)
else
TARGETGOAL		= $(.DEFAULT_GOAL)
endif

# Shortcuts
.PHONY: all clean libs $(basename $(ARCHIVE))
all: $(ARCHIVE)
libs: $(ARCHIVE)
$(basename $(ARCHIVE)): $(ARCHIVE)

# Delete the archive along with the generated object and dependency files
clean:
	@$(RM) $(ARCHIVE) $(OBJFILES) $(DEPFILES)
	@for d in $(sort $(dir $(OBJFILES))); do if test -d "$$d"; then $(RMDIR) "$$d"; fi; done
	@for d in $(sort $(dir $(DEPFILES))); do if test -d "$$d"; then $(RMDIR) "$$d"; fi; done

# Construct the static archive file
$(ARCHIVE): $(OBJFILES)
	@echo 'Linking' $(RED)$@$(NORMAL)
	$(RUN)$(AR) $(ARFLAGS) $@ $(OBJFILES)
	@$(RANLIB) $@

# Object files
$(OBJDIR)/%.o: %.c
	@echo 'Compiling' $(YELLOW)$<$(NORMAL)
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	$(RUN)$(CC) $(CFLAGS) $(CFLAGS.$<) $(DEFINES) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" -c "$(abspath $<)"

# If we've already generated dependency files, use them to see if a rebuild is required
-include $(DEPFILES)
