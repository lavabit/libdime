topdir = $(dir $(lastword $(MAKEFILE_LIST)))
include $(topdir)/common.mk

# Defines
DEFINES			:= -D_REENTRANT -D_GNU_SOURCE -DFORTIFY_SOURCE=2

# Compiler Flags
CFLAGS			:= $(CWARNS) $(CDEBUG) -std=gnu99 -fPIC -fmessage-length=0 -MMD

# Archiver Flags
ARFLAGS			:= rcs

# External programs
AR			:= ar
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

# Shortcuts
.PHONY: all clean libs $(basename $(ARCHIVE))
all: $(ARCHIVE)
libs: $(ARCHIVE)
$(basename $(ARCHIVE)): $(ARCHIVE)

# Delete the archive along with the generated object and dependency files
clean:
	@$(RM) $(ARCHIVE) $(OBJFILES) $(DEPFILES)
	@$(RM) -r $(OBJDIR) $(DEPDIR)

# Construct the static archive file
$(ARCHIVE): $(OBJFILES)
	@echo 'Linking' $(RED)$@$(NORMAL)
	$(RUN)$(AR) $(ARFLAGS) $@ $(OBJFILES)
	@$(RANLIB) $@

# Object files
$(OBJDIR)/%.o: %.c
	@echo 'Compiling' $(YELLOW)$<$(NORMAL)
	@$(MKDIR) $(DEPDIR)/$(dir $<) $(OBJDIR)/$(dir $<)
	$(RUN)$(CC) $(CFLAGS) $(CFLAGS.$<) $(DEFINES) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" -c "$(abspath $<)"

# If we've already generated dependency files, use them to see if a rebuild is required
-include $(DEPFILES)
