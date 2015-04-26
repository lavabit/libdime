topdir = $(dir $(lastword $(MAKEFILE_LIST)))
include $(topdir)/common.mk

# Defines
DEFINES			:= -D_REENTRANT -D__USE_GNU -D__GNU_SOURCE -DFORTIFY_SOURCE=2

# Compilation
CFLAGS			:= $(CWARNS) $(CDEBUG) -std=gnu99 -fPIC -rdynamic -fmessage-length=0 -MMD

# Linker Flags
LDFLAGS			:= -rdynamic $(CDEBUG)

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
.PHONY: all clean tools
all: $(TOOL)
tools: $(TOOL)

# Delete the archive along with the generated object and dependency files
clean:
	@$(RM) $(TOOL) $(OBJFILES) $(DEPFILES)
	@for d in $(sort $(dir $(OBJFILES))); do if test -d "$$d"; then $(RMDIR) "$$d"; fi; done
	@for d in $(sort $(dir $(DEPFILES))); do if test -d "$$d"; then $(RMDIR) "$$d"; fi; done

# Construct the binary executable file
$(TOOL): $(OBJFILES)
	@echo 'Linking' $(RED)$@$(NORMAL)
	@$(LD) $(LDFLAGS) --output='$@' $(OBJFILES) -Wl,--start-group $(STATIC) -Wl,--end-group $(DYNAMIC)

# Object files
$(OBJDIR)/%.o: %.c
	@echo 'Compiling' $(YELLOW)$<$(NORMAL)
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	@$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" -c "$(abspath $<)"

# If we've already generated dependency files, use them to see if a rebuild is required
-include $(DEPFILES)
