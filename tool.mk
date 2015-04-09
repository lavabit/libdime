topdir = $(dir $(lastword $(MAKEFILE_LIST)))
include $(topdir)/config.mk

# Defines
DEFINES			:= -D_REENTRANT -D__USE_GNU -D__GNU_SOURCE -DFORTIFY_SOURCE=2

# Compilation
CFLAGS			:= $(CWARNS) -std=gnu99 -fPIC -Os -rdynamic -fmessage-length=0 -g3 -ggdb -c -MMD

# Linker Flags
LDFLAGS			:= -rdynamic

# External programs
AR			:= ar
LD			:= gcc
CC			:= gcc
MV			:= mv --force
RM			:= rm --force
RMDIR			:= rmdir --parents --ignore-fail-on-non-empty
MKDIR			:= mkdir --parents
RANLIB			:= ranlib

# Text coloring
RED			:= $$(tput setaf 1)
BLUE			:= $$(tput setaf 4)
GREEN			:= $$(tput setaf 2)
WHITE			:= $$(tput setaf 7)
YELLOW			:= $$(tput setaf 3)

# Text weighting
BOLD			:= $$(tput bold)
NORMAL			:= $$(tput sgr0)

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
	@echo 'Finished' $(BOLD)$(GREEN)$(TARGETGOAL)$(NORMAL)

# Construct the binary executable file
$(TOOL): $(OBJFILES)
	@echo 'Constructing' $(RED)$@$(NORMAL)
	@$(LD) $(LDFLAGS) --output='$@' $(OBJFILES) -Wl,--start-group $(STATIC) -Wl,--end-group $(DYNAMIC)
	@echo 'Finished' $(BOLD)$(GREEN)$(TARGETGOAL)$(NORMAL)

# Object files
$(OBJDIR)/%.o: %.c
	@echo 'Building' $(YELLOW)$<$(NORMAL)
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	@$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" "$<"

# If we've already generated dependency files, use them to see if a rebuild is required
-include $(DEPFILES)
