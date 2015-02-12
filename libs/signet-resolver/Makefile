
# Module name
ARCHIVE			:= libsignet-resolver.a

# The list of include paths
INCLUDES		:= -I../../include/ -I../../include/common/ -I../../deps/sources/donna -I../../deps/sources/openssl/include

# Defines
DEFINES			:= -D_REENTRANT -D_GNU_SOURCE -DFORTIFY_SOURCE=2

# Source files
SRCFILES := \
cache_pub.c \
cache.c \
dmtp_pub.c \
dmtp.c \
dns_pub.c \
dns.c \
mrec_pub.c \
mrec.c \
ssl_pub.c \
ssl.c

# Compilation and Linker Flags
CFLAGS			:= -Wall -Werror -std=gnu99 -fPIC -O0 -rdynamic -fmessage-length=0 -g3 -ggdb -c -MMD 
ARFLAGS			:= rcs 

# External programs
AR			:= ar
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
.PHONY: all clean libs $(basename $(ARCHIVE))
all: $(ARCHIVE)
libs: $(ARCHIVE)
$(basename $(ARCHIVE)): $(ARCHIVE)

# Delete the archive along with the generated object and dependency files
clean:
	@$(RM) $(ARCHIVE) $(OBJFILES) $(DEPFILES)
	@for d in $(sort $(dir $(OBJFILES))); do if test -d "$$d"; then $(RMDIR) "$$d"; fi; done
	@for d in $(sort $(dir $(DEPFILES))); do if test -d "$$d"; then $(RMDIR) "$$d"; fi; done
	@echo 'Finished' $(BOLD)$(GREEN)$(TARGETGOAL)$(NORMAL)

# Construct the static archive file
$(ARCHIVE): $(OBJFILES)
	@echo 'Constructing' $(RED)$@$(NORMAL)
	@$(AR) $(ARFLAGS) $@ $(OBJFILES)
	@$(RANLIB) $@
	@echo 'Finished' $(BOLD)$(GREEN)$(TARGETGOAL)$(NORMAL)

# Object files
$(OBJDIR)/%.o: %.c
	@echo 'Building' $(YELLOW)$<$(NORMAL)
	@test -d $(DEPDIR)/$(dir $<) || $(MKDIR) $(DEPDIR)/$(dir $<)
	@test -d $(OBJDIR)/$(dir $<) || $(MKDIR) $(OBJDIR)/$(dir $<)
	@$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -MF"$(<:%.c=$(DEPDIR)/%.d)" -MT"$@" -o"$@" "$<"

# If we've already generated dependency files, use them to see if a rebuild is required
-include $(DEPFILES)
