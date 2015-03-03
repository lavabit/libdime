
# Module name
ARCHIVE			:= libcore.a


# Source files
SRCFILES := buckets/arrays.c buckets/pool.c buckets/stacked.c classify/ascii.c compare/search.c compare/equal.c \
compare/ends.c compare/starts.c encodings/base64.c encodings/hex.c encodings/qp.c encodings/url.c encodings/mappings.c \
encodings/zbase32.c hash/adler.c hash/fletcher.c hash/crc.c hash/murmur.c host/files.c host/host.c host/spool.c \
host/folder.c host/mappings.c host/process.c indexes/inx.c indexes/hashed.c indexes/cursors.c indexes/linked.c \
log/log.c mail/counters.c mail/mime.c mail/headers.c memory/align.c memory/bits.c memory/memory.c memory/secure.c \
parsers/trim.c parsers/line.c parsers/time.c parsers/numbers/numbers.c parsers/numbers/digits.c parsers/case.c \
parsers/formats/nvp.c parsers/token.c parsers/special/bracket.c strings/opts.c strings/info.c strings/length.c \
strings/allocation.c strings/replace.c strings/data.c strings/print.c strings/multi.c strings/validate.c \
strings/shortcuts.c strings/nuller.c thread/rwlock.c thread/keys.c thread/thread.c thread/mutex.c global.c other.c \
type.c


# The list of include paths
INCLUDES		:= -I../../include/ -I../../include/core/ -I../../include/common/ -I../../deps/sources/donna -I../../deps/sources/openssl/include









########################################################
# You shouldn't need to edit anything below this line. #
########################################################


# Defines
DEFINES			:= -D_REENTRANT -D_GNU_SOURCE -DFORTIFY_SOURCE=2

# Compiler Flags
CFLAGS			:= -Wall -Werror -std=gnu99 -fPIC -O0 -rdynamic -fmessage-length=0 -g3 -ggdb -c -MMD

# Archiver Flags
ARFLAGS			:= rcs 

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
