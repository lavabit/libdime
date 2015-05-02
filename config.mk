CC	= gcc
CWARNS	?= -Werror -Wall -Wextra -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes -Wstrict-overflow=5 -Wwrite-strings

ifeq ($(CC),clang)
CWARNS	+= -ferror-limit=5
CWARNS	+= -Weverything
CWARNS	+= -Wno-bad-function-cast
CWARNS	+= -Wno-cast-align
CWARNS	+= -Wno-conditional-uninitialized
CWARNS	+= -Wno-conversion
CWARNS	+= -Wno-covered-switch-default
CWARNS	+= -Wno-disabled-macro-expansion
CWARNS	+= -Wno-documentation
CWARNS	+= -Wno-documentation-unknown-command
CWARNS	+= -Wno-float-equal
CWARNS	+= -Wno-gnu-designator
CWARNS	+= -Wno-packed
CWARNS	+= -Wno-padded
CWARNS	+= -Wno-pedantic
CWARNS	+= -Wno-shorten-64-to-32
CWARNS	+= -Wno-sign-conversion
CWARNS	+= -Wno-switch-enum
CWARNS	+= -Wno-unreachable-code
endif

ifeq ($(CC),gcc)
#CWARNS	+= -Wconversion
#CWARNS	+= -Wpedantic
endif

CDEBUG	?= -Os -ggdb -g3

VERBOSE	?= no
