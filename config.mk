CWARNS	?= -Werror -Wall -Wextra -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
# TODO: -Wstrict-overflow=5 -Wwrite-strings -Wconversion -Wstrict-prototypes -Wmissing-prototypes -Wpedantic

CDEBUG	?=	-O0 -ggdb -g3

ifeq ($(V),1)
RUN		=
else
RUN		= @
endif
