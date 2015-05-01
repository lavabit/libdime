CC	?= gcc
CWARNS	?= -Werror -Wall -Wextra -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes -Wstrict-overflow=5 -Wwrite-strings
# TODO: -Wconversion -Wpedantic

CDEBUG	?= -O0 -ggdb -g3

VERBOSE	?= no
