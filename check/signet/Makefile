include ../Makefile.common

LIBS := -lcheck $(LIBS)

all:	build runcheck

signet.check:	build

build:	check_signet.c
	$(CC) $(CFLAGS) $(INC) -o ../signet.check check_signet.c ../libsignet.a $(LIBS)

runcheck:
	@echo Running check...
	@../signet.check

clean:
	@echo Cleaning up the checks...
	@if test -f ../signet.check; then \
		echo "rm ../signet.check"; rm ../signet.check; \
	fi

.PHONY:	all build runcheck clean
