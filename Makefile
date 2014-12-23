include Makefile.common

all:	libraries applications

check:	libraries app
	@echo Building and executing the unit tests...
	make -C checks

applications: libraries
	@echo Building applications...
	make -C app

libraries:
	@echo Building libraries...
	make -C lib

clean:	
	make -C checks clean
	make -C app clean
	make -C lib clean
