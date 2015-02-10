
all:	lib tools

lib: 
	@echo Building libraries...
	make -C lib/core

tools: 
	@echo Building applications...
	#make -C tools

check:	check
	#make -C check

clean: 
	#make -C check clean
	#make -C tools clean
	make -C lib/core clean

.PHONY:	all lib tools check clean
