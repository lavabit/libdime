include ../Makefile.common

LIBS	:= ../libsignet.a  $(LIBS)

app:	app.c
	$(CC) $(CFLAGS) $(INC) -o ../signet app.c $(LIBS)

clean:
	@echo Cleaning application data...
	@if test -f ../signet; then \
		echo "rm ../signet"; rm ../signet; \
	fi
