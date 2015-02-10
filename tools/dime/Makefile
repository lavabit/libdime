include ../Makefile.common

all: app

app:	dime genrec cachedump x ed25519 #dmtp

dime:	main.c
	$(CC) $(CFLAGS) $(INC) -o ../dime main.c -Wl,--start-group,../../libsignet/libsignet.a,../../libcommon/libcommon.a,../libdime.a,--end-group -lz -lresolv

x:	x.c
	$(CC) $(CFLAGS) $(INC) -o ../x x.c ../libdime.a ../../libsignet/libsignet.a $(LIBS)

genrec:	genrec.c
	$(CC) $(CFLAGS) $(INC) -o ../genrec genrec.c ../libdime.a ../../libsignet/libsignet.a $(LIBS)

cachedump: cachedump.c
	$(CC) $(CFLAGS) $(INC) -o ../cachedump cachedump.c ../libdime.a ../../libsignet/libsignet.a $(LIBS)

ed25519: ed25519.c
	$(CC) $(CFLAGS) $(INC) -o ../ed25519 ed25519.c ../../libsignet/libsignet.a $(LIBS)

#dmtp: dmtp.c
#	$(CC) $(CFLAGS) $(INC) -I../../libdmsg/include -I../../libcore/include -o ../dmtp dmtp.c -Wl,--start-group,../../libsignet/libsignet.a,../../libcommon/libcommon.a,../../libdmsg/libdmsg.a,../../libcore/libcore.a,../libdime.a,--end-group -lz -lresolv -lpthread

clean:	
	@echo "Cleaning the app files..."
	@if test -f ../dime; then echo rm ../dime; rm ../dime; fi 
	@if test -f ../genrec; then echo rm ../genrec; rm ../genrec; fi 
	@if test -f ../cachedump; then echo rm ../cachedump; rm ../cachedump; fi 
	@if test -f ../x; then echo rm ../x; rm ../x; fi 
	@if test -f ../ed25519; then echo rm ../ed25519; rm ../ed25519; fi 
	@if test -f ../dmtp; then echo rm ../dmtp; rm ../dmtp; fi 
	
.PHONY: all app clean
