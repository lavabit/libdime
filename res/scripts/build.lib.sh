#!/bin/bash

LINK=`readlink -f $0`
BASE=`dirname $LINK`

cd $BASE/../../lib/

M_ROOT=`pwd`
M_BUILD=`../res/scripts/build.lib.sh`

# Set parent directory as project root by default (used to find scripts,
# bundled tarballs, patches, etc.)
if [ -z "$M_PROJECT_ROOT" ]; then
	M_PROJECT_ROOT=`readlink -f ..`
fi

# Read in the build parameters.
. "$M_PROJECT_ROOT/res/scripts/build.lib.params.sh"

error() {
	if [ $? -ne 0 ]; then
		tput sgr0; tput setaf 1
		#printf "\n\n$COMMAND failed...\n\n";
		date +"%n%n$COMMAND failed at %r on %x%n%n"
		tput sgr0
		exit 1
	fi
}

# Confirm whether we really want to run this service
extract() {
	if [ -d "$M_SOURCES/$2" ]; then
		rm -rf "$M_SOURCES/$2"; error
	fi
	tar xzvf "$M_ARCHIVES/$1.tar.gz" -C "$M_SOURCES"; error
	mv "$M_SOURCES/$1" "$M_SOURCES/$2"; error
}



zlib() {

	if [[ $1 == "zlib-extract" ]]; then
		rm -f "$M_LOGS/zlib.txt"; error
	elif [[ $1 != "zlib-log" ]]; then
		date +"%n%nStarted $1 at %r on %x%n%n" &>> "$M_LOGS/zlib.txt"
	fi

	case "$1" in
		zlib-extract)
			extract $ZLIB "zlib" &>> "$M_LOGS/zlib.txt"
		;;
		zlib-prep)
			# Apply RHEL zlib prep steps.
			cd "$M_SOURCES/zlib"; error
			if [[ $ZLIB == "1.2.3" ]]; then
				chmod -Rf a+rX,u+w,g-w,o-w . &>> "$M_LOGS/zlib.txt"; error
				cat "$M_PATCHES/zlib/"zlib-1.2.3-autotools.patch | patch -p1 -b --suffix .atools --fuzz=0 &>> "$M_LOGS/zlib.txt"; error
				mkdir m4 &>> "$M_LOGS/zlib.txt"; error
				cat "$M_PATCHES/zlib/"minizip-1.2.3-malloc.patch | patch -p1 -b --suffix .mal --fuzz=0 &>> "$M_LOGS/zlib.txt"; error
				iconv -f windows-1252 -t utf-8 <ChangeLog >ChangeLog.tmp &>> "$M_LOGS/zlib.txt"; error
				mv ChangeLog.tmp ChangeLog &>> "$M_LOGS/zlib.txt"; error
				cp Makefile Makefile.old &>> "$M_LOGS/zlib.txt"; error
			fi
		;;
		zlib-build)
			cd "$M_SOURCES/zlib"; error
			if [[ $ZLIB == "1.2.3" ]]; then
				export CFLAGS="-O2 -g3 -rdynamic -fPIC -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic"; error
				export CXXFLAGS="-O2 -g3 -rdynamic -fPIC -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic"; error
				export FFLAGS="-O2 -g3 -rdynamic -fPIC -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -I/usr/lib64/gfortran/modules"; error
				autoreconf --install &>> "$M_LOGS/zlib.txt"; error
				./configure --build=x86_64-unknown-linux-gnu --host=x86_64-unknown-linux-gnu --target=x86_64-redhat-linux-gnu \
				--prefix="$M_LOCAL" &>> "$M_LOGS/zlib.txt"; error
			else
				export CFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2"
				export FFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2"
				export CXXFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2"
				./configure --prefix="$M_LOCAL" --64 &>> "$M_LOGS/zlib.txt"; error
			fi
			unset CFLAGS; unset CXXFLAGS; unset FFLAGS

			make &>> "$M_LOGS/zlib.txt"; error
			make install &>> "$M_LOGS/zlib.txt"; error

			# Fool Autotools checks into thinking this is a normal OpenSSL install (e.g., clamav)
			ln -s `pwd` lib
			ln -s `pwd` include
		;;
		zlib-check)
			cd "$M_SOURCES/zlib"; error
			export LD_LIBRARY_PATH="$M_LDPATH"; error
			make check &>> "$M_LOGS/zlib.txt"; error
		;;
		zlib-check-full)
			cd "$M_SOURCES/zlib"; error
			export LD_LIBRARY_PATH="$M_LDPATH"; error
			make check &>> "$M_LOGS/zlib.txt"; error
		;;
		zlib-clean)
			cd "$M_SOURCES/zlib"; error
			make clean &>> "$M_LOGS/zlib.txt"; error
		;;
		zlib-tail)
			tail --lines=30 --follow=name --retry "$M_LOGS/zlib.txt"; error
		;;
		zlib-log)
			cat "$M_LOGS/zlib.txt"; error
		;;
		zlib)
			zlib "zlib-extract"
			zlib "zlib-prep"
			zlib "zlib-build"
			zlib "zlib-check"
		;;
		*)
			printf "\nUnrecognized request.\n"
			exit 2
		;;
	esac

	date +"Finished $1 at %r on %x"
	date +"%n%nFinished $1 at %r on %x%n%n" &>> "$M_LOGS/zlib.txt"

	return $?

}

openssl() {

	if [[ $1 == "openssl-extract" ]]; then
		rm -f "$M_LOGS/openssl.txt"; error
	elif [[ $1 != "openssl-log" ]]; then
		date +"%n%nStarted $1 at %r on %x%n%n" &>> "$M_LOGS/openssl.txt"
	fi

	case "$1" in
		openssl-extract)
			extract $OPENSSL "openssl" &>> "$M_LOGS/openssl.txt"
		;;
		openssl-prep)
			cd "$M_SOURCES/openssl"; error
		;;
		openssl-build)
			# OpenSSL does not use environment variables to pickup additional compiler flags
			# The -d param specifies the creation of a debug build
			# See here for reasoning behind openssl-specific linker flags:
			# https://mta.openssl.org/pipermail/openssl-users/2015-April/001053.html
			cd "$M_SOURCES/openssl"; error
        	grep "CentOS Linux release 7" /etc/system-release >& /dev/null
        	if [ $? == 0 ]; then
                	export CONFIGOPTS='-fno-merge-debug-strings '
        	fi
		    ./config \
		        -d shared zlib no-asm --openssldir="$M_LOCAL" \
				-I"$M_LOCAL/zlib" -O $CONFIGOPTS -g3 -rdynamic -fPIC -DPURIFY -D_FORTIFY_SOURCE=2 \
				-L"$M_LOCAL/lib" -Wl,-rpath,"$M_LOCAL/lib" &>> "$M_LOGS/openssl.txt"; error

			make depend &>> "$M_LOGS/openssl.txt"; error
			make &>> "$M_LOGS/openssl.txt"; error
			make install &>> "$M_LOGS/openssl.txt"; error
		;;
		openssl-check)
			cd "$M_SOURCES/openssl"; error
			export LD_LIBRARY_PATH="$M_LDPATH"; error
			make test &>> "$M_LOGS/openssl.txt"; error
		;;
		openssl-check-full)
			cd "$M_SOURCES/openssl"; error
			export LD_LIBRARY_PATH="$M_LDPATH"; error
			make test &>> "$M_LOGS/openssl.txt"; error
		;;
		openssl-clean)
			cd "$M_SOURCES/openssl"; error
			make clean &>> "$M_LOGS/openssl.txt"; error
		;;
		openssl-tail)
			tail --lines=30 --follow=name --retry "$M_LOGS/openssl.txt"; error
		;;
		openssl-log)
			cat "$M_LOGS/openssl.txt"; error
		;;
		openssl)
			openssl "openssl-extract"
			openssl "openssl-prep"
			openssl "openssl-build"
			openssl "openssl-check"
		;;
		*)
			printf "\nUnrecognized request.\n"
			exit 2
		;;
	esac

	date +"Finished $1 at %r on %x"
	date +"%n%nFinished $1 at %r on %x%n%n" &>> "$M_LOGS/openssl.txt"

	return $?

}

combine() {

	rm -f "$M_SO" &>> "$M_LOGS/combine.txt"; error


	rm -rf "$M_OBJECTS/zlib" &>> "$M_LOGS/combine.txt"; error
	mkdir "$M_OBJECTS/zlib" &>> "$M_LOGS/combine.txt"; error
	cd "$M_OBJECTS/zlib" &>> "$M_LOGS/combine.txt"; error

	if [[ $ZLIB == "1.2.3" ]]; then
		ar xv "$M_SOURCES/zlib/.libs/libz.a" &>> "$M_LOGS/combine.txt"; error
	else
		ar xv "$M_SOURCES/zlib/libz.a" &>> "$M_LOGS/combine.txt"; error
	fi

	rm -rf "$M_OBJECTS/crypto" &>> "$M_LOGS/combine.txt"; error
	mkdir "$M_OBJECTS/crypto" &>> "$M_LOGS/combine.txt"; error
	cd "$M_OBJECTS/crypto" &>> "$M_LOGS/combine.txt"; error
	ar xv "$M_SOURCES/openssl/libcrypto.a" &>> "$M_LOGS/combine.txt"; error

	rm -rf "$M_OBJECTS/ssl" &>> "$M_LOGS/combine.txt"; error
	mkdir "$M_OBJECTS/ssl" &>> "$M_LOGS/combine.txt"; error
	cd "$M_OBJECTS/ssl" &>> "$M_LOGS/combine.txt"; error
	ar xv "$M_SOURCES/openssl/libssl.a" &>> "$M_LOGS/combine.txt"; error
	
	gcc -Wl,-Bsymbolic -g3 -fPIC -rdynamic -shared -o "$M_SO" "$M_OBJECTS"/zlib/*.o "$M_OBJECTS"/crypto/*.o "$M_OBJECTS"/ssl/*.o \
		-lm -lrt -ldl -lnsl -lresolv -lpthread -lstdc++ &>> "$M_LOGS/combine.txt"; error

	# Commands for creating a static version of the library.
	rm -f "$M_AR"; error
	ar -r "$M_AR" "$M_OBJECTS"/zlib/*.o "$M_OBJECTS"/crypto/*.o "$M_OBJECTS"/ssl/*.o &>> "$M_LOGS/combine.txt"; error
	
	date +"Finished creating the shared object at %r on %x"
}

combo() {

	date +"%nStarting $1 at %r on %x%n" &>> "$M_LOGS/build.txt"

	($0 "zlib-$1") & ZLIB_PID=$!
	wait $ZLIB_PID; error
	
	($0 "openssl-$1") & OPENSSL_PID=$!
	wait $OPENSSL_PID; error

	date +"%nFinished $1 at %r on %x%n"
	date +"%nFinished $1 at %r on %x%n" &>> "$M_LOGS/build.txt"
}

follow() {
	# Note that the build.txt and combo.txt log files are intentionally excluded from this list because they don't belong to a bundled package file.
	tail -n 0 -F "$M_LOGS/openssl.txt" "$M_LOGS/zlib.txt"
}

log() {
	# Note that the build.txt and combo.txt log files are intentionally excluded from this list because they don't belong to a bundled package file.
	cat "$M_LOGS/zlib.txt" "$M_LOGS/openssl.txt"
}

advance() {
	shift
	echo "$@"
}

status() {

	CPU=`iostat cpu | head -4 | tail -2`
	DISK=`iostat -m -x sda sdb sdc vda vdb vdc | tail -n +6 | sed "s/Device:/device:/" | awk '{print $1 "\t  " $6 "\t" $7 "\t" $14}'`

	while true; do
		clear
		tput sgr0;  tput sgr 0 1; tput setaf 6; printf "\n# Commands\n\n"; tput sgr0
		ps --no-headers -C build.lib -C build.lib.sh -o command:100,etime | grep -v status | cat - |
		while read line; do
			BASE=`echo "$line" | awk '{print $1}'`
			line=`eval "advance $line"`
			C=`basename "$BASE"`
			if [[ "$C" == "bash" ]]; then
				BASE=`echo "$line" | awk '{print $1}'`
				line=`eval "advance $line"`
				C=`basename "$BASE"`
			fi
			echo "$C $line"
		done
		tput sgr0;  tput sgr 0 1; tput setaf 6; printf "\n# Load\n\n"; tput sgr0
		uptime | sed "s/^.*load average://" | awk -F',' '{print "avg-load: " $1 ", " $2 ", " $3 }'
		tput sgr0;  tput sgr 0 1; tput setaf 6; printf "\n# Processor\n\n"; tput sgr0
		echo "$CPU"
		tput sgr0;  tput sgr 0 1; tput setaf 6; printf "\n# Disk\n\n"; tput sgr0
		echo "$DISK"

		# Refresh the stats for the next loop; note that this takes 4 seconds to complete.
		CPU=`iostat cpu 4 2 | tail -5 | head -2`
		DISK=`iostat -m -x sda sdb sdc vda vdb vdc 4 2 | tail -3 | head -2 | sed "s/Device:/device:/" | awk '{print $1 "\t  " $6 "\t" $7 "\t" $14}'`
	done
}

all() {
	rm -f "$M_LOGS/build.txt"; error
	date +"%nStarting at %r on %x%n"
	date +"Starting at %r on %x" &>> "$M_LOGS/build.txt"
	$M_BUILD "extract"
	$M_BUILD "prep"
	$M_BUILD "build"
	$M_BUILD "combine"
	$M_BUILD "load"
	$M_BUILD "keys"
	$M_BUILD "check"
	date +"%nFinished at %r on %x%n"
	date +"Finished at %r on %x" &>> "$M_LOGS/build.txt"
}

# Store the command for failure messages
COMMAND="$@"

# Parent
if [[ "$PARENT" == "" ]]; then
	export PARENT="$BASHPID"
fi

# Setup
if [ ! -d "$M_SOURCES" ]; then mkdir "$M_SOURCES"; error; fi
if [ ! -d "$M_LOGS" ]; then mkdir "$M_LOGS"; error; fi
if [ ! -d "$M_OBJECTS" ]; then mkdir "$M_OBJECTS"; error; fi
if [ ! -d "$M_LOCAL" ]; then mkdir "$M_LOCAL"; error; fi

# Aggregations
if [[ $1 == "extract" ]]; then combo "$1"
elif [[ $1 == "prep" ]]; then  combo "$1"
elif [[ $1 == "build" ]]; then combo "$1"
elif [[ $1 == "check" ]]; then combo "$1"
elif [[ $1 == "check-full" ]]; then combo "$1"
elif [[ $1 == "clean" ]]; then combo "$1"

# Libraries
elif [[ $1 =~ "zlib" ]]; then (zlib "$1") & ZLIB_PID=$!; wait $ZLIB_PID
elif [[ $1 =~ "openssl" ]]; then (openssl "$1") & OPENSSL_PID=$!; wait $OPENSSL_PID

# Globals
elif [[ $1 == "combine" ]]; then combine
elif [[ $1 == "status" ]]; then status
elif [[ $1 == "follow" ]]; then follow
elif [[ $1 == "log" ]]; then log
elif [[ $1 == "all" ]]; then all

# If follow were called tail it would create a keyword conflict, but we still want to be able to use tail on the command line.
elif [[ $1 == "tail" ]]; then follow

# Catchall
else
	echo ""
	echo " Libraries"
	echo $"  `basename $0` {zlib|openssl} and/or "
	echo ""
	echo " Stages (which may be combined via a dash with the above)"
	echo $"  `basename $0` {extract|prep|build|check|check-full|clean|tail|log} or "
	echo ""
	echo " Global Commands"
	echo $"  `basename $0` {combine|follow|log|status|all}"
	echo ""
	echo " Please specify a library, a stage, a global command or a combination of library and stage."
	echo ""
	exit 2
fi

# Beep the speaker 10 times to let us know when 'all' is done or 3 times for something else.
if [[ "$PARENT" == "$BASHPID" ]]; then

	if [[ $1 == "all" ]]; then
		NUMS="1 2 3 4 5 6 7 8 9 10"
	else
		NUMS="1 2 3"
	fi

	for i in $NUMS; do
	  printf "\a"; sleep 1
	done

fi

exit 0
