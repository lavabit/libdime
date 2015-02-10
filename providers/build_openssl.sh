#!/bin/bash

if [ -f params.sh ]; then
	. params.sh
else
	echo "ERROR: no params.sh. Please double-check you are at libcommon/providers directory"
	exit 1
fi

error() {

	if [ $? -ne 0 ]; then
		tput sgr0; tput setaf 1
  		date +"%n%nProvider installation failed at %r on %x%n%n"
		tput sgr0
		exit 1
	fi

}


extract() {
	if [ -d "$M_SOURCES/$2" ]; then
		rm -rf "$M_SOURCES/$2"; error
	fi
	tar xzvf "$M_ARCHIVES/$1.tar.gz" -C "$M_SOURCES"; error
	mv "$M_SOURCES/$1" "$M_SOURCES/$2"; error
}


zlib() { 
	
	case "$1" in
		zlib-extract)
	  		extract $ZLIB "zlib"
		;;
		zlib-prep)
			# Apply RHEL zlib prep steps.
			cd "$M_SOURCES/zlib"; error
			if [[ $ZLIB == "1.2.3" ]]; then	
				chmod -Rf a+rX,u+w,g-w,o-w . ; error
				cat "$M_PATCHES/zlib/"zlib-1.2.3-autotools.patch | patch -p1 -b --suffix .atools --fuzz=0 ; error
				mkdir m4 ; error
				cat "$M_PATCHES/zlib/"minizip-1.2.3-malloc.patch | patch -p1 -b --suffix .mal --fuzz=0 ; error
				iconv -f windows-1252 -t utf-8 <ChangeLog >ChangeLog.tmp ; error
				mv ChangeLog.tmp ChangeLog ; error
				cp Makefile Makefile.old ; error
			fi
		;;
		zlib-configure)
			cd "$M_SOURCES/zlib"; error
			if [[ $ZLIB == "1.2.3" ]]; then	
				export CFLAGS='-O2 -g3 -rdynamic -fPIC -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic'; error
				export CXXFLAGS='-O2 -g3 -rdynamic -fPIC -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic'; error
				export FFLAGS='-O2 -g3 -rdynamic -fPIC -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -I/usr/lib64/gfortran/modules'; error
				autoreconf --install ; error
				./configure --build=x86_64-unknown-linux-gnu --host=x86_64-unknown-linux-gnu --target=x86_64-redhat-linux-gnu ; error
			else
				export CFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2"
				export FFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2"
				export CXXFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2"
				./configure --64 ; error
			fi
			unset CFLAGS; unset CXXFLAGS; unset CPPFLAGS
		;;
		zlib-build)
			cd "$M_SOURCES/zlib"; error
			make ; error
		;;
		zlib-check)
			cd "$M_SOURCES/zlib"; error
			export LD_LIBRARY_PATH="$M_LDPATH"; error
			make check ; error
		;;
		zlib-check-full)
			cd "$M_SOURCES/zlib"; error
			export LD_LIBRARY_PATH="$M_LDPATH"; error
			make check ; error
		;;
		zlib-clean)
			cd "$M_SOURCES/zlib"; error
			make clean ; error
		;;
		zlib)
			zlib "zlib-extract"
			zlib "zlib-prep"
			zlib "zlib-configure"
			zlib "zlib-build"
			zlib "zlib-check"
		;;
		*)
			printf "\nUnrecognized request.\n"
			exit 2
		;;
	esac
	
}


openssl() { 
	
	case "$1" in
		openssl-extract)
	  		extract $OPENSSL "openssl"
		;;
		openssl-prep)
			# OpenSSL 1.0.0b has a known bug
			# http://www.mail-archive.com/openssl-dev@openssl.org/msg28468.html
			# http://cvs.openssl.org/chngview?cn=19998
			cd "$M_SOURCES/openssl"; error
			if [[ $OPENSSL == "openssl-1.0.0b" ]]; then	cat "$M_PATCHES/openssl/1.0.0b_SSL_server_fix.patch" | patch -p1 --batch ; error; fi
			if [[ $OPENSSL == "openssl-1.0.1i" ]]; then	cat "$M_PATCHES/openssl/checkhost.patch" | patch -p1 --batch ; error; fi
		;;
		openssl-configure)
			# OpenSSL does not use environment variables to pickup additional compiler flags
			# The -d param specifies the creation of a debug build
			cd "$M_SOURCES/openssl"; error
			./config -d shared zlib no-dso no-asm --openssldir="$M_SOURCES/openssl" -g3 -rdynamic -fPIC -DPURIFY -D_FORTIFY_SOURCE=2 ; error
		;;
		openssl-build)
			cd "$M_SOURCES/openssl"; error
			make ; error
			make install_docs ; error
		;;
		openssl-check)
			cd "$M_SOURCES/openssl"; error
			export LD_LIBRARY_PATH="$M_LDPATH"; error
			make test ; error
		;;
		openssl-check-full)
			cd "$M_SOURCES/openssl"; error
			export LD_LIBRARY_PATH="$M_LDPATH"; error
			make test ; error
		;;
		openssl-clean)
			cd "$M_SOURCES/openssl"; error
			make clean ; error
		;;
		openssl)
			openssl "openssl-extract"
			openssl "openssl-prep"
			openssl "openssl-configure"
			openssl "openssl-build"
			openssl "openssl-check"
		;;
		*)
			printf "\nUnrecognized request.\n"
			exit 2
		;;
	esac
}


donna() { 
	
	case "$1" in
		donna-extract)
	  		extract $DONNA "donna"
		;;
		donna-prep)
			# nothing to do here
		;;
		donna-configure)
			# nothing to do here either
		;;
		donna-build)
			cd "$M_SOURCES/donna"; error
			make ; error
		;;
		donna-check)
		;;
		donna-check-full)
		;;
		donna-clean)
			cd "$M_SOURCES/donna"; error
			make clean ; error
		;;
		donna)
			donna "donna-extract"
			donna "donna-prep"
			donna "donna-configure"
			donna "donna-build"
			donna "donna-check"
		;;
		*)
			printf "\nUnrecognized request.\n"
			exit 2
		;;
	esac
}

openssl openssl-extract
openssl openssl-prep
openssl openssl-configure
openssl openssl-build
