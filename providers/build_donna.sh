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

donna donna-extract
donna donna-build
