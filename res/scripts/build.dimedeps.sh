#!/bin/bash

LINK=`readlink -f $0`
BASE=`dirname $LINK`
M_BUILD=`readlink -f $0`

cd $BASE/../../lib/
M_ROOT=`pwd`

# Set parent directory as project root by default (used to find scripts,
# bundled tarballs, patches, etc.)
if [ -z "$M_PROJECT_ROOT" ]; then
  M_PROJECT_ROOT=`readlink -f ..`
fi

# Read in the build parameters.
. "$M_PROJECT_ROOT/res/scripts/build.dimedeps.params.sh"

# If the TERM environment variable is missing, then tput may trigger a fatal error.
if [[ -n "$TERM" ]] && [[ "$TERM" -ne "dumb" ]]; then
  export TPUT="tput"
else
  export TPUT="tput -Tvt100"
fi

# This undocumented environment variables makes it easy to use the "all" command line option, but skip still the
# normal dependency checks, this making the build process faster. The QUICK option is undocumented, because in general,
# developers interacting directly with the build.lib.sh script, should be running the "check" step to ensure
# they have a valid, and properly configured, and functional platform capable of running magma.
if [ -z QUICK ] || [ "$QUICK" != "yes" ]; then
  QUICK="no"
fi

error() {
  if [ $? -ne 0 ]; then
    ${TPUT} sgr0; ${TPUT} setaf 1
    #printf "\n\n$COMMAND failed...\n\n";
    date +"%n%n$COMMAND failed at %r on %x%n%n"
    ${TPUT} sgr0
    exit 1
  fi
}

silent() {
  if [ $? -ne 0 ]; then
    wait
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
      cd "$M_SOURCES/zlib"; error
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
      if [ "$QUICK" != "yes" ]; then zlib "zlib-check"; fi
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
      if [[ $OPENSSL =~ "openssl-1.0.2" ]]; then
        cat "$M_PATCHES/openssl/"1.0.2_curve25519_ed25519.patch | patch -p1 --verbose &>> "$M_LOGS/openssl.txt"; error
        cat "$M_PATCHES/openssl/"1.0.2_update_expiring_certificates.patch | patch -p1 --verbose &>> "$M_LOGS/openssl.txt"; error
      fi
    ;;
    openssl-build)
      # OpenSSL does not use environment variables to pickup additional compiler flags
      # The -d param specifies the creation of a debug build
      # See here for reasoning behind openssl-specific linker flags:
      # https://mta.openssl.org/pipermail/openssl-users/2015-April/001053.html
      cd "$M_SOURCES/openssl"; error
          grep -E "CentOS Linux release 7|Red Hat Enterprise.*release 7" /etc/system-release >& /dev/null
          if [ $? == 0 ]; then
                  export CONFIGOPTS='-fno-merge-debug-strings '
          fi
#        ./config \
#            -d shared zlib no-asm --openssldir="$M_LOCAL" --libdir="lib" \
#        -I"$M_SOURCES/zlib" -O $CONFIGOPTS -g3 -rdynamic -fPIC -DPURIFY -D_FORTIFY_SOURCE=2 \
#        -L"$M_SOURCES/openssl" -Wl,-rpath,"$M_SOURCES/openssl" \
#        -L"$M_SOURCES/zlib" -Wl,-rpath,"$M_SOURCES/zlib" \
#        &>> "$M_LOGS/openssl.txt"; error
#        
      ./config \
            -d shared zlib no-asm --openssldir="$M_LOCAL" --libdir="lib" \
        -I"$M_SOURCES/include/" -O $CONFIGOPTS -g3 -rdynamic -fPIC -DPURIFY -D_FORTIFY_SOURCE=2 \
        -L"$M_SOURCES/lib/" -Wl,-rpath,"$M_SOURCES/lib/" \
        &>> "$M_LOGS/openssl.txt"; error
      

      make depend &>> "$M_LOGS/openssl.txt"; error
      make &>> "$M_LOGS/openssl.txt"; error
      make install &>> "$M_LOGS/openssl.txt"; error

      # Fool autotools checks into thinking this is a normal OpenSSL install (e.g., ClamAV)
      ln -s `pwd` lib
    ;;
    openssl-check)
      cd "$M_SOURCES/openssl"; error
      export LD_LIBRARY_PATH="$M_LDPATH"; error
      export PATH="$M_BNPATH:$PATH"; error
      make test &>> "$M_LOGS/openssl.txt"; error
    ;;
    openssl-check-full)
      cd "$M_SOURCES/openssl"; error
      export LD_LIBRARY_PATH="$M_LDPATH"; error
      export PATH="$M_BNPATH:$PATH"; error
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
      if [ "$QUICK" != "yes" ]; then openssl "openssl-check"; fi
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

utf8proc() {

  if [[ $1 == "utf8proc-extract" ]]; then
    rm -f "$M_LOGS/utf8proc.txt"; error
  elif [[ $1 != "utf8proc-log" ]]; then
    date +"%n%nStarted $1 at %r on %x%n%n" &>> "$M_LOGS/utf8proc.txt"
  fi

  case "$1" in
    utf8proc-extract)
      extract $UTF8PROC "utf8proc" &>> "$M_LOGS/utf8proc.txt"
      tar xzvf "$M_ARCHIVES/$UTF8PROCTEST.tar.gz" --directory="$M_SOURCES/utf8proc/data" &>> "$M_LOGS/utf8proc.txt"; error
    ;;
    utf8proc-prep)
      cd "$M_SOURCES/utf8proc"; error
      if [[ $UTF8PROC == "1.3.1" ]]; then
        cat "$M_PATCHES/utf8proc/"utf8proc.release.version.patch | patch -p1 --verbose &>> "$M_LOGS/utf8proc.txt"; error
      fi
    ;;
    utf8proc-build)
      cd "$M_SOURCES/utf8proc"; error
      export CFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2 -O2"
      make prefix="$M_LOCAL" &>> "$M_LOGS/utf8proc.txt"; error
      make prefix="$M_LOCAL" install &>> "$M_LOGS/utf8proc.txt"; error
      unset CFLAGS;
    ;;
    utf8proc-check)
      cd "$M_SOURCES/utf8proc"; error
      export LD_LIBRARY_PATH="$M_LDPATH"; error
      make check &>> "$M_LOGS/utf8proc.txt"; error
    ;;
    utf8proc-check-full)
      cd "$M_SOURCES/utf8proc"; error
      export LD_LIBRARY_PATH="$M_LDPATH"; error
      make check &>> "$M_LOGS/utf8proc.txt"; error
    ;;
    utf8proc-clean)
      cd "$M_SOURCES/utf8proc"; error
      make clean &>> "$M_LOGS/utf8proc.txt"; error
    ;;
    utf8proc-tail)
      tail --lines=30 --follow=name --retry "$M_LOGS/utf8proc.txt"; error
    ;;
    utf8proc-log)
      cat "$M_LOGS/utf8proc.txt"; error
    ;;
    utf8proc)
      utf8proc "utf8proc-extract"
      utf8proc "utf8proc-prep"
      utf8proc "utf8proc-build"
      if [ "$QUICK" != "yes" ]; then utf8proc "utf8proc-check"; fi
    ;;
    *)
      printf "\nUnrecognized request.\n"
      exit 2
    ;;
  esac

  date +"Finished $1 at %r on %x"
  date +"%n%nFinished $1 at %r on %x%n%n" &>> "$M_LOGS/spf2.txt"

  return $?

}

googtap() {

  if [[ $1 == "googtap-extract" ]]; then
    rm -f "$M_LOGS/googtap.txt"; error
  elif [[ $1 != "googtap-log" ]]; then
    date +"%n%nStarted $1 at %r on %x%n%n" &>> "$M_LOGS/googtap.txt"
  fi

  case "$1" in
    googtap-extract)
      extract $GOOGTAP "googtap" &>> "$M_LOGS/googtap.txt"
    ;;
    googtap-prep)
      cd "$M_SOURCES/googtap"; error
    ;;
    googtap-build)
      cd "$M_SOURCES/googtap"; error
    ;;
    googtap-check)
      cd "$M_SOURCES/googtap"; error
    ;;
    googtap-check-full)
      cd "$M_SOURCES/googtap"; error
    ;;
    googtap-clean)
      cd "$M_SOURCES/googtap"; error
    ;;
    googtap-tail)
      tail --lines=30 --follow=name --retry "$M_LOGS/googtap.txt"; error
    ;;
    googtap-log)
      cat "$M_LOGS/googtap.txt"; error
    ;;
    googtap)
      googtap "googtap-extract"
      googtap "googtap-prep"
      googtap "googtap-build"
      if [ "$QUICK" != "yes" ]; then googtap "googtap-check"; fi
    ;;
    *)
      printf "\nUnrecognized request.\n"
      exit 2
    ;;
  esac

  date +"Finished $1 at %r on %x"
  date +"%n%nFinished $1 at %r on %x%n%n" &>> "$M_LOGS/googtap.txt"

  return $?

}

googtest() {

  if [[ $1 == "googtest-extract" ]]; then
    rm -f "$M_LOGS/googtest.txt"; error
  elif [[ $1 != "googtest-log" ]]; then
    date +"%n%nStarted $1 at %r on %x%n%n" &>> "$M_LOGS/googtest.txt"
  fi

  case "$1" in
    googtest-extract)
      extract $GOOGTEST "googtest" &>> "$M_LOGS/googtest.txt"
    ;;
    googtest-prep)
      cd "$M_SOURCES/googtest"; error
    ;;
    googtest-build)
      cd "$M_SOURCES/googtest"; error
      export CFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2"
      export CXXFLAGS="-fPIC -g3 -rdynamic -D_FORTIFY_SOURCE=2"

      autoreconf --install &>> "$M_LOGS/googtest.txt"; error
      ./configure --prefix="$M_LOCAL" &>> "$M_LOGS/googtest.txt"; error
      unset CFLAGS; unset CXXFLAGS

      make &>> "$M_LOGS/googtest.txt"; error
    ;;
    googtest-check)
      cd "$M_SOURCES/googtest"; error
      make check &>> "$M_LOGS/googtest.txt"; error

      mkdir build && cd build; error
      cmake -Dgtest_build_samples=ON "$M_SOURCES/googtest" &>> "$M_LOGS/googtest.txt"; error
      make &>> "$M_LOGS/googtest.txt"; error
      ./sample1_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample2_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample3_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample4_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample5_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample6_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample7_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample8_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample9_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample10_unittest &>> "$M_LOGS/googtest.txt"; error
    ;;
    googtest-check-full)
      cd "$M_SOURCES/googtest"; error
      make check &>> "$M_LOGS/googtest.txt"; error

      mkdir build && cd build; error
      cmake -Dgtest_build_samples=ON "$M_SOURCES/googtest" &>> "$M_LOGS/googtest.txt"; error
      make &>> "$M_LOGS/googtest.txt"; error
      ./sample1_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample2_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample3_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample4_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample5_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample6_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample7_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample8_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample9_unittest &>> "$M_LOGS/googtest.txt"; error
      ./sample10_unittest &>> "$M_LOGS/googtest.txt"; error
    ;;
    googtest-clean)
      cd "$M_SOURCES/googtest"; error
      make clean &>> "$M_LOGS/googtest.txt"; error
    ;;
    googtest-tail)
      tail --lines=30 --follow=name --retry "$M_LOGS/googtest.txt"; error
    ;;
    googtest-log)
      cat "$M_LOGS/googtest.txt"; error
    ;;
    googtest)
      googtest "googtest-extract"
      googtest "googtest-prep"
      googtest "googtest-build"
      if [ "$QUICK" != "yes" ]; then googtest "googtest-check"; fi
    ;;
    *)
      printf "\nUnrecognized request.\n"
      exit 2
    ;;
  esac

  date +"Finished $1 at %r on %x"
  date +"%n%nFinished $1 at %r on %x%n%n" &>> "$M_LOGS/googtest.txt"

  return $?

}

combo() {

  date +"%nStarting $1 at %r on %x%n" &>> "$M_LOGS/build.txt"

  # OpenSSL needs zlib to finish or it won't configure/build correctly.
  ($M_BUILD "zlib-$1") & ZLIB_PID=$!
  wait $ZLIB_PID; error

  ($M_BUILD "openssl-$1") & OPENSSL_PID=$!
  ($M_BUILD "utf8proc-$1") & UTF8PROC_PID=$!
  ($M_BUILD "googtest-$1") & GOOGTEST_PID=$!
  ($M_BUILD "googtap-$1") & GOOGTAP_PID=$!
  wait $OPENSSL_PID; error
  wait $UTF8PROC_PID; error
  wait $GOOGTEST_PID; error
  wait $GOOGTAP_PID; error

  date +"%nFinished $1 at %r on %x%n"
  date +"%nFinished $1 at %r on %x%n" &>> "$M_LOGS/build.txt"
}

follow() {
  # Note that the build.txt and combo.txt log files are intentionally excluded from this list because they don't belong to a bundled package file.
  tail -n 0 -F "$M_LOGS/googtest.txt" "$M_LOGS/googtap.txt" "$M_LOGS/openssl.txt" "$M_LOGS/utf8proc.txt" "$M_LOGS/zlib.txt"
}

log() {
  # Note that the build.txt and combo.txt log files are intentionally excluded from this list because they don't belong to a bundled package file.
  cat "$M_LOGS/zlib.txt" "$M_LOGS/openssl.txt" "$M_LOGS/utf8proc.txt" "$M_LOGS/googtap.txt" "$M_LOGS/googtest.txt"
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
    ${TPUT} sgr0;  ${TPUT} sgr 0 1; ${TPUT} setaf 6; printf "\n# Commands\n\n"; ${TPUT} sgr0
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
    ${TPUT} sgr0;  ${TPUT} sgr 0 1; ${TPUT} setaf 6; printf "\n# Load\n\n"; ${TPUT} sgr0
    uptime | sed "s/^.*load average://" | awk -F',' '{print "avg-load: " $1 ", " $2 ", " $3 }'
    ${TPUT} sgr0;  ${TPUT} sgr 0 1; ${TPUT} setaf 6; printf "\n# Processor\n\n"; ${TPUT} sgr0
    echo "$CPU"
    ${TPUT} sgr0;  ${TPUT} sgr 0 1; ${TPUT} setaf 6; printf "\n# Disk\n\n"; ${TPUT} sgr0
    echo "$DISK"

    # Refresh the stats for the next loop; note that this takes 4 seconds to complete.
    CPU=`iostat cpu 4 2 | tail -5 | head -2`
    DISK=`iostat -m -x sda sdb sdc vda vdb vdc 4 2 | tail -3 | head -2 | sed "s/Device:/device:/" | awk '{print $1 "\t  " $6 "\t" $7 "\t" $14}'`
  done
}

all() {
  rm -f "$M_LOGS/build.txt"; silent
  date +"%nStarting at %r on %x%n"
  date +"Starting at %r on %x" &>> "$M_LOGS/build.txt"
  $M_BUILD "extract"; silent
  $M_BUILD "prep"; silent
  $M_BUILD "build"; silent
  
  # Quick builds don't run the dependency checks, and/or unit tests.
  if [ "$QUICK" != "yes" ]; then
    $M_BUILD "check"; silent
  fi

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
if [ ! -d "$M_SOURCES" ]; then mkdir -p "$M_SOURCES"; error; fi
if [ ! -d "$M_LOGS" ]; then mkdir -p "$M_LOGS"; error; fi
if [ ! -d "$M_OBJECTS" ]; then mkdir -p "$M_OBJECTS"; error; fi
if [ ! -d "$M_LOCAL" ]; then mkdir -p "$M_LOCAL"; error; fi

# Aggregations
if [[ $1 == "extract" ]]; then combo "$1"
elif [[ $1 == "prep" ]]; then  combo "$1"
elif [[ $1 == "build" ]]; then combo "$1"
elif [[ $1 == "check" ]]; then combo "$1"
elif [[ $1 == "check-full" ]]; then combo "$1"
elif [[ $1 == "clean" ]]; then combo "$1"

# Libraries
elif [[ $1 =~ "zlib" ]]; then zlib "$1"
elif [[ $1 =~ "openssl" ]]; then openssl "$1"
elif [[ $1 =~ "utf8proc" ]]; then utf8proc "$1"
elif [[ $1 =~ "googtap" ]]; then googtap "$1"
elif [[ $1 =~ "googtest" ]]; then googtest "$1"

# Globals
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
  echo $"  `basename $0` {zlib|openssl|utf8proc|googtest|googtap} and/or "
  echo ""
  echo " Stages (which may be combined via a dash with the above)"
  echo $"  `basename $0` {extract|prep|build|check|check-full|clean|tail|log} or "
  echo ""
  echo " Global Commands"
  echo $"  `basename $0` {follow|log|status|all}"
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
