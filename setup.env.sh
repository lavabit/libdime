#!/bin/bash

echo PKG_CONFIG_PATH=../magma/lib/local/lib/pkgconfig/
echo LDFLAGS=-L../magma/lib/local/lib
echo CFLAGS=-I../magma/lib/local/include
echo LD_LIBRARY_PATH=$../magma/lib/local/lib

# An alternative version of the above that makes different assumptions.

#export PKG_CONFIG_PATH=$HOME/Lavabit/magma/lib/local/lib/pkgconfig/
#export LDFLAGS=-L$HOME/Lavabit/magma/lib/local/lib
#export CFLAGS=-I$HOME/Lavabit/magma/lib/local/include
#export LD_LIBRARY_PATH=$HOME/Lavabit/magma/lib/local/lib
