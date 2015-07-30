#!/bin/sh

# Example usage: scripts/test.sh -j4

ROOT_DIR=`git rev-parse --show-toplevel`
DEBUG_DIR="$ROOT_DIR/build/debug"
if [ -d "$DEBUG_DIR" ]; then
	cd "$DEBUG_DIR"
else
	mkdir -p "$DEBUG_DIR"
	cd "$DEBUG_DIR"
	"$ROOT_DIR/configure" \
		CFLAGS="-O0 -g" \
		CXXFLAGS="-O0 -g"
fi
make "$@" check
