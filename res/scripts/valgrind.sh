#!/bin/bash

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
make "$@" check TESTS_ENVIRONMENT=true
valgrind --leak-check=yes --log-file="$DEBUG_DIR/valgrind.log" ./gtest
cat "$DEBUG_DIR/valgrind.log"
