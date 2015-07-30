#!/bin/sh

# Example usage: ./coverage.sh -j4

ROOT_DIR=`git rev-parse --show-toplevel`
COVERAGE_DIR="$ROOT_DIR/build/coverage"
REPORT_DIR="$COVERAGE_DIR/report"
if [ -d "$COVERAGE_DIR" ]; then
	cd "$COVERAGE_DIR"
else
	mkdir -p "$COVERAGE_DIR"
	cd "$COVERAGE_DIR"
	"$ROOT_DIR/configure" \
		CFLAGS="-O0 -g --coverage" \
		CXXFLAGS="-O0 -g --coverage" \
		LDFLAGS="--coverage"
fi
make "$@" check
mkdir -p "$REPORT_DIR"
gcovr -r "$ROOT_DIR" --branches --html --html-details -o "$REPORT_DIR/index.html"
