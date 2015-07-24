#!/bin/sh

# Example usage: ./clang_scan.sh -j4

ROOT_DIR=`git rev-parse --show-toplevel`
SCAN_DIR="$ROOT_DIR/build_scan"
REPORT_DIR="$SCAN_DIR/report"
rm -rf "$SCAN_DIR"
mkdir -p "$SCAN_DIR"
cd "$SCAN_DIR"
"$ROOT_DIR/configure"
mkdir -p "$REPORT_DIR"
scan-build -o "$REPORT_DIR/index.html" make "$@"
