#!/bin/bash

ZLIB="zlib-1.2.8"
OPENSSL="openssl-1.0.1l"
DONNA="ed25519-donna"

M_ROOT=`pwd`

M_ARCHIVES="$M_ROOT/archives"
M_PATCHES="$M_ROOT/patches"
M_SOURCES="$M_ROOT/sources"

M_LDPATH="$M_SOURCES/openssl/engines/:$M_SOURCES/openssl/"
