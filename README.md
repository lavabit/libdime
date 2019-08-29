# Dark Internet Mail Environment (DIME)

## Introduction

Internet electronic mail (email) was designed in the early days of the Internet, and so
lacks any mechanism to protect the privacy of the sender and addressee. Several techniques
have been used in an attempt to increase the privacy of email. These techniques have provided
either modest increases in privacy, or have proven to be very difficult to use for most people.

In addition to protection of content, truly private email must limit information disclosed to 
handling agents, only exposing information necessary for delivery (the metadata), and provide robust
identity guarantees which prevent the impersonation of senders. 

The Dark Internet Mail Environment (DIME) achieves this level of privacy with core protocols
using multiple layers of key management and multiple layers of message encryption. The 
[DIME Protocol Specifications](https://darkmail.info/spec) (PDF, ~20 MB) contain the full technical details of 
the DIME.

The **libdime** project holds the DIME library and associated command line utilities. This code is 
developed in conjunction with the [magma](https://github.com/lavabit/magma) mail daemon, and is 
a community effort to develop and maintain a C library for building DIME compatible software, and
the standalone utilities to test, debug, and administer a DIME compatible mail service.

## Dependencies

Please see the [Quick Start Guide](res/docs/quickstart.md).

System:
c dl rt pthread resolv 

Bundled for DIME:
zlib openssl donna

Bundled for the Unit Tests
googletest gtest-tap-listener

## Supported Platforms

* CentOS 6 x86_64
* CentOS 7 x86_64

## Build Instructions

First, build the bundled dependencies:

    make setup

Then run:

    make all

The specific make targets:

    make dime
    make signet
    make genrec
    make libdime.a
    make libdime.so

Finally, to compile and run the unit tests use:

	make check
	
Or compile the check utility with the make target:

	make dime.check
	

## Directories

Directory | Description
:--- | :---
checs/ | The DIME unit test source code.
lib/ | The bundled dependencies. 
res/ | Resource files used by the different components and utilities.
sandbox/ | Where the unit tests store temporary resources..
src/ | The libdime source code.
tools/dime/ | Retrieve and validate a signet from a DIME compatible server using DMTP.
tools/signet/ | Generate, sign, view and verify a signet.
tools/genrec/ | Generate a DIME management record which must be added to the DNS zone file.

## Video

A slightly outdated video presentation of the DIME standard and the various command line tools:

https://www.youtube.com/watch?v=TWzvXaxR6us
