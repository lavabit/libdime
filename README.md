DIME
=========
This project holds the DIME libraries and related command line utilities.

Dependencies
---------

System:
c dl rt pthread resolv

Bundled:
zlib openssl donna

Unit Tests:
python check

Directories
---------

Directory | Description
:--- | :---
libs/ | The DIME libraries
libs/core/ | Various string and other data manipulation functions take from the magma core component.
libs/common/ | Error handling, network and cryptographic functionality common to the remaining DIME libraries.
libs/signet/ | Signet data format handlier, including creation, signing, parsing and validating.
libs/signet-resolver/ | Logic retrieve and a management record and then an org or user signet, including relevant validation logic.
tools/ | The command line utilities.
tools/dime/ | Generate a DIME message and send it.
tools/signet/ | Generate, sign, view and verify a signet.
tools/res/ | Resource files used by the different components and utilities.
docs/ | Various related documents.
checks/ | Unit tests (eventually).
include/ | The header files provided by the library components.

Compiling
---------

First, build the third-party libraries

    (cd deps && ./build.sh)

Then:

    make all

or

    make libs
    make tools
    make clean

The specific make targets:

    make libcore
    make libcommon
    make libsignet
    make libsignet-resolver
    make signet
    make dime

Video
---------

An old/outdated video showing the components and command-line tools:

https://darkmail.info/downloads/dime-library-cli-demo.mp4
