#Quick Start Guide

##Technologies used

###System
* C
* dl [TLDP tutorial](http://www.tldp.org/HOWTO/Program-Library-HOWTO/dl-libraries.html)
* rt 
* pthread [LLNL pthread tutorial](https://computing.llnl.gov/tutorials/pthreads/)
* resolv

###Bundled
* zlib [zlib site](http://www.zlib.org)
* openssl [openssl site](http://www.openssl.org) and [linux tutorial](http://tldp.org/LDP/LG/issue87/vinayak.html)
* donna 

###Unit Testing
* python [python site](https://www.python.org/)
* check [check site](http://check.sourceforge.net/)

##Supported Platforms

* CentOS 6 x86_64
* CentOS 7 x86_64

See the [CentOS Official Site](http://www.centos.org/) for informatino and downloads.

##Source Code Directories

Directory | Description
:--- | :---
libs/ | The DIME libraries
libs/core/ | Various string and other data manipulation functions taken from the magma core component.
libs/common/ | Error handling, network and cryptographic functionality common to the remaining DIME libraries.
libs/signet/ | Signet data format handler, including creation, signing, parsing and validating.
libs/signet-resolver/ | Logic to retrieve management records then the signets for users or organizations, including the relevant validation logic.
tools/ | The command line utilities.
tools/dime/ | Generate a DIME message and send it.
tools/signet/ | Generate, sign, view and verify a signet.
res/ | Resource files used by the different components and utilities.
checks/ | Unit tests (eventually).
include/ | The header files provided by the library components.

##Compiling

First, build the third-party libraries

```sh
    (cd deps && ./build.sh)
```

Then:

```sh
    make all
```

or

```sh
    make libs
    make tools
    make clean
```

The specific make targets:

```sh
    make libcore
    make libcommon
    make libsignet
    make libsignet-resolver
    make signet
    make dime
```

