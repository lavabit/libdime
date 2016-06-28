#Dark Internet Mail Environment (DIME)

##Introduction

Internet electronic mail (email) was designed in the early days of the Internet, and so
lacks any mechanism to protect the privacy of the sender and addressee. Several techniques
have been used in an attempt to increase the privacy of email. These techniques have provided
either modest increases in privacy, or have proven to be very difficult to use for most people.

In addition to protection of content, truly private email must limit information disclosed to 
handling agents, only exposing information necessary for delivery (the metadata), and provide robust
identity guarantees which prevent the impersonation of senders. 

The Dark Internet Mail Environment (DIME) achieves this level of privacy with core protocols
using multiple layers of key management and multiple layers of message encryption.
The [DIME Protocol Specifications](https://darkmail.info/spec)
contain the full technical details of the DIME.

The **libdime** project holds the DIME libraries and related command line utilities.

##Dependencies, Supported Platforms, and Build Instructions

Please see the [Quick Start Guide](docs/quickstart.md).

System:
c dl rt pthread resolv 

Bundled:
zlib openssl donna

Unit Tests:
python check

##Supported Platforms

* CentOS 6 x86_64
* CentOS 7 x86_64

##Directories

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

First, produce the build files from the autotools files:

    autoreconf --install

Then:

    ./configure
    make

The specific make targets:

    make signet
    make dime

##Video

An old/outdated video showing the components and command-line tools:

https://darkmail.info/downloads/dime-library-cli-demo.mp4
