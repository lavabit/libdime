The DIME libraries and related command line utilities.
=========

System Dependencies:
c dl rt pthread resolv

Bundled Dependancies:
zlib openssl donna

Unit Test Dependancies:
python check 

Directories
=========

libs/
  The DIME libraries
  
  core/
    Various string and other data manipulation functions take from the magma core component.
    
  common/
    Error handling, network and cryptographic functionality common to the remaining DIME libraries. 
    
  signet/
    Signet data format handlier, including creation, signing, parsing and validating. 
    
  signet-resolver/
    Logic retrieve and a management record and then an org or user signet, including relevant validation logic.
    
tools/
  The command line utilities.
  
  dime/
    Generate a DIME message and send it.
    
  signet/
    Generate, sign, view and verify a signet.
    
res/
  Resource files used by the different components and utilities. 

docs/
  Various related documents.
  
checks/
  Unit tests (eventually).
  
include/
  The header files provided by the library components. 
    
Compiling
=========

From the "deps" directory:

build.sh zlib
build.sh donna
build.sh openssl

Then from the main project directory:

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
=========

An old/outdated video showing the components and command-line tools: 

https://darkmail.info/downloads/dime-library-cli-demo.mp4

