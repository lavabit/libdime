##Project status

Right now, the code for the two basic tools (`tools/dime` and
`tools/signet`) is finished, but they need a lot of testing to be sure they work properly.

##Write unit tests in C

If you know C, you could help in writing unit tests for each and every C
function that is defined somewhere in `libs/*`. There are already some
examples of unit tests in `check/core`. To extend the unit tests, you
need to:

1. create a new `check_*.c` file
2. add that file to the `checks_SOURCES` variable in the `Makefile`
3. add the test suite function to `checks.h`
4. add the test suite function to `checks.c`
5. fill in the gaps in the file from step 1

There is already some code in the `lavabit/magma.classic` project, but
some of that code doesn't qualify as a unit test, since it just feeds
random numbers to the functions and checks that the code doesn't crash.
You can study that code to get an idea of how things work.

See http://check.sourceforge.net/doc/check_html/ for help. Check makes
heavy use of environment variables to adjust the verboseness of the unit
tests. Look up their names in the Check documentation:

* `CK_RUN_CASE` = name of a test case, runs only that test
* `CK_RUN_SUITE` = name of a test suite, runs only that suite
* `CK_VERBOSITY` = `silent | minimal | normal | verbose`
* `CK_FORK` = no, to debug segmentation faults
* `CK_DEFAULT_TIMEOUT` = float, in seconds; 0 means no timeout
* `CK_TIMEOUT_MULTIPLIER` = integer, default 1
* `CK_LOG_FILE_NAME` = filename, to redirect the output
* `CK_XML_LOG_FILE_NAME` = XML log file name
* `CK_TAP_LOG_FILE_NAME` = Test Anything Protocol log file name

##Write unit tests for the tools

If you don't feel too comfortable writing C code, you could help in
writing unit tests for tool/dime and tool/signet. These unit tests
should be written in bash or some other scripting language. We don't
have a test framework for that, so you can choose yourself.

##Fix bugs

If you know how to fix bugs in C, I can give you an account on
https://scan.coverity.com/, a static code analyzer that has found quite
a few bugs in the code, which need to be fixed. I already fixed some of
the simple ones, and the remaining ones get more and more trickier.
