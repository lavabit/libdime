Right now, the code for the two basic tools (tools/dime and
tools/signet) is finished, and it needs a lot of testing to be sure they
work properly.

Write unit tests in C
====

If you know C, you could help in writing unit tests for each and every C
function that is defined somewhere in libs/*. There are already some
examples for unit tests in check/core. To extend the unit tests, you
need to:

1. create a new `check_*.c` file
2. add that file to the `checks_SOURCES` variable in the `Makefile`
3. add the test suite function to `checks.h`
4. add the test suite function to `checks.c`
5. fill in the gaps in the file from step 1

There is already some code in the `lavabit/magma.classic` project, but
some of that code doesn't qualify as a unit test, since it just feeds
random numbers to the functions and checks that the code doesn't crash.
You can take that code to get an idea of how things work.

Write unit tests for the tools
====

If you don't feel too comfortable writing C code, you could help in
writing unit tests for tool/dime and tool/signet. These unit tests
should be written in bash or some other scripting language. We don't
have a test framework for that, so you can choose yourself.

Fix bugs
====

If you know how to fix bugs in C, I can give you an account on
https://scan.coverity.com/, a static code analyzer that has found quite
a few bugs in the code, which need to be fixed. I already fixed some of
the simple ones, and the remaining ones get more and more trickier.
