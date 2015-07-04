# Tools used in Magma/DIME

## DarkMail documentation
Specification Documents:
- The [Dark Internet Mail Environment](https://darkmail.info/spec)
- The STACIE Authentication Module (To Be Added)

## Source Code
Magma/DIME uses Git for source code control.
- Intro: Scott Chacon’s excellent [Introduction to Git](https://www.youtube.com/watch?v=ZDR433b0HJY)

###Github Repository
Public git repositories for the Magma project
- [Magma.classic](https://github.com/lavabit/magma.classic)
- [Libraries for the Dark Internet Mail Environment](https://github.com/lavabit/libdime)

###Gitflow
The branching model used by Magma.

###HubFlow - Our Development branching model
- Homepage for [Hubflow](https://datasift.github.io/gitflow/index.html)
- [Using Gitflow with Github](https://datasift.github.io/gitflow/GitFlowForGitHub.html)
- HubFlow is a fork of the original gitFlow, Vincent Driessen's [gitflow model](http://nvie.com/posts/a-successful-git-branching-model/)

##C Coding
### Documentation
Generate documentation from comments with [Doxygen](http://www.stack.nl/~dimitri/doxygen/).
- [User manual](http://www.stack.nl/~dimitri/doxygen/manual/starting.html)
- [Javadoc](http://www.oracle.com/technetwork/java/javase/documentation/index-jsp-135444.html) style is used for function headers.
- [Javadoc tags and comments](http://www.oracle.com/technetwork/java/javase/documentation/index-137868.html)

### Useful coding references
- [Signed and unsigned integers](http://embeddedgurus.com/stack-overflow/tag/unsigned/)
- [CERT Secure Coding Standards](https://www.securecoding.cert.org/confluence/download/attachments/3524/more-secure-coding-rules.pdf)

## Testing
###Check 0.9.14 - a C-testing framework 
- [Check homepage](https://check.sourceforge.net/)
- [Check User manual](https://check.sourceforge.net/doc/check_html/index.html#Top)

## Eclipse and Virtual Machines
The original Magma.classic development environment was [Eclipse](https://eclipse.org/) running
under [CentOS 6](https://www.centos.org/) in a [VMware](https://vmware.com/) virtual machine.

### Eclipse IDE
You'll need the Eclipse IDE for C/C++. The recommended hypervisor is **VMware**, but [VirtualBox](https://www.virtualbox.org)
is reported to work as well.
