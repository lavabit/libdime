# Tools used in Magma/DIME

## DarkMail documentation
Specification Documents:
- The [Dark Internet Mail Environment](https://darkmail.info/downloads/dark-internet-mail-environment-march-2015.pdf)
- The STACIE Authentication Module (To Be Added)

## Source Code
Magma/DIME uses **git** for source code control.
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
- [Signed and unsigned integers](embeddedgurus.com/stack-overflow/tag/unsigned/)
- [CERT Secure Coding Standards](https://slack-files.com/files-pri-safe/T0353J4TM-F05108QGZ/more-secure-coding-rules.pdf?c=1432749763-580b2ddad7a071dba0147d5153db968e6a0658ec)
- [Geary Code Style Guide](https://slack-files.com/files-pri-safe/T0353J4TM-F05108PF3/geary_code_style_guide.pdf?c=1432749821-6081383842ae47a896d11c1372951d164601a873)

## Testing
###Check 0.9.14 - a C-testing framework 
- [Check homepage](check.sourceforge.net/)
- [Check User manual](check.sourceforge.net/doc/check_html/index.html#Top)

## Eclipse and Virtual Machines
The original Magma.classic development environment was [Eclipse](eclipse.org) running
under [CentOS 6](www.centos.org) in a [VMware](vmware.com) virtual machine.

### Eclipse IDE
You'll need the Eclipse IDE for C/C++. The recommended hypervisor is **VMware**, but [VirtualBox](www.virtualbox.org)
is reported to work as well.
