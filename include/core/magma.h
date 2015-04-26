/**
 * @file
 * @brief The global include file.\ This header includes both system headers and Magma module headers.
 */

#ifndef MAGMA_H
#define MAGMA_H

#define __USE_GNU

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <dlfcn.h>
#ifdef __linux
#include <execinfo.h>
#endif
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#ifdef __linux
#include <sys/epoll.h>
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <regex.h>
#include <ftw.h>
#include <search.h>
#include <semaphore.h>
#include <sys/mman.h>

// GNU C Library
#ifdef __linux
#include <gnu/libc-version.h>
#endif

// added
#include <math.h>

#include <core/core.h>
#include <core/config.h>
#include <core/global.h>
#include <core/mail.h>

extern magma_t magma;

extern __thread char threadBuffer[1024];
#define _tbufptr (char *)&(threadBuffer)
#define _tbuflen sizeof(threadBuffer)

#endif
