#ifndef NETWORK_H
#define NETWORK_H


#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>

#include <common/error.h>

#define CONNECT_TIMEOUT		5	/* the timeout value for connection attempts, in seconds */

PUBLIC_FUNC_DECL(int, connect_host, const char *hostname, unsigned short port, int force_family);


// Private functions.
int _connect_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen);


#endif
