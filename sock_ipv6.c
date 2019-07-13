#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "corkscrew.h"

#ifdef ANSI_FUNC
int sock_connect (const char *hname, const char *port)
#else
int sock_connect (hname, port)
const char *hname;
const char *port;
#endif
{
	int fd, rv;
	struct addrinfo hints;
	struct addrinfo *res, *addr;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG;
	rv = getaddrinfo(hname, port, &hints, &res);
	if (rv != 0) {
		fprintf(stderr, "Couldn't get address info for %s: %s\n", hname, gai_strerror(rv));
		exit(EXIT_FAILURE);
	}

	for (addr = res; addr != NULL; addr = addr->ai_next) {
		fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (fd == -1)
			break;

		rv = connect(fd, (struct sockaddr *) addr->ai_addr, addr->ai_addrlen);
		if (rv != -1)
			break; /* success */

		close(fd);
		fd = -1;
	}

	freeaddrinfo(res);
	return fd;
}
