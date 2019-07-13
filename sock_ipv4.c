#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "corkscrew.h"

#if HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#ifdef ANSI_FUNC
int sock_connect (const char *hname, const char *port)
#else
int sock_connect (hname, port)
const char *hname;
const char *port;
#endif
{
	int fd;
	struct sockaddr_in addr;
	struct hostent *hent;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	hent = gethostbyname(hname);
	if (hent == NULL)
		addr.sin_addr.s_addr = inet_addr(hname);
	else
		memcpy(&addr.sin_addr, hent->h_addr, hent->h_length);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
		return -1;

	return fd;
}
