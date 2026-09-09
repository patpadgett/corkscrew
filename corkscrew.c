#include "config.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#if HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#if __STDC__
#  ifndef NOPROTOS
#    define PARAMS(args)      args
#  endif
#endif
#ifndef PARAMS
#  define PARAMS(args)        ()
#endif

char *base64_encode PARAMS((const char *in));
void usage PARAMS((void));
int sock_connect PARAMS((const char *hname, int port));
int main PARAMS((int argc, char *argv[]));

#define BUFSIZE 4096
/*
char linefeed[] = "\x0A\x0D\x0A\x0D";
*/
char linefeed[] = "\r\n\r\n"; /* it is better and tested with oops & squid */

/*
** base64.c
** Copyright (C) 2001 Tamas SZERB <toma@rulez.org>
*/

static const char base64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Include the terminator; check before either rounding or multiplying. */
static int base64_output_size(size_t len, size_t *size)
{
	size_t groups = len / 3 + (len % 3 != 0);
	if (groups > ((size_t)-1 - 1) / 4)
		return 0;
	*size = groups * 4 + 1;
	return 1;
}

/* The caller owns the allocated output, including for an empty input. */
char *base64_encode(const char *in)
{
	const unsigned char *src = (const unsigned char *)in;
	size_t len, size, i, out = 0;
	char *buf;

	if (in == NULL)
		return NULL;
	len = strlen(in);
	if (!base64_output_size(len, &size))
		return NULL;
	buf = malloc(size);
	if (buf == NULL)
		return NULL;
	for (i = 0; i < len;) {
		size_t remaining = len - i;
		unsigned int value = (unsigned int)src[i++] << 16;
		if (remaining > 1)
			value |= (unsigned int)src[i++] << 8;
		if (remaining > 2)
			value |= (unsigned int)src[i++];
		buf[out++] = base64[(value >> 18) & 63];
		buf[out++] = base64[(value >> 12) & 63];
		buf[out++] = remaining > 1 ? base64[(value >> 6) & 63] : '=';
		buf[out++] = remaining > 2 ? base64[value & 63] : '=';
	}
	buf[out] = '\0';
	return buf;
}

/* Volatile stores prevent dead-store elimination of credential clearing. */
static void clear_secret(void *memory, size_t size)
{
	volatile unsigned char *p = memory;
	while (size-- != 0)
		*p++ = 0;
}

#define AUTH_MAX_LENGTH (BUFSIZE - 1)

/* Read the first credential line, preserving spaces and stripping only EOL.
 * An extra byte permits a CRLF after a maximum-length credential. */
static char *read_credentials(FILE *fp)
{
	char *line = malloc(AUTH_MAX_LENGTH + 2);
	size_t used = 0;
	int ch;

	if (line == NULL)
		return NULL;
	while ((ch = fgetc(fp)) != EOF && ch != '\n') {
		if (ch == '\0' || used == AUTH_MAX_LENGTH + 1)
			goto invalid;
		line[used++] = (char)ch;
	}
	if (ferror(fp))
		goto invalid;
	if (ch == '\n' && used != 0 && line[used - 1] == '\r')
		used--;
	if (used == 0 || used > AUTH_MAX_LENGTH)
		goto invalid;
	line[used] = '\0';
	return line;

invalid:
	clear_secret(line, AUTH_MAX_LENGTH + 2);
	free(line);
	return NULL;
}

#ifdef ANSI_FUNC
void usage (void)
#else
void usage ()
#endif
{
	printf("corkscrew %s (agroman@agroman.net)\n\n", VERSION);
	printf("usage: corkscrew <proxyhost> <proxyport> <desthost> <destport> [authfile]\n");
}

#ifdef ANSI_FUNC
int sock_connect (const char *hname, int port)
#else
int sock_connect (hname, port)
const char *hname;
int port;
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
	addr.sin_port = htons(port);
	
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
		return -1;

	return fd;
}

#ifdef ANSI_FUNC
int main (int argc, char *argv[])
#else
int main (argc, argv)
int argc;
char *argv[];
#endif
{
#ifdef ANSI_FUNC
	char uri[BUFSIZE] = "", buffer[BUFSIZE] = "", version[BUFSIZE] = "", descr[BUFSIZE] = "";
#else
	char uri[BUFSIZE], buffer[BUFSIZE], version[BUFSIZE], descr[BUFSIZE];
#endif
	char *host = NULL, *desthost = NULL, *destport = NULL;
	char *up = NULL;
	int port, sent, setup, code, csock;
	fd_set rfd, sfd;
	struct timeval tv;
	ssize_t len;
	FILE *fp;

	port = 80;

	if ((argc == 5) || (argc == 6)) {
		if (argc == 5) {
			host = argv[1];
			port = atoi(argv[2]);
			desthost = argv[3];
			destport = argv[4];
		}
		if ((argc == 6)) {
			host = argv[1];
			port = atoi(argv[2]);
			desthost = argv[3];
			destport = argv[4];
			fp = fopen(argv[5], "r");
			if (fp == NULL) {
				fprintf(stderr, "Error opening %s: %s\n", argv[5], strerror(errno));
				exit(-1);
			} else {
				int close_error;
				up = read_credentials(fp);
				close_error = fclose(fp);
				if (up == NULL || close_error != 0) {
					if (up != NULL) {
						clear_secret(up, AUTH_MAX_LENGTH + 2);
						free(up);
					}
					fprintf(stderr, "Invalid, oversized, or unreadable authentication file\n");
					exit(EXIT_FAILURE);
				}
			}
		}
	} else {
		usage();
		exit(-1);
	}

	if (up != NULL) {
		char *encoded = base64_encode(up);
		int request_length;
		clear_secret(up, AUTH_MAX_LENGTH + 2);
		free(up);
		up = NULL;
		if (encoded == NULL) {
			fprintf(stderr, "Unable to encode proxy credentials\n");
			exit(EXIT_FAILURE);
		}
		request_length = snprintf(uri, sizeof(uri),
			"CONNECT %s:%s HTTP/1.0\r\nProxy-Authorization: Basic %s\r\n\r\n",
			desthost, destport, encoded);
		clear_secret(encoded, strlen(encoded));
		free(encoded);
		if (request_length < 0 || (size_t)request_length >= sizeof(uri)) {
			clear_secret(uri, sizeof(uri));
			fprintf(stderr, "Authenticated CONNECT request is too long\n");
			exit(EXIT_FAILURE);
		}
	} else {
		strncpy(uri, "CONNECT ", sizeof(uri));
		strncat(uri, desthost, sizeof(uri) - strlen(uri) - 1);
		strncat(uri, ":", sizeof(uri) - strlen(uri) - 1);
		strncat(uri, destport, sizeof(uri) - strlen(uri) - 1);
		strncat(uri, " HTTP/1.0", sizeof(uri) - strlen(uri) - 1);
		strncat(uri, linefeed, sizeof(uri) - strlen(uri) - 1);
	}

	csock = sock_connect(host, port);
	if(csock == -1) {
		fprintf(stderr, "Couldn't establish connection to proxy: %s\n", strerror(errno));
		exit(-1);
	}

	sent = 0;
	setup = 0;
	for(;;) {
		FD_ZERO(&sfd);
		FD_ZERO(&rfd);
		if ((setup == 0) && (sent == 0)) {
			FD_SET(csock, &sfd);
		}
		FD_SET(csock, &rfd);
		FD_SET(0, &rfd);

		tv.tv_sec = 5;
		tv.tv_usec = 0;

		if(select(csock+1,&rfd,&sfd,NULL,&tv) == -1) break;

		/* there's probably a better way to do this */
		if (setup == 0) {
			if (FD_ISSET(csock, &rfd)) {
				len = read(csock, buffer, sizeof(buffer));
				if (len<=0)
					break;
				else {
					sscanf(buffer,"%s%d%[^\n]",version,&code,descr);
					if ((strncmp(version,"HTTP/",5) == 0) && (code >= 200) && (code < 300))
						setup = 1;
					else {
						if ((strncmp(version,"HTTP/",5) == 0) && (code >= 407)) {
						}
						fprintf(stderr, "Proxy could not open connnection to %s: %s\n", desthost, descr);
						exit(-1);
					}
				}
			}
			if (FD_ISSET(csock, &sfd) && (sent == 0)) {
				len = write(csock, uri, strlen(uri));
				if (len<=0)
					break;
				else
					sent = 1;
			}
		} else {
			if (FD_ISSET(csock, &rfd)) {
				len = read(csock, buffer, sizeof(buffer));
				if (len<=0) break;
				len = write(1, buffer, len);
				if (len<=0) break;
			}

			if (FD_ISSET(0, &rfd)) {
				len = read(0, buffer, sizeof(buffer));
				if (len<=0) break;
				len = write(csock, buffer, len);
				if (len<=0) break;
			}
		}
	}
	exit(0);
}
