/* POSIX.1-2008: getaddrinfo, poll and CLOCK_MONOTONIC. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "config.h"
#include <limits.h>
#include <poll.h>
#include <time.h>
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

char *base64_encode(const char *in);
void usage(void);
int sock_connect(const char *hname, int port);
int main(int argc, char *argv[]);

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

/* Reject strtol's optional signs/whitespace as well as partial parses. */
static int parse_port(const char *text, int *port)
{
	const unsigned char *p = (const unsigned char *)text;
	char *end;
	long value;
	if (!*p)
		return -1;
	for (; *p; ++p)
		if (*p < '0' || *p > '9')
			return -1;
	errno = 0;
	value = strtol(text, &end, 10);
	if (errno == ERANGE || *end || value < 1 || value > 65535)
		return -1;
	*port = (int)value;
	return 0;
}

/* Normalize optional IPv6 brackets in argv in place. Brackets and colons
 * are accepted only for an actual IPv6 literal, never as URI syntax. */
static int validate_host(char **host)
{
	unsigned char *p = (unsigned char *)*host;
	size_t length = strlen(*host);
	struct in6_addr address;
	int bracketed = length && (*host)[0] == '[';
	if (!length)
		return -1;
	for (; *p; ++p)
		if (*p <= 0x20 || *p >= 0x7f || strchr("/@?#\\", *p))
			return -1;
	if (bracketed) {
		if (length < 3 || (*host)[length - 1] != ']')
			return -1;
		(*host)[length - 1] = '\0';
		++*host;
	}
	if (strchr(*host, '[') || strchr(*host, ']'))
		return -1;
	if (bracketed || strchr(*host, ':'))
		return inet_pton(AF_INET6, *host, &address) == 1 ? 0 : -1;
	/* DNS names, IPv4 literals and conventional underscore service names. */
	for (p = (unsigned char *)*host; *p; ++p)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '-' || *p == '.' || *p == '_'))
			return -1;
	return 0;
}

#ifndef CONNECT_TIMEOUT_MS
#define CONNECT_TIMEOUT_MS 10000
#endif

static int connect_remaining_ms(const struct timespec *deadline)
{
	struct timespec now;
	time_t seconds;
	long nanos;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return -1;
	seconds = deadline->tv_sec - now.tv_sec;
	nanos = deadline->tv_nsec - now.tv_nsec;
	if (nanos < 0) {
		--seconds;
		nanos += 1000000000L;
	}
	if (seconds < 0 || (seconds == 0 && nanos == 0)) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (seconds >= INT_MAX / 1000)
		return INT_MAX;
	return (int)(seconds * 1000 + (nanos + 999999L) / 1000000L);
}

int sock_connect(const char *hname, int port)
{
	struct addrinfo hints, *addresses, *ai;
	struct timespec deadline;
	char service[6];
	int result, saved_errno = EHOSTUNREACH;
	if (port < 1 || port > 65535) {
		errno = EINVAL;
		return -1;
	}
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;
	snprintf(service, sizeof(service), "%d", port);
	result = getaddrinfo(hname, service, &hints, &addresses);
	if (result != 0) {
		if (result != EAI_SYSTEM)
			errno = result == EAI_MEMORY ? ENOMEM : EHOSTUNREACH;
		return -1;
	}
	/* Synchronous name resolution is OS-controlled; the shared deadline
	 * bounds TCP connection attempts across all resolved addresses. */
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) < 0) {
		saved_errno = errno;
		goto done;
	}
	deadline.tv_sec += CONNECT_TIMEOUT_MS / 1000;
	deadline.tv_nsec += (CONNECT_TIMEOUT_MS % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		++deadline.tv_sec;
		deadline.tv_nsec -= 1000000000L;
	}
	for (ai = addresses; ai; ai = ai->ai_next) {
		int fd, flags, error, timeout;
		socklen_t error_length = sizeof(error);
		struct pollfd ready;
		if (connect_remaining_ms(&deadline) < 0) {
			saved_errno = errno;
			break;
		}
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			saved_errno = errno;
			continue;
		}
		flags = fcntl(fd, F_GETFL, 0);
		if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
			goto failed;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
			if (errno != EINPROGRESS && errno != EINTR)
				goto failed;
			ready.fd = fd;
			ready.events = POLLOUT;
			for (;;) {
				timeout = connect_remaining_ms(&deadline);
				if (timeout < 0)
					goto failed;
				result = poll(&ready, 1, timeout);
				if (result < 0 && errno == EINTR)
					continue;
				if (result < 0)
					goto failed;
				if (result == 0)
					continue;
				if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) < 0)
					goto failed;
				if (error) {
					errno = error;
					goto failed;
				}
				break;
			}
		}
		/* Preserve the existing caller's blocking-socket contract. */
		if (fcntl(fd, F_SETFL, flags) < 0)
			goto failed;
		freeaddrinfo(addresses);
		return fd;
failed:
		saved_errno = errno;
		close(fd);
		if (saved_errno == ETIMEDOUT)
			break;
	}
done:
	freeaddrinfo(addresses);
	errno = saved_errno;
	return -1;
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
	int port, destination_port, request_length, sent, setup, code, csock;
	fd_set rfd, sfd;
	struct timeval tv;
	ssize_t len;
	FILE *fp;

	if ((argc == 5) || (argc == 6)) {
		host = argv[1];
		desthost = argv[3];
		destport = argv[4];
		if (parse_port(argv[2], &port) < 0 ||
		    parse_port(destport, &destination_port) < 0) {
			fprintf(stderr, "Invalid port: expected decimal integer in 1..65535\n");
			return EXIT_FAILURE;
		}
		if (validate_host(&host) < 0 || validate_host(&desthost) < 0) {
			fprintf(stderr, "Invalid hostname or IP address\n");
			return EXIT_FAILURE;
		}
		request_length = snprintf(uri, sizeof(uri),
		    strchr(desthost, ':') ? "CONNECT [%s]:%d HTTP/1.0" : "CONNECT %s:%d HTTP/1.0",
		    desthost, destination_port);
		/* Reserve the final CRLF CRLF and NUL before auth is read/appended.
		 * The authentication builder must separately check its own addition. */
		if (request_length < 0 || (size_t)request_length >= sizeof(uri) - strlen(linefeed)) {
			fprintf(stderr, "CONNECT request too long\n");
			return EXIT_FAILURE;
		}
		if ((argc == 6)) {
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
		size_t used = strlen(uri);
		request_length = snprintf(uri + used, sizeof(uri) - used,
			"\r\nProxy-Authorization: Basic %s\r\n\r\n", encoded);
		clear_secret(encoded, strlen(encoded));
		free(encoded);
		if (request_length < 0 || (size_t)request_length >= sizeof(uri) - used) {
			clear_secret(uri, sizeof(uri));
			fprintf(stderr, "Authenticated CONNECT request is too long\n");
			exit(EXIT_FAILURE);
		}
	} else {
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
