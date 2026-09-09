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
#include <poll.h>
#include <signal.h>
#include <time.h>
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

/* The limit includes the terminating CRLF CRLF, but not tunnel data. */
#define HANDSHAKE_HEADER_LIMIT 16384
#define HANDSHAKE_STATUS_LIMIT 4096
#ifndef HANDSHAKE_TIMEOUT_MS
#define HANDSHAKE_TIMEOUT_MS 10000
#endif

/* Recompute the remaining time on every retry, including EINTR. */
static int handshake_wait(int fd, short events, const struct timespec *deadline)
{
	struct timespec now;
	struct pollfd pfd;
	long long remaining;
	int result;

	pfd.fd = fd;
	pfd.events = events;
	for (;;) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			return -1;
		remaining = (long long)(deadline->tv_sec - now.tv_sec) * 1000
			+ (deadline->tv_nsec - now.tv_nsec + 999999) / 1000000;
		if (remaining <= 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		pfd.revents = 0;
		result = poll(&pfd, 1, (int)remaining);
		if (result < 0 && errno == EINTR)
			continue;
		if (result < 0)
			return -1;
		if (result == 0)
			continue;
		if (pfd.revents & POLLNVAL) {
			errno = EBADF;
			return -1;
		}
		/* Read on HUP to drain any bytes received before the close. */
		if (pfd.revents & (events | POLLERR | POLLHUP))
			return 0;
	}
}

static int handshake_write(int fd, const void *buffer, size_t length,
		const struct timespec *deadline)
{
	const unsigned char *bytes = buffer;
	size_t offset = 0;
	ssize_t count;

	while (offset < length) {
		if (handshake_wait(fd, POLLOUT, deadline) < 0)
			return -1;
		count = write(fd, bytes + offset, length - offset);
		if (count < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			return -1;
		}
		if (count == 0) {
			errno = EIO;
			return -1;
		}
		offset += (size_t)count;
	}
	return 0;
}

static int handshake_token(unsigned char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		(c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL);
}

/* No network bytes are interpreted as NUL-terminated strings. */
static int handshake_status(const unsigned char *header, size_t length)
{
	size_t end = 0, pos, colon, i;
	int code;

	while (end + 1 < length &&
		!(header[end] == '\r' && header[end + 1] == '\n'))
		end++;
	if (end < 13 || end > HANDSHAKE_STATUS_LIMIT || end + 1 >= length ||
		memcmp(header, "HTTP/1.", 7) != 0 ||
		(header[7] != '0' && header[7] != '1') || header[8] != ' ' ||
		header[9] < '1' || header[9] > '5' ||
		header[10] < '0' || header[10] > '9' ||
		header[11] < '0' || header[11] > '9' || header[12] != ' ')
		return -1;
	for (i = 13; i < end; i++)
		if ((header[i] < 32 && header[i] != '\t') || header[i] == 127)
			return -1;
	code = (header[9] - '0') * 100 + (header[10] - '0') * 10 + header[11] - '0';
	pos = end + 2;
	while (pos + 1 < length) {
		if (header[pos] == '\r' && header[pos + 1] == '\n')
			return pos + 2 == length ? code : -1;
		end = pos;
		while (end + 1 < length &&
			!(header[end] == '\r' && header[end + 1] == '\n'))
			end++;
		if (end + 1 >= length)
			return -1;
		colon = pos;
		while (colon < end && handshake_token(header[colon]))
			colon++;
		if (colon == pos || colon == end || header[colon] != ':')
			return -1;
		for (i = colon + 1; i < end; i++)
			if ((header[i] < 32 && header[i] != '\t') || header[i] == 127)
				return -1;
		pos = end + 2;
	}
	return -1;
}

/* Setup owns only the proxy socket, never stdin or stdout. The deadline
 * covers request writes and header reads, not coalesced tunnel bytes.
 * Restore descriptor flags and SIGPIPE disposition before entering the relay.
 * DNS/TCP connect and relay lifetime are deliberately outside this deadline. */
static int perform_handshake(int csock, char *uri, size_t uri_size,
		unsigned char *trailing, size_t *trailing_length)
{
	unsigned char header[HANDSHAKE_HEADER_LIMIT];
	size_t used = 0, scan = 0, end = 0;
	ssize_t count;
	struct timespec deadline;
	struct sigaction ignore, previous;
	int socket_flags = -1, signal_changed = 0;
	int result = -1, saved_errno, code;

	*trailing_length = 0;
	if (clock_gettime(CLOCK_MONOTONIC, &deadline) < 0)
		goto done;
	deadline.tv_sec += HANDSHAKE_TIMEOUT_MS / 1000;
	deadline.tv_nsec += (HANDSHAKE_TIMEOUT_MS % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}
	memset(&ignore, 0, sizeof(ignore));
	ignore.sa_handler = SIG_IGN;
	sigemptyset(&ignore.sa_mask);
	if (sigaction(SIGPIPE, &ignore, &previous) < 0)
		goto done;
	signal_changed = 1;
	socket_flags = fcntl(csock, F_GETFL);
	if (socket_flags < 0 || fcntl(csock, F_SETFL, socket_flags | O_NONBLOCK) < 0)
		goto done;
	if (handshake_write(csock, uri, strlen(uri), &deadline) < 0)
		goto done;
	/* Do not retain encoded credentials while waiting for the proxy. */
	clear_secret(uri, uri_size);
	for (;;) {
		if (used == sizeof(header)) {
			errno = EMSGSIZE;
			goto done;
		}
		if (handshake_wait(csock, POLLIN, &deadline) < 0)
			goto done;
		count = read(csock, header + used, sizeof(header) - used);
		if (count < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;
			goto done;
		}
		if (count == 0) {
			errno = ECONNRESET;
			goto done;
		}
		used += (size_t)count;
		/* Retain three bytes of overlap for a split terminator. */
		for (; scan + 3 < used; scan++) {
			if (memcmp(header + scan, "\r\n\r\n", 4) == 0) {
				end = scan + 4;
				break;
			}
		}
		if (end != 0)
			break;
	}
	code = handshake_status(header, end);
	if (code < 200 || code >= 300) {
		if (code < 0)
			fprintf(stderr, "Malformed HTTP CONNECT response\n");
		else
			fprintf(stderr, "Proxy rejected CONNECT: HTTP %d\n", code);
		errno = EPROTO;
		goto done;
	}
	/* Caller provides HANDSHAKE_HEADER_LIMIT bytes; relay owns delivery. */
	*trailing_length = used - end;
	memcpy(trailing, header + end, *trailing_length);
	result = 0;
 done:
	saved_errno = errno;
	clear_secret(uri, uri_size);
	if (socket_flags >= 0 && fcntl(csock, F_SETFL, socket_flags) < 0 && result == 0) {
		saved_errno = errno;
		result = -1;
	}
	if (signal_changed && sigaction(SIGPIPE, &previous, NULL) < 0 && result == 0) {
		saved_errno = errno;
		result = -1;
	}
	errno = saved_errno;
	return result;
}

/* Buffered duplex relay. Keep each direction independent and bounded. */
/* Termination is deferred until inherited descriptor flags are restored. */
static volatile sig_atomic_t termination_requested;
static void request_termination(int signo) { termination_requested = signo; }
static int install_termination_handlers(struct sigaction previous[3])
{
    const int signals[3] = {SIGTERM, SIGINT, SIGHUP};
    struct sigaction action;
    int i;
    memset(&action, 0, sizeof(action));
    action.sa_handler = request_termination;
    sigemptyset(&action.sa_mask);
    for (i = 0; i < 3; i++) {
        if (sigaction(signals[i], &action, &previous[i]) < 0) {
            while (i-- > 0) sigaction(signals[i], &previous[i], NULL);
            return -1;
        }
    }
    return 0;
}
static void restore_termination_handlers(struct sigaction previous[3])
{
    const int signals[3] = {SIGTERM, SIGINT, SIGHUP};
    int i;
    for (i = 0; i < 3; i++) sigaction(signals[i], &previous[i], NULL);
}


struct relay_buffer {
	unsigned char data[65536];
	size_t offset, length;
};

static int relay_fcntl(int fd, int command, int flags)
{
	int result;
	do {
		result = fcntl(fd, command, flags);
	} while (result < 0 && errno == EINTR);
	return result;
}

/* Return -1 for failure, 0 for EOF, 1 for progress or retry. */
static int relay_read(int fd, struct relay_buffer *buffer)
{
	ssize_t count = read(fd, buffer->data, sizeof(buffer->data));
	if (count > 0) {
		buffer->offset = 0;
		buffer->length = (size_t)count;
		return 1;
	}
	if (count == 0)
		return 0;
	if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
		return 1;
	return -1;
}

static int relay_write(int fd, struct relay_buffer *buffer)
{
	ssize_t count = write(fd, buffer->data + buffer->offset,
	    buffer->length);
	if (count > 0) {
		buffer->offset += (size_t)count;
		buffer->length -= (size_t)count;
		return 0;
	}
	if (count < 0 && (errno == EINTR || errno == EAGAIN ||
	    errno == EWOULDBLOCK))
		return 0;
	if (count == 0)
		errno = EIO;
	return -1;
}

static int relay(int csock, const unsigned char *trailing, size_t trailing_length)
{
	struct relay_buffer upstream = {{0}, 0, 0};
	struct relay_buffer downstream = {{0}, 0, 0};
	struct pollfd ready[3];
	struct sigaction ignore, original_signal, termination_previous[3];
	int termination_installed = 0;
	int fds[3], original_flags[3], changed[3] = {0, 0, 0};
	int input_eof = 0, socket_eof = 0, write_shutdown = 0;
	int signal_changed = 0, error = 0, i, result;

	if (trailing_length > sizeof(downstream.data)) {
		fprintf(stderr, "corkscrew: relay: initial payload too large\n");
		return 1;
	}
	if (trailing_length)
		memcpy(downstream.data, trailing, trailing_length);
	downstream.length = trailing_length;
	termination_requested = 0;
	if (install_termination_handlers(termination_previous) < 0) return 1;
	termination_installed = 1;
	fds[0] = STDIN_FILENO;
	fds[1] = STDOUT_FILENO;
	fds[2] = csock;
	memset(&ignore, 0, sizeof(ignore));
	ignore.sa_handler = SIG_IGN;
	sigemptyset(&ignore.sa_mask);
	if (sigaction(SIGPIPE, &ignore, &original_signal) < 0) {
		error = errno;
		goto cleanup;
	}
	signal_changed = 1;
	/* Snapshot all flags before changing any: stdin/out may share an OFD. */
	for (i = 0; i < 3; i++) {
		original_flags[i] = relay_fcntl(fds[i], F_GETFL, 0);
		if (original_flags[i] < 0) {
			error = errno;
			goto cleanup;
		}
	}
	for (i = 0; i < 3; i++) {
		if (!(original_flags[i] & O_NONBLOCK)) {
			if (relay_fcntl(fds[i], F_SETFL,
			    original_flags[i] | O_NONBLOCK) < 0) {
				error = errno;
				goto cleanup;
			}
			changed[i] = 1;
		}
	}

	for (;;) {
		if (termination_requested) { error = EINTR; goto cleanup; }
		if (input_eof && upstream.length == 0 && !write_shutdown) {
			do {
				result = shutdown(csock, SHUT_WR);
			} while (result < 0 && errno == EINTR);
			if (result < 0) {
				error = errno;
				goto cleanup;
			}
			write_shutdown = 1;
		}
		/* A remote half-close ends only downstream; upstream lives to EOF. */
		if (socket_eof && write_shutdown && downstream.length == 0)
			break;

		ready[0].fd = (!input_eof && upstream.length == 0)
		    ? STDIN_FILENO : -1;
		ready[0].events = POLLIN;
		ready[1].fd = downstream.length ? STDOUT_FILENO : -1;
		ready[1].events = POLLOUT;
		ready[2].events = 0;
		if (!socket_eof && downstream.length == 0)
			ready[2].events |= POLLIN;
		if (upstream.length)
			ready[2].events |= POLLOUT;
		/* A disabled fd must be -1: events=0 still reports POLLHUP. */
		ready[2].fd = ready[2].events ? csock : -1;
		/* Bounded wait closes the signal-before-poll race. */
		result = poll(ready, 3, 100);
		if (result < 0) {
			if (errno == EINTR)
				continue;
			error = errno;
			goto cleanup;
		}
		for (i = 0; i < 3; i++) {
			if (ready[i].revents & POLLNVAL) {
				error = EBADF;
				goto cleanup;
			}
		}
		if (ready[2].revents & POLLERR) {
			int socket_error = 0;
			socklen_t size = sizeof(socket_error);
			if (getsockopt(csock, SOL_SOCKET, SO_ERROR, &socket_error, &size) < 0)
				error = errno;
			else
				error = socket_error ? socket_error : EIO;
			goto cleanup;
		}
		if (downstream.length &&
		    (ready[1].revents & (POLLOUT | POLLERR | POLLHUP))) {
			if (relay_write(STDOUT_FILENO, &downstream) < 0) {
				error = errno;
				goto cleanup;
			}
		}
		if (upstream.length &&
		    (ready[2].revents & (POLLOUT | POLLHUP))) {
			if (relay_write(csock, &upstream) < 0) {
				error = errno;
				goto cleanup;
			}
		}
		if (!socket_eof && downstream.length == 0 &&
		    (ready[2].revents & (POLLIN | POLLHUP))) {
			result = relay_read(csock, &downstream);
			if (result < 0) {
				error = errno;
				goto cleanup;
			}
			if (result == 0)
				socket_eof = 1;
		}
		if (!input_eof && upstream.length == 0 &&
		    (ready[0].revents & (POLLIN | POLLHUP | POLLERR))) {
			result = relay_read(STDIN_FILENO, &upstream);
			if (result < 0) {
				error = errno;
				goto cleanup;
			}
			if (result == 0)
				input_eof = 1;
		}
	}

cleanup:
	/* O_NONBLOCK belongs to the open file description, not this process. */
	for (i = 2; i >= 0; i--) {
		if (changed[i] && relay_fcntl(fds[i], F_SETFL, original_flags[i]) < 0 && !error)
			error = errno;
	}
	if (signal_changed && sigaction(SIGPIPE, &original_signal, NULL) < 0 && !error)
		error = errno;
	if (termination_installed) restore_termination_handlers(termination_previous);
	if (termination_requested) return 128 + termination_requested;
	if (error) {
		fprintf(stderr, "corkscrew: relay: %s\n", strerror(error));
		return 1;
	}
	return 0;
}
/* End buffered duplex relay. */

#ifdef ANSI_FUNC
int main (int argc, char *argv[])
#else
int main (argc, argv)
int argc;
char *argv[];
#endif
{
#ifdef ANSI_FUNC
	char uri[BUFSIZE] = "";
#else
	char uri[BUFSIZE];
#endif
	char *host = NULL, *desthost = NULL, *destport = NULL;
	char *up = NULL;
	unsigned char trailing[HANDSHAKE_HEADER_LIMIT];
	size_t trailing_length;
	int port, destination_port, request_length, csock;
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
				/* Avoid an uncleared stdio buffer containing credentials. */
				if (setvbuf(fp, NULL, _IONBF, 0) != 0) {
					fclose(fp);
					fprintf(stderr, "Unable to disable authentication file buffering\n");
					return EXIT_FAILURE;
				}
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
		clear_secret(uri, sizeof(uri));
		fprintf(stderr, "Couldn't establish connection to proxy: %s\n", strerror(errno));
		exit(-1);
	}

	if (perform_handshake(csock, uri, sizeof(uri), trailing, &trailing_length) < 0) {
		clear_secret(uri, sizeof(uri));
		fprintf(stderr, "HTTP CONNECT handshake failed: %s\n", strerror(errno));
		close(csock);
		return EXIT_FAILURE;
	}
	clear_secret(uri, sizeof(uri));
	int result = relay(csock, trailing, trailing_length);
	close(csock);
	return result;
}
