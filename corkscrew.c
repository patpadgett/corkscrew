#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "corkscrew.h"

const static char linefeed[] = "\r\n\r\n";
struct args_st args;

void usage PARAMS(());
void parse_args PARAMS((int argc, char *argv[]));
void expect_arg_param PARAMS((char *argv));

/*
** base64.c
** Copyright (C) 2001 Tamas SZERB <toma@rulez.org>
*/

const static char base64[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* the output will be allocated automagically */
#ifdef ANSI_FUNC
char *base64_encode (char *in)
#else
char * base64_encode (in)
char *in;
#endif
{
	char *src, *end;
	char *buf, *ret;

	unsigned int tmp;

	int i,len;

	len = strlen(in);
	if (!in)
		return NULL;
	else
		len = strlen(in);

	end = in + len;

	buf = malloc(4 * ((len + 2) / 3) + 1);
	if (!buf)
		return NULL;
	ret = buf;

	for (src = in; src < end - 3;) {
		tmp = *src++ << 24;
		tmp |= *src++ << 16;
		tmp |= *src++ << 8;

		*buf++ = base64[tmp >> 26];
		tmp <<= 6;
		*buf++ = base64[tmp >> 26];
		tmp <<= 6;
		*buf++ = base64[tmp >> 26];
		tmp <<= 6;
		*buf++ = base64[tmp >> 26];
	}

	tmp = 0;
	for (i = 0; src < end; i++)
		tmp |= *src++ << (24 - 8 * i);

	switch (i) {
		case 3:
			*buf++ = base64[tmp >> 26];
			tmp <<= 6;
			*buf++ = base64[tmp >> 26];
			tmp <<= 6;
			*buf++ = base64[tmp >> 26];
			tmp <<= 6;
			*buf++ = base64[tmp >> 26];
		break;
		case 2:
			*buf++ = base64[tmp >> 26];
			tmp <<= 6;
			*buf++ = base64[tmp >> 26];
			tmp <<= 6;
			*buf++ = base64[tmp >> 26];
			*buf++ = '=';
		break;
		case 1:
			*buf++ = base64[tmp >> 26];
			tmp <<= 6;
			*buf++ = base64[tmp >> 26];
			*buf++ = '=';
			*buf++ = '=';
		break;
	}

	*buf = 0;
	return ret;
}

#ifdef ANSI_FUNC
int main (int argc, char *argv[])
#else
int main (argc, argv)
int argc;
char *argv[];
#endif
{
	char uri[BUFSIZE], buffer[BUFSIZE], version[BUFSIZE], descr[BUFSIZE];
	char line[4096], *up = NULL;
	int sent, setup, code, csock;
	fd_set rfd, sfd;
	struct timeval tv;
	ssize_t len;
	FILE *fp;

	parse_args(argc, argv);
	if (!args.authfile) {
		up = getenv("CORKSCREW_AUTH");

	} else {
		fp = fopen(args.authfile, "r");
		if (fp == NULL) {
			fprintf(stderr, "Error opening %s: %s\n", args.authfile, strerror(errno));
			exit(EXIT_FAILURE);
		} else {
			if (!fscanf(fp, "%4095s", line)) {
				fprintf(stderr, "Error reading auth file's content\n");
				exit(EXIT_FAILURE);
			}
			up = line;
			fclose(fp);
		}
	}

	strncpy(uri, "CONNECT ", sizeof(uri));
	strncat(uri, args.desthost, sizeof(uri) - strlen(uri) - 1);
	strncat(uri, ":", sizeof(uri) - strlen(uri) - 1);
	strncat(uri, args.destport, sizeof(uri) - strlen(uri) - 1);
	strncat(uri, " HTTP/1.0", sizeof(uri) - strlen(uri) - 1);
	if (up != NULL) {
		strncat(uri, "\nProxy-Authorization: Basic ", sizeof(uri) - strlen(uri) - 1);
		strncat(uri, base64_encode(up), sizeof(uri) - strlen(uri) - 1);
	}
	strncat(uri, linefeed, sizeof(uri) - strlen(uri) - 1);

	csock = sock_connect(args.host, args.port);
	if(csock == -1) {
		fprintf(stderr, "Couldn't establish connection to proxy: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
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
					memset(descr, 0, sizeof(descr));
					sscanf(buffer,"%s%d%[^\n]",version,&code,descr);
					if ((strncmp(version,"HTTP/",5) == 0) && (code >= 200) && (code < 300))
						setup = 1;
					else {
						if ((strncmp(version,"HTTP/",5) == 0) && (code >= 407)) {
						}
						fprintf(stderr, "Proxy could not open connection to %s: %s\n", args.desthost, descr);
						exit(EXIT_FAILURE);
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
	exit(EXIT_SUCCESS);
}

#ifdef ANSI_FUNC
void usage (void)
#else
void usage ()
#endif
{
	printf("corkscrew %s (agroman@agroman.net)\n\n", VERSION);
	printf("usage: corkscrew [-h] [-a authfile] <proxyhost> <proxyport> <desthost> <destport>\n");
}

#ifdef ANSI_FUNC
void parse_args (int argc, char *argv[])
#else
void parse_args (argc, argv)
int argc;
char *argv[];
#endif
{
	int i, j, len;
	int reqargs; /* required argument count */

	reqargs = argc;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-')
			break;

		len = strlen(&argv[i][1]) + 1;
		for (j = 1; j < len; j++) {
			switch (argv[i][j]) {
			case 'a':
				expect_arg_param(&argv[i][j]);
				args.authfile = argv[++i];
				reqargs -= 2;
				goto end_inner;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			default:
				usage();
				exit(EXIT_FAILURE);
			}
		}

		reqargs--;
end_inner: ;
	}

	if (reqargs < 5) {
		usage();
		exit(EXIT_FAILURE);
	}

	args.host = argv[i++];
	args.port = argv[i++];
	args.desthost = argv[i++];
	args.destport = argv[i++];
}

#ifdef ANSI_FUNC
void expect_arg_param (char *argv)
#else
void expect_arg_param ()
char *argv;
#endif
{
	if (argv[1] != '\0') {
		fprintf(stderr, "Argument '-%c' expects a parameter.\n", argv[0]);
		exit(EXIT_FAILURE);
	}
}
