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
#include <event.h>  
#include "md5.h"
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

char *base64_encodei PARAMS((char *in));
void usage PARAMS((void));
int sock_connect PARAMS((const char *hname, int port));
int main PARAMS((int argc, char *argv[]));

#define BUFSIZE 4096
/*
char linefeed[] = "\x0A\x0D\x0A\x0D";
*/
char linefeed[] = "\r\n"; /* it is better and tested with oops & squid */

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

#define MD5_HASHLEN (16)
static void dump_hash(char *buf, const unsigned char *hash) 
{
	int i;

	for (i = 0; i < MD5_HASHLEN; i++) {
		buf += sprintf(buf, "%02x", hash[i]);
	}

	*buf = 0;
}

/*
	Taken from darkk/redsocks
*/
uint32_t red_randui32()
{
	uint32_t ret;
	evutil_secure_rng_get_bytes(&ret, sizeof(ret));
	return ret;
}

/*
	Based on the corresponding function on darkk/redsocks
*/

char* digest_authentication_encode(char* user, char* realm, char* passwd, char * method, char * path, char* nc, char* nonce, char* cnonce, char* qop){

	
	/* calculate the digest value */
	md5_state_t ctx;
	md5_byte_t hash[MD5_HASHLEN];
	char a1buf[MD5_HASHLEN * 2 + 1], a2buf[MD5_HASHLEN * 2 + 1];
	char response[MD5_HASHLEN * 2 + 1];
	/* A1 = username-value ":" realm-value ":" passwd */
	md5_init(&ctx);
	md5_append(&ctx, (md5_byte_t*)user, strlen(user));
	md5_append(&ctx, (md5_byte_t*)":", 1);
	md5_append(&ctx, (md5_byte_t*)realm, strlen(realm));
	md5_append(&ctx, (md5_byte_t*)":", 1);
	md5_append(&ctx, (md5_byte_t*)passwd, strlen(passwd));
	md5_finish(&ctx, hash);
	dump_hash(a1buf, hash);

	/* A2 = Method ":" digest-uri-value */
	
	md5_init(&ctx);
	md5_append(&ctx, (md5_byte_t*)method, strlen(method));
	md5_append(&ctx, (md5_byte_t*)":", 1);
	md5_append(&ctx, (md5_byte_t*)path, strlen(path));
	md5_finish(&ctx, hash);
	dump_hash(a2buf, hash);
	
	
	
	
	/* qop set: request-digest = H(A1) ":" nonce-value ":" nc-value ":" cnonce-value ":" qop-value ":" H(A2) */
	/* not set: request-digest = H(A1) ":" nonce-value ":" H(A2) */
	md5_init(&ctx);
	md5_append(&ctx, (md5_byte_t*)a1buf, strlen(a1buf));
	md5_append(&ctx, (md5_byte_t*)":", 1);
	md5_append(&ctx, (md5_byte_t*)nonce, strlen(nonce));
	md5_append(&ctx, (md5_byte_t*)":", 1);
	if (qop) {
		md5_append(&ctx, (md5_byte_t*)nc, strlen(nc));
		md5_append(&ctx, (md5_byte_t*)":", 1);
		md5_append(&ctx, (md5_byte_t*)cnonce, strlen(cnonce));
		md5_append(&ctx, (md5_byte_t*)":", 1);
		md5_append(&ctx, (md5_byte_t*)qop, strlen(qop));
		md5_append(&ctx, (md5_byte_t*)":", 1);
	}
	md5_append(&ctx, (md5_byte_t*)a2buf, strlen(a2buf));
	md5_finish(&ctx, hash);
	dump_hash(response, hash);

	/* prepare the final string */
	int len = 256;
	len += strlen(user);
	len += strlen(realm);
	len += strlen(nonce);
	len += strlen(path);
	len += strlen(response);

	if (qop) {
		len += strlen(qop);
		len += strlen(nc);
		len += strlen(cnonce);
	}

	char *res = (char*)malloc(len);
	if(qop)
		sprintf(res, "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", qop=%s, nc=%s, cnonce=\"%s\"",
			user, realm, nonce, path, response, qop, nc, cnonce);
	else
		sprintf(res, "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
			user, realm, nonce, path, response);
	
	return res;
}

typedef struct proxyauth{
	char realm[BUFSIZE];
	char nonce[33];
	char qop[BUFSIZE];
	int stale;
}proxyauth;


proxyauth* process_line(char* line){
	
	proxyauth* pa = (proxyauth *)malloc(sizeof(proxyauth));
	// for now only looking for nonce, realm and qop
	char* where = strstr(line, "nonce=");
	if(where != NULL)strncpy(pa->nonce, where + 7, 32);
	where = strstr(line, "realm=");
	if(where != NULL)sscanf(where + 7, "%[^\"]", pa->realm);
	where = strstr(line, "qop=");
	if(where != NULL)sscanf(where + 5, "%[^\"]", pa->qop);
	// only 'auth' parameter is recognized
	if(strstr(pa->qop, "auth") == NULL)pa->qop[0] = '\0'; 
	else strncpy(pa->qop, "auth", 5);
	return pa;
}


proxyauth * get_param(char * buffer){
	char line[BUFSIZE] = "";
	int cur = 0;
	int blen = strlen(buffer);
	const char pauth[20] = "Proxy-Authenticate:";
	const char conclose[18] = "Connection: close";
	while(cur < blen){
		sscanf(buffer + cur, " %[^\n]", line);
		
		cur += strlen(line) + 1;
		
		if(strncmp(line, pauth, strlen(pauth)) == 0){
			return process_line(line);
		}
		if(strncmp(line, conclose, strlen(conclose)) == 0)break;
	}
	return NULL;
	
}
#define min(a, b) ((a) < (b) ? (a) : (b))
char * header(char * buffer){
	char * where = strstr(buffer, "\r\n\r\n");
	int headlen = 2048;
	char *head = (char*)malloc(2048);
	memset(head, 0, headlen);
	if(where==NULL){
		return head;
	}
	else{
		strncat(head, buffer, min(where - buffer, headlen - 1));
		return head;
	}
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
	char line[BUFSIZE];
	char uri_path[256] = "";
	int debug;
	int n_file_descriptor;
	int nc = 1;
	char prev_nonce[33] = "";
	int reading = 0;
	
	debug = 0;
	port = 443;

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
				
				fscanf(fp, "%s", line);
				up = malloc(sizeof(line));
				up = line;
				fclose(fp);
			}
		}
	} else {
		usage();
		exit(-1);
	}
	memset(uri, 0, sizeof(uri));
	
	memset(uri_path, 0, sizeof(uri_path));
	strcat(uri_path, desthost);
	strcat(uri_path, ":");
	strcat(uri_path, destport);
	
	strcat(uri, "CONNECT ");
	strcat(uri, uri_path);
	strcat(uri, " HTTP/1.1");
	strcat(uri, linefeed);
	
	strcat(uri, "Host: ");
	strcat(uri, uri_path);
	strcat(uri, linefeed);
	
	strcat(uri, "Proxy-Connection: Keep-Alive");
	strcat(uri, linefeed);
	strcat(uri, linefeed);

	csock = sock_connect(host, port);
	if(csock == -1) {
		fprintf(stderr, "Error: Couldn't establish connection to proxy: %s\n", strerror(errno));
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
		n_file_descriptor = select(csock+1,&rfd,&sfd,NULL,&tv);
		if(debug & 1)fprintf(stderr, "DEBUG: n_file_descriptor = %d\n", n_file_descriptor);
		if(n_file_descriptor == 0)continue;
		if(n_file_descriptor == -1) break;

		/* there's probably a better way to do this */
		if (setup == 0) {
			
			if (FD_ISSET(csock, &rfd)) {
				memset(buffer, 0, sizeof(buffer));
				len = read(csock, buffer, sizeof(buffer));
				
				if (len <= 0)	break;
				else {
					if(reading == 1)continue;
					reading = 1;
					sscanf(buffer,"%s%d%[^\n]",version,&code,descr);
					if(debug & 1)fprintf(stderr, "DEBUG: version = %s code = %d\n", version, code);
					if(debug & 1)fprintf(stderr, "DEBUG: header = %s\n", header(buffer));
					if(debug & 1)fprintf(stderr, "DEBUG: len = %d\n", len);
					if ((strncmp(version,"HTTP/",5) == 0) && (code >= 200) && (code < 300))
						setup = 1;
					else {
						if ((strncmp(version,"HTTP/",5) == 0) && (code >= 407)) {
						}
						if (code == 407) {
							
							if(strstr(buffer, "Digest realm") != NULL){
								if(debug & 1)fprintf(stderr, "DEBUG: Digest auth needed\n");
								proxyauth* pa = get_param(buffer);
								if(pa == NULL){
									fprintf(stderr, "Error: Proxy response contains errors\n");
									exit(-1);
								}
								if(strlen(pa->nonce) != 32){
									fprintf(stderr, "Error: Proxy response contains errors (nonce)\n");
									exit(-1);
								}
								memset(uri, 0, sizeof(uri));
								
								strcat(uri, "CONNECT ");
								strcat(uri, uri_path);
								strcat(uri, " HTTP/1.1");
								strcat(uri, linefeed);
								
								strcat(uri, "Host: ");
								strcat(uri, uri_path);
								strcat(uri, linefeed);
								
								strcat(uri, "Proxy-Connection: Keep-Alive");
								strcat(uri, linefeed);
								
								if ((argc == 6) || (argc == 7)) {
									char user[256] = "";
									sscanf(up, "%[^:]", user);
									char passwd[256] = "";
									sscanf(up + strlen(user) + 1, "%s", passwd);
									char method[32] = "CONNECT";
									
									strcat(uri, "Proxy-Authorization: Digest ");
									
									char* auth_string;
									
									if(strncmp(pa->qop, "auth", 5) == 0){
										/* prepare a random string for cnounce */
										char cnonce[17];
										snprintf(cnonce, sizeof(cnonce), "%08x%08x", red_randui32(), red_randui32());
										
										if(strncmp(prev_nonce, pa->nonce, 32) == 0)nc++;
										else{
											strncpy(prev_nonce, pa->nonce, 32);
											nc = 1;
										}
										
										char str_nc[17];
										snprintf(str_nc, sizeof(str_nc), "%08x", nc);
										
										auth_string = digest_authentication_encode(
												user, pa->realm, passwd, //user, realm, pass
												method, uri_path, str_nc, pa->nonce, cnonce, pa->qop); // method, path, nc, cnonce, qop
									}
									else{
										auth_string = digest_authentication_encode(
												user, pa->realm, passwd, //user, realm, pass
												method, uri_path, NULL, pa->nonce, NULL, NULL); // method, path, nc, cnonce, qop
										
									}
									strcat(uri, auth_string);
									strcat(uri, linefeed);
									
									//char user_agent[256] = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0";
									//strncat(uri, user_agent, sizeof(uri) - strlen(uri) - 1);
									
									strcat(uri, linefeed);
								}
								else{
									fprintf(stderr, "Error: User and password missing\n");
									exit(-1);
								}
								
								sent = 0;
								if(debug & 1)fprintf(stderr, "DEBUG: done digest\n");
								
								if(strstr(buffer, "Connection: close") != NULL){
									// necesary to open new socket, although the proxy should not do this
									close(csock);
									csock = sock_connect(host, port);
									if(csock == -1) {
										fprintf(stderr, "Error: Couldn't establish connection to proxy: %s\n", strerror(errno));
										exit(-1);
									}
									reading = 0;
								}
								
							}
							else if(strstr(buffer, "Basic realm") != NULL){
								if(debug & 1)fprintf(stderr, "DEBUG: Basic auth needed\n");
								
								memset(uri, 0, sizeof(uri));
								
								strcat(uri, "CONNECT ");
								strcat(uri, uri_path);
								strcat(uri, " HTTP/1.1");
								strcat(uri, linefeed);
								
								if ((argc == 6) || (argc == 7)) {
									strcat(uri, "Proxy-Authorization: Basic ");
									strcat(uri, base64_encode(up));
								}
								else{
									fprintf(stderr, "Error: User and password missing\n");
									exit(-1);
								}
								strcat(uri, linefeed);
								strcat(uri, linefeed);
								
								sent = 0;
								// just in case because old socket not needed, and old HTTP/1.0 proxies may not send Connection: close header
								close(csock);
								csock = sock_connect(host, port);
								if(csock == -1) {
									fprintf(stderr, "Error: Couldn't establish connection to proxy: %s\n", strerror(errno));
									exit(-1);
								}
								reading = 0;
							}
							
							else{
								fprintf(stderr, "Error: Proxy could not open connnection to %s: %s\n", desthost, descr);
								exit(-1);
							}
							
							continue;
						}
						fprintf(stderr, "Error: Proxy could not open connnection to %s: %s\n", desthost, descr);
						exit(-1);
					}
				}
			}
			if (FD_ISSET(csock, &sfd) && (sent == 0)) {
				reading = 0;
				len = write(csock, uri, strlen(uri));
				if(debug & 1)fprintf(stderr, "DEBUG: uri = \n%s\n", uri);
				if (len <= 0)
					break;
				else{
					if(debug & 1)fprintf(stderr, "DEBUG: sent uri\n");
					sent = 1;
				}
			}
		} else {
			if(debug & 1)fprintf(stderr, "DEBUG: working\n");
			if (FD_ISSET(csock, &rfd)) {
				len = read(csock, buffer, sizeof(buffer));
				if(debug & 2)fprintf(stderr, "DEBUG: buffer = %s\n", buffer);
				if (len<=0) break;
				len = write(1, buffer, len);
				if (len<=0) break;
			}

			if (FD_ISSET(0, &rfd)) {
				len = read(0, buffer, sizeof(buffer));
				if(debug & 2)fprintf(stderr, "DEBUG: buffer = %s\n", buffer);
				if (len<=0) break;
				len = write(csock, buffer, len);
				if (len<=0) break;
			}
		}
	}
	exit(0);
}
