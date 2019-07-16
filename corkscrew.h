#ifndef _CORKSCREW_H
#define _CORKSCREW_H

#include "config.h"

#define BUFSIZE 4096

/* h_addr macro is not available when gcc compiles with strict ansi enabled. */
#ifndef HAVE_H_ADDR
#define h_addr h_addr_list[0]
#endif

#if __STDC__
#  ifndef NOPROTOS
#    define PARAMS(args)      args
#  endif
#  ifndef ANSI_FUNC
#    define ANSI_FUNC
#  endif
#endif
#ifndef PARAMS
#  define PARAMS(args)        ()
#endif

#ifdef USE_SSL
#include "ssl.h"
#else
typedef int CONN;

#define conn_init(fd) (fd)
#define FD(conn) (conn)
#define peer_read(conn, buf, count)  read((conn), (buf), (count))
#define peer_write(conn, buf, count) write((conn), (buf), (count))
#define conn_free(conn) close((conn))
#endif /* USE_SSL */

/* command line arguments */
struct args_st {
	char *host;       /* proxy host name */
	char *port;       /* proxy port */
	char *desthost;   /* destination host name */
	char *destport;   /* destination port */
	char *authfile;   /* file containing authentication credentials */

#ifdef USE_SSL
	char *trust_ca;   /* file containing trusted CA */
	int ssl;          /* enable SSL encryption with proxy server */
	int ignore_certs; /* ignore unrecognized SSL certificates */
#endif
};

extern struct args_st args;

int sock_connect PARAMS((const char *hname, const char *port));

#endif /* _CORKSCREW_H */
