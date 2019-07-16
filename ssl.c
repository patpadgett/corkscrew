#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "corkscrew.h"

union conn_un {
	int sock;
	SSL *ssl;
};

union conn_un conn;

int (*ssl_read)(CONN, void *, size_t);
int (*ssl_write)(CONN, void *, size_t);

static int intern_read PARAMS((CONN conn, void *buf, size_t count));
static int intern_write PARAMS((CONN conn, void *buf, size_t count));
static int intern_ssl_read PARAMS((CONN conn, void *buf, size_t count));
static int intern_ssl_write PARAMS((CONN conn, void *buf, size_t count));
static void ssl_exit_err PARAMS((void));

#ifdef ANSI_FUNC
CONN ssl_initialize (int sock)
#else
CONN ssl_initialize (sock)
int sock;
#endif
{
	SSL_CTX *ctx;
	SSL *ssl;

	if (!args.ssl) {
		ssl_read = intern_read;
		ssl_write = intern_write;
		conn.sock = sock;
		return &conn;
	}

	ssl_read = intern_ssl_read;
	ssl_write = intern_ssl_write;

	SSL_library_init();
	SSL_load_error_strings();

	if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
		ssl_exit_err();

	if (!args.ignore_certs)
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	if (args.trust_ca)
		SSL_CTX_load_verify_locations(ctx, args.trust_ca, NULL);

	if ((ssl = SSL_new(ctx)) == NULL)
		ssl_exit_err();

	if (SSL_set_fd(ssl, sock) != 1)
		ssl_exit_err();

	if (SSL_connect(ssl) != 1)
		ssl_exit_err();

	conn.ssl = ssl;
	return &conn;
}

#ifdef ANSI_FUNC
int ssl_get_fd (CONN conn)
#else
int ssl_get_fd (conn)
CONN conn;
#endif
{
	return (args.ssl) ? SSL_get_fd(conn->ssl) : conn->sock;
}

#ifdef ANSI_FUNC
void ssl_free (CONN conn)
#else
void ssl_free (conn)
CONN conn;
#endif
{
	if (args.ssl) {
		SSL_shutdown(conn->ssl);
		conn->sock = SSL_get_fd(conn->ssl);
	}
	close(conn->sock);
}

#ifdef ANSI_FUNC
static int intern_read (CONN conn, void *buf, size_t count)
#else
static int intern_read (conn, buf, count)
CONN conn;
void *buf;
size_t count
#endif
{
	return read(conn->sock, buf, count);
}

#ifdef ANSI_FUNC
static int intern_write (CONN conn, void *buf, size_t count)
#else
static int intern_write (conn, buf, count)
CONN conn;
void *buf;
size_t count
#endif
{
	return write(conn->sock, buf, count);
}

#ifdef ANSI_FUNC
static int intern_ssl_read (CONN conn, void *buf, size_t count)
#else
static int intern_ssl_read (conn, buf, count)
CONN conn;
void *buf;
size_t count
#endif
{
	return SSL_read(conn->ssl, buf, count);
}

#ifdef ANSI_FUNC
static int intern_ssl_write (CONN conn, void *buf, size_t count)
#else
static int intern_ssl_write (conn, buf, count)
CONN conn;
void *buf;
size_t count
#endif
{
	return SSL_write(conn->ssl, buf, count);
}

#ifdef ANSI_FUNC
static void ssl_exit_err (void)
#else
static void ssl_exit_err ()
#endif
{
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
}
